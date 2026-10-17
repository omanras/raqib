// policies.yml: base currency, accounts, categories, classes, snapshot age,
// and the policy list (reference engine ADR section 5). A declaration the
// engine cannot read is kept with status "unknown" and the reason; the
// verdict for it is `unknown` (A3/A5). Nothing is inferred (A2).
import { fmt, type Decimal } from "./decimal";
import { isPeriodKind, PERIOD_KINDS } from "./periods";
import { isCurrencyCode, parseAmount, parseIntText } from "./text";
import {
  DEFAULT_CLASSES,
  makeProblem,
  POLICY_TYPES,
  type Band,
  type Config,
  type Limit,
  type Match,
  type Measure,
  type ParsedPolicies,
  type Policy,
  type PolicyType,
  type Problem,
} from "./types";
import { isMap, isNullish, isSeq, keyedItemLines, loadYaml, textOf, yFlow, yFlowSeq, yPlainOrStr, yStr, type YamlValue } from "./yaml";

function stringList(v: YamlValue | undefined): string[] | null {
  if (isSeq(v)) {
    const out: string[] = [];
    for (const x of v) {
      const t = textOf(x);
      if (t === null) return null;
      out.push(t);
    }
    return out;
  }
  const t = textOf(v);
  return t === null ? null : [t];
}

function fail(reason: string): { ok: false; reason: string } {
  return { ok: false, reason };
}

type Parsed<T> = { ok: true; value: T } | { ok: false; reason: string };

function dotted(text: string): { head: string; tail: string | null } {
  const i = text.indexOf(".");
  if (i < 0) return { head: text, tail: null };
  return { head: text.slice(0, i), tail: text.slice(i + 1) };
}

export function parseMeasure(v: YamlValue | undefined, config: Config): Parsed<Measure> {
  if (!isMap(v)) return fail("measure must be a mapping");
  const keys = Object.keys(v);
  const kinds = keys.filter((k) => k === "sum" || k === "holdings" || k === "share" || k === "drawdown");
  if (kinds.length !== 1) return fail(`measure must have exactly one of sum, holdings, share, drawdown (got ${keys.join(", ") || "nothing"})`);
  const kind = kinds[0] as string;
  const target = textOf(v[kind]);
  if (target === null) return fail(`measure ${kind} needs a target`);
  const extra = keys.filter((k) => k !== kind && !(kind === "sum" && k === "period") && !(kind === "drawdown" && k === "window_days"));
  if (extra.length > 0) return fail(`measure ${kind}: unknown key ${extra.join(", ")}`);
  const { head, tail } = dotted(target);
  if (kind === "sum") {
    const groups = Object.keys(config.categories);
    if (!groups.includes(head)) return fail(`measure sum: unknown group "${head}"`);
    if (tail !== null && !(config.categories[head] as string[]).includes(tail)) return fail(`measure sum: unknown category "${tail}" in group ${head}`);
    const period = textOf(v["period"]);
    if (period === null) return fail("measure sum needs a period (month, quarter, year)");
    if (!isPeriodKind(period)) return fail(`measure sum: unknown period "${period}" (${PERIOD_KINDS.join(", ")})`);
    return { ok: true, value: { kind: "sum", group: head, category: tail, period } };
  }
  if (kind === "holdings") {
    if (tail === null || (head !== "class" && head !== "account")) return fail(`measure holdings must be class.<c> or account.<a> (got "${target}")`);
    if (head === "class" && !config.classes.includes(tail)) return fail(`measure holdings: unknown class "${tail}"`);
    if (head === "account" && !config.accounts.includes(tail)) return fail(`measure holdings: unknown account "${tail}"`);
    return { ok: true, value: { kind: "holdings", by: head, name: tail } };
  }
  if (kind === "share") {
    if (tail === null || head !== "class") return fail(`measure share must be class.<c> (got "${target}")`);
    if (!config.classes.includes(tail)) return fail(`measure share: unknown class "${tail}"`);
    return { ok: true, value: { kind: "share", by: "class", name: tail } };
  }
  // drawdown
  if (tail === null || head !== "account") return fail(`measure drawdown must be account.<a> (got "${target}")`);
  if (!config.accounts.includes(tail)) return fail(`measure drawdown: unknown account "${tail}"`);
  const w = textOf(v["window_days"]);
  const windowDays = w === null ? null : parseIntText(w);
  if (windowDays === null || windowDays <= 0) return fail("measure drawdown needs window_days (positive integer)");
  return { ok: true, value: { kind: "drawdown", by: "account", name: tail, windowDays } };
}

function amountOf(v: YamlValue | undefined, what: string): Parsed<Decimal> {
  const t = textOf(v);
  const d = t === null ? null : parseAmount(t);
  if (d === null) return fail(`${what} must be decimal text`);
  return { ok: true, value: d };
}

export function parseLimit(v: YamlValue | undefined): Parsed<Limit> {
  if (!isMap(v)) return fail("limit must be a mapping");
  const keys = Object.keys(v).sort().join(",");
  if (keys === "value") {
    const a = amountOf(v["value"], "limit value");
    return a.ok ? { ok: true, value: { kind: "value", value: a.value } } : a;
  }
  if (keys === "pct_of,value") {
    const of = textOf(v["pct_of"]);
    if (of !== "income") return fail(`limit pct_of must be income (got "${of ?? ""}")`);
    const a = amountOf(v["value"], "limit value");
    return a.ok ? { ok: true, value: { kind: "pct_of", of: "income", value: a.value } } : a;
  }
  if (keys === "months_of,value") {
    const of = textOf(v["months_of"]);
    if (of !== "expense") return fail(`limit months_of must be expense (got "${of ?? ""}")`);
    const a = amountOf(v["value"], "limit value");
    return a.ok ? { ok: true, value: { kind: "months_of", of: "expense", value: a.value } } : a;
  }
  if (keys === "pct") {
    const a = amountOf(v["pct"], "limit pct");
    return a.ok ? { ok: true, value: { kind: "pct", value: a.value } } : a;
  }
  return fail(`unknown limit {${Object.keys(v).join(", ")}} (value | pct_of income + value | months_of expense + value | pct)`);
}

export function parseMatch(v: YamlValue | undefined, config: Config): Parsed<Match> {
  if (!isMap(v)) return fail("match must be a mapping");
  const allowed = ["tags", "tags_any", "account", "category", "min_amount"];
  const extra = Object.keys(v).filter((k) => !allowed.includes(k));
  if (extra.length > 0) return fail(`match: unknown key ${extra.join(", ")}`);
  const m: Match = { tags: null, tagsAny: null, account: null, category: null, minAmount: null };
  if (v["tags"] !== undefined) {
    m.tags = stringList(v["tags"]);
    if (m.tags === null || m.tags.length === 0) return fail("match tags must be a tag or a list of tags");
  }
  if (v["tags_any"] !== undefined) {
    m.tagsAny = stringList(v["tags_any"]);
    if (m.tagsAny === null || m.tagsAny.length === 0) return fail("match tags_any must be a list of tags");
  }
  if (v["account"] !== undefined) {
    m.account = textOf(v["account"]);
    if (m.account === null || !config.accounts.includes(m.account)) return fail(`match: unknown account "${m.account ?? ""}"`);
  }
  if (v["category"] !== undefined) {
    m.category = textOf(v["category"]);
    const all = Object.values(config.categories).flat();
    if (m.category === null || !all.includes(m.category)) return fail(`match: unknown category "${m.category ?? ""}"`);
  }
  if (v["min_amount"] !== undefined) {
    const a = amountOf(v["min_amount"], "match min_amount");
    if (!a.ok) return a;
    m.minAmount = a.value;
  }
  if (m.tags === null && m.tagsAny === null && m.account === null && m.category === null && m.minAmount === null) {
    return fail("match needs at least one of tags, tags_any, account, category, min_amount");
  }
  return { ok: true, value: m };
}

export function parseBand(v: YamlValue | undefined): Parsed<Band> {
  if (!isMap(v)) return fail("band must be a mapping");
  const keys = Object.keys(v).sort().join(",");
  if (keys !== "max_pct,min_pct") return fail(`band must have min_pct and max_pct (got ${Object.keys(v).join(", ") || "nothing"})`);
  const lo = amountOf(v["min_pct"], "band min_pct");
  if (!lo.ok) return lo;
  const hi = amountOf(v["max_pct"], "band max_pct");
  if (!hi.ok) return hi;
  if (lo.value.gt(hi.value)) return fail("band min_pct must not exceed max_pct");
  return { ok: true, value: { minPct: lo.value, maxPct: hi.value } };
}

function isAmountMeasure(m: Measure): boolean {
  return m.kind === "sum" || m.kind === "holdings";
}

function isAmountLimit(l: Limit): boolean {
  return l.kind !== "pct";
}

function parsePolicy(item: YamlValue, index: number, line: number | null, config: Config): Policy {
  const raw: Record<string, unknown> = isMap(item) ? { ...item } : {};
  const base: Policy = {
    line,
    id: `#${index + 1}`,
    type: "",
    title: "",
    measure: null,
    limit: null,
    match: null,
    band: null,
    period: null,
    status: "unknown",
    reason: null,
    raw,
  };
  if (!isMap(item)) return { ...base, reason: "policy must be a mapping" };
  const id = textOf(item["id"]);
  if (id !== null) base.id = id;
  base.title = textOf(item["title"]) ?? "";
  const type = textOf(item["type"]) ?? "";
  base.type = type;
  if (id === null) return { ...base, reason: "policy has no id" };
  if (!(POLICY_TYPES as readonly string[]).includes(type)) return { ...base, reason: `unknown type "${type}" (${POLICY_TYPES.join(", ")})` };
  const t = type as PolicyType;
  if (t === "cap" || t === "floor" || t === "kill") {
    const m = parseMeasure(item["measure"], config);
    if (!m.ok) return { ...base, reason: m.reason };
    const l = parseLimit(item["limit"]);
    if (!l.ok) return { ...base, reason: l.reason };
    if (isAmountMeasure(m.value) !== isAmountLimit(l.value)) {
      return { ...base, measure: m.value, limit: l.value, reason: `measure ${m.value.kind} and limit ${l.value.kind} do not compare` };
    }
    return { ...base, measure: m.value, limit: l.value, status: "ok" };
  }
  if (t === "routine") {
    const mt = parseMatch(item["match"], config);
    if (!mt.ok) return { ...base, reason: mt.reason };
    const p = textOf(item["period"]);
    if (p === null) return { ...base, match: mt.value, reason: "routine needs a period (month, quarter, year)" };
    if (!isPeriodKind(p)) return { ...base, match: mt.value, reason: `unknown period "${p}" (${PERIOD_KINDS.join(", ")})` };
    return { ...base, match: mt.value, period: p, status: "ok" };
  }
  if (t === "red_line") {
    const mt = parseMatch(item["match"], config);
    if (!mt.ok) return { ...base, reason: mt.reason };
    return { ...base, match: mt.value, status: "ok" };
  }
  // allocation
  const m = parseMeasure(item["measure"], config);
  if (!m.ok) return { ...base, reason: m.reason };
  if (m.value.kind !== "share") return { ...base, measure: m.value, reason: `allocation needs a share measure (got ${m.value.kind})` };
  const b = parseBand(item["band"]);
  if (!b.ok) return { ...base, measure: m.value, reason: b.reason };
  return { ...base, measure: m.value, band: b.value, status: "ok" };
}

/** Parse policies.yml. A file-level fault gives config null and a problem. */
export function parsePolicies(text: string): ParsedPolicies {
  const problems: Problem[] = [];
  if (text.trim() === "") {
    problems.push(makeProblem("EMPTY-FILE", "policies.yml", null, "policies.yml is empty; it must declare base_currency, accounts, categories, snapshot_max_age_days and policies"));
    return { config: null, problems, count: 0 };
  }
  const loaded = loadYaml(text);
  if (!loaded.ok) {
    problems.push(makeProblem("BAD-YAML", "policies.yml", loaded.line, loaded.reason));
    return { config: null, problems, count: 0 };
  }
  const doc = loaded.value;
  if (!isMap(doc)) {
    problems.push(makeProblem("BAD-FILE", "policies.yml", null, "policies.yml must be a mapping"));
    return { config: null, problems, count: 0 };
  }
  const baseCurrency = textOf(doc["base_currency"]);
  if (baseCurrency === null || !isCurrencyCode(baseCurrency)) {
    problems.push(makeProblem("BAD-BASE-CURRENCY", "policies.yml", null, "base_currency must be an ISO-4217 code"));
    return { config: null, problems, count: 0 };
  }
  const accounts = doc["accounts"] === undefined ? [] : stringList(doc["accounts"]);
  if (accounts === null) {
    problems.push(makeProblem("BAD-ACCOUNTS", "policies.yml", null, "accounts must be a list of names"));
    return { config: null, problems, count: 0 };
  }
  const categories: Record<string, string[]> = {};
  const cats = doc["categories"];
  if (cats !== undefined && !isNullish(cats)) {
    if (!isMap(cats)) {
      problems.push(makeProblem("BAD-CATEGORIES", "policies.yml", null, "categories must map a group to a list of names"));
      return { config: null, problems, count: 0 };
    }
    for (const group of Object.keys(cats)) {
      const list = isNullish(cats[group]) ? [] : stringList(cats[group]);
      if (list === null) {
        problems.push(makeProblem("BAD-CATEGORIES", "policies.yml", null, `categories.${group} must be a list of names`));
        return { config: null, problems, count: 0 };
      }
      categories[group] = list;
    }
  }
  let classes: string[] = [...DEFAULT_CLASSES];
  if (doc["classes"] !== undefined && !isNullish(doc["classes"])) {
    const list = stringList(doc["classes"]);
    if (list === null) {
      problems.push(makeProblem("BAD-CLASSES", "policies.yml", null, "classes must be a list of names"));
      return { config: null, problems, count: 0 };
    }
    classes = list;
  }
  let snapshotMaxAgeDays: number | null = null;
  const age = textOf(doc["snapshot_max_age_days"]);
  if (age !== null) {
    snapshotMaxAgeDays = parseIntText(age);
    if (snapshotMaxAgeDays === null) {
      problems.push(makeProblem("BAD-SNAPSHOT-AGE", "policies.yml", null, "snapshot_max_age_days must be a whole number of days"));
    }
  } else {
    problems.push(makeProblem("NO-SNAPSHOT-AGE", "policies.yml", null, "snapshot_max_age_days is not declared; holdings cannot be judged stale or fresh"));
  }
  const config: Config = {
    version: textOf(doc["version"]),
    baseCurrency,
    accounts,
    categories,
    classes,
    snapshotMaxAgeDays,
    policies: [],
  };
  const list = doc["policies"];
  const items: YamlValue[] = list === undefined || isNullish(list) ? [] : isSeq(list) ? list : [];
  if (list !== undefined && !isNullish(list) && !isSeq(list)) {
    problems.push(makeProblem("BAD-POLICIES", "policies.yml", null, "policies must be a list"));
    return { config: null, problems, count: 0 };
  }
  const lines = keyedItemLines(text, "policies");
  const seen = new Set<string>();
  items.forEach((item, i) => {
    const line = lines.length === items.length ? (lines[i] as number) : null;
    const p = parsePolicy(item, i, line, config);
    if (seen.has(p.id)) problems.push(makeProblem("DUP-ID", "policies.yml", line, `policy id ${p.id} is declared twice`));
    seen.add(p.id);
    if (p.status === "unknown") problems.push(makeProblem("UNKNOWN-POLICY", "policies.yml", line, `${p.id}: ${p.reason ?? "unknown"}`));
    config.policies.push(p);
  });
  return { config, problems, count: config.policies.length };
}

// ---- declared texts (as the CLI prints them) ------------------------------

export function measureText(m: Measure): string {
  if (m.kind === "sum") return `sum ${m.group}${m.category === null ? "" : "." + m.category} per ${m.period}`;
  if (m.kind === "holdings") return `holdings ${m.by}.${m.name}`;
  if (m.kind === "share") return `share class.${m.name}`;
  return `drawdown account.${m.name} over ${m.windowDays} days`;
}

export function limitText(l: Limit, baseCurrency: string): string {
  if (l.kind === "value") return `${fmt(l.value)} ${baseCurrency}`;
  if (l.kind === "pct_of") return `${fmt(l.value)}% of income`;
  if (l.kind === "months_of") return `${fmt(l.value)} months of expense`;
  return `${fmt(l.value)}%`;
}

export function matchText(m: Match): string {
  const parts: string[] = [];
  if (m.tags !== null) parts.push(`tags ${m.tags.join(",")}`);
  if (m.tagsAny !== null) parts.push(`any tag of ${m.tagsAny.join(",")}`);
  if (m.account !== null) parts.push(`account ${m.account}`);
  if (m.category !== null) parts.push(`category ${m.category}`);
  if (m.minAmount !== null) parts.push(`amount >= ${fmt(m.minAmount)}`);
  return parts.join(", ");
}

export function bandText(b: Band): string {
  return `${fmt(b.minPct)}%..${fmt(b.maxPct)}%`;
}

// ---- serializer -----------------------------------------------------------

const POLICY_KEY_ORDER = ["id", "type", "title", "measure", "limit", "match", "band", "period"];

function policyEntryValue(key: string, v: unknown): string {
  if (v === null || v === undefined) return "null";
  if (key === "title" || key === "id") return typeof v === "string" ? yStr(v) : yFlow(v as YamlValue);
  if (typeof v === "string") return yPlainOrStr(v);
  return yFlow(v as YamlValue);
}

/** The raw mapping of a policy as declared or as the UI built it. */
export function policyRaw(p: Policy): Record<string, unknown> {
  return p.raw;
}

/**
 * policies.yml text in the reference style: block top level, flow lists and
 * flow maps inside each policy. Round-trips a parsed file semantically.
 */
export function serializePolicies(config: Config): string {
  const lines: string[] = [];
  if (config.version !== null) lines.push(`version: ${yPlainOrStr(config.version)}`);
  lines.push(`base_currency: ${config.baseCurrency}`);
  lines.push(`accounts: ${yFlowSeq(config.accounts.map(yStr))}`);
  const groups = Object.keys(config.categories);
  if (groups.length === 0) lines.push("categories: {}");
  else {
    lines.push("categories:");
    for (const g of groups) lines.push(`  ${yStr(g)}: ${yFlowSeq((config.categories[g] as string[]).map(yStr))}`);
  }
  if (config.classes.join(",") !== DEFAULT_CLASSES.join(",")) lines.push(`classes: ${yFlowSeq(config.classes.map(yStr))}`);
  if (config.snapshotMaxAgeDays !== null) lines.push(`snapshot_max_age_days: ${config.snapshotMaxAgeDays}`);
  if (config.policies.length === 0) lines.push("policies: []");
  else {
    lines.push("policies:");
    for (const p of config.policies) {
      const raw = policyRaw(p);
      const keys = [...POLICY_KEY_ORDER.filter((k) => k in raw), ...Object.keys(raw).filter((k) => !POLICY_KEY_ORDER.includes(k))];
      let first = true;
      for (const k of keys) {
        const prefix = first ? "  - " : "    ";
        lines.push(`${prefix}${yStr(k)}: ${policyEntryValue(k, raw[k])}`);
        first = false;
      }
    }
  }
  return lines.join("\n") + "\n";
}
