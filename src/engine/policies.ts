// policies.yml: base currency, accounts, categories, classes, snapshot age,
// and the policy list (reference engine ADR section 5, qayd/policies.py,
// ported one to one). A policy whose type, measure, limit, match or band
// is not a declared shape is kept with status "unknown" and the reason;
// its verdict is `unknown` (A2, A5: never guessed). A measure or match that
// names an undeclared category, account or class is both a file problem
// and an unknown policy. Every problem here is class invalid, which makes
// the household unreadable (exit 3) as in the CLI.
import { fileProblem, INVALID, problem } from "./loader";
import { PERIOD_KINDS, type PeriodKind } from "./periods";
import { intOf, isInt, isList, isMap, isNumber, isStr, PyDec, pyRepr, pyStr, toNum, type PyMap, type PyValue } from "./py";
import { DEFAULT_CLASSES, POLICY_TYPES, type Band, type Config, type Limit, type Match, type Measure, type ParsedPolicies, type Policy, type Problem } from "./types";
import { loadYaml, yFlow, yFlowSeq, yStr } from "./yaml";

const REQUIRED_GROUPS = ["income", "expense"];
const NAME_RE = /^[A-Za-z0-9_][A-Za-z0-9_.-]*\n?$/;
const CURRENCY_RE = /^[A-Z]{3}\n?$/;

const NEEDS: Record<string, string[]> = {
  cap: ["measure", "limit"],
  floor: ["measure", "limit"],
  routine: ["match", "period"],
  red_line: ["match"],
  kill: ["measure", "limit"],
  allocation: ["measure", "band"],
};
const LIMITS: Record<string, string[]> = {
  cap: ["value", "pct_of", "months_of"],
  floor: ["value", "pct_of", "months_of"],
  kill: ["pct"],
};

function isName(v: PyValue | undefined): v is string {
  return typeof v === "string" && NAME_RE.test(v);
}

function isKind(v: PyValue | undefined): v is PeriodKind {
  return typeof v === "string" && (PERIOD_KINDS as readonly string[]).includes(v);
}

function sortedKeys(keys: Iterable<string>): string {
  return [...keys].sort().join(", ");
}

/** Python's `x == 1` for a loaded value, bool excluded by the caller. */
function isOne(v: PyValue | undefined): boolean {
  return (isInt(v) || v instanceof PyDec) && v.value.eq(1);
}

class Check {
  readonly problems: Problem[] = [];
  constructor(readonly file: string) {}
  add(line: number, code: string, field: string, reason: string): void {
    this.problems.push(problem(this.file, line, code, reason, INVALID, { field }));
  }
}

interface Cfg {
  accounts: string[];
  categories: Record<string, string[]>;
  classes: string[];
  allCategories: string[];
}

type Checked<T> = { value: T; reason: null } | { value: null; reason: string };

function bad<T>(reason: string): Checked<T> {
  return { value: null, reason };
}

function ok<T>(value: T): Checked<T> {
  return { value, reason: null };
}

function validateMeasure(measure: PyValue | undefined, cfg: Cfg, chk: Check, line: number, field: string): Checked<Measure> {
  if (!isMap(measure)) return bad("measure must be a mapping");
  const keys = Object.keys(measure);
  const kinds = keys.filter((k) => k === "sum" || k === "holdings" || k === "share" || k === "drawdown");
  if (kinds.length !== 1) return bad(`measure must have exactly one of sum, holdings, share, drawdown (got ${sortedKeys(keys) || "nothing"})`);
  const kind = kinds[0] as string;
  const target = measure[kind];
  if (!isStr(target) || target === "") return bad(`measure.${kind} must be text`);
  const dot = target.indexOf(".");
  const head = dot < 0 ? target : target.slice(0, dot);
  const tail = dot < 0 ? "" : target.slice(dot + 1);
  if (kind === "sum") {
    const extra = keys.filter((k) => k !== "sum" && k !== "period");
    if (extra.length > 0) return bad(`measure has unexpected keys: ${sortedKeys(extra)}`);
    if (!("period" in measure)) return bad("measure.period is missing (month, quarter or year)");
    const period = measure["period"];
    if (!isKind(period)) return bad(`measure.period ${pyRepr(period)} is not month, quarter or year`);
    if (!(head in cfg.categories)) {
      chk.add(line, "UNDECLARED-CATEGORY", field + ".sum", `group ${pyRepr(head)} is not declared`);
      return bad(`measure.sum names undeclared group ${pyRepr(head)}`);
    }
    if (tail !== "" && (tail.includes(".") || !(cfg.categories[head] as string[]).includes(tail))) {
      chk.add(line, "UNDECLARED-CATEGORY", field + ".sum", `category ${pyRepr(tail)} is not declared under ${pyRepr(head)}`);
      return bad(`measure.sum names undeclared category ${pyRepr(target)}`);
    }
    return ok({ kind: "sum", group: head, category: tail === "" ? null : tail, period });
  }
  const extra = keys.filter((k) => k !== kind && !(kind === "drawdown" && k === "window_days"));
  if (extra.length > 0) return bad(`measure has unexpected keys: ${sortedKeys(extra)}`);
  if (kind === "holdings" && head !== "class" && head !== "account") return bad("measure.holdings must be class.<c> or account.<a>");
  if (kind === "share" && head !== "class") return bad("measure.share must be class.<c>");
  if (kind === "drawdown" && head !== "account") return bad("measure.drawdown must be account.<a>");
  if (tail === "" || tail.includes(".")) return bad(`measure.${kind} ${pyRepr(target)} is malformed`);
  if (head === "class" && !cfg.classes.includes(tail)) {
    chk.add(line, "UNDECLARED-CLASS", `${field}.${kind}`, `class ${pyRepr(tail)} is not declared`);
    return bad(`measure.${kind} names undeclared class ${pyRepr(tail)}`);
  }
  if (head === "account" && !cfg.accounts.includes(tail)) {
    chk.add(line, "UNDECLARED-ACCOUNT", `${field}.${kind}`, `account ${pyRepr(tail)} is not declared`);
    return bad(`measure.${kind} names undeclared account ${pyRepr(tail)}`);
  }
  if (kind === "holdings") return ok({ kind: "holdings", by: head as "class" | "account", name: tail });
  if (kind === "share") return ok({ kind: "share", by: "class", name: tail });
  const window = measure["window_days"];
  if (!isInt(window) || window.value.lt(1)) return bad("measure.window_days must be a positive integer");
  return ok({ kind: "drawdown", by: "account", name: tail, windowDays: intOf(window) });
}

function validateLimit(limit: PyValue | undefined, allowed: string[]): Checked<Limit> {
  if (!isMap(limit)) return bad("limit must be a mapping");
  const keys = Object.keys(limit).sort().join(",");
  if (keys === "value" && allowed.includes("value")) {
    if (!isNumber(limit["value"])) return bad("limit.value must be a number");
    return ok({ kind: "value", value: toNum(limit["value"] as PyValue) });
  }
  if (keys === "pct_of,value" && allowed.includes("pct_of")) {
    if (limit["pct_of"] !== "income") return bad("limit.pct_of must be income");
    if (!isNumber(limit["value"])) return bad("limit.value must be a number");
    return ok({ kind: "pct_of", of: "income", value: toNum(limit["value"] as PyValue) });
  }
  if (keys === "months_of,value" && allowed.includes("months_of")) {
    if (limit["months_of"] !== "expense") return bad("limit.months_of must be expense");
    if (!isNumber(limit["value"])) return bad("limit.value must be a number");
    return ok({ kind: "months_of", of: "expense", value: toNum(limit["value"] as PyValue) });
  }
  if (keys === "pct" && allowed.includes("pct")) {
    if (!isNumber(limit["pct"])) return bad("limit.pct must be a number");
    return ok({ kind: "pct", value: toNum(limit["pct"] as PyValue) });
  }
  return bad(`limit must be one of ${allowed.map((a) => `{${a}}`).join(", ")} (got keys: ${sortedKeys(Object.keys(limit)) || "nothing"})`);
}

function validateMatch(match: PyValue | undefined, cfg: Cfg, chk: Check, line: number, field: string): Checked<Match> {
  if (!isMap(match)) return bad("match must be a mapping");
  const keys = Object.keys(match);
  const extra = keys.filter((k) => !["tags", "tags_any", "account", "category", "min_amount"].includes(k));
  if (extra.length > 0) return bad(`match has unexpected keys: ${sortedKeys(extra)}`);
  if (keys.length === 0) return bad("match needs at least one of tags, tags_any, account, category, min_amount");
  const out: Match = { tags: null, tagsAny: null, account: null, category: null, minAmount: null };
  if ("tags" in match) {
    let tags = match["tags"];
    if (isStr(tags)) tags = [tags];
    if (!isList(tags) || tags.length === 0 || !tags.every(isName)) return bad("match.tags must be a tag or a list of tags");
    out.tags = tags as string[];
  }
  if ("tags_any" in match) {
    const tags = match["tags_any"];
    if (!isList(tags) || tags.length === 0 || !tags.every(isName)) return bad("match.tags_any must be a non-empty list of tags");
    out.tagsAny = tags as string[];
  }
  if ("account" in match) {
    const account = match["account"];
    if (!isStr(account)) return bad("match.account must be text");
    if (!cfg.accounts.includes(account)) {
      chk.add(line, "UNDECLARED-ACCOUNT", field + ".account", `account ${pyRepr(account)} is not declared`);
      return bad(`match.account names undeclared account ${pyRepr(account)}`);
    }
    out.account = account;
  }
  if ("category" in match) {
    const category = match["category"];
    if (!isStr(category)) return bad("match.category must be text");
    if (!cfg.allCategories.includes(category)) {
      chk.add(line, "UNDECLARED-CATEGORY", field + ".category", `category ${pyRepr(category)} is not declared`);
      return bad(`match.category names undeclared category ${pyRepr(category)}`);
    }
    out.category = category;
  }
  if ("min_amount" in match) {
    if (!isNumber(match["min_amount"])) return bad("match.min_amount must be a number");
    out.minAmount = toNum(match["min_amount"] as PyValue);
  }
  return ok(out);
}

function validateBand(band: PyValue | undefined): Checked<Band> {
  if (!isMap(band)) return bad("band must be a mapping");
  if (Object.keys(band).sort().join(",") !== "max_pct,min_pct") return bad("band must have exactly min_pct and max_pct");
  if (!isNumber(band["min_pct"]) || !isNumber(band["max_pct"])) return bad("band.min_pct and band.max_pct must be numbers");
  const lo = toNum(band["min_pct"] as PyValue);
  const hi = toNum(band["max_pct"] as PyValue);
  if (!(lo.value.gte(0) && lo.value.lte(hi.value) && hi.value.lte(100))) return bad("band must satisfy 0 <= min_pct <= max_pct <= 100");
  return ok({ minPct: lo, maxPct: hi });
}

function validatePolicy(raw: PyValue, index: number, cfg: Cfg, chk: Check, defaultLine: number, lineOf: (v: PyValue | undefined) => number | null): Policy | null {
  const line = lineOf(raw) ?? defaultLine;
  const field = `policies[${index}]`;
  if (!isMap(raw)) {
    chk.add(line, "BAD-FIELD", field, "policy must be a mapping");
    return null;
  }
  const pid = raw["id"];
  if (!isName(pid)) {
    chk.add(line, "BAD-FIELD", field + ".id", "policy id is missing or not a plain name");
    return null;
  }
  const ptype = raw["type"];
  let title: PyValue | undefined = "title" in raw ? raw["title"] : pid;
  if (!isStr(title) || title === "") {
    chk.add(line, "BAD-FIELD", field + ".title", "title must be non-empty text");
    title = pid;
  }
  const base: Policy = {
    id: pid,
    type: pyStr(ptype),
    title,
    measure: null,
    limit: null,
    match: null,
    period: null,
    band: null,
    status: "unknown",
    reason: null,
    line,
    file: chk.file,
    cite: `${chk.file}:${line}`,
    raw,
  };
  const unknownPolicy = (reason: string): Policy => ({ ...base, reason });
  if (!isStr(ptype) || !(POLICY_TYPES as readonly string[]).includes(ptype)) {
    return unknownPolicy(`type ${pyRepr(ptype)} is not one of ${POLICY_TYPES.join(", ")}`);
  }
  const needs = NEEDS[ptype] as string[];
  const allowed = new Set([...needs, "id", "type", "title"]);
  const extra = Object.keys(raw).filter((k) => !allowed.has(k));
  if (extra.length > 0) return unknownPolicy(`unexpected keys for type ${ptype}: ${sortedKeys(extra)}`);
  for (const need of needs) {
    if (!(need in raw)) return unknownPolicy(`type ${ptype} needs ${needs.join(" and ")}`);
  }
  let measure: Measure | null = null;
  let limit: Limit | null = null;
  let match: Match | null = null;
  let period: PeriodKind | null = null;
  let band: Band | null = null;
  if ("measure" in raw) {
    const m = validateMeasure(raw["measure"], cfg, chk, lineOf(raw["measure"]) ?? line, field + ".measure");
    if (m.reason !== null) return unknownPolicy(m.reason);
    measure = m.value;
    if (ptype === "kill" && measure.kind !== "drawdown") return unknownPolicy("kill needs a drawdown measure");
    if (ptype === "allocation" && measure.kind !== "share") return unknownPolicy("allocation needs a share measure");
  }
  if ("limit" in raw) {
    const l = validateLimit(raw["limit"], LIMITS[ptype] as string[]);
    if (l.reason !== null) return unknownPolicy(l.reason);
    limit = l.value;
  }
  if ("match" in raw) {
    const m = validateMatch(raw["match"], cfg, chk, lineOf(raw["match"]) ?? line, field + ".match");
    if (m.reason !== null) return unknownPolicy(m.reason);
    match = m.value;
  }
  if ("period" in raw) {
    const p = raw["period"];
    if (!isKind(p)) return unknownPolicy(`period ${pyRepr(p)} is not month, quarter or year`);
    period = p;
  }
  if ("band" in raw) {
    const b = validateBand(raw["band"]);
    if (b.reason !== null) return unknownPolicy(b.reason);
    band = b.value;
  }
  return { ...base, type: ptype, measure, limit, match, period, band, status: "ok" };
}

function names(value: PyValue | undefined, chk: Check, line: number, field: string, what: string): string[] {
  if (!isList(value) || value.length === 0) {
    chk.add(line, "BAD-FIELD", field, `${what} must be a non-empty list`);
    return [];
  }
  const out: string[] = [];
  for (const item of value) {
    if (!isName(item)) chk.add(line, "BAD-FIELD", field, `${what} entry ${pyRepr(item)} is not a plain name`);
    else if (out.includes(item)) chk.add(line, "DUP-ID", field, `${what} ${pyRepr(item)} is declared twice`);
    else out.push(item);
  }
  return out;
}

function build(doc: PyMap, top: number, chk: Check, lineOf: (v: PyValue | undefined) => number | null): Config {
  const known = new Set(["version", "base_currency", "accounts", "categories", "classes", "snapshot_max_age_days", "policies"]);
  for (const key of Object.keys(doc).filter((k) => !known.has(k)).sort()) {
    chk.add(top, "BAD-FIELD", key, `unknown top-level key ${pyRepr(key)}`);
  }
  let version: number | null = 1;
  if (!isOne(doc["version"])) {
    chk.add(top, "BAD-FIELD", "version", `version must be 1 (got ${pyRepr(doc["version"])})`);
    version = null;
  }
  let base: string | null = null;
  if (!("base_currency" in doc)) chk.add(top, "MISSING-FIELD", "base_currency", "base_currency is missing");
  else {
    const b = doc["base_currency"];
    if (!isStr(b) || !CURRENCY_RE.test(b)) chk.add(top, "BAD-FIELD", "base_currency", "base_currency must be a 3-letter ISO-4217 code");
    else base = b;
  }
  const accounts = names(doc["accounts"], chk, top, "accounts", "accounts");
  const categories: Record<string, string[]> = {};
  const cats = doc["categories"];
  if (!isMap(cats) || Object.keys(cats).length === 0) {
    chk.add(top, "BAD-FIELD", "categories", "categories must be a mapping of group -> list of names");
  } else {
    const catLine = lineOf(cats) ?? top;
    const seen = new Map<string, string>();
    for (const group of Object.keys(cats)) {
      if (!isName(group)) {
        chk.add(catLine, "BAD-FIELD", "categories", `group ${pyRepr(group)} is not a plain name`);
        continue;
      }
      const list = names(cats[group], chk, catLine, "categories." + group, "categories." + group);
      const kept: string[] = [];
      for (const name of list) {
        const prior = seen.get(name);
        if (prior !== undefined) {
          chk.add(catLine, "DUP-ID", "categories." + group, `category ${pyRepr(name)} is declared under both ${pyRepr(prior)} and ${pyRepr(group)}`);
        } else {
          seen.set(name, group);
          kept.push(name);
        }
      }
      categories[group] = kept;
    }
    for (const group of REQUIRED_GROUPS) {
      if (!(group in categories)) chk.add(catLine, "MISSING-FIELD", "categories." + group, `categories must declare the group ${pyRepr(group)}`);
    }
  }
  const classes = "classes" in doc ? names(doc["classes"], chk, top, "classes", "classes") : [...DEFAULT_CLASSES];
  let age: number | null = null;
  if (!("snapshot_max_age_days" in doc)) chk.add(top, "MISSING-FIELD", "snapshot_max_age_days", "snapshot_max_age_days is missing");
  else {
    const a = doc["snapshot_max_age_days"];
    if (!isInt(a) || a.value.lt(1)) chk.add(top, "BAD-FIELD", "snapshot_max_age_days", "snapshot_max_age_days must be a positive integer");
    else age = intOf(a);
  }
  const cfg: Cfg = { accounts, categories, classes, allCategories: Object.values(categories).flat() };
  const policies: Policy[] = [];
  const list = doc["policies"];
  if (!isList(list) || list.length === 0) {
    chk.add(top, "EMPTY-POLICIES", "policies", "policies must be a non-empty list");
  } else {
    const ids = new Map<string, number>();
    list.forEach((raw, index) => {
      const p = validatePolicy(raw, index, cfg, chk, top, lineOf);
      if (p === null) return;
      const prior = ids.get(p.id);
      if (prior !== undefined) {
        chk.add(p.line, "DUP-ID", `policies[${index}].id`, `policy id ${pyRepr(p.id)} is already used at line ${prior}`);
        return;
      }
      ids.set(p.id, p.line);
      policies.push(p);
    });
  }
  return { version, baseCurrency: base, accounts, categories, classes, snapshotMaxAgeDays: age, policies, file: chk.file };
}

/** Parse policies.yml (`null`: the file does not exist). Never throws. */
export function parsePolicies(text: string | null, file = "policies.yml"): ParsedPolicies {
  const fatal = fileProblem(text, file);
  if (fatal) return { config: null, problems: [fatal] };
  const loaded = loadYaml(text as string);
  if (!loaded.ok) return { config: null, problems: [problem(file, loaded.line, "BAD-YAML", loaded.reason)] };
  if (loaded.value === null) return { config: null, problems: [problem(file, 0, "FILE-EMPTY", "file holds no YAML document")] };
  const chk = new Check(file);
  const doc = loaded.value;
  if (!isMap(doc)) {
    chk.add(1, "BAD-SHAPE", "", "policies.yml must be a mapping at the top level");
    return { config: null, problems: chk.problems };
  }
  try {
    const config = build(doc, loaded.lineOf(doc) ?? 1, chk, loaded.lineOf);
    return { config, problems: chk.problems };
  } catch (e) {
    chk.add(0, "INTERNAL", "", `loader failed: ${e instanceof Error ? `${e.name}: ${e.message}` : String(e)}`);
    return { config: null, problems: chk.problems };
  }
}

export function policyIds(config: Config): string[] {
  return config.policies.map((p) => p.id);
}

export function policyById(config: Config, id: string): Policy | null {
  return config.policies.find((p) => p.id === id) ?? null;
}

// ---- declared texts (as the CLI prints them) ------------------------------

export function measureText(m: Measure | null): string {
  if (m === null) return "?";
  if (m.kind === "sum") return `sum ${m.group}${m.category === null ? "" : "." + m.category} per ${m.period}`;
  if (m.kind === "drawdown") return `drawdown ${m.by}.${m.name} over ${m.windowDays} days`;
  return `${m.kind} ${m.by}.${m.name}`;
}

export function limitText(l: Limit | null, baseCurrency = ""): string {
  if (l === null) return "?";
  const v = l.value.text;
  if (l.kind === "value") return (v + " " + baseCurrency).trim();
  if (l.kind === "pct_of") return `${v}% of ${l.of}`;
  if (l.kind === "months_of") return `${v} months of ${l.of}`;
  return v + "%";
}

export function bandText(b: Band | null): string {
  if (b === null) return "?";
  return `${b.minPct.text}%..${b.maxPct.text}%`;
}

export function matchText(m: Match | null): string {
  if (m === null) return "?";
  const parts: string[] = [];
  if (m.tags !== null) parts.push("tags " + m.tags.join(";"));
  if (m.tagsAny !== null) parts.push("any tag of " + m.tagsAny.join(","));
  if (m.account !== null) parts.push("account " + m.account);
  if (m.category !== null) parts.push("category " + m.category);
  if (m.minAmount !== null) parts.push("amount >= " + m.minAmount.text);
  return parts.join(", ");
}

// ---- serializer -----------------------------------------------------------

const POLICY_KEY_ORDER = ["id", "type", "title", "measure", "limit", "match", "band", "period"];

/**
 * policies.yml text in the reference style: block top level, flow lists and
 * flow maps inside each policy, numbers as written. Round-trips a parsed
 * file semantically (comments are not kept).
 */
export function serializePolicies(config: Config): string {
  const lines: string[] = [];
  if (config.version !== null) lines.push(`version: ${config.version}`);
  if (config.baseCurrency !== null) lines.push(`base_currency: ${config.baseCurrency}`);
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
    for (const p of config.policies) lines.push(...policyBlock(p.raw));
  }
  return lines.join("\n") + "\n";
}

/** One policy as the lines of a block-sequence item. */
export function policyBlock(raw: PyMap): string[] {
  const keys = [...POLICY_KEY_ORDER.filter((k) => k in raw), ...Object.keys(raw).filter((k) => !POLICY_KEY_ORDER.includes(k))];
  return keys.map((k, i) => `${i === 0 ? "  - " : "    "}${yStr(k)}: ${yFlow(raw[k])}`);
}
