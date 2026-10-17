// The policy forms' model: a draft (what the form shows) to and from the
// YAML mapping the engine reads, every field of the engine's declared
// shapes (reference engine ADR section 5). The engine is the validator:
// the edited policies.yml is parsed and the policy must come back `ok`
// with no new problem, else the change is refused with the engine's reason.
import { D } from "../engine/decimal";
import { parsePolicies, policyBlock } from "../engine/policies";
import type { PeriodKind } from "../engine/periods";
import { PyDec, PyInt, type PyMap, type PyValue } from "../engine/py";
import type { Config, Policy, PolicyType, Problem } from "../engine/types";
import { addPolicy, removePolicy, replacePolicy } from "./textEdit";

export type MeasureKind = "sum" | "holdings" | "share" | "drawdown";
export type LimitKind = "value" | "pct_of" | "months_of" | "pct";

export interface PolicyDraft {
  id: string;
  title: string;
  type: PolicyType;
  measureKind: MeasureKind;
  sumGroup: string;
  /** "" = the whole group */
  sumCategory: string;
  sumPeriod: PeriodKind;
  holdingsBy: "class" | "account";
  holdingsName: string;
  shareClass: string;
  drawdownAccount: string;
  windowDays: string;
  limitKind: LimitKind;
  limitValue: string;
  /** `;`-separated */
  tags: string;
  tagsAny: string;
  matchAccount: string;
  matchCategory: string;
  minAmount: string;
  period: PeriodKind;
  minPct: string;
  maxPct: string;
}

/** The limits each type accepts (the engine's _LIMITS). */
export const LIMITS_OF: Partial<Record<PolicyType, LimitKind[]>> = {
  cap: ["value", "pct_of", "months_of"],
  floor: ["value", "pct_of", "months_of"],
  kill: ["pct"],
};

export const MEASURES_OF: Partial<Record<PolicyType, MeasureKind[]>> = {
  cap: ["sum", "holdings", "share", "drawdown"],
  floor: ["sum", "holdings", "share", "drawdown"],
  kill: ["drawdown"],
  allocation: ["share"],
};

export function blankDraft(config: Config, type: PolicyType = "cap"): PolicyDraft {
  const groups = Object.keys(config.categories);
  return {
    id: "",
    title: "",
    type,
    measureKind: type === "kill" ? "drawdown" : type === "allocation" ? "share" : "sum",
    sumGroup: groups.includes("expense") ? "expense" : (groups[0] ?? ""),
    sumCategory: "",
    sumPeriod: "month",
    holdingsBy: "class",
    holdingsName: config.classes[0] ?? "",
    shareClass: config.classes.includes("equity") ? "equity" : (config.classes[0] ?? ""),
    drawdownAccount: config.accounts[0] ?? "",
    windowDays: "90",
    limitKind: type === "kill" ? "pct" : "value",
    limitValue: "",
    tags: "",
    tagsAny: "",
    matchAccount: "",
    matchCategory: "",
    minAmount: "",
    period: "month",
    minPct: "",
    maxPct: "",
  };
}

/** The draft of an accepted policy (an unknown one has no draft). */
export function draftOf(p: Policy, config: Config): PolicyDraft | null {
  if (p.status !== "ok") return null;
  const d = blankDraft(config, p.type as PolicyType);
  d.id = p.id;
  d.title = p.title;
  const m = p.measure;
  if (m) {
    d.measureKind = m.kind;
    if (m.kind === "sum") {
      d.sumGroup = m.group;
      d.sumCategory = m.category ?? "";
      d.sumPeriod = m.period;
    } else if (m.kind === "holdings") {
      d.holdingsBy = m.by;
      d.holdingsName = m.name;
    } else if (m.kind === "share") d.shareClass = m.name;
    else {
      d.drawdownAccount = m.name;
      d.windowDays = String(m.windowDays);
    }
  }
  if (p.limit) {
    d.limitKind = p.limit.kind;
    d.limitValue = p.limit.value.text;
  }
  if (p.match) {
    d.tags = (p.match.tags ?? []).join(";");
    d.tagsAny = (p.match.tagsAny ?? []).join(";");
    d.matchAccount = p.match.account ?? "";
    d.matchCategory = p.match.category ?? "";
    d.minAmount = p.match.minAmount?.text ?? "";
  }
  if (p.period) d.period = p.period;
  if (p.band) {
    d.minPct = p.band.minPct.text;
    d.maxPct = p.band.maxPct.text;
  }
  return d;
}

/** A number as YAML writes it plainly (int or decimal), else the text as typed for the engine to judge. */
function number(text: string): PyValue {
  const t = text.trim();
  if (/^-?\d+$/.test(t)) return new PyInt(D(t), t);
  if (/^-?\d+\.\d+$/.test(t)) return new PyDec(D(t), t, t);
  return t;
}

function tagList(text: string): string[] {
  return text === "" ? [] : text.split(";").map((x) => x.trim());
}

/** The YAML mapping of a draft, keys in the reference order. */
export function rawOf(d: PolicyDraft): PyMap {
  const raw: PyMap = { id: d.id.trim(), type: d.type, title: d.title };
  const measure = (): PyMap => {
    if (d.measureKind === "sum") return { sum: d.sumCategory ? `${d.sumGroup}.${d.sumCategory}` : d.sumGroup, period: d.sumPeriod };
    if (d.measureKind === "holdings") return { holdings: `${d.holdingsBy}.${d.holdingsName}` };
    if (d.measureKind === "share") return { share: `class.${d.shareClass}` };
    return { drawdown: `account.${d.drawdownAccount}`, window_days: number(d.windowDays) };
  };
  const limit = (): PyMap => {
    if (d.limitKind === "pct_of") return { pct_of: "income", value: number(d.limitValue) };
    if (d.limitKind === "months_of") return { months_of: "expense", value: number(d.limitValue) };
    if (d.limitKind === "pct") return { pct: number(d.limitValue) };
    return { value: number(d.limitValue) };
  };
  const match = (): PyMap => {
    const m: PyMap = {};
    const tags = tagList(d.tags);
    const any = tagList(d.tagsAny);
    if (tags.length === 1) m["tags"] = tags[0] as string;
    else if (tags.length > 1) m["tags"] = tags;
    if (any.length > 0) m["tags_any"] = any;
    if (d.matchAccount) m["account"] = d.matchAccount;
    if (d.matchCategory) m["category"] = d.matchCategory;
    if (d.minAmount.trim() !== "") m["min_amount"] = number(d.minAmount);
    return m;
  };
  if (d.type === "cap" || d.type === "floor" || d.type === "kill") {
    raw["measure"] = measure();
    raw["limit"] = limit();
  } else if (d.type === "allocation") {
    raw["measure"] = measure();
    raw["band"] = { min_pct: number(d.minPct), max_pct: number(d.maxPct) };
  } else if (d.type === "routine") {
    raw["match"] = match();
    raw["period"] = d.period;
  } else raw["match"] = match();
  return raw;
}

export type Change = { ok: true; text: string; id: string } | { ok: false; problems: Problem[]; reason: string | null; layout: boolean };

function problemKey(p: Problem): string {
  return `${p.code}|${p.field ?? ""}|${p.reason}`;
}

/**
 * Judge an edited policies.yml: the policy `id` must be accepted (`ok`)
 * and no problem may appear that was not there before.
 */
function judge(before: string, after: string, id: string | null): Change {
  const old = new Set(parsePolicies(before).problems.map(problemKey));
  const parsed = parsePolicies(after);
  const fresh = parsed.problems.filter((p) => !old.has(problemKey(p)));
  const p = id === null ? null : (parsed.config?.policies.find((x) => x.id === id) ?? null);
  if (fresh.length > 0) return { ok: false, problems: fresh, reason: p?.reason ?? null, layout: false };
  if (id !== null && (p === null || p.status !== "ok")) return { ok: false, problems: [], reason: p?.reason ?? "the policy was not read back", layout: false };
  return { ok: true, text: after, id: id ?? "" };
}

/** Add a policy from a draft. */
export function addFromDraft(text: string, config: Config, d: PolicyDraft): Change {
  const e = addPolicy(text, policyBlock(rawOf(d)), config.policies.length);
  if (!e.ok) return { ok: false, problems: [], reason: null, layout: true };
  return judge(text, e.text, rawOf(d)["id"] as string);
}

/** Replace policy `index` with a draft. */
export function editFromDraft(text: string, config: Config, index: number, d: PolicyDraft): Change {
  const e = replacePolicy(text, index, policyBlock(rawOf(d)), config.policies.length);
  if (!e.ok) return { ok: false, problems: [], reason: null, layout: true };
  return judge(text, e.text, rawOf(d)["id"] as string);
}

/**
 * Remove policy `index`. Refused when it leaves a problem behind (the last
 * policy: an empty list cannot be read). Decisions naming it become
 * problems of decisions.yml, which the confirmation shows first.
 */
export function removeAt(text: string, config: Config, index: number): Change {
  const e = removePolicy(text, index, config.policies.length);
  if (!e.ok) return { ok: false, problems: [], reason: null, layout: true };
  const judged = judge(text, e.text, null);
  return judged.ok ? { ...judged, id: (config.policies[index] as Policy).id } : judged;
}
