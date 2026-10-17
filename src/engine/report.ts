// Text and JSON rendering of the commands (reference engine ADR section 8,
// qayd/report.py, ported one to one). Text: one line per policy
// `<verdict> <id> <title> <measure> vs <limit>` then indented citations,
// reds first; then the findings that belong to no policy; then one summary
// line GREEN / RED. JSON: every amount is decimal text, never a number (A5).
import { daysUntilReview, isDue } from "./decisions";
import { fmt, money, pct } from "./decimal";
import { sameFinding, type Finding } from "./findings";
import type { Measured } from "./measures";
import { bandText, limitText, matchText, measureText } from "./policies";
import type { Period } from "./periods";
import { order, verdictCites, type RoutineItem, type Verdict } from "./rules";
import type { Decision, FileName, Problem } from "./types";
import { citesOf, type Unknown, type Value } from "./values";

export const VERSION = 1;

// ---- JSON shapes --------------------------------------------------------------

export type ValueJson =
  | { status: "ok"; amount: string; cites: string[]; text: string }
  | { status: "stale"; amount: string | null; age_days: number; date: string; cites: string[]; text: string }
  | { status: "unknown" | "invalid"; reason: string; cites: string[]; text: string };

export interface DeclaredJson {
  measure: string | null;
  limit: string | null;
  match: string | null;
  band: string | null;
  period: string | null;
}

export interface VerdictJson {
  id: string;
  type: string;
  title: string;
  verdict: string;
  period: string | null;
  scope: string;
  measure: ValueJson | null;
  limit: ValueJson | null;
  declared: DeclaredJson;
  cites: string[];
  reason: string | null;
  findings: string[];
}

export interface FindingJson {
  code: string;
  class: "red" | "warn";
  policy: string | null;
  period: string | null;
  date: string | null;
  cites: string[];
  reason: string;
}

export type FilesJson = Partial<Record<FileName, number | null>>;

export interface CheckJson {
  version: number;
  command: "check";
  as_of: string;
  green: boolean;
  base_currency: string | null;
  policies: VerdictJson[];
  findings: FindingJson[];
  files: FilesJson;
  problems: Problem[];
}

export interface RoutineItemJson {
  id: string;
  title: string;
  period: string | null;
  status: string;
  match: string | null;
  cites: string[];
  reason: string | null;
}

export interface RoutineJson {
  version: number;
  command: "routine";
  period: string;
  as_of: string;
  all_done: boolean;
  routines: RoutineItemJson[];
  findings: FindingJson[];
  files: FilesJson;
  problems: Problem[];
}

export interface DecisionJson {
  id: string;
  date: string;
  title: string;
  policy: string | null;
  criteria: string;
  review_by: string;
  status: string;
  closes: string | null;
  days_until_review: number | null;
  due: boolean;
  cite: string;
}

export interface DecisionsJson {
  version: number;
  command: "decisions";
  as_of: string;
  due: boolean;
  decisions: DecisionJson[];
  findings: FindingJson[];
  files: FilesJson;
  problems: Problem[];
}

/**
 * The CLI's JSON text: json.dumps(indent=2) and a final newline; like
 * Python (ensure_ascii) every character beyond ASCII is written as an escape.
 */
export function jsonText(doc: unknown): string {
  const BACKSLASH_U = String.fromCharCode(92) + "u";
  return JSON.stringify(doc, null, 2).replace(/[^\x00-\x7f]/g, (c) => BACKSLASH_U + c.charCodeAt(0).toString(16).padStart(4, "0")) + "\n";
}

// ---- displays -------------------------------------------------------------------

function isPctPolicy(v: Verdict): boolean {
  const kind = v.policy.measure !== null ? v.policy.measure.kind : null;
  return kind === "share" || kind === "drawdown";
}

/** Short text for the measure side of a verdict line. */
export function measureDisplay(v: Verdict, base: string): string {
  const m = v.measure;
  if (m === null) return "-";
  if (m.tag === "unknown") return "unknown";
  if (v.policy.type === "routine" || v.policy.type === "red_line") {
    const n = m.rows.length;
    return n === 0 ? "no row" : `${n} row${n === 1 ? "" : "s"}`;
  }
  if (m.tag === "stale") {
    if (m.amount === null) return `stale (${m.ageDays} days)`;
    const shown = isPctPolicy(v) ? pct(m.amount) : money(m.amount, base);
    return `stale ${shown} as of ${m.date} (${m.ageDays} days)`;
  }
  return isPctPolicy(v) ? pct(m.amount) : money(m.amount, base);
}

/** Short text for the limit side of a verdict line. */
export function limitDisplay(v: Verdict, base: string): string {
  const p = v.policy;
  const lim = v.limit;
  if (p.type === "routine") return `1 row required (${matchText(p.match)})`;
  if (p.type === "red_line") return `none (${matchText(p.match)})`;
  if (p.type === "allocation") return p.band !== null ? bandText(p.band) : "?";
  if (p.type === "kill") return p.limit !== null ? limitText(p.limit) : "?";
  if (p.limit === null) return "?";
  const declared = limitText(p.limit, base);
  if (lim === null || lim.tag === "unknown") return p.limit.kind === "value" ? declared : `unknown (${declared})`;
  if (p.limit.kind === "value") return declared;
  return `${money(lim.amount, base)} (${limitText(p.limit)})`;
}

/** What the verdict is about: a period label, "as of <date>" for holdings-based policies, "ever" for a red line. */
export function scopeDisplay(v: Verdict, asOf: string | null): string {
  if (v.policy.type === "red_line") return "ever";
  if (v.period === null) return "";
  if (v.policy.measure !== null && v.policy.measure.kind !== "sum" && v.policy.type !== "routine") {
    const cut = asOf === null || asOf >= v.period.end ? v.period.end : asOf;
    return `as of ${cut}`;
  }
  return v.period.text;
}

function valueJson(x: Measured | Value | Unknown | null, text: string): ValueJson | null {
  if (x === null) return null;
  if (x.tag === "unknown") return { status: x.cause === "invalid" ? "invalid" : "unknown", reason: x.reason, cites: [...x.cites], text };
  if (x.tag === "stale") {
    return { status: "stale", amount: x.amount === null ? null : fmt(x.amount), age_days: x.ageDays, date: x.date, cites: citesOf(x.rows), text };
  }
  return { status: "ok", amount: fmt(x.amount), cites: citesOf(x.rows), text };
}

export function verdictJson(v: Verdict, base: string, asOf: string | null): VerdictJson {
  const p = v.policy;
  return {
    id: p.id,
    type: p.type,
    title: p.title,
    verdict: v.verdict,
    period: v.period !== null ? v.period.text : null,
    scope: scopeDisplay(v, asOf),
    measure: valueJson(v.measure, measureDisplay(v, base)),
    limit: valueJson(v.limit, limitDisplay(v, base)),
    declared: {
      measure: p.measure !== null ? measureText(p.measure) : null,
      limit: p.limit !== null ? limitText(p.limit, base) : null,
      match: p.match !== null ? matchText(p.match) : null,
      band: p.band !== null ? bandText(p.band) : null,
      period: p.period,
    },
    cites: verdictCites(v),
    reason: v.reason,
    findings: v.findings.map((f) => f.code),
  };
}

export function findingJson(f: Finding): FindingJson {
  return { code: f.code, class: f.cls, policy: f.policy, period: f.period, date: f.date, cites: [...f.cites], reason: f.reason };
}

// ---- check ------------------------------------------------------------------------

export interface CheckReport {
  asOf: string;
  baseCurrency: string | null;
  verdicts: Verdict[];
  findings: Finding[];
  files: FilesJson;
  problems: Problem[];
  green: boolean;
}

export function checkToJson(r: CheckReport): CheckJson {
  const base = r.baseCurrency;
  return {
    version: VERSION,
    command: "check",
    as_of: r.asOf,
    green: r.green,
    base_currency: base,
    policies: order(r.verdicts).map((v) => verdictJson(v, base ?? "", r.asOf)),
    findings: r.findings.map(findingJson),
    files: { ...r.files },
    problems: r.problems.map((p) => ({ ...p })),
  };
}

function pad(s: string, width: number): string {
  return s.length >= width ? s : s + " ".repeat(width - s.length);
}

function findingLine(f: Finding): string {
  return `  ${pad(f.cls, 5)} ${pad(f.code, 16)} ${f.cites.join(" ")}  ${f.reason}`;
}

/** The CLI's last line: GREEN|RED as of <date>: N of M policies hold, ... */
export function summaryLine(r: CheckReport): string {
  const holds = r.verdicts.filter((v) => v.verdict === "hold").length;
  const reds = r.findings.filter((f) => f.cls === "red").length;
  const warns = r.findings.filter((f) => f.cls === "warn").length;
  return `${r.green ? "GREEN" : "RED"} as of ${r.asOf}: ${holds} of ${r.verdicts.length} policies hold, ${reds} red finding${reds === 1 ? "" : "s"}, ${warns} warning${warns === 1 ? "" : "s"}`;
}

/** The verdict line of one policy, exactly as the CLI prints it. */
export function verdictLine(v: Verdict, base: string, asOf: string | null): string {
  const scope = scopeDisplay(v, asOf);
  let line = `${pad(v.verdict, 8)} ${pad(v.policy.id, 10)} ${v.policy.title}  ${measureDisplay(v, base)} vs ${limitDisplay(v, base)}`;
  if (scope !== "") line += ` [${scope}]`;
  if (v.reason) line += "  -- " + v.reason;
  return line;
}

export function renderCheckText(r: CheckReport): string {
  const base = r.baseCurrency ?? "";
  const lines: string[] = [];
  for (const v of order(r.verdicts)) {
    lines.push(verdictLine(v, base, r.asOf));
    let cites = verdictCites(v);
    if (cites.length === 0) cites = v.findings.flatMap((f) => f.cites);
    if (cites.length > 0) lines.push("         " + cites.join(" "));
  }
  const shown = r.verdicts.flatMap((v) => v.findings);
  const loose = r.findings.filter((f) => !shown.some((s) => sameFinding(s, f)));
  if (loose.length > 0) {
    lines.push("findings:");
    for (const f of loose) lines.push(findingLine(f));
  }
  lines.push(summaryLine(r));
  return lines.join("\n") + "\n";
}

// ---- routine ------------------------------------------------------------------------

export function routineItemJson(item: RoutineItem): RoutineItemJson {
  const v = item.verdict;
  return {
    id: item.policy.id,
    title: item.policy.title,
    period: item.period !== null ? item.period.text : null,
    status: item.status,
    match: item.policy.match !== null ? matchText(item.policy.match) : null,
    cites: verdictCites(v),
    reason: v.reason,
  };
}

export function routineToJson(items: readonly RoutineItem[], period: Period, asOf: string, findings: readonly Finding[], files: FilesJson, problems: readonly Problem[]): RoutineJson {
  return {
    version: VERSION,
    command: "routine",
    period: period.text,
    as_of: asOf,
    all_done: items.every((i) => i.status === "done"),
    routines: items.map(routineItemJson),
    findings: findings.map(findingJson),
    files: { ...files },
    problems: problems.map((p) => ({ ...p })),
  };
}

export function renderRoutineText(items: readonly RoutineItem[], period: Period, asOf: string, findings: readonly Finding[] = []): string {
  const lines: string[] = [];
  for (const item of items) {
    const label = item.period !== null ? item.period.text : "?";
    let line = `${pad(item.status, 8)} ${pad(item.policy.id, 10)} ${item.policy.title} [${label}]`;
    if (item.verdict.reason) line += "  -- " + item.verdict.reason;
    lines.push(line);
    let cites = verdictCites(item.verdict);
    if (cites.length === 0) cites = item.verdict.findings.flatMap((f) => f.cites);
    if (cites.length > 0) lines.push("         " + cites.join(" "));
  }
  const loose = findings.filter((f) => f.policy === null);
  if (loose.length > 0) {
    lines.push("findings:");
    for (const f of loose) lines.push(findingLine(f));
  }
  const done = items.filter((i) => i.status === "done").length;
  lines.push(`${done === items.length ? "ALL DONE" : "MISSING"} routine ${period.text} as of ${asOf}: ${done} of ${items.length} done`);
  return lines.join("\n") + "\n";
}

// ---- decisions ----------------------------------------------------------------------

export function decisionJson(d: Decision, asOf: string): DecisionJson {
  return {
    id: d.id,
    date: d.date,
    title: d.title,
    policy: d.policy,
    criteria: d.criteria,
    review_by: d.reviewBy,
    status: d.status,
    closes: d.closes,
    days_until_review: d.status === "open" ? daysUntilReview(d, asOf) : null,
    due: isDue(d, asOf),
    cite: d.cite,
  };
}

function daysText(days: number): string {
  if (days < 0) return `${-days} day${days === -1 ? "" : "s"} overdue`;
  return `${days} day${days === 1 ? "" : "s"} left`;
}

/** Due first, then open, then closed; by date, then line. */
export function orderDecisions(decisions: readonly Decision[], asOf: string): Decision[] {
  const rank = (d: Decision): number => (isDue(d, asOf) ? 0 : d.status === "open" ? 1 : 2);
  return [...decisions].sort((a, b) => rank(a) - rank(b) || (a.date < b.date ? -1 : a.date > b.date ? 1 : 0) || a.line - b.line);
}

export function renderDecisionsText(decisions: readonly Decision[], asOf: string, findings: readonly Finding[] = []): string {
  const lines: string[] = [];
  for (const d of orderDecisions(decisions, asOf)) {
    let line: string;
    if (d.status === "open") {
      const status = isDue(d, asOf) ? "due" : "open";
      line = `${pad(status, 8)} ${pad(d.id, 14)} ${d.title}  review by ${d.reviewBy} (${daysText(daysUntilReview(d, asOf))})`;
      if (d.policy) line += "  policy " + d.policy;
    } else {
      line = `${pad("closed", 8)} ${pad(d.id, 14)} ${d.title}  decided ${d.date}`;
      if (d.closes) line += "  closes " + d.closes;
      else if (d.policy) line += "  policy " + d.policy;
    }
    lines.push(line);
    lines.push("         " + d.cite);
  }
  const loose = findings.filter((f) => f.code !== "DECISION-DUE");
  if (loose.length > 0) {
    lines.push("findings:");
    for (const f of loose) lines.push(findingLine(f));
  }
  const due = decisions.filter((d) => isDue(d, asOf)).length;
  const open = decisions.filter((d) => d.status === "open").length;
  lines.push(`${due > 0 ? "DUE" : "NONE DUE"} decisions as of ${asOf}: ${open} open, ${due} due, ${decisions.length - open} closed`);
  return lines.join("\n") + "\n";
}

export function decisionsToJson(decisions: readonly Decision[], asOf: string, findings: readonly Finding[], files: FilesJson, problems: readonly Problem[]): DecisionsJson {
  return {
    version: VERSION,
    command: "decisions",
    as_of: asOf,
    due: decisions.some((d) => isDue(d, asOf)),
    decisions: decisions.map((d) => decisionJson(d, asOf)),
    findings: findings.map(findingJson),
    files: { ...files },
    problems: problems.map((p) => ({ ...p })),
  };
}
