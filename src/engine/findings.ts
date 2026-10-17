// Findings (A3, A4): what the owner must look at. Each names the policy
// when it has one and cites rows, or the period or date for the silence
// findings (reference engine qayd/rules.py). Codes:
//   BREACH, KILL, ROUTINE-MISSING, EMPTY-PERIOD, STALE-SNAPSHOT, UNKNOWN,
//   INVALID                     from the verdicts (rules.ts)
//   DECISION-DUE                an open decision past its review date
//   <loader code>               every loader problem: red for invalid
//                               rows, warn for DUP-ROW
import { daysUntilReview, isDue } from "./decisions";
import type { Decision, Problem } from "./types";

export interface Finding {
  code: string;
  cls: "red" | "warn";
  policy: string | null;
  /** period label when the finding is about a period */
  period: string | null;
  /** ISO date when the finding is about a date */
  date: string | null;
  /** file:line */
  cites: string[];
  reason: string;
}

export function finding(
  code: string,
  policy: string | null,
  reason: string,
  cites: readonly string[] = [],
  opts: { period?: string | null; date?: string | null; cls?: "red" | "warn" } = {},
): Finding {
  return { code, cls: opts.cls ?? "red", policy, period: opts.period ?? null, date: opts.date ?? null, cites: [...cites], reason };
}

/** DECISION-DUE for every open decision whose review_by < asOf (ADR 7). */
export function decisionFindings(decisions: readonly Decision[], asOf: string): Finding[] {
  const out: Finding[] = [];
  for (const d of decisions) {
    if (!isDue(d, asOf)) continue;
    const days = -daysUntilReview(d, asOf);
    const reason = `decision ${d.id} is open and its review date ${d.reviewBy} is ${days} day${days === 1 ? "" : "s"} past`;
    out.push(finding("DECISION-DUE", d.policy, reason, [d.cite], { date: d.reviewBy }));
  }
  return out;
}

/** Loader problems as findings: invalid rows red, DUP-ROW warn. */
export function problemFindings(problems: readonly Problem[]): Finding[] {
  return problems.map((p) =>
    finding(p.code, null, p.reason, [`${p.file}:${p.line}`], { date: p.date ?? null, cls: p.class === "warn" ? "warn" : "red" }),
  );
}

/** Two findings are the same finding when every field is equal. */
export function sameFinding(a: Finding, b: Finding): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}
