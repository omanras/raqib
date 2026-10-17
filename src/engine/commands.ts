// The three commands of the reference CLI, returning exactly its JSON
// (`check --json`, `routine --json`, `decisions --json`) and its text, so
// the differential test is a deep equality (app ADR section 4).
//
// A household with a fatal problem (the CLI's exit 3) gets no verdicts:
// the CLI prints only the problems. Here the JSON still comes back, with
// no policies, green false, and every fatal problem as a red finding, so
// nothing is hidden (A3); fatalText() is the CLI's message.
import { decisionFindings, finding, problemFindings, type Finding } from "./findings";
import type { Household } from "./household";
import type { Period } from "./periods";
import { check as checkRules, isGreen, routine as routineRules, type RoutineItem } from "./rules";
import {
  checkToJson,
  decisionsToJson,
  renderCheckText,
  renderDecisionsText,
  renderRoutineText,
  routineToJson,
  type CheckJson,
  type CheckReport,
  type DecisionsJson,
  type RoutineJson,
} from "./report";

export const EXIT_GREEN = 0;
export const EXIT_RED = 1;
export const EXIT_FILE = 3;

/** The CLI's message for a household it cannot read (exit 3). */
export function fatalText(h: Household): string {
  let out = "qayd: cannot read or parse the household files:\n";
  for (const p of h.fatal) out += `  ${p.line ? `${p.file}:${p.line}` : p.file} ${p.code}: ${p.reason}\n`;
  return out;
}

function fatalFindings(h: Household): Finding[] {
  return h.fatal.map((p) => finding(p.code, null, p.reason, [p.line ? `${p.file}:${p.line}` : p.file], { date: p.date ?? null }));
}

/** Findings from decisions.yml and rates.csv problems (ledger and holdings come with the verdicts). */
function looseFindings(h: Household): Finding[] {
  return [...problemFindings(h.problemsByFile["decisions.yml"] ?? []), ...problemFindings(h.problemsByFile["rates.csv"] ?? [])];
}

/** The check of a household as of a date: verdicts, findings, green. */
export function buildCheck(h: Household, asOf: string): CheckReport {
  if (h.fatal.length > 0 || h.ctx === null || h.config === null) {
    return { asOf, baseCurrency: h.config?.baseCurrency ?? null, verdicts: [], findings: fatalFindings(h), files: h.files, problems: h.problems, green: false };
  }
  const { verdicts, findings } = checkRules(h.ctx, asOf);
  const all = [...findings, ...decisionFindings(h.decisions, asOf), ...looseFindings(h)];
  return { asOf, baseCurrency: h.config.baseCurrency, verdicts, findings: all, files: h.files, problems: h.problems, green: isGreen(verdicts, all) };
}

/** `check --json` */
export function check(h: Household, asOf: string): CheckJson {
  return checkToJson(buildCheck(h, asOf));
}

/** `check` as text, and its exit code. */
export function checkText(h: Household, asOf: string): { text: string; exit: number } {
  if (h.fatal.length > 0) return { text: fatalText(h), exit: EXIT_FILE };
  const r = buildCheck(h, asOf);
  return { text: renderCheckText(r), exit: r.green ? EXIT_GREEN : EXIT_RED };
}

export interface RoutineResult {
  items: RoutineItem[];
  findings: Finding[];
}

export function buildRoutine(h: Household, period: Period, asOf: string): RoutineResult {
  if (h.fatal.length > 0 || h.ctx === null) return { items: [], findings: fatalFindings(h) };
  const items = routineRules(h.ctx, period, asOf);
  const findings = [...problemFindings(h.ctx.ledgerProblems), ...problemFindings(h.ctx.holdingsProblems), ...looseFindings(h)];
  return { items, findings };
}

/** `routine --period P --json` (the CLI's default period is the month of as-of). */
export function routine(h: Household, period: Period, asOf: string): RoutineJson {
  const r = buildRoutine(h, period, asOf);
  const json = routineToJson(r.items, period, asOf, r.findings, h.files, h.problems);
  return h.fatal.length > 0 ? { ...json, all_done: false } : json;
}

export function routineText(h: Household, period: Period, asOf: string): { text: string; exit: number } {
  if (h.fatal.length > 0) return { text: fatalText(h), exit: EXIT_FILE };
  const r = buildRoutine(h, period, asOf);
  return { text: renderRoutineText(r.items, period, asOf, r.findings), exit: r.items.every((i) => i.status === "done") ? EXIT_GREEN : EXIT_RED };
}

function decisionsFindings(h: Household, asOf: string): Finding[] {
  if (h.fatal.length > 0) return fatalFindings(h);
  return [...decisionFindings(h.decisions, asOf), ...looseFindings(h)];
}

/** `decisions --json` */
export function decisions(h: Household, asOf: string): DecisionsJson {
  const json = decisionsToJson(h.fatal.length > 0 ? [] : h.decisions, asOf, decisionsFindings(h, asOf), h.files, h.problems);
  return h.fatal.length > 0 ? { ...json, due: true } : json;
}

export function decisionsText(h: Household, asOf: string): { text: string; exit: number } {
  if (h.fatal.length > 0) return { text: fatalText(h), exit: EXIT_FILE };
  const due = h.decisions.some((d) => d.status === "open" && d.reviewBy < asOf);
  return { text: renderDecisionsText(h.decisions, asOf, decisionsFindings(h, asOf)), exit: due ? EXIT_RED : EXIT_GREEN };
}

