// Verdicts (reference engine ADR section 6, qayd/rules.py, ported one to
// one). Deterministic, cited, never advising.
//
// verdict(policy, ctx, asOf) for one policy:
//   cap         measure <= limit -> hold, else breach
//   floor       measure >= limit -> hold, else breach
//   allocation  band.min_pct <= share <= band.max_pct -> hold, else breach
//   red_line    no matching row ever (up to asOf) -> hold; else breach,
//               citing every matching row
//   routine     a matching row in the current period -> hold; else missing
//   kill        drawdown crossed the threshold on any snapshot date (rolling
//               window) -> kill, and it stays kill until a decision with
//               closes=<id> is dated after the crossing (then hold, with the
//               closing noted)
// Other verdicts: stale (holdings snapshot older than allowed), unknown
// (undeclared shape, missing rate, no data), invalid (an invalid row
// touches the period), missing (routine without its row, or a
// ledger-based policy whose period has no ledger rows at all).
import { daysBetween } from "./dates";
import { D, money, pct, type Decimal } from "./decimal";
import { finding, problemFindings, type Finding } from "./findings";
import { latestSnapshot } from "./holdings";
import { drawdownHistory, endOf, evaluate, invalidIn, limitValue, rowsIn, type Context, type Measured, type Point } from "./measures";
import { periodContaining, periodsBetween, type Period } from "./periods";
import { bandText, matchText, measureText } from "./policies";
import { pyRepr } from "./py";
import type { Citable, Decision, LedgerRow, Match, Policy } from "./types";
import { citesOf, stale, unknown, value, type Stale, type Unknown, type Value } from "./values";

export type VerdictName = "hold" | "breach" | "kill" | "missing" | "stale" | "invalid" | "unknown";

export const RED_VERDICTS: readonly VerdictName[] = ["breach", "kill", "missing", "stale", "invalid", "unknown"];

export interface Verdict {
  policy: Policy;
  verdict: VerdictName;
  /** null for a red line ("ever") */
  period: Period | null;
  measure: Measured | null;
  limit: Value | Unknown | null;
  /** the rows the verdict rests on */
  rows: Citable[];
  reason: string | null;
  findings: Finding[];
}

export function isRed(v: Verdict): boolean {
  return v.verdict !== "hold";
}

export function verdictCites(v: Verdict): string[] {
  return citesOf(v.rows);
}

// ---- matching ---------------------------------------------------------------

function amountInBase(ctx: Context, row: LedgerRow): Decimal | null {
  const conv = ctx.rates !== null ? ctx.rates.convert(row.amount, row.currency, row.date) : null;
  if (conv === null) return row.currency === ctx.config.baseCurrency ? row.amount : null;
  if ("tag" in conv) return null;
  return conv.amount;
}

/**
 * Rows matching a match spec, and the undecided ones: rows that match every
 * criterion except min_amount, whose foreign currency has no rate (A5).
 */
export function matchRows(match: Match, rows: readonly LedgerRow[], ctx: Context): { matched: LedgerRow[]; undecided: LedgerRow[] } {
  const matched: LedgerRow[] = [];
  const undecided: LedgerRow[] = [];
  for (const r of rows) {
    if (match.tags !== null && !match.tags.every((t) => r.tags.includes(t))) continue;
    if (match.tagsAny !== null && !match.tagsAny.some((t) => r.tags.includes(t))) continue;
    if (match.account !== null && r.account !== match.account) continue;
    if (match.category !== null && r.category !== match.category) continue;
    if (match.minAmount !== null) {
      const amount = amountInBase(ctx, r);
      if (amount === null) {
        undecided.push(r);
        continue;
      }
      if (amount.abs().lt(match.minAmount.value)) continue;
    }
    matched.push(r);
  }
  return { matched, undecided };
}

// ---- helpers ----------------------------------------------------------------

/** A row count as the Decimal amount of a Value. */
function count(n: number): Decimal {
  return D(String(n));
}

function rowsWord(n: number): string {
  return `${n} row${n === 1 ? "" : "s"}`;
}

function periodFor(policy: Policy, asOf: string): Period {
  const m = policy.measure;
  if (m !== null && m.kind === "sum") return periodContaining(asOf, m.period);
  if (policy.period !== null) return periodContaining(asOf, policy.period);
  return periodContaining(asOf, "month");
}

function ledgerBased(policy: Policy): boolean {
  return policy.measure !== null && policy.measure.kind === "sum";
}

function verdictOf(
  policy: Policy,
  verdict: VerdictName,
  period: Period | null,
  measure: Measured | null,
  limit: Value | Unknown | null,
  rows: Citable[],
  reason: string | null,
  findings: Finding[],
): Verdict {
  return { policy, verdict, period, measure, limit, rows, reason, findings };
}

function unknownVerdict(policy: Policy, period: Period | null, u: Unknown, limit: Value | Unknown | null, prefix: string): Verdict {
  const reason = `${prefix}: ${u.reason}`;
  const kind: VerdictName = u.cause === "invalid" ? "invalid" : "unknown";
  const f = finding(kind.toUpperCase(), policy.id, reason, u.cites, { period: period !== null ? period.text : null });
  return verdictOf(policy, kind, period, u, limit, [], reason, [f]);
}

function declaredUnknown(policy: Policy, asOf: string): Verdict {
  const period = periodFor(policy, asOf);
  const reason = `policy is not declared: ${policy.reason ?? "None"}`;
  const f = finding("UNKNOWN", policy.id, reason, [policy.cite], { period: period.text });
  return verdictOf(policy, "unknown", period, null, null, [], reason, [f]);
}

/** The verdict of a ledger-based policy whose period has no ledger rows. */
export function emptyPeriod(policy: Policy, period: Period): Verdict {
  const reason = `no ledger rows in ${period.text}`;
  const f = finding("EMPTY-PERIOD", policy.id, reason, [], { period: period.text });
  return verdictOf(policy, "missing", period, null, null, [], reason, [f]);
}

function staleVerdict(policy: Policy, period: Period, s: Stale, limit: Value | Unknown | null, maxAge: number): Verdict {
  const reason = `holdings snapshot ${s.date} is ${s.ageDays} days old; ${maxAge} allowed`;
  const f = finding("STALE-SNAPSHOT", policy.id, reason, citesOf(s.rows), { date: s.date });
  return verdictOf(policy, "stale", period, s, limit, s.rows, reason, [f]);
}

function compare(policy: Policy, period: Period, v: Value, limit: Value, holds: boolean, breachText: string): Verdict {
  const rows = [...v.rows, ...limit.rows];
  if (holds) return verdictOf(policy, "hold", period, v, limit, rows, null, []);
  const f = finding("BREACH", policy.id, breachText, [...citesOf(v.rows), ...citesOf(limit.rows)], { period: period.text });
  return verdictOf(policy, "breach", period, v, limit, rows, breachText, [f]);
}

// ---- rule types -------------------------------------------------------------

function capFloorAllocation(policy: Policy, ctx: Context, asOf: string): Verdict {
  const period = periodFor(policy, asOf);
  if (ledgerBased(policy) && rowsIn(ctx, period).length === 0) return emptyPeriod(policy, period);
  const v = evaluate(policy.measure, ctx, period);
  let limit: Value | Unknown | null = null;
  if (policy.type !== "allocation") {
    limit = limitValue(policy.limit, ctx, period);
    if (limit.tag === "unknown") return unknownVerdict(policy, period, limit, null, "limit");
  }
  if (v.tag === "unknown") return unknownVerdict(policy, period, v, limit, "measure");
  if (v.tag === "stale") return staleVerdict(policy, period, v, limit, ctx.config.snapshotMaxAgeDays as number);
  const base = ctx.config.baseCurrency ?? "";
  if (policy.type === "cap") {
    const l = limit as Value;
    return compare(policy, period, v, l, v.amount.lte(l.amount), `${measureText(policy.measure)} = ${money(v.amount, base)} exceeds ${money(l.amount, base)}`);
  }
  if (policy.type === "floor") {
    const l = limit as Value;
    return compare(policy, period, v, l, v.amount.gte(l.amount), `${measureText(policy.measure)} = ${money(v.amount, base)} is below ${money(l.amount, base)}`);
  }
  const band = policy.band;
  if (band === null) return declaredUnknown(policy, asOf);
  const holds = band.minPct.value.lte(v.amount) && v.amount.lte(band.maxPct.value);
  const bandLimit = value(band.minPct.value); // for the record: the band is the limit
  if (holds) return verdictOf(policy, "hold", period, v, bandLimit, v.rows, null, []);
  const text = `${measureText(policy.measure)} = ${pct(v.amount)} is outside ${bandText(band)}`;
  const f = finding("BREACH", policy.id, text, citesOf(v.rows), { period: period.text });
  return verdictOf(policy, "breach", period, v, bandLimit, v.rows, text, [f]);
}

function redLine(policy: Policy, ctx: Context, asOf: string): Verdict {
  const match = policy.match as Match;
  const rows = ctx.ledger.filter((r) => r.date <= asOf);
  const { matched, undecided } = matchRows(match, rows, ctx);
  const v = value(count(matched.length), matched);
  if (matched.length > 0) {
    const text = `${matched.length} matching row${matched.length === 1 ? "" : "s"} (${matchText(match)})`;
    const f = finding("BREACH", policy.id, text, citesOf(matched));
    return verdictOf(policy, "breach", null, v, null, matched, text, [f]);
  }
  const bad = invalidIn(ctx.ledgerProblems, "0001-01-01", asOf);
  if (bad.length > 0) {
    const first = bad[0] as (typeof bad)[number];
    const u = unknown(`invalid ledger row ${first.file}:${first.line} (${first.code}) may match`, bad.map((p) => `${p.file}:${p.line}`), "invalid");
    return unknownVerdict(policy, null, u, null, "red line");
  }
  if (undecided.length > 0) {
    const u = unknown(`${rowsWord(undecided.length)} cannot be converted for min_amount`, undecided.map((r) => r.cite));
    return unknownVerdict(policy, null, u, null, "red line");
  }
  return verdictOf(policy, "hold", null, v, null, [], null, []);
}

function routineVerdict(policy: Policy, ctx: Context, asOf: string): Verdict {
  const match = policy.match as Match;
  const period = periodContaining(asOf, policy.period ?? "month");
  const rows = rowsIn(ctx, period);
  const bad = invalidIn(ctx.ledgerProblems, period.start, endOf(ctx, period));
  if (rows.length === 0 && bad.length === 0) return emptyPeriod(policy, period);
  const { matched, undecided } = matchRows(match, rows, ctx);
  const v = value(count(matched.length), matched);
  if (matched.length > 0) return verdictOf(policy, "hold", period, v, null, matched, null, []);
  if (bad.length > 0) {
    const first = bad[0] as (typeof bad)[number];
    const u = unknown(`invalid ledger row ${first.file}:${first.line} (${first.code}) may be the routine row`, bad.map((p) => `${p.file}:${p.line}`), "invalid");
    return unknownVerdict(policy, period, u, null, "routine");
  }
  if (undecided.length > 0) {
    const u = unknown(`${rowsWord(undecided.length)} cannot be converted for min_amount`, undecided.map((r) => r.cite));
    return unknownVerdict(policy, period, u, null, "routine");
  }
  const text = `no row matching ${matchText(match)} in ${period.text}`;
  const f = finding("ROUTINE-MISSING", policy.id, text, [], { period: period.text });
  return verdictOf(policy, "missing", period, v, null, [], text, [f]);
}

function kill(policy: Policy, ctx: Context, asOf: string): Verdict {
  const period = periodContaining(asOf, "month");
  const m = policy.measure as Extract<NonNullable<Policy["measure"]>, { kind: "drawdown" }>;
  const threshold = (policy.limit as NonNullable<Policy["limit"]>).value.value;
  const limit = value(threshold);
  const snap = latestSnapshot(ctx.holdings, asOf);
  const history = drawdownHistory(ctx, m.name, m.windowDays, asOf);
  if (!Array.isArray(history)) return unknownVerdict(policy, period, history, limit, "drawdown history");
  const crossings = history.filter((p) => p.drawdown !== null && p.drawdown.gte(threshold));
  const last = history[history.length - 1] as Point;
  const v = last.drawdown !== null ? value(last.drawdown, last.rows, history) : null;
  let note: string | null = null;
  if (crossings.length > 0) {
    const c = crossings[crossings.length - 1] as Point;
    const closers = ctx.decisions.filter((d) => d.closes === policy.id && c.date < d.date && d.date <= asOf);
    if (closers.length === 0) {
      const base = ctx.config.baseCurrency ?? "";
      const text = `drawdown ${pct(c.drawdown as Decimal)} on ${c.date} crossed ${pct(threshold)} (peak ${money(c.peak, base)} on ${c.peakDate})`;
      const f = finding("KILL", policy.id, text, citesOf(c.rows), { date: c.date });
      return verdictOf(policy, "kill", period, v, limit, c.rows, text, [f]);
    }
    const closer = [...closers].sort((a: Decision, b: Decision) => (a.date < b.date ? -1 : a.date > b.date ? 1 : a.line - b.line))[0] as Decision;
    note = `kill of ${c.date} closed by ${closer.id} (${closer.date})`;
  }
  const maxAge = ctx.config.snapshotMaxAgeDays;
  if (maxAge === null) return unknownVerdict(policy, period, unknown("snapshot_max_age_days is not declared"), limit, "drawdown");
  const age = daysBetween(snap.date as string, asOf);
  if (age > maxAge) {
    const s = staleVerdict(policy, period, stale(age, snap.date as string, last.drawdown, last.rows), limit, maxAge);
    return note !== null ? { ...s, reason: `${s.reason as string}; ${note}` } : s;
  }
  if (v === null) {
    return unknownVerdict(policy, period, unknown(`peak value of account.${m.name} is not positive`, citesOf(last.rows)), limit, "drawdown");
  }
  return verdictOf(policy, "hold", period, v, limit, last.rows, note, []);
}

/** The verdict of one policy as of a date; an undeclared policy is unknown. */
export function verdict(policy: Policy, ctx0: Context, asOf: string): Verdict {
  const ctx = ctx0.asOf === asOf ? ctx0 : { ...ctx0, asOf };
  if (policy.status !== "ok") return declaredUnknown(policy, asOf);
  if (policy.type === "cap" || policy.type === "floor" || policy.type === "allocation") return capFloorAllocation(policy, ctx, asOf);
  if (policy.type === "red_line") return redLine(policy, ctx, asOf);
  if (policy.type === "routine") return routineVerdict(policy, ctx, asOf);
  if (policy.type === "kill") return kill(policy, ctx, asOf);
  return declaredUnknown({ ...policy, reason: `type ${pyRepr(policy.type)} is not declared` }, asOf);
}

/** Verdicts for every policy, in file order, plus the ledger and holdings findings. */
export function check(ctx: Context, asOf: string): { verdicts: Verdict[]; findings: Finding[] } {
  const verdicts = ctx.config.policies.map((p) => verdict(p, ctx, asOf));
  const findings = [...verdicts.flatMap((v) => v.findings), ...problemFindings(ctx.ledgerProblems), ...problemFindings(ctx.holdingsProblems)];
  return { verdicts, findings };
}

/** Green = every policy hold and no red finding. */
export function isGreen(verdicts: readonly Verdict[], findings: readonly Finding[]): boolean {
  return verdicts.every((v) => v.verdict === "hold") && !findings.some((f) => f.cls === "red");
}

/** Reds first (file order), then holds (file order). */
export function order(verdicts: readonly Verdict[]): Verdict[] {
  return [...verdicts.filter(isRed), ...verdicts.filter((v) => !isRed(v))];
}

// ---- routine ----------------------------------------------------------------

export type RoutineStatus = "done" | "missing" | "unknown" | "invalid" | VerdictName;

/** One routine policy in one period. */
export interface RoutineItem {
  policy: Policy;
  /** null for an undeclared routine */
  period: Period | null;
  status: RoutineStatus;
  verdict: Verdict;
}

/**
 * The periods of the policy's kind to look at for a requested period: the
 * sub-periods inside it when the policy's kind is finer (a monthly routine
 * over a quarter: three months), else the one period of the policy's kind
 * that contains the requested period's end.
 */
export function routinePeriods(policy: Policy, period: Period): Period[] {
  const kind = policy.period ?? "month";
  const inside = periodsBetween(period.start, period.end, kind);
  if (inside.length > 0 && (inside[0] as Period).start >= period.start && (inside[inside.length - 1] as Period).end <= period.end) return inside;
  return [periodContaining(period.end, kind)];
}

/** Every routine policy over the requested period, cut at asOf. */
export function routine(ctx: Context, period: Period, asOf: string): RoutineItem[] {
  const items: RoutineItem[] = [];
  for (const policy of ctx.config.policies) {
    if (policy.type !== "routine") continue;
    if (policy.status !== "ok") {
      items.push({ policy, period: null, status: "unknown", verdict: verdict(policy, ctx, asOf) });
      continue;
    }
    for (const sub of routinePeriods(policy, period)) {
      const cut = asOf >= sub.end ? sub.end : asOf;
      if (cut < sub.start) {
        const v = { ...emptyPeriod(policy, sub), reason: `period ${sub.text} starts after ${asOf}` };
        items.push({ policy, period: sub, status: "missing", verdict: v });
        continue;
      }
      const v = verdict(policy, ctx, cut);
      const status: RoutineStatus = v.verdict === "hold" ? "done" : v.verdict;
      items.push({ policy, period: sub, status, verdict: v });
    }
  }
  return items;
}
