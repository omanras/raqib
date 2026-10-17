// Measures and limits in base currency, with citations (reference engine
// ADR section 5, qayd/measures.py, ported one to one).
//
// Rules that hold everywhere here:
// - Money is Decimal; a foreign-currency row is converted with the rates
//   table at the row's date and the rate row is cited; no rate -> Unknown.
// - An Unknown anywhere makes the whole measure Unknown; never a partial sum.
// - Rows tagged `transfer` never count as income or expense.
// - Nothing after ctx.asOf is seen: every period is cut at asOf.
// - An invalid ledger or holdings row (a loader problem of class invalid)
//   dated inside the period, or without a date, makes the measure Unknown.
// - Expense sums are reported positive; income and other groups as recorded.
import { addDays, daysBetween } from "./dates";
import { D, HUNDRED, ZERO, type Decimal } from "./decimal";
import { latestSnapshot } from "./holdings";
import { monthPeriods, trailingWindow, type Period } from "./periods";
import type { RateTable } from "./rates";
import type { Citable, Config, Decision, HoldingRow, LedgerRow, Limit, Measure, Problem, RateRow, Snapshot } from "./types";
import { citesOf, stale, uniqueRows, unknown, value, type Stale, type Unknown, type Value } from "./values";

export const TRANSFER_TAG = "transfer";
export const DEBT_CLASS = "debt";
const DATE_MIN = "0001-01-01";

export interface Context {
  config: Config;
  ledger: readonly LedgerRow[];
  holdings: readonly HoldingRow[];
  /** null: no rates table at all */
  rates: RateTable | null;
  /** ISO date; null = no cut */
  asOf: string | null;
  ledgerProblems: readonly Problem[];
  holdingsProblems: readonly Problem[];
  /** kill closers */
  decisions: readonly Decision[];
}

export type Measured = Value | Unknown | Stale;

/** The last date the measure may see: the period end, cut at asOf. */
export function endOf(ctx: Pick<Context, "asOf">, period: Period): string {
  if (ctx.asOf === null || ctx.asOf >= period.end) return period.end;
  return ctx.asOf;
}

/** Valid ledger rows dated inside the period (cut at asOf), file order. */
export function rowsIn(ctx: Context, period: Period): LedgerRow[] {
  const end = endOf(ctx, period);
  return ctx.ledger.filter((r) => period.start <= r.date && r.date <= end);
}

/** Loader problems of class invalid dated in [start, end] or undated. */
export function invalidIn(problems: readonly Problem[], start: string, end: string): Problem[] {
  return problems.filter((p) => p.class === "invalid" && (p.date === undefined || (start <= p.date && p.date <= end)));
}

function poisoned(problems: readonly Problem[], start: string, end: string, what: string): Unknown | null {
  const hits = invalidIn(problems, start, end);
  if (hits.length === 0) return null;
  const first = hits[0] as Problem;
  return unknown(
    `invalid ${what} row ${first.file}:${first.line} (${first.code}) touches ${start}..${end}`,
    hits.map((p) => `${p.file}:${p.line}`),
    "invalid",
  );
}

type Moneyed = LedgerRow | HoldingRow;

function amountOf(row: Moneyed): Decimal {
  return "amount" in row ? row.amount : row.value;
}

function convert(ctx: Context, amount: Decimal, currency: string, date: string, row: Citable): { amount: Decimal; rate: RateRow | null } | Unknown {
  const conv = ctx.rates !== null ? ctx.rates.convert(amount, currency, date) : null;
  if (conv === null) {
    if (currency === ctx.config.baseCurrency) return { amount, rate: null };
    return unknown(`no rates table; cannot convert ${currency} at ${row.cite}`, [row.cite]);
  }
  if ("tag" in conv) return unknown(`${conv.reason} at ${row.cite}`, [row.cite, ...conv.cites]);
  return conv;
}

/** Sum of rows converted to base, and the rows cited (then the rate rows). */
function sumRows(ctx: Context, rows: readonly Moneyed[]): { total: Decimal; cited: Citable[] } | Unknown {
  let total = ZERO;
  const cited: Citable[] = [...rows];
  for (const row of rows) {
    const out = convert(ctx, amountOf(row), row.currency, row.date, row);
    if ("tag" in out) return out;
    total = total.plus(out.amount);
    if (out.rate !== null) cited.push(out.rate);
  }
  return { total, cited };
}

// ---- sums -------------------------------------------------------------------

function groupRows(ctx: Context, group: string, category: string | null, period: Period): LedgerRow[] {
  const end = endOf(ctx, period);
  const names = ctx.config.categories[group] ?? [];
  return ctx.ledger.filter((r) => {
    if (!(period.start <= r.date && r.date <= end)) return false;
    if (category !== null ? r.category !== category : !names.includes(r.category)) return false;
    if ((group === "income" || group === "expense") && r.tags.includes(TRANSFER_TAG)) return false;
    return true;
  });
}

function sum(ctx: Context, group: string, category: string | null, period: Period): Value | Unknown {
  const end = endOf(ctx, period);
  const bad = poisoned(ctx.ledgerProblems, period.start, end, "ledger");
  if (bad !== null) return bad;
  const out = sumRows(ctx, groupRows(ctx, group, category, period));
  if ("tag" in out) return out;
  return value(group === "expense" ? out.total.neg() : out.total, out.cited);
}

/** Sum of the income group over the period, transfers excluded. */
export function income(ctx: Context, period: Period): Value | Unknown {
  return sum(ctx, "income", null, period);
}

/** Sum of the expense group over the period, as a positive number. */
export function expense(ctx: Context, period: Period): Value | Unknown {
  return sum(ctx, "expense", null, period);
}

// ---- holdings ---------------------------------------------------------------

function snapshot(ctx: Context, date: string): Snapshot | Unknown {
  const snap = latestSnapshot(ctx.holdings, date);
  if (snap.date === null) {
    return poisoned(ctx.holdingsProblems, DATE_MIN, date, "holdings") ?? unknown(`no holdings snapshot on or before ${date}`);
  }
  return poisoned(ctx.holdingsProblems, snap.date, date, "holdings") ?? snap;
}

function staleCheck(ctx: Context, snapDate: string, asOfDate: string, amount: Decimal | null, rows: Citable[]): Stale | Unknown | null {
  const maxAge = ctx.config.snapshotMaxAgeDays;
  if (maxAge === null) return unknown("snapshot_max_age_days is not declared");
  const age = daysBetween(snapDate, asOfDate);
  if (age > maxAge) return stale(age, snapDate, amount, rows);
  return null;
}

function select(rows: readonly HoldingRow[], by: "class" | "account", name: string): HoldingRow[] {
  return rows.filter((r) => (by === "class" ? r.cls === name : r.account === name));
}

/** Value of class.<name> or account.<name> as of the period end. */
export function holdings(ctx: Context, by: "class" | "account", name: string, period: Period): Measured {
  const date = endOf(ctx, period);
  const snap = snapshot(ctx, date);
  if ("tag" in snap) return snap;
  const out = sumRows(ctx, select(snap.rows, by, name));
  if ("tag" in out) return out;
  return staleCheck(ctx, snap.date as string, date, out.total, out.cited) ?? value(out.total, out.cited);
}

/** Value of class.<name> over total holdings (debt excluded), in percent. */
export function share(ctx: Context, name: string, period: Period): Measured {
  const date = endOf(ctx, period);
  const snap = snapshot(ctx, date);
  if ("tag" in snap) return snap;
  const snapDate = snap.date as string;
  const part = sumRows(ctx, select(snap.rows, "class", name));
  if ("tag" in part) return part;
  const whole = sumRows(
    ctx,
    snap.rows.filter((r) => r.cls !== DEBT_CLASS),
  );
  if ("tag" in whole) return whole;
  const cited = uniqueRows([...part.cited, ...whole.cited]);
  if (whole.total.isZero()) {
    const bad = unknown(`total holdings (debt excluded) is zero on ${snapDate}`, citesOf(cited));
    return staleCheck(ctx, snapDate, date, null, cited) ?? bad;
  }
  const p = part.total.div(whole.total).times(HUNDRED);
  return staleCheck(ctx, snapDate, date, p, cited) ?? value(p, cited);
}

/** One snapshot date in a drawdown history. */
export interface Point {
  date: string;
  /** account value on that date, base currency */
  value: Decimal;
  /** date of the window peak (<= date) */
  peakDate: string;
  peak: Decimal;
  /** percent; null while the peak is not positive */
  drawdown: Decimal | null;
  /** rows behind value and peak (holdings + rates) */
  rows: Citable[];
}

/**
 * One Point per snapshot date <= date, each against the peak over the
 * windowDays calendar days ending on it (a rolling window), so a crossing
 * on any past date can be found. Unknown if any snapshot in the history
 * cannot be valued or an invalid holdings row exists.
 */
export function drawdownHistory(ctx: Context, name: string, windowDays: number, date: string): Point[] | Unknown {
  const bad = poisoned(ctx.holdingsProblems, DATE_MIN, date, "holdings");
  if (bad !== null) return bad;
  const dates = [...new Set(ctx.holdings.filter((r) => r.date <= date).map((r) => r.date))].sort();
  if (dates.length === 0) return unknown(`no holdings snapshot on or before ${date}`);
  const values = new Map<string, Decimal>();
  const cited = new Map<string, Citable[]>();
  for (const d of dates) {
    const out = sumRows(
      ctx,
      ctx.holdings.filter((r) => r.date === d && r.account === name),
    );
    if ("tag" in out) return out;
    values.set(d, out.total);
    cited.set(d, out.cited);
  }
  return dates.map((d) => {
    const start = addDays(d, -(windowDays - 1));
    let peakDate = d;
    for (const w of dates) {
      if (start <= w && w <= d && (values.get(w) as Decimal).gt(values.get(peakDate) as Decimal)) peakDate = w;
    }
    const peak = values.get(peakDate) as Decimal;
    const v = values.get(d) as Decimal;
    const dd = peak.gt(0) ? peak.minus(v).div(peak).times(HUNDRED) : null;
    const rows = uniqueRows([...(cited.get(d) as Citable[]), ...(peakDate !== d ? (cited.get(peakDate) as Citable[]) : [])]);
    return { date: d, value: v, peakDate, peak, drawdown: dd, rows };
  });
}

/** A drawdown series entry: date, value, drawdown pct (null before a positive peak). */
export type SeriesPoint = [string, Decimal, Decimal | null];

/**
 * Peak-to-latest drawdown of account.<name> over the last windowDays, in
 * percent; detail is the (date, value, pct) series with the running peak.
 * The kill rule uses drawdownHistory instead.
 */
export function drawdown(ctx: Context, name: string, windowDays: number, period: Period): Measured {
  const date = endOf(ctx, period);
  const snap = snapshot(ctx, date);
  if ("tag" in snap) return snap;
  const start = addDays(date, -(windowDays - 1));
  const bad = poisoned(ctx.holdingsProblems, start, date, "holdings");
  if (bad !== null) return bad;
  const st = staleCheck(ctx, snap.date as string, date, null, []);
  if (st !== null) return st;
  const dates = [...new Set(ctx.holdings.filter((r) => start <= r.date && r.date <= date).map((r) => r.date))].sort();
  if (dates.length === 0) return unknown(`no holdings snapshot within ${windowDays} days of ${date} (latest is ${snap.date as string})`);
  const series: SeriesPoint[] = [];
  const cited: Citable[] = [];
  let peak: Decimal | null = null;
  for (const d of dates) {
    const out = sumRows(
      ctx,
      ctx.holdings.filter((r) => r.date === d && r.account === name),
    );
    if ("tag" in out) return out;
    cited.push(...out.cited);
    if (peak === null || out.total.gt(peak)) peak = out.total;
    series.push([d, out.total, peak.gt(0) ? peak.minus(out.total).div(peak).times(HUNDRED) : null]);
  }
  if (peak === null || peak.lte(0)) {
    return unknown(`peak value of account.${name} in the window is not positive (${peak === null ? "None" : pyDecText(peak)})`, citesOf(cited));
  }
  const last = (series[series.length - 1] as SeriesPoint)[2];
  if (last === null) return unknown(`drawdown of account.${name} is undefined before the first positive value`, citesOf(cited));
  return value(last, uniqueRows(cited), series);
}

/** str() of a computed Decimal; Python would also keep the trailing zeros of the sum. */
function pyDecText(x: Decimal): string {
  return x.isZero() ? "0" : x.toString();
}

// ---- entry ------------------------------------------------------------------

/** Evaluate a normalized measure (Policy.measure). */
export function evaluate(measure: Measure | null, ctx: Context, period: Period): Measured {
  if (measure === null) return unknown("measure is not declared");
  if (measure.kind === "sum") return sum(ctx, measure.group, measure.category, period);
  if (measure.kind === "holdings") return holdings(ctx, measure.by, measure.name, period);
  if (measure.kind === "share") return share(ctx, measure.name, period);
  return drawdown(ctx, measure.name, measure.windowDays, period);
}

/** Evaluate a normalized limit (Policy.limit) -> Value or Unknown. */
export function limitValue(limit: Limit | null, ctx: Context, period: Period): Value | Unknown {
  if (limit === null) return unknown("limit is not declared");
  if (limit.kind === "value" || limit.kind === "pct") return value(limit.value.value);
  if (limit.kind === "pct_of") {
    const base = income(ctx, period);
    if (base.tag === "unknown") return base;
    return value(base.amount.times(limit.value.value).div(HUNDRED), base.rows);
  }
  const avg = averageMonthlyExpense(ctx, period);
  if (avg.tag === "unknown") return avg;
  return value(avg.amount.times(limit.value.value), avg.rows, avg.detail);
}

/**
 * Average expense per complete month over the trailing `months` months
 * ending at the period end (cut at asOf). Only complete months count, and
 * among them only those with at least one ledger row; fewer months than
 * asked -> the months available. detail: the month labels used.
 */
export function averageMonthlyExpense(ctx: Context, period: Period, months = 12): Value | Unknown {
  const end = endOf(ctx, period);
  const window = trailingWindow(end, months);
  const complete = monthPeriods(window).filter((m) => m.end <= end);
  const used: string[] = [];
  let total = ZERO;
  const cited: Citable[] = [];
  for (const m of complete) {
    const bad = poisoned(ctx.ledgerProblems, m.start, m.end, "ledger");
    if (bad !== null) return bad;
    if (rowsIn(ctx, m).length === 0) continue;
    const out = expense(ctx, m);
    if (out.tag === "unknown") return out;
    total = total.plus(out.amount);
    cited.push(...out.rows);
    used.push(m.text);
  }
  if (used.length === 0) return unknown(`no complete month with ledger rows in ${window.text}`);
  return value(total.div(D(String(used.length))), uniqueRows(cited), used);
}

