// rates.csv (optional): currency rates by date, header `date,currency,rate`
// (qayd/rates.py). A rate is base-currency units per one unit of `currency`.
// Conversion takes the latest rate on or before the date and cites the rate
// row; the base currency needs no row; no rate is Unknown, never a guess
// (A5). Two different rates for one currency and date conflict: a problem,
// and Unknown on that date.
import { csvLine } from "./csv";
import type { Decimal } from "./decimal";
import { dated, INVALID, loadCsv, problem } from "./loader";
import { isCurrencyCode, parseIsoDate, parseRate } from "./text";
import type { Problem, RateRow } from "./types";
import { unknown, type Unknown } from "./values";

export const RATES_HEADER = "date,currency,rate";

export interface Conversion {
  amount: Decimal;
  /** null when no conversion was needed */
  rate: RateRow | null;
}

export class RateTable {
  readonly rows: readonly RateRow[];
  private readonly byCurrency = new Map<string, RateRow[]>();

  constructor(
    rows: readonly RateRow[],
    readonly base: string | null,
  ) {
    this.rows = rows;
    for (const r of rows) {
      const list = this.byCurrency.get(r.currency) ?? [];
      list.push(r);
      this.byCurrency.set(r.currency, list);
    }
    for (const list of this.byCurrency.values()) list.sort((a, b) => (a.date < b.date ? -1 : a.date > b.date ? 1 : a.line - b.line));
  }

  get currencies(): string[] {
    return [...this.byCurrency.keys()].sort();
  }

  /** An amount in `currency` on `date`, in base currency, or Unknown. */
  convert(amount: Decimal, currency: string, date: string): Conversion | Unknown {
    if (currency === this.base) return { amount, rate: null };
    if (this.base === null) return unknown(`base currency is not declared; cannot convert ${currency}`);
    const candidates = this.byCurrency.get(currency);
    if (!candidates || candidates.length === 0) return unknown(`no rate for ${currency} (no rows for that currency)`);
    let latest: RateRow | null = null;
    for (const r of candidates) {
      if (r.date <= date) latest = r;
      else break;
    }
    if (latest === null) {
      return unknown(`no rate for ${currency} on or before ${date} (earliest is ${(candidates[0] as RateRow).date})`);
    }
    const day = latest.date;
    const sameDay = candidates.filter((r) => r.date === day);
    if (new Set(sameDay.map((r) => r.rate.toString())).size > 1) {
      return unknown(`conflicting rates for ${currency} on ${day}`, sameDay.map((r) => r.cite));
    }
    return { amount: amount.times(latest.rate), rate: latest };
  }
}

export interface ParsedRates {
  table: RateTable;
  problems: Problem[];
}

/**
 * Parse rates text. `null` is a file that does not exist: rates.csv is
 * optional, so that is an empty table and no problem (the CLI's
 * load_optional).
 */
export function parseRates(text: string | null, baseCurrency: string | null, file = "rates.csv"): ParsedRates {
  if (text === null) return { table: new RateTable([], baseCurrency), problems: [] };
  const loaded = loadCsv<RateRow>(text, file, RATES_HEADER, 3, (fields, line, f) => {
    const [dText, cur, rText] = fields as [string, string, string];
    const problems: Problem[] = [];
    const date = parseIsoDate(dText);
    if (date === null) problems.push(problem(f, line, "BAD-DATE", `date '${dText}' is not YYYY-MM-DD`));
    const extra = dated(date);
    if (!isCurrencyCode(cur)) problems.push(problem(f, line, "BAD-CURRENCY", `currency '${cur}' is not a 3-letter ISO-4217 code`, INVALID, extra));
    else if (baseCurrency !== null && cur === baseCurrency) problems.push(problem(f, line, "BASE-RATE", `the base currency ${cur} needs no rate`, INVALID, extra));
    const rate = parseRate(rText);
    if (rate === null) problems.push(problem(f, line, "BAD-RATE", `rate '${rText}' is not positive decimal text`, INVALID, extra));
    if (problems.length > 0 || date === null || rate === null) return { row: null, problems };
    return { row: { date, currency: cur, rate, rateText: rText, line, file: f, cite: `${f}:${line}` }, problems };
  });
  const problems = [...loaded.problems];
  const seen = new Map<string, RateRow>();
  for (const r of loaded.rows) {
    const key = `${r.date}|${r.currency}`;
    const first = seen.get(key);
    if (first === undefined) seen.set(key, r);
    else if (!first.rate.eq(r.rate)) {
      problems.push(problem(r.file, r.line, "CONFLICT-RATE", `rate for ${r.currency} on ${r.date} differs from line ${first.line}`, INVALID, { date: r.date }));
    }
  }
  return { table: new RateTable(loaded.rows, baseCurrency), problems };
}

export function rateLine(row: Pick<RateRow, "date" | "currency" | "rateText">): string {
  return csvLine([row.date, row.currency, row.rateText]);
}

export function serializeRates(rows: readonly RateRow[]): string {
  let out = RATES_HEADER + "\n";
  for (const r of rows) out += rateLine(r) + "\n";
  return out;
}
