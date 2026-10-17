// rates.csv (optional): currency rates by date, header `date,currency,rate`.
// A rate is base-currency units per one unit of `currency`. Lookup takes
// the latest rate on or before the date; two different rates on one date
// conflict and the date has no rate (FAILURE_MODEL "Missing rates").
import { csvLine, readCsv, type CsvRecord } from "./csv";
import { isValidDate } from "./dates";
import { isCurrencyCode, parseAmount } from "./text";
import { makeProblem, type InvalidRow, type ParsedRates, type Problem, type RateRow } from "./types";

export const RATES_HEADER = "date,currency,rate";
const RATES_COLUMNS = RATES_HEADER.split(",");

function invalid(line: number, date: string | null, code: string, reason: string, raw: string): InvalidRow {
  return { line, date, code, reason, raw };
}

function checkRow(rec: CsvRecord): RateRow | InvalidRow {
  const f = rec.fields;
  if (f.length !== RATES_COLUMNS.length) {
    return invalid(rec.line, null, "BAD-COLUMNS", `${f.length} columns, expected ${RATES_COLUMNS.length}`, rec.raw);
  }
  const [date, currency, rateText] = f as [string, string, string];
  if (!isValidDate(date)) return invalid(rec.line, null, "BAD-DATE", `bad date "${date}" (YYYY-MM-DD)`, rec.raw);
  if (!isCurrencyCode(currency)) return invalid(rec.line, date, "BAD-CURRENCY", `bad currency "${currency}" (ISO-4217 code)`, rec.raw);
  const rate = parseAmount(rateText);
  if (rate === null || rate.lte(0)) return invalid(rec.line, date, "BAD-RATE", `bad rate "${rateText}" (positive decimal text)`, rec.raw);
  return { line: rec.line, date, currency, rate, rateText };
}

/** Parse rates text; an empty text is a valid, empty table. */
export function parseRates(text: string): ParsedRates {
  const problems: Problem[] = [];
  const rates: RateRow[] = [];
  const invalidRows: InvalidRow[] = [];
  if (text.trim() === "") return { rates, invalid: invalidRows, problems, count: 0 };
  const csv = readCsv(text);
  if (csv.header === null || csv.header.fields.join(",") !== RATES_HEADER) {
    const line = csv.header ? csv.header.line : 1;
    problems.push(makeProblem("BAD-HEADER", "rates.csv", line, `header must be exactly "${RATES_HEADER}"`));
    return { rates, invalid: invalidRows, problems, count: 0 };
  }
  for (const rec of csv.records) {
    const r = checkRow(rec);
    if ("rateText" in r) rates.push(r);
    else {
      invalidRows.push(r);
      problems.push(makeProblem(r.code, "rates.csv", r.line, r.reason));
    }
  }
  return { rates, invalid: invalidRows, problems, count: csv.records.length };
}

export type RateLookup =
  | { status: "ok"; rate: RateRow }
  | { status: "missing"; reason: string }
  | { status: "conflict"; reason: string; lines: number[] };

/** The rate in force for a currency on a date. */
export function rateFor(rates: readonly RateRow[], currency: string, date: string): RateLookup {
  let bestDate: string | null = null;
  for (const r of rates) {
    if (r.currency === currency && r.date <= date && (bestDate === null || r.date > bestDate)) bestDate = r.date;
  }
  if (bestDate === null) return { status: "missing", reason: `no rate for ${currency} on or before ${date}` };
  const onDate = rates.filter((r) => r.currency === currency && r.date === bestDate);
  const first = onDate[0] as RateRow;
  const different = onDate.filter((r) => !r.rate.eq(first.rate));
  if (different.length > 0) {
    const lines = onDate.map((r) => r.line);
    return { status: "conflict", reason: `two different rates for ${currency} on ${bestDate} (rates.csv:${lines.join(", rates.csv:")})`, lines };
  }
  return { status: "ok", rate: first };
}

export function rateLine(row: RateRow): string {
  return csvLine([row.date, row.currency, row.rateText]);
}

export function serializeRates(rows: readonly RateRow[]): string {
  let out = RATES_HEADER + "\n";
  for (const r of rows) out += rateLine(r) + "\n";
  return out;
}
