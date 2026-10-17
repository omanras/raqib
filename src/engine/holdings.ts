// holdings.csv: snapshots of balances and positions (reference engine ADR
// section 4). Header exactly `date,account,asset,class,quantity,value,currency`.
import { csvLine, readCsv, type CsvRecord } from "./csv";
import { isValidDate } from "./dates";
import { isCurrencyCode, parseAmount } from "./text";
import { makeProblem, type Config, type DupNote, type HoldingRow, type InvalidRow, type ParsedHoldings, type Problem, type Snapshot } from "./types";

export const HOLDINGS_HEADER = "date,account,asset,class,quantity,value,currency";
const HOLDINGS_COLUMNS = HOLDINGS_HEADER.split(",");

function invalid(line: number, date: string | null, code: string, reason: string, raw: string): InvalidRow {
  return { line, date, code, reason, raw };
}

function checkRow(rec: CsvRecord, config: Config | null): HoldingRow | InvalidRow {
  const f = rec.fields;
  if (f.length !== HOLDINGS_COLUMNS.length) {
    return invalid(rec.line, null, "BAD-COLUMNS", `${f.length} columns, expected ${HOLDINGS_COLUMNS.length}`, rec.raw);
  }
  const [date, account, asset, cls, quantityText, valueText, currency] = f as [string, string, string, string, string, string, string];
  if (!isValidDate(date)) return invalid(rec.line, null, "BAD-DATE", `bad date "${date}" (YYYY-MM-DD)`, rec.raw);
  const quantity = parseAmount(quantityText);
  if (quantity === null) return invalid(rec.line, date, "BAD-QUANTITY", `bad quantity "${quantityText}" (decimal text)`, rec.raw);
  const value = parseAmount(valueText);
  if (value === null) return invalid(rec.line, date, "BAD-VALUE", `bad value "${valueText}" (decimal text)`, rec.raw);
  if (!isCurrencyCode(currency)) return invalid(rec.line, date, "BAD-CURRENCY", `bad currency "${currency}" (ISO-4217 code)`, rec.raw);
  if (config) {
    if (!config.accounts.includes(account)) {
      return invalid(rec.line, date, "UNKNOWN-ACCOUNT", `account "${account}" is not declared in policies.yml`, rec.raw);
    }
    if (!config.classes.includes(cls)) {
      return invalid(rec.line, date, "UNKNOWN-CLASS", `class "${cls}" is not declared in policies.yml`, rec.raw);
    }
  }
  return { line: rec.line, date, account, asset, cls, quantity, quantityText, value, valueText, currency };
}

export function parseHoldings(text: string, config: Config | null): ParsedHoldings {
  const problems: Problem[] = [];
  const rows: HoldingRow[] = [];
  const invalidRows: InvalidRow[] = [];
  const dupNotes: DupNote[] = [];
  const csv = readCsv(text);
  if (csv.header === null) {
    if (text.trim() !== "") problems.push(makeProblem("BAD-HEADER", "holdings.csv", 1, `header must be exactly "${HOLDINGS_HEADER}"`));
    else problems.push(makeProblem("EMPTY-FILE", "holdings.csv", null, `empty file; header must be "${HOLDINGS_HEADER}"`));
    return { rows, invalid: invalidRows, problems, dupNotes, count: 0 };
  }
  if (csv.header.fields.join(",") !== HOLDINGS_HEADER) {
    problems.push(makeProblem("BAD-HEADER", "holdings.csv", csv.header.line, `header is "${csv.header.raw}", must be exactly "${HOLDINGS_HEADER}"`));
    return { rows, invalid: invalidRows, problems, dupNotes, count: 0 };
  }
  const seen = new Map<string, number>();
  for (const rec of csv.records) {
    const first = seen.get(rec.raw);
    if (first !== undefined) dupNotes.push({ line: rec.line, firstLine: first, text: rec.raw });
    else seen.set(rec.raw, rec.line);
    const r = checkRow(rec, config);
    if ("valueText" in r) rows.push(r);
    else {
      invalidRows.push(r);
      problems.push(makeProblem(r.code, "holdings.csv", r.line, r.reason));
    }
  }
  return { rows, invalid: invalidRows, problems, dupNotes, count: csv.records.length };
}

/** The snapshot dates present, ascending, unique. */
export function snapshotDates(rows: readonly HoldingRow[]): string[] {
  const s = new Set<string>();
  for (const r of rows) s.add(r.date);
  return [...s].sort();
}

/** All rows of one date, in file order. */
export function snapshotOn(rows: readonly HoldingRow[], date: string): Snapshot {
  return { date, rows: rows.filter((r) => r.date === date) };
}

/** The current snapshot as of a date: the latest date <= asOf, or null. */
export function latestSnapshot(rows: readonly HoldingRow[], asOf: string): Snapshot | null {
  let best: string | null = null;
  for (const r of rows) {
    if (r.date <= asOf && (best === null || r.date > best)) best = r.date;
  }
  return best === null ? null : snapshotOn(rows, best);
}

export function holdingLine(row: HoldingRow): string {
  return csvLine([row.date, row.account, row.asset, row.cls, row.quantityText, row.valueText, row.currency]);
}

export function serializeHoldings(rows: readonly HoldingRow[]): string {
  let out = HOLDINGS_HEADER + "\n";
  for (const r of rows) out += holdingLine(r) + "\n";
  return out;
}

/** Append rows (a new snapshot) to holdings text without rewriting the rest. */
export function appendHoldingLines(text: string, rows: readonly HoldingRow[]): string {
  let out = text.length === 0 ? HOLDINGS_HEADER + "\n" : text.endsWith("\n") ? text : text + "\n";
  for (const r of rows) out += holdingLine(r) + "\n";
  return out;
}
