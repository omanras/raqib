// ledger.csv: one row per money movement (reference engine ADR section 3).
// Header exactly `date,amount,currency,account,category,tags,note`.
import { csvLine, readCsv, type CsvRecord } from "./csv";
import { isValidDate } from "./dates";
import { isCurrencyCode, parseAmount, splitTags } from "./text";
import { makeProblem, type Config, type DupNote, type InvalidRow, type LedgerRow, type ParsedLedger, type Problem } from "./types";

export const LEDGER_HEADER = "date,amount,currency,account,category,tags,note";
const LEDGER_COLUMNS = LEDGER_HEADER.split(",");

function invalid(line: number, date: string | null, code: string, reason: string, raw: string): InvalidRow {
  return { line, date, code, reason, raw };
}

export function declaredCategories(config: Config): Set<string> {
  const out = new Set<string>();
  for (const group of Object.keys(config.categories)) {
    for (const c of config.categories[group] as string[]) out.add(c);
  }
  return out;
}

/** The group a category belongs to, or null. */
export function groupOf(config: Config, category: string): string | null {
  for (const group of Object.keys(config.categories)) {
    if ((config.categories[group] as string[]).includes(category)) return group;
  }
  return null;
}

function checkRow(rec: CsvRecord, config: Config | null): LedgerRow | InvalidRow {
  const f = rec.fields;
  if (f.length !== LEDGER_COLUMNS.length) {
    return invalid(rec.line, null, "BAD-COLUMNS", `${f.length} columns, expected ${LEDGER_COLUMNS.length}`, rec.raw);
  }
  const [date, amountText, currency, account, category, tags, note] = f as [string, string, string, string, string, string, string];
  if (!isValidDate(date)) return invalid(rec.line, null, "BAD-DATE", `bad date "${date}" (YYYY-MM-DD)`, rec.raw);
  const amount = parseAmount(amountText);
  if (amount === null) return invalid(rec.line, date, "BAD-AMOUNT", `bad amount "${amountText}" (decimal text)`, rec.raw);
  if (!isCurrencyCode(currency)) return invalid(rec.line, date, "BAD-CURRENCY", `bad currency "${currency}" (ISO-4217 code)`, rec.raw);
  if (config) {
    if (!config.accounts.includes(account)) {
      return invalid(rec.line, date, "UNKNOWN-ACCOUNT", `account "${account}" is not declared in policies.yml`, rec.raw);
    }
    if (!declaredCategories(config).has(category)) {
      return invalid(rec.line, date, "UNKNOWN-CATEGORY", `category "${category}" is not declared in policies.yml`, rec.raw);
    }
  }
  return { line: rec.line, date, amount, amountText, currency, account, category, tags: splitTags(tags), note };
}

/**
 * Parse ledger text. A malformed row is a problem naming its line and the
 * run continues; exact duplicate lines are noted, never dropped. Without a
 * config (policies.yml unreadable) accounts and categories are not checked.
 */
export function parseLedger(text: string, config: Config | null): ParsedLedger {
  const problems: Problem[] = [];
  const rows: LedgerRow[] = [];
  const invalidRows: InvalidRow[] = [];
  const dupNotes: DupNote[] = [];
  const csv = readCsv(text);
  if (csv.header === null) {
    if (text.trim() !== "") problems.push(makeProblem("BAD-HEADER", "ledger.csv", 1, `header must be exactly "${LEDGER_HEADER}"`));
    else problems.push(makeProblem("EMPTY-FILE", "ledger.csv", null, `empty file; header must be "${LEDGER_HEADER}"`));
    return { rows, invalid: invalidRows, problems, dupNotes, count: 0 };
  }
  if (csv.header.fields.join(",") !== LEDGER_HEADER) {
    problems.push(makeProblem("BAD-HEADER", "ledger.csv", csv.header.line, `header is "${csv.header.raw}", must be exactly "${LEDGER_HEADER}"`));
    return { rows, invalid: invalidRows, problems, dupNotes, count: 0 };
  }
  const seen = new Map<string, number>();
  for (const rec of csv.records) {
    const first = seen.get(rec.raw);
    if (first !== undefined) dupNotes.push({ line: rec.line, firstLine: first, text: rec.raw });
    else seen.set(rec.raw, rec.line);
    const r = checkRow(rec, config);
    if ("amountText" in r) rows.push(r);
    else {
      invalidRows.push(r);
      problems.push(makeProblem(r.code, "ledger.csv", r.line, r.reason));
    }
  }
  return { rows, invalid: invalidRows, problems, dupNotes, count: csv.records.length };
}

export function ledgerLine(row: LedgerRow): string {
  return csvLine([row.date, row.amountText, row.currency, row.account, row.category, row.tags.join(";"), row.note]);
}

/** Canonical CSV text: the header, then every row in order, LF ends. */
export function serializeLedger(rows: readonly LedgerRow[]): string {
  let out = LEDGER_HEADER + "\n";
  for (const r of rows) out += ledgerLine(r) + "\n";
  return out;
}

/** Append one row to ledger text without rewriting the other lines (A6). */
export function appendLedgerLine(text: string, row: LedgerRow): string {
  const base = text.length === 0 ? LEDGER_HEADER + "\n" : text.endsWith("\n") ? text : text + "\n";
  return base + ledgerLine(row) + "\n";
}
