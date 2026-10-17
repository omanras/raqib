// ledger.csv: one row per money movement (reference engine ADR section 3,
// qayd/ledger.py). Header exactly `date,amount,currency,account,category,tags,note`.
import { csvLine } from "./csv";
import { dated, loadCsv, problem } from "./loader";
import { isCurrencyCode, parseAmount, parseIsoDate, parseTags } from "./text";
import type { Config, DupNote, LedgerRow, ParsedLedger, Problem } from "./types";

export const LEDGER_HEADER = "date,amount,currency,account,category,tags,note";

export function declaredCategories(config: Config | null): Set<string> {
  const out = new Set<string>();
  if (!config) return out;
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

export function dupNotesOf(problems: readonly Problem[]): DupNote[] {
  return problems.filter((p) => p.code === "DUP-ROW" && p.dup_of !== undefined).map((p) => ({ line: p.line, firstLine: p.dup_of as number }));
}

/**
 * Parse ledger text. Every malformed field is a problem naming its line
 * (a row may have several) and the run continues; exact duplicates are
 * DUP-ROW warnings, never dropped. Accounts and categories are checked
 * against the config; without one nothing is declared.
 */
export function parseLedger(text: string | null, config: Config | null, file = "ledger.csv"): ParsedLedger {
  const accounts = new Set(config ? config.accounts : []);
  const categories = declaredCategories(config);
  const loaded = loadCsv<LedgerRow>(text, file, LEDGER_HEADER, 7, (fields, line, f) => {
    const [dText, aText, cur, account, category, tagsText, note] = fields as [string, string, string, string, string, string, string];
    const problems: Problem[] = [];
    const date = parseIsoDate(dText);
    if (date === null) problems.push(problem(f, line, "BAD-DATE", `date '${dText}' is not YYYY-MM-DD`));
    const extra = dated(date);
    const amount = parseAmount(aText);
    if (amount === null) problems.push(problem(f, line, "BAD-AMOUNT", `amount '${aText}' is not decimal text`, "invalid", extra));
    if (!isCurrencyCode(cur)) problems.push(problem(f, line, "BAD-CURRENCY", `currency '${cur}' is not a 3-letter ISO-4217 code`, "invalid", extra));
    if (!accounts.has(account)) problems.push(problem(f, line, "UNKNOWN-ACCOUNT", `account '${account}' is not declared`, "invalid", extra));
    if (!categories.has(category)) problems.push(problem(f, line, "UNKNOWN-CATEGORY", `category '${category}' is not declared`, "invalid", extra));
    const tags = parseTags(tagsText);
    if (tags === null) problems.push(problem(f, line, "BAD-TAGS", `tags '${tagsText}' must be ';'-separated non-empty tokens`, "invalid", extra));
    if (problems.length > 0 || date === null || amount === null || tags === null) return { row: null, problems };
    return {
      row: { date, amount, amountText: aText, currency: cur, account, category, tags, note, line, file: f, cite: `${f}:${line}` },
      problems,
    };
  });
  return { rows: loaded.rows, problems: loaded.problems, dupNotes: dupNotesOf(loaded.problems) };
}

export function ledgerLine(row: Pick<LedgerRow, "date" | "amountText" | "currency" | "account" | "category" | "tags" | "note">): string {
  return csvLine([row.date, row.amountText, row.currency, row.account, row.category, row.tags.join(";"), row.note]);
}

/** Canonical CSV text: the header, then every row in order, LF ends. */
export function serializeLedger(rows: readonly LedgerRow[]): string {
  let out = LEDGER_HEADER + "\n";
  for (const r of rows) out += ledgerLine(r) + "\n";
  return out;
}

/** Append one row to ledger text without rewriting the other lines (A6). */
export function appendLedgerLine(text: string | null, row: Parameters<typeof ledgerLine>[0]): string {
  const base = text === null || text.length === 0 ? LEDGER_HEADER + "\n" : text.endsWith("\n") ? text : text + "\n";
  return base + ledgerLine(row) + "\n";
}
