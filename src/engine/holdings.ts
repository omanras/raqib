// holdings.csv: snapshots of balances and positions (reference engine ADR
// section 4, qayd/ledger.py). Header exactly `date,account,asset,class,quantity,value,currency`.
import { csvLine } from "./csv";
import { dupNotesOf } from "./ledger";
import { dated, loadCsv, problem } from "./loader";
import { isCurrencyCode, parseAmount, parseIsoDate } from "./text";
import type { Config, HoldingRow, ParsedHoldings, Problem, Snapshot } from "./types";

export const HOLDINGS_HEADER = "date,account,asset,class,quantity,value,currency";

export function parseHoldings(text: string | null, config: Config | null, file = "holdings.csv"): ParsedHoldings {
  const accounts = new Set(config ? config.accounts : []);
  const classes = new Set(config ? config.classes : []);
  const loaded = loadCsv<HoldingRow>(text, file, HOLDINGS_HEADER, 7, (fields, line, f) => {
    const [dText, account, asset, cls, qText, vText, cur] = fields as [string, string, string, string, string, string, string];
    const problems: Problem[] = [];
    const date = parseIsoDate(dText);
    if (date === null) problems.push(problem(f, line, "BAD-DATE", `date '${dText}' is not YYYY-MM-DD`));
    const extra = dated(date);
    if (!accounts.has(account)) problems.push(problem(f, line, "UNKNOWN-ACCOUNT", `account '${account}' is not declared`, "invalid", extra));
    if (asset === "") problems.push(problem(f, line, "BAD-ASSET", "asset name is empty", "invalid", extra));
    if (!classes.has(cls)) problems.push(problem(f, line, "UNKNOWN-CLASS", `class '${cls}' is not declared`, "invalid", extra));
    const quantity = parseAmount(qText);
    if (quantity === null) problems.push(problem(f, line, "BAD-QUANTITY", `quantity '${qText}' is not decimal text`, "invalid", extra));
    const value = parseAmount(vText);
    if (value === null) problems.push(problem(f, line, "BAD-VALUE", `value '${vText}' is not decimal text`, "invalid", extra));
    if (!isCurrencyCode(cur)) problems.push(problem(f, line, "BAD-CURRENCY", `currency '${cur}' is not a 3-letter ISO-4217 code`, "invalid", extra));
    if (problems.length > 0 || date === null || quantity === null || value === null) return { row: null, problems };
    return {
      row: { date, account, asset, cls, quantity, quantityText: qText, value, valueText: vText, currency: cur, line, file: f, cite: `${f}:${line}` },
      problems,
    };
  });
  return { rows: loaded.rows, problems: loaded.problems, dupNotes: dupNotesOf(loaded.problems) };
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

/** The current snapshot as of a date: the latest date <= asOf; date null when there is none. */
export function latestSnapshot(rows: readonly HoldingRow[], asOf: string): Snapshot {
  let best: string | null = null;
  for (const r of rows) {
    if (r.date <= asOf && (best === null || r.date > best)) best = r.date;
  }
  return best === null ? { date: null, rows: [] } : snapshotOn(rows, best);
}

export function holdingLine(row: Pick<HoldingRow, "date" | "account" | "asset" | "cls" | "quantityText" | "valueText" | "currency">): string {
  return csvLine([row.date, row.account, row.asset, row.cls, row.quantityText, row.valueText, row.currency]);
}

export function serializeHoldings(rows: readonly HoldingRow[]): string {
  let out = HOLDINGS_HEADER + "\n";
  for (const r of rows) out += holdingLine(r) + "\n";
  return out;
}

/** Append rows (a new snapshot) to holdings text without rewriting the rest. */
export function appendHoldingLines(text: string | null, rows: readonly Parameters<typeof holdingLine>[0][]): string {
  let out = text === null || text.length === 0 ? HOLDINGS_HEADER + "\n" : text.endsWith("\n") ? text : text + "\n";
  for (const r of rows) out += holdingLine(r) + "\n";
  return out;
}
