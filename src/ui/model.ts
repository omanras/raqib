// What the data screens compute from the household's text, kept free of
// the DOM so it can be unit tested: today's date, the text behind a
// citation, the ledger table and its filters, the reversing row, appending
// a row or a snapshot through the engine's writers and judging the new
// lines with the engine's loaders before anything is saved.
import { splitLines } from "../engine/csv";
import { appendHoldingLines, latestSnapshot, parseHoldings } from "../engine/holdings";
import { appendLedgerLine, parseLedger } from "../engine/ledger";
import { daysBetween } from "../engine/dates";
import type { Config, FileName, HoldingRow, HouseholdText, LedgerRow, Problem } from "../engine/types";

/** Today on the device clock, as ISO text (the as-of default). */
export function todayIso(now: Date = new Date()): string {
  const p = (n: number, w: number) => String(n).padStart(w, "0");
  return `${p(now.getFullYear(), 4)}-${p(now.getMonth() + 1, 2)}-${p(now.getDate(), 2)}`;
}

/** The line a citation names ("ledger.csv:249"), as written in the file. */
export function citedLine(files: HouseholdText, cite: string): { file: string; line: number | null; text: string | null } {
  const m = /^(.+?):(\d+)$/.exec(cite);
  if (!m) return { file: cite, line: null, text: null };
  const file = m[1] as string;
  const line = parseInt(m[2] as string, 10);
  const text = files[file as FileName];
  if (typeof text !== "string") return { file, line, text: null };
  const l = splitLines(text).find((x) => x.line === line);
  return { file, line, text: l ? l.text : null };
}

// ---- ledger -------------------------------------------------------------------

export interface LedgerFilter {
  month: string;
  account: string;
  category: string;
  tag: string;
  text: string;
}

export const NO_FILTER: LedgerFilter = { month: "", account: "", category: "", tag: "", text: "" };

/** Newest first: by date, then by line, both descending. */
export function newestFirst<T extends { date: string; line: number }>(rows: readonly T[]): T[] {
  return [...rows].sort((a, b) => (a.date < b.date ? 1 : a.date > b.date ? -1 : b.line - a.line));
}

export function filterLedger(rows: readonly LedgerRow[], f: LedgerFilter): LedgerRow[] {
  const needle = f.text.trim().toLowerCase();
  return rows.filter((r) => {
    if (f.month && !r.date.startsWith(f.month + "-")) return false;
    if (f.account && r.account !== f.account) return false;
    if (f.category && r.category !== f.category) return false;
    if (f.tag && !r.tags.includes(f.tag)) return false;
    if (needle) {
      const hay = [r.date, r.amountText, r.currency, r.account, r.category, r.tags.join(";"), r.note].join(" ").toLowerCase();
      if (!hay.includes(needle)) return false;
    }
    return true;
  });
}

/** The months, accounts, categories and tags present, for the filter lists. */
export function ledgerFacets(rows: readonly LedgerRow[]): { months: string[]; accounts: string[]; categories: string[]; tags: string[] } {
  const months = new Set<string>();
  const accounts = new Set<string>();
  const categories = new Set<string>();
  const tags = new Set<string>();
  for (const r of rows) {
    months.add(r.date.slice(0, 7));
    accounts.add(r.account);
    categories.add(r.category);
    for (const t of r.tags) tags.add(t);
  }
  return { months: [...months].sort().reverse(), accounts: [...accounts].sort(), categories: [...categories].sort(), tags: [...tags].sort() };
}

export interface LedgerInput {
  date: string;
  amountText: string;
  currency: string;
  account: string;
  category: string;
  /** as typed: `;`-separated */
  tagsText: string;
  note: string;
}

export const REVERSAL_TAG = "reversal";

/** The mirror of a row (A6): same date, opposite amount, tagged reversal, citing the original. */
export function reversalOf(row: LedgerRow): LedgerInput {
  const t = row.amountText;
  const amountText = t.startsWith("-") ? t.slice(1) : "-" + t;
  const tags = row.tags.includes(REVERSAL_TAG) ? row.tags : [...row.tags, REVERSAL_TAG];
  return {
    date: row.date,
    amountText,
    currency: row.currency,
    account: row.account,
    category: row.category,
    tagsText: tags.join(";"),
    note: `reverses ${row.cite}`,
  };
}

/** The line number the next appended line gets. */
function nextLine(text: string | null, header: string): number {
  const base = text === null || text === "" ? header + "\n" : text.endsWith("\n") ? text : text + "\n";
  return base.split("\n").length;
}

export type Appended = { ok: true; text: string; line: number; warnings: Problem[] } | { ok: false; problems: Problem[] };

/**
 * Append a ledger row through the engine's writer and judge the new line
 * with the engine's loader. Invalid -> refused with the problems; a
 * warning (an exact duplicate) does not refuse: the CLI allows it.
 */
export function appendLedger(text: string | null, config: Config | null, input: LedgerInput): Appended {
  const row = { ...input, tags: input.tagsText === "" ? [] : input.tagsText.split(";") };
  const line = nextLine(text, "date,amount,currency,account,category,tags,note");
  const next = appendLedgerLine(text, row);
  const mine = parseLedger(next, config).problems.filter((p) => p.line >= line);
  const bad = mine.filter((p) => p.class === "invalid");
  if (bad.length > 0) return { ok: false, problems: bad };
  return { ok: true, text: next, line, warnings: mine };
}

// ---- holdings -----------------------------------------------------------------

export interface HoldingInput {
  account: string;
  asset: string;
  cls: string;
  quantityText: string;
  valueText: string;
  currency: string;
}

/** The latest snapshot's rows, as the starting point of a new one. */
export function prefillSnapshot(rows: readonly HoldingRow[]): HoldingInput[] {
  const latest = latestSnapshot(rows, "9999-12-31");
  return latest.rows.map((r) => ({ account: r.account, asset: r.asset, cls: r.cls, quantityText: r.quantityText, valueText: r.valueText, currency: r.currency }));
}

export function appendSnapshot(text: string | null, config: Config | null, date: string, rows: readonly HoldingInput[]): Appended {
  const line = nextLine(text, "date,account,asset,class,quantity,value,currency");
  const next = appendHoldingLines(text, rows.map((r) => ({ ...r, date })));
  const mine = parseHoldings(next, config).problems.filter((p) => p.line >= line);
  const bad = mine.filter((p) => p.class === "invalid");
  if (rows.length === 0) return { ok: false, problems: [] };
  if (bad.length > 0) return { ok: false, problems: bad };
  return { ok: true, text: next, line, warnings: mine };
}

/** Snapshots newest first. */
export function snapshotsNewestFirst(rows: readonly HoldingRow[]): { date: string; rows: HoldingRow[] }[] {
  const by = new Map<string, HoldingRow[]>();
  for (const r of rows) by.set(r.date, [...(by.get(r.date) ?? []), r]);
  return [...by.keys()]
    .sort()
    .reverse()
    .map((date) => ({ date, rows: by.get(date) as HoldingRow[] }));
}

export type Freshness = { kind: "none" } | { kind: "unknown"; date: string; age: number } | { kind: "fresh" | "stale"; date: string; age: number; max: number };

/** The current snapshot as of a date and its age against snapshot_max_age_days. */
export function freshness(rows: readonly HoldingRow[], asOf: string, maxAge: number | null): Freshness {
  const snap = latestSnapshot(rows, asOf);
  if (snap.date === null) return { kind: "none" };
  const age = daysBetween(snap.date, asOf);
  if (maxAge === null) return { kind: "unknown", date: snap.date, age };
  return { kind: age > maxAge ? "stale" : "fresh", date: snap.date, age, max: maxAge };
}

/** Problems that stop a raw text from being saved (warnings do not). */
export function blocking(problems: readonly Problem[]): Problem[] {
  return problems.filter((p) => p.class === "invalid");
}
