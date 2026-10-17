// What a measure or a limit evaluates to (reference engine qayd/measures.py):
//   Value    the amount and the rows it rests on (ledger, holdings, rates)
//   Unknown  cannot be known from the declared files; red (A5)
//   Stale    a holdings snapshot older than snapshot_max_age_days allows
import type { Decimal } from "./decimal";
import type { Citable } from "./types";

export interface Value {
  tag: "value";
  amount: Decimal;
  rows: Citable[];
  /** extra detail: month labels used, a drawdown series, a kill history */
  detail: unknown[];
}

export interface Unknown {
  tag: "unknown";
  reason: string;
  cites: string[];
  /** "invalid" when an invalid loader row is the reason */
  cause: "unknown" | "invalid";
}

export interface Stale {
  tag: "stale";
  ageDays: number;
  date: string;
  /** the value the stale snapshot gives, when it can be computed */
  amount: Decimal | null;
  rows: Citable[];
}

export function value(amount: Decimal, rows: Citable[] = [], detail: unknown[] = []): Value {
  return { tag: "value", amount, rows, detail };
}

export function unknown(reason: string, cites: string[] = [], cause: "unknown" | "invalid" = "unknown"): Unknown {
  return { tag: "unknown", reason, cites, cause };
}

export function stale(ageDays: number, date: string, amount: Decimal | null, rows: Citable[] = []): Stale {
  return { tag: "stale", ageDays, date, amount, rows };
}

/** Cites of rows, first occurrence order, without repeats. */
export function citesOf(rows: readonly Citable[]): string[] {
  return [...new Set(rows.map((r) => r.cite))];
}

/** Rows without repeats (by identity), first occurrence order. */
export function uniqueRows<T>(rows: readonly T[]): T[] {
  return [...new Set(rows)];
}
