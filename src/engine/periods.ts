// Periods are ISO calendar months, quarters and years written as
// 2026-09, 2026-Q3 and 2026 (reference engine ADR section 5).
import { daysInMonth, formatDate, parseDate } from "./dates";

export type PeriodKind = "month" | "quarter" | "year";

export const PERIOD_KINDS: readonly PeriodKind[] = ["month", "quarter", "year"];

export function isPeriodKind(x: unknown): x is PeriodKind {
  return x === "month" || x === "quarter" || x === "year";
}

export interface Period {
  kind: PeriodKind;
  text: string;
  /** first day, ISO */
  start: string;
  /** last day, ISO */
  end: string;
}

function pad2(n: number): string {
  return n < 10 ? "0" + n : String(n);
}

function quarterOfMonth(m: number): number {
  return Math.floor((m - 1) / 3) + 1;
}

/** The period text of the given kind that contains the date. */
export function periodOf(date: string, kind: PeriodKind): string {
  const p = parseDate(date);
  if (!p) throw new Error(`periodOf: bad date ${date}`);
  if (kind === "month") return `${p.y}-${pad2(p.m)}`;
  if (kind === "quarter") return `${p.y}-Q${quarterOfMonth(p.m)}`;
  return String(p.y);
}

const MONTH_RE = /^(\d{4})-(\d{2})$/;
const QUARTER_RE = /^(\d{4})-Q([1-4])$/;
const YEAR_RE = /^(\d{4})$/;

/** Parse period text into its bounds; null when it is not a period. */
export function parsePeriod(text: string): Period | null {
  let m = MONTH_RE.exec(text);
  if (m) {
    const y = parseInt(m[1] as string, 10);
    const mo = parseInt(m[2] as string, 10);
    if (mo < 1 || mo > 12) return null;
    return {
      kind: "month",
      text,
      start: formatDate({ y, m: mo, d: 1 }),
      end: formatDate({ y, m: mo, d: daysInMonth(y, mo) }),
    };
  }
  m = QUARTER_RE.exec(text);
  if (m) {
    const y = parseInt(m[1] as string, 10);
    const q = parseInt(m[2] as string, 10);
    const m1 = (q - 1) * 3 + 1;
    const m3 = m1 + 2;
    return {
      kind: "quarter",
      text,
      start: formatDate({ y, m: m1, d: 1 }),
      end: formatDate({ y, m: m3, d: daysInMonth(y, m3) }),
    };
  }
  m = YEAR_RE.exec(text);
  if (m) {
    return { kind: "year", text, start: `${m[1]}-01-01`, end: `${m[1]}-12-31` };
  }
  return null;
}

/** The period of the given kind that contains the date. */
export function periodContaining(date: string, kind: PeriodKind): Period {
  const p = parsePeriod(periodOf(date, kind));
  if (!p) throw new Error(`periodContaining: bad date ${date}`);
  return p;
}

/** True when the date (ISO) falls inside the period. */
export function inPeriod(date: string, period: Period): boolean {
  return date >= period.start && date <= period.end;
}

function monthIndex(y: number, m: number): number {
  return y * 12 + (m - 1);
}

function monthText(index: number): string {
  const y = Math.floor(index / 12);
  const m = (index % 12) + 1;
  return `${y}-${pad2(m)}`;
}

/** The n calendar months ending with the month of asOf, ascending. */
export function trailing(asOf: string, n: number): string[] {
  const p = parseDate(asOf);
  if (!p) throw new Error(`trailing: bad date ${asOf}`);
  const last = monthIndex(p.y, p.m);
  const out: string[] = [];
  for (let i = last - n + 1; i <= last; i++) out.push(monthText(i));
  return out;
}

/** The next period of the same kind. */
export function nextPeriod(period: Period): Period {
  const p = parseDate(period.end);
  if (!p) throw new Error("nextPeriod: bad period");
  const next = p.m === 12 ? formatDate({ y: p.y + 1, m: 1, d: 1 }) : formatDate({ y: p.y, m: p.m + 1, d: 1 });
  return periodContaining(next, period.kind);
}

/** Every period of the kind from the one containing start to the one containing end. */
export function periodsBetween(start: string, end: string, kind: PeriodKind): Period[] {
  if (!parseDate(start) || !parseDate(end)) throw new Error("periodsBetween: bad date");
  const out: Period[] = [];
  if (start > end) return out;
  let cur = periodContaining(start, kind);
  const last = periodOf(end, kind);
  for (;;) {
    out.push(cur);
    if (cur.text === last) break;
    cur = nextPeriod(cur);
  }
  return out;
}

/** The calendar months inside a period, ascending. */
export function monthsOf(period: Period): string[] {
  return periodsBetween(period.start, period.end, "month").map((p) => p.text);
}
