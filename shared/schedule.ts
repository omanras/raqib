/**
 * Schedule (ADR-0001 §2): pure functions from (start_date, period, due_day,
 * n) to due dates. Dates are ISO calendar dates ("YYYY-MM-DD") with no time
 * and no time zone; all arithmetic is on integer day numbers (days since
 * 1970-01-01 in the proleptic Gregorian calendar), never on Date objects.
 */
import { mulAmount } from './money.js';

export type Period = 'monthly' | 'weekly' | 'biweekly';
export const PERIODS: readonly Period[] = ['monthly', 'weekly', 'biweekly'];

/** For monthly: day of month 1-28. For weekly/biweekly: ISO weekday 1 (Mon) - 7 (Sun). */
export type DueDay = number;

export function isPeriod(value: unknown): value is Period {
  return value === 'monthly' || value === 'weekly' || value === 'biweekly';
}

export function isValidDueDay(period: Period, dueDay: number): boolean {
  if (!Number.isInteger(dueDay)) return false;
  return period === 'monthly' ? dueDay >= 1 && dueDay <= 28 : dueDay >= 1 && dueDay <= 7;
}

/** Days since 1970-01-01 for a proleptic Gregorian date (H. Hinnant's algorithm). */
export function daysFromCivil(y: number, m: number, d: number): number {
  const yy = m <= 2 ? y - 1 : y;
  const era = Math.floor(yy / 400);
  const yoe = yy - era * 400;
  const doy = Math.floor((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5) + d - 1;
  const doe = yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy;
  return era * 146097 + doe - 719468;
}

export function civilFromDays(days: number): { y: number; m: number; d: number } {
  const z = days + 719468;
  const era = Math.floor(z / 146097);
  const doe = z - era * 146097;
  const yoe = Math.floor((doe - Math.floor(doe / 1460) + Math.floor(doe / 36524) - Math.floor(doe / 146096)) / 365);
  const doy = doe - (365 * yoe + Math.floor(yoe / 4) - Math.floor(yoe / 100));
  const mp = Math.floor((5 * doy + 2) / 153);
  const d = doy - Math.floor((153 * mp + 2) / 5) + 1;
  const m = mp + (mp < 10 ? 3 : -9);
  return { y: yoe + era * 400 + (m <= 2 ? 1 : 0), m, d };
}

export function isLeapYear(y: number): boolean {
  return (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0;
}

export function daysInMonth(y: number, m: number): number {
  return [31, isLeapYear(y) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][m - 1] as number;
}

const ISO_DATE = /^(\d{4})-(\d{2})-(\d{2})$/;

export function isISODate(text: unknown): text is string {
  if (typeof text !== 'string') return false;
  const m = ISO_DATE.exec(text);
  if (!m) return false;
  const y = Number(m[1]);
  const mo = Number(m[2]);
  const d = Number(m[3]);
  return mo >= 1 && mo <= 12 && d >= 1 && d <= daysInMonth(y, mo);
}

export function toDays(iso: string): number {
  if (!isISODate(iso)) throw new RangeError(`not an ISO date: ${iso}`);
  const [y, m, d] = iso.split('-').map(Number) as [number, number, number];
  return daysFromCivil(y, m, d);
}

export function fromDays(days: number): string {
  const { y, m, d } = civilFromDays(days);
  return `${String(y).padStart(4, '0')}-${String(m).padStart(2, '0')}-${String(d).padStart(2, '0')}`;
}

export function addDays(iso: string, n: number): string {
  return fromDays(toDays(iso) + n);
}

/** b - a in days. */
export function daysBetween(a: string, b: string): number {
  return toDays(b) - toDays(a);
}

/** ISO weekday: 1 = Monday ... 7 = Sunday. 1970-01-01 was a Thursday (4). */
export function isoWeekday(iso: string): number {
  return ((((toDays(iso) + 3) % 7) + 7) % 7) + 1;
}

/** Adds whole months keeping the day; only valid for days 1-28. */
function addMonths(y: number, m: number, d: number, k: number): string {
  const idx = y * 12 + (m - 1) + k;
  const ny = Math.floor(idx / 12);
  const nm = (idx % 12) + 1;
  return fromDays(daysFromCivil(ny, nm, d));
}

/**
 * Due date of round n (1-based).
 * - monthly: round 1 is the first date on or after start whose day of month
 *   is dueDay (1-28, so every month has it); round n is n-1 months later.
 * - weekly / biweekly: round 1 is the first date on or after start whose ISO
 *   weekday is dueDay; round n is 7 or 14 days per round later.
 */
export function dueDate(start: string, period: Period, dueDay: DueDay, n: number): string {
  if (!isISODate(start)) throw new RangeError(`not an ISO date: ${start}`);
  if (!isValidDueDay(period, dueDay)) throw new RangeError(`invalid due day ${dueDay} for ${period}`);
  if (!Number.isSafeInteger(n) || n < 1) throw new RangeError(`invalid round ${n}`);
  const [y, m, d] = start.split('-').map(Number) as [number, number, number];
  if (period === 'monthly') {
    return d <= dueDay ? addMonths(y, m, dueDay, n - 1) : addMonths(y, m, dueDay, n);
  }
  const startDays = toDays(start);
  const offset = (dueDay - isoWeekday(start) + 7) % 7;
  const step = period === 'weekly' ? 7 : 14;
  return fromDays(startDays + offset + step * (n - 1));
}

export interface ScheduleInput {
  startDate: string;
  period: Period;
  dueDay: DueDay;
  memberCount: number;
  contribution: number;
  recipientPays: boolean;
  /** Member ids by position: order[0] receives in round 1. */
  order: readonly string[];
}

export interface ScheduledRound {
  n: number;
  dueDate: string;
  recipient: string;
  /** Expected pot in minor units: contribution x payers. */
  pot: number;
  /** Members expected to contribute this round. */
  payers: number;
}

/** Number of members who contribute in a round. */
export function payersPerRound(memberCount: number, recipientPays: boolean): number {
  return recipientPays ? memberCount : memberCount - 1;
}

/** All rounds of a circle: n = 1..member_count, one recipient each. */
export function roundsFor(circle: ScheduleInput): ScheduledRound[] {
  if (circle.order.length !== circle.memberCount) {
    throw new RangeError('order must list every member exactly once');
  }
  if (new Set(circle.order).size !== circle.order.length) throw new RangeError('order has duplicates');
  const payers = payersPerRound(circle.memberCount, circle.recipientPays);
  const pot = mulAmount(circle.contribution, payers);
  const rounds: ScheduledRound[] = [];
  for (let n = 1; n <= circle.memberCount; n += 1) {
    rounds.push({
      n,
      dueDate: dueDate(circle.startDate, circle.period, circle.dueDay, n),
      recipient: circle.order[n - 1] as string,
      pot,
      payers,
    });
  }
  return rounds;
}
