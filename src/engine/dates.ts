// Calendar arithmetic on ISO dates (YYYY-MM-DD) with integer math only.
// No JS Date, no time zones: the same text gives the same day everywhere.

export interface Ymd {
  y: number;
  m: number;
  d: number;
}

const ISO_DATE = /^(\d{4})-(\d{2})-(\d{2})$/;

export function isLeapYear(y: number): boolean {
  return (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0;
}

export function daysInMonth(y: number, m: number): number {
  if (m === 2) return isLeapYear(y) ? 29 : 28;
  if (m === 4 || m === 6 || m === 9 || m === 11) return 30;
  return 31;
}

/** Parse strict ISO text into a calendar-valid date, or null. */
export function parseDate(text: string): Ymd | null {
  const m = ISO_DATE.exec(text);
  if (!m) return null;
  const y = parseInt(m[1] as string, 10);
  const mo = parseInt(m[2] as string, 10);
  const d = parseInt(m[3] as string, 10);
  if (y < 1 || mo < 1 || mo > 12) return null; // Python's date starts at year 1
  if (d < 1 || d > daysInMonth(y, mo)) return null;
  return { y, m: mo, d };
}

export function isValidDate(text: string): boolean {
  return parseDate(text) !== null;
}

function pad(n: number, width: number): string {
  let s = String(n);
  while (s.length < width) s = "0" + s;
  return s;
}

export function formatDate(x: Ymd): string {
  return `${pad(x.y, 4)}-${pad(x.m, 2)}-${pad(x.d, 2)}`;
}

/** Days since 1970-01-01 (proleptic Gregorian), Howard Hinnant's algorithm. */
export function toDays(x: Ymd): number {
  const y = x.m <= 2 ? x.y - 1 : x.y;
  const era = Math.floor(y / 400);
  const yoe = y - era * 400;
  const mp = (x.m + 9) % 12;
  const doy = Math.floor((153 * mp + 2) / 5) + x.d - 1;
  const doe = yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy;
  return era * 146097 + doe - 719468;
}

export function fromDays(z0: number): Ymd {
  const z = z0 + 719468;
  const era = Math.floor(z / 146097);
  const doe = z - era * 146097;
  const yoe = Math.floor((doe - Math.floor(doe / 1460) + Math.floor(doe / 36524) - Math.floor(doe / 146096)) / 365);
  const y = yoe + era * 400;
  const doy = doe - (365 * yoe + Math.floor(yoe / 4) - Math.floor(yoe / 100));
  const mp = Math.floor((5 * doy + 2) / 153);
  const d = doy - Math.floor((153 * mp + 2) / 5) + 1;
  const m = mp < 10 ? mp + 3 : mp - 9;
  return { y: m <= 2 ? y + 1 : y, m, d };
}

/** Whole days from a to b (b - a); both strict ISO dates. */
export function daysBetween(a: string, b: string): number {
  const pa = parseDate(a);
  const pb = parseDate(b);
  if (!pa || !pb) throw new Error(`daysBetween: bad date ${a} or ${b}`);
  return toDays(pb) - toDays(pa);
}

export function addDays(date: string, n: number): string {
  const p = parseDate(date);
  if (!p) throw new Error(`addDays: bad date ${date}`);
  return formatDate(fromDays(toDays(p) + n));
}

/** ISO text order equals calendar order for valid dates. */
export function compareDates(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}
