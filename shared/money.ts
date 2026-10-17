/**
 * Money (ADR-0001 §2, Constitution A4). Amounts are integers in the minor
 * unit of one declared currency (fils, cents). No floating point anywhere:
 * parsing works on the text, arithmetic on safe integers with explicit
 * overflow checks, formatting by integer division.
 */

export type MinorUnit = 2 | 3;

/** ISO-4217 currencies a circle may declare, with their minor unit. */
export const CURRENCIES: Readonly<Record<string, MinorUnit>> = Object.freeze({
  AED: 2,
  AUD: 2,
  BDT: 2,
  BHD: 3,
  CAD: 2,
  CHF: 2,
  DZD: 2,
  EGP: 2,
  EUR: 2,
  GBP: 2,
  IDR: 2,
  INR: 2,
  IQD: 3,
  JOD: 3,
  KES: 2,
  KWD: 3,
  LBP: 2,
  LYD: 3,
  MAD: 2,
  MYR: 2,
  NGN: 2,
  OMR: 3,
  PHP: 2,
  PKR: 2,
  QAR: 2,
  SAR: 2,
  SDG: 2,
  SEK: 2,
  SYP: 2,
  TND: 3,
  TRY: 2,
  USD: 2,
  YER: 2,
});

export function isCurrency(code: unknown): code is string {
  return typeof code === 'string' && Object.prototype.hasOwnProperty.call(CURRENCIES, code);
}

export function minorUnitOf(code: string): MinorUnit {
  const unit = CURRENCIES[code];
  if (unit === undefined) throw new RangeError(`unknown currency ${code}`);
  return unit;
}

/**
 * Largest single amount accepted (a contribution, a report, a payout), in
 * minor units. With at most MAX_MEMBERS members and rounds, every total a
 * circle can produce stays far below Number.MAX_SAFE_INTEGER.
 */
export const MAX_AMOUNT = 100_000_000_000; // 1e11 minor units
export const MAX_MEMBERS = 100;

export function isAmount(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= MAX_AMOUNT;
}

/** a + b, refusing non-integers and results outside the safe range. */
export function addAmounts(a: number, b: number): number {
  if (!Number.isSafeInteger(a) || !Number.isSafeInteger(b)) throw new RangeError('amounts must be safe integers');
  const r = a + b;
  if (!Number.isSafeInteger(r)) throw new RangeError('amount overflow');
  return r;
}

export function subAmounts(a: number, b: number): number {
  return addAmounts(a, -b);
}

/** Sum of amounts; accumulated in bigint, checked once at the end. */
export function sumAmounts(values: Iterable<number>): number {
  let total = 0n;
  for (const v of values) {
    if (!Number.isSafeInteger(v)) throw new RangeError('amounts must be safe integers');
    total += BigInt(v);
  }
  if (total > BigInt(Number.MAX_SAFE_INTEGER) || total < BigInt(Number.MIN_SAFE_INTEGER)) {
    throw new RangeError('amount overflow');
  }
  return Number(total);
}

/** amount * count (count a non-negative integer), checked. */
export function mulAmount(amount: number, count: number): number {
  if (!Number.isSafeInteger(amount) || !Number.isSafeInteger(count) || count < 0) {
    throw new RangeError('amount and count must be safe integers');
  }
  const r = BigInt(amount) * BigInt(count);
  if (r > BigInt(Number.MAX_SAFE_INTEGER) || r < BigInt(Number.MIN_SAFE_INTEGER)) throw new RangeError('amount overflow');
  return Number(r);
}

export type ParseAmountError =
  | 'empty'
  | 'sign'
  | 'exponent'
  | 'format'
  | 'grouping'
  | 'leading_zero'
  | 'too_many_decimals'
  | 'too_large';

export type ParseAmountResult = { ok: true; value: number } | { ok: false; error: ParseAmountError };

const ARABIC_INDIC = '٠١٢٣٤٥٦٧٨٩';
const EXTENDED_ARABIC_INDIC = '۰۱۲۳۴۵۶۷۸۹';

/** Arabic-Indic digits and Arabic separators to their Latin forms. */
function normalizeDigits(text: string): string {
  let out = '';
  for (const ch of text) {
    const a = ARABIC_INDIC.indexOf(ch);
    const e = EXTENDED_ARABIC_INDIC.indexOf(ch);
    if (a >= 0) out += String(a);
    else if (e >= 0) out += String(e);
    else if (ch === '٫') out += '.'; // Arabic decimal separator
    else if (ch === '٬') out += ','; // Arabic thousands separator
    else out += ch;
  }
  return out;
}

/**
 * Parses user input into minor units. The documented form is:
 *
 *   digits [ "." 1..minorUnit digits ]
 *
 * where the integer digits may be grouped by "," in groups of exactly three
 * ("1,234,567.500"); grouping is all or nothing. Arabic-Indic digits and the
 * Arabic decimal and thousands separators are accepted and read as their
 * Latin equivalents. Surrounding whitespace is ignored. Everything else is
 * refused with a reason: a sign (amounts are never negative), an exponent,
 * spaces or other characters, a leading zero ("012"), a bare or trailing
 * point (".5", "5."), more decimals than the currency has, or an amount
 * above MAX_AMOUNT.
 */
export function parseAmount(text: string, minorUnit: MinorUnit): ParseAmountResult {
  const s = normalizeDigits(text.trim());
  if (s === '') return { ok: false, error: 'empty' };
  if (/[+\-−]/.test(s)) return { ok: false, error: 'sign' };
  if (/[eE]/.test(s)) return { ok: false, error: 'exponent' };
  const m = /^([0-9][0-9,]*)(?:\.([0-9]+))?$/.exec(s);
  if (!m) return { ok: false, error: 'format' };
  const intPart = m[1] as string;
  const frac = m[2] ?? '';
  let digits = intPart;
  if (intPart.includes(',')) {
    if (!/^[1-9][0-9]{0,2}(,[0-9]{3})+$/.test(intPart)) return { ok: false, error: 'grouping' };
    digits = intPart.replace(/,/g, '');
  }
  if (digits.length > 1 && digits.startsWith('0')) return { ok: false, error: 'leading_zero' };
  if (frac.length > minorUnit) return { ok: false, error: 'too_many_decimals' };
  if (digits.length > 15) return { ok: false, error: 'too_large' };
  const minor = BigInt(digits) * 10n ** BigInt(minorUnit) + BigInt(frac.padEnd(minorUnit, '0') || '0');
  if (minor > BigInt(MAX_AMOUNT)) return { ok: false, error: 'too_large' };
  return { ok: true, value: Number(minor) };
}

/**
 * Minor units to text with Latin digits, "," thousands grouping and "."
 * decimals: formatMinor(123450, 3) === "123.450".
 */
export function formatMinor(amount: number, minorUnit: MinorUnit, options: { grouping?: boolean } = {}): string {
  if (!Number.isSafeInteger(amount)) throw new RangeError('amount must be a safe integer');
  const negative = amount < 0;
  const abs = BigInt(negative ? -amount : amount);
  const base = 10n ** BigInt(minorUnit);
  const whole = (abs / base).toString();
  const frac = (abs % base).toString().padStart(minorUnit, '0');
  const grouped = options.grouping === false ? whole : whole.replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  return `${negative ? '-' : ''}${grouped}.${frac}`;
}

/** formatMoney(123450, "OMR") === "123.450 OMR"; the code is always shown. */
export function formatMoney(amount: number, currency: string, options: { grouping?: boolean } = {}): string {
  return `${formatMinor(amount, minorUnitOf(currency), options)} ${currency}`;
}
