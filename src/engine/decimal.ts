// A5: money is exact. Every amount in the engine is a Decimal from this
// module, configured like the reference engine's Python decimal context:
// 28 significant digits, ROUND_HALF_EVEN. A JS number never holds an amount.
import { Decimal as DecimalBase } from "decimal.js";

export const Decimal = DecimalBase.clone({
  precision: 28,
  rounding: DecimalBase.ROUND_HALF_EVEN,
  // Never print exponent notation: amounts are plain decimal text.
  toExpNeg: -9e15,
  toExpPos: 9e15,
});

export type Decimal = InstanceType<typeof Decimal>;

/** Build a Decimal from decimal text or another Decimal. */
export function D(value: string | Decimal): Decimal {
  return new Decimal(value);
}

export const ZERO: Decimal = D("0");
export const HUNDRED: Decimal = D("100");

/** Canonical amount text: no exponent, no trailing zeros, "0" for zero. */
export function fmt(value: Decimal): string {
  if (value.isZero()) return "0";
  return value.toString();
}

/** The CLI's money(): exact decimal text without trailing zeros, then the currency. */
export function money(amount: Decimal, currency = ""): string {
  return (fmt(amount) + " " + currency).trim();
}

/** The CLI's pct(): two decimals, half-even, trailing zeros dropped (display only). */
export function pct(amount: Decimal): string {
  const q = amount.toDecimalPlaces(2, Decimal.ROUND_HALF_EVEN);
  const text = q.isZero() ? (q.isNeg() ? "-0" : "0") : q.toString();
  return text + "%";
}

const DECIMAL_TEXT = /^([-+]?)(\d*)(?:\.(\d*))?(?:[eE]([-+]?\d+))?$/;

/**
 * Python's str(Decimal(text)) for decimal text: trailing zeros kept,
 * scientific notation when the exponent is positive or the number is
 * smaller than 1e-6 (the CLI prints declared limits this way:
 * "4500.50 OMR"). Null when the text is not decimal text.
 */
export function pyDecimalStr(text: string): string | null {
  const m = DECIMAL_TEXT.exec(text);
  if (!m) return null;
  const sign = m[1] === "-" ? "-" : "";
  const intDigits = m[2] ?? "";
  const fracDigits = m[3] ?? "";
  if (intDigits === "" && fracDigits === "") return null;
  let digits = (intDigits + fracDigits).replace(/^0+/, "");
  if (digits === "") digits = "0";
  const exp = parseInt(m[4] ?? "0", 10) - fracDigits.length;
  const leftdigits = exp + digits.length;
  const dotplace = exp <= 0 && leftdigits > -6 ? leftdigits : 1;
  let intpart: string;
  let fracpart: string;
  if (dotplace <= 0) {
    intpart = "0";
    fracpart = "." + "0".repeat(-dotplace) + digits;
  } else if (dotplace >= digits.length) {
    intpart = digits + "0".repeat(dotplace - digits.length);
    fracpart = "";
  } else {
    intpart = digits.slice(0, dotplace);
    fracpart = "." + digits.slice(dotplace);
  }
  const e = leftdigits - dotplace;
  const expText = e === 0 ? "" : "E" + (e > 0 ? "+" : "-") + Math.abs(e);
  return sign + intpart + fracpart + expText;
}

/** A declared number: its exact value and the text the CLI prints for it. */
export interface Num {
  value: Decimal;
  /** Python's str() of the Decimal the CLI holds */
  text: string;
}

export function num(text: string): Num {
  return { value: D(text), text: pyDecimalStr(text) ?? fmt(D(text)) };
}
