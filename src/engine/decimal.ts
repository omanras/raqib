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

/** Canonical amount text: no exponent, no trailing zeros, "0" for zero. */
export function fmt(value: Decimal): string {
  if (value.isZero()) return "0";
  return value.toString();
}
