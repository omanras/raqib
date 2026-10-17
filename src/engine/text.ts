// The field rules of the reference loaders (qayd/ledger.py, rates.py).
// Amount text is plain decimal ("-300.000", "3.50", "1200"); nothing else
// is an amount (A5).
import { D, type Decimal } from "./decimal";
import { isValidDate } from "./dates";

const AMOUNT_RE = /^-?[0-9]+(\.[0-9]+)?$/;
const RATE_RE = /^[0-9]+(\.[0-9]+)?$/;
const CURRENCY_RE = /^[A-Z]{3}$/;
const DATE_RE = /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/;
// Python's \s for str patterns (Unicode whitespace) and the ';' separator.
const TAG_RE = /^[^\t\n\v\f\r\x1c-\x1f \x85\xa0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000;]+$/;

/** A strict ISO date (YYYY-MM-DD, calendar-valid), else null. */
export function parseIsoDate(text: string): string | null {
  return DATE_RE.test(text) && isValidDate(text) ? text : null;
}

/** Decimal from plain decimal text, or null when the text is not an amount. */
export function parseAmount(text: string): Decimal | null {
  return AMOUNT_RE.test(text) ? D(text) : null;
}

/** A rate: unsigned decimal text, positive. */
export function parseRate(text: string): Decimal | null {
  if (!RATE_RE.test(text)) return null;
  const r = D(text);
  return r.lte(0) ? null : r;
}

export function isCurrencyCode(text: string): boolean {
  return CURRENCY_RE.test(text);
}

/** `;`-separated non-empty tokens without whitespace, or null when malformed. */
export function parseTags(text: string): string[] | null {
  if (text === "") return [];
  const tokens = text.split(";");
  return tokens.every((t) => TAG_RE.test(t)) ? tokens : null;
}
