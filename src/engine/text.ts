// Small validators shared by the loaders. Amount text is plain decimal
// ("-300.000", "3.50", "1200"); nothing else is an amount (A5).
import { D, type Decimal } from "./decimal";

const AMOUNT_RE = /^[-+]?(\d+(\.\d*)?|\.\d+)$/;
const CURRENCY_RE = /^[A-Z]{3}$/;
const INT_RE = /^\d+$/;

export function isAmountText(text: string): boolean {
  return AMOUNT_RE.test(text);
}

/** Decimal from plain decimal text, or null when the text is not an amount. */
export function parseAmount(text: string): Decimal | null {
  if (!AMOUNT_RE.test(text)) return null;
  return D(text);
}

export function isCurrencyCode(text: string): boolean {
  return CURRENCY_RE.test(text);
}

/** A non-negative integer from digit text, or null. */
export function parseIntText(text: string): number | null {
  if (!INT_RE.test(text)) return null;
  return parseInt(text, 10);
}

/** `;`-separated tags; empty tokens dropped; nothing trimmed. */
export function splitTags(text: string): string[] {
  if (text === "") return [];
  return text.split(";").filter((t) => t !== "");
}
