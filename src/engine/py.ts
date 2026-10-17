// The values the reference engine reads from YAML, as PyYAML's safe loader
// builds them (YAML 1.1 scalars), and the few Python spellings the CLI's
// messages are made of: repr() and str() of those values. Declared numbers
// are never JS numbers (A5): an int keeps its exact Decimal value, a float
// is read as Decimal from its text, as the CLI does.
import { D, fmt, pyDecimalStr, type Decimal, type Num } from "./decimal";

/** A YAML int (1.1 rules: 0x.., 0o.., 0b.., 1_000, 1:30). */
export class PyInt {
  constructor(
    readonly value: Decimal,
    /** the scalar as written, for the serializer */
    readonly source: string,
  ) {}
}

/** A YAML float read as Decimal from its text (underscores removed). */
export class PyDec {
  constructor(
    readonly value: Decimal,
    /** the text the Decimal was built from */
    readonly text: string,
    /** the scalar as written, for the serializer */
    readonly source: string,
  ) {}
}

export type PyValue = string | boolean | null | PyInt | PyDec | PyValue[] | PyMap;

export interface PyMap {
  [key: string]: PyValue;
}

export function isMap(v: PyValue | undefined): v is PyMap {
  return typeof v === "object" && v !== null && !Array.isArray(v) && !(v instanceof PyInt) && !(v instanceof PyDec);
}

export function isList(v: PyValue | undefined): v is PyValue[] {
  return Array.isArray(v);
}

export function isStr(v: PyValue | undefined): v is string {
  return typeof v === "string";
}

export function isInt(v: PyValue | undefined): v is PyInt {
  return v instanceof PyInt;
}

const NUMBER_TEXT = /^-?[0-9]+(\.[0-9]+)?\n?$/;

/** The CLI's is_number(): a YAML int, a YAML float, or decimal text. Not bool. */
export function isNumber(v: PyValue | undefined): boolean {
  if (v instanceof PyInt || v instanceof PyDec) return true;
  return typeof v === "string" && NUMBER_TEXT.test(v);
}

/** The CLI's to_decimal() for a value that passed isNumber(). */
export function toNum(v: PyValue): Num {
  if (v instanceof PyInt) return { value: v.value, text: fmt(v.value) };
  if (v instanceof PyDec) return { value: v.value, text: pyDecimalStr(v.text) ?? fmt(v.value) };
  const t = (v as string).trim();
  return { value: D(t), text: pyDecimalStr(t) ?? t };
}

/** A small whole number (days, window) from a YAML int. */
export function intOf(v: PyInt): number {
  return parseInt(fmt(v.value), 10);
}

function reprStr(s: string): string {
  const quote = s.includes("'") && !s.includes('"') ? '"' : "'";
  let out = quote;
  for (const ch of s) {
    const c = ch.codePointAt(0) as number;
    if (ch === "\\") out += "\\\\";
    else if (ch === quote) out += "\\" + quote;
    else if (ch === "\n") out += "\\n";
    else if (ch === "\r") out += "\\r";
    else if (ch === "\t") out += "\\t";
    else if (c < 0x20 || (c >= 0x7f && c < 0xa0)) out += "\\x" + c.toString(16).padStart(2, "0");
    else out += ch;
  }
  return out + quote;
}

/** Python's repr() of a loaded value, as the CLI's %r messages show it. */
export function pyRepr(v: PyValue | undefined): string {
  if (v === undefined || v === null) return "None";
  if (v === true) return "True";
  if (v === false) return "False";
  if (typeof v === "string") return reprStr(v);
  if (v instanceof PyInt) return fmt(v.value);
  if (v instanceof PyDec) return `Decimal('${pyDecimalStr(v.text) ?? fmt(v.value)}')`;
  if (Array.isArray(v)) return "[" + v.map(pyRepr).join(", ") + "]";
  return "{" + Object.keys(v).map((k) => `${reprStr(k)}: ${pyRepr(v[k])}`).join(", ") + "}";
}

/** Python's str() of a loaded value. */
export function pyStr(v: PyValue | undefined): string {
  if (typeof v === "string") return v;
  if (v instanceof PyDec) return pyDecimalStr(v.text) ?? fmt(v.value);
  return pyRepr(v);
}
