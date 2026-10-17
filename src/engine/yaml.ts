// YAML in and out for policies.yml and decisions.yml. Loading uses the
// failsafe schema so every scalar arrives as text (a number is never built
// from an amount, A5); the loaders convert what they need. Line numbers of
// block-sequence items are found in the text so verdicts can cite them.
import yaml from "js-yaml";
import { isValidDate } from "./dates";

export type YamlValue = string | YamlValue[] | { [key: string]: YamlValue } | null;

export type YamlLoad = { ok: true; value: YamlValue } | { ok: false; line: number | null; reason: string };

/** Load one YAML document; every scalar is text; an empty document is null. */
export function loadYaml(text: string): YamlLoad {
  try {
    const v = yaml.load(text, { schema: yaml.FAILSAFE_SCHEMA });
    if (v === undefined) return { ok: true, value: null };
    return { ok: true, value: v as YamlValue };
  } catch (e) {
    if (e instanceof yaml.YAMLException) {
      const mark = (e as { mark?: { line?: number } }).mark;
      const line = mark && typeof mark.line === "number" ? mark.line + 1 : null;
      return { ok: false, line, reason: e.reason || e.message };
    }
    return { ok: false, line: null, reason: String(e) };
  }
}

export function isMap(v: YamlValue | undefined): v is { [key: string]: YamlValue } {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export function isSeq(v: YamlValue | undefined): v is YamlValue[] {
  return Array.isArray(v);
}

/** A text scalar that is not the YAML spelling of null, or null. */
export function textOf(v: YamlValue | undefined): string | null {
  if (typeof v !== "string") return null;
  if (v === "" || v === "~" || v === "null" || v === "Null" || v === "NULL") return null;
  return v;
}

/** True for a scalar that spells null in YAML (or an absent key). */
export function isNullish(v: YamlValue | undefined): boolean {
  return v === undefined || v === null || (typeof v === "string" && textOf(v) === null);
}

/**
 * 1-based line numbers of the items of a block sequence whose "- " markers
 * sit at the given column, in order. Only lines outside block scalars are
 * considered; a flow-style document yields no lines.
 */
export function itemLines(text: string, column: number, fromLine = 1): number[] {
  const out: number[] = [];
  const lines = text.split(/\r?\n/);
  const prefix = " ".repeat(column);
  for (let i = fromLine - 1; i < lines.length; i++) {
    const l = lines[i] as string;
    if (l.startsWith(prefix + "- ") || l === prefix + "-") out.push(i + 1);
  }
  return out;
}

/** Line of the first top-level `key:` line, or null. */
export function keyLine(text: string, key: string): number | null {
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i] as string;
    if (l.startsWith(key + ":")) return i + 1;
  }
  return null;
}

/** Line numbers of the items of the sequence under a top-level key. */
export function keyedItemLines(text: string, key: string): number[] {
  const start = keyLine(text, key);
  if (start === null) return [];
  const lines = text.split(/\r?\n/);
  let column: number | null = null;
  const out: number[] = [];
  for (let i = start; i < lines.length; i++) {
    const l = lines[i] as string;
    if (l.trim() === "" || l.trim().startsWith("#")) continue;
    const indent = l.length - l.trimStart().length;
    if (column === null) {
      if (indent === 0) break;
      if (!l.trimStart().startsWith("- ")) break;
      column = indent;
    }
    if (indent < column) break;
    if (indent === column && (l.trimStart().startsWith("- ") || l.trim() === "-")) out.push(i + 1);
  }
  return out;
}

// ---- emitting -------------------------------------------------------------

const PLAIN_RE = /^[A-Za-z_][A-Za-z0-9_.\-/() ]*[A-Za-z0-9_.\-/()]$|^[A-Za-z_]$/;
const RESERVED = new Set(["true", "false", "null", "yes", "no", "on", "off", "y", "n", "~", "True", "False", "Null", "Yes", "No", "On", "Off", "TRUE", "FALSE", "NULL", "YES", "NO", "ON", "OFF"]);
const NUMBER_RE = /^[-+]?(\d+(\.\d*)?|\.\d+)([eE][-+]?\d+)?$/;

/** A string scalar, plain when YAML would read it back as the same text. */
export function yStr(s: string): string {
  if (PLAIN_RE.test(s) && !RESERVED.has(s)) return s;
  return JSON.stringify(s);
}

/** A scalar that may be read as a number or a date by other loaders (kept plain). */
export function yPlainOrStr(s: string): string {
  if (NUMBER_RE.test(s) || isValidDate(s)) return s;
  return yStr(s);
}

export function yNull(): string {
  return "null";
}

export function yFlowSeq(items: readonly string[]): string {
  return "[" + items.join(", ") + "]";
}

export function yFlowMap(entries: readonly (readonly [string, string])[]): string {
  return "{" + entries.map(([k, v]) => `${k}: ${v}`).join(", ") + "}";
}

/** Emit a loaded value inline (flow style), plain numbers kept plain. */
export function yFlow(v: YamlValue): string {
  if (v === null) return yNull();
  if (typeof v === "string") return yPlainOrStr(v);
  if (Array.isArray(v)) return yFlowSeq(v.map(yFlow));
  return yFlowMap(Object.keys(v).map((k) => [yStr(k), yFlow(v[k] as YamlValue)] as const));
}
