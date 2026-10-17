// YAML in and out for policies.yml and decisions.yml. Loading resolves
// plain scalars as PyYAML's safe loader does (YAML 1.1: yes/no/on/off are
// booleans, 010 is octal, 1_000 is an int), with the reference engine's
// overrides: a float is a Decimal read from its text (A5) and a date stays
// text. Every mapping remembers the line it starts on, so verdicts can cite
// policies.yml:N and decisions.yml:N like the CLI.
import yaml from "js-yaml";
import { D } from "./decimal";
import { isMap, PyDec, PyInt, pyRepr, type PyValue } from "./py";
import { isValidDate } from "./dates";

const BOOL_RE = /^(?:yes|Yes|YES|no|No|NO|true|True|TRUE|false|False|FALSE|on|On|ON|off|Off|OFF)$/;
const TRUE_RE = /^(?:yes|Yes|YES|true|True|TRUE|on|On|ON)$/;
const NULL_RE = /^(?:~|null|Null|NULL|)$/;
const INT_RE = /^(?:[-+]?0b[0-1_]+|[-+]?0[0-7_]+|[-+]?(?:0|[1-9][0-9_]*)|[-+]?0x[0-9a-fA-F_]+|[-+]?[1-9][0-9_]*(?::[0-5]?[0-9])+)$/;
const FLOAT_RE =
  /^(?:[-+]?(?:[0-9][0-9_]*)\.[0-9_]*(?:[eE][-+][0-9]+)?|\.[0-9_]+(?:[eE][-+][0-9]+)?|[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))$/;
// What Python's Decimal() accepts from a float scalar once "_" is removed.
const DECIMAL_FLOAT_RE = /^[-+]?(?:\d+\.?\d*|\.\d+)(?:[eE][-+]?\d+)?$/;

function constructInt(source: string): PyInt {
  let v = source.replace(/_/g, "");
  let sign = "";
  if (v[0] === "-") sign = "-";
  if (v[0] === "-" || v[0] === "+") v = v.slice(1);
  if (v === "0") return new PyInt(D("0"), source);
  let value;
  if (v.startsWith("0b")) value = D("0b" + v.slice(2));
  else if (v.startsWith("0x")) value = D("0x" + v.slice(2));
  else if (v[0] === "0") value = D("0o" + v.slice(1));
  else if (v.includes(":")) {
    value = D("0");
    for (const part of v.split(":")) value = value.times(60).plus(D(String(parseInt(part, 10))));
  } else value = D(v);
  return new PyInt(sign === "-" ? value.neg() : value, source);
}

function constructFloat(source: string): PyDec | string {
  const text = source.replace(/_/g, "");
  if (!DECIMAL_FLOAT_RE.test(text)) return source; // .inf, .nan, 1:30.5: left as text
  return new PyDec(D(text), text, source);
}

const types = [
  new yaml.Type("tag:yaml.org,2002:null", {
    kind: "scalar",
    resolve: (data: string | null) => data === null || NULL_RE.test(data),
    construct: () => null,
  }),
  new yaml.Type("tag:yaml.org,2002:bool", {
    kind: "scalar",
    resolve: (data: string | null) => data !== null && BOOL_RE.test(data),
    construct: (data: string) => TRUE_RE.test(data),
  }),
  new yaml.Type("tag:yaml.org,2002:int", {
    kind: "scalar",
    resolve: (data: string | null) => data !== null && INT_RE.test(data),
    construct: constructInt,
  }),
  new yaml.Type("tag:yaml.org,2002:float", {
    kind: "scalar",
    resolve: (data: string | null) => data !== null && FLOAT_RE.test(data),
    construct: constructFloat,
  }),
];

// js-yaml's own merge key type (<<), which PyYAML's safe loader also honours.
const MERGE = (yaml as unknown as { types: { merge: yaml.Type } }).types.merge;
const SCHEMA = yaml.FAILSAFE_SCHEMA.extend({ implicit: [...types, MERGE] });

export type YamlLoad =
  | {
      ok: true;
      /** null when the document holds nothing (the CLI's FILE-EMPTY) */
      value: PyValue;
      /** 1-based line where a loaded mapping starts, else null */
      lineOf: (v: PyValue | undefined) => number | null;
    }
  | { ok: false; line: number; reason: string };

interface ListenerState {
  input: string;
  position: number;
  line: number;
  kind: string | null;
  result: unknown;
}

/** 1-based line of the first token at or after the parser position. */
function tokenLine(state: ListenerState): number {
  const s = state.input;
  let i = state.position;
  let line = state.line;
  for (;;) {
    const ch = s[i];
    if (ch === " " || ch === "\t" || ch === "\r") i++;
    else if (ch === "\n") {
      i++;
      line++;
    } else if (ch === "#") {
      while (i < s.length && s[i] !== "\n") i++;
    } else break;
  }
  return line + 1;
}

/** 1-based line of the `---` that starts a second document, else 0. */
function secondDocumentLine(text: string): number {
  let content = false;
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const l = (lines[i] as string).replace(/\r$/, "");
    if (/^---(\s|$)/.test(l)) {
      if (content) return i + 1;
      content = l.slice(3).trim() !== "" && !l.slice(3).trim().startsWith("#");
      continue;
    }
    if (l.trim() !== "" && !l.trim().startsWith("#") && !l.startsWith("%")) content = true;
  }
  return 0;
}

/**
 * Load one YAML document. A document that holds nothing (empty, comments
 * only, a bare null) loads as null; the caller reports FILE-EMPTY.
 */
export function loadYaml(text0: string): YamlLoad {
  const text = text0.charCodeAt(0) === 0xfeff ? text0.slice(1) : text0;
  const lines = new WeakMap<object, number>();
  const stack: number[] = [];
  const listener = (event: "open" | "close", state: ListenerState): void => {
    if (event === "open") {
      stack.push(tokenLine(state));
      return;
    }
    const line = stack.pop() as number;
    const r = state.result;
    if (state.kind === "mapping" && typeof r === "object" && r !== null && !lines.has(r)) lines.set(r, line);
  };
  let value: unknown;
  try {
    value = yaml.load(text, { schema: SCHEMA, listener } as yaml.LoadOptions);
  } catch (e) {
    if (e instanceof yaml.YAMLException) {
      const mark = (e as { mark?: { line?: number } }).mark;
      let line = mark && typeof mark.line === "number" ? mark.line + 1 : 0;
      let reason = e.reason || e.message;
      if (reason.startsWith("expected a single document")) {
        // PyYAML marks where the second document starts.
        line = secondDocumentLine(text);
        reason = "but found another document";
      }
      if (reason === "duplicated mapping key") {
        // PyYAML names the key: "duplicate key 'limit'"; js-yaml marks its line.
        const key = /^\s*(?:- )?([^\s:#'"{}[\],][^:#{}[\],]*?)\s*:/.exec(text.split("\n")[line - 1] ?? "");
        reason = key ? `duplicate key ${pyRepr(key[1] as string)}` : "duplicate key";
      }
      return { ok: false, line, reason: "YAML error: " + reason };
    }
    return { ok: false, line: 0, reason: "YAML error: " + String(e) };
  }
  return {
    ok: true,
    value: value === undefined ? null : (value as PyValue),
    lineOf: (v) => (isMap(v) ? (lines.get(v) ?? null) : null),
  };
}

// ---- emitting -------------------------------------------------------------

const PLAIN_RE = /^[A-Za-z_][A-Za-z0-9_.\-/() ]*[A-Za-z0-9_.\-/()]$|^[A-Za-z_]$/;
const NUMBER_RE = /^[-+]?(\d+(\.\d*)?|\.\d+)([eE][-+]?\d+)?$/;

/** A string scalar, plain when YAML 1.1 would read it back as the same text. */
export function yStr(s: string): string {
  if (PLAIN_RE.test(s) && !BOOL_RE.test(s) && !NULL_RE.test(s) && s !== "y" && s !== "n" && s !== "Y" && s !== "N") return s;
  return JSON.stringify(s);
}

/** A scalar that other loaders read as a number or a date when written plain. */
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

/** Emit a loaded value inline (flow style); numbers as they were written. */
export function yFlow(v: PyValue | undefined): string {
  if (v === null || v === undefined) return yNull();
  if (v === true) return "true";
  if (v === false) return "false";
  if (v instanceof PyInt || v instanceof PyDec) return v.source;
  if (typeof v === "string") return yStr(v);
  if (Array.isArray(v)) return yFlowSeq(v.map(yFlow));
  return yFlowMap(Object.keys(v).map((k) => [yStr(k), yFlow(v[k])] as const));
}
