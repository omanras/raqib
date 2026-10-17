// Import and export of the five files (app ADR section 2). Import takes the
// file as the CLI would read it: UTF-8 bytes, decoded strictly (a byte the
// CLI could not decode is refused, never replaced). A file the CLI could
// not read at all (wrong CSV header, empty, not YAML, wrong top-level
// shape) is refused with the reason and, for a CSV, the expected header;
// anything else is imported as is and judged by the engine.
import { utf8Length, MAX_FILE_BYTES } from "../engine/csv";
import { loadDecisions } from "../engine/decisions";
import { HOLDINGS_HEADER } from "../engine/holdings";
import { LEDGER_HEADER } from "../engine/ledger";
import { parsePolicies } from "../engine/policies";
import { RATES_HEADER } from "../engine/rates";
import { FILE_NAMES, type FileName, type Problem } from "../engine/types";

export const CSV_HEADERS: Partial<Record<FileName, string>> = {
  "ledger.csv": LEDGER_HEADER,
  "holdings.csv": HOLDINGS_HEADER,
  "rates.csv": RATES_HEADER,
};

export type Refusal =
  | { kind: "not-utf8"; detail: string }
  | { kind: "empty" }
  | { kind: "too-large"; bytes: number }
  | { kind: "wrong-header"; expected: string; got: string }
  | { kind: "unreadable"; problem: Problem }
  | { kind: "unknown-name"; name: string };

export type Checked = { ok: true; name: FileName; text: string } | { ok: false; name: string; refusal: Refusal };

/** The household file a chosen file stands for, by its exact name. */
export function fileNameOf(name: string): FileName | null {
  const base = name.split(/[\\/]/).pop() ?? name;
  return (FILE_NAMES as readonly string[]).includes(base) ? (base as FileName) : null;
}

/** Decode UTF-8 strictly; the byte where decoding fails is named. */
export function decodeUtf8(bytes: Uint8Array): { ok: true; text: string } | { ok: false; detail: string } {
  try {
    return { ok: true, text: new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes) };
  } catch {
    // find the first bad byte for the message
    let lo = 0;
    let hi = bytes.length;
    while (hi - lo > 1) {
      const mid = (lo + hi) >> 1;
      try {
        new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(0, mid), { stream: true });
        lo = mid;
      } catch {
        hi = mid;
      }
    }
    return { ok: false, detail: `byte ${lo}` };
  }
}

function firstLine(text: string): string {
  const t = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
  const nl = t.indexOf("\n");
  const line = nl < 0 ? t : t.slice(0, nl);
  return line.endsWith("\r") ? line.slice(0, -1) : line;
}

const YAML_FILE_LEVEL = ["FILE-EMPTY", "BAD-YAML", "BAD-SHAPE", "FILE-TOO-LARGE", "INTERNAL"];

/** Check one file's text before it replaces the stored one. */
export function checkImport(name: FileName, text: string): Checked {
  if (text === "") return { ok: false, name, refusal: { kind: "empty" } };
  const bytes = utf8Length(text);
  if (bytes >= MAX_FILE_BYTES) return { ok: false, name, refusal: { kind: "too-large", bytes } };
  const header = CSV_HEADERS[name];
  if (header !== undefined) {
    const got = firstLine(text);
    if (got !== header) return { ok: false, name, refusal: { kind: "wrong-header", expected: header, got } };
    return { ok: true, name, text };
  }
  const problems = name === "policies.yml" ? parsePolicies(text).problems : loadDecisions(text, new Set(), null).problems;
  const fatal = problems.find((p) => YAML_FILE_LEVEL.includes(p.code));
  if (fatal) return { ok: false, name, refusal: { kind: "unreadable", problem: fatal } };
  return { ok: true, name, text };
}

/** Check a chosen file (bytes and its name, or the file it was chosen for). */
export function checkFileBytes(chosenName: string, bytes: Uint8Array, forName: FileName | null = null): Checked {
  const name = forName ?? fileNameOf(chosenName);
  if (name === null) return { ok: false, name: chosenName, refusal: { kind: "unknown-name", name: chosenName } };
  const decoded = decodeUtf8(bytes);
  if (!decoded.ok) return { ok: false, name, refusal: { kind: "not-utf8", detail: decoded.detail } };
  return checkImport(name, decoded.text);
}
