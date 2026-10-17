// The CSV loader shared by ledger.csv, holdings.csv and rates.csv (the
// reference engine's ledger._load). It never throws: a missing or empty
// file, a header that does not match, a malformed line, each becomes a
// problem naming the file and the line, and the run continues past it.
import { MAX_FILE_BYTES, MAX_LINE_BYTES, splitCsvLine, splitLines, utf8Length } from "./csv";
import type { Problem } from "./types";

export const INVALID = "invalid";
export const WARN = "warn";

export function problem(
  file: string,
  line: number,
  code: string,
  reason: string,
  cls: "invalid" | "warn" = INVALID,
  extra: { date?: string; dup_of?: number; field?: string } = {},
): Problem {
  return { file, line, code, class: cls, reason, ...extra };
}

/** The extra keys of a row problem: the row's date when it parsed. */
export function dated(date: string | null): { date?: string } {
  return date === null ? {} : { date };
}

export type RowParser<R> = (fields: string[], line: number, file: string) => { row: R | null; problems: Problem[] };

export interface Loaded<R> {
  rows: R[];
  problems: Problem[];
}

/** File-level checks before any line is read; a problem here stops the file. */
export function fileProblem(text: string | null, file: string): Problem | null {
  if (text === null) return problem(file, 0, "FILE-MISSING", `file not found: ${file}`);
  const size = utf8Length(text);
  if (size >= MAX_FILE_BYTES) return problem(file, 0, "FILE-TOO-LARGE", `file is ${size} bytes; the limit is ${MAX_FILE_BYTES}`);
  return null;
}

export function loadCsv<R>(text: string | null, file: string, header: string, expected: number, parseRow: RowParser<R>): Loaded<R> {
  const rows: R[] = [];
  const problems: Problem[] = [];
  try {
    const fatal = fileProblem(text, file);
    if (fatal) return { rows, problems: [fatal] };
    if (text === "") return { rows, problems: [problem(file, 0, "FILE-EMPTY", "file is empty: no header")] };
    const lines = splitLines(text as string);
    for (const l of lines) {
      if (l.text === null) problems.push(problem(file, l.line, "LINE-TOO-LONG", `line is ${l.bytes} bytes; the limit is ${MAX_LINE_BYTES}`));
    }
    const head = lines[0] as (typeof lines)[number];
    if (head.text === null) {
      problems.push(problem(file, head.line, "BAD-HEADER", "header line could not be read"));
      return { rows, problems };
    }
    if (head.text !== header) {
      problems.push(problem(file, head.line, "BAD-HEADER", `header must be exactly '${header}', got '${head.text}'`));
      return { rows, problems };
    }
    const seen = new Map<string, number>();
    for (const l of lines.slice(1)) {
      if (l.text === null) continue;
      if (l.text === "") {
        problems.push(problem(file, l.line, "EMPTY-LINE", "empty line"));
        continue;
      }
      const split = splitCsvLine(l.text);
      if (!split.ok) {
        problems.push(problem(file, l.line, "BAD-CSV", `malformed CSV: ${split.error}`));
        continue;
      }
      if (split.fields.length !== expected) {
        problems.push(problem(file, l.line, "COLUMN-COUNT", `expected ${expected} columns, got ${split.fields.length}`));
        continue;
      }
      const key = JSON.stringify(split.fields);
      const first = seen.get(key);
      if (first === undefined) seen.set(key, l.line);
      else problems.push(problem(file, l.line, "DUP-ROW", `exact duplicate of line ${first}`, WARN, { dup_of: first }));
      const r = parseRow(split.fields, l.line, file);
      problems.push(...r.problems);
      if (r.row !== null) rows.push(r.row);
    }
  } catch (e) {
    problems.push(problem(file, 0, "INTERNAL", `loader failed: ${e instanceof Error ? `${e.name}: ${e.message}` : String(e)}`));
  }
  return { rows, problems };
}
