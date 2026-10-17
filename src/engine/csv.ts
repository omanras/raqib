// CSV the way the reference engine reads it: the file is split into lines
// on "\n" (a trailing "\r" is dropped, a BOM is tolerated), and each line is
// one record parsed like Python's csv.reader in strict mode (excel dialect).
// A record never spans lines. Output quotes only the fields that need it.

export const MAX_LINE_BYTES = 1024 * 1024;
export const MAX_FILE_BYTES = 64 * 1024 * 1024;

/** UTF-8 byte length of a string (a lone surrogate counts as three bytes). */
export function utf8Length(s: string): number {
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x80) n += 1;
    else if (c < 0x800) n += 2;
    else if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length && (s.charCodeAt(i + 1) & 0xfc00) === 0xdc00) {
      n += 4;
      i++;
    } else n += 3;
  }
  return n;
}

export interface TextLine {
  /** 1-based */
  line: number;
  /** null when the line could not be read (too long) */
  text: string | null;
  /** UTF-8 bytes of the line, for LINE-TOO-LONG */
  bytes: number;
}

/** Split file text into numbered lines as the CLI does; the final newline ends the last line. */
export function splitLines(text0: string): TextLine[] {
  const text = text0.charCodeAt(0) === 0xfeff ? text0.slice(1) : text0;
  const raw = text.split("\n");
  if (text.endsWith("\n")) raw.pop();
  return raw.map((chunk0, i) => {
    const chunk = chunk0.endsWith("\r") ? chunk0.slice(0, -1) : chunk0;
    const bytes = utf8Length(chunk);
    return { line: i + 1, text: bytes >= MAX_LINE_BYTES ? null : chunk, bytes };
  });
}

export type CsvSplit = { ok: true; fields: string[] } | { ok: false; error: string };

const enum S {
  StartRecord,
  StartField,
  InField,
  InQuoted,
  QuoteInQuoted,
  EatCrnl,
}

/** One line through Python's csv.reader(strict=True); the error text is Python's. */
export function splitCsvLine(line: string): CsvSplit {
  const fields: string[] = [];
  let field = "";
  let state: S = S.StartRecord;
  const chars = [...line];
  for (let i = 0; i <= chars.length; i++) {
    const eol = i === chars.length;
    const c = eol ? "" : (chars[i] as string);
    const nl = !eol && (c === "\n" || c === "\r");
    if (state === S.StartRecord) {
      if (eol) return { ok: true, fields };
      if (nl) {
        state = S.EatCrnl;
        continue;
      }
      state = S.StartField;
    }
    switch (state) {
      case S.StartField:
        if (eol || nl) {
          fields.push(field);
          field = "";
          state = eol ? S.StartRecord : S.EatCrnl;
        } else if (c === '"') state = S.InQuoted;
        else if (c === ",") {
          fields.push(field);
          field = "";
        } else {
          field += c;
          state = S.InField;
        }
        break;
      case S.InField:
        if (eol || nl) {
          fields.push(field);
          field = "";
          state = eol ? S.StartRecord : S.EatCrnl;
        } else if (c === ",") {
          fields.push(field);
          field = "";
          state = S.StartField;
        } else field += c;
        break;
      case S.InQuoted:
        if (eol) break;
        if (c === '"') state = S.QuoteInQuoted;
        else field += c;
        break;
      case S.QuoteInQuoted:
        if (c === '"') {
          field += '"';
          state = S.InQuoted;
        } else if (c === ",") {
          fields.push(field);
          field = "";
          state = S.StartField;
        } else if (eol || nl) {
          fields.push(field);
          field = "";
          state = eol ? S.StartRecord : S.EatCrnl;
        } else return { ok: false, error: `',' expected after '"'` };
        break;
      case S.EatCrnl:
        if (nl) break;
        if (eol) state = S.StartRecord;
        else return { ok: false, error: "new-line character seen in unquoted field - do you need to open the file with newline=''?" };
        break;
      default:
        break;
    }
  }
  if (state !== S.StartRecord) return { ok: false, error: "unexpected end of data" };
  return { ok: true, fields };
}

function needsQuote(field: string): boolean {
  return /[",\r\n]/.test(field);
}

export function csvField(field: string): string {
  return needsQuote(field) ? '"' + field.replace(/"/g, '""') + '"' : field;
}

export function csvLine(fields: readonly string[]): string {
  return fields.map(csvField).join(",");
}
