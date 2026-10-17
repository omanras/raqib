// Minimal RFC 4180 CSV reading and writing, with physical line numbers.
// A BOM and CRLF line ends are tolerated on input; output is LF.

export interface CsvRecord {
  /** 1-based physical line where the record starts */
  line: number;
  fields: string[];
  /** the record's text as written (without the line end) */
  raw: string;
}

export interface CsvText {
  /** the header fields, or null for an empty file */
  header: CsvRecord | null;
  records: CsvRecord[];
}

/** Split text into records; blank lines are skipped; quotes honoured. */
export function readCsv(text0: string): CsvText {
  let text = text0;
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  const records: CsvRecord[] = [];
  let i = 0;
  let line = 1;
  const n = text.length;
  while (i < n) {
    const startLine = line;
    const start = i;
    const fields: string[] = [];
    let field = "";
    let quoted = false;
    let any = false;
    for (;;) {
      if (i >= n) break;
      const ch = text[i] as string;
      if (quoted) {
        if (ch === '"') {
          if (text[i + 1] === '"') {
            field += '"';
            i += 2;
          } else {
            quoted = false;
            i++;
          }
        } else {
          if (ch === "\n") line++;
          field += ch;
          i++;
        }
        continue;
      }
      if (ch === '"' && field === "") {
        quoted = true;
        any = true;
        i++;
        continue;
      }
      if (ch === ",") {
        fields.push(field);
        field = "";
        any = true;
        i++;
        continue;
      }
      if (ch === "\r") {
        i++;
        if (text[i] === "\n") i++;
        line++;
        break;
      }
      if (ch === "\n") {
        i++;
        line++;
        break;
      }
      field += ch;
      any = true;
      i++;
    }
    const rawEnd = i;
    let raw = text.slice(start, rawEnd);
    if (raw.endsWith("\r\n")) raw = raw.slice(0, -2);
    else if (raw.endsWith("\n") || raw.endsWith("\r")) raw = raw.slice(0, -1);
    if (!any && field === "") continue; // blank line
    fields.push(field);
    records.push({ line: startLine, fields, raw });
  }
  const header = records.length > 0 ? (records[0] as CsvRecord) : null;
  return { header, records: records.slice(1) };
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
