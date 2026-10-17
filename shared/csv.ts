/**
 * CSV for exports made in the browser (RFC 4180 quoting) with S4.4
 * formula-injection escaping: a cell that starts with =, +, -, @, a tab or
 * a carriage return gets a leading single quote so a spreadsheet shows it
 * as text. The same rule as server/csv.ts, which serves the statement CSV.
 */
const FORMULA_START = /^[=+\-@\t\r]/;

export type Cell = string | number | boolean | null | undefined;

export function csvCell(value: Cell): string {
  let text = value === null || value === undefined ? '' : String(value);
  if (FORMULA_START.test(text)) text = `'${text}`;
  if (/[",\n\r]/.test(text)) text = `"${text.replace(/"/g, '""')}"`;
  return text;
}

export function csvRow(cells: readonly Cell[]): string {
  return cells.map(csvCell).join(',');
}

/** UTF-8 with a byte-order mark, so spreadsheet programs read Arabic correctly. */
export function csvDocument(header: readonly string[], rows: readonly (readonly Cell[])[]): string {
  return `﻿${[csvRow(header), ...rows.map(csvRow)].join('\r\n')}\r\n`;
}
