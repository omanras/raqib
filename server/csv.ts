/**
 * CSV for exports (RFC 4180 quoting) with S4.4 formula-injection escaping:
 * a cell that starts with =, +, -, @, a tab or a carriage return is
 * prefixed with a single quote so a spreadsheet shows it as text instead of
 * evaluating it.
 */
const FORMULA_START = /^[=+\-@\t\r]/;

export function csvCell(value: string | number | boolean | null | undefined): string {
  let text = value === null || value === undefined ? '' : String(value);
  if (FORMULA_START.test(text)) text = `'${text}`;
  if (/[",\n\r]/.test(text)) text = `"${text.replace(/"/g, '""')}"`;
  return text;
}

export function csvRow(cells: readonly (string | number | boolean | null | undefined)[]): string {
  return cells.map(csvCell).join(',');
}

/** UTF-8 with a byte-order mark, so spreadsheet programs read Arabic names correctly. */
export function csvDocument(header: readonly string[], rows: readonly (readonly (string | number | boolean | null | undefined)[])[]): string {
  return `﻿${[csvRow(header), ...rows.map(csvRow)].join('\r\n')}\r\n`;
}
