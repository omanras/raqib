// Changes the forms make to the YAML files, done on the text so the rest
// of the file is untouched (comments, layout, the other entries): replace,
// add or remove one policy's block item, flip one decision's status line,
// and the next free decision id. When the layout is not one block item per
// entry the change is refused and the raw panel is the way (never a silent
// rewrite of the whole file). Also the "export all" bundle and its reader.
import { FILE_NAMES, type FileName, type HouseholdText } from "../engine/types";

function lines(text: string): string[] {
  return text.split("\n");
}

function indentOf(l: string): number {
  return l.length - l.trimStart().length;
}

function isBlankOrComment(l: string): boolean {
  const t = l.trim();
  return t === "" || t.startsWith("#");
}

function isItem(l: string, col: number): boolean {
  return indentOf(l) === col && (l.trimStart().startsWith("- ") || l.trim() === "-");
}

export interface Section {
  /** 0-based index of the `policies:` line, or -1 for a top-level list */
  keyLine: number;
  /** column of the items' "- " */
  col: number;
  /** 0-based index of each item's first line */
  starts: number[];
  /** 0-based index of the section's last line that belongs to it */
  last: number;
}

/** The block items of a list: under a top-level key, or the document itself. */
export function listSection(text: string, key: string | null): Section | null {
  const ls = lines(text);
  let i = 0;
  let keyLine = -1;
  if (key !== null) {
    keyLine = ls.findIndex((l) => l === `${key}:` || l.startsWith(`${key}:`) && isBlankOrComment(l.slice(key.length + 1)));
    if (keyLine < 0) return null;
    i = keyLine + 1;
  }
  let col: number | null = null;
  const starts: number[] = [];
  let last = keyLine;
  for (; i < ls.length; i++) {
    const l = ls[i] as string;
    if (isBlankOrComment(l)) continue;
    if (col === null) {
      if (!l.trimStart().startsWith("-")) return key === null ? null : { keyLine, col: 2, starts: [], last: keyLine };
      col = indentOf(l);
    }
    if (isItem(l, col)) starts.push(i);
    else if (indentOf(l) <= col && !(indentOf(l) === col && l.trimStart().startsWith("-"))) break;
    last = i;
  }
  return { keyLine, col: col ?? 2, starts, last };
}

/** [first, last] 0-based lines of item k, trailing blank and comment lines left out. */
function itemRange(text: string, s: Section, k: number): [number, number] {
  const ls = lines(text);
  const first = s.starts[k] as number;
  let end = k + 1 < s.starts.length ? (s.starts[k + 1] as number) - 1 : s.last;
  while (end > first && isBlankOrComment(ls[end] as string)) end--;
  return [first, end];
}

export type Edit = { ok: true; text: string } | { ok: false; reason: "layout" };

/** Replace policy k's block with the given lines (they carry their own "  - "). */
export function replacePolicy(text: string, k: number, block: string[], count: number): Edit {
  const s = listSection(text, "policies");
  if (s === null || s.starts.length !== count || k >= count) return { ok: false, reason: "layout" };
  const [a, b] = itemRange(text, s, k);
  const ls = lines(text);
  return { ok: true, text: [...ls.slice(0, a), ...reindent(block, s.col), ...ls.slice(b + 1)].join("\n") };
}

export function removePolicy(text: string, k: number, count: number): Edit {
  const s = listSection(text, "policies");
  if (s === null || s.starts.length !== count || k >= count) return { ok: false, reason: "layout" };
  const [a, b] = itemRange(text, s, k);
  const ls = lines(text);
  const rest = [...ls.slice(0, a), ...ls.slice(b + 1)];
  if (count === 1) {
    // the list is now empty: say so, as the serializer would
    rest[s.keyLine] = "policies: []";
  }
  return { ok: true, text: rest.join("\n") };
}

export function addPolicy(text: string, block: string[], count: number): Edit {
  const ls = lines(text);
  const empty = ls.findIndex((l) => /^policies:\s*\[\s*\]\s*(#.*)?$/.test(l));
  if (empty >= 0 && count === 0) {
    return { ok: true, text: [...ls.slice(0, empty), "policies:", ...block, ...ls.slice(empty + 1)].join("\n") };
  }
  const s = listSection(text, "policies");
  if (s === null) {
    if (count !== 0 || ls.some((l) => l.startsWith("policies:"))) return { ok: false, reason: "layout" };
    const base = text === "" || text.endsWith("\n") ? text : text + "\n";
    return { ok: true, text: base + ["policies:", ...block].join("\n") + "\n" };
  }
  if (s.starts.length !== count) return { ok: false, reason: "layout" };
  const end = count === 0 ? s.keyLine : itemRange(text, s, count - 1)[1];
  return { ok: true, text: [...ls.slice(0, end + 1), ...reindent(block, s.col), ...ls.slice(end + 1)].join("\n") };
}

/** policyBlock() writes items at column 2; follow the file's own column. */
function reindent(block: string[], col: number): string[] {
  if (col === 2) return block;
  return block.map((l) => (col > 2 ? " ".repeat(col - 2) + l : l.slice(2 - col)));
}

/** decisions.yml with the given decision's `status: open` set to closed. */
export function closeDecision(text: string, decisionLine: number): Edit {
  const s = listSection(text, null);
  if (s === null) return { ok: false, reason: "layout" };
  const k = s.starts.indexOf(decisionLine - 1);
  if (k < 0) return { ok: false, reason: "layout" };
  const [a, b] = itemRange(text, s, k);
  const ls = lines(text);
  for (let i = a; i <= b; i++) {
    const m = /^(\s*(?:- )?status:\s*)open(\s*(?:#.*)?)$/.exec(ls[i] as string);
    if (m) {
      ls[i] = `${m[1]}closed${m[2]}`;
      return { ok: true, text: ls.join("\n") };
    }
  }
  return { ok: false, reason: "layout" };
}

/** D-<date>-<n>, the first n not used by an id in the file. */
export function nextDecisionId(text: string | null, date: string): string {
  const used = new Set<string>();
  for (const l of lines(text ?? "")) {
    const m = /^\s*(?:- )?id:\s*["']?([^"'\s#]+)/.exec(l);
    if (m) used.add(m[1] as string);
  }
  for (let n = 1; ; n++) {
    const id = `D-${date}-${n}`;
    if (!used.has(id)) return id;
  }
}

// ---- export all ----------------------------------------------------------------

const SECTION_RE = /^=== (\S+) ===$/;

/**
 * Every present file, each after its line `=== name ===`; the text follows
 * as is, then one "\n" that the reader takes off again, so any text (even
 * one without a final newline) comes back byte for byte.
 */
export function bundleText(files: HouseholdText): string {
  let out = "";
  for (const f of FILE_NAMES) {
    const t = files[f];
    if (t === null) continue;
    out += `=== ${f} ===\n${t}\n`;
  }
  return out;
}

export interface BundlePart {
  name: string;
  text: string;
}

/**
 * The sections of a bundle, in order. Each part's text is everything
 * between its header line and the next header line; the last part also
 * ends with the bundle's final "\n", which is taken off.
 */
export function readBundle(text: string): BundlePart[] {
  const parts: { name: string; body: string[] }[] = [];
  for (const l of text.split("\n")) {
    const m = SECTION_RE.exec(l.replace(/\r$/, ""));
    if (m && isFileName(m[1] as string)) parts.push({ name: m[1] as string, body: [] });
    else parts[parts.length - 1]?.body.push(l);
  }
  return parts.map((p, i) => {
    const body = p.body.join("\n");
    return { name: p.name, text: i === parts.length - 1 && text.endsWith("\n") ? body.slice(0, -1) : body };
  });
}

export function isFileName(x: string): x is FileName {
  return (FILE_NAMES as readonly string[]).includes(x);
}
