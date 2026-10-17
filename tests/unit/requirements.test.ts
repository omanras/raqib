import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

const root = new URL('../../', import.meta.url).pathname;

function testFiles(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) out.push(...testFiles(full));
    else if (/\.(test|spec)\.tsx?$/.test(name)) out.push(full);
  }
  return out;
}

/** The titles passed to describe/it/test in every test file (unit, API, e2e, client). */
function titles(): string[] {
  const files = [...testFiles(join(root, 'tests')), ...testFiles(join(root, 'client'))];
  const out: string[] = [];
  for (const f of files) {
    const text = readFileSync(f, 'utf8');
    for (const m of text.matchAll(/\b(?:describe|it|test)(?:\.\w+)?\(\s*(['"`])([^'"`]*)\1/g)) out.push(m[2] as string);
    // Curried forms: it.skipIf(condition)(title, ...).
    for (const m of text.matchAll(/\)\(\s*(['"`])([^'"`]*)\1/g)) out.push(m[2] as string);
  }
  return out;
}

describe('M3.1 E1: every security requirement has a test named with its id', () => {
  it('each S-item of docs/SECURITY_REQUIREMENTS.md appears in at least one test title', () => {
    const doc = readFileSync(join(root, 'docs/SECURITY_REQUIREMENTS.md'), 'utf8');
    const ids = [...new Set([...doc.matchAll(/^- (S\d\.\d) /gm)].map((m) => m[1] as string))];
    expect(ids.length).toBeGreaterThanOrEqual(25);
    const all = titles();
    const missing = ids.filter((id) => !all.some((title) => new RegExp(`\\b${id.replace('.', '\\.')}\\b`).test(title)));
    expect(missing).toEqual([]);
  });
});
