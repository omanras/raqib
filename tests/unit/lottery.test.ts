import { createHash, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { webSha256Hex } from '../../shared/hash.js';
import { commit, commitAsync, finalize, finalizeAsync, isSecret, verifyReveal } from '../../shared/lottery.js';

const sha = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex');

interface Case {
  name: string;
  circleId: string;
  members: string[];
  secrets: Record<string, string>;
  commitments: Record<string, string>;
  reveals: Record<string, string>;
  expected: { seed: string; order: string[]; revealed: string[]; silent: string[] };
}
const vectors = JSON.parse(readFileSync(new URL('./lottery.vectors.json', import.meta.url), 'utf8')) as { cases: Case[] };

describe('lottery vectors (tests/unit/lottery.vectors.json)', () => {
  for (const c of vectors.cases) {
    it(`${c.name}: commitments, seed and order match`, async () => {
      for (const m of c.members) {
        expect(commit(c.secrets[m] as string, m, sha)).toBe(c.commitments[m]);
        expect(await commitAsync(c.secrets[m] as string, m, webSha256Hex)).toBe(c.commitments[m]);
        expect(verifyReveal(c.commitments[m] as string, c.secrets[m] as string, m, sha)).toBe(true);
      }
      const r = finalize(c.circleId, c.members, c.reveals, sha);
      expect(r).toEqual(c.expected);
      expect(await finalizeAsync(c.circleId, c.members, c.reveals, webSha256Hex)).toEqual(c.expected);
      // Input order of members does not matter.
      expect(finalize(c.circleId, [...c.members].reverse(), new Map(Object.entries(c.reveals)), sha)).toEqual(c.expected);
    });
  }
});

describe('lottery rules', () => {
  const members = ['m3', 'm1', 'm4', 'm2', 'm5'];
  const secrets = Object.fromEntries(members.map((m) => [m, randomBytes(32).toString('hex')]));

  it('places members who never revealed last, in member-id order (silent-member rule)', () => {
    const reveals = { m3: secrets.m3 as string, m1: secrets.m1 as string, m5: secrets.m5 as string };
    const r = finalize('circle-x', members, reveals, sha);
    expect(r.silent).toEqual(['m2', 'm4']);
    expect(r.order.slice(-2)).toEqual(['m2', 'm4']);
    expect(new Set(r.order.slice(0, 3))).toEqual(new Set(['m1', 'm3', 'm5']));
    expect(r.order).toHaveLength(5);
  });

  it('with no reveals at all the order is member-id order and the seed depends on the circle only', () => {
    const r = finalize('circle-y', members, {}, sha);
    expect(r.order).toEqual(['m1', 'm2', 'm3', 'm4', 'm5']);
    expect(r.seed).toBe(sha('circle-y'));
  });

  it('is deterministic, and any single changed secret changes the seed', () => {
    const a = finalize('c', members, secrets, sha);
    const b = finalize('c', members, { ...secrets }, sha);
    expect(a).toEqual(b);
    const changed = finalize('c', members, { ...secrets, m2: randomBytes(32).toString('hex') }, sha);
    expect(changed.seed).not.toBe(a.seed);
    expect(finalize('other-circle', members, secrets, sha).seed).not.toBe(a.seed);
  });

  it('refuses a wrong secret, a wrong member and malformed input', () => {
    const c = commit(secrets.m1 as string, 'm1', sha);
    expect(verifyReveal(c, secrets.m2 as string, 'm1', sha)).toBe(false);
    expect(verifyReveal(c, secrets.m1 as string, 'm2', sha)).toBe(false);
    expect(verifyReveal(c, 'not-hex', 'm1', sha)).toBe(false);
    expect(verifyReveal('short', secrets.m1 as string, 'm1', sha)).toBe(false);
    expect(isSecret('A'.repeat(64))).toBe(false);
    expect(() => commit('xyz', 'm1', sha)).toThrow(TypeError);
    expect(() => finalize('c', members, { stranger: secrets.m1 as string }, sha)).toThrow(RangeError);
    expect(() => finalize('c', ['a', 'a'], {}, sha)).toThrow(RangeError);
    expect(() => finalize('c', members, { m1: 'bad' }, sha)).toThrow(TypeError);
  });

  it('spreads first positions over many draws (no member is favoured by id)', () => {
    const counts = new Map<string, number>();
    for (let i = 0; i < 2000; i += 1) {
      const s = Object.fromEntries(members.map((m) => [m, sha(`draw${i}:${m}`)]));
      const first = finalize(`circle${i}`, members, s, sha).order[0] as string;
      counts.set(first, (counts.get(first) ?? 0) + 1);
    }
    for (const m of members) {
      const n = counts.get(m) ?? 0;
      expect(n).toBeGreaterThan(300);
      expect(n).toBeLessThan(500);
    }
  });
});
