import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { webSha256Hex } from '../../shared/hash.js';
import {
  GENESIS_HASH,
  canonical,
  hashEntry,
  inspect,
  nextEntry,
  preimage,
  verify,
  verifyAsync,
  type JsonObject,
  type LedgerEntry,
} from '../../shared/ledger.js';

const sha = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex');

interface VectorEntry extends LedgerEntry {
  canonical: string;
  preimage: string;
}
const vectors = JSON.parse(readFileSync(new URL('./ledger.vectors.json', import.meta.url), 'utf8')) as {
  entries: VectorEntry[];
};
const strip = (e: VectorEntry): LedgerEntry => ({
  seq: e.seq,
  ts: e.ts,
  actor: e.actor,
  type: e.type,
  payload: e.payload,
  prevHash: e.prevHash,
  hash: e.hash,
});

function chain(n: number): LedgerEntry[] {
  const out: LedgerEntry[] = [];
  for (let i = 0; i < n; i += 1) {
    out.push(
      nextEntry(
        out[i - 1] ?? null,
        {
          ts: new Date(Date.UTC(2026, 9, 17, 12, 0, 0, i)).toISOString(),
          actor: `user${i % 3}`,
          type: 'contribution.reported',
          payload: { round: 1, amount: 1000 + i, note: `entry ${i}` },
        },
        sha,
      ),
    );
  }
  return out;
}

describe('ledger.canonical', () => {
  it('sorts keys, drops whitespace, keeps strings as JSON writes them', () => {
    expect(canonical({ b: 1, a: [true, null, 'x'], c: { z: 'ع', y: 2 } })).toBe('{"a":[true,null,"x"],"b":1,"c":{"y":2,"z":"ع"}}');
    expect(canonical({})).toBe('{}');
    expect(canonical('a"b\n')).toBe('"a\\"b\\n"');
  });

  it('refuses floats, non-finite numbers, undefined and non-plain objects', () => {
    expect(() => canonical({ a: 1.5 })).toThrow(TypeError);
    expect(() => canonical({ a: Number.NaN })).toThrow(TypeError);
    expect(() => canonical({ a: Number.POSITIVE_INFINITY })).toThrow(TypeError);
    expect(() => canonical({ a: 2 ** 60 })).toThrow(TypeError);
    expect(() => canonical({ a: undefined })).toThrow(TypeError);
    expect(() => canonical({ a: new Date(0) })).toThrow(TypeError);
    expect(() => canonical({ a: 1n })).toThrow(TypeError);
  });

  it('matches the committed vectors exactly', () => {
    for (const e of vectors.entries) {
      expect(canonical(e.payload)).toBe(e.canonical);
      expect(preimage(e)).toBe(e.preimage);
      expect(hashEntry(e, sha)).toBe(e.hash);
    }
  });
});

describe('ledger.verify', () => {
  it('accepts the vector chain and a generated chain', () => {
    const v = verify(vectors.entries.map(strip), sha);
    expect(v).toEqual({ ok: true, count: 6, lastSeq: 6, lastHash: vectors.entries[5]?.hash });
    const c = chain(25);
    expect(c[0]?.prevHash).toBe(GENESIS_HASH);
    expect(verify(c, sha).ok).toBe(true);
    expect(verify([], sha)).toEqual({ ok: true, count: 0, lastSeq: 0, lastHash: GENESIS_HASH });
  });

  it('ledger.tamper: one flipped byte breaks that seq and the chain after it still links to it', () => {
    const c = chain(10);
    const k = 6;
    const tampered = c.map((e) => ({ ...e, payload: { ...e.payload } }));
    const target = tampered[k - 1] as LedgerEntry;
    target.payload = { ...target.payload, note: 'entry 4' }; // was "entry 5": one byte
    const r = verify(tampered, sha);
    expect(r).toMatchObject({ ok: false, brokenSeq: k, reason: 'hash' });
    const checks = inspect(tampered, sha);
    expect(checks.filter((x) => !x.ok).map((x) => x.seq)).toEqual([k]);
    for (const x of checks.slice(k)) expect(x.ok).toBe(true);
    // The suffix after the break verifies on its own, chained to the stored hash.
    expect(verify(tampered.slice(k), sha, { prevHash: target.hash, startSeq: k + 1 }).ok).toBe(true);
  });

  it('detects an edited hash, a removed entry, a reordered pair and a bad genesis', () => {
    const c = chain(8);
    const editedHash = c.map((e, i) => (i === 2 ? { ...e, hash: sha('x') } : e));
    expect(verify(editedHash, sha)).toMatchObject({ ok: false, brokenSeq: 3, reason: 'hash' });
    const removed = [...c.slice(0, 3), ...c.slice(4)];
    expect(verify(removed, sha)).toMatchObject({ ok: false, brokenSeq: 5, reason: 'seq' });
    const swapped = [c[0], c[2], c[1], ...c.slice(3)] as LedgerEntry[];
    expect(verify(swapped, sha)).toMatchObject({ ok: false, brokenSeq: 3, reason: 'seq' });
    const rehashed = { ...(c[0] as LedgerEntry), prevHash: sha('other') };
    expect(verify([rehashed, ...c.slice(1)], sha)).toMatchObject({ ok: false, brokenSeq: 1, reason: 'link' });
  });

  it('a re-hashed forgery still breaks the link to the next entry', () => {
    const c = chain(5);
    const forged = { ...(c[1] as LedgerEntry), payload: { round: 1, amount: 999999, note: 'forged' } as JsonObject };
    forged.hash = hashEntry(forged, sha);
    const r = verify([c[0] as LedgerEntry, forged, ...c.slice(2)], sha);
    expect(r).toMatchObject({ ok: false, brokenSeq: 3, reason: 'link' });
  });

  it('flags malformed fields as format breaks', () => {
    const c = chain(3);
    const bad = [
      { ...(c[0] as LedgerEntry), ts: '2026-10-17 12:00:00' },
      { ...(c[0] as LedgerEntry), actor: 'has space' },
      { ...(c[0] as LedgerEntry), type: 'NotAType' },
      { ...(c[0] as LedgerEntry), payload: { amount: 1.5 } as unknown as JsonObject },
      { ...(c[0] as LedgerEntry), prevHash: 'zz' },
    ];
    for (const b of bad) expect(verify([b, ...c.slice(1)], sha)).toMatchObject({ ok: false, brokenSeq: 1, reason: 'format' });
  });

  it('Web Crypto and node:crypto agree on the vectors and on random chains', async () => {
    const entries = vectors.entries.map(strip);
    expect(await verifyAsync(entries, webSha256Hex)).toEqual(verify(entries, sha));
    for (const e of vectors.entries) expect(await webSha256Hex(e.preimage)).toBe(e.hash);
    const c = chain(30);
    expect(await verifyAsync(c, webSha256Hex)).toEqual(verify(c, sha));
    const t = c.map((e, i) => (i === 11 ? { ...e, payload: { ...e.payload, amount: 1 } } : e));
    expect(await verifyAsync(t, webSha256Hex)).toEqual(verify(t, sha));
  });
});
