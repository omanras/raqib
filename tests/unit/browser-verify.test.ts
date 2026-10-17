import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { csvCell, csvDocument } from '../../shared/csv.js';
import { verify, type LedgerEntry } from '../../shared/ledger.js';
import { ledgerCsv, newSecret, recomputeDraw, verifyLedger } from '../../client/trust.js';

/**
 * The browser path (client/trust.ts: Web Crypto SHA-256 through
 * shared/ledger.verifyAsync and shared/lottery.finalizeAsync) against the
 * committed vectors and against node:crypto.
 */
const sha = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex');
const ledger = JSON.parse(readFileSync(new URL('./ledger.vectors.json', import.meta.url), 'utf8')) as { entries: (LedgerEntry & Record<string, unknown>)[] };
const lottery = JSON.parse(readFileSync(new URL('./lottery.vectors.json', import.meta.url), 'utf8')) as {
  cases: {
    circleId: string;
    members: string[];
    reveals: Record<string, string>;
    commitments: Record<string, string>;
    expected: { seed: string; order: string[] };
  }[];
};
const entries: LedgerEntry[] = ledger.entries.map((e) => ({
  seq: e.seq,
  ts: e.ts,
  actor: e.actor,
  type: e.type,
  payload: e.payload,
  prevHash: e.prevHash,
  hash: e.hash,
}));

describe('browser verification agrees with the server (M2.3 E1)', () => {
  it('Web Crypto verifies the ledger vectors exactly as node:crypto does', async () => {
    const browser = await verifyLedger(entries);
    expect(browser).toEqual(verify(entries, sha));
    expect(browser).toMatchObject({ ok: true, count: entries.length, lastHash: entries.at(-1)?.hash });
  });

  it('and finds a tampered entry at the same seq', async () => {
    const tampered = entries.map((e) => (e.seq === 3 ? { ...e, payload: { ...e.payload, method: 'manual!' } } : e));
    const browser = await verifyLedger(tampered);
    expect(browser).toEqual(verify(tampered, sha));
    expect(browser).toMatchObject({ ok: false, brokenSeq: 3, reason: 'hash' });
  });

  it('recomputes every lottery vector and rejects a doctored order or reveal', async () => {
    for (const c of lottery.cases) {
      const record = {
        seed: c.expected.seed,
        order: c.expected.order,
        members: c.members,
        reveals: Object.entries(c.reveals).map(([memberId, secret], i) => ({ memberId, secret, seq: i + 1 })),
        commitments: Object.entries(c.commitments).map(([memberId, commitment], i) => ({ memberId, commitment, seq: i + 1 })),
      };
      expect((await recomputeDraw(c.circleId, record)).ok, c.circleId).toBe(true);
      if (c.expected.order.length > 1) {
        const swapped = [...c.expected.order].reverse();
        expect((await recomputeDraw(c.circleId, { ...record, order: swapped })).ok).toBe(false);
      }
      if (record.reveals.length > 0) {
        const bad = { ...record, reveals: record.reveals.map((r, i) => (i === 0 ? { ...r, secret: 'f'.repeat(64) } : r)) };
        const out = await recomputeDraw(c.circleId, bad);
        expect(out.ok).toBe(false);
        expect(out.badReveals).toEqual([record.reveals[0]?.memberId]);
      }
    }
  });

  it('makes 64-hex secrets from the platform random source', () => {
    const a = newSecret();
    expect(a).toMatch(/^[0-9a-f]{64}$/);
    expect(newSecret()).not.toBe(a);
  });

  it('S4.4 the browser CSV export escapes formula-leading cells too', () => {
    expect(csvCell('=SUM(A1)')).toBe("'=SUM(A1)");
    expect(csvCell('+1')).toBe("'+1");
    expect(csvCell('-2')).toBe("'-2");
    expect(csvCell('@x')).toBe("'@x");
    expect(csvCell('a,b')).toBe('"a,b"');
    expect(csvCell('say "hi"')).toBe('"say ""hi"""');
    expect(csvDocument(['h'], [['=1']])).toBe("﻿h\r\n'=1\r\n");
    const csv = ledgerCsv(entries);
    expect(csv.split('\r\n')[0]).toBe('﻿seq,ts,actor,type,payload,prev_hash,hash');
    expect(csv.split('\r\n')).toHaveLength(entries.length + 2);
  });
});
