import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { foldBooks, statementOf } from '../../shared/books.js';
import { nextEntry, type JsonObject, type LedgerEntry } from '../../shared/ledger.js';

const sha = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex');

function chain(items: [string, JsonObject][]): LedgerEntry[] {
  const out: LedgerEntry[] = [];
  items.forEach(([type, payload], i) => {
    out.push(nextEntry(out[i - 1] ?? null, { ts: new Date(Date.UTC(2026, 9, 17, 10, i)).toISOString(), actor: 'org', type, payload }, sha));
  });
  return out;
}

const started = (recipientPays: boolean): [string, JsonObject] => [
  'circle.started',
  {
    memberCount: 3,
    startDate: '2026-11-01',
    contribution: 1000,
    currency: 'USD',
    recipientPays,
    pot: recipientPays ? 3000 : 2000,
    rounds: [
      { n: 1, dueDate: '2026-11-05', recipientMemberId: 'a' },
      { n: 2, dueDate: '2026-12-05', recipientMemberId: 'b' },
      { n: 3, dueDate: '2027-01-05', recipientMemberId: 'c' },
    ],
  },
];

const base: [string, JsonObject][] = [
  ['circle.created', { circleId: 'c1', name: 'Books', currency: 'USD', minorUnit: 2, contribution: 1000, period: 'monthly', dueDay: 5, startDate: null, recipientPays: true, rulesText: '' }],
  ['member.joined', { memberId: 'a', userId: 'ua', displayName: 'A', role: 'organizer' }],
  ['member.joined', { memberId: 'b', userId: 'ub', displayName: 'B', role: 'member' }],
  ['member.joined', { memberId: 'c', userId: 'uc', displayName: 'C', role: 'member' }],
];

describe('books: recomputed from the ledger', () => {
  it('derives obligations, reports, confirmations, waivers and payouts with their seqs', () => {
    const entries = chain([
      ...base,
      started(true),
      ['round.opened', { n: 1 }],
      ['contribution.reported', { reportId: 'r1', roundN: 1, memberId: 'b', amount: 400 }],
      ['contribution.reported', { reportId: 'r2', roundN: 1, memberId: 'b', amount: 600 }],
      ['contribution.confirmed', { reportIds: ['r1', 'r2'] }],
      ['contribution.reported', { reportId: 'r3', roundN: 1, memberId: 'c', amount: 1000 }],
      ['contribution.waived', { roundN: 1, memberId: 'a', reason: 'organizer fee' }],
      ['payout.recorded', { roundN: 1, amount: 2000, paidOn: '2026-11-06' }],
      ['payout.acknowledged', { roundN: 1 }],
      ['round.closed', { n: 1 }],
    ]);
    const books = foldBooks(entries);
    expect(books.obligations.size).toBe(9);
    const s = statementOf(books, '2026-11-20');
    const r1 = s.rounds[0];
    expect(r1?.status).toBe('closed');
    const line = (m: string) => r1?.lines.find((l) => l.memberId === m);
    expect(line('a')).toMatchObject({ state: 'waived', outstanding: 0, seqs: [11], waiveReason: 'organizer fee' });
    expect(line('b')).toMatchObject({ state: 'confirmed', confirmed: 1000, outstanding: 0, seqs: [7, 8, 9] });
    expect(line('c')).toMatchObject({ state: 'reported', reported: 1000, confirmed: 0, outstanding: 1000, ageDays: 15, seqs: [10] });
    expect(r1?.payout).toMatchObject({ amount: 2000, seq: 12, acknowledgedSeq: 13 });
    expect(r1?.seqs).toEqual([6, 14, 12, 13]);
    expect(s.rounds[1]?.lines.every((l) => l.state === 'not_due' && l.outstanding === 0)).toBe(true);
    expect(s.totals).toEqual({ expected: 9000, expectedDue: 3000, reported: 2000, confirmed: 1000, outstanding: 1000, paidOut: 2000 });
    const mine = statementOf(books, '2026-11-20', 'c');
    expect(mine.rounds.every((r) => r.lines.every((l) => l.memberId === 'c'))).toBe(true);
    expect(mine.rounds[0]?.payout).toBeNull();
    expect(statementOf(books, '2026-11-20', 'a').rounds[0]?.payout?.amount).toBe(2000);
  });

  it('without recipient_pays the recipient owes nothing in their own round', () => {
    const books = foldBooks(chain([...base, started(false)]));
    expect(books.obligations.size).toBe(6);
    expect(books.obligations.has('1:a')).toBe(false);
    expect(books.obligations.has('2:a')).toBe(true);
  });

  it('a confirmation of an unknown report changes nothing', () => {
    const books = foldBooks(
      chain([...base, started(true), ['round.opened', { n: 1 }], ['contribution.confirmed', { reportIds: ['nope'] }]]),
    );
    expect(statementOf(books, '2026-11-01').totals.confirmed).toBe(0);
  });
});
