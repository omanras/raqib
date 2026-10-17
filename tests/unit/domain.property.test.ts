import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { verify, nextEntry, type LedgerEntry } from '../../shared/ledger.js';
import { finalize } from '../../shared/lottery.js';
import { MAX_AMOUNT, formatMinor, mulAmount, parseAmount, sumAmounts, type MinorUnit } from '../../shared/money.js';
import { daysBetween, isoWeekday, roundsFor, type Period } from '../../shared/schedule.js';
import { checkCloseRound, checkOpenRound, type RoundRef } from '../../shared/state.js';

const sha = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex');

/** mulberry32: a small seeded PRNG so failures reproduce. */
function prng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const int = (r: () => number, lo: number, hi: number) => lo + Math.floor(r() * (hi - lo + 1));

interface RandomCircle {
  id: string;
  startDate: string;
  period: Period;
  dueDay: number;
  memberCount: number;
  contribution: number;
  recipientPays: boolean;
  members: string[];
  minorUnit: MinorUnit;
}

function randomCircle(r: () => number, i: number): RandomCircle {
  const period = (['monthly', 'weekly', 'biweekly'] as const)[int(r, 0, 2)] as Period;
  const y = int(r, 2024, 2040);
  const m = int(r, 1, 12);
  const d = int(r, 1, 28);
  const memberCount = int(r, 2, 40);
  return {
    id: `circle${i}`,
    startDate: `${y}-${String(m).padStart(2, '0')}-${String(d).padStart(2, '0')}`,
    period,
    dueDay: period === 'monthly' ? int(r, 1, 28) : int(r, 1, 7),
    memberCount,
    contribution: int(r, 1, 10_000_000),
    recipientPays: r() < 0.7,
    members: Array.from({ length: memberCount }, (_, k) => sha(`c${i}m${k}`).slice(0, 22)),
    minorUnit: r() < 0.5 ? 2 : 3,
  };
}

describe('domain invariants over 100 random circles (seed 20261017)', () => {
  const r = prng(20261017);
  const circles = Array.from({ length: 100 }, (_, i) => randomCircle(r, i));

  it('pot = contribution x members; every member receives exactly once; due dates strictly increase', () => {
    for (const c of circles) {
      const reveals = Object.fromEntries(c.members.filter(() => r() < 0.8).map((m) => [m, sha(`${c.id}${m}secret`)]));
      const draw = finalize(c.id, c.members, reveals, sha);
      const rounds = roundsFor({ ...c, order: draw.order });

      expect(rounds).toHaveLength(c.memberCount);
      const payers = c.recipientPays ? c.memberCount : c.memberCount - 1;
      for (const round of rounds) {
        expect(round.pot).toBe(mulAmount(c.contribution, payers));
        if (c.recipientPays) expect(round.pot).toBe(c.contribution * c.memberCount);
      }
      const recipients = rounds.map((x) => x.recipient);
      expect(new Set(recipients).size).toBe(c.memberCount);
      expect([...recipients].sort()).toEqual([...c.members].sort());

      for (let k = 1; k < rounds.length; k += 1) {
        const gap = daysBetween((rounds[k - 1] as { dueDate: string }).dueDate, (rounds[k] as { dueDate: string }).dueDate);
        expect(gap).toBeGreaterThan(0);
        if (c.period === 'weekly') expect(gap).toBe(7);
        if (c.period === 'biweekly') expect(gap).toBe(14);
        if (c.period === 'monthly') expect(gap).toBeGreaterThanOrEqual(28);
      }
      const first = rounds[0] as { dueDate: string };
      expect(daysBetween(c.startDate, first.dueDate)).toBeGreaterThanOrEqual(0);
      if (c.period === 'monthly') {
        expect(rounds.every((x) => Number(x.dueDate.slice(8)) === c.dueDay)).toBe(true);
      } else {
        expect(rounds.every((x) => isoWeekday(x.dueDate) === c.dueDay)).toBe(true);
      }

      // The silent members are exactly the tail of the order.
      expect(draw.order.slice(draw.order.length - draw.silent.length)).toEqual(draw.silent);
    }
  });

  it('rounds can only be run open -> close in order, and totals stay exact', () => {
    for (const c of circles.slice(0, 30)) {
      const rounds: RoundRef[] = Array.from({ length: c.memberCount }, (_, k) => ({ n: k + 1, status: 'upcoming' }));
      for (let n = 1; n <= c.memberCount; n += 1) {
        const skip = int(r, 1, c.memberCount);
        if (skip !== n) expect(checkOpenRound(rounds, skip).ok).toBe(false);
        expect(checkOpenRound(rounds, n).ok).toBe(true);
        (rounds[n - 1] as RoundRef).status = 'open';
        expect(checkCloseRound(rounds, n).ok).toBe(true);
        (rounds[n - 1] as RoundRef).status = 'closed';
      }
      const payers = c.recipientPays ? c.memberCount : c.memberCount - 1;
      const total = sumAmounts(Array.from({ length: c.memberCount }, () => mulAmount(c.contribution, payers)));
      expect(total).toBe(c.contribution * payers * c.memberCount);
    }
  });

  it('money: random amounts survive format -> parse in both minor units', () => {
    for (const c of circles) {
      const x = int(r, 0, MAX_AMOUNT);
      const back = parseAmount(formatMinor(x, c.minorUnit), c.minorUnit);
      expect(back).toEqual({ ok: true, value: x });
    }
  });

  it('ledger: random chains verify, and a random single tamper is found at its seq', () => {
    for (const c of circles.slice(0, 40)) {
      const n = int(r, 1, 40);
      const entries: LedgerEntry[] = [];
      for (let k = 0; k < n; k += 1) {
        entries.push(
          nextEntry(
            entries[k - 1] ?? null,
            {
              ts: new Date(Date.UTC(2026, 0, 1, 0, 0, k)).toISOString(),
              actor: c.members[k % c.members.length] as string,
              type: 'contribution.reported',
              payload: { round: 1 + (k % c.memberCount), amount: c.contribution },
            },
            sha,
          ),
        );
      }
      expect(verify(entries, sha).ok).toBe(true);
      const at = int(r, 0, n - 1);
      const t = entries.map((e, k) => (k === at ? { ...e, payload: { ...e.payload, amount: c.contribution + 1 } } : e));
      expect(verify(t, sha)).toMatchObject({ ok: false, brokenSeq: at + 1 });
    }
  });
});
