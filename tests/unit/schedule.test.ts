import { describe, expect, it } from 'vitest';
import {
  addDays,
  civilFromDays,
  daysBetween,
  daysFromCivil,
  dueDate,
  fromDays,
  isISODate,
  isoWeekday,
  roundsFor,
  toDays,
} from '../../shared/schedule.js';

describe('schedule calendar arithmetic', () => {
  it('round-trips every day from 1999 to 2101 against Date.UTC', () => {
    const start = daysFromCivil(1999, 1, 1);
    const end = daysFromCivil(2101, 12, 31);
    for (let d = start; d <= end; d += 1) {
      const iso = new Date(d * 86_400_000).toISOString().slice(0, 10);
      expect(fromDays(d)).toBe(iso);
      expect(toDays(iso)).toBe(d);
      const c = civilFromDays(d);
      expect(daysFromCivil(c.y, c.m, c.d)).toBe(d);
    }
  });

  it('validates ISO dates including leap days', () => {
    expect(isISODate('2028-02-29')).toBe(true);
    expect(isISODate('2026-02-29')).toBe(false);
    expect(isISODate('2100-02-29')).toBe(false);
    expect(isISODate('2000-02-29')).toBe(true);
    expect(isISODate('2026-04-31')).toBe(false);
    expect(isISODate('2026-13-01')).toBe(false);
    expect(isISODate('2026-1-01')).toBe(false);
    expect(isISODate('2026-01-01T00:00')).toBe(false);
  });

  it('computes ISO weekdays', () => {
    expect(isoWeekday('1970-01-01')).toBe(4);
    expect(isoWeekday('2026-10-17')).toBe(6); // a Saturday
    expect(isoWeekday('2026-10-19')).toBe(1);
    expect(isoWeekday('2026-10-18')).toBe(7);
    expect(addDays('2028-02-28', 1)).toBe('2028-02-29');
    expect(addDays('2027-02-28', 1)).toBe('2027-03-01');
    expect(daysBetween('2026-12-31', '2027-01-01')).toBe(1);
  });
});

describe('schedule.dueDate monthly', () => {
  it('uses the start month when the due day is not yet past', () => {
    expect(dueDate('2026-11-01', 'monthly', 5, 1)).toBe('2026-11-05');
    expect(dueDate('2026-11-05', 'monthly', 5, 1)).toBe('2026-11-05');
    expect(dueDate('2026-11-01', 'monthly', 5, 2)).toBe('2026-12-05');
    expect(dueDate('2026-11-01', 'monthly', 5, 3)).toBe('2027-01-05');
  });

  it('moves to the next month when the due day is past', () => {
    expect(dueDate('2026-11-06', 'monthly', 5, 1)).toBe('2026-12-05');
    expect(dueDate('2026-12-20', 'monthly', 1, 1)).toBe('2027-01-01');
  });

  it('handles month ends and leap years', () => {
    expect(dueDate('2026-01-31', 'monthly', 28, 1)).toBe('2026-02-28');
    expect(dueDate('2028-01-31', 'monthly', 28, 1)).toBe('2028-02-28');
    expect(dueDate('2028-02-29', 'monthly', 28, 1)).toBe('2028-03-28');
    expect(dueDate('2028-02-29', 'monthly', 1, 1)).toBe('2028-03-01');
    expect(dueDate('2027-12-31', 'monthly', 28, 2)).toBe('2028-02-28');
    const year = Array.from({ length: 12 }, (_, i) => dueDate('2028-01-01', 'monthly', 28, i + 1));
    expect(year).toEqual([
      '2028-01-28', '2028-02-28', '2028-03-28', '2028-04-28', '2028-05-28', '2028-06-28',
      '2028-07-28', '2028-08-28', '2028-09-28', '2028-10-28', '2028-11-28', '2028-12-28',
    ]);
  });

  it('refuses due days outside 1-28 and bad input', () => {
    expect(() => dueDate('2026-11-01', 'monthly', 29, 1)).toThrow(RangeError);
    expect(() => dueDate('2026-11-01', 'monthly', 0, 1)).toThrow(RangeError);
    expect(() => dueDate('2026-11-01', 'monthly', 5, 0)).toThrow(RangeError);
    expect(() => dueDate('2026-02-30', 'monthly', 5, 1)).toThrow(RangeError);
  });
});

describe('schedule.dueDate weekly and biweekly', () => {
  it('picks the first matching weekday on or after start', () => {
    // 2026-10-17 is a Saturday (6)
    expect(dueDate('2026-10-17', 'weekly', 6, 1)).toBe('2026-10-17');
    expect(dueDate('2026-10-17', 'weekly', 7, 1)).toBe('2026-10-18');
    expect(dueDate('2026-10-17', 'weekly', 1, 1)).toBe('2026-10-19');
    expect(dueDate('2026-10-17', 'weekly', 5, 1)).toBe('2026-10-23');
    expect(dueDate('2026-10-17', 'weekly', 5, 2)).toBe('2026-10-30');
    expect(dueDate('2026-10-17', 'biweekly', 5, 2)).toBe('2026-11-06');
  });

  it('crosses leap days and year ends', () => {
    expect(dueDate('2028-02-22', 'weekly', isoWeekday('2028-02-22'), 2)).toBe('2028-02-29');
    expect(dueDate('2028-02-15', 'biweekly', isoWeekday('2028-02-15'), 2)).toBe('2028-02-29');
    expect(dueDate('2026-12-25', 'weekly', isoWeekday('2026-12-25'), 2)).toBe('2027-01-01');
    for (let n = 1; n <= 60; n += 1) {
      const d = dueDate('2027-11-03', 'weekly', 3, n);
      expect(isoWeekday(d)).toBe(3);
      expect(daysBetween('2027-11-03', d)).toBe(7 * (n - 1));
    }
  });

  it('refuses weekday 0 and 8', () => {
    expect(() => dueDate('2026-10-17', 'weekly', 0, 1)).toThrow(RangeError);
    expect(() => dueDate('2026-10-17', 'biweekly', 8, 1)).toThrow(RangeError);
  });
});

describe('schedule.roundsFor', () => {
  it('lists one round per member with the recipient by position', () => {
    const rounds = roundsFor({
      startDate: '2026-11-01',
      period: 'monthly',
      dueDay: 5,
      memberCount: 3,
      contribution: 50000,
      recipientPays: true,
      order: ['c', 'a', 'b'],
    });
    expect(rounds.map((r) => [r.n, r.dueDate, r.recipient, r.pot])).toEqual([
      [1, '2026-11-05', 'c', 150000],
      [2, '2026-12-05', 'a', 150000],
      [3, '2027-01-05', 'b', 150000],
    ]);
  });

  it('excludes the recipient from the pot when recipient_pays is false', () => {
    const rounds = roundsFor({
      startDate: '2026-11-01',
      period: 'weekly',
      dueDay: 4,
      memberCount: 4,
      contribution: 1000,
      recipientPays: false,
      order: ['a', 'b', 'c', 'd'],
    });
    expect(rounds.every((r) => r.pot === 3000 && r.payers === 3)).toBe(true);
  });

  it('refuses an order that is not a full permutation', () => {
    const base = { startDate: '2026-11-01', period: 'monthly' as const, dueDay: 5, contribution: 1, recipientPays: true };
    expect(() => roundsFor({ ...base, memberCount: 3, order: ['a', 'b'] })).toThrow(RangeError);
    expect(() => roundsFor({ ...base, memberCount: 2, order: ['a', 'a'] })).toThrow(RangeError);
  });
});
