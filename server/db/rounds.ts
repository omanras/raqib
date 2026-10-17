import { newId } from '../crypto.js';
import { stmt, type DB } from './db.js';

export interface ContributionRow {
  id: string;
  circle_id: string;
  round_n: number;
  member_id: string;
  expected: number;
  waived_at: string | null;
  waived_by: string | null;
  waive_reason: string | null;
  created_at: string;
}

export interface PayoutRow {
  id: string;
  circle_id: string;
  round_n: number;
  amount: number;
  paid_on: string;
  method: string;
  reference: string;
  recorded_by: string;
  recorded_at: string;
  acknowledged_at: string | null;
  acknowledged_by: string | null;
  created_at: string;
}

export function setRoundOpen(db: DB, circleId: string, n: number, now: Date): void {
  stmt(db, "UPDATE rounds SET status = 'open', opened_at = ? WHERE circle_id = ? AND n = ?").run(now.toISOString(), circleId, n);
}

export function setRoundClosed(db: DB, circleId: string, n: number, now: Date): void {
  stmt(db, "UPDATE rounds SET status = 'closed', closed_at = ? WHERE circle_id = ? AND n = ?").run(now.toISOString(), circleId, n);
}

export function getContribution(db: DB, id: string): ContributionRow | undefined {
  return stmt(db, 'SELECT * FROM contributions WHERE id = ?').get(id) as ContributionRow | undefined;
}

export function findContribution(db: DB, circleId: string, roundN: number, memberId: string): ContributionRow | undefined {
  return stmt(db, 'SELECT * FROM contributions WHERE circle_id = ? AND round_n = ? AND member_id = ?').get(circleId, roundN, memberId) as
    | ContributionRow
    | undefined;
}

export function markWaived(db: DB, id: string, userId: string, reason: string, now: Date): void {
  stmt(db, 'UPDATE contributions SET waived_at = ?, waived_by = ?, waive_reason = ? WHERE id = ?').run(now.toISOString(), userId, reason, id);
}

export function insertPayout(
  db: DB,
  p: { circleId: string; roundN: number; amount: number; paidOn: string; method: string; reference: string; recordedBy: string; now: Date },
): PayoutRow {
  const id = newId();
  const ts = p.now.toISOString();
  stmt(
    db,
    `INSERT INTO payouts (id, circle_id, round_n, amount, paid_on, method, reference, recorded_by, recorded_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(id, p.circleId, p.roundN, p.amount, p.paidOn, p.method, p.reference, p.recordedBy, ts, ts);
  return stmt(db, 'SELECT * FROM payouts WHERE id = ?').get(id) as PayoutRow;
}

export function findPayout(db: DB, circleId: string, roundN: number): PayoutRow | undefined {
  return stmt(db, 'SELECT * FROM payouts WHERE circle_id = ? AND round_n = ?').get(circleId, roundN) as PayoutRow | undefined;
}

export function markPayoutAcknowledged(db: DB, id: string, userId: string, now: Date): void {
  stmt(db, 'UPDATE payouts SET acknowledged_at = ?, acknowledged_by = ? WHERE id = ?').run(now.toISOString(), userId, id);
}
