import type { Period } from '../../shared/schedule.js';
import type { CircleStatus, RoundStatus } from '../../shared/state.js';
import { newId } from '../crypto.js';
import { stmt, type DB } from './db.js';

export interface CircleRow {
  id: string;
  name: string;
  currency: string;
  minor_unit: 2 | 3;
  contribution: number;
  period: Period;
  due_day: number;
  start_date: string | null;
  member_count: number | null;
  recipient_pays: 0 | 1;
  status: CircleStatus;
  rules_text: string;
  created_by: string;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  cancelled_at: string | null;
}

export interface MemberRow {
  id: string;
  circle_id: string;
  user_id: string;
  role: 'organizer' | 'member';
  display_name: string;
  position: number | null;
  joined_at: string;
  left_at: string | null;
  created_at: string;
}

export interface RoundRow {
  id: string;
  circle_id: string;
  n: number;
  due_date: string;
  recipient_member_id: string;
  status: RoundStatus;
  opened_at: string | null;
  closed_at: string | null;
  created_at: string;
}

export interface InviteRow {
  id: string;
  circle_id: string;
  token_hash: string;
  created_by: string;
  created_at: string;
  expires_at: string;
  accepted_at: string | null;
  accepted_by: string | null;
  revoked_at: string | null;
  revoked_by: string | null;
}

// ---------------------------------------------------------------- circles

export interface NewCircle {
  name: string;
  currency: string;
  minorUnit: 2 | 3;
  contribution: number;
  period: Period;
  dueDay: number;
  startDate: string | null;
  recipientPays: boolean;
  rulesText: string;
  createdBy: string;
  now: Date;
}

export function insertCircle(db: DB, c: NewCircle): CircleRow {
  const id = newId();
  stmt(
    db,
    `INSERT INTO circles (id, name, currency, minor_unit, contribution, period, due_day, start_date,
       recipient_pays, status, rules_text, created_by, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'draft', ?, ?, ?)`,
  ).run(
    id,
    c.name,
    c.currency,
    c.minorUnit,
    c.contribution,
    c.period,
    c.dueDay,
    c.startDate,
    c.recipientPays ? 1 : 0,
    c.rulesText,
    c.createdBy,
    c.now.toISOString(),
  );
  return getCircle(db, id) as CircleRow;
}

export function getCircle(db: DB, id: string): CircleRow | undefined {
  return stmt(db, 'SELECT * FROM circles WHERE id = ?').get(id) as CircleRow | undefined;
}

/** Columns PATCH may change, mapped from API field names. */
export const EDITABLE = {
  name: 'name',
  currency: 'currency',
  minorUnit: 'minor_unit',
  contribution: 'contribution',
  period: 'period',
  dueDay: 'due_day',
  startDate: 'start_date',
  recipientPays: 'recipient_pays',
  rulesText: 'rules_text',
} as const;
export type EditableField = keyof typeof EDITABLE;

export function updateCircleField(db: DB, id: string, field: EditableField, value: string | number | null): void {
  // The column name comes from the fixed EDITABLE map, never from input; the value is bound.
  stmt(db, `UPDATE circles SET ${EDITABLE[field]} = ? WHERE id = ?`).run(value, id);
}

export function setCircleStatus(db: DB, id: string, status: CircleStatus, now: Date): void {
  const ts = now.toISOString();
  const col = status === 'active' ? 'started_at' : status === 'completed' ? 'completed_at' : status === 'cancelled' ? 'cancelled_at' : null;
  if (col) stmt(db, `UPDATE circles SET status = ?, ${col} = ? WHERE id = ?`).run(status, ts, id);
  else stmt(db, 'UPDATE circles SET status = ? WHERE id = ?').run(status, id);
}

export function freezeMemberCount(db: DB, id: string, count: number): void {
  stmt(db, 'UPDATE circles SET member_count = ? WHERE id = ?').run(count, id);
}

export interface MyCircleRow extends CircleRow {
  my_role: 'organizer' | 'member';
  my_member_id: string;
  active_members: number;
}

export function listCirclesForUser(db: DB, userId: string): MyCircleRow[] {
  return stmt(
    db,
    `SELECT c.*, m.role AS my_role, m.id AS my_member_id,
       (SELECT COUNT(*) FROM members x WHERE x.circle_id = c.id AND x.left_at IS NULL) AS active_members
     FROM circles c JOIN members m ON m.circle_id = c.id
     WHERE m.user_id = ? AND m.left_at IS NULL
     ORDER BY c.created_at DESC`,
  ).all(userId) as MyCircleRow[];
}

// ---------------------------------------------------------------- members

export function insertMember(
  db: DB,
  m: { circleId: string; userId: string; role: 'organizer' | 'member'; displayName: string; now: Date },
): MemberRow {
  const id = newId();
  const ts = m.now.toISOString();
  stmt(
    db,
    `INSERT INTO members (id, circle_id, user_id, role, display_name, joined_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
  ).run(id, m.circleId, m.userId, m.role, m.displayName, ts, ts);
  return stmt(db, 'SELECT * FROM members WHERE id = ?').get(id) as MemberRow;
}

export function activeMembers(db: DB, circleId: string): MemberRow[] {
  return stmt(
    db,
    `SELECT * FROM members WHERE circle_id = ? AND left_at IS NULL
     ORDER BY CASE WHEN position IS NULL THEN 1 ELSE 0 END, position, joined_at, id`,
  ).all(circleId) as MemberRow[];
}

export function findActiveMember(db: DB, circleId: string, userId: string): MemberRow | undefined {
  return stmt(db, 'SELECT * FROM members WHERE circle_id = ? AND user_id = ? AND left_at IS NULL').get(circleId, userId) as
    | MemberRow
    | undefined;
}

export function getMember(db: DB, memberId: string): MemberRow | undefined {
  return stmt(db, 'SELECT * FROM members WHERE id = ?').get(memberId) as MemberRow | undefined;
}

export function countActiveMembers(db: DB, circleId: string): number {
  return (stmt(db, 'SELECT COUNT(*) AS n FROM members WHERE circle_id = ? AND left_at IS NULL').get(circleId) as { n: number }).n;
}

export function markMemberLeft(db: DB, memberId: string, now: Date): void {
  stmt(db, 'UPDATE members SET left_at = ?, position = NULL WHERE id = ?').run(now.toISOString(), memberId);
}

/** Sets positions 1..n in the given order (clearing first, so the unique index never trips mid-way). */
export function setPositions(db: DB, circleId: string, order: readonly string[]): void {
  stmt(db, 'UPDATE members SET position = NULL WHERE circle_id = ?').run(circleId);
  order.forEach((memberId, i) => {
    stmt(db, 'UPDATE members SET position = ? WHERE id = ? AND circle_id = ?').run(i + 1, memberId, circleId);
  });
}

export function clearPositions(db: DB, circleId: string): void {
  stmt(db, 'UPDATE members SET position = NULL WHERE circle_id = ?').run(circleId);
}

// ---------------------------------------------------------------- rounds and obligations

export function insertRound(
  db: DB,
  r: { circleId: string; n: number; dueDate: string; recipientMemberId: string; now: Date },
): void {
  stmt(
    db,
    `INSERT INTO rounds (id, circle_id, n, due_date, recipient_member_id, status, created_at)
     VALUES (?, ?, ?, ?, ?, 'upcoming', ?)`,
  ).run(newId(), r.circleId, r.n, r.dueDate, r.recipientMemberId, r.now.toISOString());
}

export function listRounds(db: DB, circleId: string): RoundRow[] {
  return stmt(db, 'SELECT * FROM rounds WHERE circle_id = ? ORDER BY n').all(circleId) as RoundRow[];
}

export function insertObligation(db: DB, o: { circleId: string; roundN: number; memberId: string; expected: number; now: Date }): void {
  stmt(
    db,
    `INSERT INTO contributions (id, circle_id, round_n, member_id, expected, created_at)
     VALUES (?, ?, ?, ?, ?, ?)`,
  ).run(newId(), o.circleId, o.roundN, o.memberId, o.expected, o.now.toISOString());
}

// ---------------------------------------------------------------- invites

export function insertInvite(db: DB, i: { circleId: string; tokenHash: string; createdBy: string; now: Date; ttlMs: number }): InviteRow {
  const id = newId();
  stmt(
    db,
    `INSERT INTO invites (id, circle_id, token_hash, created_by, created_at, expires_at)
     VALUES (?, ?, ?, ?, ?, ?)`,
  ).run(id, i.circleId, i.tokenHash, i.createdBy, i.now.toISOString(), new Date(i.now.getTime() + i.ttlMs).toISOString());
  return stmt(db, 'SELECT * FROM invites WHERE id = ?').get(id) as InviteRow;
}

export function findInviteByTokenHash(db: DB, tokenHash: string): InviteRow | undefined {
  return stmt(db, 'SELECT * FROM invites WHERE token_hash = ?').get(tokenHash) as InviteRow | undefined;
}

export function getInvite(db: DB, id: string): InviteRow | undefined {
  return stmt(db, 'SELECT * FROM invites WHERE id = ?').get(id) as InviteRow | undefined;
}

export function listInvites(db: DB, circleId: string): InviteRow[] {
  return stmt(db, 'SELECT * FROM invites WHERE circle_id = ? ORDER BY created_at DESC').all(circleId) as InviteRow[];
}

export function countActiveInvites(db: DB, circleId: string, now: Date): number {
  return (
    stmt(
      db,
      `SELECT COUNT(*) AS n FROM invites WHERE circle_id = ? AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > ?`,
    ).get(circleId, now.toISOString()) as { n: number }
  ).n;
}

export function markInviteAccepted(db: DB, id: string, userId: string, now: Date): boolean {
  return (
    stmt(db, 'UPDATE invites SET accepted_at = ?, accepted_by = ? WHERE id = ? AND accepted_at IS NULL AND revoked_at IS NULL').run(
      now.toISOString(),
      userId,
      id,
    ).changes === 1
  );
}

export function markInviteRevoked(db: DB, id: string, userId: string, now: Date): boolean {
  return (
    stmt(db, 'UPDATE invites SET revoked_at = ?, revoked_by = ? WHERE id = ? AND accepted_at IS NULL AND revoked_at IS NULL').run(
      now.toISOString(),
      userId,
      id,
    ).changes === 1
  );
}

export function inviteStatus(i: InviteRow, now: Date): 'active' | 'accepted' | 'revoked' | 'expired' {
  if (i.accepted_at) return 'accepted';
  if (i.revoked_at) return 'revoked';
  if (Date.parse(i.expires_at) <= now.getTime()) return 'expired';
  return 'active';
}
