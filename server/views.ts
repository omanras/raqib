import { mulAmount } from '../shared/money.js';
import { payersPerRound } from '../shared/schedule.js';
import { checkStart, type Check } from '../shared/state.js';
import type { CircleAccess } from './circle-access.js';
import { activeMembers, listRounds, type CircleRow, type MemberRow, type RoundRow } from './db/circles.js';
import type { DB } from './db/db.js';
import { ledgerHead } from './db/ledger.js';
import { obligationStatuses, summarize } from './obligations.js';

export function memberCountOf(db: DB, circle: CircleRow, members?: MemberRow[]): number {
  return circle.member_count ?? (members ?? activeMembers(db, circle.id)).length;
}

export function circleJson(circle: CircleRow, memberCount: number) {
  const payers = Math.max(0, payersPerRound(memberCount, circle.recipient_pays === 1));
  return {
    id: circle.id,
    name: circle.name,
    currency: circle.currency,
    minorUnit: circle.minor_unit,
    contribution: circle.contribution,
    period: circle.period,
    dueDay: circle.due_day,
    startDate: circle.start_date,
    recipientPays: circle.recipient_pays === 1,
    status: circle.status,
    rulesText: circle.rules_text,
    memberCount,
    pot: mulAmount(circle.contribution, payers),
    createdAt: circle.created_at,
    startedAt: circle.started_at,
    completedAt: circle.completed_at,
    cancelledAt: circle.cancelled_at,
  };
}

export function memberJson(m: MemberRow) {
  return {
    id: m.id,
    userId: m.user_id,
    displayName: m.display_name,
    role: m.role,
    position: m.position,
    joinedAt: m.joined_at,
  };
}

export function roundJson(r: RoundRow) {
  return {
    n: r.n,
    dueDate: r.due_date,
    recipientMemberId: r.recipient_member_id,
    status: r.status,
    openedAt: r.opened_at,
    closedAt: r.closed_at,
  };
}

export function startCheckOf(db: DB, circle: CircleRow, members: MemberRow[], drawFinalized: boolean): Check {
  const ordered = members.every((m) => m.position !== null)
    ? [...members].sort((a, b) => (a.position as number) - (b.position as number)).map((m) => m.id)
    : null;
  return checkStart({
    status: circle.status,
    memberCount: members.length,
    memberIds: members.map((m) => m.id),
    order: ordered,
    startDate: circle.start_date,
    drawFinalized,
  });
}

/** GET /api/circles/:id for a member: the same view for every member (A1). */
export function circleView(db: DB, access: CircleAccess, now: Date, drawFinalized: boolean) {
  const { circle, me } = access;
  const members = activeMembers(db, circle.id);
  const memberCount = memberCountOf(db, circle, members);
  const statuses = obligationStatuses(db, circle.id, now);
  const all = summarize(statuses);
  const mine = summarize(statuses.filter((s) => s.memberId === me.id));
  return {
    circle: circleJson(circle, memberCount),
    me: { memberId: me.id, userId: me.user_id, role: me.role, displayName: me.display_name, position: me.position },
    members: members.map(memberJson),
    rounds: listRounds(db, circle.id).map(roundJson),
    summary: {
      outstandingCount: all.outstandingCount,
      outstandingAmount: all.outstandingAmount,
      myOutstandingCount: mine.outstandingCount,
      myOutstandingAmount: mine.outstandingAmount,
    },
    startCheck: startCheckOf(db, circle, members, drawFinalized),
    ledgerHead: ledgerHead(db, circle.id),
  };
}
