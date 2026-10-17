import { addAmounts } from '../shared/money.js';
import { contributionStatus, type ContributionState } from '../shared/state.js';
import { stmt, type DB } from './db/db.js';

export interface ObligationStatus {
  contributionId: string;
  roundN: number;
  memberId: string;
  dueDate: string;
  roundStatus: 'upcoming' | 'open' | 'closed';
  state: ContributionState;
  expected: number;
  reported: number;
  confirmed: number;
  outstanding: number;
  waived: boolean;
}

interface Row {
  id: string;
  round_n: number;
  member_id: string;
  expected: number;
  waived_at: string | null;
  due_date: string;
  round_status: 'upcoming' | 'open' | 'closed';
}

/**
 * Every (round, member) obligation of a circle with its derived state (ADR
 * §2). Only rounds that are open or closed are due; an upcoming round's
 * obligations are listed but owe nothing yet.
 */
export function obligationStatuses(db: DB, circleId: string, _now: Date): ObligationStatus[] {
  const rows = stmt(
    db,
    `SELECT c.id, c.round_n, c.member_id, c.expected, c.waived_at, r.due_date, r.status AS round_status
     FROM contributions c JOIN rounds r ON r.circle_id = c.circle_id AND r.n = c.round_n
     WHERE c.circle_id = ? ORDER BY c.round_n, c.member_id`,
  ).all(circleId) as Row[];
  return rows.map((r) => {
    const s = contributionStatus(r.expected, [], r.waived_at !== null);
    return {
      contributionId: r.id,
      roundN: r.round_n,
      memberId: r.member_id,
      dueDate: r.due_date,
      roundStatus: r.round_status,
      state: s.state,
      expected: s.expected,
      reported: s.reported,
      confirmed: s.confirmed,
      outstanding: s.outstanding,
      waived: r.waived_at !== null,
    };
  });
}

export function summarize(statuses: readonly ObligationStatus[]): { outstandingCount: number; outstandingAmount: number } {
  let outstandingCount = 0;
  let outstandingAmount = 0;
  for (const s of statuses) {
    if (s.roundStatus === 'upcoming') continue;
    if (s.outstanding > 0) {
      outstandingCount += 1;
      outstandingAmount = addAmounts(outstandingAmount, s.outstanding);
    }
  }
  return { outstandingCount, outstandingAmount };
}
