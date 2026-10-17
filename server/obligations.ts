import { foldBooks, obligationKey, viewObligation, type Books, type ObligationView } from '../shared/books.js';
import { addAmounts } from '../shared/money.js';
import { isoDateOf } from '../shared/schedule.js';
import { stmt, type DB } from './db/db.js';
import { listLedger } from './db/ledger.js';

export interface ObligationStatus extends ObligationView {
  /** The contributions row id: the `:cid` of the confirm and waive routes. */
  contributionId: string;
  dueDate: string;
  roundStatus: 'upcoming' | 'open' | 'closed';
}

/** The books of a circle recomputed from its ledger. */
export function booksOf(db: DB, circleId: string): Books {
  return foldBooks(listLedger(db, circleId));
}

export function contributionIds(db: DB, circleId: string): Map<string, string> {
  const rows = stmt(db, 'SELECT id, round_n, member_id FROM contributions WHERE circle_id = ?').all(circleId) as {
    id: string;
    round_n: number;
    member_id: string;
  }[];
  return new Map(rows.map((r) => [obligationKey(r.round_n, r.member_id), r.id]));
}

/**
 * Every (round, member) obligation of a circle with its state derived from
 * the ledger (ADR §2). Only open and closed rounds are due.
 */
export function obligationStatuses(db: DB, circleId: string, now: Date, books: Books = booksOf(db, circleId)): ObligationStatus[] {
  const ids = contributionIds(db, circleId);
  const today = isoDateOf(now);
  const out: ObligationStatus[] = [];
  for (const round of books.rounds) {
    for (const o of books.obligations.values()) {
      if (o.roundN !== round.n) continue;
      out.push({
        ...viewObligation(o, round, today),
        contributionId: ids.get(obligationKey(o.roundN, o.memberId)) ?? '',
        dueDate: round.dueDate,
        roundStatus: round.status,
      });
    }
  }
  return out;
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
