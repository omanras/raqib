/**
 * The books of a circle, recomputed from its ledger (Constitution rule 4:
 * totals are recomputed from the ledger, never stored as the truth). A pure
 * fold over the entries: the server builds statements and the overview
 * from it, and a member's browser can run the same code on the exported
 * ledger and get the same numbers.
 */
import type { LedgerEntry } from './ledger.js';
import { addAmounts, sumAmounts } from './money.js';
import { daysBetween } from './schedule.js';
import { contributionStatus, type ContributionState, type RoundStatus } from './state.js';

export interface BookReport {
  reportId: string;
  amount: number;
  method: string;
  reference: string;
  recordedBy: string;
  ts: string;
  seq: number;
  confirmedSeq: number | null;
}

export interface BookObligation {
  roundN: number;
  memberId: string;
  expected: number;
  reports: BookReport[];
  waived: { seq: number; reason: string } | null;
}

export interface BookPayout {
  amount: number;
  paidOn: string;
  method: string;
  reference: string;
  seq: number;
  acknowledgedSeq: number | null;
}

export interface BookRound {
  n: number;
  dueDate: string;
  recipientMemberId: string;
  status: RoundStatus;
  openedSeq: number | null;
  closedSeq: number | null;
  payout: BookPayout | null;
}

export interface BookMember {
  memberId: string;
  userId: string;
  displayName: string;
  role: 'organizer' | 'member';
  joinedSeq: number;
  leftSeq: number | null;
}

export interface Books {
  name: string;
  currency: string;
  minorUnit: number;
  contribution: number;
  recipientPays: boolean;
  status: string;
  startedSeq: number | null;
  memberCount: number;
  members: Map<string, BookMember>;
  rounds: BookRound[];
  obligations: Map<string, BookObligation>;
  lastSeq: number;
}

export const obligationKey = (roundN: number, memberId: string): string => `${roundN}:${memberId}`;

type P = Record<string, unknown>;

export function foldBooks(entries: readonly LedgerEntry[]): Books {
  const b: Books = {
    name: '',
    currency: '',
    minorUnit: 2,
    contribution: 0,
    recipientPays: true,
    status: 'draft',
    startedSeq: null,
    memberCount: 0,
    members: new Map(),
    rounds: [],
    obligations: new Map(),
    lastSeq: 0,
  };
  const reportsById = new Map<string, BookReport>();
  for (const e of entries) {
    const p = e.payload as P;
    b.lastSeq = e.seq;
    switch (e.type) {
      case 'circle.created':
        b.name = p.name as string;
        b.currency = p.currency as string;
        b.minorUnit = p.minorUnit as number;
        b.contribution = p.contribution as number;
        b.recipientPays = p.recipientPays as boolean;
        break;
      case 'circle.rule_changed': {
        const to = p.to;
        if (p.field === 'name') b.name = to as string;
        if (p.field === 'currency') b.currency = to as string;
        if (p.field === 'minorUnit') b.minorUnit = to as number;
        if (p.field === 'contribution') b.contribution = to as number;
        if (p.field === 'recipientPays') b.recipientPays = to as boolean;
        break;
      }
      case 'member.joined':
        b.members.set(p.memberId as string, {
          memberId: p.memberId as string,
          userId: p.userId as string,
          displayName: p.displayName as string,
          role: p.role as 'organizer' | 'member',
          joinedSeq: e.seq,
          leftSeq: null,
        });
        break;
      case 'member.left': {
        const m = b.members.get(p.memberId as string);
        if (m) m.leftSeq = e.seq;
        break;
      }
      case 'circle.started': {
        b.status = 'active';
        b.startedSeq = e.seq;
        b.memberCount = p.memberCount as number;
        b.contribution = p.contribution as number;
        b.recipientPays = p.recipientPays as boolean;
        const rounds = p.rounds as { n: number; dueDate: string; recipientMemberId: string }[];
        const everyone = rounds.map((r) => r.recipientMemberId);
        b.rounds = rounds.map((r) => ({
          n: r.n,
          dueDate: r.dueDate,
          recipientMemberId: r.recipientMemberId,
          status: 'upcoming',
          openedSeq: null,
          closedSeq: null,
          payout: null,
        }));
        for (const r of rounds) {
          for (const memberId of everyone) {
            if (!b.recipientPays && memberId === r.recipientMemberId) continue;
            b.obligations.set(obligationKey(r.n, memberId), { roundN: r.n, memberId, expected: b.contribution, reports: [], waived: null });
          }
        }
        break;
      }
      case 'round.opened': {
        const r = b.rounds.find((x) => x.n === p.n);
        if (r) {
          r.status = 'open';
          r.openedSeq = e.seq;
        }
        break;
      }
      case 'round.closed': {
        const r = b.rounds.find((x) => x.n === p.n);
        if (r) {
          r.status = 'closed';
          r.closedSeq = e.seq;
        }
        break;
      }
      case 'contribution.reported': {
        const o = b.obligations.get(obligationKey(p.roundN as number, p.memberId as string));
        if (o) {
          const report: BookReport = {
            reportId: p.reportId as string,
            amount: p.amount as number,
            method: (p.method as string) ?? '',
            reference: (p.reference as string) ?? '',
            recordedBy: e.actor,
            ts: e.ts,
            seq: e.seq,
            confirmedSeq: null,
          };
          o.reports.push(report);
          reportsById.set(report.reportId, report);
        }
        break;
      }
      case 'contribution.confirmed':
        for (const id of p.reportIds as string[]) {
          const r = reportsById.get(id);
          if (r && r.confirmedSeq === null) r.confirmedSeq = e.seq;
        }
        break;
      case 'contribution.waived': {
        const o = b.obligations.get(obligationKey(p.roundN as number, p.memberId as string));
        if (o) o.waived = { seq: e.seq, reason: p.reason as string };
        break;
      }
      case 'payout.recorded': {
        const r = b.rounds.find((x) => x.n === p.roundN);
        if (r) {
          r.payout = {
            amount: p.amount as number,
            paidOn: p.paidOn as string,
            method: (p.method as string) ?? '',
            reference: (p.reference as string) ?? '',
            seq: e.seq,
            acknowledgedSeq: null,
          };
        }
        break;
      }
      case 'payout.acknowledged': {
        const r = b.rounds.find((x) => x.n === p.roundN);
        if (r?.payout) r.payout.acknowledgedSeq = e.seq;
        break;
      }
      case 'circle.completed':
        b.status = 'completed';
        break;
      case 'circle.cancelled':
        b.status = 'cancelled';
        break;
      default:
        break;
    }
  }
  return b;
}

export type LineState = ContributionState | 'not_due';

export interface ObligationView {
  roundN: number;
  memberId: string;
  state: LineState;
  expected: number;
  reported: number;
  confirmed: number;
  outstanding: number;
  /** Days past the due date while something is outstanding (A5); null otherwise. */
  ageDays: number | null;
  /** Every ledger entry this line rests on (reports, confirmations, waiver). */
  seqs: number[];
  reports: BookReport[];
  waiveReason: string | null;
}

export function viewObligation(o: BookObligation, round: BookRound, today: string): ObligationView {
  const s = contributionStatus(
    o.expected,
    o.reports.map((r) => ({ amount: r.amount, confirmed: r.confirmedSeq !== null })),
    o.waived !== null,
  );
  const due = round.status !== 'upcoming';
  const seqs = [...o.reports.flatMap((r) => (r.confirmedSeq === null ? [r.seq] : [r.seq, r.confirmedSeq])), ...(o.waived ? [o.waived.seq] : [])];
  const outstanding = due ? s.outstanding : 0;
  const late = daysBetween(round.dueDate, today);
  return {
    roundN: o.roundN,
    memberId: o.memberId,
    state: due ? s.state : 'not_due',
    expected: s.expected,
    reported: s.reported,
    confirmed: s.confirmed,
    outstanding,
    ageDays: outstanding > 0 && late > 0 ? late : null,
    seqs: [...new Set(seqs)].sort((a, b) => a - b),
    reports: o.reports,
    waiveReason: o.waived?.reason ?? null,
  };
}

export function obligationsOfRound(books: Books, n: number): BookObligation[] {
  return [...books.obligations.values()].filter((o) => o.roundN === n);
}

export interface StatementRound {
  n: number;
  dueDate: string;
  status: RoundStatus;
  recipientMemberId: string;
  expected: number;
  reported: number;
  confirmed: number;
  outstanding: number;
  payout: BookPayout | null;
  seqs: number[];
  lines: ObligationView[];
}

export interface Statement {
  currency: string;
  minorUnit: number;
  memberId: string | null;
  asOfSeq: number;
  today: string;
  rounds: StatementRound[];
  totals: { expected: number; expectedDue: number; reported: number; confirmed: number; outstanding: number; paidOut: number };
}

/** The statement of the whole circle, or of one member (A8: every line cites its ledger seqs). */
export function statementOf(books: Books, today: string, memberId: string | null = null): Statement {
  const rounds: StatementRound[] = books.rounds.map((round) => {
    const lines = obligationsOfRound(books, round.n)
      .filter((o) => memberId === null || o.memberId === memberId)
      .map((o) => viewObligation(o, round, today));
    const payout = memberId === null || memberId === round.recipientMemberId ? round.payout : null;
    const roundSeqs = [round.openedSeq, round.closedSeq, payout?.seq ?? null, payout?.acknowledgedSeq ?? null].filter(
      (s): s is number => s !== null,
    );
    return {
      n: round.n,
      dueDate: round.dueDate,
      status: round.status,
      recipientMemberId: round.recipientMemberId,
      expected: sumAmounts(lines.map((l) => l.expected)),
      reported: sumAmounts(lines.map((l) => l.reported)),
      confirmed: sumAmounts(lines.map((l) => l.confirmed)),
      outstanding: sumAmounts(lines.map((l) => l.outstanding)),
      payout,
      seqs: roundSeqs,
      lines,
    };
  });
  const due = rounds.filter((r) => r.status !== 'upcoming');
  return {
    currency: books.currency,
    minorUnit: books.minorUnit,
    memberId,
    asOfSeq: books.lastSeq,
    today,
    rounds,
    totals: {
      expected: sumAmounts(rounds.map((r) => r.expected)),
      expectedDue: sumAmounts(due.map((r) => r.expected)),
      reported: sumAmounts(rounds.map((r) => r.reported)),
      confirmed: sumAmounts(rounds.map((r) => r.confirmed)),
      outstanding: sumAmounts(rounds.map((r) => r.outstanding)),
      paidOut: rounds.reduce((acc, r) => (r.payout ? addAmounts(acc, r.payout.amount) : acc), 0),
    },
  };
}
