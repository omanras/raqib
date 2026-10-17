/**
 * State machines (ADR-0001 §2, S3.3). The server enforces them; the client
 * shows the same refusal reasons. Every refusal has a stable code and a
 * sentence a member can read.
 */
import { addAmounts, sumAmounts } from './money.js';

export type Check = { ok: true } | { ok: false; code: string; reason: string };

const OK: Check = { ok: true };

function refuse(code: string, reason: string): Check {
  return { ok: false, code, reason };
}

// ---------------------------------------------------------------- circle

export type CircleStatus = 'draft' | 'drawing' | 'active' | 'completed' | 'cancelled';
export const CIRCLE_STATUSES: readonly CircleStatus[] = ['draft', 'drawing', 'active', 'completed', 'cancelled'];

export type CircleAction =
  | 'edit'
  | 'invite'
  | 'join'
  | 'leave'
  | 'set_order'
  | 'open_draw'
  | 'draw'
  | 'start'
  | 'cancel'
  | 'run_rounds'
  | 'complete';

interface Rule {
  from: readonly CircleStatus[];
  to?: CircleStatus;
  code: string;
  reason: string;
}

const CIRCLE_RULES: Record<CircleAction, Rule> = {
  edit: {
    from: ['draft'],
    code: 'circle_not_draft',
    reason: 'Rules, amount, period and dates can only change while the circle is a draft.',
  },
  invite: {
    from: ['draft'],
    code: 'circle_not_draft',
    reason: 'Invitations can only be created while the circle is a draft.',
  },
  join: {
    from: ['draft'],
    code: 'circle_closed_to_members',
    reason: 'This circle no longer accepts members: its draw has opened or it has started.',
  },
  leave: {
    from: ['draft'],
    code: 'circle_not_draft',
    reason: 'Members can only leave while the circle is a draft; after that the organizer records a substitute.',
  },
  set_order: {
    from: ['draft'],
    code: 'circle_not_draft',
    reason: 'A manual turn order can only be set while the circle is a draft.',
  },
  open_draw: {
    from: ['draft'],
    to: 'drawing',
    code: 'circle_not_draft',
    reason: 'A draw can only be opened while the circle is a draft.',
  },
  draw: {
    from: ['drawing'],
    code: 'circle_not_drawing',
    reason: 'There is no draw in progress for this circle.',
  },
  start: {
    from: ['draft', 'drawing'],
    to: 'active',
    code: 'circle_not_startable',
    reason: 'Only a draft or drawing circle can start.',
  },
  cancel: {
    from: ['draft', 'drawing'],
    to: 'cancelled',
    code: 'circle_not_cancellable',
    reason: 'A circle can only be cancelled before it starts.',
  },
  run_rounds: {
    from: ['active'],
    code: 'circle_not_active',
    reason: 'Rounds run only while the circle is active.',
  },
  complete: {
    from: ['active'],
    to: 'completed',
    code: 'circle_not_active',
    reason: 'Only an active circle can complete.',
  },
};

export function checkCircle(status: CircleStatus, action: CircleAction): Check {
  const rule = CIRCLE_RULES[action];
  return rule.from.includes(status) ? OK : refuse(rule.code, rule.reason);
}

/** The status after an allowed action; throws on a refused one. */
export function nextCircleStatus(status: CircleStatus, action: CircleAction): CircleStatus {
  const c = checkCircle(status, action);
  if (!c.ok) throw new RangeError(c.reason);
  return CIRCLE_RULES[action].to ?? status;
}

export const MIN_MEMBERS = 2;

export interface StartInput {
  status: CircleStatus;
  memberCount: number;
  memberIds: readonly string[];
  order: readonly (string | null)[] | null;
  startDate: string | null;
  drawFinalized: boolean;
}

/** All preconditions of starting a circle, first failure first. */
export function checkStart(input: StartInput): Check {
  const base = checkCircle(input.status, 'start');
  if (!base.ok) return base;
  if (input.memberCount < MIN_MEMBERS) {
    return refuse('too_few_members', `A circle needs at least ${MIN_MEMBERS} members to start.`);
  }
  if (input.status === 'drawing' && !input.drawFinalized) {
    return refuse('draw_not_finalized', 'The draw must be finalized before the circle starts.');
  }
  if (!input.order || !isPermutation(input.order, input.memberIds)) {
    return refuse('no_order', 'Every member needs a turn: set the order by hand or by a draw first.');
  }
  if (!input.startDate) return refuse('no_start_date', 'Set a start date before starting the circle.');
  return OK;
}

export function isPermutation(order: readonly (string | null)[], members: readonly string[]): boolean {
  if (order.length !== members.length) return false;
  const set = new Set(order);
  if (set.size !== order.length) return false;
  return members.every((m) => set.has(m));
}

// ---------------------------------------------------------------- draw

export type DrawPhase = 'committing' | 'revealing' | 'finalized';

export type DrawAction = 'commit' | 'close_commits' | 'reveal' | 'finalize';

export function checkDraw(phase: DrawPhase | null, action: DrawAction): Check {
  if (phase === null) return refuse('no_draw', 'There is no draw in progress for this circle.');
  switch (action) {
    case 'commit':
    case 'close_commits':
      return phase === 'committing'
        ? OK
        : refuse('commits_closed', 'Commitments are closed for this draw.');
    case 'reveal':
    case 'finalize':
      if (phase === 'committing') return refuse('commits_open', 'Commitments are still open; reveals come after they close.');
      return phase === 'revealing' ? OK : refuse('draw_finalized', 'The draw is already finalized.');
  }
}

// ---------------------------------------------------------------- rounds

export type RoundStatus = 'upcoming' | 'open' | 'closed';

export interface RoundRef {
  n: number;
  status: RoundStatus;
}

/** Rounds open strictly in order, one at a time. */
export function checkOpenRound(rounds: readonly RoundRef[], n: number): Check {
  const round = rounds.find((r) => r.n === n);
  if (!round) return refuse('no_such_round', `This circle has no round ${n}.`);
  if (round.status === 'open') return refuse('round_already_open', `Round ${n} is already open.`);
  if (round.status === 'closed') return refuse('round_closed', `Round ${n} is closed.`);
  const open = rounds.find((r) => r.status === 'open');
  if (open) return refuse('another_round_open', `Round ${open.n} is still open; close it first.`);
  const pending = rounds.find((r) => r.n < n && r.status !== 'closed');
  if (pending) return refuse('previous_round_not_closed', `Round ${pending.n} must be closed before round ${n} opens.`);
  return OK;
}

export function checkCloseRound(rounds: readonly RoundRef[], n: number): Check {
  const round = rounds.find((r) => r.n === n);
  if (!round) return refuse('no_such_round', `This circle has no round ${n}.`);
  if (round.status !== 'open') return refuse('round_not_open', `Round ${n} is not open.`);
  return OK;
}

/** Contributions and payouts are recorded only in an open round. */
export function checkRoundOpenForRecords(round: RoundRef | undefined): Check {
  if (!round) return refuse('no_such_round', 'This circle has no such round.');
  if (round.status !== 'open') return refuse('round_not_open', `Round ${round.n} is not open.`);
  return OK;
}

export function allRoundsClosed(rounds: readonly RoundRef[]): boolean {
  return rounds.length > 0 && rounds.every((r) => r.status === 'closed');
}

// ---------------------------------------------------------------- contributions

export type ContributionState = 'outstanding' | 'reported' | 'confirmed' | 'waived';

export interface ContributionRecord {
  amount: number;
  confirmed: boolean;
}

export interface ContributionStatus {
  state: ContributionState;
  expected: number;
  /** Everything reported, confirmed or not. */
  reported: number;
  confirmed: number;
  /** expected - confirmed, never below zero; zero when waived. */
  outstanding: number;
}

/**
 * Derived state of one member's contribution in one round (ADR §2). Nothing
 * is assumed paid (A5): only confirmed amounts reduce what is outstanding.
 * - waived when the organizer waived it;
 * - confirmed when confirmed amounts reach the expected amount;
 * - reported when reported amounts reach it but confirmation is pending;
 * - outstanding otherwise (partial reports are visible in the amounts).
 */
export function contributionStatus(
  expected: number,
  records: readonly ContributionRecord[],
  waived: boolean,
): ContributionStatus {
  const reported = sumAmounts(records.map((r) => r.amount));
  const confirmed = sumAmounts(records.filter((r) => r.confirmed).map((r) => r.amount));
  const remaining = Math.max(0, addAmounts(expected, -confirmed));
  if (waived) return { state: 'waived', expected, reported, confirmed, outstanding: 0 };
  if (confirmed >= expected) return { state: 'confirmed', expected, reported, confirmed, outstanding: 0 };
  if (reported >= expected) return { state: 'reported', expected, reported, confirmed, outstanding: remaining };
  return { state: 'outstanding', expected, reported, confirmed, outstanding: remaining };
}

/** How much more a member may still report this round (over-payment is refused). */
export function reportableAmount(expected: number, records: readonly ContributionRecord[]): number {
  return Math.max(0, addAmounts(expected, -sumAmounts(records.map((r) => r.amount))));
}
