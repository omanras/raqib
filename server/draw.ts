import type { LedgerEntry } from '../shared/ledger.js';
import { finalize, type LotteryResult } from '../shared/lottery.js';
import type { DrawPhase } from '../shared/state.js';
import { sha256Hex } from './crypto.js';
import type { DB } from './db/db.js';
import { listLedger } from './db/ledger.js';

/**
 * The draw of a circle, folded from its ledger entries (draw.opened,
 * draw.committed, draw.commits_closed, draw.revealed, draw.finalized). The
 * ledger is the only record of the draw, so the server, a member's browser
 * and an outside verifier all compute the same state from the same
 * evidence.
 */
export interface DrawState {
  phase: DrawPhase;
  openedSeq: number;
  commitDeadline: string;
  revealDeadline: string;
  /** Member ids taking part (the active members when the draw opened), sorted. */
  members: string[];
  commitments: Map<string, { commitment: string; seq: number }>;
  reveals: Map<string, { secret: string; seq: number }>;
  commitsClosed: { seq: number; automatic: boolean } | null;
  result: (LotteryResult & { seq: number; notCommitted: string[] }) | null;
}

export const DRAW_TYPES = ['draw.opened', 'draw.committed', 'draw.commits_closed', 'draw.revealed', 'draw.finalized'] as const;

export function foldDraw(entries: readonly LedgerEntry[]): DrawState | null {
  let state: DrawState | null = null;
  for (const e of entries) {
    const p = e.payload as Record<string, unknown>;
    switch (e.type) {
      case 'draw.opened':
        state = {
          phase: 'committing',
          openedSeq: e.seq,
          commitDeadline: p.commitDeadline as string,
          revealDeadline: p.revealDeadline as string,
          members: [...(p.members as string[])].sort(),
          commitments: new Map(),
          reveals: new Map(),
          commitsClosed: null,
          result: null,
        };
        break;
      case 'draw.committed':
        state?.commitments.set(p.memberId as string, { commitment: p.commitment as string, seq: e.seq });
        break;
      case 'draw.commits_closed':
        if (state) {
          state.phase = 'revealing';
          state.commitsClosed = { seq: e.seq, automatic: p.automatic === true };
        }
        break;
      case 'draw.revealed':
        state?.reveals.set(p.memberId as string, { secret: p.secret as string, seq: e.seq });
        break;
      case 'draw.finalized':
        if (state) {
          state.phase = 'finalized';
          state.result = {
            seed: p.seed as string,
            order: p.order as string[],
            revealed: p.revealed as string[],
            silent: p.silent as string[],
            notCommitted: p.notCommitted as string[],
            seq: e.seq,
          };
        }
        break;
      default:
        break;
    }
  }
  return state;
}

export function loadDraw(db: DB, circleId: string): DrawState | null {
  return foldDraw(listLedger(db, circleId).filter((e) => (DRAW_TYPES as readonly string[]).includes(e.type)));
}

/** The order the entries imply: shared/lottery.finalize over the verified reveals. */
export function computeResult(circleId: string, state: DrawState): LotteryResult & { notCommitted: string[] } {
  const reveals = new Map([...state.reveals].map(([m, r]) => [m, r.secret]));
  const result = finalize(circleId, state.members, reveals, sha256Hex);
  return { ...result, notCommitted: state.members.filter((m) => !state.commitments.has(m)) };
}

/** The phase as of `now`: commitments are closed once their deadline has passed, written or not. */
export function effectivePhase(state: DrawState, now: Date): DrawPhase {
  if (state.phase === 'committing' && now.getTime() >= Date.parse(state.commitDeadline)) return 'revealing';
  return state.phase;
}

export function allCommitted(state: DrawState): boolean {
  return state.members.every((m) => state.commitments.has(m));
}

export function allRevealed(state: DrawState): boolean {
  return [...state.commitments.keys()].every((m) => state.reveals.has(m));
}
