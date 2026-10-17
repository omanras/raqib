import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { isCommitment, isSecret, verifyReveal } from '../../shared/lottery.js';
import { MIN_MEMBERS, checkCircle, checkDraw, type DrawAction } from '../../shared/state.js';
import { audit } from '../audit.js';
import { accessCircle, enforce } from '../circle-access.js';
import { sha256Hex } from '../crypto.js';
import { activeMembers, clearPositions, setCircleStatus, setPositions, type CircleRow } from '../db/circles.js';
import { withTx } from '../db/db.js';
import { appendLedger } from '../db/ledger.js';
import { allCommitted, allRevealed, computeResult, effectivePhase, loadDraw, type DrawState } from '../draw.js';
import { AppError } from '../errors.js';
import { route, signedIn } from '../http.js';
import { CircleIdParams, instant } from '../schemas.js';

const HOUR = 60 * 60 * 1000;
const MAX_AHEAD = 30 * 24 * HOUR;

const OpenBody = z.strictObject({ commitDeadline: instant, revealDeadline: instant });
const CommitBody = z.strictObject({
  commitment: z.string().refine(isCommitment, 'SHA-256 as 64 lowercase hex characters'),
});
const RevealBody = z.strictObject({ secret: z.string().refine(isSecret, '64 lowercase hex characters') });

/** The system actor for entries no person wrote (the automatic close at the commit deadline). */
export const SYSTEM_ACTOR = 'system';

function requireDraw(circleId: string, db: FastifyInstance['db']): DrawState {
  const state = loadDraw(db, circleId);
  if (!state) throw new AppError(409, 'no_draw', 'There is no draw in progress for this circle.');
  return state;
}

/**
 * Commitments close by themselves at their deadline (A5: nothing waits on
 * a silent member). The entry is written by the first draw request after
 * the deadline, in its own transaction, so it stands even if that request
 * is then refused.
 */
function settleDeadline(req: FastifyRequest, circle: CircleRow, now: Date): DrawState | null {
  const db = req.server.db;
  const state = loadDraw(db, circle.id);
  if (!state || state.phase !== 'committing' || now.getTime() < Date.parse(state.commitDeadline)) return state;
  withTx(db, () => {
    appendLedger(
      db,
      circle.id,
      SYSTEM_ACTOR,
      'draw.commits_closed',
      {
        automatic: true,
        committed: state.commitments.size,
        notCommitted: state.members.filter((m) => !state.commitments.has(m)),
      },
      now,
    );
    audit(req, { circleId: circle.id, action: 'draw.commits_closed', target: `circle:${circle.id}`, actorId: null, details: { automatic: true } });
  });
  return loadDraw(db, circle.id);
}

function step(state: DrawState, action: DrawAction): void {
  enforce(checkDraw(state.phase, action));
}

export function drawJson(state: DrawState | null, memberId: string, now: Date) {
  if (!state) return { draw: null };
  const mine = { committed: state.commitments.has(memberId), revealed: state.reveals.has(memberId), commitment: state.commitments.get(memberId)?.commitment ?? null };
  const finalized = state.phase === 'finalized';
  return {
    draw: {
      phase: effectivePhase(state, now),
      openedSeq: state.openedSeq,
      commitDeadline: state.commitDeadline,
      revealDeadline: state.revealDeadline,
      memberCount: state.members.length,
      committedCount: state.commitments.size,
      revealedCount: state.reveals.size,
      takingPart: state.members.includes(memberId),
      mine,
      commitsClosed: state.commitsClosed,
      // The whole record once the order is fixed, so any member can recompute it.
      result: finalized && state.result
        ? {
            seed: state.result.seed,
            order: state.result.order,
            revealed: state.result.revealed,
            silent: state.result.silent,
            notCommitted: state.result.notCommitted,
            seq: state.result.seq,
            members: state.members,
            reveals: [...state.reveals].map(([m, r]) => ({ memberId: m, secret: r.secret, seq: r.seq })),
            commitments: [...state.commitments].map(([m, c]) => ({ memberId: m, commitment: c.commitment, seq: c.seq })),
          }
        : null,
    },
  };
}

export function drawRoutes(api: FastifyInstance): void {
  const app = api;

  route(api, {
    method: 'GET',
    url: '/circles/:id/draw',
    auth: 'user',
    params: CircleIdParams,
    handler: (ctx) => {
      const { req, params, now } = signedIn(ctx);
      const { circle, me } = accessCircle(req, params.id, 'member');
      return drawJson(loadDraw(app.db, circle.id), me.id, now);
    },
  });

  route(api, {
    method: 'POST',
    url: '/circles/:id/draw/open',
    auth: 'user',
    params: CircleIdParams,
    body: OpenBody,
    handler: (ctx) => {
      const { req, user, params, body, now } = signedIn(ctx);
      const { circle, me } = accessCircle(req, params.id, 'organizer');
      enforce(checkCircle(circle.status, 'open_draw'));
      const members = activeMembers(app.db, circle.id);
      if (members.length < MIN_MEMBERS) {
        throw new AppError(409, 'too_few_members', `A draw needs at least ${MIN_MEMBERS} members.`);
      }
      const commitAt = Date.parse(body.commitDeadline);
      const revealAt = Date.parse(body.revealDeadline);
      if (commitAt < now.getTime() + HOUR) {
        throw new AppError(400, 'deadline_too_soon', 'The commitment deadline must be at least one hour ahead.');
      }
      if (revealAt < commitAt + HOUR) {
        throw new AppError(400, 'deadline_too_soon', 'The reveal deadline must be at least one hour after the commitment deadline.');
      }
      if (revealAt > now.getTime() + MAX_AHEAD) {
        throw new AppError(400, 'deadline_too_far', 'Deadlines must be within 30 days.');
      }
      // Members commit knowing the schedule: the start date is set, and not before the draw ends.
      if (!circle.start_date) {
        throw new AppError(409, 'no_start_date', 'Set a start date before opening the draw: members commit knowing when the circle starts.');
      }
      if (circle.start_date < new Date(revealAt).toISOString().slice(0, 10)) {
        throw new AppError(409, 'start_before_draw_ends', 'The start date must be on or after the day the reveal deadline falls on.');
      }
      const hadOrder = members.some((m) => m.position !== null);
      withTx(app.db, () => {
        if (hadOrder) clearPositions(app.db, circle.id);
        setCircleStatus(app.db, circle.id, 'drawing', now);
        appendLedger(
          app.db,
          circle.id,
          user.id,
          'draw.opened',
          {
            commitDeadline: new Date(commitAt).toISOString(),
            revealDeadline: new Date(revealAt).toISOString(),
            members: members.map((m) => m.id).sort(),
            orderCleared: hadOrder,
          },
          now,
        );
        audit(req, { circleId: circle.id, action: 'draw.opened', target: `circle:${circle.id}` });
      });
      return drawJson(loadDraw(app.db, circle.id), me.id, now);
    },
  });

  route(api, {
    method: 'POST',
    url: '/circles/:id/draw/commit',
    auth: 'user',
    params: CircleIdParams,
    body: CommitBody,
    handler: (ctx) => {
      const { req, user, params, body, now } = signedIn(ctx);
      const { circle, me } = accessCircle(req, params.id, 'member');
      enforce(checkCircle(circle.status, 'draw'));
      const state = settleDeadline(req, circle, now) ?? requireDraw(circle.id, app.db);
      step(state, 'commit');
      if (!state.members.includes(me.id)) throw new AppError(409, 'not_in_draw', 'You were not a member when this draw opened.');
      if (state.commitments.has(me.id)) throw new AppError(409, 'already_committed', 'You have already committed in this draw.');
      withTx(app.db, () => {
        // Only the hash goes into the ledger; the secret stays with the member until the reveal.
        appendLedger(app.db, circle.id, user.id, 'draw.committed', { memberId: me.id, commitment: body.commitment }, now);
        audit(req, { circleId: circle.id, action: 'draw.committed', target: `member:${me.id}` });
      });
      return drawJson(loadDraw(app.db, circle.id), me.id, now);
    },
  });

  route(api, {
    method: 'POST',
    url: '/circles/:id/draw/close-commits',
    auth: 'user',
    params: CircleIdParams,
    handler: (ctx) => {
      const { req, user, params, now } = signedIn(ctx);
      const { circle, me } = accessCircle(req, params.id, 'organizer');
      enforce(checkCircle(circle.status, 'draw'));
      const state = settleDeadline(req, circle, now) ?? requireDraw(circle.id, app.db);
      step(state, 'close_commits');
      if (!allCommitted(state)) {
        const missing = state.members.length - state.commitments.size;
        throw new AppError(
          409,
          'commits_pending',
          `${missing} member(s) have not committed yet; commitments close early only when everyone has committed, otherwise at the deadline.`,
          { missing },
        );
      }
      withTx(app.db, () => {
        appendLedger(
          app.db,
          circle.id,
          user.id,
          'draw.commits_closed',
          { automatic: false, committed: state.commitments.size, notCommitted: [] },
          now,
        );
        audit(req, { circleId: circle.id, action: 'draw.commits_closed', target: `circle:${circle.id}` });
      });
      return drawJson(loadDraw(app.db, circle.id), me.id, now);
    },
  });

  route(api, {
    method: 'POST',
    url: '/circles/:id/draw/reveal',
    auth: 'user',
    params: CircleIdParams,
    body: RevealBody,
    handler: (ctx) => {
      const { req, user, params, body, now } = signedIn(ctx);
      const { circle, me } = accessCircle(req, params.id, 'member');
      enforce(checkCircle(circle.status, 'draw'));
      const state = settleDeadline(req, circle, now) ?? requireDraw(circle.id, app.db);
      step(state, 'reveal');
      if (now.getTime() >= Date.parse(state.revealDeadline)) {
        throw new AppError(409, 'reveals_closed', 'The reveal deadline has passed.');
      }
      const commitment = state.commitments.get(me.id);
      if (!commitment) throw new AppError(409, 'not_committed', 'Only members who committed can reveal.');
      if (state.reveals.has(me.id)) throw new AppError(409, 'already_revealed', 'You have already revealed.');
      if (!verifyReveal(commitment.commitment, body.secret, me.id, sha256Hex)) {
        withTx(app.db, () => {
          audit(req, { circleId: circle.id, action: 'draw.reveal_refused', target: `member:${me.id}` });
        });
        throw new AppError(400, 'wrong_secret', 'This secret does not match your commitment.');
      }
      withTx(app.db, () => {
        appendLedger(app.db, circle.id, user.id, 'draw.revealed', { memberId: me.id, secret: body.secret }, now);
        audit(req, { circleId: circle.id, action: 'draw.revealed', target: `member:${me.id}` });
      });
      return drawJson(loadDraw(app.db, circle.id), me.id, now);
    },
  });

  route(api, {
    method: 'POST',
    url: '/circles/:id/draw/finalize',
    auth: 'user',
    params: CircleIdParams,
    handler: (ctx) => {
      const { req, user, params, now } = signedIn(ctx);
      const { circle, me } = accessCircle(req, params.id, 'organizer');
      enforce(checkCircle(circle.status, 'draw'));
      const state = settleDeadline(req, circle, now) ?? requireDraw(circle.id, app.db);
      step(state, 'finalize');
      if (!allRevealed(state) && now.getTime() < Date.parse(state.revealDeadline)) {
        const missing = state.commitments.size - state.reveals.size;
        throw new AppError(
          409,
          'reveals_pending',
          `${missing} member(s) have not revealed yet; the draw can be finalized when everyone has, or after the reveal deadline.`,
          { missing },
        );
      }
      const result = computeResult(circle.id, state);
      withTx(app.db, () => {
        setPositions(app.db, circle.id, result.order);
        appendLedger(
          app.db,
          circle.id,
          user.id,
          'draw.finalized',
          {
            seed: result.seed,
            order: result.order,
            revealed: result.revealed,
            silent: result.silent,
            notCommitted: result.notCommitted,
            members: state.members,
            rule: 'silent members (never revealed) are placed last in member-id order',
          },
          now,
        );
        audit(req, { circleId: circle.id, action: 'draw.finalized', target: `circle:${circle.id}`, details: { silent: result.silent.length } });
      });
      return drawJson(loadDraw(app.db, circle.id), me.id, now);
    },
  });
}
