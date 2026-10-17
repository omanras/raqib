import type { FastifyRequest } from 'fastify';
import type { Check } from '../shared/state.js';
import { findActiveMember, getCircle, type CircleRow, type MemberRow } from './db/circles.js';
import { AppError } from './errors.js';
import { UNAUTHENTICATED } from './http.js';

export type CircleNeed = 'member' | 'organizer';

export interface CircleAccess {
  circle: CircleRow;
  me: MemberRow;
}

/**
 * The one place a circle route decides who may act (S3, A6):
 * - nobody signed in: 401;
 * - not an active member of this circle (or no such circle): 404, so a
 *   circle you are not in cannot be told apart from one that does not
 *   exist (S8.1);
 * - a member where the organizer is needed: 403 (your own circle, so the
 *   refusal may be informative).
 */
export function accessCircle(req: FastifyRequest, circleId: string, need: CircleNeed): CircleAccess {
  if (!req.user) throw UNAUTHENTICATED();
  const circle = getCircle(req.server.db, circleId);
  const me = circle ? findActiveMember(req.server.db, circle.id, req.user.id) : undefined;
  if (!circle || !me) throw new AppError(404, 'not_found', 'Not found.');
  if (need === 'organizer' && me.role !== 'organizer') {
    throw new AppError(403, 'forbidden', 'Only the organizer of this circle can do this.');
  }
  return { circle, me };
}

/** A refused state transition (S3.3): 409 with the machine's code and reason. */
export function enforce(check: Check): void {
  if (!check.ok) throw new AppError(409, check.code, check.reason);
}
