import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { MAX_MEMBERS } from '../../shared/money.js';
import { checkCircle } from '../../shared/state.js';
import { DISPLAY_NAME_MAX } from '../../shared/validate.js';
import { audit } from '../audit.js';
import { accessCircle, enforce } from '../circle-access.js';
import { newToken, sha256Hex } from '../crypto.js';
import {
  activeMembers,
  countActiveInvites,
  countActiveMembers,
  findActiveMember,
  findInviteByTokenHash,
  getCircle,
  getInvite,
  insertInvite,
  insertMember,
  inviteStatus,
  listInvites,
  markInviteAccepted,
  markInviteRevoked,
  type InviteRow,
} from '../db/circles.js';
import { withTx } from '../db/db.js';
import { appendLedger } from '../db/ledger.js';
import { AppError } from '../errors.js';
import { route, signedIn } from '../http.js';
import { CircleIdParams, id, text, token } from '../schemas.js';
import { circleJson, memberCountOf } from '../views.js';

/** ADR §4 / M1.2: one-time tokens, 7-day expiry, at most 50 active per circle. */
export const INVITE_TTL_MS = 7 * 24 * 60 * 60 * 1000;
export const MAX_ACTIVE_INVITES = 50;

const TokenParams = z.strictObject({ token });
const InviteParams = z.strictObject({ id, inviteId: id });
const AcceptBody = z.strictObject({ displayName: text(1, DISPLAY_NAME_MAX).optional() });

const INVALID = (): AppError => new AppError(404, 'not_found', 'This invitation link is not valid: it may have expired, been used or been revoked.');

function inviteJson(i: InviteRow, now: Date) {
  return { id: i.id, createdAt: i.created_at, expiresAt: i.expires_at, status: inviteStatus(i, now), acceptedAt: i.accepted_at };
}

export function inviteRoutes(api: FastifyInstance): void {
  const app = api;

  route(api, {
    method: 'POST',
    url: '/circles/:id/invites',
    auth: 'user',
    rateLimit: 'invite',
    params: CircleIdParams,
    handler: (ctx) => {
      const { req, reply, params, user, now } = signedIn(ctx);
      const { circle } = accessCircle(req, params.id, 'organizer');
      enforce(checkCircle(circle.status, 'invite'));
      if (countActiveInvites(app.db, circle.id, now) >= MAX_ACTIVE_INVITES) {
        throw new AppError(409, 'too_many_invites', `A circle can have at most ${MAX_ACTIVE_INVITES} open invitations; revoke some first.`);
      }
      const secret = newToken();
      const invite = withTx(app.db, () => {
        const row = insertInvite(app.db, { circleId: circle.id, tokenHash: sha256Hex(secret), createdBy: user.id, now, ttlMs: INVITE_TTL_MS });
        audit(req, { circleId: circle.id, action: 'invite.created', target: `invite:${row.id}` });
        return row;
      });
      void reply.status(201);
      // The token exists in clear only in this response: the organizer shares the link.
      return { invite: inviteJson(invite, now), token: secret, link: `${app.config.baseUrl}/join/${secret}` };
    },
  });

  route(api, {
    method: 'GET',
    url: '/circles/:id/invites',
    auth: 'user',
    params: CircleIdParams,
    handler: (ctx) => {
      const { req, params, now } = signedIn(ctx);
      const { circle } = accessCircle(req, params.id, 'organizer');
      return { invites: listInvites(app.db, circle.id).map((i) => inviteJson(i, now)) };
    },
  });

  route(api, {
    method: 'POST',
    url: '/circles/:id/invites/:inviteId/revoke',
    auth: 'user',
    rateLimit: 'invite',
    params: InviteParams,
    handler: (ctx) => {
      const { req, params, user, now } = signedIn(ctx);
      const { circle } = accessCircle(req, params.id, 'organizer');
      const invite = getInvite(app.db, params.inviteId);
      if (!invite || invite.circle_id !== circle.id) throw new AppError(404, 'not_found', 'Not found.');
      if (inviteStatus(invite, now) !== 'active') {
        throw new AppError(409, 'invite_not_active', 'This invitation was already used, revoked or has expired.');
      }
      withTx(app.db, () => {
        markInviteRevoked(app.db, invite.id, user.id, now);
        audit(req, { circleId: circle.id, action: 'invite.revoked', target: `invite:${invite.id}` });
      });
      return { invite: inviteJson(getInvite(app.db, invite.id) as InviteRow, now) };
    },
  });

  route(api, {
    method: 'GET',
    url: '/invites/:token',
    auth: 'user',
    rateLimit: 'invite',
    params: TokenParams,
    handler: (ctx) => {
      const { params, user, now } = signedIn(ctx);
      const invite = findInviteByTokenHash(app.db, sha256Hex(params.token));
      if (!invite || inviteStatus(invite, now) !== 'active') throw INVALID();
      const circle = getCircle(app.db, invite.circle_id);
      if (!circle || !checkCircle(circle.status, 'join').ok) throw INVALID();
      const members = activeMembers(app.db, circle.id);
      const organizer = members.find((m) => m.role === 'organizer');
      return {
        circle: circleJson(circle, memberCountOf(app.db, circle, members)),
        organizerName: organizer?.display_name ?? '',
        invite: { expiresAt: invite.expires_at },
        alreadyMember: members.some((m) => m.user_id === user.id),
      };
    },
  });

  route(api, {
    method: 'POST',
    url: '/invites/:token/accept',
    auth: 'user',
    rateLimit: 'invite',
    params: TokenParams,
    body: AcceptBody,
    handler: (ctx) => {
      const { req, params, body, user, now } = signedIn(ctx);
      const invite = findInviteByTokenHash(app.db, sha256Hex(params.token));
      if (!invite || inviteStatus(invite, now) !== 'active') throw INVALID();
      const circle = getCircle(app.db, invite.circle_id);
      if (!circle) throw INVALID();
      enforce(checkCircle(circle.status, 'join'));
      if (findActiveMember(app.db, circle.id, user.id)) {
        throw new AppError(409, 'already_member', 'You are already a member of this circle.');
      }
      if (countActiveMembers(app.db, circle.id) >= MAX_MEMBERS) {
        throw new AppError(409, 'circle_full', `A circle has at most ${MAX_MEMBERS} members.`);
      }
      const member = withTx(app.db, () => {
        if (!markInviteAccepted(app.db, invite.id, user.id, now)) throw INVALID();
        const m = insertMember(app.db, {
          circleId: circle.id,
          userId: user.id,
          role: 'member',
          displayName: body.displayName ?? user.displayName,
          now,
        });
        appendLedger(
          app.db,
          circle.id,
          user.id,
          'member.joined',
          { memberId: m.id, userId: user.id, displayName: m.display_name, role: 'member' },
          now,
        );
        audit(req, { circleId: circle.id, action: 'member.joined', target: `member:${m.id}`, details: { inviteId: invite.id } });
        return m;
      });
      return { circleId: circle.id, memberId: member.id };
    },
  });
}
