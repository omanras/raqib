import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { JsonObject } from '../../shared/ledger.js';
import { isCurrency, minorUnitOf, mulAmount } from '../../shared/money.js';
import { addDays, isValidDueDay, isoDateOf, payersPerRound, roundsFor, type Period } from '../../shared/schedule.js';
import { checkCircle } from '../../shared/state.js';
import { CIRCLE_NAME_MAX, DISPLAY_NAME_MAX, REASON_MAX, RULES_TEXT_MAX } from '../../shared/validate.js';
import { audit } from '../audit.js';
import { accessCircle, enforce } from '../circle-access.js';
import {
  EDITABLE,
  activeMembers,
  freezeMemberCount,
  getCircle,
  insertCircle,
  insertMember,
  insertObligation,
  insertRound,
  listCirclesForUser,
  markMemberLeft,
  clearPositions,
  setCircleStatus,
  setPositions,
  updateCircleField,
  type CircleRow,
  type EditableField,
} from '../db/circles.js';
import { withTx } from '../db/db.js';
import { appendLedger } from '../db/ledger.js';
import { AppError } from '../errors.js';
import { route, signedIn } from '../http.js';
import { obligationStatuses, summarize } from '../obligations.js';
import { CircleIdParams, amount, id, isoDate, text } from '../schemas.js';
import { circleView, startCheckOf } from '../views.js';
import { drawFinalized } from './draw-state.js';

const period = z.enum(['monthly', 'weekly', 'biweekly']);
const dueDay = z.number().int().min(1).max(28);
const currency = z.string().max(3).refine(isCurrency, 'a supported ISO-4217 currency code');

const CreateBody = z
  .strictObject({
    name: text(1, CIRCLE_NAME_MAX),
    currency,
    contribution: amount,
    period,
    dueDay,
    startDate: isoDate.nullable().optional(),
    rulesText: text(0, RULES_TEXT_MAX, { multiline: true }).optional(),
    recipientPays: z.boolean().optional(),
    displayName: text(1, DISPLAY_NAME_MAX).optional(),
  })
  .superRefine((v, ctx) => {
    if (!isValidDueDay(v.period, v.dueDay)) {
      ctx.addIssue({ code: 'custom', path: ['dueDay'], message: 'weekly and biweekly circles take an ISO weekday 1-7' });
    }
  });

const PatchBody = z
  .strictObject({
    name: text(1, CIRCLE_NAME_MAX).optional(),
    currency: currency.optional(),
    contribution: amount.optional(),
    period: period.optional(),
    dueDay: dueDay.optional(),
    startDate: isoDate.nullable().optional(),
    rulesText: text(0, RULES_TEXT_MAX, { multiline: true }).optional(),
    recipientPays: z.boolean().optional(),
  })
  .refine((v) => Object.keys(v).length > 0, 'nothing to change');

const OrderBody = z.strictObject({ order: z.array(id).min(1).max(100) });
const CancelBody = z.strictObject({ reason: text(0, REASON_MAX, { multiline: true }).optional() });

/** A start date may be today (UTC, with one day of slack for time zones) up to five years ahead. */
function requireUsableStartDate(startDate: string | null | undefined, now: Date): void {
  if (startDate === null || startDate === undefined) return;
  const today = isoDateOf(now);
  if (startDate < addDays(today, -1)) {
    throw new AppError(409, 'start_date_past', 'The start date is in the past; choose today or a later date.');
  }
  if (startDate > addDays(today, 5 * 366)) {
    throw new AppError(400, 'start_date_far', 'The start date is more than five years ahead.');
  }
}

function view(app: FastifyInstance, circleId: string, userId: string, now: Date) {
  const circle = getCircle(app.db, circleId) as CircleRow;
  const me = activeMembers(app.db, circleId).find((m) => m.user_id === userId);
  if (!me) return { ok: true };
  return circleView(app.db, { circle, me }, now, drawFinalized(app.db, circleId));
}

export function circleRoutes(api: FastifyInstance): void {
  const app = api;

  route(api, {
    method: 'POST',
    url: '/circles',
    auth: 'user',
    body: CreateBody,
    handler: (ctx) => {
      const { req, reply, user, body, now } = signedIn(ctx);
      requireUsableStartDate(body.startDate, now);
      const created = withTx(app.db, () => {
        const circle = insertCircle(app.db, {
          name: body.name,
          currency: body.currency,
          minorUnit: minorUnitOf(body.currency),
          contribution: body.contribution,
          period: body.period,
          dueDay: body.dueDay,
          startDate: body.startDate ?? null,
          recipientPays: body.recipientPays ?? true,
          rulesText: body.rulesText ?? '',
          createdBy: user.id,
          now,
        });
        const organizer = insertMember(app.db, {
          circleId: circle.id,
          userId: user.id,
          role: 'organizer',
          displayName: body.displayName ?? user.displayName,
          now,
        });
        appendLedger(
          app.db,
          circle.id,
          user.id,
          'circle.created',
          {
            circleId: circle.id,
            name: circle.name,
            currency: circle.currency,
            minorUnit: circle.minor_unit,
            contribution: circle.contribution,
            period: circle.period,
            dueDay: circle.due_day,
            startDate: circle.start_date,
            recipientPays: circle.recipient_pays === 1,
            rulesText: circle.rules_text,
          },
          now,
        );
        appendLedger(
          app.db,
          circle.id,
          user.id,
          'member.joined',
          { memberId: organizer.id, userId: user.id, displayName: organizer.display_name, role: 'organizer' },
          now,
        );
        audit(req, { circleId: circle.id, action: 'circle.created', target: `circle:${circle.id}` });
        return { circle, organizer };
      });
      void reply.status(201);
      return circleView(app.db, { circle: created.circle, me: created.organizer }, now, false);
    },
  });

  route(api, {
    method: 'GET',
    url: '/circles',
    auth: 'user',
    handler: (ctx) => {
      const { user, now } = signedIn(ctx);
      const circles = listCirclesForUser(app.db, user.id).map((c) => {
        const statuses = obligationStatuses(app.db, c.id, now);
        const mine = summarize(statuses.filter((s) => s.memberId === c.my_member_id));
        const all = summarize(statuses);
        const memberCount = c.member_count ?? c.active_members;
        return {
          id: c.id,
          name: c.name,
          status: c.status,
          role: c.my_role,
          memberId: c.my_member_id,
          currency: c.currency,
          minorUnit: c.minor_unit,
          contribution: c.contribution,
          period: c.period,
          memberCount,
          pot: mulAmount(c.contribution, Math.max(0, payersPerRound(memberCount, c.recipient_pays === 1))),
          startDate: c.start_date,
          myOutstandingCount: mine.outstandingCount,
          myOutstandingAmount: mine.outstandingAmount,
          outstandingCount: all.outstandingCount,
        };
      });
      return { circles };
    },
  });

  route(api, {
    method: 'GET',
    url: '/circles/:id',
    auth: 'user',
    params: CircleIdParams,
    handler: (ctx) => {
      const { req, params, now } = signedIn(ctx);
      const access = accessCircle(req, params.id, 'member');
      return circleView(app.db, access, now, drawFinalized(app.db, access.circle.id));
    },
  });

  route(api, {
    method: 'PATCH',
    url: '/circles/:id',
    auth: 'user',
    params: CircleIdParams,
    body: PatchBody,
    handler: (ctx) => {
      const { req, user, params, body, now } = signedIn(ctx);
      const { circle } = accessCircle(req, params.id, 'organizer');
      enforce(checkCircle(circle.status, 'edit'));
      const next = {
        name: body.name ?? circle.name,
        currency: body.currency ?? circle.currency,
        contribution: body.contribution ?? circle.contribution,
        period: (body.period ?? circle.period) as Period,
        dueDay: body.dueDay ?? circle.due_day,
        startDate: body.startDate === undefined ? circle.start_date : body.startDate,
        recipientPays: body.recipientPays === undefined ? circle.recipient_pays === 1 : body.recipientPays,
        rulesText: body.rulesText ?? circle.rules_text,
      };
      const minorUnit = minorUnitOf(next.currency);
      if (minorUnit !== circle.minor_unit && body.contribution === undefined) {
        throw new AppError(400, 'contribution_required', 'The new currency has a different minor unit; give the contribution again.');
      }
      if (!isValidDueDay(next.period, next.dueDay)) {
        throw new AppError(400, 'invalid_due_day', 'Weekly and biweekly circles take an ISO weekday 1-7 as due day.');
      }
      if (body.startDate !== undefined) requireUsableStartDate(next.startDate, now);
      const current: Record<EditableField, string | number | boolean | null> = {
        name: circle.name,
        currency: circle.currency,
        minorUnit: circle.minor_unit,
        contribution: circle.contribution,
        period: circle.period,
        dueDay: circle.due_day,
        startDate: circle.start_date,
        recipientPays: circle.recipient_pays === 1,
        rulesText: circle.rules_text,
      };
      const wanted: Record<EditableField, string | number | boolean | null> = { ...next, minorUnit };
      const changed = (Object.keys(EDITABLE) as EditableField[]).filter((f) => current[f] !== wanted[f]);
      withTx(app.db, () => {
        for (const field of changed) {
          const to = wanted[field];
          updateCircleField(app.db, circle.id, field, typeof to === 'boolean' ? (to ? 1 : 0) : to);
          appendLedger(app.db, circle.id, user.id, 'circle.rule_changed', { field, from: current[field], to } as JsonObject, now);
        }
        audit(req, { circleId: circle.id, action: 'circle.rule_changed', target: `circle:${circle.id}`, details: { fields: changed } });
      });
      return { changed, ...view(app, circle.id, user.id, now) };
    },
  });

  route(api, {
    method: 'POST',
    url: '/circles/:id/order',
    auth: 'user',
    params: CircleIdParams,
    body: OrderBody,
    handler: (ctx) => {
      const { req, user, params, body, now } = signedIn(ctx);
      const { circle } = accessCircle(req, params.id, 'organizer');
      enforce(checkCircle(circle.status, 'set_order'));
      const members = activeMembers(app.db, circle.id);
      const ids = new Set(members.map((m) => m.id));
      const given = new Set(body.order);
      if (body.order.length !== members.length || given.size !== body.order.length || !body.order.every((m) => ids.has(m))) {
        throw new AppError(400, 'invalid_order', 'The order must list every current member exactly once.');
      }
      withTx(app.db, () => {
        setPositions(app.db, circle.id, body.order);
        appendLedger(app.db, circle.id, user.id, 'order.set', { order: body.order, method: 'manual' }, now);
        audit(req, { circleId: circle.id, action: 'order.set', target: `circle:${circle.id}` });
      });
      return view(app, circle.id, user.id, now);
    },
  });

  route(api, {
    method: 'POST',
    url: '/circles/:id/start',
    auth: 'user',
    params: CircleIdParams,
    handler: (ctx) => {
      const { req, user, params, now } = signedIn(ctx);
      const { circle } = accessCircle(req, params.id, 'organizer');
      const members = activeMembers(app.db, circle.id);
      enforce(startCheckOf(app.db, circle, members, drawFinalized(app.db, circle.id)));
      requireUsableStartDate(circle.start_date, now);
      const order = [...members].sort((a, b) => (a.position as number) - (b.position as number)).map((m) => m.id);
      const recipientPays = circle.recipient_pays === 1;
      const schedule = roundsFor({
        startDate: circle.start_date as string,
        period: circle.period,
        dueDay: circle.due_day,
        memberCount: members.length,
        contribution: circle.contribution,
        recipientPays,
        order,
      });
      withTx(app.db, () => {
        freezeMemberCount(app.db, circle.id, members.length);
        for (const r of schedule) {
          insertRound(app.db, { circleId: circle.id, n: r.n, dueDate: r.dueDate, recipientMemberId: r.recipient, now });
          for (const memberId of order) {
            if (!recipientPays && memberId === r.recipient) continue;
            insertObligation(app.db, { circleId: circle.id, roundN: r.n, memberId, expected: circle.contribution, now });
          }
        }
        setCircleStatus(app.db, circle.id, 'active', now);
        appendLedger(
          app.db,
          circle.id,
          user.id,
          'circle.started',
          {
            memberCount: members.length,
            startDate: circle.start_date as string,
            contribution: circle.contribution,
            currency: circle.currency,
            recipientPays,
            pot: schedule[0]?.pot ?? 0,
            rounds: schedule.map((r) => ({ n: r.n, dueDate: r.dueDate, recipientMemberId: r.recipient })),
          },
          now,
        );
        audit(req, { circleId: circle.id, action: 'circle.started', target: `circle:${circle.id}` });
      });
      return view(app, circle.id, user.id, now);
    },
  });

  route(api, {
    method: 'POST',
    url: '/circles/:id/leave',
    auth: 'user',
    params: CircleIdParams,
    handler: (ctx) => {
      const { req, user, params, now } = signedIn(ctx);
      const { circle, me } = accessCircle(req, params.id, 'member');
      if (me.role === 'organizer') {
        throw new AppError(409, 'organizer_cannot_leave', 'The organizer cannot leave; cancel the circle instead.');
      }
      enforce(checkCircle(circle.status, 'leave'));
      withTx(app.db, () => {
        const hadOrder = activeMembers(app.db, circle.id).some((m) => m.position !== null);
        markMemberLeft(app.db, me.id, now);
        if (hadOrder) clearPositions(app.db, circle.id);
        appendLedger(
          app.db,
          circle.id,
          user.id,
          'member.left',
          { memberId: me.id, userId: user.id, displayName: me.display_name, orderCleared: hadOrder },
          now,
        );
        audit(req, { circleId: circle.id, action: 'member.left', target: `member:${me.id}` });
      });
      return { ok: true };
    },
  });

  route(api, {
    method: 'POST',
    url: '/circles/:id/cancel',
    auth: 'user',
    params: CircleIdParams,
    body: CancelBody,
    handler: (ctx) => {
      const { req, user, params, body, now } = signedIn(ctx);
      const { circle } = accessCircle(req, params.id, 'organizer');
      enforce(checkCircle(circle.status, 'cancel'));
      withTx(app.db, () => {
        setCircleStatus(app.db, circle.id, 'cancelled', now);
        appendLedger(app.db, circle.id, user.id, 'circle.cancelled', { reason: body.reason ?? '', status: circle.status }, now);
        audit(req, { circleId: circle.id, action: 'circle.cancelled', target: `circle:${circle.id}` });
      });
      return view(app, circle.id, user.id, now);
    },
  });
}
