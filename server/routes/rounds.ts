import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { obligationKey, obligationsOfRound, statementOf, viewObligation, type Books } from '../../shared/books.js';
import { subAmounts, sumAmounts } from '../../shared/money.js';
import { addDays, isoDateOf } from '../../shared/schedule.js';
import { allRoundsClosed, checkCircle, checkCloseRound, checkOpenRound } from '../../shared/state.js';
import { REASON_MAX, SHORT_TEXT_MAX } from '../../shared/validate.js';
import { audit } from '../audit.js';
import { accessCircle, enforce } from '../circle-access.js';
import { newId } from '../crypto.js';
import { activeMembers, listRounds, setCircleStatus, type CircleRow, type RoundRow } from '../db/circles.js';
import { withTx } from '../db/db.js';
import { appendLedger } from '../db/ledger.js';
import {
  findContribution,
  findPayout,
  getContribution,
  insertPayout,
  markPayoutAcknowledged,
  markWaived,
  setRoundClosed,
  setRoundOpen,
} from '../db/rounds.js';
import { AppError } from '../errors.js';
import { route, signedIn } from '../http.js';
import { booksOf, contributionIds } from '../obligations.js';
import { amount, id, isoDate, text } from '../schemas.js';

const roundN = z
  .string()
  .regex(/^[1-9][0-9]{0,2}$/, 'a round number')
  .transform(Number);
const RoundParams = z.strictObject({ id, n: roundN });
const ContributionParams = z.strictObject({ id, n: roundN, cid: id });

const ReportBody = z.strictObject({
  memberId: id.optional(),
  amount,
  method: text(0, SHORT_TEXT_MAX).optional(),
  reference: text(0, SHORT_TEXT_MAX).optional(),
});
const ConfirmBody = z.strictObject({ reportIds: z.array(id).min(1).max(100).optional() });
const WaiveBody = z.strictObject({ reason: text(1, REASON_MAX, { multiline: true }) });
const PayoutBody = z.strictObject({
  amount,
  paidOn: isoDate.optional(),
  method: text(0, SHORT_TEXT_MAX).optional(),
  reference: text(0, SHORT_TEXT_MAX).optional(),
});

/** Records (reports, confirmations, waivers, payouts) are kept while the circle runs and after it completes. */
function requireRecordable(circle: CircleRow): void {
  if (circle.status !== 'active' && circle.status !== 'completed') {
    throw new AppError(409, 'circle_not_active', 'Payments are recorded only once the circle has started.');
  }
}

function requireRound(db: FastifyInstance['db'], circleId: string, n: number): RoundRow {
  const round = listRounds(db, circleId).find((r) => r.n === n);
  if (!round) throw new AppError(404, 'not_found', `This circle has no round ${n}.`);
  return round;
}

function requireDue(round: RoundRow): void {
  if (round.status === 'upcoming') {
    throw new AppError(409, 'round_not_due', `Round ${round.n} has not opened yet; nothing is due in it.`);
  }
}

/** Round n with its lines, as every mutation of a round answers. */
export function roundView(db: FastifyInstance['db'], circleId: string, n: number, now: Date, books: Books = booksOf(db, circleId)) {
  const round = books.rounds.find((r) => r.n === n);
  if (!round) return { round: null, lines: [] };
  const ids = contributionIds(db, circleId);
  const today = isoDateOf(now);
  const lines = obligationsOfRound(books, n).map((o) => ({
    ...viewObligation(o, round, today),
    contributionId: ids.get(obligationKey(o.roundN, o.memberId)) ?? '',
    displayName: books.members.get(o.memberId)?.displayName ?? '',
  }));
  return {
    round: {
      n: round.n,
      dueDate: round.dueDate,
      status: round.status,
      recipientMemberId: round.recipientMemberId,
      payout: round.payout,
      expected: sumAmounts(lines.map((l) => l.expected)),
      reported: sumAmounts(lines.map((l) => l.reported)),
      confirmed: sumAmounts(lines.map((l) => l.confirmed)),
      outstanding: sumAmounts(lines.map((l) => l.outstanding)),
    },
    lines,
  };
}

/** Opens round n (state machine checked by the caller): index row, ledger entry, audit row. */
export function openRound(req: FastifyRequest, circle: CircleRow, n: number, actorId: string, now: Date): void {
  const db = req.server.db;
  const round = requireRound(db, circle.id, n);
  const books = booksOf(db, circle.id);
  const obligations = obligationsOfRound(books, n);
  setRoundOpen(db, circle.id, n, now);
  appendLedger(
    db,
    circle.id,
    actorId,
    'round.opened',
    {
      n,
      dueDate: round.due_date,
      recipientMemberId: round.recipient_member_id,
      expected: sumAmounts(obligations.map((o) => o.expected)),
      payers: obligations.length,
    },
    now,
  );
  audit(req, { circleId: circle.id, action: 'round.opened', target: `round:${n}` });
}

export function roundRoutes(api: FastifyInstance): void {
  const app = api;

  route(api, {
    method: 'POST',
    url: '/circles/:id/rounds/:n/open',
    auth: 'user',
    params: RoundParams,
    handler: (ctx) => {
      const { req, user, params, now } = signedIn(ctx);
      const { circle } = accessCircle(req, params.id, 'organizer');
      enforce(checkCircle(circle.status, 'run_rounds'));
      enforce(checkOpenRound(listRounds(app.db, circle.id), params.n));
      withTx(app.db, () => openRound(req, circle, params.n, user.id, now));
      return roundView(app.db, circle.id, params.n, now);
    },
  });

  route(api, {
    method: 'POST',
    url: '/circles/:id/rounds/:n/close',
    auth: 'user',
    params: RoundParams,
    handler: (ctx) => {
      const { req, user, params, now } = signedIn(ctx);
      const { circle } = accessCircle(req, params.id, 'organizer');
      enforce(checkCircle(circle.status, 'run_rounds'));
      enforce(checkCloseRound(listRounds(app.db, circle.id), params.n));
      const view = roundView(app.db, circle.id, params.n, now);
      // Closing with money outstanding is allowed (A5): the entry lists exactly what is missing.
      const outstanding = view.lines
        .filter((l) => l.outstanding > 0)
        .map((l) => ({ memberId: l.memberId, contributionId: l.contributionId, outstanding: l.outstanding }));
      withTx(app.db, () => {
        setRoundClosed(app.db, circle.id, params.n, now);
        appendLedger(
          app.db,
          circle.id,
          user.id,
          'round.closed',
          {
            n: params.n,
            expected: view.round?.expected ?? 0,
            confirmed: view.round?.confirmed ?? 0,
            outstanding,
            payout: view.round?.payout?.amount ?? null,
          },
          now,
        );
        audit(req, { circleId: circle.id, action: 'round.closed', target: `round:${params.n}`, details: { outstanding: outstanding.length } });
        if (allRoundsClosed(listRounds(app.db, circle.id))) {
          setCircleStatus(app.db, circle.id, 'completed', now);
          const books = booksOf(app.db, circle.id);
          const totals = statementOf(books, isoDateOf(now)).totals;
          appendLedger(
            app.db,
            circle.id,
            user.id,
            'circle.completed',
            { rounds: books.rounds.length, confirmed: totals.confirmed, outstanding: totals.outstanding },
            now,
          );
          audit(req, { circleId: circle.id, action: 'circle.completed', target: `circle:${circle.id}` });
        }
      });
      return roundView(app.db, circle.id, params.n, now);
    },
  });

  route(api, {
    method: 'POST',
    url: '/circles/:id/rounds/:n/contributions',
    auth: 'user',
    params: RoundParams,
    body: ReportBody,
    handler: (ctx) => {
      const { req, reply, user, params, body, now } = signedIn(ctx);
      const { circle, me } = accessCircle(req, params.id, 'member');
      requireRecordable(circle);
      const target = body.memberId ?? me.id;
      if (target !== me.id && me.role !== 'organizer') {
        throw new AppError(403, 'forbidden', 'You can report only your own payments; the organizer can record anyone’s.');
      }
      if (!activeMembers(app.db, circle.id).some((m) => m.id === target)) throw new AppError(404, 'not_found', 'No such member.');
      const round = requireRound(app.db, circle.id, params.n);
      requireDue(round);
      const row = findContribution(app.db, circle.id, params.n, target);
      if (!row) {
        throw new AppError(409, 'no_obligation', 'This member owes nothing in this round (the recipient does not pay into their own pot).');
      }
      const books = booksOf(app.db, circle.id);
      const ob = books.obligations.get(obligationKey(params.n, target));
      if (!ob) throw new AppError(409, 'no_obligation', 'This member owes nothing in this round.');
      if (ob.waived) throw new AppError(409, 'waived', 'This contribution was waived by the organizer.');
      const reportable = subAmounts(ob.expected, sumAmounts(ob.reports.map((r) => r.amount)));
      if (body.amount > reportable) {
        throw new AppError(
          409,
          'overpayment',
          reportable === 0 ? 'The full amount has already been reported.' : 'This is more than what is still due for this round.',
          { reportable },
        );
      }
      const reportId = newId();
      withTx(app.db, () => {
        appendLedger(
          app.db,
          circle.id,
          user.id,
          'contribution.reported',
          {
            reportId,
            contributionId: row.id,
            roundN: params.n,
            memberId: target,
            amount: body.amount,
            method: body.method ?? '',
            reference: body.reference ?? '',
          },
          now,
        );
        audit(req, { circleId: circle.id, action: 'contribution.reported', target: `contribution:${row.id}`, details: { reportId } });
      });
      void reply.status(201);
      return { reportId, ...roundView(app.db, circle.id, params.n, now) };
    },
  });

  function obligationFor(req: FastifyRequest, circle: CircleRow, n: number, cid: string) {
    const row = getContribution(req.server.db, cid);
    if (!row || row.circle_id !== circle.id || row.round_n !== n) throw new AppError(404, 'not_found', 'Not found.');
    const books = booksOf(req.server.db, circle.id);
    const ob = books.obligations.get(obligationKey(n, row.member_id));
    if (!ob) throw new AppError(404, 'not_found', 'Not found.');
    return { row, ob, books };
  }

  route(api, {
    method: 'POST',
    url: '/circles/:id/rounds/:n/contributions/:cid/confirm',
    auth: 'user',
    params: ContributionParams,
    body: ConfirmBody,
    handler: (ctx) => {
      const { req, user, params, body, now } = signedIn(ctx);
      const { circle } = accessCircle(req, params.id, 'organizer');
      requireRecordable(circle);
      requireDue(requireRound(app.db, circle.id, params.n));
      const { row, ob } = obligationFor(req, circle, params.n, params.cid);
      const pending = ob.reports.filter((r) => r.confirmedSeq === null);
      let chosen = pending;
      if (body?.reportIds) {
        const ids = new Set(body.reportIds);
        chosen = pending.filter((r) => ids.has(r.reportId));
        if (chosen.length !== ids.size) {
          throw new AppError(409, 'unknown_report', 'Some of these reports do not exist for this contribution or are already confirmed.');
        }
      }
      if (chosen.length === 0) throw new AppError(409, 'nothing_to_confirm', 'There is no reported payment waiting for confirmation.');
      withTx(app.db, () => {
        appendLedger(
          app.db,
          circle.id,
          user.id,
          'contribution.confirmed',
          {
            contributionId: row.id,
            roundN: params.n,
            memberId: row.member_id,
            reportIds: chosen.map((r) => r.reportId),
            amount: sumAmounts(chosen.map((r) => r.amount)),
          },
          now,
        );
        audit(req, { circleId: circle.id, action: 'contribution.confirmed', target: `contribution:${row.id}` });
      });
      return roundView(app.db, circle.id, params.n, now);
    },
  });

  route(api, {
    method: 'POST',
    url: '/circles/:id/rounds/:n/contributions/:cid/waive',
    auth: 'user',
    params: ContributionParams,
    body: WaiveBody,
    handler: (ctx) => {
      const { req, user, params, body, now } = signedIn(ctx);
      const { circle } = accessCircle(req, params.id, 'organizer');
      requireRecordable(circle);
      const round = requireRound(app.db, circle.id, params.n);
      requireDue(round);
      const { row, ob, books } = obligationFor(req, circle, params.n, params.cid);
      if (ob.waived) throw new AppError(409, 'already_waived', 'This contribution is already waived.');
      const view = viewObligation(ob, books.rounds.find((r) => r.n === params.n) as Books['rounds'][number], isoDateOf(now));
      if (view.state === 'confirmed') throw new AppError(409, 'already_confirmed', 'This contribution is fully confirmed; there is nothing to waive.');
      withTx(app.db, () => {
        markWaived(app.db, row.id, user.id, body.reason, now);
        appendLedger(
          app.db,
          circle.id,
          user.id,
          'contribution.waived',
          { contributionId: row.id, roundN: params.n, memberId: row.member_id, reason: body.reason, waived: view.outstanding },
          now,
        );
        audit(req, { circleId: circle.id, action: 'contribution.waived', target: `contribution:${row.id}` });
      });
      return roundView(app.db, circle.id, params.n, now);
    },
  });

  route(api, {
    method: 'POST',
    url: '/circles/:id/rounds/:n/payout',
    auth: 'user',
    params: RoundParams,
    body: PayoutBody,
    handler: (ctx) => {
      const { req, reply, user, params, body, now } = signedIn(ctx);
      const { circle } = accessCircle(req, params.id, 'organizer');
      requireRecordable(circle);
      const round = requireRound(app.db, circle.id, params.n);
      requireDue(round);
      if (findPayout(app.db, circle.id, params.n)) throw new AppError(409, 'payout_exists', 'A payout is already recorded for this round.');
      const today = isoDateOf(now);
      const paidOn = body.paidOn ?? today;
      if (paidOn > addDays(today, 1)) throw new AppError(400, 'paid_on_future', 'A payout cannot be dated in the future.');
      const confirmedPot = roundView(app.db, circle.id, params.n, now).round?.confirmed ?? 0;
      withTx(app.db, () => {
        insertPayout(app.db, {
          circleId: circle.id,
          roundN: params.n,
          amount: body.amount,
          paidOn,
          method: body.method ?? '',
          reference: body.reference ?? '',
          recordedBy: user.id,
          now,
        });
        // The payout is what the organizer says was paid; the pot is what was confirmed. Both are shown.
        appendLedger(
          app.db,
          circle.id,
          user.id,
          'payout.recorded',
          {
            roundN: params.n,
            recipientMemberId: round.recipient_member_id,
            amount: body.amount,
            paidOn,
            method: body.method ?? '',
            reference: body.reference ?? '',
            confirmedPot,
          },
          now,
        );
        audit(req, { circleId: circle.id, action: 'payout.recorded', target: `round:${params.n}` });
      });
      void reply.status(201);
      return roundView(app.db, circle.id, params.n, now);
    },
  });

  route(api, {
    method: 'POST',
    url: '/circles/:id/rounds/:n/payout/ack',
    auth: 'user',
    params: RoundParams,
    handler: (ctx) => {
      const { req, user, params, now } = signedIn(ctx);
      const { circle, me } = accessCircle(req, params.id, 'member');
      requireRecordable(circle);
      const round = requireRound(app.db, circle.id, params.n);
      if (round.recipient_member_id !== me.id) {
        throw new AppError(403, 'not_recipient', 'Only the recipient of this round can acknowledge its payout.');
      }
      const payout = findPayout(app.db, circle.id, params.n);
      if (!payout) throw new AppError(409, 'no_payout', 'No payout has been recorded for this round yet.');
      if (payout.acknowledged_at) throw new AppError(409, 'already_acknowledged', 'You have already acknowledged this payout.');
      withTx(app.db, () => {
        markPayoutAcknowledged(app.db, payout.id, user.id, now);
        appendLedger(
          app.db,
          circle.id,
          user.id,
          'payout.acknowledged',
          { roundN: params.n, recipientMemberId: me.id, amount: payout.amount },
          now,
        );
        audit(req, { circleId: circle.id, action: 'payout.acknowledged', target: `round:${params.n}` });
      });
      return roundView(app.db, circle.id, params.n, now);
    },
  });
}
