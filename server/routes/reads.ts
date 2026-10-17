import type { FastifyInstance, FastifyReply } from 'fastify';
import { z } from 'zod';
import { obligationKey, statementOf, viewObligation, type Books, type Statement } from '../../shared/books.js';
import { verify } from '../../shared/ledger.js';
import { formatMinor, type MinorUnit } from '../../shared/money.js';
import { daysBetween, isoDateOf } from '../../shared/schedule.js';
import { listAudit } from '../audit.js';
import { accessCircle } from '../circle-access.js';
import { sha256Hex } from '../crypto.js';
import { csvDocument } from '../csv.js';
import { activeMembers, type CircleRow, type MemberRow } from '../db/circles.js';
import { ledgerHead, listLedger } from '../db/ledger.js';
import { AppError } from '../errors.js';
import { route, signedIn } from '../http.js';
import { booksOf, contributionIds } from '../obligations.js';
import { CircleIdParams, id } from '../schemas.js';
import { roundView } from './rounds.js';

const positiveInt = (max: number) =>
  z
    .string()
    .regex(/^[1-9][0-9]{0,9}$/, 'a positive whole number')
    .transform(Number)
    .refine((n) => n <= max, `at most ${max}`);

const LedgerQuery = z.strictObject({ from: positiveInt(10_000_000).optional(), verify: z.enum(['0', '1']).optional() });
const StatementQuery = z.strictObject({ member: id.optional() });
const AuditQuery = z.strictObject({ before: positiveInt(Number.MAX_SAFE_INTEGER).optional(), limit: positiveInt(200).optional() });

/** S4: a member may see only their own statement; the organizer anyone's. 404 for a member not in the circle. */
function statementFor(app: FastifyInstance, circle: CircleRow, me: MemberRow, member: string | undefined, now: Date) {
  if (member !== undefined) {
    if (member !== me.id && me.role !== 'organizer') {
      throw new AppError(403, 'forbidden', 'You can open only your own statement; the organizer can open anyone’s.');
    }
  }
  const books = booksOf(app.db, circle.id);
  if (member !== undefined && !books.members.has(member)) throw new AppError(404, 'not_found', 'No such member.');
  return { books, statement: statementOf(books, isoDateOf(now), member ?? null) };
}

function names(books: Books): Record<string, string> {
  return Object.fromEntries([...books.members.values()].map((m) => [m.memberId, m.displayName]));
}

export function statementCsv(statement: Statement, books: Books): string {
  const unit = statement.minorUnit as MinorUnit;
  const money = (n: number) => formatMinor(n, unit, { grouping: false });
  const who = names(books);
  const rows: (string | number)[][] = [];
  for (const r of statement.rounds) {
    for (const l of r.lines) {
      rows.push([
        r.n,
        r.dueDate,
        r.status,
        who[l.memberId] ?? '',
        l.memberId,
        statement.currency,
        money(l.expected),
        money(l.reported),
        money(l.confirmed),
        money(l.outstanding),
        l.state,
        l.ageDays ?? '',
        l.waiveReason ?? '',
        l.seqs.join(' '),
      ]);
    }
    if (r.payout) {
      rows.push([
        r.n,
        r.dueDate,
        r.status,
        who[r.recipientMemberId] ?? '',
        r.recipientMemberId,
        statement.currency,
        '',
        '',
        '',
        '',
        `payout ${money(r.payout.amount)} on ${r.payout.paidOn}${r.payout.acknowledgedSeq ? ' (acknowledged)' : ''}`,
        '',
        '',
        [r.payout.seq, r.payout.acknowledgedSeq].filter((s) => s !== null).join(' '),
      ]);
    }
  }
  return csvDocument(
    ['round', 'due_date', 'round_status', 'member', 'member_id', 'currency', 'expected', 'reported', 'confirmed', 'outstanding', 'state', 'days_overdue', 'waive_reason', 'ledger_seqs'],
    rows,
  );
}

function sendCsv(reply: FastifyReply, filename: string, body: string): FastifyReply {
  return reply
    .header('content-type', 'text/csv; charset=utf-8')
    .header('content-disposition', `attachment; filename="${filename}"`)
    .header('cache-control', 'no-store')
    .send(body);
}

export function readRoutes(api: FastifyInstance): void {
  const app = api;

  route(api, {
    method: 'GET',
    url: '/circles/:id/ledger',
    auth: 'user',
    params: CircleIdParams,
    query: LedgerQuery,
    handler: (ctx) => {
      const { req, params, query, now } = signedIn(ctx);
      const { circle } = accessCircle(req, params.id, 'member');
      const all = listLedger(app.db, circle.id);
      const from = query.from ?? 1;
      return {
        circleId: circle.id,
        fetchedAt: now.toISOString(),
        head: ledgerHead(app.db, circle.id),
        entries: all.filter((e) => e.seq >= from),
        verification: query.verify === '1' ? verify(all, sha256Hex) : null,
      };
    },
  });

  route(api, {
    method: 'GET',
    url: '/circles/:id/statement',
    auth: 'user',
    params: CircleIdParams,
    query: StatementQuery,
    handler: (ctx) => {
      const { req, params, query, now } = signedIn(ctx);
      const { circle, me } = accessCircle(req, params.id, 'member');
      const { books, statement } = statementFor(app, circle, me, query.member, now);
      const ids = contributionIds(app.db, circle.id);
      return {
        circleId: circle.id,
        name: books.name,
        members: names(books),
        statement: {
          ...statement,
          rounds: statement.rounds.map((r) => ({
            ...r,
            lines: r.lines.map((l) => ({ ...l, contributionId: ids.get(obligationKey(l.roundN, l.memberId)) ?? '' })),
          })),
        },
      };
    },
  });

  route(api, {
    method: 'GET',
    url: '/circles/:id/statement.csv',
    auth: 'user',
    params: CircleIdParams,
    query: StatementQuery,
    handler: (ctx) => {
      const { req, reply, params, query, now } = signedIn(ctx);
      const { circle, me } = accessCircle(req, params.id, 'member');
      const { books, statement } = statementFor(app, circle, me, query.member, now);
      const suffix = query.member ? `-${query.member}` : '';
      return sendCsv(reply, `dawr-statement-${circle.id}${suffix}.csv`, statementCsv(statement, books));
    },
  });

  route(api, {
    method: 'GET',
    url: '/circles/:id/audit',
    auth: 'user',
    params: CircleIdParams,
    query: AuditQuery,
    handler: (ctx) => {
      const { req, params, query } = signedIn(ctx);
      const { circle } = accessCircle(req, params.id, 'organizer');
      const limit = query.limit ?? 50;
      const rows = listAudit(app.db, circle.id, limit + 1, query.before);
      const page = rows.slice(0, limit);
      const byUser = new Map(activeMembers(app.db, circle.id).map((m) => [m.user_id, m.display_name]));
      return {
        entries: page.map((r) => ({
          id: r.id,
          ts: r.ts,
          action: r.action,
          target: r.target,
          actorId: r.actorId,
          actorName: r.actorId ? (byUser.get(r.actorId) ?? null) : null,
          requestId: r.requestId,
          ipPrefix: r.ipPrefix,
          uaHash: r.uaHash,
          details: r.details,
        })),
        nextBefore: rows.length > limit ? (page.at(-1)?.id ?? null) : null,
      };
    },
  });

  route(api, {
    method: 'GET',
    url: '/circles/:id/overview',
    auth: 'user',
    params: CircleIdParams,
    handler: (ctx) => {
      const { req, params, now } = signedIn(ctx);
      const { circle, me } = accessCircle(req, params.id, 'member');
      const books = booksOf(app.db, circle.id);
      const today = isoDateOf(now);
      const who = names(books);
      const current =
        books.rounds.find((r) => r.status === 'open') ??
        books.rounds.find((r) => r.status === 'upcoming') ??
        books.rounds.at(-1) ??
        null;
      const view = current ? roundView(app.db, circle.id, current.n, now, books) : null;
      const ids = contributionIds(app.db, circle.id);
      const arrears = [...books.obligations.values()]
        .map((o) => ({ o, round: books.rounds.find((r) => r.n === o.roundN) }))
        .filter(({ round }) => round && round.status === 'closed')
        .map(({ o, round }) => ({ ...viewObligation(o, round as Books['rounds'][number], today), contributionId: ids.get(obligationKey(o.roundN, o.memberId)) ?? '' }))
        .filter((l) => l.outstanding > 0)
        .map((l) => ({ ...l, displayName: who[l.memberId] ?? '' }));
      const myLine = view?.lines.find((l) => l.memberId === me.id) ?? null;
      return {
        circle: {
          id: circle.id,
          name: circle.name,
          status: circle.status,
          currency: circle.currency,
          minorUnit: circle.minor_unit,
          contribution: circle.contribution,
          memberCount: circle.member_count ?? activeMembers(app.db, circle.id).length,
          rounds: books.rounds.length,
        },
        today,
        round:
          current && view?.round
            ? {
                ...view.round,
                of: books.rounds.length,
                daysUntilDue: daysBetween(today, current.dueDate),
                recipient: { memberId: current.recipientMemberId, displayName: who[current.recipientMemberId] ?? '' },
                members: view.lines,
              }
            : null,
        arrears,
        me: {
          memberId: me.id,
          role: me.role,
          line: myLine,
          canReport: Boolean(current && current.status === 'open' && myLine && myLine.outstanding > 0 && myLine.state !== 'waived' && myLine.reported < myLine.expected),
          isRecipient: current?.recipientMemberId === me.id,
        },
        ledgerHead: ledgerHead(app.db, circle.id),
      };
    },
  });
}
