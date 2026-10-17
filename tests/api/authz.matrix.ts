/**
 * The authorization matrix (docs/SECURITY_REQUIREMENTS.md S3). One row per
 * route; for each role the status a well-formed request from that role
 * must get. Requests target circle A or organizerA's own objects, so the
 * matrix shows who may act on them. tests/api/authz.matrix.test.ts runs
 * every cell against a fresh world and fails if any registered route has
 * no row here.
 */
import { commit } from '../../shared/lottery.js';
import { sha256Hex } from '../../server/crypto.js';
import { PASSWORD } from './helpers.js';
import { drawDeadlines, newSecret, type Role, type World, type WorldState } from './world.js';

export type Method = 'GET' | 'POST' | 'PATCH';

export interface CellRequest {
  url?: string;
  body?: unknown;
}

export interface MatrixRow {
  method: Method;
  /** The Fastify route pattern exactly as registered. */
  route: string;
  state?: WorldState;
  /** A well-formed request for this role (url defaults to the route). */
  build?: (w: World, role: Role) => CellRequest;
  expect: Record<Role, number>;
}

const all = (status: number): Record<Role, number> => ({
  anonymous: status,
  memberA: status,
  organizerA: status,
  memberB: status,
});
const signedIn = (status: number): Record<Role, number> => ({
  anonymous: 401,
  memberA: status,
  organizerA: status,
  memberB: status,
});
/** A circle-A action for the organizer only. */
const organizerOnly = (status: number): Record<Role, number> => ({
  anonymous: 401,
  memberA: 403,
  organizerA: status,
  memberB: 404,
});
/** A circle-A action any member of A may take. */
const membersOf = (status: number): Record<Role, number> => ({
  anonymous: 401,
  memberA: status,
  organizerA: status,
  memberB: 404,
});
const A = (w: World, path = '') => `/api/circles/${w.ids.circleA}${path}`;

let unique = 0;
const loginOf = (w: World, role: Role) => (role === 'anonymous' ? w.people.organizerA.login : w.people[role].login);

export const MATRIX: MatrixRow[] = [
  // ---------------------------------------------------------------- health
  { method: 'GET', route: '/api/health', expect: all(200) },

  // ---------------------------------------------------------------- auth (M1.1)
  { method: 'GET', route: '/api/auth/csrf', expect: all(200) },
  {
    method: 'POST',
    route: '/api/auth/signup',
    build: () => {
      unique += 1;
      return { body: { login: `newcomer${unique}`, displayName: 'Newcomer', password: PASSWORD } };
    },
    expect: all(201),
  },
  {
    method: 'POST',
    route: '/api/auth/login',
    build: (w, role) => ({ body: { login: loginOf(w, role), password: PASSWORD } }),
    expect: all(200),
  },
  { method: 'POST', route: '/api/auth/logout', expect: signedIn(200) },
  { method: 'POST', route: '/api/auth/logout-all', expect: signedIn(200) },
  { method: 'GET', route: '/api/auth/me', expect: signedIn(200) },
  { method: 'PATCH', route: '/api/auth/me', build: () => ({ body: { displayName: 'Renamed' } }), expect: signedIn(200) },
  { method: 'GET', route: '/api/auth/sessions', expect: signedIn(200) },
  {
    // organizerA's own session: only organizerA may revoke it; others do not see it.
    method: 'POST',
    route: '/api/auth/sessions/:id/revoke',
    build: (w) => ({ url: `/api/auth/sessions/${w.people.organizerA.sessionId}/revoke` }),
    expect: { anonymous: 401, memberA: 404, organizerA: 200, memberB: 404 },
  },
  {
    method: 'POST',
    route: '/api/auth/password',
    build: () => ({ body: { currentPassword: PASSWORD, newPassword: 'a fresh passphrase 2026' } }),
    expect: signedIn(200),
  },
  {
    method: 'POST',
    route: '/api/auth/recovery',
    build: (w, role) => {
      const who = role === 'anonymous' ? w.people.organizerA : w.people[role];
      return { body: { login: who.login, recoveryCode: who.recoveryCodes[0], newPassword: 'a recovered passphrase 7' } };
    },
    expect: all(200),
  },
  {
    method: 'POST',
    route: '/api/auth/recovery-codes',
    build: () => ({ body: { password: PASSWORD } }),
    expect: signedIn(200),
  },

  // ---------------------------------------------------------------- circles (M1.2)
  {
    method: 'POST',
    route: '/api/circles',
    build: () => ({ body: { name: 'New circle', currency: 'OMR', contribution: 10000, period: 'monthly', dueDay: 1 } }),
    expect: signedIn(201),
  },
  { method: 'GET', route: '/api/circles', state: 'draft', expect: signedIn(200) },
  { method: 'GET', route: '/api/circles/:id', state: 'draft', build: (w) => ({ url: A(w) }), expect: membersOf(200) },
  {
    method: 'PATCH',
    route: '/api/circles/:id',
    state: 'draft',
    build: (w) => ({ url: A(w), body: { rulesText: 'New rules.' } }),
    expect: organizerOnly(200),
  },
  { method: 'POST', route: '/api/circles/:id/invites', state: 'draft', build: (w) => ({ url: A(w, '/invites') }), expect: organizerOnly(201) },
  { method: 'GET', route: '/api/circles/:id/invites', state: 'draft', build: (w) => ({ url: A(w, '/invites') }), expect: organizerOnly(200) },
  {
    method: 'POST',
    route: '/api/circles/:id/invites/:inviteId/revoke',
    state: 'draft',
    build: (w) => ({ url: A(w, `/invites/${w.ids.inviteA}/revoke`) }),
    expect: organizerOnly(200),
  },
  {
    // Whoever holds the link may preview the circle after signing in.
    method: 'GET',
    route: '/api/invites/:token',
    state: 'draft',
    build: (w) => ({ url: `/api/invites/${w.ids.inviteTokenA}` }),
    expect: signedIn(200),
  },
  {
    method: 'POST',
    route: '/api/invites/:token/accept',
    state: 'draft',
    build: (w) => ({ url: `/api/invites/${w.ids.inviteTokenA}/accept` }),
    expect: { anonymous: 401, memberA: 409, organizerA: 409, memberB: 200 },
  },
  {
    method: 'POST',
    route: '/api/circles/:id/order',
    state: 'draft',
    build: (w) => ({ url: A(w, '/order'), body: { order: [w.ids.memberAInA, w.ids.organizerAInA] } }),
    expect: organizerOnly(200),
  },
  {
    method: 'POST',
    route: '/api/circles/:id/start',
    state: 'ordered',
    build: (w) => ({ url: A(w, '/start') }),
    expect: organizerOnly(200),
  },
  {
    method: 'POST',
    route: '/api/circles/:id/leave',
    state: 'draft',
    build: (w) => ({ url: A(w, '/leave') }),
    expect: { anonymous: 401, memberA: 200, organizerA: 409, memberB: 404 },
  },
  { method: 'POST', route: '/api/circles/:id/cancel', state: 'draft', build: (w) => ({ url: A(w, '/cancel') }), expect: organizerOnly(200) },

  // ---------------------------------------------------------------- draw (M1.3)
  { method: 'GET', route: '/api/circles/:id/draw', state: 'drawing', build: (w) => ({ url: A(w, '/draw') }), expect: membersOf(200) },
  {
    method: 'POST',
    route: '/api/circles/:id/draw/open',
    state: 'ordered',
    build: (w) => ({ url: A(w, '/draw/open'), body: drawDeadlines(w.t.clock.now()) }),
    expect: organizerOnly(200),
  },
  {
    method: 'POST',
    route: '/api/circles/:id/draw/commit',
    state: 'drawing',
    build: (w, role) => {
      const memberId = role === 'memberA' ? w.ids.memberAInA : w.ids.organizerAInA;
      return { url: A(w, '/draw/commit'), body: { commitment: commit(newSecret(), memberId as string, sha256Hex) } };
    },
    expect: membersOf(200),
  },
  {
    method: 'POST',
    route: '/api/circles/:id/draw/close-commits',
    state: 'committed',
    build: (w) => ({ url: A(w, '/draw/close-commits') }),
    expect: organizerOnly(200),
  },
  {
    method: 'POST',
    route: '/api/circles/:id/draw/reveal',
    state: 'revealing',
    build: (w, role) => {
      const memberId = role === 'memberA' ? w.ids.memberAInA : w.ids.organizerAInA;
      return { url: A(w, '/draw/reveal'), body: { secret: w.ids[`secret:${memberId}`] ?? newSecret() } };
    },
    expect: membersOf(200),
  },
  {
    method: 'POST',
    route: '/api/circles/:id/draw/finalize',
    state: 'revealed',
    build: (w) => ({ url: A(w, '/draw/finalize') }),
    expect: organizerOnly(200),
  },

  // ---------------------------------------------------------------- rounds and money (M1.4)
  { method: 'POST', route: '/api/circles/:id/rounds/:n/open', state: 'active', build: (w) => ({ url: A(w, '/rounds/1/open') }), expect: organizerOnly(200) },
  { method: 'POST', route: '/api/circles/:id/rounds/:n/close', state: 'round-open', build: (w) => ({ url: A(w, '/rounds/1/close') }), expect: organizerOnly(200) },
  {
    // Each member reports for themself (the organizer pays too: recipient_pays is on).
    method: 'POST',
    route: '/api/circles/:id/rounds/:n/contributions',
    state: 'round-open',
    build: (w) => ({ url: A(w, '/rounds/1/contributions'), body: { amount: 50_000, method: 'bank transfer', reference: 'TX-1' } }),
    expect: membersOf(201),
  },
  {
    method: 'POST',
    route: '/api/circles/:id/rounds/:n/contributions/:cid/confirm',
    state: 'reported',
    build: (w) => ({ url: A(w, `/rounds/1/contributions/${w.ids.cidA}/confirm`) }),
    expect: organizerOnly(200),
  },
  {
    method: 'POST',
    route: '/api/circles/:id/rounds/:n/contributions/:cid/waive',
    state: 'round-open',
    build: (w) => ({ url: A(w, `/rounds/1/contributions/${w.ids.cidA}/waive`), body: { reason: 'Hardship this month' } }),
    expect: organizerOnly(200),
  },
  {
    method: 'POST',
    route: '/api/circles/:id/rounds/:n/payout',
    state: 'round-open',
    build: (w) => ({ url: A(w, '/rounds/1/payout'), body: { amount: 100_000, method: 'cash' } }),
    expect: organizerOnly(201),
  },
  {
    // Only the recipient of round 1 (organizerA holds position 1) acknowledges.
    method: 'POST',
    route: '/api/circles/:id/rounds/:n/payout/ack',
    state: 'paid-out',
    build: (w) => ({ url: A(w, '/rounds/1/payout/ack') }),
    expect: { anonymous: 401, memberA: 403, organizerA: 200, memberB: 404 },
  },
  { method: 'GET', route: '/api/circles/:id/ledger', state: 'active', build: (w) => ({ url: A(w, '/ledger?verify=1') }), expect: membersOf(200) },
  { method: 'GET', route: '/api/circles/:id/statement', state: 'reported', build: (w) => ({ url: A(w, '/statement') }), expect: membersOf(200) },
  { method: 'GET', route: '/api/circles/:id/statement.csv', state: 'reported', build: (w) => ({ url: A(w, '/statement.csv') }), expect: membersOf(200) },
  { method: 'GET', route: '/api/circles/:id/audit', state: 'active', build: (w) => ({ url: A(w, '/audit') }), expect: organizerOnly(200) },
  { method: 'GET', route: '/api/circles/:id/overview', state: 'round-open', build: (w) => ({ url: A(w, '/overview') }), expect: membersOf(200) },
];
