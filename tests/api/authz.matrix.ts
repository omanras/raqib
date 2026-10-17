/**
 * The authorization matrix (docs/SECURITY_REQUIREMENTS.md S3). One row per
 * route; for each role the status a well-formed request from that role
 * must get. Requests target circle A or organizerA's own objects, so the
 * matrix shows who may act on them. tests/api/authz.matrix.test.ts runs
 * every cell against a fresh world and fails if any registered route has
 * no row here.
 */
import { PASSWORD } from './helpers.js';
import type { Role, World, WorldState } from './world.js';

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
];
