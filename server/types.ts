import type { Config } from './config.js';
import type { DB } from './db/db.js';
import type { Limits } from './ratelimit.js';

/** The signed-in user attached to a request by the session plugin. */
export interface SessionUser {
  id: string;
  login: string;
  displayName: string;
  /** Row id of the session (shown in the sessions list). */
  sessionId: string;
  /** SHA-256 of the bearer token; binds the CSRF token. Never sent to clients. */
  sessionTokenHash: string;
}

export interface Clock {
  now(): Date;
}

export const systemClock: Clock = { now: () => new Date() };

export interface RouteEntry {
  method: string;
  url: string;
}

declare module 'fastify' {
  interface FastifyInstance {
    db: DB;
    config: Config;
    clock: Clock;
    limits: Limits;
    /** Every route registered, for the authorization-matrix coverage test. */
    routeTable: RouteEntry[];
  }
  interface FastifyRequest {
    user: SessionUser | null;
    cookies: Map<string, string>;
  }
}
