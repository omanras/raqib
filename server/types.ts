import type { Config } from './config.js';
import type { DB } from './db/db.js';

/** The signed-in user attached to a request by the session plugin (M1.1). */
export interface SessionUser {
  id: string;
  login: string;
  displayName: string;
  sessionId: string;
}

export interface Clock {
  now(): Date;
}

export const systemClock: Clock = { now: () => new Date() };

declare module 'fastify' {
  interface FastifyInstance {
    db: DB;
    config: Config;
    clock: Clock;
  }
  interface FastifyRequest {
    user: SessionUser | null;
  }
}
