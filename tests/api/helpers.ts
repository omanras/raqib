import type { LightMyRequestResponse } from 'fastify';
import { buildApp, type AppOptions, type App } from '../../server/app.js';
import { hashPassword } from '../../server/auth/password.js';
import { issueRecoveryCodes } from '../../server/auth/recovery.js';
import { issueSession } from '../../server/auth/sessions.js';
import { migrate, openDb, type DB } from '../../server/db/db.js';
import { insertUser } from '../../server/db/users.js';
import { createLogger } from '../../server/logging.js';
import type { Clock } from '../../server/types.js';

export const PASSWORD = 'a-long-unusual-passphrase-41';

/** A clock tests can move. */
export class TestClock implements Clock {
  t: number;
  constructor(iso = '2026-10-17T09:00:00.000Z') {
    this.t = Date.parse(iso);
  }
  now(): Date {
    return new Date(this.t);
  }
  advance(ms: number): void {
    this.t += ms;
  }
}

export interface TestApp {
  app: App;
  db: DB;
  clock: TestClock;
}

export function testApp(options: Partial<AppOptions> = {}): TestApp {
  const db = options.db ?? openDb(':memory:');
  if (!options.db) migrate(db);
  const clock = (options.clock as TestClock | undefined) ?? new TestClock();
  const app = buildApp({ logger: createLogger({ level: 'silent' }), clientDir: false, db, clock, ...options });
  return { app, db, clock };
}

/** Cookie jar of one simulated browser. */
export class Agent {
  readonly app: App;
  readonly cookies = new Map<string, string>();
  csrf = '';
  ip: string;
  ua = 'Mozilla/5.0 (Dawr tests)';

  constructor(app: App, ip = '198.51.100.10') {
    this.app = app;
    this.ip = ip;
  }

  cookieHeader(): string {
    return [...this.cookies].map(([k, v]) => `${k}=${v}`).join('; ');
  }

  private absorb(res: LightMyRequestResponse): void {
    const set = res.headers['set-cookie'];
    for (const c of set === undefined ? [] : Array.isArray(set) ? set : [set]) {
      const [pair, ...attrs] = String(c).split(';');
      const eq = (pair as string).indexOf('=');
      const name = (pair as string).slice(0, eq).trim();
      const value = (pair as string).slice(eq + 1).trim();
      const expired = attrs.some((a) => a.trim().toLowerCase() === 'max-age=0');
      if (expired || value === '') this.cookies.delete(name);
      else this.cookies.set(name, value);
    }
  }

  async request(
    method: 'GET' | 'POST' | 'PATCH' | 'DELETE' | 'PUT',
    url: string,
    body?: unknown,
    extraHeaders: Record<string, string> = {},
  ): Promise<LightMyRequestResponse> {
    const headers: Record<string, string> = { 'user-agent': this.ua, ...extraHeaders };
    if (this.cookies.size) headers.cookie = this.cookieHeader();
    if (method !== 'GET' && this.csrf && !('x-csrf-token' in extraHeaders)) headers['x-csrf-token'] = this.csrf;
    const res = await this.app.inject({
      method,
      url,
      headers,
      remoteAddress: this.ip,
      ...(body === undefined ? {} : { payload: body as Record<string, unknown> }),
    });
    this.absorb(res);
    if (res.headers['content-type']?.toString().includes('json') && res.body) {
      const token = (res.json() as { csrfToken?: unknown }).csrfToken;
      if (typeof token === 'string') this.csrf = token;
    }
    return res;
  }

  async get(url: string): Promise<LightMyRequestResponse> {
    return this.request('GET', url);
  }

  async post(url: string, body: unknown = {}, headers: Record<string, string> = {}): Promise<LightMyRequestResponse> {
    return this.request('POST', url, body, headers);
  }

  async patch(url: string, body: unknown = {}): Promise<LightMyRequestResponse> {
    return this.request('PATCH', url, body);
  }

  /** Fetches a CSRF token for the current state (session or pre-session). */
  async refreshCsrf(): Promise<string> {
    const res = await this.get('/api/auth/csrf');
    this.csrf = (res.json() as { csrfToken: string }).csrfToken;
    return this.csrf;
  }

  async signup(login: string, displayName = login, password = PASSWORD): Promise<{ recoveryCodes: string[]; userId: string }> {
    if (!this.csrf) await this.refreshCsrf();
    const res = await this.post('/api/auth/signup', { login, displayName, password });
    if (res.statusCode !== 201) throw new Error(`signup ${login}: ${res.statusCode} ${res.body}`);
    const body = res.json() as { recoveryCodes: string[]; user: { id: string } };
    return { recoveryCodes: body.recoveryCodes, userId: body.user.id };
  }

  async login(login: string, password = PASSWORD): Promise<LightMyRequestResponse> {
    if (!this.csrf) await this.refreshCsrf();
    return this.post('/api/auth/login', { login, password });
  }
}

let fastHash: Promise<string> | undefined;

/**
 * Creates a user directly (one scrypt hash shared by all fixture users, so
 * fixtures stay fast) and an Agent signed in with a fresh session.
 */
export interface FixtureUser {
  agent: Agent;
  userId: string;
  login: string;
  sessionId: string;
  recoveryCodes: string[];
}

export async function fixtureUser(t: TestApp, login: string, displayName = login, ip?: string): Promise<FixtureUser> {
  fastHash ??= hashPassword(PASSWORD);
  const user = insertUser(t.db, { login, displayName, passwordHash: await fastHash, now: t.clock.now() });
  const recoveryCodes = issueRecoveryCodes(t.db, user.id, t.clock.now());
  const agent = new Agent(t.app, ip);
  const s = issueSession(t.db, user.id, t.clock.now());
  agent.cookies.set('dawr_session', s.token);
  await agent.refreshCsrf();
  return { agent, userId: user.id, login, sessionId: s.row.id, recoveryCodes };
}

/** A fresh session for an existing user, as a new Agent. */
export async function freshAgent(t: TestApp, userId: string): Promise<Agent> {
  const agent = new Agent(t.app);
  const s = issueSession(t.db, userId, t.clock.now());
  agent.cookies.set('dawr_session', s.token);
  await agent.refreshCsrf();
  return agent;
}

/** An anonymous Agent holding a pre-session CSRF token. */
export async function anonymousAgent(t: TestApp, ip?: string): Promise<Agent> {
  const agent = new Agent(t.app, ip);
  await agent.refreshCsrf();
  return agent;
}
