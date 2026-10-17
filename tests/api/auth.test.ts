import { describe, expect, it } from 'vitest';
import { tokenHash } from '../../server/auth/sessions.js';
import { Agent, PASSWORD, TestClock, anonymousAgent, fixtureUser, testApp } from './helpers.js';

const DAY = 24 * 60 * 60 * 1000;
type ErrorBody = { error: { code: string; message: string; requestId: string; details?: Record<string, unknown> } };
const err = (res: { json(): unknown }) => (res.json() as ErrorBody).error;

describe('signup', () => {
  it('creates the account, signs in, returns 8 recovery codes once and a CSRF token', async () => {
    const t = testApp();
    const a = await anonymousAgent(t);
    const res = await a.post('/api/auth/signup', { login: 'Sara.H', displayName: '  سارة  ', password: PASSWORD });
    expect(res.statusCode).toBe(201);
    const body = res.json() as { user: { login: string; displayName: string }; recoveryCodes: string[]; csrfToken: string };
    expect(body.user).toMatchObject({ login: 'sara.h', displayName: 'سارة' });
    expect(body.recoveryCodes).toHaveLength(8);
    expect(new Set(body.recoveryCodes).size).toBe(8);
    const me = await a.get('/api/auth/me');
    expect(me.statusCode).toBe(200);
    expect(me.json()).toMatchObject({ user: { login: 'sara.h' }, recoveryCodesRemaining: 8 });
    expect(JSON.stringify(me.json())).not.toContain(body.recoveryCodes[0]);
    const stored = t.db.prepare('SELECT code_hash FROM recovery_codes').all() as { code_hash: string }[];
    expect(stored.every((r) => !body.recoveryCodes.some((c) => r.code_hash.includes(c.replace(/-/g, ''))))).toBe(true);
    const rows = t.db.prepare("SELECT action FROM audit WHERE action = 'auth.signup'").all();
    expect(rows).toHaveLength(1);
  });

  it('refuses a taken login (case-insensitive), a bad login, weak passwords and unsafe names', async () => {
    const t = testApp();
    const a = await anonymousAgent(t);
    expect((await a.post('/api/auth/signup', { login: 'omar', displayName: 'Omar', password: PASSWORD })).statusCode).toBe(201);
    const b = await anonymousAgent(t, '198.51.100.11');
    const taken = await b.post('/api/auth/signup', { login: 'OMAR', displayName: 'Other', password: PASSWORD });
    expect(taken.statusCode).toBe(409);
    expect(err(taken).code).toBe('login_taken');
    const bad = await b.post('/api/auth/signup', { login: 'a b', displayName: 'x', password: PASSWORD });
    expect(err(bad).code).toBe('invalid_login');
    const common = await b.post('/api/auth/signup', { login: 'newuser', displayName: 'x', password: '1234567890' });
    expect(common.statusCode).toBe(400);
    expect(err(common)).toMatchObject({ code: 'weak_password', details: { problem: 'common' } });
    const short = await b.post('/api/auth/signup', { login: 'newuser', displayName: 'x', password: 'short' });
    expect(err(short)).toMatchObject({ code: 'weak_password', details: { problem: 'too_short' } });
    const bidi = await b.post('/api/auth/signup', { login: 'newuser', displayName: 'evil‮txt.exe', password: PASSWORD });
    expect(err(bidi).code).toBe('invalid_input');
    const blank = await b.post('/api/auth/signup', { login: 'newuser', displayName: '   ', password: PASSWORD });
    expect(err(blank).code).toBe('invalid_input');
  });
});

describe('S1.3 auth.enumeration', () => {
  it('answers an unknown login and a wrong password identically, in the same timing class', async () => {
    const t = testApp();
    const known = await fixtureUser(t, 'known.user');
    const a = await anonymousAgent(t);
    await a.login('known.user', 'wrong password 123');
    const timings = { unknown: [] as number[], wrong: [] as number[] };
    let unknownRes;
    let wrongRes;
    for (let i = 0; i < 3; i += 1) {
      let t0 = performance.now();
      unknownRes = await a.login('nobody.here', 'wrong password 123');
      timings.unknown.push(performance.now() - t0);
      t0 = performance.now();
      wrongRes = await a.login('known.user', 'wrong password 123');
      timings.wrong.push(performance.now() - t0);
    }
    expect(unknownRes?.statusCode).toBe(401);
    expect(wrongRes?.statusCode).toBe(401);
    const u = err(unknownRes as never);
    const w = err(wrongRes as never);
    expect({ code: u.code, message: u.message }).toEqual({ code: w.code, message: w.message });
    const median = (xs: number[]) => [...xs].sort((x, y) => x - y)[1] as number;
    expect(median(timings.unknown)).toBeGreaterThan(median(timings.wrong) * 0.4);
    expect(median(timings.wrong)).toBeGreaterThan(median(timings.unknown) * 0.4);
    expect(known.userId).toBeTruthy();
  });
});

describe('login and sessions', () => {
  it('S2.1 session.*: logs in with a fresh 256-bit session stored only as a hash, rotated on login', async () => {
    const t = testApp();
    await fixtureUser(t, 'layla');
    const a = await anonymousAgent(t);
    const first = await a.login('layla');
    expect(first.statusCode).toBe(200);
    const token1 = a.cookies.get('dawr_session') as string;
    expect(token1).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const rows = t.db.prepare('SELECT token_hash FROM sessions').all() as { token_hash: string }[];
    expect(rows.some((r) => r.token_hash === tokenHash(token1))).toBe(true);
    expect(JSON.stringify(t.db.prepare('SELECT * FROM sessions').all())).not.toContain(token1);
    const second = await a.login('layla');
    expect(second.statusCode).toBe(200);
    const token2 = a.cookies.get('dawr_session') as string;
    expect(token2).not.toBe(token1);
    const replay = new Agent(t.app);
    replay.cookies.set('dawr_session', token1);
    expect((await replay.get('/api/auth/me')).statusCode).toBe(401);
    expect((await a.get('/api/auth/me')).statusCode).toBe(200);
  });

  it('S2.1 session.idle-expiry after 30 days and session.absolute-expiry after 90 days', async () => {
    const t = testApp();
    const u = await fixtureUser(t, 'idle.user');
    t.clock.advance(29 * DAY);
    expect((await u.agent.get('/api/auth/me')).statusCode).toBe(200);
    t.clock.advance(29 * DAY);
    expect((await u.agent.get('/api/auth/me')).statusCode).toBe(200);
    t.clock.advance(31 * DAY);
    expect((await u.agent.get('/api/auth/me')).statusCode).toBe(401);

    const v = await fixtureUser(t, 'busy.user');
    for (let d = 0; d < 89; d += 10) {
      expect((await v.agent.get('/api/auth/me')).statusCode).toBe(200);
      t.clock.advance(10 * DAY);
    }
    expect((await v.agent.get('/api/auth/me')).statusCode).toBe(401);
  });

  it('S2.2 session.cookie: HttpOnly, SameSite=Lax, Path=/, no Domain; Secure and __Host- in production', async () => {
    const dev = testApp();
    await fixtureUser(dev, 'cookie.dev');
    const a = await anonymousAgent(dev);
    const res = await a.login('cookie.dev');
    const cookie = [res.headers['set-cookie']].flat().find((c) => String(c).startsWith('dawr_session=')) as string;
    expect(cookie).toContain('HttpOnly');
    expect(cookie).toContain('SameSite=Lax');
    expect(cookie).toContain('Path=/');
    expect(cookie).not.toMatch(/Domain=/i);
    expect(cookie).not.toContain('Secure');

    const prod = testApp({ config: { production: true } });
    await fixtureUser(prod, 'cookie.prod');
    const p = new Agent(prod.app);
    const csrf = await p.get('/api/auth/csrf');
    const pre = [csrf.headers['set-cookie']].flat().find((c) => String(c).startsWith('__Host-dawr_pre=')) as string;
    expect(pre).toContain('Secure');
    expect(pre).toContain('SameSite=Strict');
    p.csrf = (csrf.json() as { csrfToken: string }).csrfToken;
    const login = await p.post('/api/auth/login', { login: 'cookie.prod', password: PASSWORD });
    expect(login.statusCode).toBe(200);
    const sc = [login.headers['set-cookie']].flat().find((c) => String(c).startsWith('__Host-dawr_session=')) as string;
    expect(sc).toContain('Secure');
    expect(sc).toContain('HttpOnly');
    expect(sc).toContain('SameSite=Lax');
    expect(sc).toContain('Path=/');
    expect(sc).not.toMatch(/Domain=/i);
    expect(login.headers['strict-transport-security']).toBeDefined();
  });

  it('S1.6 auth.logout revokes the server-side session; a copied cookie is refused afterwards', async () => {
    const t = testApp();
    const u = await fixtureUser(t, 'logout.user');
    const stolen = u.agent.cookies.get('dawr_session') as string;
    const res = await u.agent.post('/api/auth/logout');
    expect(res.statusCode).toBe(200);
    expect(u.agent.cookies.has('dawr_session')).toBe(false);
    const thief = new Agent(t.app);
    thief.cookies.set('dawr_session', stolen);
    expect((await thief.get('/api/auth/me')).statusCode).toBe(401);
    const row = t.db.prepare('SELECT revoked_reason FROM sessions WHERE id = ?').get(u.sessionId) as { revoked_reason: string };
    expect(row.revoked_reason).toBe('logout');
  });

  it('S1.6 auth.logout-all signs out everywhere', async () => {
    const t = testApp();
    const u = await fixtureUser(t, 'many.devices');
    const phone = await anonymousAgent(t, '198.51.100.20');
    await phone.login('many.devices');
    const laptop = await anonymousAgent(t, '198.51.100.21');
    await laptop.login('many.devices');
    const list = await u.agent.get('/api/auth/sessions');
    const sessions = (list.json() as { sessions: { id: string; current: boolean }[] }).sessions;
    expect(sessions).toHaveLength(3);
    expect(sessions.filter((s) => s.current)).toHaveLength(1);
    const res = await phone.post('/api/auth/logout-all');
    expect(res.json()).toMatchObject({ ok: true, revoked: 3 });
    for (const a of [u.agent, phone, laptop]) expect((await a.get('/api/auth/me')).statusCode).toBe(401);
  });

  it('revokes one of my sessions, and not someone else s (404)', async () => {
    const t = testApp();
    const u = await fixtureUser(t, 'owner.one');
    const other = await fixtureUser(t, 'owner.two');
    const second = await anonymousAgent(t, '198.51.100.30');
    await second.login('owner.one');
    const sessions = ((await u.agent.get('/api/auth/sessions')).json() as { sessions: { id: string; current: boolean }[] })
      .sessions;
    const notCurrent = sessions.find((s) => !s.current) as { id: string };
    expect((await other.agent.post(`/api/auth/sessions/${notCurrent.id}/revoke`)).statusCode).toBe(404);
    expect((await u.agent.post(`/api/auth/sessions/${notCurrent.id}/revoke`)).statusCode).toBe(200);
    expect((await second.get('/api/auth/me')).statusCode).toBe(401);
    expect((await u.agent.get('/api/auth/me')).statusCode).toBe(200);
  });

  it('S2.1 changing the password revokes all sessions and rotates the current one', async () => {
    const t = testApp();
    const u = await fixtureUser(t, 'changer');
    const other = await anonymousAgent(t, '198.51.100.40');
    await other.login('changer');
    const before = u.agent.cookies.get('dawr_session');
    const wrong = await u.agent.post('/api/auth/password', { currentPassword: 'not it at all', newPassword: 'brand new passphrase 77' });
    expect(wrong.statusCode).toBe(403);
    const weak = await u.agent.post('/api/auth/password', { currentPassword: PASSWORD, newPassword: 'qwertyuiop' });
    expect(err(weak).code).toBe('weak_password');
    const ok = await u.agent.post('/api/auth/password', { currentPassword: PASSWORD, newPassword: 'brand new passphrase 77' });
    expect(ok.statusCode).toBe(200);
    expect(u.agent.cookies.get('dawr_session')).not.toBe(before);
    expect((await u.agent.get('/api/auth/me')).statusCode).toBe(200);
    expect((await other.get('/api/auth/me')).statusCode).toBe(401);
    const fresh = await anonymousAgent(t, '198.51.100.41');
    expect((await fresh.login('changer')).statusCode).toBe(401);
    expect((await fresh.login('changer', 'brand new passphrase 77')).statusCode).toBe(200);
  });

  it('updates the display name (PATCH /api/auth/me)', async () => {
    const t = testApp();
    const u = await fixtureUser(t, 'renamer');
    const res = await u.agent.patch('/api/auth/me', { displayName: 'New Name' });
    expect(res.json()).toMatchObject({ user: { displayName: 'New Name' } });
  });
});

describe('S1.5 auth.recovery', () => {
  it('a recovery code sets a new password, revokes every session, and works once', async () => {
    const t = testApp();
    const a = await anonymousAgent(t);
    const { recoveryCodes } = await a.signup('forgetful', 'Forgetful');
    const b = await anonymousAgent(t, '198.51.100.50');
    const code = (recoveryCodes[3] as string).toLowerCase();
    const res = await b.post('/api/auth/recovery', { login: 'forgetful', recoveryCode: code, newPassword: 'recovered passphrase 9' });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({ user: { login: 'forgetful' }, recoveryCodesRemaining: 7 });
    expect((await a.get('/api/auth/me')).statusCode).toBe(401);
    expect((await b.get('/api/auth/me')).statusCode).toBe(200);
    const again = await anonymousAgent(t, '198.51.100.51');
    const reuse = await again.post('/api/auth/recovery', { login: 'forgetful', recoveryCode: code, newPassword: 'another passphrase 10' });
    expect(reuse.statusCode).toBe(401);
    expect(err(reuse).code).toBe('invalid_recovery');
    expect((await again.login('forgetful', 'recovered passphrase 9')).statusCode).toBe(200);
  });

  it('refuses a wrong code and an unknown login with the same answer', async () => {
    const t = testApp();
    await fixtureUser(t, 'rec.user');
    const a = await anonymousAgent(t);
    const wrong = await a.post('/api/auth/recovery', { login: 'rec.user', recoveryCode: 'AAAA-BBBB-CCCC-DDDD', newPassword: 'whatever passphrase 1' });
    const unknown = await a.post('/api/auth/recovery', { login: 'no.user', recoveryCode: 'AAAA-BBBB-CCCC-DDDD', newPassword: 'whatever passphrase 1' });
    expect(wrong.statusCode).toBe(401);
    expect(unknown.statusCode).toBe(401);
    expect(err(wrong).message).toBe(err(unknown).message);
  });

  it('regenerating codes needs the password and invalidates the old set', async () => {
    const t = testApp();
    const u = await fixtureUser(t, 'regen');
    expect((await u.agent.post('/api/auth/recovery-codes', { password: 'not the password' })).statusCode).toBe(403);
    const res = await u.agent.post('/api/auth/recovery-codes', { password: PASSWORD });
    const codes = (res.json() as { recoveryCodes: string[] }).recoveryCodes;
    expect(codes).toHaveLength(8);
    const a = await anonymousAgent(t, '198.51.100.60');
    const old = await a.post('/api/auth/recovery', { login: 'regen', recoveryCode: u.recoveryCodes[0], newPassword: 'whatever passphrase 2' });
    expect(old.statusCode).toBe(401);
    const fresh = await a.post('/api/auth/recovery', { login: 'regen', recoveryCode: codes[0], newPassword: 'whatever passphrase 2' });
    expect(fresh.statusCode).toBe(200);
  });
});

describe('S1.4 auth.lockout and auth.ratelimit', () => {
  it('auth.lockout: 10 failures per login in 15 minutes -> 423 with retry time, even for the right password', async () => {
    const t = testApp();
    await fixtureUser(t, 'target');
    const a = await anonymousAgent(t, '203.0.113.1');
    for (let i = 0; i < 10; i += 1) expect((await a.login('target', `wrong guess ${i}xx`)).statusCode).toBe(401);
    const locked = await a.login('target');
    expect(locked.statusCode).toBe(423);
    expect(err(locked).code).toBe('locked');
    const retry = Number(locked.headers['retry-after']);
    expect(retry).toBeGreaterThan(0);
    expect(retry).toBeLessThanOrEqual(15 * 60);
    expect(err(locked).details).toMatchObject({ retryAfterSeconds: retry });
    t.clock.advance(15 * 60 * 1000 + 1000);
    expect((await a.login('target')).statusCode).toBe(200);
  });

  it('auth.lockout treats an unknown login the same way (no enumeration through 423)', async () => {
    const t = testApp();
    const a = await anonymousAgent(t, '203.0.113.2');
    for (let i = 0; i < 10; i += 1) expect((await a.login('ghost.user', `wrong guess ${i}xx`)).statusCode).toBe(401);
    expect((await a.login('ghost.user', 'wrong guess 99')).statusCode).toBe(423);
  });

  it('auth.ratelimit: the 31st POST /api/auth/* from one IP in 15 minutes is 429; other IPs are unaffected', async () => {
    const clock = new TestClock();
    const t = testApp({ clock });
    const a = await anonymousAgent(t, '203.0.113.3');
    for (let i = 0; i < 30; i += 1) {
      const r = await a.post('/api/auth/login', { login: `user${i}`, password: 'wrong guess xyz' });
      expect(r.statusCode, `request ${i + 1}`).toBe(401);
    }
    const limited = await a.post('/api/auth/login', { login: 'user31', password: 'wrong guess xyz' });
    expect(limited.statusCode).toBe(429);
    expect(err(limited).code).toBe('rate_limited');
    expect(Number(limited.headers['retry-after'])).toBeGreaterThan(0);
    const b = await anonymousAgent(t, '203.0.113.4');
    expect((await b.post('/api/auth/login', { login: 'x', password: 'y' })).statusCode).toBe(401);
    clock.advance(15 * 60 * 1000 + 1);
    expect((await a.post('/api/auth/login', { login: 'x', password: 'y' })).statusCode).toBe(401);
  });

  it('auth.ratelimit does not count GET /api/auth/me or /csrf', async () => {
    const t = testApp();
    const u = await fixtureUser(t, 'reader', 'Reader', '203.0.113.5');
    for (let i = 0; i < 40; i += 1) expect((await u.agent.get('/api/auth/me')).statusCode).toBe(200);
    expect((await u.agent.post('/api/auth/logout')).statusCode).toBe(200);
  });
});

describe('S2.3 csrf.*', () => {
  it('csrf.required: a mutating request without the header is 403, with a wrong one 403, GET needs none', async () => {
    const t = testApp();
    const u = await fixtureUser(t, 'csrf.user');
    const none = await u.agent.post('/api/auth/logout', {}, { 'x-csrf-token': '' });
    expect(none.statusCode).toBe(403);
    expect(err(none).code).toBe('csrf');
    const wrong = await u.agent.post('/api/auth/logout', {}, { 'x-csrf-token': 'f'.repeat(64) });
    expect(wrong.statusCode).toBe(403);
    expect((await u.agent.get('/api/auth/me')).statusCode).toBe(200);
    expect((await u.agent.post('/api/auth/logout')).statusCode).toBe(200);
  });

  it('csrf.bound: a token from another session does not work, nor the pre-session one after sign-in', async () => {
    const t = testApp();
    const one = await fixtureUser(t, 'csrf.one');
    const two = await fixtureUser(t, 'csrf.two');
    const stolen = await one.agent.post('/api/auth/logout', {}, { 'x-csrf-token': two.agent.csrf });
    expect(stolen.statusCode).toBe(403);
    const a = await anonymousAgent(t);
    const preToken = a.csrf;
    expect((await a.login('csrf.one')).statusCode).toBe(200);
    expect(a.csrf).not.toBe(preToken);
    expect((await a.post('/api/auth/logout', {}, { 'x-csrf-token': preToken })).statusCode).toBe(403);
    expect((await a.post('/api/auth/logout')).statusCode).toBe(200);
  });

  it('csrf.anonymous: sign-in without any CSRF token is 403', async () => {
    const t = testApp();
    await fixtureUser(t, 'csrf.anon');
    const a = new Agent(t.app);
    expect((await a.post('/api/auth/login', { login: 'csrf.anon', password: PASSWORD })).statusCode).toBe(403);
  });
});

describe('S4 input.* and S8 errors.*', () => {
  it('S4.1 input.strict: unknown keys, wrong types and over-long strings are 400 invalid_input naming the field', async () => {
    const t = testApp();
    const a = await anonymousAgent(t);
    const extra = await a.post('/api/auth/login', { login: 'x', password: 'y', admin: true });
    expect(extra.statusCode).toBe(400);
    expect(err(extra)).toMatchObject({ code: 'invalid_input', details: { where: 'body' } });
    expect(JSON.stringify(err(extra).details)).toContain('admin');
    const typed = await a.post('/api/auth/login', { login: 5, password: 'y' });
    expect(err(typed).code).toBe('invalid_input');
    const long = await a.post('/api/auth/login', { login: 'x'.repeat(65), password: 'y' });
    expect(err(long).code).toBe('invalid_input');
    const query = await a.get('/api/auth/csrf?debug=1');
    expect(query.statusCode).toBe(400);
    expect(err(query)).toMatchObject({ code: 'invalid_input', details: { where: 'query' } });
    const body = await a.post('/api/auth/login', { login: 'x', password: 'y'.repeat(2000) });
    expect(err(body).code).toBe('invalid_input');
    expect(body.body).not.toContain('y'.repeat(50));
  });

  it('S4.2 input.limit: bodies over 64 KB are 413; non-JSON is 415', async () => {
    const t = testApp();
    const a = await anonymousAgent(t);
    const big = await a.post('/api/auth/login', { login: 'x', password: 'p', pad: 'z'.repeat(70 * 1024) });
    expect(big.statusCode).toBe(413);
    expect(err(big).code).toBe('body_too_large');
    const text = await a.request('POST', '/api/auth/login', 'login=x', { 'content-type': 'application/x-www-form-urlencoded' });
    expect(text.statusCode).toBe(415);
    const broken = await t.app.inject({
      method: 'POST',
      url: '/api/auth/login',
      headers: { 'content-type': 'application/json', cookie: a.cookieHeader(), 'x-csrf-token': a.csrf },
      payload: '{"login": ',
      remoteAddress: a.ip,
    });
    expect(broken.statusCode).toBe(400);
    expect(err(broken).code).toBe('invalid_json');
  });

  it('S8.1 errors.shape: {error: {code, message, requestId}}, never a stack trace', async () => {
    const t = testApp();
    const a = await anonymousAgent(t);
    for (const res of [
      await a.get('/api/auth/me'),
      await a.post('/api/auth/login', { nope: 1 }),
      await a.get('/api/does-not-exist'),
      await a.post('/api/auth/logout', {}, { 'x-csrf-token': 'bad' }),
    ]) {
      const e = err(res);
      expect(typeof e.code).toBe('string');
      expect(typeof e.message).toBe('string');
      expect(e.requestId).toBe(res.headers['x-request-id']);
      expect(res.body).not.toMatch(/\bat \S+:\d+:\d+/);
      expect(res.body).not.toContain('node_modules');
    }
  });
});
