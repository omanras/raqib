import { Writable } from 'node:stream';
import { describe, expect, it } from 'vitest';
import { buildApp } from '../../server/app.js';
import { REDACTED, createLogger } from '../../server/logging.js';
import { Agent } from './helpers.js';

function capture() {
  const lines: string[] = [];
  const stream = new Writable({
    write(chunk: Buffer, _enc, cb) {
      lines.push(...chunk.toString().split('\n').filter(Boolean));
      cb();
    },
  });
  return { lines, logger: createLogger({ level: 'debug', stream }) };
}

const KNOWN = {
  password: 'correct-horse-battery-staple-42',
  secret: 'f'.repeat(64),
  token: 'invite-token-abcdefghijklmnop',
  cookie: 'dawr_session=session-id-zyxwvutsrqponmlk',
  authorization: 'Bearer bearer-secret-0123456789',
  recoveryCode: 'RCVR-1234-5678',
};

describe('logging.redaction', () => {
  it('redacts cookie, authorization, password, secret, token and recovery code', async () => {
    const { lines, logger } = capture();
    const app = buildApp({ logger, clientDir: false });
    app.post('/api/test-log/:id', async (req) => {
      // A route that (wrongly) logs everything it received: redaction must still hold.
      req.log.info({ headers: req.headers, body: req.body }, 'echo');
      req.log.info({ req: { headers: req.headers } }, 'echo nested');
      req.log.info({ password: KNOWN.password, data: { token: KNOWN.token, nested: { secret: KNOWN.secret } } }, 'flat');
      return { ok: true };
    });
    const agent = new Agent(app);
    const csrf = await agent.refreshCsrf();
    const pre = agent.cookieHeader();
    const res = await app.inject({
      method: 'POST',
      url: '/api/test-log/OBJECTID123',
      headers: { cookie: `${KNOWN.cookie}; ${pre}`, authorization: KNOWN.authorization, 'x-csrf-token': csrf },
      payload: {
        login: 'sara',
        password: KNOWN.password,
        newPassword: KNOWN.password,
        secret: KNOWN.secret,
        token: KNOWN.token,
        recoveryCode: KNOWN.recoveryCode,
      },
    });
    expect(res.statusCode).toBe(200);
    const all = lines.join('\n');
    for (const [name, value] of Object.entries({ ...KNOWN, csrf, pre: pre.split('=')[1] as string })) {
      expect(all, `${name} leaked`).not.toContain(value);
    }
    expect(all).toContain(REDACTED);
    expect(all).toContain('"login":"sara"');
    await app.close();
  });

  it('writes one line per request with requestId, route pattern, status and duration, not the raw URL', async () => {
    const { lines, logger } = capture();
    const app = buildApp({ logger, clientDir: false });
    app.get('/api/test-route/:id', async () => ({ ok: true }));
    const res = await app.inject({ method: 'GET', url: '/api/test-route/OBJECTID123?x=1' });
    const requestId = res.headers['x-request-id'] as string;
    const reqLines = lines.map((l) => JSON.parse(l) as Record<string, unknown>).filter((l) => l.msg === 'request');
    expect(reqLines).toHaveLength(1);
    expect(reqLines[0]).toMatchObject({
      level: 'info',
      requestId,
      method: 'GET',
      route: '/api/test-route/:id',
      status: 200,
    });
    expect(typeof reqLines[0]?.durationMs).toBe('number');
    expect(typeof reqLines[0]?.time).toBe('string');
    expect(lines.join('\n')).not.toContain('OBJECTID123');
    await app.close();
  });

  it('logs a 500 with the error for operators but sends only the error shape', async () => {
    const { lines, logger } = capture();
    const app = buildApp({ logger, clientDir: false });
    app.get('/api/test-crash', async () => {
      throw new Error('database exploded at /secret/path');
    });
    const res = await app.inject({ method: 'GET', url: '/api/test-crash' });
    expect(res.statusCode).toBe(500);
    const body = res.json() as { error: { code: string; message: string; requestId: string } };
    expect(body).toEqual({ error: { code: 'internal', message: 'Internal error.', requestId: res.headers['x-request-id'] } });
    expect(res.body).not.toContain('exploded');
    expect(res.body).not.toContain('at ');
    expect(lines.join('\n')).toContain('database exploded');
    await app.close();
  });

  it('honours the configured level', async () => {
    const { lines, logger } = capture();
    logger.level = 'warn';
    const app = buildApp({ logger, clientDir: false });
    await app.inject({ method: 'GET', url: '/api/health' });
    expect(lines.filter((l) => l.includes('"msg":"request"'))).toHaveLength(0);
    await app.close();
  });
});
