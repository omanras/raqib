import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { buildApp } from '../../server/app.js';
import { listMigrations, migrate, openDb } from '../../server/db/db.js';
import { createLogger } from '../../server/logging.js';
import { CONTENT_SECURITY_POLICY } from '../../server/plugins/security-headers.js';
import { appVersion } from '../../server/version.js';

const silent = createLogger({ level: 'silent' });

function fakeClient(): string {
  const dir = mkdtempSync(join(tmpdir(), 'dawr-client-'));
  mkdirSync(join(dir, 'assets'));
  writeFileSync(join(dir, 'index.html'), '<!doctype html><title>Dawr</title><div id="app"></div>');
  writeFileSync(join(dir, 'assets', 'app-abc123.js'), 'console.log(1)');
  return dir;
}

describe('GET /api/health', () => {
  const app = buildApp({ logger: silent, clientDir: false });
  afterAll(() => app.close());

  it('answers ok with the version, db state and applied migration count', async () => {
    const res = await app.inject({ method: 'GET', url: '/api/health' });
    expect(res.statusCode).toBe(200);
    const body = res.json() as { ok: boolean; version: string; db: string; migrations: number };
    expect(body).toEqual({ ok: true, version: appVersion(), db: 'ok', migrations: listMigrations().length });
    expect(body.migrations).toBeGreaterThanOrEqual(1);
  });

  it('answers 503 when the database is unusable', async () => {
    const db = openDb(':memory:');
    migrate(db);
    const broken = buildApp({ logger: silent, clientDir: false, db });
    await broken.ready();
    db.close();
    const res = await broken.inject({ method: 'GET', url: '/api/health' });
    expect(res.statusCode).toBe(503);
    expect(res.json()).toMatchObject({ ok: false, db: 'error' });
    await broken.close();
  });

  it('S5.1 headers.csp and S5.2 headers.nosniff/referrer/permissions on /api/health', async () => {
    const res = await app.inject({ method: 'GET', url: '/api/health' });
    expect(res.headers['content-security-policy']).toBe(CONTENT_SECURITY_POLICY);
    expect(CONTENT_SECURITY_POLICY).toContain("default-src 'self'");
    expect(CONTENT_SECURITY_POLICY).toContain("frame-ancestors 'none'");
    expect(CONTENT_SECURITY_POLICY).not.toContain('unsafe-inline');
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['referrer-policy']).toBe('no-referrer');
    expect(res.headers['permissions-policy']).toContain('camera=()');
    expect(res.headers['permissions-policy']).toContain('microphone=()');
    expect(res.headers['permissions-policy']).toContain('geolocation=()');
    expect(res.headers['strict-transport-security']).toBeUndefined();
  });

  it('carries a fresh x-request-id on every response and ignores a client-sent one', async () => {
    const a = await app.inject({ method: 'GET', url: '/api/health', headers: { 'x-request-id': 'forged' } });
    const b = await app.inject({ method: 'GET', url: '/api/health' });
    expect(a.headers['x-request-id']).toMatch(/^[A-Za-z0-9_-]{16}$/);
    expect(b.headers['x-request-id']).toMatch(/^[A-Za-z0-9_-]{16}$/);
    expect(a.headers['x-request-id']).not.toBe('forged');
    expect(a.headers['x-request-id']).not.toBe(b.headers['x-request-id']);
  });

  it('answers unknown API paths with the error shape and the same headers', async () => {
    const res = await app.inject({ method: 'GET', url: '/api/nope' });
    expect(res.statusCode).toBe(404);
    const body = res.json() as { error: { code: string; message: string; requestId: string } };
    expect(body.error.code).toBe('not_found');
    expect(body.error.requestId).toBe(res.headers['x-request-id']);
    expect(res.headers['content-security-policy']).toBe(CONTENT_SECURITY_POLICY);
  });
});

describe('production headers', () => {
  it('S5.2 headers.hsts: Strict-Transport-Security in production', async () => {
    const app = buildApp({ logger: silent, clientDir: false, config: { production: true } });
    const res = await app.inject({ method: 'GET', url: '/api/health' });
    expect(res.headers['strict-transport-security']).toContain('max-age=');
    await app.close();
  });
});

describe('static client and SPA fallback', () => {
  const dir = fakeClient();
  const app = buildApp({ logger: silent, clientDir: dir });
  afterAll(() => app.close());

  it('S5.1 headers.csp on the client: index.html for client routes (SPA fallback), never for /api', async () => {
    for (const url of ['/', '/join/abc', '/circles/x/ledger']) {
      const res = await app.inject({ method: 'GET', url });
      expect(res.statusCode, url).toBe(200);
      expect(res.headers['content-type']).toContain('text/html');
      expect(res.body).toContain('<div id="app">');
      expect(res.headers['content-security-policy']).toBe(CONTENT_SECURITY_POLICY);
    }
    const api = await app.inject({ method: 'GET', url: '/api/unknown' });
    expect(api.statusCode).toBe(404);
    expect(api.headers['content-type']).toContain('application/json');
  });

  it('serves hashed assets as immutable and refuses traversal', async () => {
    const asset = await app.inject({ method: 'GET', url: '/assets/app-abc123.js' });
    expect(asset.statusCode).toBe(200);
    expect(asset.headers['cache-control']).toContain('immutable');
    const trav = await app.inject({ method: 'GET', url: '/assets/..%2f..%2fpackage.json' });
    expect(trav.body).not.toContain('"dependencies"');
  });

  it('does not render the client for non-GET methods', async () => {
    const res = await app.inject({ method: 'POST', url: '/somewhere', payload: {} });
    expect(res.statusCode).toBe(404);
  });
});

describe('input limits', () => {
  const app = buildApp({ logger: silent, clientDir: false });
  afterAll(() => app.close());

  it('S4.2 input.json-only: non-JSON bodies are 415 with the error shape', async () => {
    app.post('/api/echo-test', async (req) => req.body);
    const res = await app.inject({
      method: 'POST',
      url: '/api/echo-test',
      headers: { 'content-type': 'text/plain' },
      payload: 'hello',
    });
    expect(res.statusCode).toBe(415);
    expect((res.json() as { error: { code: string } }).error.code).toBe('unsupported_media_type');
  });
});
