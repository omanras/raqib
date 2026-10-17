import { mkdtempSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { ConfigError, SECRET_FILE, loadConfig } from '../../server/config.js';

const dir = () => mkdtempSync(join(tmpdir(), 'dawr-cfg-'));
const strong = 's'.repeat(48);

describe('config', () => {
  it('refuses to start in production without SESSION_SECRET', () => {
    expect(() => loadConfig({ NODE_ENV: 'production', DATA_DIR: dir(), TRUST_PROXY: '1', BASE_URL: 'https://d.example' })).toThrow(
      ConfigError,
    );
    expect(() =>
      loadConfig({ NODE_ENV: 'production', DATA_DIR: dir(), TRUST_PROXY: '1', BASE_URL: 'https://d.example', SESSION_SECRET: 'short' }),
    ).toThrow(/at least 32/);
  });

  it('refuses production without HTTPS awareness (TRUST_PROXY=1 and an https BASE_URL)', () => {
    expect(() =>
      loadConfig({ NODE_ENV: 'production', DATA_DIR: dir(), SESSION_SECRET: strong, BASE_URL: 'https://d.example' }),
    ).toThrow(/TRUST_PROXY/);
    expect(() =>
      loadConfig({ NODE_ENV: 'production', DATA_DIR: dir(), SESSION_SECRET: strong, TRUST_PROXY: '1', BASE_URL: 'http://d.example' }),
    ).toThrow(/https/);
  });

  it('starts in production when everything is set', () => {
    const c = loadConfig({
      NODE_ENV: 'production',
      DATA_DIR: dir(),
      SESSION_SECRET: strong,
      TRUST_PROXY: '1',
      BASE_URL: 'https://dawr.example.org/',
      PORT: '8080',
      LOG_LEVEL: 'warn',
    });
    expect(c).toMatchObject({ production: true, port: 8080, baseUrl: 'https://dawr.example.org', logLevel: 'warn', trustProxy: true });
    expect(c.sessionSecret).toBe(strong);
  });

  it('generates a development secret into DATA_DIR once (mode 0600) and reuses it', () => {
    const d = dir();
    const a = loadConfig({ DATA_DIR: d });
    const file = join(d, SECRET_FILE);
    expect(a.sessionSecret.length).toBeGreaterThanOrEqual(32);
    expect(readFileSync(file, 'utf8').trim()).toBe(a.sessionSecret);
    expect(statSync(file).mode & 0o777).toBe(0o600);
    const b = loadConfig({ DATA_DIR: d });
    expect(b.sessionSecret).toBe(a.sessionSecret);
    expect(a.dbFile).toBe(join(d, 'dawr.sqlite'));
    expect(a.production).toBe(false);
  });

  it('validates PORT, LOG_LEVEL and BASE_URL', () => {
    expect(() => loadConfig({ DATA_DIR: dir(), PORT: '0' })).toThrow(ConfigError);
    expect(() => loadConfig({ DATA_DIR: dir(), PORT: 'abc' })).toThrow(ConfigError);
    expect(() => loadConfig({ DATA_DIR: dir(), LOG_LEVEL: 'loud' })).toThrow(ConfigError);
    expect(() => loadConfig({ DATA_DIR: dir(), BASE_URL: 'javascript:alert(1)' })).toThrow(ConfigError);
    expect(() => loadConfig({ DATA_DIR: dir(), BASE_URL: 'https://x.example/path' })).toThrow(ConfigError);
  });
});
