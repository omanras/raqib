import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { newToken } from './crypto.js';

/** Configuration from the environment (ADR-0001 §8). */
export interface Config {
  production: boolean;
  nodeEnv: string;
  dataDir: string;
  dbFile: string;
  port: number;
  host: string;
  sessionSecret: string;
  baseUrl: string;
  logLevel: string;
  trustProxy: boolean;
  clientDir: string;
}

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConfigError';
  }
}

const LOG_LEVELS = ['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent'];
export const MIN_SECRET_LENGTH = 32;
export const SECRET_FILE = 'session-secret';

type Env = Record<string, string | undefined>;

/**
 * Reads and checks the environment. In production the server refuses to
 * start without SESSION_SECRET (>= 32 characters), without TRUST_PROXY=1
 * (TLS is terminated by the reverse proxy, so the app must be told it is
 * behind one) and without an https BASE_URL. In development a secret is
 * generated once into DATA_DIR/session-secret (mode 0600) and reused.
 */
export function loadConfig(env: Env = process.env): Config {
  const nodeEnv = env.NODE_ENV ?? 'development';
  const production = nodeEnv === 'production';
  const dataDir = resolve(env.DATA_DIR ?? './data');
  const port = Number(env.PORT ?? 3000);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new ConfigError(`PORT must be 1-65535, not ${env.PORT}`);
  const host = env.HOST ?? '127.0.0.1';
  const logLevel = env.LOG_LEVEL ?? 'info';
  if (!LOG_LEVELS.includes(logLevel)) throw new ConfigError(`LOG_LEVEL must be one of ${LOG_LEVELS.join(', ')}`);
  const trustProxy = env.TRUST_PROXY === '1';
  const baseUrl = (env.BASE_URL ?? `http://127.0.0.1:${port}`).replace(/\/+$/, '');
  if (!/^https?:\/\/[^/\s]+$/.test(baseUrl)) throw new ConfigError('BASE_URL must be an origin like https://dawr.example.org');

  mkdirSync(dataDir, { recursive: true, mode: 0o700 });

  let sessionSecret = env.SESSION_SECRET ?? '';
  if (production) {
    if (sessionSecret.length < MIN_SECRET_LENGTH) {
      throw new ConfigError(`SESSION_SECRET is required in production (at least ${MIN_SECRET_LENGTH} characters)`);
    }
    if (!trustProxy) {
      throw new ConfigError('TRUST_PROXY=1 is required in production: run Dawr behind a TLS-terminating reverse proxy');
    }
    if (!baseUrl.startsWith('https://')) throw new ConfigError('BASE_URL must use https in production');
  } else if (sessionSecret === '') {
    sessionSecret = developmentSecret(dataDir);
  } else if (sessionSecret.length < MIN_SECRET_LENGTH) {
    throw new ConfigError(`SESSION_SECRET must be at least ${MIN_SECRET_LENGTH} characters`);
  }

  return {
    production,
    nodeEnv,
    dataDir,
    dbFile: join(dataDir, 'dawr.sqlite'),
    port,
    host,
    sessionSecret,
    baseUrl,
    logLevel,
    trustProxy,
    clientDir: resolve(env.CLIENT_DIR ?? 'client/dist'),
  };
}

function developmentSecret(dataDir: string): string {
  const file = join(dataDir, SECRET_FILE);
  if (existsSync(file)) {
    const s = readFileSync(file, 'utf8').trim();
    if (s.length >= MIN_SECRET_LENGTH) return s;
  }
  const s = newToken();
  writeFileSync(file, `${s}\n`, { mode: 0o600 });
  chmodSync(file, 0o600);
  return s;
}
