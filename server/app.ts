import { randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import fastifyStatic from '@fastify/static';
import Fastify, { LogController, type FastifyBaseLogger } from 'fastify';
import type { DestinationStream, Logger } from 'pino';
import { logUserId } from './audit.js';
import type { Config } from './config.js';
import { newToken } from './crypto.js';
import { migrate, openDb, type DB } from './db/db.js';
import { errorBody, mapError } from './errors.js';
import { createLogger } from './logging.js';
import { securityHeaders } from './plugins/security-headers.js';
import { securityHooks } from './plugins/session.js';
import { createLimits, type Limits } from './ratelimit.js';
import { authRoutes } from './routes/auth.js';
import { healthRoutes } from './routes/health.js';
import { systemClock, type Clock, type RouteEntry } from './types.js';

export const BODY_LIMIT_BYTES = 64 * 1024;

export interface AppOptions {
  /** A ready pino logger; when absent one is created from logLevel/logStream. */
  logger?: Logger;
  logLevel?: string;
  logStream?: DestinationStream;
  /** An open, migrated database; when absent an in-memory one is created (tests). */
  db?: DB;
  /** Configuration; missing fields take development/test defaults. */
  config?: Partial<Config>;
  clock?: Clock;
  /** Rate-limit stores; tests pass their own to inspect or reset them. */
  limits?: Limits;
  /** Directory of the built client; false disables static serving. */
  clientDir?: string | false;
}

export function newRequestId(): string {
  return randomBytes(12).toString('base64url');
}

function defaultConfig(partial: Partial<Config>): Config {
  return {
    production: false,
    nodeEnv: 'test',
    dataDir: '',
    dbFile: ':memory:',
    port: 0,
    host: '127.0.0.1',
    sessionSecret: newToken(),
    baseUrl: 'http://127.0.0.1:3000',
    logLevel: 'silent',
    trustProxy: false,
    clientDir: resolve('client/dist'),
    ...partial,
  };
}

export function buildApp(options: AppOptions = {}) {
  const config = defaultConfig(options.config ?? {});
  const logger =
    options.logger ?? createLogger({ level: options.logLevel ?? config.logLevel, stream: options.logStream });
  const headers = securityHeaders(config.production);
  const clock = options.clock ?? systemClock;
  let db = options.db;
  if (!db) {
    db = openDb(':memory:');
    migrate(db);
  }

  const app = Fastify({
    loggerInstance: logger as FastifyBaseLogger,
    logController: new LogController({ disableRequestLogging: true, requestIdLogLabel: 'requestId' }),
    requestIdHeader: false,
    genReqId: newRequestId,
    bodyLimit: BODY_LIMIT_BYTES,
    // One trusted hop: req.ip is the address the reverse proxy saw, so a
    // client cannot choose its own address by sending X-Forwarded-For.
    trustProxy: config.trustProxy ? (_address: string, hop: number) => hop === 0 : false,
    return503OnClosing: true,
  });

  app.decorate('db', db);
  app.decorate('config', config);
  app.decorate('clock', clock);
  app.decorate('limits', options.limits ?? createLimits(clock));
  app.decorateRequest('user', null);

  const routeTable: RouteEntry[] = [];
  app.decorate('routeTable', routeTable);
  app.addHook('onRoute', (r) => {
    for (const method of Array.isArray(r.method) ? r.method : [r.method]) {
      if (method !== 'HEAD') routeTable.push({ method, url: r.url });
    }
  });

  // JSON only (S4.2): drop the default text/plain parser.
  app.removeContentTypeParser('text/plain');

  app.addHook('onRequest', async (req, reply) => {
    reply.header('x-request-id', req.id);
    reply.headers(headers);
  });

  // One structured line per request, with the route pattern instead of the
  // raw URL so ids do not land in the operator log (ADR §7).
  app.addHook('onResponse', async (req, reply) => {
    req.log.info(
      {
        method: req.method,
        route: req.routeOptions.url ?? 'unmatched',
        status: reply.statusCode,
        durationMs: Math.round(reply.elapsedTime),
        userId: req.user ? logUserId(config.sessionSecret, req.user.id) : undefined,
      },
      'request',
    );
  });

  securityHooks(app);

  app.setErrorHandler((err, req, reply) => {
    const mapped = mapError(err);
    if (mapped.internal) {
      req.log.error({ err }, 'unhandled error');
    } else {
      req.log.info({ errorCode: mapped.code, status: mapped.status }, 'client error');
    }
    void reply.status(mapped.status).send(errorBody(mapped.code, mapped.message, req.id, mapped.details));
  });

  app.register(
    async (api) => {
      healthRoutes(api);
      authRoutes(api);
    },
    { prefix: '/api' },
  );

  const clientDir = options.clientDir === false ? false : resolve(options.clientDir ?? config.clientDir);
  const hasClient = clientDir !== false && existsSync(resolve(clientDir, 'index.html'));
  if (hasClient) {
    app.register(fastifyStatic, {
      root: clientDir,
      wildcard: false,
      index: false,
      list: false,
      dotfiles: 'deny',
      cacheControl: false,
      setHeaders(reply, path) {
        void reply.header('cache-control', path.includes('/assets/') ? 'public, max-age=31536000, immutable' : 'no-cache');
      },
    });
  }

  app.setNotFoundHandler((req, reply) => {
    const path = req.url.split('?')[0] ?? '';
    const isApi = path === '/api' || path.startsWith('/api/');
    if (!isApi && hasClient && (req.method === 'GET' || req.method === 'HEAD')) {
      // SPA fallback: every non-API path renders the client, which routes.
      void reply.header('cache-control', 'no-cache').type('text/html; charset=utf-8').sendFile('index.html');
      return;
    }
    void reply.status(404).send(errorBody('not_found', 'Not found.', req.id));
  });

  return app;
}

export type App = ReturnType<typeof buildApp>;
