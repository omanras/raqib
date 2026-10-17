import { randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import fastifyStatic from '@fastify/static';
import Fastify, { LogController } from 'fastify';
import type { DestinationStream, Logger } from 'pino';
import { errorBody, mapError } from './errors.js';
import { createLogger } from './logging.js';
import { securityHeaders } from './plugins/security-headers.js';
import { healthRoutes } from './routes/health.js';

export const BODY_LIMIT_BYTES = 64 * 1024;

export interface AppOptions {
  /** A ready pino logger; when absent one is created from logLevel/logStream. */
  logger?: Logger;
  logLevel?: string;
  logStream?: DestinationStream;
  /** Directory of the built client; false disables static serving. */
  clientDir?: string | false;
  /** Production mode: HSTS on, secure cookies (later), strict config. */
  production?: boolean;
  /** Trust X-Forwarded-* from one reverse proxy (TRUST_PROXY=1). */
  trustProxy?: boolean;
}

export function newRequestId(): string {
  return randomBytes(12).toString('base64url');
}

export function buildApp(options: AppOptions = {}) {
  const logger = options.logger ?? createLogger({ level: options.logLevel, stream: options.logStream });
  const production = options.production ?? false;
  const headers = securityHeaders(production);

  const app = Fastify({
    loggerInstance: logger,
    logController: new LogController({ disableRequestLogging: true, requestIdLogLabel: 'requestId' }),
    requestIdHeader: false,
    genReqId: newRequestId,
    bodyLimit: BODY_LIMIT_BYTES,
    trustProxy: options.trustProxy ?? false,
    return503OnClosing: true,
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
      },
      'request',
    );
  });

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
    },
    { prefix: '/api' },
  );

  const clientDir = options.clientDir === false ? false : resolve(options.clientDir ?? process.env.CLIENT_DIR ?? 'client/dist');
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
