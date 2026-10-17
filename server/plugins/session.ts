import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { CSRF_HEADER, preSessionCsrfToken, sessionCsrfToken } from '../auth/csrf.js';
import { ABSOLUTE_MS, resolveSession } from '../auth/sessions.js';
import { safeEqual } from '../crypto.js';
import { findUserById } from '../db/users.js';
import { AppError } from '../errors.js';
import { appendSetCookie, parseCookies, serializeCookie } from '../http.js';

export interface CookieNames {
  session: string;
  pre: string;
}

/** `__Host-` names in production (Secure, Path=/, no Domain enforced by the browser). */
export function cookieNames(production: boolean): CookieNames {
  return production ? { session: '__Host-dawr_session', pre: '__Host-dawr_pre' } : { session: 'dawr_session', pre: 'dawr_pre' };
}

export function setSessionCookie(app: FastifyInstance, reply: FastifyReply, token: string): void {
  const names = cookieNames(app.config.production);
  appendSetCookie(
    reply,
    serializeCookie(names.session, token, {
      maxAgeSeconds: Math.floor(ABSOLUTE_MS / 1000),
      secure: app.config.production,
      sameSite: 'Lax',
    }),
  );
}

export function clearSessionCookie(app: FastifyInstance, reply: FastifyReply): void {
  const names = cookieNames(app.config.production);
  appendSetCookie(reply, serializeCookie(names.session, '', { maxAgeSeconds: 0, secure: app.config.production, sameSite: 'Lax' }));
}

export function setPreSessionCookie(app: FastifyInstance, reply: FastifyReply, value: string): void {
  const names = cookieNames(app.config.production);
  appendSetCookie(
    reply,
    serializeCookie(names.pre, value, { maxAgeSeconds: 24 * 60 * 60, secure: app.config.production, sameSite: 'Strict' }),
  );
}

/** The CSRF token the caller must send back, or null when it has neither a session nor a pre-session cookie. */
export function expectedCsrfToken(req: FastifyRequest): string | null {
  const secret = req.server.config.sessionSecret;
  if (req.user) return sessionCsrfToken(secret, req.user.sessionTokenHash);
  const pre = req.cookies.get(cookieNames(req.server.config.production).pre);
  return pre ? preSessionCsrfToken(secret, pre) : null;
}

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

function isApi(req: FastifyRequest): boolean {
  return req.url === '/api' || req.url.startsWith('/api/');
}

/**
 * Session, CSRF and rate-limit hooks (S1.4, S2.1-S2.3). Registered once on
 * the root instance so every API route passes through them.
 */
export function securityHooks(app: FastifyInstance): void {
  app.decorateRequest('cookies', null as unknown as Map<string, string>);

  // Rate limits first: a refused request costs no database work.
  app.addHook('onRequest', async (req, reply) => {
    const cls = req.routeOptions.config?.rateLimit;
    if (cls !== 'auth' || SAFE_METHODS.has(req.method)) return;
    const key = `ip:${req.ip}`;
    const count = app.limits.authIp.hit(key);
    if (count > app.limits.authIp.limit) {
      const seconds = Math.ceil(app.limits.authIp.retryAfterMs(key) / 1000);
      void reply.header('retry-after', String(seconds));
      throw new AppError(429, 'rate_limited', 'Too many attempts from this address; wait and try again.', {
        retryAfterSeconds: seconds,
      });
    }
  });

  app.addHook('onRequest', async (req, reply) => {
    req.cookies = parseCookies(req.headers.cookie);
    if (!isApi(req)) return;
    const token = req.cookies.get(cookieNames(app.config.production).session);
    if (!token) return;
    const row = resolveSession(app.db, token, app.clock.now());
    const user = row ? findUserById(app.db, row.user_id) : undefined;
    if (!row || !user) {
      clearSessionCookie(app, reply);
      return;
    }
    req.user = {
      id: user.id,
      login: user.login,
      displayName: user.display_name,
      sessionId: row.id,
      sessionTokenHash: row.token_hash,
    };
  });

  // S2.3: every non-GET API request carries the CSRF token in its header.
  app.addHook('preValidation', async (req) => {
    if (SAFE_METHODS.has(req.method) || !isApi(req)) return;
    const expected = expectedCsrfToken(req);
    const sent = req.headers[CSRF_HEADER];
    if (!expected || typeof sent !== 'string' || !safeEqual(sent, expected)) {
      throw new AppError(403, 'csrf', 'Missing or invalid CSRF token; reload the page and try again.');
    }
  });
}
