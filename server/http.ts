import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { AppError } from './errors.js';
import type { SessionUser } from './types.js';

// ---------------------------------------------------------------- cookies

/** Parses a Cookie header; the first occurrence of a name wins. */
export function parseCookies(header: string | undefined): Map<string, string> {
  const out = new Map<string, string>();
  if (!header) return out;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq <= 0) continue;
    const name = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();
    if (name && !out.has(name)) out.set(name, value);
  }
  return out;
}

export interface CookieOptions {
  maxAgeSeconds: number;
  secure: boolean;
  sameSite: 'Lax' | 'Strict';
}

/** S2.2: HttpOnly, Secure in production, SameSite, Path=/, never a Domain. */
export function serializeCookie(name: string, value: string, o: CookieOptions): string {
  const parts = [`${name}=${value}`, 'Path=/', 'HttpOnly', `SameSite=${o.sameSite}`, `Max-Age=${o.maxAgeSeconds}`];
  if (o.secure) parts.push('Secure');
  return parts.join('; ');
}

export function appendSetCookie(reply: FastifyReply, cookie: string): void {
  const prev = reply.getHeader('set-cookie');
  const list = prev === undefined ? [] : Array.isArray(prev) ? prev.map(String) : [String(prev)];
  void reply.header('set-cookie', [...list, cookie]);
}

// ---------------------------------------------------------------- input

export interface Issue {
  path: string;
  code: string;
  message: string;
}

function issuesOf(error: z.ZodError): Issue[] {
  return error.issues.map((i) => ({ path: i.path.map(String).join('.'), code: i.code, message: i.message }));
}

/** S4.1: parses with zod or throws 400 invalid_input naming the fields (never echoing values). */
export function parseInput<T>(schema: z.ZodType<T>, value: unknown, where: 'body' | 'params' | 'query'): T {
  const r = schema.safeParse(value);
  if (!r.success) {
    throw new AppError(400, 'invalid_input', `The request ${where} is not valid.`, { where, issues: issuesOf(r.error) });
  }
  return r.data;
}

const EMPTY = z.strictObject({});

// ---------------------------------------------------------------- routes

export type Auth = 'public' | 'user';
export type RateLimitClass = 'auth' | 'invite';

export interface RouteContext<B, P, Q> {
  req: FastifyRequest;
  reply: FastifyReply;
  body: B;
  params: P;
  query: Q;
  user: SessionUser | null;
  now: Date;
}

export interface RouteDef<B, P, Q> {
  method: 'GET' | 'POST' | 'PATCH';
  url: string;
  /** Who may call it at all. Circle roles are checked inside, in one place (circle-access). */
  auth: Auth;
  body?: z.ZodType<B>;
  params?: z.ZodType<P>;
  query?: z.ZodType<Q>;
  rateLimit?: RateLimitClass;
  handler(ctx: RouteContext<B, P, Q>): Promise<unknown> | unknown;
}

export interface SignedInContext<B, P, Q> extends RouteContext<B, P, Q> {
  user: SessionUser;
}

export const UNAUTHENTICATED = (): AppError => new AppError(401, 'unauthenticated', 'Sign in to continue.');

/**
 * Registers a route whose every input is checked by zod (body, params,
 * query; unknown keys refused) after the authentication requirement.
 */
export function route<B = undefined, P = Record<string, never>, Q = Record<string, never>>(
  api: FastifyInstance,
  def: RouteDef<B, P, Q>,
): void {
  api.route({
    method: def.method,
    url: def.url,
    config: { auth: def.auth, rateLimit: def.rateLimit },
    handler: async (req, reply) => {
      if (def.auth === 'user' && !req.user) throw UNAUTHENTICATED();
      const params = parseInput((def.params ?? EMPTY) as z.ZodType<P>, req.params ?? {}, 'params');
      const query = parseInput((def.query ?? EMPTY) as z.ZodType<Q>, req.query ?? {}, 'query');
      let body: B;
      if (def.body) {
        body = parseInput(def.body, req.body, 'body');
      } else {
        if (req.body !== undefined && req.body !== null) parseInput(EMPTY, req.body, 'body');
        body = undefined as B;
      }
      return def.handler({ req, reply, body, params, query, user: req.user, now: req.server.clock.now() });
    },
  });
}

/** For handlers of auth: 'user' routes. */
export function signedIn<B, P, Q>(ctx: RouteContext<B, P, Q>): SignedInContext<B, P, Q> {
  if (!ctx.user) throw UNAUTHENTICATED();
  return ctx as SignedInContext<B, P, Q>;
}

declare module 'fastify' {
  interface FastifyContextConfig {
    auth?: Auth;
    rateLimit?: RateLimitClass | undefined;
  }
}
