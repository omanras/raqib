import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { DISPLAY_NAME_MAX, cleanText, codePoints, hasForbiddenChars, isValidLogin, normalizeLogin } from '../../shared/validate.js';
import { audit, uaHash } from '../audit.js';
import { newPreSessionValue, preSessionCsrfToken, sessionCsrfToken } from '../auth/csrf.js';
import { PASSWORD_MESSAGES, hashPassword, passwordProblem, verifyAgainstDummy, verifyPassword } from '../auth/password.js';
import { consumeRecoveryCode, issueRecoveryCodes, remainingRecoveryCodes } from '../auth/recovery.js';
import {
  findSession,
  issueSession,
  listLiveSessions,
  revokeAllSessions,
  revokeSession,
  tokenHash,
} from '../auth/sessions.js';
import { hmacHex } from '../crypto.js';
import { withTx } from '../db/db.js';
import { findUserById, findUserByLogin, insertUser, publicUser, setDisplayName, setPassword, type UserRow } from '../db/users.js';
import { AppError } from '../errors.js';
import { route, signedIn } from '../http.js';
import { clearSessionCookie, cookieNames, setPreSessionCookie, setSessionCookie } from '../plugins/session.js';
import type { SlidingWindow } from '../ratelimit.js';

const displayName = z
  .string()
  .max(DISPLAY_NAME_MAX * 4)
  .transform(cleanText)
  .refine((s) => codePoints(s) >= 1 && codePoints(s) <= DISPLAY_NAME_MAX, `1 to ${DISPLAY_NAME_MAX} characters`)
  .refine((s) => !hasForbiddenChars(s), 'contains characters that are not allowed');

const loginInput = z.string().min(1).max(64);
/** Bounded generously; the policy (S1.1) is applied to new passwords separately. */
const passwordInput = z.string().min(1).max(1024);
const recoveryCodeInput = z.string().min(1).max(64);

const SignupBody = z.strictObject({ displayName, login: loginInput, password: passwordInput });
const LoginBody = z.strictObject({ login: loginInput, password: passwordInput });
const RecoveryBody = z.strictObject({ login: loginInput, recoveryCode: recoveryCodeInput, newPassword: passwordInput });
const PasswordBody = z.strictObject({ currentPassword: passwordInput, newPassword: passwordInput });
const ProfileBody = z.strictObject({ displayName });
const ConfirmPasswordBody = z.strictObject({ password: passwordInput });
const SessionParams = z.strictObject({ id: z.string().min(1).max(64) });

function requireStrongPassword(password: string, login?: string): void {
  const problem = passwordProblem(password, { login });
  if (problem) throw new AppError(400, 'weak_password', PASSWORD_MESSAGES[problem], { problem });
}

function lockedError(limiter: SlidingWindow, key: string, reply: FastifyReply): AppError {
  const seconds = Math.ceil(limiter.retryAfterMs(key) / 1000);
  void reply.header('retry-after', String(seconds));
  return new AppError(423, 'locked', 'Too many failed attempts for this account; wait and try again.', {
    retryAfterSeconds: seconds,
  });
}

/** Audit target for a login name typed by someone: keyed hash, so a password typed into the login field is never stored. */
function loginTarget(secret: string, login: string): string {
  return `login:${hmacHex(`audit-login:${secret}`, login).slice(0, 16)}`;
}

function csrfFor(app: FastifyInstance, sessionToken: string): string {
  return sessionCsrfToken(app.config.sessionSecret, tokenHash(sessionToken));
}

/** Rotation (S2.1): the session a request arrived with is revoked before a new one is issued. */
function startSession(req: FastifyRequest, reply: FastifyReply, user: UserRow, now: Date): string {
  const app = req.server;
  if (req.user) revokeSession(app.db, req.user.sessionId, 'rotated', now);
  const issued = issueSession(app.db, user.id, now, uaHash(app.config.sessionSecret, req.headers['user-agent']));
  setSessionCookie(app, reply, issued.token);
  req.user = {
    id: user.id,
    login: user.login,
    displayName: user.display_name,
    sessionId: issued.row.id,
    sessionTokenHash: issued.row.token_hash,
  };
  return issued.token;
}

export function authRoutes(api: FastifyInstance): void {
  const app = api;

  route(api, {
    method: 'GET',
    url: '/auth/csrf',
    auth: 'public',
    handler: ({ req, reply }) => {
      if (req.user) return { csrfToken: sessionCsrfToken(app.config.sessionSecret, req.user.sessionTokenHash) };
      let pre = req.cookies.get(cookieNames(app.config.production).pre);
      if (!pre || !/^[A-Za-z0-9_-]{43}$/.test(pre)) {
        pre = newPreSessionValue();
        setPreSessionCookie(app, reply, pre);
      }
      return { csrfToken: preSessionCsrfToken(app.config.sessionSecret, pre) };
    },
  });

  route(api, {
    method: 'POST',
    url: '/auth/signup',
    auth: 'public',
    rateLimit: 'auth',
    body: SignupBody,
    handler: async ({ req, reply, body, now }) => {
      const login = normalizeLogin(body.login);
      if (!isValidLogin(login)) {
        throw new AppError(400, 'invalid_login', 'A login is 3-32 characters: letters a-z, digits, dot, dash or underscore.');
      }
      requireStrongPassword(body.password, login);
      if (findUserByLogin(app.db, login)) throw new AppError(409, 'login_taken', 'This login is already taken.');
      const passwordHash = await hashPassword(body.password);
      const result = withTx(app.db, () => {
        if (findUserByLogin(app.db, login)) throw new AppError(409, 'login_taken', 'This login is already taken.');
        const user = insertUser(app.db, { login, displayName: body.displayName, passwordHash, now });
        const recoveryCodes = issueRecoveryCodes(app.db, user.id, now);
        const token = startSession(req, reply, user, now);
        audit(req, { action: 'auth.signup', target: `user:${user.id}` });
        return { user, recoveryCodes, token };
      });
      void reply.status(201);
      return { user: publicUser(result.user), recoveryCodes: result.recoveryCodes, csrfToken: csrfFor(app, result.token) };
    },
  });

  route(api, {
    method: 'POST',
    url: '/auth/login',
    auth: 'public',
    rateLimit: 'auth',
    body: LoginBody,
    handler: async ({ req, reply, body, now }) => {
      const login = normalizeLogin(body.login);
      const key = `login:${login}`;
      const limiter = app.limits.loginFailures;
      if (limiter.blocked(key)) {
        audit(req, { action: 'auth.login_locked', target: loginTarget(app.config.sessionSecret, login) });
        throw lockedError(limiter, key, reply);
      }
      const user = findUserByLogin(app.db, login);
      const ok = user ? await verifyPassword(body.password, user.password_hash) : await verifyAgainstDummy(body.password);
      if (!user || !ok) {
        limiter.hit(key);
        audit(req, { action: 'auth.login_failed', target: loginTarget(app.config.sessionSecret, login), actorId: null });
        throw new AppError(401, 'invalid_credentials', 'The login or the password is not correct.');
      }
      limiter.reset(key);
      const token = withTx(app.db, () => {
        const t = startSession(req, reply, user, now);
        audit(req, { action: 'auth.login', target: `user:${user.id}` });
        return t;
      });
      return { user: publicUser(user), csrfToken: csrfFor(app, token) };
    },
  });

  route(api, {
    method: 'POST',
    url: '/auth/logout',
    auth: 'user',
    rateLimit: 'auth',
    handler: (ctx) => {
      const { req, reply, user, now } = signedIn(ctx);
      withTx(app.db, () => {
        revokeSession(app.db, user.sessionId, 'logout', now);
        audit(req, { action: 'auth.logout', target: `session:${user.sessionId}` });
      });
      clearSessionCookie(app, reply);
      return { ok: true };
    },
  });

  route(api, {
    method: 'POST',
    url: '/auth/logout-all',
    auth: 'user',
    rateLimit: 'auth',
    handler: (ctx) => {
      const { req, reply, user, now } = signedIn(ctx);
      const revoked = withTx(app.db, () => {
        const n = revokeAllSessions(app.db, user.id, 'logout_all', now);
        audit(req, { action: 'auth.logout_all', target: `user:${user.id}`, details: { revoked: n } });
        return n;
      });
      clearSessionCookie(app, reply);
      return { ok: true, revoked };
    },
  });

  route(api, {
    method: 'GET',
    url: '/auth/me',
    auth: 'user',
    handler: (ctx) => {
      const { user } = signedIn(ctx);
      const row = findUserById(app.db, user.id) as UserRow;
      return { user: publicUser(row), recoveryCodesRemaining: remainingRecoveryCodes(app.db, user.id) };
    },
  });

  route(api, {
    method: 'PATCH',
    url: '/auth/me',
    auth: 'user',
    body: ProfileBody,
    handler: (ctx) => {
      const { req, user, body } = signedIn(ctx);
      withTx(app.db, () => {
        setDisplayName(app.db, user.id, body.displayName);
        audit(req, { action: 'auth.profile_changed', target: `user:${user.id}` });
      });
      return { user: publicUser(findUserById(app.db, user.id) as UserRow) };
    },
  });

  route(api, {
    method: 'GET',
    url: '/auth/sessions',
    auth: 'user',
    handler: (ctx) => {
      const { user, now } = signedIn(ctx);
      return { sessions: listLiveSessions(app.db, user.id, now, user.sessionId) };
    },
  });

  route(api, {
    method: 'POST',
    url: '/auth/sessions/:id/revoke',
    auth: 'user',
    rateLimit: 'auth',
    params: SessionParams,
    handler: (ctx) => {
      const { req, reply, user, params, now } = signedIn(ctx);
      const s = findSession(app.db, params.id);
      if (!s || s.user_id !== user.id) throw new AppError(404, 'not_found', 'Not found.');
      withTx(app.db, () => {
        revokeSession(app.db, s.id, 'revoked_by_user', now);
        audit(req, { action: 'auth.session_revoked', target: `session:${s.id}` });
      });
      if (s.id === user.sessionId) clearSessionCookie(app, reply);
      return { ok: true };
    },
  });

  route(api, {
    method: 'POST',
    url: '/auth/password',
    auth: 'user',
    rateLimit: 'auth',
    body: PasswordBody,
    handler: async (ctx) => {
      const { req, reply, user, body, now } = signedIn(ctx);
      const key = `login:${user.login}`;
      const limiter = app.limits.loginFailures;
      if (limiter.blocked(key)) throw lockedError(limiter, key, reply);
      const row = findUserById(app.db, user.id) as UserRow;
      if (!(await verifyPassword(body.currentPassword, row.password_hash))) {
        limiter.hit(key);
        audit(req, { action: 'auth.password_change_failed', target: `user:${user.id}` });
        throw new AppError(403, 'wrong_password', 'The current password is not correct.');
      }
      requireStrongPassword(body.newPassword, row.login);
      const passwordHash = await hashPassword(body.newPassword);
      const token = withTx(app.db, () => {
        setPassword(app.db, user.id, passwordHash, now);
        const revoked = revokeAllSessions(app.db, user.id, 'password_changed', now);
        req.user = null;
        const t = startSession(req, reply, row, now);
        audit(req, { action: 'auth.password_changed', target: `user:${user.id}`, details: { revoked } });
        return t;
      });
      return { ok: true, csrfToken: csrfFor(app, token) };
    },
  });

  route(api, {
    method: 'POST',
    url: '/auth/recovery',
    auth: 'public',
    rateLimit: 'auth',
    body: RecoveryBody,
    handler: async ({ req, reply, body, now }) => {
      const login = normalizeLogin(body.login);
      const key = `login:${login}`;
      const limiter = app.limits.recoveryFailures;
      if (limiter.blocked(key)) throw lockedError(limiter, key, reply);
      requireStrongPassword(body.newPassword, login);
      const user = findUserByLogin(app.db, login);
      const fail = (): AppError => {
        limiter.hit(key);
        audit(req, { action: 'auth.recovery_failed', target: loginTarget(app.config.sessionSecret, login), actorId: null });
        return new AppError(401, 'invalid_recovery', 'The login or the recovery code is not correct.');
      };
      const passwordHash = await hashPassword(body.newPassword);
      if (!user) throw fail();
      const result = withTx(app.db, () => {
        if (!consumeRecoveryCode(app.db, user.id, body.recoveryCode, now)) return null;
        setPassword(app.db, user.id, passwordHash, now);
        const revoked = revokeAllSessions(app.db, user.id, 'recovery', now);
        req.user = null;
        const token = startSession(req, reply, user, now);
        audit(req, { action: 'auth.recovered', target: `user:${user.id}`, details: { revoked } });
        return { token };
      });
      if (!result) throw fail();
      limiter.reset(key);
      return {
        user: publicUser(user),
        csrfToken: csrfFor(app, result.token),
        recoveryCodesRemaining: remainingRecoveryCodes(app.db, user.id),
      };
    },
  });

  route(api, {
    method: 'POST',
    url: '/auth/recovery-codes',
    auth: 'user',
    rateLimit: 'auth',
    body: ConfirmPasswordBody,
    handler: async (ctx) => {
      const { req, reply, user, body, now } = signedIn(ctx);
      const key = `login:${user.login}`;
      const limiter = app.limits.loginFailures;
      if (limiter.blocked(key)) throw lockedError(limiter, key, reply);
      const row = findUserById(app.db, user.id) as UserRow;
      if (!(await verifyPassword(body.password, row.password_hash))) {
        limiter.hit(key);
        audit(req, { action: 'auth.recovery_codes_failed', target: `user:${user.id}` });
        throw new AppError(403, 'wrong_password', 'The password is not correct.');
      }
      const recoveryCodes = withTx(app.db, () => {
        const codes = issueRecoveryCodes(app.db, user.id, now);
        audit(req, { action: 'auth.recovery_codes_regenerated', target: `user:${user.id}` });
        return codes;
      });
      return { recoveryCodes };
    },
  });
}
