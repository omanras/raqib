import { hmacHex, newToken } from '../crypto.js';

/**
 * S2.3: CSRF double-submit, bound to the session. A signed-in request must
 * carry X-CSRF-Token = HMAC(SESSION_SECRET, session token hash). Before a
 * session exists (sign-up, sign-in, recovery) the token is bound instead to
 * a random pre-session cookie: X-CSRF-Token = HMAC(SESSION_SECRET, that
 * cookie). Either way a page on another origin can read neither the cookie
 * nor the token, so it cannot forge the header.
 */
export const CSRF_HEADER = 'x-csrf-token';

export function sessionCsrfToken(secret: string, sessionTokenHash: string): string {
  return hmacHex(`csrf:${secret}`, `session:${sessionTokenHash}`);
}

export function preSessionCsrfToken(secret: string, preSessionValue: string): string {
  return hmacHex(`csrf:${secret}`, `pre:${preSessionValue}`);
}

export function newPreSessionValue(): string {
  return newToken();
}
