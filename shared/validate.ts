/**
 * Input rules shared by the server (zod schemas) and the client (form
 * hints). The server is the authority; the client only explains early.
 */

/** S1.1: passwords are 10 to 128 characters (Unicode code points), any characters. */
export const PASSWORD_MIN = 10;
export const PASSWORD_MAX = 128;

/** Logins are ASCII, case-insensitive: 3-32 of a-z 0-9 . _ - starting with a letter or digit. */
export const LOGIN_PATTERN = /^[a-z0-9][a-z0-9._-]{2,31}$/;

export const DISPLAY_NAME_MAX = 60;
export const CIRCLE_NAME_MAX = 80;
export const RULES_TEXT_MAX = 4000;
export const SHORT_TEXT_MAX = 120;
export const REASON_MAX = 500;

export function normalizeLogin(login: string): string {
  return login.trim().toLowerCase();
}

export function isValidLogin(login: string): boolean {
  return LOGIN_PATTERN.test(login);
}

export function codePoints(text: string): number {
  return [...text].length;
}

/**
 * Characters refused in any free text: C0/C1 controls (except tab and, where
 * allowed, newline), the bidirectional embedding/override/isolate controls
 * that can make text display differently from what it is (U+202A-U+202E,
 * U+2066-U+2069), and lone surrogates. Zero-width joiner and non-joiner stay
 * allowed: Arabic-script text needs them.
 */
// eslint-disable-next-line no-control-regex
const FORBIDDEN_INLINE = /[\u0000-\u0008\u000A-\u001F\u007F-\u009F‪-‮⁦-⁩]/;
// eslint-disable-next-line no-control-regex
const FORBIDDEN_MULTILINE = /[\u0000-\u0008\u000B-\u001F\u007F-\u009F‪-‮⁦-⁩]/;
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

export function hasForbiddenChars(text: string, multiline = false): boolean {
  return (multiline ? FORBIDDEN_MULTILINE : FORBIDDEN_INLINE).test(text) || LONE_SURROGATE.test(text);
}

/** NFC, \r\n to \n, trimmed. */
export function cleanText(text: string): string {
  return text.normalize('NFC').replace(/\r\n?/g, '\n').trim();
}
