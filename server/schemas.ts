import { z } from 'zod';
import { MAX_AMOUNT } from '../shared/money.js';
import { isISODate } from '../shared/schedule.js';
import { cleanText, codePoints, hasForbiddenChars } from '../shared/validate.js';

/** Free text: NFC, trimmed, bounded in code points, no control or bidi-override characters (S4.1). */
export function text(min: number, max: number, options: { multiline?: boolean } = {}) {
  return z
    .string()
    .max(max * 4 + 16)
    .transform(cleanText)
    .refine((s) => codePoints(s) >= min && codePoints(s) <= max, min > 0 ? `${min} to ${max} characters` : `at most ${max} characters`)
    .refine((s) => !hasForbiddenChars(s, options.multiline ?? false), 'contains characters that are not allowed');
}

/** A random id from a URL: 22 base64url characters (newId). Anything else is simply not found. */
export const id = z.string().regex(/^[A-Za-z0-9_-]{1,64}$/, 'not an id');

/** A bearer token from a link (newToken: 43 base64url characters). */
export const token = z.string().regex(/^[A-Za-z0-9_-]{16,128}$/, 'not a token');

/** Integer minor units, 1..MAX_AMOUNT (S4.1: amounts are integers in minor units). */
export const amount = z.number().int().min(1).max(MAX_AMOUNT);

export const isoDate = z.string().refine(isISODate, 'an ISO date YYYY-MM-DD');

/** ISO-8601 instant with a time zone, as the client sends deadlines. */
export const instant = z
  .string()
  .max(40)
  .refine((s) => /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{1,3})?)?(Z|[+-]\d{2}:\d{2})$/.test(s) && !Number.isNaN(Date.parse(s)), 'an ISO date-time with a time zone');

export const CircleIdParams = z.strictObject({ id });
