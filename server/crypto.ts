import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import type { Sha256Hex } from '../shared/hash.js';

/** SHA-256 over UTF-8, lowercase hex: the server side of shared/hash.ts. */
export const sha256Hex: Sha256Hex = (text) => createHash('sha256').update(text, 'utf8').digest('hex');

export function hmacHex(key: string, text: string): string {
  return createHmac('sha256', key).update(text, 'utf8').digest('hex');
}

/** A random identifier for rows that appear in URLs: 128 bits, base64url (22 chars). */
export function newId(): string {
  return randomBytes(16).toString('base64url');
}

/** A random bearer secret (session id, invite token): 256 bits, base64url (43 chars). */
export function newToken(): string {
  return randomBytes(32).toString('base64url');
}

/** Constant-time comparison of two strings of any length. */
export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  if (ab.length !== bb.length) {
    timingSafeEqual(ab, ab);
    return false;
  }
  return timingSafeEqual(ab, bb);
}
