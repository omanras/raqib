import { randomBytes, scrypt, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { PASSWORD_MAX, PASSWORD_MIN, codePoints } from '../../shared/validate.js';

/** S1.2: scrypt N=2^15, r=8, p=1, 32-byte random salt, 64-byte hash. */
export const SCRYPT = { N: 2 ** 15, r: 8, p: 1, saltBytes: 32, keyBytes: 64 } as const;
const MAXMEM = 128 * SCRYPT.N * SCRYPT.r * 2;

function scryptAsync(password: string, salt: Buffer, N: number, r: number, p: number, keylen: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scrypt(password, salt, keylen, { N, r, p, maxmem: MAXMEM }, (err, key) => (err ? reject(err) : resolve(key)));
  });
}

/** NIST SP 800-63B: compare passwords after NFKC so the same text typed on two keyboards matches. */
function prepare(password: string): string {
  return password.normalize('NFKC');
}

/** Stored as scrypt$N$r$p$<salt base64>$<hash base64>. */
export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(SCRYPT.saltBytes);
  const key = await scryptAsync(prepare(password), salt, SCRYPT.N, SCRYPT.r, SCRYPT.p, SCRYPT.keyBytes);
  return `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt.toString('base64')}$${key.toString('base64')}`;
}

/** Constant-time check of a password against a stored hash; false on any malformed hash. */
export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parts = stored.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const N = Number(parts[1]);
  const r = Number(parts[2]);
  const p = Number(parts[3]);
  const salt = Buffer.from(parts[4] as string, 'base64');
  const expected = Buffer.from(parts[5] as string, 'base64');
  if (!Number.isInteger(N) || !Number.isInteger(r) || !Number.isInteger(p) || expected.length === 0) return false;
  if (N > 2 ** 20 || r > 16 || p > 4) return false;
  const key = await scryptAsync(prepare(password), salt, N, r, p, expected.length);
  return timingSafeEqual(key, expected);
}

let dummy: Promise<string> | undefined;

/**
 * S1.3: an unknown login still costs one full scrypt verification against a
 * hash of a random password, so both answers take the same time.
 */
export async function verifyAgainstDummy(password: string): Promise<false> {
  dummy ??= hashPassword(randomBytes(24).toString('base64'));
  await verifyPassword(password, await dummy);
  return false;
}

const LIST_FILE = fileURLToPath(new URL('./common-passwords.txt', import.meta.url));
let common: Set<string> | undefined;

export function commonPasswords(): Set<string> {
  common ??= new Set(
    readFileSync(LIST_FILE, 'utf8')
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l !== '' && !l.startsWith('#'))
      .map((l) => l.toLowerCase()),
  );
  return common;
}

export type PasswordProblem = 'too_short' | 'too_long' | 'common' | 'is_login';

/** S1.1: length 10-128 code points, not one of the 1,000 most common, not the login itself. */
export function passwordProblem(password: string, context: { login?: string } = {}): PasswordProblem | null {
  const n = codePoints(prepare(password));
  if (n < PASSWORD_MIN) return 'too_short';
  if (n > PASSWORD_MAX) return 'too_long';
  const lower = prepare(password).toLowerCase();
  if (commonPasswords().has(lower)) return 'common';
  if (context.login && lower === context.login.toLowerCase()) return 'is_login';
  return null;
}

export const PASSWORD_MESSAGES: Record<PasswordProblem, string> = {
  too_short: `Use at least ${PASSWORD_MIN} characters.`,
  too_long: `Use at most ${PASSWORD_MAX} characters.`,
  common: 'This password is on the list of the most common passwords; choose another.',
  is_login: 'Do not use your login as your password.',
};
