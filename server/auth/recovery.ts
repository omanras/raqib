import { randomInt } from 'node:crypto';
import { newId, safeEqual, sha256Hex } from '../crypto.js';
import { stmt, type DB } from '../db/db.js';

/** S1.5: 8 codes per set, shown once, stored hashed, single use. */
export const RECOVERY_CODE_COUNT = 8;

/** Crockford base32 without I, L, O, U: easy to write down and read back. */
const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const GROUPS = 4;
const GROUP_LEN = 4;

/**
 * A recovery code: 16 symbols of a 32-letter alphabet (80 bits), shown as
 * XXXX-XXXX-XXXX-XXXX. At 80 bits a salted SHA-256 is enough at rest: the
 * codes stay verifiable after SESSION_SECRET is rotated.
 */
export function newRecoveryCode(): string {
  const groups: string[] = [];
  for (let g = 0; g < GROUPS; g += 1) {
    let s = '';
    for (let i = 0; i < GROUP_LEN; i += 1) s += ALPHABET[randomInt(ALPHABET.length)];
    groups.push(s);
  }
  return groups.join('-');
}

/** Uppercase, drops spaces and dashes, reads the usual look-alikes (O->0, I/L->1). */
export function normalizeRecoveryCode(code: string): string {
  return code
    .toUpperCase()
    .replace(/[\s-]/g, '')
    .replace(/O/g, '0')
    .replace(/[IL]/g, '1');
}

function codeHash(userId: string, code: string): string {
  return sha256Hex(`dawr-recovery:${userId}:${normalizeRecoveryCode(code)}`);
}

/** Replaces the user's codes with a fresh set and returns them (the only time they exist in clear). */
export function issueRecoveryCodes(db: DB, userId: string, now: Date): string[] {
  const ts = now.toISOString();
  stmt(db, 'UPDATE recovery_codes SET used_at = ? WHERE user_id = ? AND used_at IS NULL').run(ts, userId);
  const codes: string[] = [];
  for (let i = 0; i < RECOVERY_CODE_COUNT; i += 1) {
    const code = newRecoveryCode();
    codes.push(code);
    stmt(db, 'INSERT INTO recovery_codes (id, user_id, code_hash, created_at) VALUES (?, ?, ?, ?)').run(
      newId(),
      userId,
      codeHash(userId, code),
      ts,
    );
  }
  return codes;
}

/** Marks a matching unused code as used; true when one matched. */
export function consumeRecoveryCode(db: DB, userId: string, code: string, now: Date): boolean {
  if (normalizeRecoveryCode(code).length !== GROUPS * GROUP_LEN) return false;
  const h = codeHash(userId, code);
  const rows = stmt(db, 'SELECT id, code_hash FROM recovery_codes WHERE user_id = ? AND used_at IS NULL').all(userId) as {
    id: string;
    code_hash: string;
  }[];
  const match = rows.find((r) => safeEqual(r.code_hash, h));
  if (!match) return false;
  return stmt(db, 'UPDATE recovery_codes SET used_at = ? WHERE id = ? AND used_at IS NULL').run(now.toISOString(), match.id)
    .changes === 1;
}

export function remainingRecoveryCodes(db: DB, userId: string): number {
  return (stmt(db, 'SELECT COUNT(*) AS n FROM recovery_codes WHERE user_id = ? AND used_at IS NULL').get(userId) as { n: number })
    .n;
}
