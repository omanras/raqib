import { describe, expect, it } from 'vitest';
import {
  SCRYPT,
  commonPasswords,
  hashPassword,
  passwordProblem,
  verifyAgainstDummy,
  verifyPassword,
} from '../../server/auth/password.js';
import { newRecoveryCode, normalizeRecoveryCode } from '../../server/auth/recovery.js';

describe('S1.2 auth.hash', () => {
  it('uses scrypt N=2^15 r=8 p=1 with a 32-byte salt and a 64-byte hash', async () => {
    const h = await hashPassword('a-long-unusual-passphrase');
    const [alg, N, r, p, salt, key] = h.split('$');
    expect(alg).toBe('scrypt');
    expect(Number(N)).toBe(2 ** 15);
    expect(Number(r)).toBe(8);
    expect(Number(p)).toBe(1);
    expect(Buffer.from(salt as string, 'base64')).toHaveLength(32);
    expect(Buffer.from(key as string, 'base64')).toHaveLength(64);
    expect(SCRYPT).toMatchObject({ N: 32768, r: 8, p: 1, saltBytes: 32, keyBytes: 64 });
  });

  it('salts every hash and verifies only the right password', async () => {
    const a = await hashPassword('same password here');
    const b = await hashPassword('same password here');
    expect(a).not.toBe(b);
    expect(await verifyPassword('same password here', a)).toBe(true);
    expect(await verifyPassword('same password herE', a)).toBe(false);
    expect(await verifyPassword('', a)).toBe(false);
    expect(await verifyPassword('x', 'not-a-hash')).toBe(false);
    expect(await verifyPassword('x', 'scrypt$1048577$8$1$AA==$AA==')).toBe(false);
  });

  it('compares after NFKC, so composed and decomposed text match', async () => {
    const h = await hashPassword('café au lait 2026');
    expect(await verifyPassword('café au lait 2026', h)).toBe(true);
  });

  it('S1.3 the dummy verification for unknown logins costs a real scrypt', async () => {
    await verifyAgainstDummy('warm-up');
    const t0 = performance.now();
    expect(await verifyAgainstDummy('anything at all')).toBe(false);
    const dummyMs = performance.now() - t0;
    const h = await hashPassword('another passphrase');
    const t1 = performance.now();
    await verifyPassword('wrong passphrase!', h);
    const realMs = performance.now() - t1;
    expect(dummyMs).toBeGreaterThan(realMs * 0.4);
  });
});

describe('S1.1 auth.password-policy', () => {
  it('bundles the 1,000 most common passwords', () => {
    const list = commonPasswords();
    expect(list.size).toBe(1000);
    expect(list.has('123456')).toBe(true);
    expect(list.has('password')).toBe(true);
    expect(list.has('qwertyuiop')).toBe(true);
  });

  it('requires 10 to 128 characters, any characters', () => {
    expect(passwordProblem('short9char')).toBeNull();
    expect(passwordProblem('nine char')).toBe('too_short');
    expect(passwordProblem('x'.repeat(128))).toBeNull();
    expect(passwordProblem('x'.repeat(129))).toBe('too_long');
    expect(passwordProblem('كلمة سر طويلة')).toBeNull();
    expect(passwordProblem('🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑')).toBeNull();
    expect(passwordProblem('🔑🔑🔑🔑🔑🔑🔑🔑🔑')).toBe('too_short');
  });

  it('refuses common passwords whatever their case, and the login itself', () => {
    expect(passwordProblem('1234567890')).toBe('common');
    expect(passwordProblem('QWERTYUIOP')).toBe('common');
    expect(passwordProblem('sara.alhinai', { login: 'sara.alhinai' })).toBe('is_login');
    expect(passwordProblem('Sara.Alhinai', { login: 'sara.alhinai' })).toBe('is_login');
  });
});

describe('S1.5 recovery code format', () => {
  it('is 16 symbols of Crockford base32 in four groups', () => {
    for (let i = 0; i < 50; i += 1) {
      expect(newRecoveryCode()).toMatch(/^[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){3}$/);
    }
    expect(normalizeRecoveryCode(' abcd-efgh-jkmn-pqrs ')).toBe('ABCDEFGHJKMNPQRS');
    expect(normalizeRecoveryCode('O0I1-L000-0000-0000')).toBe('0011100000000000');
  });
});
