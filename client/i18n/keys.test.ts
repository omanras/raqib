import { describe, expect, it } from 'vitest';
import { ar } from './ar.js';
import { en } from './en.js';

/** The missing-key check (M2.1 E2): both dictionaries hold the same keys, filled, with the same placeholders. */
const placeholders = (s: string) => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort();

describe('i18n keys', () => {
  it('en and ar have exactly the same keys', () => {
    const enKeys = Object.keys(en).sort();
    const arKeys = Object.keys(ar).sort();
    expect(arKeys.filter((k) => !enKeys.includes(k)), 'keys only in ar').toEqual([]);
    expect(enKeys.filter((k) => !arKeys.includes(k)), 'keys missing from ar').toEqual([]);
  });

  it('no value is empty and placeholders match', () => {
    for (const key of Object.keys(en) as (keyof typeof en)[]) {
      expect(en[key].trim(), key).not.toBe('');
      expect(ar[key].trim(), key).not.toBe('');
      expect(placeholders(ar[key]), key).toEqual(placeholders(en[key]));
    }
  });

  it('Arabic strings are written in Arabic script with Latin digits only', () => {
    const latinOnly = ['lang.switch', 'circles.perPeriod'];
    for (const key of Object.keys(ar) as (keyof typeof ar)[]) {
      expect(ar[key], key).not.toMatch(/[٠-٩۰-۹]/);
      if (!latinOnly.includes(key)) expect(ar[key], key).toMatch(/[؀-ۿ]/);
    }
  });
});
