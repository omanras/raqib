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
    // The language switch is meant to read "English"; anything else with words must be Arabic.
    const exempt = ['lang.switch'];
    for (const key of Object.keys(ar) as (keyof typeof ar)[]) {
      expect(ar[key], key).not.toMatch(/[\u0660-\u0669\u06F0-\u06F9]/);
      const words = ar[key].replace(/\{\w+\}/g, '').replace(/[A-Z0-9-]{4,}|a-z|ISO|OMR/g, '');
      if (!exempt.includes(key) && /[A-Za-z\u0600-\u06FF]/.test(words)) expect(words, key).toMatch(/[\u0600-\u06FF]/);
    }
  });
});
