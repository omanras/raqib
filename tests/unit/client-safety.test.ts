import { describe, expect, it } from 'vitest';
import { safeNext } from '../../client/screens/auth.js';

describe('client: open redirect after sign-in', () => {
  it('follows ?next= only to same-origin paths', () => {
    expect(safeNext('/join/abc')).toBe('/join/abc');
    expect(safeNext('/circles/x/ledger?verify=1')).toBe('/circles/x/ledger?verify=1');
    for (const bad of [null, '', 'https://evil.example', '//evil.example', '/\\evil.example', 'javascript:alert(1)', '/\u0000x', 'circles']) {
      expect(safeNext(bad), String(bad)).toBe('/circles');
    }
  });
});
