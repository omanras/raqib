// E4 of M1.3: every interface string exists in both languages and none of
// the Arabic ones is an English placeholder; slots match.
import { describe, expect, it } from "vitest";
import { STRINGS, type StringKey } from "../../src/i18n/strings";

const SAME_IN_BOTH: StringKey[] = ["lang.en", "lang.ar"];
const ARABIC = /[\u0600-\u06ff]/;

describe("i18n", () => {
  it("has the same keys in English and Arabic", () => {
    expect(Object.keys(STRINGS.ar).sort()).toEqual(Object.keys(STRINGS.en).sort());
  });

  it("translates every string (no English left in the Arabic table)", () => {
    const keys = Object.keys(STRINGS.en) as StringKey[];
    const untranslated = keys.filter((k) => !SAME_IN_BOTH.includes(k) && (STRINGS.ar[k] === STRINGS.en[k] || !ARABIC.test(STRINGS.ar[k])));
    expect(untranslated).toEqual([]);
  });

  it("keeps every {slot} and writes numbers in Latin digits", () => {
    const keys = Object.keys(STRINGS.en) as StringKey[];
    for (const k of keys) {
      const slots = (s: string) => (s.match(/\{\w+\}/g) ?? []).sort();
      expect(slots(STRINGS.ar[k]), k).toEqual(slots(STRINGS.en[k]));
      expect(/[\u0660-\u0669\u06f0-\u06f9]/.test(STRINGS.ar[k]), k).toBe(false);
    }
  });
});
