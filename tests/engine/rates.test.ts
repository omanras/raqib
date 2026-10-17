// rates.csv and conversion: the rates part of the reference engine's
// tests/test_measures.py over its fixtures, plus the example household.
import { describe, expect, it } from "vitest";
import { D } from "../../src/engine/decimal";
import { parseRates, RateTable, RATES_HEADER, serializeRates, type Conversion } from "../../src/engine/rates";
import type { Unknown } from "../../src/engine/values";
import { fixture, readExample } from "./fixtures";

function load(name: string) {
  return parseRates(fixture(`rates/${name}`), "OMR", name);
}

function ok(c: Conversion | Unknown): Conversion {
  if ("tag" in c) throw new Error(c.reason);
  return c;
}

describe("engine/rates", () => {
  it("parses the example and round-trips it", () => {
    const text = readExample("rates.csv");
    const p = parseRates(text, "OMR");
    expect(p.problems).toEqual([]);
    expect(p.table.rows.length).toBe(24);
    expect(serializeRates(p.table.rows)).toBe(text);
    const c = ok(p.table.convert(D("1430.00"), "USD", "2026-09-30"));
    expect(c.amount.toString()).toBe("551.122");
    expect(c.rate?.cite).toBe("rates.csv:25");
  });

  it("converts with the latest rate on or before the date and cites it", () => {
    const { table, problems } = load("valid.csv");
    expect(problems).toEqual([]);
    expect(table.base).toBe("OMR");
    expect(table.currencies).toEqual(["EUR", "USD"]);
    expect(table.rows.length).toBe(4);
    expect(ok(table.convert(D("10"), "OMR", "2026-07-14"))).toEqual({ amount: D("10"), rate: null });
    const exact = ok(table.convert(D("20.000"), "USD", "2026-07-14"));
    expect(exact.amount.eq("7.680000")).toBe(true);
    expect(exact.rate?.cite).toBe("valid.csv:3");
    const before = ok(table.convert(D("20"), "USD", "2026-07-13"));
    expect([before.amount.eq("7.700"), before.rate?.line]).toEqual([true, 2]);
    const later = ok(table.convert(D("1"), "USD", "2030-01-01"));
    expect([later.amount.eq("0.386"), later.rate?.line]).toEqual([true, 4]);
    const eur = ok(table.convert(D("100"), "EUR", "2026-01-01"));
    expect([eur.amount.eq("42.00"), eur.rate?.line]).toEqual([true, 5]);
  });

  it("is Unknown without a rate, never a guess (A5)", () => {
    const { table } = load("valid.csv");
    const early = table.convert(D("1"), "USD", "2026-06-30") as Unknown;
    expect(early.tag).toBe("unknown");
    expect(early.reason).toContain("on or before 2026-06-30");
    const gbp = table.convert(D("1"), "GBP", "2026-07-14") as Unknown;
    expect(gbp.reason).toContain("GBP");
    const noBase = new RateTable([], null).convert(D("1"), "USD", "2026-07-14") as Unknown;
    expect(noBase.reason).toContain("base currency");
    expect(ok(new RateTable([], "OMR").convert(D("3"), "OMR", "2026-01-01")).amount.eq(3)).toBe(true);
  });

  it("bad rows are problems naming the line", () => {
    const { table, problems } = load("bad_rows.csv");
    expect(problems.map((p) => [p.line, p.code])).toEqual([
      [3, "BAD-DATE"],
      [4, "BAD-CURRENCY"],
      [5, "BAD-RATE"],
      [6, "BAD-RATE"],
      [7, "BAD-RATE"],
      [8, "BAD-RATE"],
      [9, "BASE-RATE"],
      [10, "COLUMN-COUNT"],
    ]);
    expect(table.rows.map((r) => r.line)).toEqual([2]);
  });

  it("two different rates on one date: a problem, and Unknown on that date", () => {
    const { table, problems } = load("conflict.csv");
    expect(problems.map((p) => [p.line, p.code])).toEqual([[3, "CONFLICT-RATE"]]);
    expect(problems[0]?.reason).toContain("line 2");
    const u = table.convert(D("1"), "USD", "2026-07-15") as Unknown;
    expect(u.cites).toEqual(["conflict.csv:2", "conflict.csv:3"]);
    expect(ok(table.convert(D("1"), "USD", "2026-08-01")).amount.eq("0.390")).toBe(true);
  });

  it("an exact duplicate is a warning, not a conflict", () => {
    const { table, problems } = load("dup.csv");
    expect(problems.map((p) => [p.line, p.code, p.class])).toEqual([[3, "DUP-ROW", "warn"]]);
    expect(ok(table.convert(D("2"), "USD", "2026-07-01")).amount.eq("0.770")).toBe(true);
  });

  it("file level: a bad header; an absent file is an empty table, an empty one a problem", () => {
    const bad = load("bad_header.csv");
    expect([bad.table.rows.length, bad.problems.map((p) => p.code)]).toEqual([0, ["BAD-HEADER"]]);
    const absent = parseRates(null, "OMR");
    expect([absent.table.rows.length, absent.problems, absent.table.base]).toEqual([0, [], "OMR"]);
    expect(parseRates("", "OMR").problems.map((p) => p.code)).toEqual(["FILE-EMPTY"]);
    expect(parseRates(RATES_HEADER + "\n", "OMR").problems).toEqual([]);
  });
});
