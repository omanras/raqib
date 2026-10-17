import { describe, expect, it } from "vitest";
import { parseRates, rateFor, RATES_HEADER, serializeRates } from "../../src/engine/rates";
import { readExample } from "./fixtures";

const H = RATES_HEADER + "\n";

describe("engine/rates", () => {
  it("parses the example, round-trips it, and looks up the rate in force", () => {
    const text = readExample("rates.csv");
    const p = parseRates(text);
    expect(p.problems).toEqual([]);
    expect(p.count).toBe(24);
    expect(serializeRates(p.rates)).toBe(text);
    const r = rateFor(p.rates, "USD", "2026-09-16");
    expect(r.status).toBe("ok");
    if (r.status === "ok") {
      expect(r.rate.line).toBe(25);
      expect(r.rate.rate.toString()).toBe("0.3854");
    }
    const exact = rateFor(p.rates, "USD", "2025-11-01");
    expect(exact.status === "ok" && exact.rate.line).toBe(15);
    const before = rateFor(p.rates, "USD", "2024-09-30");
    expect(before.status).toBe("missing");
    expect(rateFor(p.rates, "EUR", "2026-09-16").status).toBe("missing");
  });

  it("treats an empty file as an empty table", () => {
    expect(parseRates("")).toEqual({ rates: [], invalid: [], problems: [], count: 0 });
    expect(parseRates("\n")).toEqual({ rates: [], invalid: [], problems: [], count: 0 });
  });

  it("refuses a wrong header and names bad rows", () => {
    expect(parseRates("date,rate\n2026-01-01,1\n").problems[0]?.code).toBe("BAD-HEADER");
    const p = parseRates(H + "2026-01-01,USD,0.38\n2026-01-02,USD\n2026-01-32,USD,0.38\n2026-01-03,usd,0.38\n2026-01-04,USD,-1\n2026-01-05,USD,zero\n");
    expect(p.rates.length).toBe(1);
    expect(p.invalid.map((r) => [r.line, r.code])).toEqual([
      [3, "BAD-COLUMNS"],
      [4, "BAD-DATE"],
      [5, "BAD-CURRENCY"],
      [6, "BAD-RATE"],
      [7, "BAD-RATE"],
    ]);
  });

  it("reports two different rates on one date as a conflict, the same rate twice as fine", () => {
    const p = parseRates(H + "2026-01-01,USD,0.38\n2026-01-01,USD,0.39\n2026-02-01,USD,0.40\n2026-02-01,USD,0.40\n");
    const c = rateFor(p.rates, "USD", "2026-01-15");
    expect(c.status).toBe("conflict");
    if (c.status === "conflict") expect(c.lines).toEqual([2, 3]);
    const ok = rateFor(p.rates, "USD", "2026-02-15");
    expect(ok.status).toBe("ok");
    if (ok.status === "ok") expect(ok.rate.line).toBe(4);
  });
});
