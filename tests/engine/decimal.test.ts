import { describe, expect, it } from "vitest";
import { D, Decimal, fmt } from "../../src/engine/decimal";

describe("engine/decimal", () => {
  it("adds exactly: 0.1 + 0.2 = 0.3", () => {
    expect(D("0.1").plus("0.2").eq("0.3")).toBe(true);
  });

  it("is configured with precision 28 and ROUND_HALF_EVEN", () => {
    expect(Decimal.precision).toBe(28);
    expect(Decimal.rounding).toBe(Decimal.ROUND_HALF_EVEN);
    // 28 significant digits on division, like Python's default context.
    expect(D("97.095").div("558.975").times(100).toString()).toBe(
      "17.37018650207969944988595197",
    );
    // half-even: 2.5 -> 2, 3.5 -> 4
    expect(D("2.5").toDecimalPlaces(0).toString()).toBe("2");
    expect(D("3.5").toDecimalPlaces(0).toString()).toBe("4");
  });

  it("formats amounts as plain text without trailing zeros", () => {
    expect(fmt(D("1200.000").times("0.1"))).toBe("120");
    expect(fmt(D("10900.000"))).toBe("10900");
    expect(fmt(D("17.507"))).toBe("17.507");
    expect(fmt(D("0.000"))).toBe("0");
    expect(fmt(D("-0.000"))).toBe("0");
    expect(fmt(D("1e21"))).toBe("1000000000000000000000");
    expect(fmt(D("0.00000001"))).toBe("0.00000001");
  });
});
