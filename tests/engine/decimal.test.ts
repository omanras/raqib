import { describe, expect, it } from "vitest";
import { D, Decimal, fmt, money, num, pct, pyDecimalStr } from "../../src/engine/decimal";

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

  it("prints money and percentages as the CLI does", () => {
    expect(money(D("248.180000"), "OMR")).toBe("248.18 OMR");
    expect(money(D("1900.000"), "OMR")).toBe("1900 OMR");
    expect(money(D("0.1"))).toBe("0.1");
    expect(money(D("-0.000"))).toBe("0");
    expect(money(D("1E+3"))).toBe("1000");
    expect(pct(D("4.545454545"))).toBe("4.55%");
    expect(pct(D("77.5"))).toBe("77.5%");
    expect(pct(D("0"))).toBe("0%");
    expect(pct(D("17.37018650207969944988595197"))).toBe("17.37%");
    expect(pct(D("2.125"))).toBe("2.12%");
    expect(pct(D("-0.001"))).toBe("-0%");
  });

  it("spells a declared number like Python's str(Decimal)", () => {
    expect(pyDecimalStr("10")).toBe("10");
    expect(pyDecimalStr("4500.50")).toBe("4500.50");
    expect(pyDecimalStr("007.50")).toBe("7.50");
    expect(pyDecimalStr("-0")).toBe("-0");
    expect(pyDecimalStr("0.000001")).toBe("0.000001");
    expect(pyDecimalStr("0.0000001")).toBe("1E-7");
    expect(pyDecimalStr("1.5e+3")).toBe("1.5E+3");
    expect(pyDecimalStr("1.")).toBe("1");
    expect(pyDecimalStr(".5")).toBe("0.5");
    expect(pyDecimalStr("abc")).toBeNull();
    expect(num("12.50")).toEqual({ value: D("12.5"), text: "12.50" });
  });
});
