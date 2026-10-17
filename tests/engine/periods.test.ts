import { describe, expect, it } from "vitest";
import { inPeriod, monthsOf, nextPeriod, parsePeriod, periodContaining, periodOf, periodsBetween, trailing } from "../../src/engine/periods";

describe("engine/periods", () => {
  it("names the period of a date", () => {
    expect(periodOf("2026-09-30", "month")).toBe("2026-09");
    expect(periodOf("2026-09-30", "quarter")).toBe("2026-Q3");
    expect(periodOf("2026-09-30", "year")).toBe("2026");
    expect(periodOf("2025-11-30", "quarter")).toBe("2025-Q4");
    expect(periodOf("2026-01-01", "quarter")).toBe("2026-Q1");
    expect(periodOf("2026-12-31", "quarter")).toBe("2026-Q4");
  });

  it("parses period text into bounds", () => {
    expect(parsePeriod("2026-03")).toEqual({ kind: "month", text: "2026-03", start: "2026-03-01", end: "2026-03-31" });
    expect(parsePeriod("2024-02")).toEqual({ kind: "month", text: "2024-02", start: "2024-02-01", end: "2024-02-29" });
    expect(parsePeriod("2025-02")?.end).toBe("2025-02-28");
    expect(parsePeriod("2026-Q3")).toEqual({ kind: "quarter", text: "2026-Q3", start: "2026-07-01", end: "2026-09-30" });
    expect(parsePeriod("2026-Q4")?.end).toBe("2026-12-31");
    expect(parsePeriod("2026")).toEqual({ kind: "year", text: "2026", start: "2026-01-01", end: "2026-12-31" });
    expect(parsePeriod("2026-13")).toBeNull();
    expect(parsePeriod("2026-Q5")).toBeNull();
    expect(parsePeriod("2026-9")).toBeNull();
    expect(parsePeriod("Q3-2026")).toBeNull();
    expect(parsePeriod("")).toBeNull();
  });

  it("tests membership with the bounds", () => {
    const q = periodContaining("2026-08-15", "quarter");
    expect(inPeriod("2026-07-01", q)).toBe(true);
    expect(inPeriod("2026-09-30", q)).toBe(true);
    expect(inPeriod("2026-10-01", q)).toBe(false);
    expect(inPeriod("2026-06-30", q)).toBe(false);
  });

  it("lists trailing months across a year boundary", () => {
    expect(trailing("2026-03-31", 12)).toEqual([
      "2025-04", "2025-05", "2025-06", "2025-07", "2025-08", "2025-09",
      "2025-10", "2025-11", "2025-12", "2026-01", "2026-02", "2026-03",
    ]);
    expect(trailing("2026-01-15", 2)).toEqual(["2025-12", "2026-01"]);
    expect(trailing("2024-02-29", 1)).toEqual(["2024-02"]);
  });

  it("steps to the next period at year ends", () => {
    expect(nextPeriod(parsePeriod("2025-12")!).text).toBe("2026-01");
    expect(nextPeriod(parsePeriod("2025-Q4")!).text).toBe("2026-Q1");
    expect(nextPeriod(parsePeriod("2025")!).text).toBe("2026");
  });

  it("enumerates periods between two dates", () => {
    expect(periodsBetween("2025-11-15", "2026-02-01", "month").map((p) => p.text)).toEqual(["2025-11", "2025-12", "2026-01", "2026-02"]);
    expect(periodsBetween("2025-11-15", "2026-04-01", "quarter").map((p) => p.text)).toEqual(["2025-Q4", "2026-Q1", "2026-Q2"]);
    expect(periodsBetween("2024-10-01", "2026-09-30", "year").map((p) => p.text)).toEqual(["2024", "2025", "2026"]);
    expect(periodsBetween("2026-09-30", "2026-01-01", "month")).toEqual([]);
    expect(monthsOf(parsePeriod("2026-Q3")!)).toEqual(["2026-07", "2026-08", "2026-09"]);
    expect(monthsOf(parsePeriod("2024")!).length).toBe(12);
  });
});
