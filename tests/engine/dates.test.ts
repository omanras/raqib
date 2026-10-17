import { describe, expect, it } from "vitest";
import { addDays, daysBetween, formatDate, fromDays, isLeapYear, isValidDate, parseDate, toDays } from "../../src/engine/dates";

describe("engine/dates", () => {
  it("accepts only strict, calendar-valid ISO dates", () => {
    expect(isValidDate("2026-09-30")).toBe(true);
    expect(isValidDate("2024-02-29")).toBe(true);
    expect(isValidDate("2025-02-29")).toBe(false);
    expect(isValidDate("2026-02-30")).toBe(false);
    expect(isValidDate("2026-04-31")).toBe(false);
    expect(isValidDate("2026-13-01")).toBe(false);
    expect(isValidDate("2026-00-10")).toBe(false);
    expect(isValidDate("2026-9-30")).toBe(false);
    expect(isValidDate("30-09-2026")).toBe(false);
    expect(isValidDate(" 2026-09-30")).toBe(false);
    expect(isValidDate("2026-09-30T00:00")).toBe(false);
    expect(isValidDate("")).toBe(false);
  });

  it("knows leap years", () => {
    expect(isLeapYear(2024)).toBe(true);
    expect(isLeapYear(2100)).toBe(false);
    expect(isLeapYear(2000)).toBe(true);
    expect(isLeapYear(2026)).toBe(false);
  });

  it("counts days like the oracle (92 days from 2026-09-30 to 2026-12-31)", () => {
    expect(daysBetween("2026-09-30", "2026-12-31")).toBe(92);
    expect(daysBetween("2026-09-15", "2026-09-30")).toBe(15);
    expect(daysBetween("2026-09-30", "2026-09-15")).toBe(-15);
    expect(daysBetween("2026-09-15", "2026-12-31")).toBe(107);
    expect(daysBetween("2025-12-31", "2026-01-01")).toBe(1);
    expect(daysBetween("2024-02-28", "2024-03-01")).toBe(2);
    expect(daysBetween("2025-02-28", "2025-03-01")).toBe(1);
  });

  it("adds days across month and year ends", () => {
    expect(addDays("2025-11-30", -90)).toBe("2025-09-01");
    expect(addDays("2026-12-31", 1)).toBe("2027-01-01");
    expect(addDays("2024-02-28", 1)).toBe("2024-02-29");
    expect(addDays("2024-03-01", -1)).toBe("2024-02-29");
    expect(addDays("2026-01-01", -1)).toBe("2025-12-31");
  });

  it("round-trips the day number over a long range", () => {
    const start = toDays({ y: 1970, m: 1, d: 1 });
    expect(start).toBe(0);
    for (let n = -200_000; n <= 200_000; n += 997) {
      const ymd = fromDays(n);
      expect(toDays(ymd)).toBe(n);
      expect(parseDate(formatDate(ymd))).toEqual(ymd);
    }
  });
});
