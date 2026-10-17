import { describe, expect, it } from "vitest";
import { appendHoldingLines, HOLDINGS_HEADER, latestSnapshot, parseHoldings, serializeHoldings, snapshotDates } from "../../src/engine/holdings";
import { parsePolicies } from "../../src/engine/policies";
import type { Config } from "../../src/engine/types";
import { readExample } from "./fixtures";

const config = parsePolicies(readExample("policies.yml")).config as Config;
const H = HOLDINGS_HEADER + "\n";

describe("engine/holdings", () => {
  it("parses the example without problems and round-trips it", () => {
    const text = readExample("holdings.csv");
    const p = parseHoldings(text, config);
    expect(p.problems).toEqual([]);
    expect(p.count).toBe(72);
    expect(p.rows.length).toBe(72);
    const r = p.rows.find((x) => x.line === 72);
    expect(r?.date).toBe("2026-09-30");
    expect(r?.account).toBe("broker");
    expect(r?.cls).toBe("equity");
    expect(r?.quantity.toString()).toBe("10");
    expect(r?.value.toString()).toBe("1430");
    expect(r?.valueText).toBe("1430.00");
    expect(r?.currency).toBe("USD");
    expect(serializeHoldings(p.rows)).toBe(text);
    expect(snapshotDates(p.rows).length).toBe(24);
    expect(snapshotDates(p.rows)[0]).toBe("2024-10-31");
  });

  it("finds the latest snapshot on or before a date", () => {
    const rows = parseHoldings(readExample("holdings.csv"), config).rows;
    expect(latestSnapshot(rows, "2026-09-30")?.date).toBe("2026-09-30");
    expect(latestSnapshot(rows, "2026-12-31")?.date).toBe("2026-09-30");
    expect(latestSnapshot(rows, "2026-09-29")?.date).toBe("2026-08-31");
    expect(latestSnapshot(rows, "2024-10-30")).toBeNull();
    expect(latestSnapshot(rows, "2026-09-30")?.rows.map((r) => r.line)).toEqual([71, 72, 73]);
  });

  it("names malformed rows and continues", () => {
    const text =
      H +
      "2026-09-30,savings,savings account,cash,1,1,OMR\n" +
      "2026-09-30,savings,savings account,cash,1,1\n" +
      "2026-02-30,savings,savings account,cash,1,1,OMR\n" +
      "2026-09-30,savings,savings account,cash,ten,1,OMR\n" +
      "2026-09-30,savings,savings account,cash,1,1.000.00,OMR\n" +
      "2026-09-30,savings,savings account,cash,1,1,omr\n" +
      "2026-09-30,vault,savings account,cash,1,1,OMR\n" +
      "2026-09-30,savings,savings account,crypto,1,1,OMR\n";
    const p = parseHoldings(text, config);
    expect(p.rows.map((r) => r.line)).toEqual([2]);
    expect(p.invalid.map((r) => [r.line, r.code])).toEqual([
      [3, "BAD-COLUMNS"],
      [4, "BAD-DATE"],
      [5, "BAD-QUANTITY"],
      [6, "BAD-VALUE"],
      [7, "BAD-CURRENCY"],
      [8, "UNKNOWN-ACCOUNT"],
      [9, "UNKNOWN-CLASS"],
    ]);
    expect(p.count).toBe(8);
  });

  it("refuses a wrong header", () => {
    const p = parseHoldings("date,account,asset,quantity,value,currency\n", config);
    expect(p.problems[0]?.code).toBe("BAD-HEADER");
    expect(p.problems[0]?.reason).toContain(HOLDINGS_HEADER);
  });

  it("notes duplicates and appends snapshots", () => {
    const text = H + "2026-09-30,cash,gold coin,gold,1,150.000,OMR\n2026-09-30,cash,gold coin,gold,1,150.000,OMR\n";
    const p = parseHoldings(text, config);
    expect(p.dupNotes).toEqual([{ line: 3, firstLine: 2, text: "2026-09-30,cash,gold coin,gold,1,150.000,OMR" }]);
    const added = appendHoldingLines(text, [{ ...p.rows[0]!, date: "2026-10-31" }]);
    expect(added).toBe(text + "2026-10-31,cash,gold coin,gold,1,150.000,OMR\n");
  });
});
