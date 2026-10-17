// holdings.csv loader: tests/test_ledger.py (holdings part) over the CLI's
// fixtures, plus the example household and the serializer.
import { describe, expect, it } from "vitest";
import { appendHoldingLines, HOLDINGS_HEADER, latestSnapshot, parseHoldings, serializeHoldings, snapshotDates } from "../../src/engine/holdings";
import { parsePolicies } from "../../src/engine/policies";
import type { Config, Problem } from "../../src/engine/types";
import { fixture, readExample } from "./fixtures";

const config = parsePolicies(readExample("policies.yml")).config as Config;
const H = HOLDINGS_HEADER + "\n";

function load(name: string) {
  return parseHoldings(fixture(`holdings/${name}`), config, name);
}

function codes(problems: Problem[]): [number, string][] {
  return problems.map((p) => [p.line, p.code]);
}

describe("engine/holdings", () => {
  it("parses the example without problems and round-trips it", () => {
    const text = readExample("holdings.csv");
    const p = parseHoldings(text, config);
    expect(p.problems).toEqual([]);
    expect(p.rows.length).toBe(72);
    const r = p.rows.find((x) => x.line === 72)!;
    expect([r.date, r.account, r.cls, r.quantity.toString(), r.value.toString(), r.valueText, r.currency]).toEqual(["2026-09-30", "broker", "equity", "10", "1430", "1430.00", "USD"]);
    expect(serializeHoldings(p.rows)).toBe(text);
    expect(snapshotDates(p.rows).length).toBe(24);
  });

  it("valid rows and their types", () => {
    const { rows, problems } = load("valid.csv");
    expect(problems).toEqual([]);
    expect(rows.length).toBe(6);
    const r = rows[1]!;
    expect([r.date, r.account, r.asset, r.cls, r.quantity.eq("10.5"), r.value.eq("1234.56"), r.currency, r.line, r.file]).toEqual([
      "2026-01-31",
      "broker",
      "VWRA",
      "fund",
      true,
      true,
      "USD",
      3,
      "valid.csv",
    ]);
    expect(rows[4]?.value.eq("-200.00")).toBe(true);
    expect(rows[4]?.cls).toBe("debt");
  });

  it("finds the latest snapshot on or before a date", () => {
    const { rows } = load("valid.csv");
    expect(snapshotDates(rows)).toEqual(["2025-12-31", "2026-01-31", "2026-02-28"]);
    const snap = latestSnapshot(rows, "2026-02-10");
    expect(snap.date).toBe("2026-01-31");
    expect(snap.rows.map((r) => r.line)).toEqual([2, 3]);
    expect(latestSnapshot(rows, "2026-02-28").rows.map((r) => r.line)).toEqual([4, 5, 6]);
    expect(latestSnapshot(rows, "2030-01-01").date).toBe("2026-02-28");
    expect(latestSnapshot(rows, "2025-12-31").date).toBe("2025-12-31");
    expect(latestSnapshot(rows, "2025-01-01")).toEqual({ date: null, rows: [] });
    expect(latestSnapshot([], "2026-01-01")).toEqual({ date: null, rows: [] });
  });

  it("names every malformed row and continues", () => {
    expect(codes(load("bad_header.csv").problems)).toEqual([[1, "BAD-HEADER"]]);
    expect(codes(load("bad_date.csv").problems)).toEqual([[2, "BAD-DATE"]]);
    expect(codes(load("unknown_account.csv").problems)).toEqual([[2, "UNKNOWN-ACCOUNT"]]);
    const cls = load("unknown_class.csv");
    expect(codes(cls.problems)).toEqual([[2, "UNKNOWN-CLASS"], [3, "UNKNOWN-CLASS"]]);
    expect(cls.rows.map((r) => r.line)).toEqual([4]);
    expect(codes(load("bad_asset.csv").problems)).toEqual([[2, "BAD-ASSET"]]);
    expect(codes(load("bad_quantity.csv").problems)).toEqual([[2, "BAD-QUANTITY"], [3, "BAD-QUANTITY"]]);
    expect(codes(load("bad_value.csv").problems)).toEqual([[2, "BAD-VALUE"], [3, "BAD-VALUE"]]);
    expect(codes(load("bad_currency.csv").problems)).toEqual([[2, "BAD-CURRENCY"]]);
    expect(codes(load("column_count.csv").problems)).toEqual([[2, "COLUMN-COUNT"], [3, "COLUMN-COUNT"]]);
    expect(codes(parseHoldings(null, config, "nope.csv").problems)).toEqual([[0, "FILE-MISSING"]]);
  });

  it("an exact duplicate is a warning; the row stays", () => {
    const { rows, problems } = load("dup_row.csv");
    expect(rows.length).toBe(3);
    expect(codes(problems)).toEqual([[3, "DUP-ROW"]]);
    expect([problems[0]?.class, problems[0]?.dup_of]).toEqual(["warn", 2]);
  });

  it("appends a snapshot without rewriting the rest", () => {
    const text = H + "2026-09-30,cash,gold coin,gold,1,150.000,OMR\n";
    const row = parseHoldings(text, config).rows[0]!;
    expect(appendHoldingLines(text, [{ ...row, date: "2026-10-31" }])).toBe(text + "2026-10-31,cash,gold coin,gold,1,150.000,OMR\n");
    expect(appendHoldingLines(null, [row])).toBe(text);
  });
});
