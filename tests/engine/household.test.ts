import { describe, expect, it } from "vitest";
import { emptyHouseholdText, loadHousehold } from "../../src/engine/household";
import { exampleHousehold } from "./fixtures";

describe("engine/household", () => {
  it("loads the example household without a single problem and counts like the CLI", () => {
    const h = loadHousehold(exampleHousehold());
    expect(h.problems).toEqual([]);
    expect(h.files).toEqual({ "policies.yml": 8, "ledger.csv": 271, "holdings.csv": 72, "decisions.yml": 4, "rates.csv": 24 });
    expect(h.policies.config?.baseCurrency).toBe("OMR");
  });

  it("checks the ledger against the declared accounts and categories", () => {
    const t = exampleHousehold();
    t["ledger.csv"] += "2026-10-01,-1,OMR,cash,coffee,,x\n";
    const h = loadHousehold(t);
    expect(h.problems.map((p) => [p.code, p.cite])).toEqual([["UNKNOWN-CATEGORY", "ledger.csv:273"]]);
    expect(h.files["ledger.csv"]).toBe(272);
  });

  it("goes on when policies.yml is unreadable", () => {
    const t = exampleHousehold();
    t["policies.yml"] = "base_currency: [\n";
    const h = loadHousehold(t);
    expect(h.policies.config).toBeNull();
    expect(h.problems[0]?.code).toBe("BAD-YAML");
    expect(h.ledger.rows.length).toBe(271);
    expect(h.files["policies.yml"]).toBe(0);
  });

  it("treats an empty household as problems, not as green", () => {
    const h = loadHousehold(emptyHouseholdText());
    expect(h.problems.map((p) => [p.code, p.file])).toEqual([
      ["EMPTY-FILE", "policies.yml"],
      ["EMPTY-FILE", "ledger.csv"],
      ["EMPTY-FILE", "holdings.csv"],
    ]);
  });
});
