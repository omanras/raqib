// Loading a household as the CLI's load_household does: counts, problems
// in file order, and the fatal set (exit 3).
import { describe, expect, it } from "vitest";
import { emptyHouseholdText, loadHousehold } from "../../src/engine/household";
import { exampleHousehold, fixtureHousehold } from "./fixtures";

describe("engine/household", () => {
  it("loads the example without a single problem and counts like the CLI", () => {
    const h = loadHousehold(exampleHousehold());
    expect(h.problems).toEqual([]);
    expect(h.fatal).toEqual([]);
    expect(h.files).toEqual({ "policies.yml": 8, "ledger.csv": 271, "holdings.csv": 72, "decisions.yml": 4, "rates.csv": 24 });
    expect(h.config?.baseCurrency).toBe("OMR");
    expect(h.decisions.length).toBe(4);
    expect(h.ctx?.asOf).toBeNull();
  });

  it("counts valid rows only; a row problem is not fatal", () => {
    const t = exampleHousehold();
    t["ledger.csv"] += "2026-10-01,-1,OMR,cash,coffee,,x\n";
    const h = loadHousehold(t);
    expect(h.problems.map((p) => [p.code, `${p.file}:${p.line}`, p.date])).toEqual([["UNKNOWN-CATEGORY", "ledger.csv:273", "2026-10-01"]]);
    expect(h.files["ledger.csv"]).toBe(271);
    expect(h.fatal).toEqual([]);
  });

  it("an absent rates.csv is an empty table and counts as null", () => {
    const h = fixtureHousehold("rules/household");
    expect(h.fatal).toEqual([]);
    expect(h.files).toEqual({ "policies.yml": 12, "ledger.csv": 22, "holdings.csv": 11, "decisions.yml": 0, "rates.csv": null });
    expect(fixtureHousehold("rules/kill").decisions.map((d) => d.id)).toEqual(["D-close"]);
  });

  it("stops on what the CLI cannot read: bad policies, a missing file, an invalid config", () => {
    const broken = fixtureHousehold("rules/broken_policies");
    expect([broken.config, broken.fatal.map((p) => [p.code, p.line])]).toEqual([null, [["BAD-YAML", 4]]]);
    expect(broken.files).toEqual({ "policies.yml": null });
    expect(fixtureHousehold("rules/missing_ledger").fatal.map((p) => [p.file, p.code])).toEqual([["ledger.csv", "FILE-MISSING"]]);
    expect(fixtureHousehold("rules/bad_config").fatal.map((p) => p.code)).toContain("MISSING-FIELD");
    const decisions = fixtureHousehold("rules/decisions");
    expect(decisions.problemsByFile["decisions.yml"]?.map((p) => p.code)).toEqual(["BAD-CLOSES"]);
    expect(decisions.fatal).toEqual([]);
  });

  it("treats a household of absent files as unreadable, not as green", () => {
    const h = loadHousehold(emptyHouseholdText());
    expect(h.fatal.map((p) => [p.file, p.code])).toEqual([["policies.yml", "FILE-MISSING"]]);
    const t = exampleHousehold();
    t["ledger.csv"] = "";
    expect(loadHousehold(t).fatal.map((p) => [p.file, p.code])).toEqual([["ledger.csv", "FILE-EMPTY"]]);
  });
});
