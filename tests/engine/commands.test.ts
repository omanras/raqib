// The three commands as the app calls them. The CLI's own output is checked
// byte for byte in tests/differential; here: what the CLI never prints (the
// JSON of an unreadable household), exit codes and the summary lines.
import { describe, expect, it } from "vitest";
import { buildCheck, check, checkText, decisions, decisionsText, EXIT_FILE, EXIT_GREEN, EXIT_RED, fatalText, routine, routineText } from "../../src/engine/commands";
import { decisionFindings } from "../../src/engine/findings";
import { loadHousehold } from "../../src/engine/household";
import { parsePeriod, type Period } from "../../src/engine/periods";
import { jsonText, summaryLine, verdictLine } from "../../src/engine/report";
import { exampleHousehold, fixtureHousehold } from "./fixtures";

const example = loadHousehold(exampleHousehold());

describe("engine/commands", () => {
  it("check of the example: the planted facts and the CLI's summary lines", () => {
    expect(checkText(example, "2026-09-30")).toMatchObject({ exit: EXIT_RED });
    expect(checkText(example, "2026-09-30").text.trimEnd().split("\n").pop()).toBe("RED as of 2026-09-30: 8 of 8 policies hold, 1 red finding, 0 warnings");
    expect(checkText(example, "2026-09-14")).toMatchObject({ exit: EXIT_GREEN });
    expect(summaryLine(buildCheck(example, "2026-09-14"))).toBe("GREEN as of 2026-09-14: 8 of 8 policies hold, 0 red findings, 0 warnings");
    const july = buildCheck(example, "2026-07-31");
    expect(verdictLine(july.verdicts[0]!, "OMR", "2026-07-31")).toBe(
      "breach   WLT-01     discretionary spending per month  158.492 OMR vs 120 OMR (10% of income) [2026-07]  -- sum expense.discretionary per month = 158.492 OMR exceeds 120 OMR",
    );
    expect(check(example, "2026-03-31").policies[0]?.verdict).toBe("missing");
    expect(check(example, "2025-11-30").policies[0]).toMatchObject({ id: "WLT-05", verdict: "kill" });
    expect(check(example, "2025-12-31").policies.find((p) => p.id === "WLT-05")).toMatchObject({ verdict: "hold", reason: "kill of 2025-11-30 closed by D-2025-12-05 (2025-12-05)" });
  });

  it("routine and decisions of the example", () => {
    const march = parsePeriod("2026-03") as Period;
    expect(routine(example, march, "2026-10-17").all_done).toBe(false);
    expect(routineText(example, march, "2026-10-17").text.trimEnd().split("\n").pop()).toBe("MISSING routine 2026-03 as of 2026-10-17: 1 of 2 done");
    expect(routineText(example, parsePeriod("2026-09") as Period, "2026-09-30").exit).toBe(EXIT_GREEN);
    expect(decisions(example, "2026-09-30").due).toBe(true);
    expect(decisionsText(example, "2026-09-14")).toMatchObject({ exit: EXIT_GREEN });
    expect(decisionFindings(example.decisions, "2026-12-31").map((f) => f.reason)).toEqual(["decision D-2026-06-01 is open and its review date 2026-09-15 is 107 days past"]);
  });

  it("an unreadable household is never green: no verdicts, every fatal problem a red finding", () => {
    const h = fixtureHousehold("rules/broken_policies");
    expect(checkText(h, "2026-09-30").exit).toBe(EXIT_FILE);
    expect(fatalText(h)).toMatch(/^qayd: cannot read or parse the household files:\n {2}policies\.yml:4 BAD-YAML: YAML error: /);
    const j = check(h, "2026-09-30");
    expect([j.green, j.policies, j.base_currency, j.files]).toEqual([false, [], null, { "policies.yml": null }]);
    expect(j.findings.map((f) => [f.code, f.class, f.cites])).toEqual([["BAD-YAML", "red", ["policies.yml:4"]]]);
    expect(j.problems.map((p) => p.code)).toEqual(["BAD-YAML"]);
    expect(routine(h, parsePeriod("2026-09") as Period, "2026-09-30")).toMatchObject({ all_done: false, routines: [] });
    expect(decisions(h, "2026-09-30")).toMatchObject({ due: true, decisions: [] });
    const missing = fixtureHousehold("rules/missing_ledger");
    expect(check(missing, "2026-09-30").findings.map((f) => [f.code, f.cites])).toEqual([["FILE-MISSING", ["ledger.csv"]]]);
    expect(fatalText(missing)).toBe("qayd: cannot read or parse the household files:\n  ledger.csv FILE-MISSING: file not found: ledger.csv\n");
  });

  it("JSON text is the CLI's: indent 2, ASCII only, a final newline", () => {
    expect(jsonText({ a: ["x"], b: null })).toBe('{\n  "a": [\n    "x"\n  ],\n  "b": null\n}\n');
    const BACKSLASH = String.fromCharCode(92);
    expect(jsonText({ note: "caf" + String.fromCharCode(0xe9) })).toBe(`{\n  "note": "caf${BACKSLASH}u00e9"\n}\n`);
  });
});
