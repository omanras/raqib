import { describe, expect, it } from "vitest";
import { appendDecision, parseDecisions, serializeDecisions } from "../../src/engine/decisions";
import { parsePolicies } from "../../src/engine/policies";
import type { Config, Decision } from "../../src/engine/types";
import { readExample } from "./fixtures";

const config = parsePolicies(readExample("policies.yml")).config as Config;

describe("engine/decisions", () => {
  it("parses the example: 4 decisions at lines 2, 10, 18, 26", () => {
    const p = parseDecisions(readExample("decisions.yml"), config);
    expect(p.problems).toEqual([]);
    expect(p.count).toBe(4);
    expect(p.decisions.map((d) => d.line)).toEqual([2, 10, 18, 26]);
    expect(p.decisions[1]).toEqual({
      line: 10,
      id: "D-2025-12-05",
      date: "2025-12-05",
      title: "broker pilot stopped after the November drawdown; no new money, position kept",
      policy: "WLT-05",
      criteria: "the kill fired on 2025-11-30 (drawdown over 15%); this decision answers it",
      reviewBy: "2026-03-01",
      status: "closed",
      closes: "WLT-05",
    });
    expect(p.decisions[3]?.policy).toBeNull();
    expect(p.decisions[3]?.closes).toBeNull();
  });

  it("round-trips the example semantically", () => {
    const d1 = parseDecisions(readExample("decisions.yml"), config).decisions;
    const text = serializeDecisions(d1);
    const d2 = parseDecisions(text, config).decisions;
    expect(d2.map((d) => ({ ...d, line: null }))).toEqual(d1.map((d) => ({ ...d, line: null })));
    expect(d2.map((d) => d.line)).toEqual([1, 9, 17, 25]);
    expect(text).toContain('  criteria: "stop if drawdown > 15% in any 90 days; review quarterly"\n');
    expect(text).toContain("  policy: null\n");
    expect(text).toContain("  date: 2024-10-01\n");
  });

  it("names a decision it cannot read and continues", () => {
    const text =
      "- id: D-1\n  date: 2026-01-01\n  title: ok\n  policy: null\n  criteria: c\n  review_by: 2026-06-01\n  status: open\n  closes: null\n" +
      "- id: D-2\n  date: 2026-02-30\n  title: bad date\n  review_by: 2026-06-01\n  status: open\n" +
      "- id: D-3\n  date: 2026-01-01\n  title: bad status\n  review_by: 2026-06-01\n  status: pending\n" +
      "- date: 2026-01-01\n  title: no id\n  review_by: 2026-06-01\n  status: open\n" +
      "- id: D-5\n  date: 2026-01-01\n  title: closes a cap\n  review_by: 2026-06-01\n  status: closed\n  closes: WLT-01\n" +
      "- id: D-6\n  date: 2026-01-01\n  title: unknown policy\n  policy: WLT-99\n  review_by: 2026-06-01\n  status: open\n" +
      "- id: D-1\n  date: 2026-01-01\n  title: dup\n  review_by: 2026-06-01\n  status: open\n";
    const p = parseDecisions(text, config);
    expect(p.count).toBe(7);
    expect(p.decisions.map((d) => d.id)).toEqual(["D-1", "D-5", "D-6", "D-1"]);
    expect(p.problems.map((x) => [x.code, x.line])).toEqual([
      ["BAD-DATE", 9],
      ["BAD-STATUS", 14],
      ["BAD-DECISION", 19],
      ["BAD-CLOSES", 23],
      ["BAD-POLICY", 29],
      ["DUP-ID", 35],
    ]);
    expect(p.problems[3]?.reason).toContain("not a kill policy");
  });

  it("accepts an empty file and refuses a mapping", () => {
    expect(parseDecisions("", config)).toEqual({ decisions: [], problems: [], count: 0 });
    expect(parseDecisions("[]\n", config)).toEqual({ decisions: [], problems: [], count: 0 });
    expect(parseDecisions("id: x\n", config).problems[0]?.code).toBe("BAD-FILE");
    expect(parseDecisions("- id: [\n", config).problems[0]?.code).toBe("BAD-YAML");
  });

  it("appends a decision without rewriting the others", () => {
    const d: Decision = { line: null, id: "D-2026-10-01-1", date: "2026-10-01", title: "t", policy: null, criteria: "", reviewBy: "2027-01-01", status: "open", closes: null };
    const block = "- id: D-2026-10-01-1\n  date: 2026-10-01\n  title: t\n  policy: null\n  criteria: \"\"\n  review_by: 2027-01-01\n  status: open\n  closes: null\n";
    expect(appendDecision("", d)).toBe(block);
    expect(appendDecision("[]\n", d)).toBe(block);
    const base = readExample("decisions.yml");
    expect(appendDecision(base, d)).toBe(base + block);
    expect(parseDecisions(appendDecision(base, d), config).decisions.length).toBe(5);
    expect(serializeDecisions([])).toBe("[]\n");
  });
});
