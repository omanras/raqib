// decisions.yml loader: the decisions parts of the reference engine's
// tests/test_policies.py and tests/test_decisions.py, the example household
// and the serializer.
import { describe, expect, it } from "vitest";
import { appendDecision, daysUntilReview, isDue, loadDecisions, parseDecisions, serializeDecisions, type DecisionFields } from "../../src/engine/decisions";
import { parsePolicies } from "../../src/engine/policies";
import type { Config } from "../../src/engine/types";
import { fixture, readExample } from "./fixtures";

const config = parsePolicies(readExample("policies.yml")).config as Config;
const IDS = new Set(["WLT-01", "WLT-05"]);

function load(name: string, ids: ReadonlySet<string> = IDS, kills: ReadonlySet<string> | null = null) {
  return loadDecisions(fixture(`decisions/${name}`), ids, kills, name);
}

function codes(problems: { line: number; code: string; field?: string }[]): [number, string, string | undefined][] {
  return problems.map((p) => [p.line, p.code, p.field]);
}

describe("engine/decisions: the example household", () => {
  it("4 decisions at lines 2, 10, 18, 26", () => {
    const p = parseDecisions(readExample("decisions.yml"), config);
    expect(p.problems).toEqual([]);
    expect(p.decisions.map((d) => [d.id, d.line, d.cite])).toEqual([
      ["D-2024-10-01", 2, "decisions.yml:2"],
      ["D-2025-12-05", 10, "decisions.yml:10"],
      ["D-2026-01-10", 18, "decisions.yml:18"],
      ["D-2026-06-01", 26, "decisions.yml:26"],
    ]);
    const d = p.decisions[1]!;
    expect([d.date, d.reviewBy, d.status, d.policy, d.closes]).toEqual(["2025-12-05", "2026-03-01", "closed", "WLT-05", "WLT-05"]);
    expect([p.decisions[3]?.policy, p.decisions[3]?.closes]).toEqual([null, null]);
  });

  it("round-trips semantically and appends without rewriting", () => {
    const d1 = parseDecisions(readExample("decisions.yml"), config).decisions;
    const text = serializeDecisions(d1);
    const d2 = parseDecisions(text, config).decisions;
    expect(d2.map((d) => ({ ...d, line: 0, cite: "" }))).toEqual(d1.map((d) => ({ ...d, line: 0, cite: "" })));
    expect(d2.map((d) => d.line)).toEqual([1, 9, 17, 25]);
    expect(text).toContain('  criteria: "stop if drawdown > 15% in any 90 days; review quarterly"\n');
    expect(text).toContain("  policy: null\n  criteria");
    const d: DecisionFields = { id: "D-2026-10-01-1", date: "2026-10-01", title: "t", policy: null, criteria: "", reviewBy: "2027-01-01", status: "open", closes: null };
    const block = '- id: D-2026-10-01-1\n  date: 2026-10-01\n  title: t\n  policy: null\n  criteria: ""\n  review_by: 2027-01-01\n  status: open\n  closes: null\n';
    expect(appendDecision("", d)).toBe(block);
    expect(appendDecision("[]\n", d)).toBe(block);
    expect(appendDecision(null, d)).toBe(block);
    const base = readExample("decisions.yml");
    expect(appendDecision(base, d)).toBe(base + block);
    expect(parseDecisions(appendDecision(base, d), config).decisions.length).toBe(5);
    expect(serializeDecisions([])).toBe("[]\n");
  });
});

describe("engine/decisions: the CLI's fixtures", () => {
  it("valid decisions", () => {
    const { decisions: ds, problems } = load("valid.yml");
    expect(problems).toEqual([]);
    expect(ds.map((d) => d.id)).toEqual(["D-2026-10-01", "D-2025-12-05", "D-min"]);
    const d = ds[0]!;
    expect([d.date, d.reviewBy, d.title, d.policy, d.closes, d.status, d.line, d.file, d.cite]).toEqual([
      "2026-10-01",
      "2027-01-01",
      "start broker pilot with 500 OMR",
      "WLT-05",
      null,
      "open",
      1,
      "valid.yml",
      "valid.yml:1",
    ]);
    expect(d.criteria.startsWith("stop if drawdown")).toBe(true);
    expect([ds[1]?.status, ds[1]?.closes, ds[1]?.date]).toEqual(["closed", "WLT-05", "2025-12-05"]);
    expect([ds[2]?.title, ds[2]?.criteria, ds[2]?.policy]).toEqual(["", "", null]);
  });

  it("each bad field is named; the entry is dropped and the run continues", () => {
    const bad = load("bad_date.yml");
    expect(bad.decisions.map((d) => d.id)).toEqual(["D-5"]);
    expect(codes(bad.problems)).toEqual([
      [1, "BAD-DATE", "decisions[0].date"],
      [6, "BAD-DATE", "decisions[1].review_by"],
      [11, "BAD-DATE", "decisions[2].date"],
      [16, "BAD-DATE", "decisions[3].review_by"],
    ]);
    expect(bad.problems[3]?.reason).toContain("before");
    const pol = load("unknown_policy.yml");
    expect(pol.decisions.map((d) => d.id)).toEqual(["D-3"]);
    expect(codes(pol.problems)).toEqual([
      [1, "UNKNOWN-POLICY", "decisions[0].policy"],
      [7, "UNKNOWN-POLICY", "decisions[1].closes"],
    ]);
    const st = load("bad_status.yml");
    expect(st.decisions.map((d) => d.id)).toEqual(["D-4"]);
    expect(codes(st.problems)).toEqual([
      [1, "BAD-STATUS", "decisions[0].status"],
      [6, "BAD-STATUS", "decisions[1].status"],
      [10, "BAD-STATUS", "decisions[2].status"],
    ]);
    const dup = load("dup_id.yml");
    expect([dup.decisions.map((d) => d.id), dup.decisions[0]?.title]).toEqual([["D-1"], "first"]);
    expect(codes(dup.problems)).toEqual([[6, "DUP-ID", "decisions[1].id"]]);
    const missing = load("missing_fields.yml");
    expect(missing.decisions).toEqual([]);
    expect(codes(missing.problems)).toEqual([
      [1, "BAD-FIELD", "decisions[0].id"],
      [5, "MISSING-FIELD", "decisions[1].date"],
      [5, "MISSING-FIELD", "decisions[1].review_by"],
      [8, "BAD-FIELD", "decisions[2].owner"],
      [14, "BAD-FIELD", "decisions[3].title"],
      [1, "BAD-FIELD", "decisions[4]"],
    ]);
  });

  it("file level: not a list, an empty list, an empty or absent file", () => {
    expect(load("not_a_list.yml").problems.map((p) => [p.line, p.code])).toEqual([[1, "BAD-SHAPE"]]);
    expect(load("empty_list.yml")).toEqual({ decisions: [], problems: [] });
    expect(load("empty.yml").problems.map((p) => [p.line, p.code])).toEqual([[0, "FILE-EMPTY"]]);
    expect(loadDecisions(null, IDS, null, "nope.yml").problems.map((p) => [p.line, p.code])).toEqual([[0, "FILE-MISSING"]]);
  });

  it("closes must name a kill policy when the kills are known", () => {
    const text = fixture("rules/decisions/decisions.yml");
    const ids = new Set(["K1", "CAP-HOLD"]);
    const checked = loadDecisions(text, ids, new Set(["K1"]));
    expect(checked.decisions.map((d) => d.id)).toEqual(["D-due", "D-open", "D-today", "D-close", "D-done"]);
    expect(codes(checked.problems)).toEqual([[28, "BAD-CLOSES", "decisions[4].closes"]]);
    expect(checked.problems[0]?.reason).toContain("not of type kill");
    expect(loadDecisions(text, ids, null).problems).toEqual([]);
    expect(loadDecisions(text, ids, new Set()).problems.map((p) => p.code)).toEqual(["BAD-CLOSES", "BAD-CLOSES"]);
    expect(load("unknown_policy.yml", new Set(["WLT-05"]), new Set(["WLT-05"])).problems.map((p) => p.code)).toEqual(["UNKNOWN-POLICY", "UNKNOWN-POLICY"]);
  });

  it("days to review and due: open and review_by strictly before as-of", () => {
    const ds = loadDecisions(fixture("rules/decisions/decisions.yml"), new Set(["K1", "CAP-HOLD"]), new Set(["K1"])).decisions;
    const due = ds.find((d) => d.id === "D-due")!;
    expect([daysUntilReview(due, "2026-09-30"), isDue(due, "2026-09-30")]).toEqual([-15, true]);
    expect([daysUntilReview(due, "2026-09-15"), isDue(due, "2026-09-15")]).toEqual([0, false]);
    expect([isDue(due, "2026-09-14"), isDue(due, "2026-09-16")]).toEqual([false, true]);
    expect(daysUntilReview(ds.find((d) => d.id === "D-open")!, "2026-09-30")).toBe(93);
    expect(isDue(ds.find((d) => d.id === "D-close")!, "2030-01-01")).toBe(false);
  });
});
