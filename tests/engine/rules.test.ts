// Verdicts: the reference engine's tests/test_rules.py over its households
// (fixtures/qayd/rules): a holding and a breaching case for every rule
// type, the kill that persists until a later closing decision, a backdated
// closing decision, missing rates, stale snapshots, and the silence findings.
import { describe, expect, it } from "vitest";
import { D } from "../../src/engine/decimal";
import { finding } from "../../src/engine/findings";
import type { Context } from "../../src/engine/measures";
import { policyById } from "../../src/engine/policies";
import { check, isGreen, matchRows, order, verdict, verdictCites, type Verdict } from "../../src/engine/rules";
import type { Match, Policy } from "../../src/engine/types";
import { fixtureHousehold } from "./fixtures";

function ctxOf(name: string): Context {
  const h = fixtureHousehold(`rules/${name}`);
  expect(h.fatal).toEqual([]);
  return h.ctx as Context;
}

function verdicts(name: string, asOf = "2026-09-30") {
  const r = check(ctxOf(name), asOf);
  return { byId: Object.fromEntries(r.verdicts.map((v) => [v.policy.id, v])) as Record<string, Verdict>, findings: r.findings, all: r.verdicts };
}

function verdictOf(name: string, id: string, asOf = "2026-09-30"): Verdict {
  const c = ctxOf(name);
  return verdict(policyById(c.config, id) as Policy, c, asOf);
}

function amount(v: Verdict, side: "measure" | "limit"): string {
  const x = v[side];
  if (x === null || x.tag === "unknown" || x.amount === null) throw new Error(`no ${side} amount`);
  return x.amount.toString();
}

const match = (m: Partial<Match>): Match => ({ tags: null, tagsAny: null, account: null, category: null, minAmount: null, ...m });

describe("engine/rules: cap, floor, allocation", () => {
  it("a cap holds and breaches; the breach cites the measure rows, then the income rows", () => {
    let v = verdictOf("household", "CAP-HOLD");
    expect([v.verdict, v.findings, amount(v, "measure"), amount(v, "limit"), v.period?.text, verdictCites(v)]).toEqual(["hold", [], "40", "100", "2026-09", ["ledger.csv:22"]]);
    v = verdictOf("household", "CAP-BREACH");
    expect([v.verdict, amount(v, "measure"), amount(v, "limit"), verdictCites(v)]).toEqual(["breach", "15", "10", ["ledger.csv:23", "ledger.csv:19"]]);
    const f = v.findings[0]!;
    expect([v.findings.map((x) => x.code), f.cls, f.policy, f.period, f.cites]).toEqual([["BREACH"], "red", "CAP-BREACH", "2026-09", ["ledger.csv:23", "ledger.csv:19"]]);
    expect(f.reason).toContain("exceeds");
  });

  it("a cap equal to its limit holds", () => {
    expect(verdictOf("household", "CAP-HOLD", "2026-05-31").verdict).toBe("hold");
    const c = ctxOf("household");
    const p = policyById(c.config, "CAP-HOLD") as Policy;
    expect(verdict({ ...p, limit: { kind: "value", value: { value: D("40"), text: "40" } } }, c, "2026-09-30").verdict).toBe("hold");
    expect(verdict({ ...p, limit: { kind: "value", value: { value: D("39.999"), text: "39.999" } } }, c, "2026-09-30").verdict).toBe("breach");
  });

  it("a floor holds and breaches", () => {
    let v = verdictOf("household", "FLOOR-HOLD");
    expect([v.verdict, amount(v, "measure"), verdictCites(v)]).toEqual(["hold", "1900", ["holdings.csv:10"]]);
    v = verdictOf("household", "FLOOR-BREACH");
    expect([v.verdict, amount(v, "measure"), amount(v, "limit"), v.findings[0]?.code]).toEqual(["breach", "1000", "2000", "BREACH"]);
    expect(v.reason).toContain("below");
  });

  it("an allocation inside and outside its band", () => {
    let v = verdictOf("household", "ALLOC-HOLD");
    expect(v.verdict).toBe("hold");
    expect(v.measure?.tag === "value" && v.measure.amount.eq(D("1900").div("2450").times(100))).toBe(true);
    v = verdictOf("household", "ALLOC-BREACH");
    expect(v.verdict).toBe("breach");
    expect(v.measure?.tag === "value" && v.measure.amount.eq(D("100").div("2450").times(100))).toBe(true);
    expect(v.reason).toContain("outside 20%..50%");
    expect(new Set(verdictCites(v))).toEqual(new Set(["holdings.csv:10", "holdings.csv:11", "holdings.csv:12"]));
  });
});

describe("engine/rules: red line and routine", () => {
  it("a red line holds when no row ever matches", () => {
    const v = verdictOf("household", "RED-HOLD");
    expect([v.verdict, v.period, v.rows, amount(v, "measure")]).toEqual(["hold", null, [], "0"]);
  });

  it("a red line breaches citing every matching row ever, and only from the day it exists", () => {
    const v = verdictOf("household", "RED-BREACH");
    expect([v.verdict, verdictCites(v), v.findings[0]?.code, v.findings[0]?.cites, v.findings[0]?.period]).toEqual(["breach", ["ledger.csv:6"], "BREACH", ["ledger.csv:6"], null]);
    expect(verdictOf("household", "RED-BREACH", "2026-05-09").verdict).toBe("hold");
    expect(verdictOf("household", "RED-BREACH", "2026-05-10").verdict).toBe("breach");
  });

  it("matching: every tag, any tag, account, category, |amount| >= min_amount", () => {
    const c = ctxOf("household");
    const rows = [...c.ledger];
    let r = matchRows(match({ tags: ["transfer"], account: "savings" }), rows, c);
    expect([r.matched.length, r.matched.every((x) => x.account === "savings"), r.undecided]).toEqual([5, true, []]);
    expect(matchRows(match({ tags: ["transfer"], account: "savings", minAmount: { value: D("300.001"), text: "300.001" } }), rows, c).matched).toEqual([]);
    r = matchRows(match({ category: "discretionary", minAmount: { value: D("200"), text: "200" } }), rows, c);
    expect(r.matched.map((x) => x.line)).toEqual([6]);
    expect(matchRows(match({ tagsAny: ["margin", "transfer"] }), rows, c).matched.length).toBe(10);
    expect(matchRows(match({ tags: ["transfer", "margin"] }), rows, c).matched).toEqual([]);
  });

  it("a routine holds with its row and is missing without; silence is red before the row of the month", () => {
    let v = verdictOf("household", "ROUT-HOLD");
    expect([v.verdict, verdictCites(v), v.period?.text]).toEqual(["hold", ["ledger.csv:21"], "2026-09"]);
    v = verdictOf("household", "ROUT-MISS");
    expect([v.verdict, v.period?.text, v.findings.map((f) => f.code), v.findings[0]?.period, v.findings[0]?.cites]).toEqual(["missing", "2026-Q3", ["ROUTINE-MISSING"], "2026-Q3", []]);
    expect(verdictOf("household", "ROUT-HOLD", "2026-09-02").verdict).toBe("missing");
  });
});

describe("engine/rules: kill", () => {
  it("crosses, persists until a decision dated after the crossing, then kills again on a new crossing", () => {
    let v = verdictOf("kill", "K1", "2026-08-31");
    expect(v.verdict).toBe("kill");
    expect(new Set(verdictCites(v))).toEqual(new Set(["holdings.csv:8", "holdings.csv:9", "holdings.csv:5", "holdings.csv:6"]));
    expect([v.findings[0]?.code, v.findings[0]?.date]).toEqual(["KILL", "2026-08-31"]);
    expect(v.reason).toContain("crossed 5%");
    expect(v.reason).toContain("peak 500 OMR on 2026-07-31");
    expect(verdictOf("kill", "K1", "2026-09-04").verdict).toBe("kill");
    v = verdictOf("kill", "K1", "2026-09-05");
    expect([v.verdict, v.findings, v.reason]).toEqual(["hold", [], "kill of 2026-08-31 closed by D-close (2026-09-05)"]);
    expect(verdictOf("kill", "K1", "2026-09-30").verdict).toBe("hold");
    v = verdictOf("kill", "K1", "2026-10-31");
    expect([v.verdict, v.findings[0]?.date]).toEqual(["kill", "2026-10-31"]);
    expect(v.measure?.tag === "value" && v.measure.amount.eq(D("100").div("550").times(100))).toBe(true);
    v = verdictOf("kill", "K1", "2026-07-31");
    expect([v.verdict, v.reason]).toEqual(["hold", null]);
  });

  it("a decision dated before the crossing closes nothing", () => {
    const v = verdictOf("kill_backdated", "K1", "2026-09-30");
    expect([v.verdict, v.findings[0]?.date]).toEqual(["kill", "2026-08-31"]);
  });

  it("holds while the threshold is never crossed", () => {
    const v = verdictOf("household", "KILL-HOLD");
    expect([v.verdict, amount(v, "measure"), amount(v, "limit")]).toEqual(["hold", "0", "50"]);
    expect(verdictOf("household", "KILL-BREACH").verdict).toBe("kill");
  });
});

describe("engine/rules: silence (A3), unknown and invalid", () => {
  it("an empty period makes ledger-based policies missing; holdings do not care", () => {
    let r = verdicts("empty_period");
    expect([r.byId["CAP-M"]?.verdict, r.byId["CAP-M"]?.findings[0]?.code, r.byId["CAP-M"]?.findings[0]?.period, r.byId["CAP-M"]?.findings[0]?.cites]).toEqual(["missing", "EMPTY-PERIOD", "2026-09", []]);
    expect([r.byId["ROUT-M"]?.verdict, r.byId["ROUT-M"]?.findings[0]?.code]).toEqual(["missing", "EMPTY-PERIOD"]);
    expect([r.byId["CAP-Q"]?.verdict, amount(r.byId["CAP-Q"]!, "measure")]).toEqual(["hold", "80"]);
    expect(r.byId["FLOOR-H"]?.verdict).toBe("hold");
    expect(r.findings.map((f) => f.code)).toEqual(["EMPTY-PERIOD", "EMPTY-PERIOD"]);
    expect(isGreen(r.all, r.findings)).toBe(false);
    r = verdicts("empty_period", "2026-08-31");
    expect([new Set(r.all.map((v) => v.verdict)), r.findings]).toEqual([new Set(["hold"]), []]);
  });

  it("a stale snapshot makes holdings-based policies stale; the age limit itself still holds", () => {
    let r = verdicts("stale");
    for (const id of ["FLOOR-H", "ALLOC", "K1"]) {
      const v = r.byId[id]!;
      expect([v.verdict, v.findings[0]?.code, v.findings[0]?.date], id).toEqual(["stale", "STALE-SNAPSHOT", "2026-07-31"]);
      expect(v.reason).toContain("61 days old; 45 allowed");
    }
    expect(r.byId["FLOOR-H"]?.measure?.tag === "stale" && r.byId["FLOOR-H"]?.measure.amount?.eq(1300)).toBe(true);
    expect(r.byId["CAP-M"]?.verdict).toBe("hold");
    expect(r.byId["K1"]?.findings[0]?.cites).toEqual(["holdings.csv:5"]);
    r = verdicts("stale", "2026-09-14");
    expect(new Set(r.all.map((v) => v.verdict))).toEqual(new Set(["hold"]));
  });

  it("an invalid row makes the policies it touches invalid and is a red finding", () => {
    let r = verdicts("invalid_rows");
    expect([r.byId["CAP-SEP"]?.verdict, r.byId["CAP-SEP"]?.findings[0]?.code, r.byId["CAP-SEP"]?.findings[0]?.cites]).toEqual(["invalid", "INVALID", ["ledger.csv:14"]]);
    expect([r.byId["CAP-Q"]?.verdict, r.byId["RED"]?.verdict, r.byId["ROUT"]?.verdict]).toEqual(["invalid", "invalid", "hold"]);
    expect(r.byId["CAP-SEP"]?.measure?.tag === "unknown" && r.byId["CAP-SEP"]?.measure.cause).toBe("invalid");
    expect(r.findings.filter((f) => f.policy === null).map((f) => [f.code, f.cls, f.cites])).toEqual([
      ["BAD-AMOUNT", "red", ["ledger.csv:14"]],
      ["DUP-ROW", "warn", ["ledger.csv:16"]],
    ]);
    r = verdicts("invalid_rows", "2026-08-31");
    expect([r.byId["CAP-SEP"]?.verdict, r.byId["RED"]?.verdict]).toEqual(["hold", "hold"]);
    expect(r.findings.filter((f) => f.policy === null).map((f) => f.code)).toEqual(["BAD-AMOUNT", "DUP-ROW"]);
    expect(verdictOf("invalid_rows", "RED", "2026-09-16").verdict).toBe("invalid");
  });

  it("a foreign row without a rate is unknown (A5), and so is an undeclared shape", () => {
    let v = verdictOf("invalid_rows", "CAP-FX", "2026-08-31");
    expect([v.verdict, v.measure?.tag, v.measure?.tag === "unknown" && v.measure.cause, v.findings[0]?.code, verdictCites(v), v.findings[0]?.cites]).toEqual([
      "unknown",
      "unknown",
      "unknown",
      "UNKNOWN",
      [],
      ["ledger.csv:17"],
    ]);
    v = verdictOf("invalid_rows", "SHAPE");
    expect([v.verdict, v.measure, v.findings[0]?.code, v.findings[0]?.cites]).toEqual(["unknown", null, "UNKNOWN", ["policies.yml:21"]]);
    expect(v.reason).toContain("not declared");
  });
});

describe("engine/rules: order and green", () => {
  it("reds first in file order; green is strict; a warning alone keeps it green", () => {
    const r = verdicts("household");
    const ordered = order(r.all);
    expect(ordered.slice(0, 6).map((v) => v.verdict)).toEqual(["breach", "breach", "missing", "breach", "kill", "breach"]);
    expect(ordered.slice(6).every((v) => v.verdict === "hold")).toBe(true);
    expect(isGreen(r.all, r.findings)).toBe(false);
    const g = verdicts("green");
    expect([isGreen(g.all, g.findings), g.findings]).toEqual([true, []]);
    const warn = finding("DUP-ROW", null, "dup", ["ledger.csv:3"], { cls: "warn" });
    expect(isGreen(g.all, [warn])).toBe(true);
    expect(isGreen(g.all, [{ ...warn, cls: "red", code: "BAD-AMOUNT" }])).toBe(false);
  });
});
