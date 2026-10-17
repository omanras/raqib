// Measures and limits: the reference engine's tests/test_measures.py over
// its hand-computable household (fixtures/qayd/measures):
//   rates: USD 0.385 from 2026-07-01, 0.384 from 2026-07-14, 0.386 from
//   2026-09-01; no EUR or GBP rate.
//   2026-07 income 1000; expense housing 200 + food 50.5 - refund 10
//           + discretionary 20 USD * 0.384 = 7.68  -> 248.18
//   2026-08 income 1000 + 100 side = 1100; expense 200 + 60 = 260
//   2026-09 income 1000 (a +50 row tagged transfer is not income);
//           expense has a 25 EUR row -> Unknown (no rate)
//   holdings 2026-08-31: cash 1600; broker 800 USD + 250 USD at 0.384
//           = 307.2 + 96 = 403.2; debt 500 (excluded from share totals)
//   holdings 2026-09-30: cash 1900; broker (950 + 300) * 0.386 = 482.5;
//           debt 400; gold 100 GBP -> Unknown
//   broker by snapshot: 07-31 (900+200)*0.384 = 422.4; 08-31 403.2;
//           09-30 482.5 -> drawdown on 08-31 = 19.2/422.4 = 4.5454..%
import { describe, expect, it } from "vitest";
import { D, Decimal } from "../../src/engine/decimal";
import { parseHoldings } from "../../src/engine/holdings";
import { parseLedger } from "../../src/engine/ledger";
import { averageMonthlyExpense, endOf, evaluate, expense, income, invalidIn, limitValue, rowsIn, type Context, type Measured, type SeriesPoint } from "../../src/engine/measures";
import { parsePeriod, type Period } from "../../src/engine/periods";
import { parsePolicies, policyById } from "../../src/engine/policies";
import { parseRates } from "../../src/engine/rates";
import type { Config, Measure, Problem } from "../../src/engine/types";
import { citesOf, type Stale, type Unknown, type Value } from "../../src/engine/values";
import { fixture } from "./fixtures";

const config = parsePolicies(fixture("measures/policies.yml")).config as Config;
const ledger = parseLedger(fixture("measures/ledger.csv"), config);
const holdings = parseHoldings(fixture("measures/holdings.csv"), config);
const rates = parseRates(fixture("measures/rates.csv"), "OMR");

function ctx(asOf = "2026-09-30", extra: Partial<Context> = {}): Context {
  return { config, ledger: ledger.rows, holdings: holdings.rows, rates: rates.table, asOf, ledgerProblems: [], holdingsProblems: [], decisions: [], ...extra };
}

function P(text: string): Period {
  return parsePeriod(text) as Period;
}

function val(m: Measured): Value {
  if (m.tag !== "value") throw new Error(`expected a value, got ${JSON.stringify(m)}`);
  return m;
}

function unk(m: Measured): Unknown {
  if (m.tag !== "unknown") throw new Error(`expected unknown, got ${m.tag}`);
  return m;
}

function st(m: Measured): Stale {
  if (m.tag !== "stale") throw new Error(`expected stale, got ${m.tag}`);
  return m;
}

function q4(x: Decimal): string {
  return x.toDecimalPlaces(4, Decimal.ROUND_HALF_EVEN).toString();
}

const SUM_DISC: Measure = { kind: "sum", group: "expense", category: "discretionary", period: "month" };
const SUM_FOOD: Measure = { kind: "sum", group: "expense", category: "food", period: "month" };
const HOLD_CASH: Measure = { kind: "holdings", by: "class", name: "cash" };
const HOLD_BROKER: Measure = { kind: "holdings", by: "account", name: "broker" };
const SHARE_EQUITY: Measure = { kind: "share", by: "class", name: "equity" };
const dd = (name: string, windowDays: number): Measure => ({ kind: "drawdown", by: "account", name, windowDays });
const measureOf = (id: string) => policyById(config, id)!.measure;
const limitOf = (id: string) => policyById(config, id)!.limit;
const problem = (p: Partial<Problem>): Problem => ({ file: "ledger.csv", line: 1, code: "BAD-AMOUNT", class: "invalid", reason: "x", ...p });

describe("engine/measures: sums", () => {
  it("the fixtures load clean", () => {
    expect([ledger.problems, holdings.problems, rates.problems]).toEqual([[], [], []]);
  });

  it("income excludes transfers and cites its rows", () => {
    let v = val(income(ctx(), P("2026-07")));
    expect([v.amount.eq(1000), citesOf(v.rows)]).toEqual([true, ["ledger.csv:2"]]);
    v = val(income(ctx(), P("2026-08")));
    expect([v.amount.eq(1100), citesOf(v.rows)]).toEqual([true, ["ledger.csv:9", "ledger.csv:14"]]);
    v = val(income(ctx(), P("2026-09")));
    expect([v.amount.eq(1000), citesOf(v.rows)]).toEqual([true, ["ledger.csv:15"]]);
    v = val(income(ctx(), P("2026-Q3")));
    expect([v.amount.eq(3100), v.rows.length]).toEqual([true, 4]);
  });

  it("expense is positive, with the refund and the converted foreign row (rate cited after the rows)", () => {
    let v = val(expense(ctx(), P("2026-07")));
    expect(v.amount.eq("248.18")).toBe(true);
    expect(citesOf(v.rows)).toEqual(["ledger.csv:5", "ledger.csv:6", "ledger.csv:7", "ledger.csv:8", "rates.csv:3"]);
    v = val(expense(ctx(), P("2026-08")));
    expect([v.amount.eq(260), citesOf(v.rows)]).toEqual([true, ["ledger.csv:12", "ledger.csv:13"]]);
  });

  it("sums a category or a whole group", () => {
    let v = val(evaluate(SUM_FOOD, ctx(), P("2026-07")));
    expect([v.amount.eq("40.5"), citesOf(v.rows)]).toEqual([true, ["ledger.csv:6", "ledger.csv:8"]]);
    v = val(evaluate(SUM_DISC, ctx(), P("2026-07")));
    expect([v.amount.eq("7.68"), citesOf(v.rows)]).toEqual([true, ["ledger.csv:7", "rates.csv:3"]]);
    expect(val(evaluate(measureOf("M-07"), ctx(), P("2026-08"))).amount.eq(260)).toBe(true);
    expect(val(evaluate(measureOf("M-06"), ctx(), P("2026-Q3"))).amount.eq(3100)).toBe(true);
    v = val(evaluate({ kind: "sum", group: "invest", category: null, period: "month" }, ctx(), P("2026-07")));
    expect([v.amount.isZero(), v.rows]).toEqual([true, []]);
  });

  it("a missing rate makes the measure Unknown, never a partial sum", () => {
    const u = unk(evaluate(SUM_DISC, ctx(), P("2026-09")));
    expect(u.reason).toContain("EUR");
    expect(u.cites).toEqual(["ledger.csv:18"]);
    unk(expense(ctx(), P("2026-Q3")));
    unk(expense(ctx(), P("2026-09")));
  });

  it("nothing after as-of is seen", () => {
    const v = val(evaluate(SUM_DISC, ctx("2026-09-10"), P("2026-09")));
    expect([v.amount.isZero(), v.rows]).toEqual([true, []]);
    unk(evaluate(SUM_DISC, ctx("2026-09-28"), P("2026-09")));
    expect(val(income(ctx("2026-08-10"), P("2026-08"))).amount.eq(1000)).toBe(true);
    expect(rowsIn(ctx("2026-08-10"), P("2026-08"))).toEqual(ledger.rows.filter((r) => r.date >= "2026-08-01" && r.date <= "2026-08-10"));
    expect(endOf(ctx("2026-08-10"), P("2026-08"))).toBe("2026-08-10");
    expect(endOf(ctx("2026-09-30"), P("2026-08"))).toBe("2026-08-31");
    expect(endOf({ asOf: null }, P("2026-08"))).toBe("2026-08-31");
  });

  it("an invalid ledger row poisons its period; an undated one every period; a warning none", () => {
    const dated = [problem({ line: 99, date: "2026-07-03" })];
    const u = unk(income(ctx("2026-09-30", { ledgerProblems: dated }), P("2026-07")));
    expect([u.cites, u.reason.includes("BAD-AMOUNT"), u.cause]).toEqual([["ledger.csv:99"], true, "invalid"]);
    expect(val(income(ctx("2026-09-30", { ledgerProblems: dated }), P("2026-08"))).amount.eq(1100)).toBe(true);
    unk(income(ctx("2026-09-30", { ledgerProblems: dated }), P("2026-Q3")));
    const undated = [problem({ line: 5, code: "COLUMN-COUNT" })];
    unk(income(ctx("2026-09-30", { ledgerProblems: undated }), P("2026-08")));
    const warn = [problem({ line: 5, code: "DUP-ROW", class: "warn", date: "2026-08-03" })];
    expect(val(income(ctx("2026-09-30", { ledgerProblems: warn }), P("2026-08"))).amount.eq(1100)).toBe(true);
    expect(invalidIn([...dated, ...undated], "2026-08-01", "2026-08-31")).toEqual(undated);
  });
});

describe("engine/measures: limits", () => {
  it("absolute and pct", () => {
    expect(val(limitValue({ kind: "value", value: { value: D("2000"), text: "2000" } }, ctx(), P("2026-08")))).toEqual({ tag: "value", amount: D("2000"), rows: [], detail: [] });
    const v = val(limitValue(limitOf("M-03"), ctx(), P("2026-09")));
    expect([v.amount.eq(15), v.rows]).toEqual([true, []]);
  });

  it("pct_of income cites the income rows", () => {
    let v = val(limitValue(limitOf("M-01"), ctx(), P("2026-07")));
    expect([v.amount.eq(100), citesOf(v.rows)]).toEqual([true, ["ledger.csv:2"]]);
    expect(val(limitValue(limitOf("M-01"), ctx(), P("2026-08"))).amount.eq(110)).toBe(true);
    v = val(limitValue({ kind: "pct_of", of: "income", value: { value: D("12.5"), text: "12.5" } }, ctx(), P("2026-08")));
    expect(v.amount.eq("137.5")).toBe(true);
  });

  it("months_of expense averages the complete months that hold rows", () => {
    const v = val(limitValue(limitOf("M-02"), ctx(), P("2026-08")));
    expect([v.amount.eq("1524.54"), v.detail]).toEqual([true, ["2026-07", "2026-08"]]);
    expect(new Set(citesOf(v.rows))).toEqual(new Set(["ledger.csv:5", "ledger.csv:6", "ledger.csv:7", "ledger.csv:8", "rates.csv:3", "ledger.csv:12", "ledger.csv:13"]));
    expect(val(averageMonthlyExpense(ctx(), P("2026-08"))).amount.eq("254.09")).toBe(true);
    unk(limitValue(limitOf("M-02"), ctx(), P("2026-09")));
    const mid = val(limitValue(limitOf("M-02"), ctx("2026-09-10"), P("2026-09")));
    expect([mid.amount.eq("1524.54"), mid.detail]).toEqual([true, ["2026-07", "2026-08"]]);
    const none = unk(limitValue(limitOf("M-02"), ctx("2026-06-30"), P("2026-06")));
    expect(none.reason).toContain("no complete month");
    const bad = [problem({ line: 4, code: "BAD-DATE", date: "2026-07-09" })];
    unk(limitValue(limitOf("M-02"), ctx("2026-09-30", { ledgerProblems: bad }), P("2026-08")));
  });

  it("an undeclared limit or measure is Unknown", () => {
    unk(limitValue(null, ctx(), P("2026-08")));
    unk(evaluate(null, ctx(), P("2026-08")));
  });
});

describe("engine/measures: holdings and share", () => {
  it("holdings as of the period end (cut at as-of)", () => {
    let v = val(evaluate(HOLD_CASH, ctx(), P("2026-09")));
    expect([v.amount.eq(1900), citesOf(v.rows)]).toEqual([true, ["holdings.csv:11"]]);
    v = val(evaluate(HOLD_BROKER, ctx(), P("2026-09")));
    expect([v.amount.eq("482.5"), citesOf(v.rows)]).toEqual([true, ["holdings.csv:12", "holdings.csv:13", "rates.csv:4"]]);
    v = val(evaluate(HOLD_CASH, ctx(), P("2026-08")));
    expect([v.amount.eq(1600), citesOf(v.rows)]).toEqual([true, ["holdings.csv:7"]]);
    expect(val(evaluate(HOLD_CASH, ctx("2026-09-15"), P("2026-09"))).amount.eq(1600)).toBe(true);
    expect(unk(evaluate(measureOf("M-09"), ctx(), P("2026-09"))).cites).toEqual(["holdings.csv:15"]);
    expect(unk(evaluate(HOLD_BROKER, ctx("2026-06-30"), P("2026-06"))).reason).toContain("on or before 2026-06-30");
    expect(val(evaluate(HOLD_CASH, ctx("2026-06-30"), P("2026-06"))).amount.eq(1000)).toBe(true);
  });

  it("no snapshot is Unknown", () => {
    expect(unk(evaluate(HOLD_CASH, ctx("2026-05-31"), P("2026-05"))).reason).toBe("no holdings snapshot on or before 2026-05-31");
    unk(evaluate(SHARE_EQUITY, ctx("2026-05-31"), P("2026-05")));
    unk(evaluate(dd("broker", 90), ctx("2026-05-31"), P("2026-05")));
  });

  it("a stale snapshot carries its age and value; the age limit itself is fine", () => {
    const s = st(evaluate(HOLD_CASH, ctx("2026-11-30"), P("2026-11")));
    expect([s.ageDays, s.date, s.amount?.eq(1900), citesOf(s.rows)]).toEqual([61, "2026-09-30", true, ["holdings.csv:11"]]);
    expect(val(evaluate(HOLD_CASH, ctx("2026-11-14"), P("2026-11"))).amount.eq(1900)).toBe(true);
    expect(st(evaluate(HOLD_CASH, ctx("2026-11-15"), P("2026-11"))).ageDays).toBe(46);
    unk(evaluate(SHARE_EQUITY, ctx("2026-10-20"), P("2026-10")));
    const d = st(evaluate(dd("broker", 90), ctx("2026-11-30"), P("2026-11")));
    expect([d.ageDays, d.amount]).toEqual([61, null]);
  });

  it("without snapshot_max_age_days a holdings measure is Unknown", () => {
    const u = unk(evaluate(HOLD_CASH, { ...ctx(), config: { ...config, snapshotMaxAgeDays: null } }, P("2026-09")));
    expect(u.reason).toContain("snapshot_max_age_days");
  });

  it("an invalid holdings row poisons the snapshot it may belong to", () => {
    const bad = [problem({ file: "holdings.csv", line: 7, code: "BAD-VALUE", date: "2026-08-31" })];
    expect(unk(evaluate(HOLD_CASH, ctx("2026-08-31", { holdingsProblems: bad }), P("2026-08"))).cites).toEqual(["holdings.csv:7"]);
    expect(val(evaluate(HOLD_CASH, ctx("2026-09-30", { holdingsProblems: bad }), P("2026-09"))).amount.eq(1900)).toBe(true);
    expect(val(evaluate(HOLD_CASH, ctx("2026-07-31", { holdingsProblems: bad }), P("2026-07"))).amount.eq(1300)).toBe(true);
    unk(evaluate(HOLD_CASH, ctx("2026-09-15", { holdingsProblems: bad }), P("2026-09")));
    const undated = [problem({ file: "holdings.csv", line: 3, code: "COLUMN-COUNT" })];
    unk(evaluate(HOLD_CASH, ctx("2026-09-30", { holdingsProblems: undated }), P("2026-09")));
    unk(evaluate(HOLD_CASH, ctx("2026-05-31", { holdingsProblems: undated }), P("2026-05")));
  });

  it("share excludes debt from the total", () => {
    const v = val(evaluate(SHARE_EQUITY, ctx("2026-08-31"), P("2026-08")));
    expect(v.amount.eq(D("96").div("2003.2").times(100))).toBe(true);
    expect(q4(v.amount)).toBe("4.7923");
    expect(new Set(citesOf(v.rows))).toEqual(new Set(["holdings.csv:7", "holdings.csv:8", "holdings.csv:9", "rates.csv:3"]));
    expect(q4(val(evaluate({ kind: "share", by: "class", name: "cash" }, ctx("2026-08-31"), P("2026-08"))).amount)).toBe(q4(D("1600").div("2003.2").times(100)));
    expect(val(evaluate({ kind: "share", by: "class", name: "property" }, ctx("2026-08-31"), P("2026-08"))).amount.isZero()).toBe(true);
    unk(evaluate(SHARE_EQUITY, ctx(), P("2026-09")));
    const onlyDebt = holdings.rows.filter((r) => r.cls === "debt");
    expect(unk(evaluate(SHARE_EQUITY, ctx("2026-09-30", { holdings: onlyDebt }), P("2026-09"))).reason).toContain("zero");
  });
});

describe("engine/measures: drawdown", () => {
  it("the series carries the running peak inside the window", () => {
    let v = val(evaluate(dd("broker", 90), ctx(), P("2026-09")));
    expect(v.amount.isZero()).toBe(true);
    const series = v.detail as SeriesPoint[];
    expect(series.map((x) => x[0])).toEqual(["2026-07-31", "2026-08-31", "2026-09-30"]);
    expect(series.map((x) => x[1].toString())).toEqual(["422.4", "403.2", "482.5"]);
    expect(series[1]?.[2]?.eq(D("19.2").div("422.4").times(100))).toBe(true);
    expect(q4(series[1]?.[2] as Decimal)).toBe("4.5455");
    expect(["rates.csv:3", "rates.csv:4", "holdings.csv:5"].every((c) => citesOf(v.rows).includes(c))).toBe(true);
    v = val(evaluate(dd("broker", 40), ctx("2026-08-31"), P("2026-08")));
    expect([q4(v.amount), v.detail.length]).toEqual(["4.5455", 2]);
    v = val(evaluate(dd("broker", 10), ctx(), P("2026-09")));
    expect([v.amount.isZero(), v.detail.length]).toEqual([true, 1]);
  });

  it("Unknown cases: no rate in the window, no rows, no snapshot in the window, a foreign row, a bad row", () => {
    expect(unk(evaluate(dd("broker", 90), ctx("2026-08-31"), P("2026-08"))).cites).toEqual(["holdings.csv:3"]);
    expect(unk(evaluate(dd("salary", 60), ctx(), P("2026-09"))).reason).toContain("not positive");
    expect(unk(evaluate(dd("broker", 20), ctx("2026-10-30"), P("2026-10"))).reason).toContain("within 20 days");
    expect(unk(evaluate(dd("cash", 60), ctx(), P("2026-09"))).cites).toEqual(["holdings.csv:15"]);
    const bad = [problem({ file: "holdings.csv", line: 5, code: "BAD-VALUE", date: "2026-07-31" })];
    unk(evaluate(dd("broker", 90), ctx("2026-09-30", { holdingsProblems: bad }), P("2026-09")));
    expect(val(evaluate(dd("broker", 40), ctx("2026-09-30", { holdingsProblems: bad }), P("2026-09"))).amount.isZero()).toBe(true);
  });

  it("counts every position of the account, debt included at its sign", () => {
    const noGold = holdings.rows.filter((r) => r.cls !== "gold");
    const v = val(evaluate(dd("cash", 60), ctx("2026-09-30", { holdings: noGold }), P("2026-09")));
    expect(v.amount.eq(20)).toBe(true);
    expect((v.detail as SeriesPoint[]).map((x) => x[1].toString())).toEqual(["500", "400"]);
  });
});
