// The review (src/engine/review.ts): its data model on the sample household
// with Decimal expectations computed by hand from reference/examples, the
// pixel helpers, and the page itself, byte for byte against the pages the
// reference CLI wrote (review/cli-reviews.json, from review/generate.py).
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { D } from "../../src/engine/decimal";
import { loadHousehold } from "../../src/engine/household";
import { parsePeriod, type Period } from "../../src/engine/periods";
import { buildReview, esc, f1, niceStep, renderReviewPage, reviewAsOf, ticks } from "../../src/engine/review";
import type { HouseholdText } from "../../src/engine/types";
import type { Measured } from "../../src/engine/measures";
import { sampleHousehold } from "../../src/store/sample";

const h = loadHousehold(sampleHousehold());
const P = (t: string) => parsePeriod(t) as Period;
const amount = (m: Measured) => (m.tag === "value" ? m.amount.toString() : m.tag);

describe("review: the data model", () => {
  const q3 = buildReview(h, P("2026-Q3"), reviewAsOf(P("2026-Q3"), "2026-10-17"));

  it("is as of the period end when it is past, else the date given", () => {
    expect(q3.asOf).toBe("2026-09-30");
    expect(reviewAsOf(P("2026-Q4"), "2026-10-17")).toBe("2026-10-17");
  });

  it("judges the policies at the end of every month of the period", () => {
    expect(q3.columns.map((c) => [c.month.text, c.cut])).toEqual([
      ["2026-07", "2026-07-31"],
      ["2026-08", "2026-08-31"],
      ["2026-09", "2026-09-30"],
    ]);
    expect(q3.columns.map((c) => c.verdicts.find((v) => v.policy.id === "WLT-01")?.verdict)).toEqual(["breach", "hold", "hold"]);
    expect(q3.findings.map((f) => [f.code, f.policy, f.period ?? f.date])).toEqual([
      ["BREACH", "WLT-01", "2026-07"],
      ["DECISION-DUE", null, "2026-09-15"],
    ]);
    const q4 = buildReview(h, P("2026-Q4"), "2026-10-17");
    expect(q4.columns.map((c) => [c.month.text, c.cut])).toEqual([["2026-10", "2026-10-17"]]);
  });

  it("sums income and expense per month over the trailing twelve months", () => {
    expect(q3.months12.map(([m]) => m.text)).toEqual(["2025-10", "2025-11", "2025-12", "2026-01", "2026-02", "2026-03", "2026-04", "2026-05", "2026-06", "2026-07", "2026-08", "2026-09"]);
    const sep = q3.months12[11]!;
    expect(sep[1].tag === "value" && sep[1].amount.eq(D("1200"))).toBe(true);
    // rent 300 + fuel 45 + family 100 + food 112.416 + gift 17.507 + a 1 USD fee at 0.3854
    expect(sep[2].tag === "value" && sep[2].amount.eq(D("575.3084"))).toBe(true);
    const jul = q3.months12[9]!;
    // 300 + 45 + 100 + food 146.726 + cinema 33.492 + phone 125
    expect(jul[2].tag === "value" && jul[2].amount.eq(D("750.218"))).toBe(true);
  });

  it("orders spending by category largest first, and the categories add up to WLT-07", () => {
    expect(q3.spending.map(([c, m]) => [c, amount(m)])).toEqual([
      ["housing", "900"],
      ["food", "374.888"],
      ["family", "300"],
      ["discretionary", "236.933"],
      ["transport", "135"],
      ["fees", "0.3854"],
    ]);
    const total = q3.spending.reduce((s, [, m]) => (m.tag === "value" ? s.plus(m.amount) : s), D("0"));
    expect(total.eq(D("1947.2064"))).toBe(true);
  });

  it("gives every class its value and its share, debt excluded", () => {
    const by = Object.fromEntries(q3.allocation.map(([c, v, s]) => [c, [amount(v), amount(s)]]));
    expect(by["cash"]?.[0]).toBe("10900");
    expect(by["equity"]?.[0]).toBe("551.122"); // 1430 USD at 0.3854
    expect(by["gold"]?.[0]).toBe("150");
    expect(by["equity"]?.[1]).toBe("4.750592227200093232361490552");
    expect(D(by["cash"]?.[1] as string).eq(D("10900").div("11601.122").times(100))).toBe(true);
    expect(by["fund"]).toEqual(["0", "0"]);
  });

  it("collects every cited row once, by file and line", () => {
    expect(q3.rows.holdings.map((r) => r.line)).toEqual([65, 66, 67, 68, 69, 70, 71, 72, 73]);
    expect(q3.rows.rates.map((r) => r.line)).toEqual(expect.arrayContaining([23, 24, 25]));
    const lines = q3.rows.ledger.map((r) => r.line);
    expect([...lines].sort((a, b) => a - b)).toEqual(lines);
    expect(new Set(lines).size).toBe(lines.length);
  });
});

describe("review: pixels and ticks", () => {
  it("formats geometry like Python's '%.1f' (exact binary value, half to even)", () => {
    expect([f1(0.25), f1(0.35), f1(0.45), f1(1.05), f1(2.5), f1(-0.04), f1(0), f1(226), f1(19.2)]).toEqual(["0.2", "0.3", "0.5", "1.1", "2.5", "-0.0", "0.0", "226.0", "19.2"]);
  });

  it("puts ticks at real values from {1, 2, 5} x 10^k", () => {
    expect(niceStep(D("1200")).toString()).toBe("500");
    expect(niceStep(D("900")).toString()).toBe("200");
    expect(niceStep(D("0.3854")).toString()).toBe("0.1");
    expect(niceStep(D("0")).toString()).toBe("1");
    const [t, top] = ticks(D("1200"));
    expect([t.map((x) => x.toString()), top.toString()]).toEqual([["0", "500", "1000", "1500"], "1500"]);
  });

  it("escapes like html.escape(quote=True)", () => {
    expect(esc(`<b>&"'`)).toBe("&lt;b&gt;&amp;&quot;&#x27;");
  });
});

interface Recorded {
  name: string;
  files: HouseholdText;
  reviews: { period: string; as_of: string; page: string }[];
}

const RECORDED = JSON.parse(readFileSync(join(process.cwd(), "tests", "ui", "review", "cli-reviews.json"), "utf8")) as Recorded[];

describe("review: the page is the CLI's, byte for byte", () => {
  it("has the recorded pages", () => {
    expect(RECORDED.reduce((n, c) => n + c.reviews.length, 0)).toBe(17);
  });
  for (const c of RECORDED) {
    const hh = loadHousehold(c.files);
    for (const r of c.reviews) {
      it(`${c.name} ${r.period} as of ${r.as_of}`, () => {
        const period = P(r.period);
        expect(renderReviewPage(buildReview(hh, period, reviewAsOf(period, r.as_of)))).toBe(r.page);
      });
    }
  }
});
