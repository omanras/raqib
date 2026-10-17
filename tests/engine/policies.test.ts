import { describe, expect, it } from "vitest";
import { bandText, limitText, matchText, measureText, parsePolicies, serializePolicies } from "../../src/engine/policies";
import type { Config, Policy } from "../../src/engine/types";
import { readExample } from "./fixtures";

const example = readExample("policies.yml");

function byId(config: Config, id: string): Policy {
  const p = config.policies.find((x) => x.id === id);
  if (!p) throw new Error(`no policy ${id}`);
  return p;
}

function withPolicy(block: string): ReturnType<typeof parsePolicies> {
  const head = example.slice(0, example.indexOf("policies:")) + "policies:\n";
  return parsePolicies(head + block);
}

describe("engine/policies", () => {
  it("parses the example: 8 accepted policies, base OMR, line numbers", () => {
    const p = parsePolicies(example);
    expect(p.problems).toEqual([]);
    expect(p.count).toBe(8);
    const c = p.config as Config;
    expect(c.baseCurrency).toBe("OMR");
    expect(c.version).toBe("1");
    expect(c.accounts).toEqual(["salary", "savings", "broker", "cash"]);
    expect(Object.keys(c.categories)).toEqual(["income", "expense", "transfer", "invest"]);
    expect(c.categories["expense"]).toEqual(["housing", "food", "transport", "family", "discretionary", "fees"]);
    expect(c.classes).toEqual(["cash", "equity", "fund", "property", "gold", "debt", "other"]);
    expect(c.snapshotMaxAgeDays).toBe(45);
    expect(c.policies.map((x) => x.status)).toEqual(["ok", "ok", "ok", "ok", "ok", "ok", "ok", "ok"]);
    expect(c.policies.map((x) => x.line)).toEqual([12, 17, 22, 27, 31, 36, 41, 46]);
  });

  it("prints declared texts exactly as the oracle does", () => {
    const c = parsePolicies(example).config as Config;
    const w1 = byId(c, "WLT-01");
    expect(measureText(w1.measure!)).toBe("sum expense.discretionary per month");
    expect(limitText(w1.limit!, "OMR")).toBe("10% of income");
    const w2 = byId(c, "WLT-02");
    expect(measureText(w2.measure!)).toBe("holdings class.cash");
    expect(limitText(w2.limit!, "OMR")).toBe("6 months of expense");
    expect(matchText(byId(c, "WLT-03").match!)).toBe("tags transfer, account savings, amount >= 300");
    expect(byId(c, "WLT-03").period).toBe("month");
    expect(matchText(byId(c, "WLT-04").match!)).toBe("any tag of margin,options");
    const w5 = byId(c, "WLT-05");
    expect(measureText(w5.measure!)).toBe("drawdown account.broker over 90 days");
    expect(limitText(w5.limit!, "OMR")).toBe("15%");
    const w6 = byId(c, "WLT-06");
    expect(measureText(w6.measure!)).toBe("share class.equity");
    expect(bandText(w6.band!)).toBe("2%..30%");
    const w7 = byId(c, "WLT-07");
    expect(measureText(w7.measure!)).toBe("sum expense per quarter");
    expect(limitText(w7.limit!, "OMR")).toBe("2400 OMR");
    expect(matchText(byId(c, "WLT-08").match!)).toBe("category housing, amount >= 250");
  });

  it("keeps an unknown type, measure, limit or combination with the reason (A3/A5)", () => {
    const cases: [string, string][] = [
      ["  - id: X-1\n    type: ceiling\n    title: t\n", 'unknown type "ceiling"'],
      ["  - id: X-2\n    type: cap\n    title: t\n    measure: {median: expense, period: month}\n    limit: {value: 1}\n", "exactly one of sum, holdings, share, drawdown"],
      ["  - id: X-3\n    type: cap\n    title: t\n    measure: {sum: expense.discretionary, period: week}\n    limit: {value: 1}\n", 'unknown period "week"'],
      ["  - id: X-4\n    type: cap\n    title: t\n    measure: {sum: expense.discretionary}\n    limit: {value: 1}\n", "needs a period"],
      ["  - id: X-5\n    type: cap\n    title: t\n    measure: {sum: expense.coffee, period: month}\n    limit: {value: 1}\n", 'unknown category "coffee"'],
      ["  - id: X-6\n    type: cap\n    title: t\n    measure: {sum: expense, period: month}\n    limit: {pct: 10}\n", "do not compare"],
      ["  - id: X-7\n    type: cap\n    title: t\n    measure: {sum: expense, period: month}\n    limit: {ratio: 10}\n", "unknown limit"],
      ["  - id: X-8\n    type: floor\n    title: t\n    measure: {holdings: class.crypto}\n    limit: {value: 1}\n", 'unknown class "crypto"'],
      ["  - id: X-9\n    type: routine\n    title: t\n    match: {tags: transfer}\n", "needs a period"],
      ["  - id: X-10\n    type: routine\n    title: t\n    match: {weekday: monday}\n    period: month\n", "unknown key weekday"],
      ["  - id: X-11\n    type: red_line\n    title: t\n    match: {}\n", "at least one of"],
      ["  - id: X-12\n    type: kill\n    title: t\n    measure: {drawdown: account.broker}\n    limit: {pct: 15}\n", "window_days"],
      ["  - id: X-13\n    type: allocation\n    title: t\n    measure: {holdings: class.equity}\n    band: {min_pct: 2, max_pct: 30}\n", "needs a share measure"],
      ["  - id: X-14\n    type: allocation\n    title: t\n    measure: {share: class.equity}\n    band: {min_pct: 40, max_pct: 30}\n", "must not exceed"],
      ["  - type: cap\n    title: t\n    measure: {sum: expense, period: month}\n    limit: {value: 1}\n", "no id"],
      ["  - id: X-16\n    type: cap\n    title: t\n    measure: {sum: expense, period: month}\n    limit: {value: \"1,5\"}\n", "decimal text"],
    ];
    for (const [block, reason] of cases) {
      const p = withPolicy(block);
      expect(p.config, block).not.toBeNull();
      const pol = (p.config as Config).policies[0] as Policy;
      expect(pol.status, block).toBe("unknown");
      expect(pol.reason, block).toContain(reason);
      expect(p.problems.map((x) => x.code), block).toEqual(["UNKNOWN-POLICY"]);
      expect(p.count).toBe(1);
    }
  });

  it("reports duplicate ids and file-level faults", () => {
    const dup = withPolicy("  - id: A\n    type: red_line\n    title: t\n    match: {tags: margin}\n  - id: A\n    type: red_line\n    title: t\n    match: {tags: margin}\n");
    expect(dup.problems.map((x) => x.code)).toEqual(["DUP-ID"]);
    expect(parsePolicies("version: 1\naccounts: [a]\n").problems[0]?.code).toBe("BAD-BASE-CURRENCY");
    expect(parsePolicies("- a\n- b\n").problems[0]?.code).toBe("BAD-FILE");
    expect(parsePolicies("base_currency: OMR\naccounts: [a\n").problems[0]?.code).toBe("BAD-YAML");
    const noAge = parsePolicies("base_currency: OMR\naccounts: [a]\ncategories: {expense: [x]}\npolicies: []\n");
    expect(noAge.config?.snapshotMaxAgeDays).toBeNull();
    expect(noAge.problems.map((x) => x.code)).toEqual(["NO-SNAPSHOT-AGE"]);
    expect(parsePolicies("base_currency: OMR\nsnapshot_max_age_days: 45\npolicies: []\n").config?.accounts).toEqual([]);
  });

  it("keeps scalars as text: value 10 is decimal text, never a JS number (A5)", () => {
    const c = parsePolicies(example).config as Config;
    const l = byId(c, "WLT-01").limit;
    expect(l?.kind).toBe("pct_of");
    expect(l?.kind === "pct_of" && l.value.toString()).toBe("10");
    expect(byId(c, "WLT-01").raw["limit"]).toEqual({ pct_of: "income", value: "10" });
  });

  it("serialises the example semantically round-trip", () => {
    const c1 = parsePolicies(example).config as Config;
    const text = serializePolicies(c1);
    const p2 = parsePolicies(text);
    expect(p2.problems).toEqual([]);
    const c2 = p2.config as Config;
    expect(c2.policies.map((x) => x.line)).toEqual(c1.policies.map((x) => x.line).map((l) => (l as number) - 1));
    const strip = (c: Config) => ({ ...c, policies: c.policies.map((x) => ({ ...x, line: null })) });
    expect(strip(c2)).toEqual(strip(c1));
    expect(text).toContain("measure: {sum: expense.discretionary, period: month}");
    expect(text).toContain("accounts: [salary, savings, broker, cash]");
    expect(text).toContain("  - id: WLT-01\n    type: cap\n");
    expect(serializePolicies(text === "" ? c1 : c2)).toBe(text);
  });

  it("quotes what YAML would misread", () => {
    const c = parsePolicies("base_currency: OMR\naccounts: [a]\ncategories: {expense: [x]}\nsnapshot_max_age_days: 45\nclasses: [cash, crypto]\npolicies:\n  - id: \"1\"\n    type: red_line\n    title: \"yes: no\"\n    match: {tags: \"a, b\"}\n").config as Config;
    const text = serializePolicies(c);
    expect(text).toContain('classes: [cash, crypto]');
    expect(text).toContain('- id: "1"');
    expect(text).toContain('title: "yes: no"');
    expect(text).toContain('match: {tags: "a, b"}');
    const back = parsePolicies(text).config as Config;
    expect(back.policies[0]?.title).toBe("yes: no");
    expect(back.policies[0]?.match?.tags).toEqual(["a, b"]);
  });
});
