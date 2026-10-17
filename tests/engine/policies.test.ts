// policies.yml loader: the reference engine's tests/test_policies.py
// (policies part) over its fixtures, the example household, and the
// serializer round trip.
import { describe, expect, it } from "vitest";
import { bandText, limitText, matchText, measureText, parsePolicies, policyById, policyIds, serializePolicies } from "../../src/engine/policies";
import { PyInt } from "../../src/engine/py";
import type { Config, Policy } from "../../src/engine/types";
import { fixture, readExample } from "./fixtures";

const example = readExample("policies.yml");

function load(name: string) {
  return parsePolicies(fixture(`policies/${name}`), name);
}

function byId(config: Config, id: string): Policy {
  const p = policyById(config, id);
  if (!p) throw new Error(`no policy ${id}`);
  return p;
}

function codes(p: ReturnType<typeof parsePolicies>): [number, string, string | undefined][] {
  return p.problems.map((x) => [x.line, x.code, x.field]);
}

describe("engine/policies: the example household", () => {
  it("8 accepted policies, base OMR, the default classes, line numbers", () => {
    const p = parsePolicies(example);
    expect(p.problems).toEqual([]);
    const c = p.config as Config;
    expect([c.version, c.baseCurrency, c.snapshotMaxAgeDays, c.file]).toEqual([1, "OMR", 45, "policies.yml"]);
    expect(c.accounts).toEqual(["salary", "savings", "broker", "cash"]);
    expect(Object.keys(c.categories)).toEqual(["income", "expense", "transfer", "invest"]);
    expect(c.classes).toEqual(["cash", "equity", "fund", "property", "gold", "debt", "other"]);
    expect(c.policies.map((x) => [x.id, x.status, x.line])).toEqual([
      ["WLT-01", "ok", 12],
      ["WLT-02", "ok", 17],
      ["WLT-03", "ok", 22],
      ["WLT-04", "ok", 27],
      ["WLT-05", "ok", 31],
      ["WLT-06", "ok", 36],
      ["WLT-07", "ok", 41],
      ["WLT-08", "ok", 46],
    ]);
  });

  it("prints the declared texts exactly as the oracle does", () => {
    const c = parsePolicies(example).config as Config;
    expect(measureText(byId(c, "WLT-01").measure)).toBe("sum expense.discretionary per month");
    expect(limitText(byId(c, "WLT-01").limit, "OMR")).toBe("10% of income");
    expect(measureText(byId(c, "WLT-02").measure)).toBe("holdings class.cash");
    expect(limitText(byId(c, "WLT-02").limit, "OMR")).toBe("6 months of expense");
    expect(matchText(byId(c, "WLT-03").match)).toBe("tags transfer, account savings, amount >= 300");
    expect(matchText(byId(c, "WLT-04").match)).toBe("any tag of margin,options");
    expect(measureText(byId(c, "WLT-05").measure)).toBe("drawdown account.broker over 90 days");
    expect(limitText(byId(c, "WLT-05").limit, "OMR")).toBe("15%");
    expect(bandText(byId(c, "WLT-06").band)).toBe("2%..30%");
    expect(measureText(byId(c, "WLT-07").measure)).toBe("sum expense per quarter");
    expect(limitText(byId(c, "WLT-07").limit, "OMR")).toBe("2400 OMR");
    expect(matchText(byId(c, "WLT-08").match)).toBe("category housing, amount >= 250");
    expect([measureText(null), limitText(null), matchText(null), bandText(null)]).toEqual(["?", "?", "?", "?"]);
  });

  it("serialises semantically round-trip, numbers as written", () => {
    const c1 = parsePolicies(example).config as Config;
    const text = serializePolicies(c1);
    const p2 = parsePolicies(text);
    expect(p2.problems).toEqual([]);
    const c2 = p2.config as Config;
    const strip = (c: Config) => c.policies.map((x) => ({ ...x, line: 0, cite: "", raw: {} }));
    expect(strip(c2)).toEqual(strip(c1));
    expect({ ...c2, policies: [] }).toEqual({ ...c1, policies: [] });
    expect(c2.policies.map((x) => x.line)).toEqual(c1.policies.map((x) => x.line - 1));
    expect(text).toContain("  - id: WLT-01\n    type: cap\n    title: discretionary spending per month\n    measure: {sum: expense.discretionary, period: month}\n    limit: {pct_of: income, value: 10}\n");
    expect(text).toContain("accounts: [salary, savings, broker, cash]");
    expect(serializePolicies(c2)).toBe(text);
  });

  it("keeps declared numbers exact and as the CLI prints them (A5)", () => {
    const c = parsePolicies(example).config as Config;
    expect(byId(c, "WLT-01").raw["limit"]).toEqual({ pct_of: "income", value: new PyInt(byId(c, "WLT-01").limit!.value.value, "10") });
    const odd = parsePolicies(example.replace("limit: {value: 2400}", "limit: {value: 2400.50}").replace("min_amount: 300}", "min_amount: 0x12C}")).config as Config;
    expect(limitText(byId(odd, "WLT-07").limit, "OMR")).toBe("2400.50 OMR");
    expect(matchText(byId(odd, "WLT-03").match)).toBe("tags transfer, account savings, amount >= 300");
    expect(serializePolicies(odd)).toContain("limit: {value: 2400.50}");
    expect(serializePolicies(odd)).toContain("min_amount: 0x12C}");
  });
});

describe("engine/policies: the CLI's fixtures", () => {
  it("valid.yml: fields, normalized policies, line of each policy", () => {
    const { config, problems } = load("valid.yml");
    expect(problems).toEqual([]);
    const c = config as Config;
    expect(c.file).toBe("valid.yml");
    expect(policyIds(c)).toEqual(Array.from({ length: 11 }, (_, i) => `WLT-${String(i + 1).padStart(2, "0")}`));
    expect(c.policies.every((p) => p.status === "ok" && p.reason === null)).toBe(true);
    const p1 = byId(c, "WLT-01");
    expect(p1.measure).toEqual({ kind: "sum", group: "expense", category: "discretionary", period: "month" });
    expect([p1.limit?.kind, p1.limit?.value.text, p1.line, p1.cite]).toEqual(["pct_of", "10", 11, "valid.yml:11"]);
    expect(byId(c, "WLT-03").match).toMatchObject({ tags: ["transfer"], account: "savings" });
    expect(byId(c, "WLT-03").match?.minAmount?.text).toBe("300");
    expect(byId(c, "WLT-04").match).toEqual({ tags: null, tagsAny: ["margin", "options"], account: null, category: null, minAmount: null });
    expect(byId(c, "WLT-05").measure).toEqual({ kind: "drawdown", by: "account", name: "broker", windowDays: 90 });
    expect(bandText(byId(c, "WLT-06").band)).toBe("20%..50%");
    expect(limitText(byId(c, "WLT-07").limit, "OMR")).toBe("4500.50 OMR");
    expect(byId(c, "WLT-08").measure).toEqual({ kind: "sum", group: "income", category: null, period: "year" });
    expect(byId(c, "WLT-11").period).toBe("quarter");
    expect([byId(c, "WLT-04").measure, byId(c, "WLT-04").limit, byId(c, "WLT-04").band]).toEqual([null, null, null]);
  });

  it("decimals.yml: Decimal from the text, never a float", () => {
    const c = load("decimals.yml").config as Config;
    expect(byId(c, "P-01").limit?.value.text).toBe("0.1");
    expect(bandText(byId(c, "P-02").band)).toBe("12.5%..37.75%");
    expect(byId(c, "P-03").limit?.value.value.eq("1234.5678")).toBe(true);
    expect(byId(c, "P-04").limit?.value.value.eq("10.5")).toBe(true);
  });

  it("custom classes replace the default; an undeclared one is a problem and an unknown policy", () => {
    const p = load("classes_custom.yml");
    const c = p.config as Config;
    expect(c.classes).toEqual(["cash", "stocks", "gold"]);
    expect(byId(c, "P-01").status).toBe("ok");
    expect(byId(c, "P-02").status).toBe("unknown");
    expect(byId(c, "P-02").reason).toContain("equity");
    expect(codes(p)).toEqual([[20, "UNDECLARED-CLASS", "policies[1].measure.share"]]);
  });

  it("unknown shapes are kept as unknown with the reason; the file is not rejected", () => {
    const p = load("unknown_shapes.yml");
    expect(p.problems).toEqual([]);
    const c = p.config as Config;
    expect(c.policies.length).toBe(21);
    expect(byId(c, "OK-01").status).toBe("ok");
    const unknown = c.policies.filter((x) => x.id.startsWith("U-"));
    expect(unknown.every((x) => x.status === "unknown" && x.reason && x.measure === null && x.limit === null && x.match === null && x.band === null)).toBe(true);
    const reason = (id: string) => byId(c, id).reason as string;
    expect(reason("U-01")).toContain("ceiling");
    expect(byId(c, "U-01").type).toBe("ceiling");
    const expected: [string, string][] = [
      ["U-02", "period"],
      ["U-03", "average"],
      ["U-04", "max"],
      ["U-05", "pct"],
      ["U-06", "drawdown"],
      ["U-07", "window_days"],
      ["U-08", "min_pct <= max_pct"],
      ["U-09", "share"],
      ["U-10", "period"],
      ["U-11", "week"],
      ["U-12", "at least one"],
      ["U-13", "merchant"],
      ["U-14", "needs measure and limit"],
      ["U-15", "number"],
      ["U-16", "income"],
      ["U-17", "band"],
      ["U-18", "period"],
      ["U-19", "number"],
      ["U-20", "number"],
    ];
    for (const [id, part] of expected) expect(reason(id), id).toContain(part);
    expect(byId(c, "U-01").raw["title"]).toBe("unknown type");
    expect(byId(c, "U-01").line).toBe(11);
  });

  it("problems: duplicate id, undeclared names, empty or missing policies, missing fields", () => {
    const dup = load("dup_id.yml");
    expect(codes(dup)).toEqual([[20, "DUP-ID", "policies[2].id"]]);
    expect(dup.problems[0]?.reason).toContain("line 11");
    expect(policyIds(dup.config as Config)).toEqual(["WLT-01", "WLT-02"]);
    expect(byId(dup.config as Config, "WLT-01").limit?.value.text).toBe("100");
    const und = load("undeclared.yml");
    expect(codes(und)).toEqual([
      [14, "UNDECLARED-CATEGORY", "policies[0].measure.sum"],
      [19, "UNDECLARED-CATEGORY", "policies[1].measure.sum"],
      [24, "UNDECLARED-CLASS", "policies[2].measure.holdings"],
      [29, "UNDECLARED-ACCOUNT", "policies[3].measure.drawdown"],
      [34, "UNDECLARED-ACCOUNT", "policies[4].match.account"],
      [39, "UNDECLARED-CATEGORY", "policies[5].match.category"],
      [43, "UNDECLARED-CATEGORY", "policies[6].measure.sum"],
    ]);
    expect(und.problems.every((x) => x.class === "invalid")).toBe(true);
    expect((und.config as Config).policies.every((x) => x.status === "unknown")).toBe(true);
    expect(und.problems[6]?.reason).toContain("food");
    expect(und.problems[6]?.reason).toContain("income");
    expect(codes(load("empty_policies.yml"))).toEqual([[1, "EMPTY-POLICIES", "policies"]]);
    expect(codes(load("no_policies_key.yml"))).toEqual([[1, "EMPTY-POLICIES", "policies"]]);
    const base = load("missing_base_currency.yml");
    expect(codes(base)).toEqual([[1, "MISSING-FIELD", "base_currency"]]);
    expect([base.config?.baseCurrency, base.config?.policies.length]).toEqual([null, 1]);
    const age = load("missing_snapshot_age.yml");
    expect(codes(age)).toEqual([[1, "MISSING-FIELD", "snapshot_max_age_days"]]);
    expect(age.config?.snapshotMaxAgeDays).toBeNull();
    const groups = load("categories_missing_group.yml");
    expect(codes(groups)).toEqual([[5, "MISSING-FIELD", "categories.expense"]]);
    expect("expense" in (groups.config as Config).categories).toBe(false);
  });

  it("bad fields are each named", () => {
    const p = load("bad_fields.yml");
    expect(p.problems.map((x) => [x.code, x.field])).toEqual([
      ["BAD-FIELD", "colour"],
      ["BAD-FIELD", "version"],
      ["BAD-FIELD", "base_currency"],
      ["DUP-ID", "accounts"],
      ["BAD-FIELD", "accounts"],
      ["DUP-ID", "categories.expense"],
      ["BAD-FIELD", "categories.transfer"],
      ["BAD-FIELD", "snapshot_max_age_days"],
      ["BAD-FIELD", "policies[1].id"],
      ["BAD-FIELD", "policies[2]"],
    ]);
    const c = p.config as Config;
    expect([c.version, c.baseCurrency, c.snapshotMaxAgeDays]).toEqual([null, null, null]);
    expect(c.accounts).toEqual(["salary"]);
    expect(c.categories).toEqual({ income: ["salary"], expense: ["food"], transfer: [] });
    expect(policyIds(c)).toEqual(["P-01"]);
  });

  it("file level: bad YAML with its line, duplicate keys, not a mapping, empty, unsafe tags, two documents", () => {
    const bad = load("bad_yaml.yml");
    expect([bad.config, bad.problems.map((x) => [x.line, x.code])]).toEqual([null, [[5, "BAD-YAML"]]]);
    const dupKey = load("dup_key.yml");
    expect(dupKey.problems.map((x) => [x.line, x.code])).toEqual([[16, "BAD-YAML"]]);
    expect(dupKey.problems[0]?.reason).toContain("duplicate key 'limit'");
    expect(load("not_a_mapping.yml").problems.map((x) => [x.line, x.code])).toEqual([[1, "BAD-SHAPE"]]);
    for (const name of ["empty.yml", "comment_only.yml"]) expect(load(name).problems.map((x) => [x.line, x.code])).toEqual([[0, "FILE-EMPTY"]]);
    expect(load("unsafe_tag.yml").problems.map((x) => x.code)).toEqual(["BAD-YAML"]);
    expect(load("multi_doc.yml").problems.map((x) => [x.line, x.code])).toEqual([[11, "BAD-YAML"]]);
    expect(parsePolicies(null, "nope.yml").problems.map((x) => [x.line, x.code])).toEqual([[0, "FILE-MISSING"]]);
  });
});
