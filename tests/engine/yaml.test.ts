// YAML read as PyYAML's safe loader reads it (YAML 1.1 scalars), with the
// reference engine's overrides, and Python's repr() for the CLI's messages.
import { describe, expect, it } from "vitest";
import { D } from "../../src/engine/decimal";
import { isNumber, PyDec, PyInt, pyRepr, pyStr, toNum, type PyMap } from "../../src/engine/py";
import { loadYaml, yFlow, yStr } from "../../src/engine/yaml";

function load(text: string): PyMap {
  const r = loadYaml(text);
  if (!r.ok) throw new Error(r.reason);
  return r.value as PyMap;
}

describe("engine/yaml", () => {
  it("resolves plain scalars by YAML 1.1 rules; quoted scalars stay text", () => {
    const v = load("a: 010\nb: 0x1F\nc: 1_000\nd: 1:30\ne: 2.50\nf: .inf\ng: yes\nh: ~\ni: '10'\nj: 2026-10-01\nk: -0\nl: 1e5\nm: 1.5e+3\nn: off\no:\n");
    const ints = ["a", "b", "c", "d", "k"].map((k) => (v[k] as PyInt).value.toString());
    expect(ints).toEqual(["8", "31", "1000", "90", "0"]);
    expect(v["e"]).toEqual(new PyDec(D("2.50"), "2.50", "2.50"));
    expect([v["f"], v["g"], v["h"], v["i"], v["j"], v["l"], v["n"], v["o"]]).toEqual([".inf", true, null, "10", "2026-10-01", "1e5", false, null]);
    expect((v["m"] as PyDec).value.toString()).toBe("1500");
  });

  it("knows the line where each mapping starts", () => {
    const r = loadYaml("# comment\ntop: 1\nlist:\n  - id: A\n    m: {x: 1}\n  -\n    id: B\n");
    if (!r.ok) throw new Error(r.reason);
    const doc = r.value as PyMap;
    const list = doc["list"] as PyMap[];
    expect([r.lineOf(doc), r.lineOf(list[0]), r.lineOf(list[0]!["m"]), r.lineOf(list[1])]).toEqual([2, 4, 5, 7]);
  });

  it("reports what it cannot read with a line, and an empty document as null", () => {
    const dup = loadYaml("a: 1\nb:\n  c: 1\n  c: 2\n");
    expect(dup).toEqual({ ok: false, line: 4, reason: "YAML error: duplicate key 'c'" });
    const bad = loadYaml("a: [1\n");
    expect(bad.ok).toBe(false);
    expect(loadYaml("---\n").ok && (loadYaml("---\n") as { value: unknown }).value).toBeNull();
    expect((loadYaml("# only a comment\n") as { value: unknown }).value).toBeNull();
    expect(loadYaml("a: !!python/object:os.system x\n").ok).toBe(false);
  });

  it("numbers are the CLI's is_number and to_decimal", () => {
    const v = load("i: 10\nf: 12.50\ns: '7.5'\nb: true\nt: ten\n");
    expect(["i", "f", "s", "b", "t"].map((k) => isNumber(v[k]))).toEqual([true, true, true, false, false]);
    expect(toNum(v["f"]!)).toEqual({ value: D("12.5"), text: "12.50" });
    expect(toNum(v["i"]!).text).toBe("10");
    expect(toNum(v["s"]!).text).toBe("7.5");
  });

  it("repr and str like Python", () => {
    const v = load("s: it's\nq: plain\nd: 2.5\nn: 3\nl: [a, 1]\nm: {k: v}\n");
    expect(pyRepr(v["s"])).toBe(`"it's"`);
    expect(pyRepr(v["q"])).toBe("'plain'");
    expect(pyRepr(v["d"])).toBe("Decimal('2.5')");
    expect([pyRepr(v["n"]), pyRepr(null), pyRepr(undefined), pyRepr(true)]).toEqual(["3", "None", "None", "True"]);
    expect(pyRepr(v["l"])).toBe("['a', 1]");
    expect(pyRepr(v["m"])).toBe("{'k': 'v'}");
    expect(pyRepr("a\nb\\")).toBe("'a\\nb\\\\'");
    expect([pyStr(v["q"]), pyStr(v["d"]), pyStr(undefined)]).toEqual(["plain", "2.5", "None"]);
  });

  it("writes scalars back so they read the same", () => {
    expect([yStr("month"), yStr("yes"), yStr("10"), yStr("a, b"), yStr("expense.food"), yStr("")]).toEqual(["month", '"yes"', '"10"', '"a, b"', "expense.food", '""']);
    const v = load("m: {value: 0x1F, f: 2.50, t: true, n: null, s: '10'}\n");
    expect(yFlow(v["m"])).toBe('{value: 0x1F, f: 2.50, t: true, "n": null, s: "10"}'); // y/n quoted: YAML 1.1 booleans elsewhere
  });
});
