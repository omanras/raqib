// ledger.csv loader: the reference engine's tests/test_ledger.py (ledger
// part) over its fixtures, plus the example household and the serializer.
import { describe, expect, it } from "vitest";
import { D } from "../../src/engine/decimal";
import { appendLedgerLine, LEDGER_HEADER, parseLedger, serializeLedger } from "../../src/engine/ledger";
import type { Config, Problem } from "../../src/engine/types";
import { parsePolicies } from "../../src/engine/policies";
import { fixture, readExample } from "./fixtures";

const config = parsePolicies(readExample("policies.yml")).config as Config;
const H = LEDGER_HEADER + "\n";

function load(name: string) {
  return parseLedger(fixture(`ledger/${name}`), config, name);
}

function codes(problems: Problem[]): [number, string][] {
  return problems.map((p) => [p.line, p.code]);
}

describe("engine/ledger: the example household", () => {
  it("parses without problems, with line numbers and Decimal amounts", () => {
    const p = parseLedger(readExample("ledger.csv"), config);
    expect(p.problems).toEqual([]);
    expect(p.rows.length).toBe(271);
    expect(p.rows[0]?.line).toBe(2);
    expect(p.rows[270]?.cite).toBe("ledger.csv:272");
    const r = p.rows.find((x) => x.line === 270);
    expect(r?.amount.eq("-17.507")).toBe(true);
    expect(r?.amountText).toBe("-17.507");
    expect(p.rows.find((x) => x.line === 263)?.tags).toEqual(["transfer"]);
  });

  it("serialises back byte for byte", () => {
    const text = readExample("ledger.csv");
    expect(serializeLedger(parseLedger(text, config).rows)).toBe(text);
  });
});

describe("engine/ledger: the CLI's fixtures", () => {
  it("valid rows, types, quoting, order", () => {
    const { rows, problems } = load("valid.csv");
    expect(problems).toEqual([]);
    expect(rows.length).toBe(7);
    const r = rows[0]!;
    expect([r.date, r.amount.eq("1200.000"), r.currency, r.account, r.category, r.tags, r.note]).toEqual(["2026-01-05", true, "OMR", "salary", "salary", [], "January salary"]);
    expect([r.line, r.file, r.cite]).toEqual([2, "valid.csv", "valid.csv:2"]);
    expect(rows[3]?.tags).toEqual(["grocery", "weekly"]);
    expect(rows[3]?.note).toBe("milk, bread");
    expect(rows[3]?.amount.eq("-12.345")).toBe(true);
    expect(rows[4]?.note).toBe('he said "ok"');
    expect(rows[4]?.currency).toBe("USD");
    expect(rows[5]?.amount.isZero()).toBe(true);
    expect(rows[6]?.date).toBe("2025-12-31");
    expect(rows.map((x) => x.line)).toEqual([2, 3, 4, 5, 6, 7, 8]);
  });

  it("tolerates a BOM and CRLF, with a UTF-8 note", () => {
    const { rows, problems } = load("valid_bom_crlf.csv");
    const plain = load("valid.csv").rows;
    expect(problems).toEqual([]);
    expect(rows.length).toBe(7);
    expect(rows[0]?.date).toBe("2026-01-05");
    expect(rows[3]?.note).toBe("caf" + String.fromCharCode(0xe9) + ", bread");
    expect(rows[0]?.note).toBe("January salary");
    rows.forEach((a, i) => {
      const b = plain[i]!;
      expect({ ...a, note: "", file: "", cite: "" }).toEqual({ ...b, note: "", file: "", cite: "" });
    });
  });

  it("header only: zero rows, no problem", () => {
    expect(load("header_only.csv")).toEqual({ rows: [], problems: [], dupNotes: [] });
  });

  it("file-level problems: empty, missing, bad header (even a space)", () => {
    const empty = load("empty.csv");
    expect(codes(empty.problems)).toEqual([[0, "FILE-EMPTY"]]);
    expect(empty.problems[0]?.class).toBe("invalid");
    expect(empty.problems[0]?.file).toBe("empty.csv");
    const missing = parseLedger(null, config, "does_not_exist.csv");
    expect(codes(missing.problems)).toEqual([[0, "FILE-MISSING"]]);
    expect(missing.problems[0]?.reason).toContain("does_not_exist.csv");
    const bad = load("bad_header.csv");
    expect(bad.rows).toEqual([]);
    expect(codes(bad.problems)).toEqual([[1, "BAD-HEADER"]]);
    expect(bad.problems[0]?.reason).toContain(LEDGER_HEADER);
    expect(codes(load("bad_header_space.csv").problems)).toEqual([[1, "BAD-HEADER"]]);
  });

  it("bad dates name each line, carry no date, and the run continues", () => {
    const { rows, problems } = load("bad_date.csv");
    expect(codes(problems)).toEqual([[3, "BAD-DATE"], [4, "BAD-DATE"], [5, "BAD-DATE"], [6, "BAD-DATE"], [7, "BAD-DATE"]]);
    expect(rows.map((r) => r.line)).toEqual([2, 8]);
    expect(problems.every((p) => p.class === "invalid" && !("date" in p))).toBe(true);
    expect(problems[0]?.reason).toContain("2026-13-01");
  });

  it("only plain decimal text is an amount; the period hint survives", () => {
    const { rows, problems } = load("bad_amount.csv");
    expect(problems.map((p) => p.line)).toEqual([2, 3, 4, 5, 6, 7, 8, 9, 10]);
    expect(new Set(problems.map((p) => p.code))).toEqual(new Set(["BAD-AMOUNT"]));
    expect(rows.map((r) => r.line)).toEqual([11]);
    expect(rows[0]?.amount.eq("-7.25")).toBe(true);
    expect(problems.every((p) => p.date === "2026-01-05")).toBe(true);
  });

  it("currency, account, category, column count, tags, empty lines, CSV quoting", () => {
    expect(codes(load("bad_currency.csv").problems)).toEqual([[2, "BAD-CURRENCY"], [3, "BAD-CURRENCY"], [4, "BAD-CURRENCY"], [5, "BAD-CURRENCY"]]);
    const acc = load("unknown_account.csv");
    expect(codes(acc.problems)).toEqual([[3, "UNKNOWN-ACCOUNT"], [4, "UNKNOWN-ACCOUNT"], [5, "UNKNOWN-ACCOUNT"]]);
    expect(acc.problems[0]?.reason).toContain("wallet");
    expect(acc.problems[1]?.reason).toContain("Salary");
    const cat = load("unknown_category.csv");
    expect(codes(cat.problems)).toEqual([[3, "UNKNOWN-CATEGORY"], [4, "UNKNOWN-CATEGORY"]]);
    expect(cat.problems[1]?.reason).toContain("expense");
    const cols = load("column_count.csv");
    expect(codes(cols.problems)).toEqual([[3, "COLUMN-COUNT"], [4, "COLUMN-COUNT"], [5, "COLUMN-COUNT"]]);
    expect(cols.problems[0]?.reason).toContain("expected 7 columns, got 6");
    expect(cols.problems[1]?.reason).toContain("got 8");
    expect(cols.problems[2]?.reason).toContain("got 1");
    expect(cols.rows.map((r) => r.line)).toEqual([2, 6]);
    const tags = load("bad_tags.csv");
    expect(codes(tags.problems)).toEqual([[2, "BAD-TAGS"], [3, "BAD-TAGS"], [4, "BAD-TAGS"], [5, "BAD-TAGS"]]);
    expect(tags.rows[0]?.tags).toEqual(["a", "b", "a"]);
    const blank = load("empty_line.csv");
    expect(codes(blank.problems)).toEqual([[3, "EMPTY-LINE"], [5, "EMPTY-LINE"]]);
    expect(blank.rows.map((r) => r.line)).toEqual([2, 4]);
    const csv = load("bad_csv.csv");
    expect(codes(csv.problems)).toEqual([[2, "BAD-CSV"], [3, "BAD-CSV"]]);
    expect(csv.rows.map((r) => r.line)).toEqual([4]);
  });

  it("a row with several faults reports each once, in field order", () => {
    const { rows, problems } = load("multi_problem.csv");
    expect(rows).toEqual([]);
    expect(problems.filter((p) => p.line === 2).map((p) => p.code)).toEqual([
      "BAD-DATE",
      "BAD-AMOUNT",
      "BAD-CURRENCY",
      "UNKNOWN-ACCOUNT",
      "UNKNOWN-CATEGORY",
      "BAD-TAGS",
    ]);
    const line3 = problems.filter((p) => p.line === 3);
    expect(line3.map((p) => p.code)).toEqual(["BAD-AMOUNT", "UNKNOWN-ACCOUNT"]);
    expect(line3.every((p) => p.date === "2026-01-05")).toBe(true);
    expect(problems.filter((p) => p.line === 2).every((p) => !("date" in p))).toBe(true);
  });

  it("an exact duplicate is a warning and no row is dropped", () => {
    const { rows, problems, dupNotes } = load("dup_row.csv");
    expect(rows.map((r) => r.line)).toEqual([2, 3, 4, 5]);
    expect(codes(problems)).toEqual([[3, "DUP-ROW"], [5, "DUP-ROW"]]);
    for (const p of problems) {
      expect(p.class).toBe("warn");
      expect(p.dup_of).toBe(2);
      expect(p.reason).toContain("line 2");
    }
    expect(dupNotes).toEqual([{ line: 3, firstLine: 2 }, { line: 5, firstLine: 2 }]);
    expect(rows[2]?.note).toBe("coffee again");
  });

  it("a line of 1 MiB or more is LINE-TOO-LONG, just under is fine", () => {
    const prefix = "2026-01-06,-1,OMR,cash,food,,";
    const make = (n: number) => H + "2026-01-05,1,OMR,salary,salary,,ok\n" + prefix + "x".repeat(n) + "\n2026-01-07,-2,OMR,cash,food,,ok too\n";
    const long = parseLedger(make(1024 * 1024 - prefix.length), config);
    expect(codes(long.problems)).toEqual([[3, "LINE-TOO-LONG"]]);
    expect(long.rows.map((r) => r.line)).toEqual([2, 4]);
    const almost = parseLedger(make(1024 * 1024 - prefix.length - 1), config);
    expect(almost.problems).toEqual([]);
    expect(almost.rows.length).toBe(3);
  });

  it("without a config nothing is declared", () => {
    expect(codes(parseLedger(H + "2026-09-05,1,OMR,salary,salary,,x\n", null).problems)).toEqual([[2, "UNKNOWN-ACCOUNT"], [2, "UNKNOWN-CATEGORY"]]);
  });
});

describe("engine/ledger: writing", () => {
  it("appends a row without touching the existing lines (A6)", () => {
    const base = H + "2026-09-01,1200.000,OMR,salary,salary,,salary\n";
    const row = { date: "2026-09-28", amountText: "-200", currency: "OMR", account: "cash", category: "discretionary", tags: [], note: "phone" };
    expect(appendLedgerLine(base, row)).toBe(base + "2026-09-28,-200,OMR,cash,discretionary,,phone\n");
    expect(appendLedgerLine(base.trimEnd(), row)).toBe(base + "2026-09-28,-200,OMR,cash,discretionary,,phone\n");
    expect(appendLedgerLine("", row)).toBe(H + "2026-09-28,-200,OMR,cash,discretionary,,phone\n");
    expect(appendLedgerLine(null, row)).toBe(H + "2026-09-28,-200,OMR,cash,discretionary,,phone\n");
  });

  it("quotes a note with a comma and reads it back", () => {
    const row = { date: "2026-09-28", amount: D("-2"), amountText: "-2", currency: "OMR", account: "cash", category: "food", tags: ["a"], note: "fish, bread", line: 2, file: "ledger.csv", cite: "ledger.csv:2" };
    const text = serializeLedger([row]);
    expect(text).toBe(H + '2026-09-28,-2,OMR,cash,food,a,"fish, bread"\n');
    expect(parseLedger(text, config).rows[0]?.note).toBe("fish, bread");
  });
});
