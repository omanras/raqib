import { describe, expect, it } from "vitest";
import { appendLedgerLine, LEDGER_HEADER, parseLedger, serializeLedger } from "../../src/engine/ledger";
import { parsePolicies } from "../../src/engine/policies";
import type { Config } from "../../src/engine/types";
import { readExample } from "./fixtures";

const config = parsePolicies(readExample("policies.yml")).config as Config;
const H = LEDGER_HEADER + "\n";

describe("engine/ledger", () => {
  it("parses the example without problems, with line numbers and Decimal amounts", () => {
    const text = readExample("ledger.csv");
    const p = parseLedger(text, config);
    expect(p.problems).toEqual([]);
    expect(p.invalid).toEqual([]);
    expect(p.dupNotes).toEqual([]);
    expect(p.count).toBe(271);
    expect(p.rows.length).toBe(271);
    expect(p.rows[0]?.line).toBe(2);
    expect(p.rows[270]?.line).toBe(272);
    const r = p.rows.find((x) => x.line === 270);
    expect(r?.date).toBe("2026-09-15");
    expect(r?.amount.toString()).toBe("-17.507");
    expect(r?.amountText).toBe("-17.507");
    expect(r?.category).toBe("discretionary");
    expect(r?.tags).toEqual([]);
    const t = p.rows.find((x) => x.line === 263);
    expect(t?.tags).toEqual(["transfer"]);
    expect(t?.account).toBe("savings");
  });

  it("serialises the example back byte for byte", () => {
    const text = readExample("ledger.csv");
    expect(serializeLedger(parseLedger(text, config).rows)).toBe(text);
  });

  it("tolerates a BOM and CRLF", () => {
    const p = parseLedger("﻿" + H.replace("\n", "\r\n") + "2026-09-01,1200.000,OMR,salary,salary,,salary\r\n", config);
    expect(p.problems).toEqual([]);
    expect(p.rows.length).toBe(1);
    expect(p.rows[0]?.note).toBe("salary");
  });

  it("refuses a wrong header and names the expected one", () => {
    const p = parseLedger("date,amount,currency,account,category,note\n2026-09-01,1,OMR,salary,salary,x\n", config);
    expect(p.rows).toEqual([]);
    expect(p.count).toBe(0);
    expect(p.problems.length).toBe(1);
    expect(p.problems[0]?.code).toBe("BAD-HEADER");
    expect(p.problems[0]?.cite).toBe("ledger.csv:1");
    expect(p.problems[0]?.reason).toContain(LEDGER_HEADER);
    expect(parseLedger("", config).problems[0]?.code).toBe("EMPTY-FILE");
  });

  it("names each malformed row by line and continues", () => {
    const text =
      H +
      "2026-09-01,1200.000,OMR,salary,salary,,ok\n" +
      "2026-09-02,1,OMR,salary,salary\n" +
      "2026-09-31,1,OMR,salary,salary,,bad date\n" +
      "2026-09-03,\"1,200.00\",OMR,salary,salary,,thousands separator\n" +
      "2026-09-04,1,omr,salary,salary,,bad currency\n" +
      "2026-09-05,1,OMR,wallet,salary,,unknown account\n" +
      "2026-09-06,-1,OMR,cash,coffee,,unknown category\n" +
      "2026-09-07,-2.5,OMR,cash,food,a;b,ok too\n";
    const p = parseLedger(text, config);
    expect(p.rows.map((r) => r.line)).toEqual([2, 9]);
    expect(p.rows[1]?.tags).toEqual(["a", "b"]);
    expect(p.invalid.map((r) => [r.line, r.code, r.date])).toEqual([
      [3, "BAD-COLUMNS", null],
      [4, "BAD-DATE", null],
      [5, "BAD-AMOUNT", "2026-09-03"],
      [6, "BAD-CURRENCY", "2026-09-04"],
      [7, "UNKNOWN-ACCOUNT", "2026-09-05"],
      [8, "UNKNOWN-CATEGORY", "2026-09-06"],
    ]);
    expect(p.problems.map((x) => x.cite)).toEqual(["ledger.csv:3", "ledger.csv:4", "ledger.csv:5", "ledger.csv:6", "ledger.csv:7", "ledger.csv:8"]);
    expect(p.problems[5]?.reason).toContain('"coffee"');
    expect(p.count).toBe(8);
  });

  it("notes exact duplicate lines and keeps both", () => {
    const text = H + "2026-09-12,-25.993,OMR,cash,food,,fruit\n2026-09-13,-1,OMR,cash,food,,x\n2026-09-12,-25.993,OMR,cash,food,,fruit\n";
    const p = parseLedger(text, config);
    expect(p.rows.length).toBe(3);
    expect(p.dupNotes).toEqual([{ line: 4, firstLine: 2, text: "2026-09-12,-25.993,OMR,cash,food,,fruit" }]);
    expect(p.problems).toEqual([]);
  });

  it("skips account and category checks without a config", () => {
    const p = parseLedger(H + "2026-09-05,1,OMR,wallet,coffee,,x\n", null);
    expect(p.problems).toEqual([]);
    expect(p.rows.length).toBe(1);
  });

  it("appends a row without touching the existing lines (A6)", () => {
    const base = H + "2026-09-01,1200.000,OMR,salary,salary,,salary\n";
    const row = parseLedger(H + "2026-09-28,-200,OMR,cash,discretionary,,phone\n", config).rows[0]!;
    expect(appendLedgerLine(base, row)).toBe(base + "2026-09-28,-200,OMR,cash,discretionary,,phone\n");
    expect(appendLedgerLine(base.trimEnd(), row)).toBe(base + "2026-09-28,-200,OMR,cash,discretionary,,phone\n");
    expect(appendLedgerLine("", row)).toBe(H + "2026-09-28,-200,OMR,cash,discretionary,,phone\n");
  });

  it("quotes a note with a comma on the way out and reads it back", () => {
    const row = { line: 2, date: "2026-09-28", amount: parseLedger(H + "2026-09-28,-2,OMR,cash,food,,x\n", config).rows[0]!.amount, amountText: "-2", currency: "OMR", account: "cash", category: "food", tags: ["a"], note: "fish, bread" };
    const text = serializeLedger([row]);
    expect(text).toBe(H + '2026-09-28,-2,OMR,cash,food,a,"fish, bread"\n');
    expect(parseLedger(text, config).rows[0]?.note).toBe("fish, bread");
  });
});
