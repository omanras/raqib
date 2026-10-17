import { describe, expect, it } from "vitest";
import { csvLine, readCsv } from "../../src/engine/csv";

describe("engine/csv", () => {
  it("reads records with physical line numbers and raw text", () => {
    const t = readCsv("a,b\n1,2\n3,4\n");
    expect(t.header?.fields).toEqual(["a", "b"]);
    expect(t.records.map((r) => [r.line, r.fields, r.raw])).toEqual([
      [2, ["1", "2"], "1,2"],
      [3, ["3", "4"], "3,4"],
    ]);
  });

  it("tolerates a BOM, CRLF and blank lines", () => {
    const t = readCsv("﻿a,b\r\n1,2\r\n\r\n3,4");
    expect(t.header?.fields).toEqual(["a", "b"]);
    expect(t.records.map((r) => [r.line, r.fields, r.raw])).toEqual([
      [2, ["1", "2"], "1,2"],
      [4, ["3", "4"], "3,4"],
    ]);
  });

  it("honours quotes, escaped quotes and embedded commas", () => {
    const t = readCsv('a,b\n"x, y","say ""hi"""\n,\n');
    expect(t.records[0]?.fields).toEqual(["x, y", 'say "hi"']);
    expect(t.records[1]?.fields).toEqual(["", ""]);
  });

  it("keeps the line of a record that spans lines inside quotes", () => {
    const t = readCsv('a,b\n"two\nlines",1\n3,4\n');
    expect(t.records.map((r) => [r.line, r.fields[0]])).toEqual([
      [2, "two\nlines"],
      [4, "3"],
    ]);
  });

  it("writes minimal quoting", () => {
    expect(csvLine(["2026-09-01", "-1.5", "a b", "x,y", 'q"q', ""])).toBe('2026-09-01,-1.5,a b,"x,y","q""q",');
  });

  it("gives an empty file no header", () => {
    expect(readCsv("")).toEqual({ header: null, records: [] });
    expect(readCsv("\n\n")).toEqual({ header: null, records: [] });
  });
});
