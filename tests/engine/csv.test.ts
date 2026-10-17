import { describe, expect, it } from "vitest";
import { csvLine, MAX_LINE_BYTES, splitCsvLine, splitLines, utf8Length } from "../../src/engine/csv";

const BOM = String.fromCharCode(0xfeff);

describe("engine/csv", () => {
  it("splits lines on \\n, drops one trailing \\r, tolerates a BOM; the final newline ends the last line", () => {
    expect(splitLines("a,b\n1,2\n").map((l) => [l.line, l.text])).toEqual([
      [1, "a,b"],
      [2, "1,2"],
    ]);
    expect(splitLines(BOM + "a,b\r\n1,2\r\n\r\n3,4").map((l) => [l.line, l.text])).toEqual([
      [1, "a,b"],
      [2, "1,2"],
      [3, ""],
      [4, "3,4"],
    ]);
    expect(splitLines("a\n\n").map((l) => l.text)).toEqual(["a", ""]);
    expect(splitLines("\n").map((l) => l.text)).toEqual([""]);
  });

  it("marks a line of 1 MiB or more as unreadable", () => {
    const long = "x".repeat(MAX_LINE_BYTES);
    const lines = splitLines("h\n" + long + "\n" + "y".repeat(MAX_LINE_BYTES - 1) + "\n");
    expect(lines.map((l) => [l.line, l.text === null, l.bytes])).toEqual([
      [1, false, 1],
      [2, true, MAX_LINE_BYTES],
      [3, false, MAX_LINE_BYTES - 1],
    ]);
    expect(utf8Length("caf" + String.fromCharCode(0xe9))).toBe(5);
    expect(utf8Length(String.fromCharCode(0xd83d, 0xde00))).toBe(4);
  });

  it("parses one line like Python's csv.reader in strict mode", () => {
    expect(splitCsvLine("a,b,c")).toEqual({ ok: true, fields: ["a", "b", "c"] });
    expect(splitCsvLine('"x, y","say ""hi""",')).toEqual({ ok: true, fields: ["x, y", 'say "hi"', ""] });
    expect(splitCsvLine(",")).toEqual({ ok: true, fields: ["", ""] });
    expect(splitCsvLine('a"b,c')).toEqual({ ok: true, fields: ['a"b', "c"] });
    expect(splitCsvLine(" a , b")).toEqual({ ok: true, fields: [" a ", " b"] });
    expect(splitCsvLine("a,b\r")).toEqual({ ok: true, fields: ["a", "b"] });
  });

  it("gives Python's error texts for malformed quoting", () => {
    expect(splitCsvLine('"a"b,c')).toEqual({ ok: false, error: `',' expected after '"'` });
    expect(splitCsvLine('a,"unclosed')).toEqual({ ok: false, error: "unexpected end of data" });
    expect(splitCsvLine("a\rb")).toEqual({ ok: false, error: "new-line character seen in unquoted field - do you need to open the file with newline=''?" });
  });

  it("writes minimal quoting", () => {
    expect(csvLine(["2026-09-01", "-1.5", "a b", "x,y", 'q"q', ""])).toBe('2026-09-01,-1.5,a b,"x,y","q""q",');
  });
});
