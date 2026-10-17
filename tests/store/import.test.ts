// Import checks: what the CLI could not read at all is refused, with the
// expected header for a CSV; UTF-8 is decoded strictly; names are matched.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { loadHousehold } from "../../src/engine/household";
import { FILE_NAMES } from "../../src/engine/types";
import { checkFileBytes, checkImport, decodeUtf8, fileNameOf } from "../../src/store/import";
import { sampleHousehold } from "../../src/store/sample";

const BOM = String.fromCharCode(0xfeff);
const enc = (s: string) => new TextEncoder().encode(s);

describe("store/import", () => {
  it("refuses a CSV whose first line is not the header, and names the expected one", () => {
    const r = checkImport("ledger.csv", "date,amount,note\n2026-01-01,1,x\n");
    expect(r).toEqual({ ok: false, name: "ledger.csv", refusal: { kind: "wrong-header", expected: "date,amount,currency,account,category,tags,note", got: "date,amount,note" } });
    expect(checkImport("holdings.csv", "date,account,asset,class,quantity,value,currency \n").ok).toBe(false);
    expect(checkImport("rates.csv", BOM + "date,currency,rate\r\n2026-01-01,USD,0.38\r\n").ok).toBe(true);
    expect(checkImport("ledger.csv", "")).toMatchObject({ ok: false, refusal: { kind: "empty" } });
  });

  it("refuses YAML the CLI could not read at all, accepts what the engine judges", () => {
    expect(checkImport("policies.yml", "base_currency: [\n")).toMatchObject({ ok: false, refusal: { kind: "unreadable", problem: { code: "BAD-YAML" } } });
    expect(checkImport("policies.yml", "- a\n")).toMatchObject({ ok: false, refusal: { kind: "unreadable", problem: { code: "BAD-SHAPE" } } });
    expect(checkImport("decisions.yml", "# nothing\n")).toMatchObject({ ok: false, refusal: { kind: "unreadable", problem: { code: "FILE-EMPTY" } } });
    expect(checkImport("decisions.yml", "id: x\n")).toMatchObject({ ok: false, refusal: { kind: "unreadable", problem: { code: "BAD-SHAPE" } } });
    expect(checkImport("decisions.yml", "[]\n").ok).toBe(true);
    // a policy problem is the engine's to show, not a refusal
    expect(checkImport("policies.yml", "version: 2\n").ok).toBe(true);
  });

  it("decodes UTF-8 strictly and names the bad byte", () => {
    expect(decodeUtf8(enc("caf" + String.fromCharCode(0xe9)))).toEqual({ ok: true, text: "caf" + String.fromCharCode(0xe9) });
    expect(decodeUtf8(new Uint8Array([0x61, 0x62, 0xff, 0x63]))).toEqual({ ok: false, detail: "byte 2" });
    expect(decodeUtf8(enc(BOM + "a"))).toEqual({ ok: true, text: BOM + "a" });
    expect(checkFileBytes("rates.csv", new Uint8Array([0x64, 0xff]))).toMatchObject({ ok: false, refusal: { kind: "not-utf8" } });
  });

  it("matches a chosen file by its exact name", () => {
    expect(fileNameOf("ledger.csv")).toBe("ledger.csv");
    expect(fileNameOf("C:\\books\\policies.yml")).toBe("policies.yml");
    expect(fileNameOf("Ledger.csv")).toBeNull();
    expect(checkFileBytes("notes.txt", enc("x"))).toMatchObject({ ok: false, refusal: { kind: "unknown-name", name: "notes.txt" } });
    expect(checkFileBytes("whatever.csv", enc("date,currency,rate\n"), "rates.csv")).toMatchObject({ ok: true, name: "rates.csv" });
  });

  it("the bundled sample is reference/examples byte for byte, and loads as the CLI counts it", () => {
    const sample = sampleHousehold();
    for (const f of FILE_NAMES) expect(sample[f]).toBe(readFileSync(join(process.cwd(), "reference", "examples", f), "utf8"));
    for (const f of FILE_NAMES) expect(checkImport(f, sample[f] as string).ok).toBe(true);
    expect(loadHousehold(sample).files).toEqual({ "policies.yml": 8, "ledger.csv": 271, "holdings.csv": 72, "decisions.yml": 4, "rates.csv": 24 });
  });
});
