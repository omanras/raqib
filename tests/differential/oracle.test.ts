// A10: on reference/examples the app's check, routine and decisions equal
// the CLI's JSON in reference/oracle/ by deep equality, with no
// normalisation. A disagreement is a bug in the port, never in the oracle.
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { check, decisions, routine } from "../../src/engine/commands";
import { loadHousehold } from "../../src/engine/household";
import { parsePeriod } from "../../src/engine/periods";
import { exampleHousehold, readOracle, REFERENCE_DIR } from "../engine/fixtures";

const ORACLE = readdirSync(join(REFERENCE_DIR, "oracle")).filter((f) => f.endsWith(".json")).sort();

describe("differential: reference/oracle", () => {
  const h = loadHousehold(exampleHousehold());

  it("covers every oracle file", () => {
    expect(ORACLE).toEqual([
      "check-2025-11-30.json",
      "check-2026-03-31.json",
      "check-2026-07-31.json",
      "check-2026-09-30.json",
      "check-2026-12-31.json",
      "decisions-2026-09-30.json",
      "routine-2026-03.json",
    ]);
  });

  for (const name of ORACLE) {
    it(name, () => {
      const oracle = readOracle(name) as { command: string; as_of: string; period?: string };
      let result: unknown;
      if (oracle.command === "check") result = check(h, oracle.as_of);
      else if (oracle.command === "decisions") result = decisions(h, oracle.as_of);
      else result = routine(h, parsePeriod(oracle.period as string)!, oracle.as_of);
      expect(result).toEqual(oracle);
      // byte level too: the CLI's own text (json.dumps indent 2, key order, final newline)
      expect(JSON.stringify(result, null, 2) + "\n").toBe(readFileSync(join(REFERENCE_DIR, "oracle", name), "utf8"));
    });
  }
});
