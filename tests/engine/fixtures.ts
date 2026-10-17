// The synthetic example household (A9) read from reference/ (read-only),
// and the reference engine's own test fixtures (synthetic, copied from
// branch qayd tests/fixtures into fixtures/qayd/) so the CLI's tests can be
// ported with their expectations.
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { loadHousehold, type Household } from "../../src/engine/household";
import { FILE_NAMES, type HouseholdText } from "../../src/engine/types";

export const REFERENCE_DIR = join(process.cwd(), "reference");
export const QAYD_FIXTURES = join(process.cwd(), "tests", "engine", "fixtures", "qayd");

export function readExample(name: keyof HouseholdText): string {
  return readFileSync(join(REFERENCE_DIR, "examples", name), "utf8");
}

export function exampleHousehold(): HouseholdText {
  return {
    "policies.yml": readExample("policies.yml"),
    "ledger.csv": readExample("ledger.csv"),
    "holdings.csv": readExample("holdings.csv"),
    "decisions.yml": readExample("decisions.yml"),
    "rates.csv": readExample("rates.csv"),
  };
}

export function readOracle(name: string): unknown {
  return JSON.parse(readFileSync(join(REFERENCE_DIR, "oracle", name), "utf8"));
}

/** A file of fixtures/qayd/<path>, or null when it does not exist (FILE-MISSING). */
export function fixture(path: string): string | null {
  const p = join(QAYD_FIXTURES, path);
  return existsSync(p) ? readFileSync(p, "utf8") : null;
}

/** The five files of a fixture directory (fixtures/qayd/<dir>/); absent files are null. */
export function fixtureText(dir: string): HouseholdText {
  const out = {} as HouseholdText;
  for (const f of FILE_NAMES) out[f] = fixture(join(dir, f));
  return out;
}

export function fixtureHousehold(dir: string): Household {
  return loadHousehold(fixtureText(dir));
}
