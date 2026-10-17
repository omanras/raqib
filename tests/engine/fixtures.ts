// The synthetic example household (A9) read from reference/ (read-only).
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { HouseholdText } from "../../src/engine/types";

export const REFERENCE_DIR = join(process.cwd(), "reference");

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
