// The synthetic sample household (A9), bundled at build time from
// reference/examples/ as text: the same bytes the CLI's oracle was made from.
import decisions from "../../reference/examples/decisions.yml?raw";
import holdings from "../../reference/examples/holdings.csv?raw";
import ledger from "../../reference/examples/ledger.csv?raw";
import policies from "../../reference/examples/policies.yml?raw";
import rates from "../../reference/examples/rates.csv?raw";
import type { HouseholdText } from "../engine/types";

export function sampleHousehold(): HouseholdText {
  return {
    "policies.yml": policies,
    "ledger.csv": ledger,
    "holdings.csv": holdings,
    "decisions.yml": decisions,
    "rates.csv": rates,
  };
}
