// A household is the five files as text. Loading parses them in the order
// the CLI does (policies first, since the others are checked against it)
// and collects every problem; nothing stops the run (A3: a problem is a
// finding, not an exception).
import { parseDecisions } from "./decisions";
import { parseHoldings } from "./holdings";
import { parseLedger } from "./ledger";
import { parsePolicies } from "./policies";
import { parseRates } from "./rates";
import type { HouseholdText, ParsedDecisions, ParsedHoldings, ParsedLedger, ParsedPolicies, ParsedRates, Problem } from "./types";

export interface Household {
  text: HouseholdText;
  policies: ParsedPolicies;
  ledger: ParsedLedger;
  holdings: ParsedHoldings;
  decisions: ParsedDecisions;
  rates: ParsedRates;
  /** every problem of every file, in file order */
  problems: Problem[];
  /** row and policy counts, the CLI's `files` object */
  files: { [K in keyof HouseholdText]: number };
}

export function emptyHouseholdText(): HouseholdText {
  return { "policies.yml": "", "ledger.csv": "", "holdings.csv": "", "decisions.yml": "", "rates.csv": "" };
}

export function loadHousehold(text: HouseholdText): Household {
  const policies = parsePolicies(text["policies.yml"]);
  const config = policies.config;
  const ledger = parseLedger(text["ledger.csv"], config);
  const holdings = parseHoldings(text["holdings.csv"], config);
  const decisions = parseDecisions(text["decisions.yml"], config);
  const rates = parseRates(text["rates.csv"]);
  const problems = [...policies.problems, ...ledger.problems, ...holdings.problems, ...decisions.problems, ...rates.problems];
  return {
    text,
    policies,
    ledger,
    holdings,
    decisions,
    rates,
    problems,
    files: {
      "policies.yml": policies.count,
      "ledger.csv": ledger.count,
      "holdings.csv": holdings.count,
      "decisions.yml": decisions.count,
      "rates.csv": rates.count,
    },
  };
}
