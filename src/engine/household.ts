// A household is the five files as text. Loading follows the CLI's
// load_household: policies first (the others are checked against it);
// every problem is collected and nothing throws (A3: a problem is a
// finding, not an exception). Problems that would make the CLI exit 3 are
// `fatal`: any policies.yml problem, and a file-level problem (missing,
// empty, too large, bad header, bad YAML or shape) in another file.
import { parseDecisions } from "./decisions";
import { parseHoldings } from "./holdings";
import { parseLedger } from "./ledger";
import type { Context } from "./measures";
import { parsePolicies } from "./policies";
import { parseRates } from "./rates";
import { FILE_NAMES, type Config, type Decision, type FileName, type HouseholdText, type Problem } from "./types";

export const FILE_LEVEL = ["FILE-MISSING", "FILE-UNREADABLE", "FILE-TOO-LARGE", "FILE-EMPTY", "BAD-HEADER", "BAD-YAML", "BAD-SHAPE", "INTERNAL"];

export interface Household {
  text: HouseholdText;
  /** null when policies.yml could not be read; nothing else is loaded then */
  config: Config | null;
  /** the measure context (asOf unset: each command sets it) */
  ctx: Context | null;
  decisions: Decision[];
  /** loader problems per file, for the files that were loaded */
  problemsByFile: Partial<Record<FileName, Problem[]>>;
  /** every problem, in file order */
  problems: Problem[];
  /** row counts as the CLI's `files` (null: absent rates.csv, unreadable policies.yml) */
  files: Partial<Record<FileName, number | null>>;
  /** the problems that stop the run (CLI exit 3) */
  fatal: Problem[];
}

export function emptyHouseholdText(): HouseholdText {
  return { "policies.yml": null, "ledger.csv": null, "holdings.csv": null, "decisions.yml": null, "rates.csv": null };
}

function isFileLevel(p: Problem): boolean {
  return p.line === 0 || FILE_LEVEL.includes(p.code);
}

export function loadHousehold(text: HouseholdText): Household {
  const problemsByFile: Partial<Record<FileName, Problem[]>> = {};
  const files: Partial<Record<FileName, number | null>> = {};
  const fatal: Problem[] = [];
  const done = (config: Config | null, ctx: Context | null, decisions: Decision[]): Household => ({
    text,
    config,
    ctx,
    decisions,
    problemsByFile,
    problems: FILE_NAMES.flatMap((f) => problemsByFile[f] ?? []),
    files,
    fatal,
  });

  const pol = parsePolicies(text["policies.yml"]);
  problemsByFile["policies.yml"] = pol.problems;
  files["policies.yml"] = pol.config !== null ? pol.config.policies.length : null;
  fatal.push(...pol.problems.filter((p) => p.class === "invalid"));
  const config = pol.config;
  if (config === null) return done(null, null, []);

  const led = parseLedger(text["ledger.csv"], config);
  problemsByFile["ledger.csv"] = led.problems;
  files["ledger.csv"] = led.rows.length;
  fatal.push(...led.problems.filter(isFileLevel));

  const hol = parseHoldings(text["holdings.csv"], config);
  problemsByFile["holdings.csv"] = hol.problems;
  files["holdings.csv"] = hol.rows.length;
  fatal.push(...hol.problems.filter(isFileLevel));

  const dec = parseDecisions(text["decisions.yml"], config);
  problemsByFile["decisions.yml"] = dec.problems;
  files["decisions.yml"] = dec.decisions.length;
  fatal.push(...dec.problems.filter(isFileLevel));

  const rt = parseRates(text["rates.csv"], config.baseCurrency);
  problemsByFile["rates.csv"] = rt.problems;
  files["rates.csv"] = text["rates.csv"] !== null ? rt.table.rows.length : null;
  fatal.push(...rt.problems.filter(isFileLevel));

  const ctx: Context = {
    config,
    ledger: led.rows,
    holdings: hol.rows,
    rates: rt.table,
    asOf: null,
    ledgerProblems: led.problems,
    holdingsProblems: hol.problems,
    decisions: dec.decisions,
  };
  return done(config, ctx, dec.decisions);
}
