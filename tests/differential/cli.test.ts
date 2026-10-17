// Every run recorded from the reference CLI (tests/differential/cli/*.json,
// written by generate_cli.py from branch qayd) replayed through the port:
// the same stdout byte for byte (text and --json), the same exit code, and
// for an unreadable household (exit 3) the same message.
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { check, checkText, decisions, decisionsText, EXIT_FILE, fatalText, routine, routineText } from "../../src/engine/commands";
import { loadHousehold } from "../../src/engine/household";
import { parsePeriod, periodContaining } from "../../src/engine/periods";
import { jsonText } from "../../src/engine/report";
import type { HouseholdText } from "../../src/engine/types";

interface Run {
  args: string[];
  exit: number;
  stdout: string;
  stderr: string;
}

interface Case {
  name: string;
  files: HouseholdText;
  runs: Run[];
}

const DIR = join(process.cwd(), "tests", "differential", "cli");
const CASES: Case[] = readdirSync(DIR)
  .filter((f) => f.endsWith(".json"))
  .sort()
  .map((f) => JSON.parse(readFileSync(join(DIR, f), "utf8")) as Case);

/**
 * The one normalisation (questions file, M0.3): the wording of a YAML
 * parser error is the parser's own (PyYAML vs js-yaml); file, line and code
 * of the BAD-YAML problem still have to agree.
 */
function yamlWording(stderr: string): string {
  return stderr.replace(/(BAD-YAML: YAML error: ).*$/gm, "$1<parser message>");
}

function opt(args: string[], name: string): string | null {
  const i = args.indexOf(name);
  return i < 0 ? null : (args[i + 1] as string);
}

/** The port run the way the CLI was: { stdout, stderr, exit }. */
function replay(files: HouseholdText, args: string[]): { stdout: string; stderr: string; exit: number } {
  const h = loadHousehold(files);
  const asOf = opt(args, "--as-of") as string;
  const json = args.includes("--json");
  if (h.fatal.length > 0) return { stdout: "", stderr: fatalText(h), exit: EXIT_FILE };
  const command = args[0];
  if (command === "check") {
    const t = checkText(h, asOf);
    return { stdout: json ? jsonText(check(h, asOf)) : t.text, stderr: "", exit: t.exit };
  }
  if (command === "routine") {
    const p = opt(args, "--period");
    const period = p === null ? periodContaining(asOf, "month") : parsePeriod(p);
    if (period === null) throw new Error(`bad period ${p}`);
    const t = routineText(h, period, asOf);
    return { stdout: json ? jsonText(routine(h, period, asOf)) : t.text, stderr: "", exit: t.exit };
  }
  const t = decisionsText(h, asOf);
  return { stdout: json ? jsonText(decisions(h, asOf)) : t.text, stderr: "", exit: t.exit };
}

describe("differential: the reference CLI's recorded runs", () => {
  it("has the recorded households", () => {
    expect(CASES.length).toBeGreaterThanOrEqual(39);
    expect(CASES.reduce((n, c) => n + c.runs.length, 0)).toBeGreaterThan(1000);
  });

  for (const c of CASES) {
    describe(c.name, () => {
      for (const run of c.runs) {
        it(run.args.join(" "), () => {
          const got = replay(c.files, run.args);
          expect(got.exit).toBe(run.exit);
          expect(got.stdout).toBe(run.stdout);
          expect(yamlWording(got.stderr)).toBe(yamlWording(run.stderr));
        });
      }
    });
  }
});
