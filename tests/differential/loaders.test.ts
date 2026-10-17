// The reference loaders' output on their own fixtures (loaders.json, written
// by generate_cli.py from branch qayd) against the port: every problem
// (file, line, code, class, reason, date, dup_of, field) and every row,
// policy and decision. One normalisation, as in cli.test.ts: the wording
// of a YAML parser error (PyYAML vs js-yaml); its file, line and code agree.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { pyDecimalStr } from "../../src/engine/decimal";
import { loadDecisions } from "../../src/engine/decisions";
import { parseHoldings } from "../../src/engine/holdings";
import { parseLedger } from "../../src/engine/ledger";
import { bandText, limitText, matchText, measureText, parsePolicies } from "../../src/engine/policies";
import { parseRates } from "../../src/engine/rates";
import type { Config, Problem } from "../../src/engine/types";
import { fixture } from "../engine/fixtures";

interface Entry {
  kind: "ledger" | "holdings" | "rates" | "policies" | "decisions";
  name: string;
  problems: Problem[];
  rows?: unknown[];
  config?: unknown;
  decisions?: unknown[];
}

const ENTRIES = JSON.parse(readFileSync(join(process.cwd(), "tests", "differential", "loaders.json"), "utf8")) as Entry[];

const CONFIG = {
  accounts: ["salary", "savings", "broker", "cash"],
  categories: {
    income: ["salary", "bonus", "side"],
    expense: ["housing", "food", "transport", "family", "discretionary", "fees"],
    transfer: ["transfer"],
    invest: ["buy", "sell", "dividend"],
  },
  classes: ["cash", "equity", "fund", "property", "gold", "debt", "other"],
} as unknown as Config;

function normal(problems: Problem[]): Problem[] {
  return problems.map((p) => (p.code === "BAD-YAML" ? { ...p, reason: "YAML error: <parser message>" } : p));
}

function configJson(c: Config | null): unknown {
  if (c === null) return null;
  return {
    version: c.version,
    base_currency: c.baseCurrency,
    accounts: c.accounts,
    categories: c.categories,
    classes: c.classes,
    snapshot_max_age_days: c.snapshotMaxAgeDays,
    policies: c.policies.map((p) => ({
      id: p.id,
      type: p.type,
      title: p.title,
      status: p.status,
      reason: p.reason,
      line: p.line,
      measure: p.measure ? measureText(p.measure) : null,
      limit: p.limit ? limitText(p.limit, "OMR") : null,
      match: p.match ? matchText(p.match) : null,
      band: p.band ? bandText(p.band) : null,
      period: p.period,
    })),
  };
}

describe("differential: the reference loaders on their fixtures", () => {
  it("has every fixture but the two invalid-UTF-8 ones", () => {
    expect(ENTRIES.length).toBe(61);
  });

  for (const e of ENTRIES) {
    it(`${e.kind}/${e.name}`, () => {
      const text = fixture(`${e.kind}/${e.name}`);
      if (e.kind === "ledger") {
        const got = parseLedger(text, CONFIG, e.name);
        expect(got.problems).toEqual(e.problems);
        expect(got.rows.map((r) => [r.line, r.date, fmtPy(r.amountText), r.currency, r.account, r.category, r.tags, r.note])).toEqual(e.rows);
      } else if (e.kind === "holdings") {
        const got = parseHoldings(text, CONFIG, e.name);
        expect(got.problems).toEqual(e.problems);
        expect(got.rows.map((r) => [r.line, r.date, r.account, r.asset, r.cls, fmtPy(r.quantityText), fmtPy(r.valueText), r.currency])).toEqual(e.rows);
      } else if (e.kind === "rates") {
        const got = parseRates(text, "OMR", e.name);
        expect(got.problems).toEqual(e.problems);
        expect(got.table.rows.map((r) => [r.line, r.date, r.currency, fmtPy(r.rateText)])).toEqual(e.rows);
      } else if (e.kind === "policies") {
        const got = parsePolicies(text, e.name);
        expect(normal(got.problems)).toEqual(normal(e.problems));
        expect(configJson(got.config)).toEqual(e.config);
      } else {
        const got = loadDecisions(text, new Set(["WLT-01", "WLT-05"]), new Set(["WLT-05"]), e.name);
        expect(normal(got.problems)).toEqual(normal(e.problems));
        expect(got.decisions.map((d) => [d.id, d.date, d.title, d.policy, d.criteria, d.reviewBy, d.status, d.closes, d.line])).toEqual(e.decisions);
      }
    });
  }
});

/** Python's str(Decimal(text)), as the generator wrote amounts. */
function fmtPy(text: string): string | null {
  return pyDecimalStr(text);
}
