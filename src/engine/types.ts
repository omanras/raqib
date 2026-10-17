// Shared types of the engine port. Amounts are Decimal (A5); every row
// keeps its line number so a verdict can cite file:line (A4).
import type { Decimal } from "./decimal";
import type { PeriodKind } from "./periods";

export type FileName = "policies.yml" | "ledger.csv" | "holdings.csv" | "decisions.yml" | "rates.csv";

export const FILE_NAMES: readonly FileName[] = [
  "policies.yml",
  "ledger.csv",
  "holdings.csv",
  "decisions.yml",
  "rates.csv",
];

/** Something a file says that the engine cannot accept. The run continues. */
export interface Problem {
  code: string;
  file: FileName;
  /** 1-based line, or null when the whole file is concerned */
  line: number | null;
  /** "file:line" or "file" */
  cite: string;
  reason: string;
}

export function makeProblem(code: string, file: FileName, line: number | null, reason: string): Problem {
  return { code, file, line, cite: line === null ? file : `${file}:${line}`, reason };
}

/** A row the engine could not read. It still touches its period (A3). */
export interface InvalidRow {
  line: number;
  /** the row's date when it could be read, else null (touches every period) */
  date: string | null;
  code: string;
  reason: string;
  raw: string;
}

export interface LedgerRow {
  line: number;
  date: string;
  amount: Decimal;
  /** the amount as written in the file; serialised back unchanged */
  amountText: string;
  currency: string;
  account: string;
  category: string;
  tags: string[];
  note: string;
}

export interface DupNote {
  line: number;
  firstLine: number;
  text: string;
}

export interface ParsedLedger {
  rows: LedgerRow[];
  invalid: InvalidRow[];
  problems: Problem[];
  dupNotes: DupNote[];
  /** data lines (valid and invalid) */
  count: number;
}

export interface HoldingRow {
  line: number;
  date: string;
  account: string;
  asset: string;
  cls: string;
  quantity: Decimal;
  quantityText: string;
  value: Decimal;
  valueText: string;
  currency: string;
}

export interface ParsedHoldings {
  rows: HoldingRow[];
  invalid: InvalidRow[];
  problems: Problem[];
  dupNotes: DupNote[];
  count: number;
}

export interface Snapshot {
  date: string;
  rows: HoldingRow[];
}

export interface RateRow {
  line: number;
  date: string;
  currency: string;
  rate: Decimal;
  rateText: string;
}

export interface ParsedRates {
  rates: RateRow[];
  invalid: InvalidRow[];
  problems: Problem[];
  count: number;
}

export type PolicyType = "cap" | "floor" | "routine" | "red_line" | "kill" | "allocation";

export const POLICY_TYPES: readonly PolicyType[] = ["cap", "floor", "routine", "red_line", "kill", "allocation"];

export type Measure =
  | { kind: "sum"; group: string; category: string | null; period: PeriodKind }
  | { kind: "holdings"; by: "class" | "account"; name: string }
  | { kind: "share"; by: "class"; name: string }
  | { kind: "drawdown"; by: "account"; name: string; windowDays: number };

export type Limit =
  | { kind: "value"; value: Decimal }
  | { kind: "pct_of"; of: "income"; value: Decimal }
  | { kind: "months_of"; of: "expense"; value: Decimal }
  | { kind: "pct"; value: Decimal };

export interface Match {
  tags: string[] | null;
  tagsAny: string[] | null;
  account: string | null;
  category: string | null;
  minAmount: Decimal | null;
}

export interface Band {
  minPct: Decimal;
  maxPct: Decimal;
}

export interface Policy {
  /** 1-based line of the "- id:" item, or null when unknown */
  line: number | null;
  id: string;
  type: PolicyType | string;
  title: string;
  measure: Measure | null;
  limit: Limit | null;
  match: Match | null;
  band: Band | null;
  period: PeriodKind | null;
  /** "ok" when the loader accepted the declaration, else "unknown" */
  status: "ok" | "unknown";
  /** why the declaration is unknown */
  reason: string | null;
  /** the raw YAML mapping, kept for the serializer and the UI */
  raw: Record<string, unknown>;
}

export interface Config {
  version: string | null;
  baseCurrency: string;
  accounts: string[];
  /** group -> categories, in file order */
  categories: Record<string, string[]>;
  classes: string[];
  snapshotMaxAgeDays: number | null;
  policies: Policy[];
}

export interface ParsedPolicies {
  config: Config | null;
  problems: Problem[];
  count: number;
}

export type DecisionStatus = "open" | "closed";

export interface Decision {
  line: number | null;
  id: string;
  date: string;
  title: string;
  policy: string | null;
  criteria: string;
  reviewBy: string;
  status: DecisionStatus;
  closes: string | null;
}

export interface ParsedDecisions {
  decisions: Decision[];
  problems: Problem[];
  count: number;
}

export const DEFAULT_CLASSES: readonly string[] = ["cash", "equity", "fund", "property", "gold", "debt", "other"];

/** The five files as text: the whole state of a household. */
export interface HouseholdText {
  "policies.yml": string;
  "ledger.csv": string;
  "holdings.csv": string;
  "decisions.yml": string;
  "rates.csv": string;
}
