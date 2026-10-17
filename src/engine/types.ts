// Shared types of the engine port. Amounts are Decimal (A5); every row
// keeps its file and line so a verdict can cite file:line (A4). Shapes
// follow the reference engine (branch qayd, qayd/*.py) one to one.
import type { Decimal, Num } from "./decimal";
import type { PeriodKind } from "./periods";
import type { PyMap } from "./py";

export type FileName = "policies.yml" | "ledger.csv" | "holdings.csv" | "decisions.yml" | "rates.csv";

export const FILE_NAMES: readonly FileName[] = [
  "policies.yml",
  "ledger.csv",
  "holdings.csv",
  "decisions.yml",
  "rates.csv",
];

/**
 * A loader problem, the CLI's plain dict: `line` 0 means the whole file;
 * `class` is "invalid" (red; the row is not loaded) or "warn" (the row is
 * loaded; DUP-ROW). Row problems carry the row's ISO `date` when it parsed,
 * so later layers can mark the period. Serialised as is in `problems`.
 */
export interface Problem {
  file: string;
  line: number;
  code: string;
  class: "invalid" | "warn";
  reason: string;
  date?: string;
  dup_of?: number;
  field?: string;
}

export interface Citable {
  /** "file:line" */
  cite: string;
}

export interface LedgerRow extends Citable {
  date: string;
  amount: Decimal;
  /** the amount as written in the file; serialised back unchanged */
  amountText: string;
  currency: string;
  account: string;
  category: string;
  tags: string[];
  note: string;
  line: number;
  file: string;
}

export interface HoldingRow extends Citable {
  date: string;
  account: string;
  asset: string;
  cls: string;
  quantity: Decimal;
  quantityText: string;
  value: Decimal;
  valueText: string;
  currency: string;
  line: number;
  file: string;
}

export interface RateRow extends Citable {
  date: string;
  currency: string;
  rate: Decimal;
  rateText: string;
  line: number;
  file: string;
}

export interface DupNote {
  line: number;
  firstLine: number;
}

export interface ParsedLedger {
  rows: LedgerRow[];
  /** every loader problem in line order, warnings included */
  problems: Problem[];
  dupNotes: DupNote[];
}

export interface ParsedHoldings {
  rows: HoldingRow[];
  problems: Problem[];
  dupNotes: DupNote[];
}

export interface Snapshot {
  /** null when no snapshot is on or before the date */
  date: string | null;
  rows: HoldingRow[];
}

export type PolicyType = "cap" | "floor" | "routine" | "red_line" | "kill" | "allocation";

export const POLICY_TYPES: readonly PolicyType[] = ["cap", "floor", "routine", "red_line", "kill", "allocation"];

export type Measure =
  | { kind: "sum"; group: string; category: string | null; period: PeriodKind }
  | { kind: "holdings"; by: "class" | "account"; name: string }
  | { kind: "share"; by: "class"; name: string }
  | { kind: "drawdown"; by: "account"; name: string; windowDays: number };

export type Limit =
  | { kind: "value"; value: Num }
  | { kind: "pct_of"; of: "income"; value: Num }
  | { kind: "months_of"; of: "expense"; value: Num }
  | { kind: "pct"; value: Num };

export interface Match {
  tags: string[] | null;
  tagsAny: string[] | null;
  account: string | null;
  category: string | null;
  minAmount: Num | null;
}

export interface Band {
  minPct: Num;
  maxPct: Num;
}

export interface Policy extends Citable {
  id: string;
  /** the declared type, as text (Python's str() of whatever was written) */
  type: PolicyType | string;
  title: string;
  measure: Measure | null;
  limit: Limit | null;
  match: Match | null;
  period: PeriodKind | null;
  band: Band | null;
  /** "ok" when the loader accepted the declaration, else "unknown" */
  status: "ok" | "unknown";
  /** why the declaration is unknown */
  reason: string | null;
  line: number;
  file: string;
  /** the raw YAML mapping, kept for the serializer and the UI */
  raw: PyMap;
}

export interface Config {
  /** 1 when declared correctly, else null (a problem names it) */
  version: number | null;
  baseCurrency: string | null;
  accounts: string[];
  /** group -> categories, in file order */
  categories: Record<string, string[]>;
  classes: string[];
  snapshotMaxAgeDays: number | null;
  policies: Policy[];
  file: string;
}

export interface ParsedPolicies {
  /** null only when the file could not be read or is not a mapping */
  config: Config | null;
  problems: Problem[];
}

export type DecisionStatus = "open" | "closed";

export interface Decision extends Citable {
  id: string;
  date: string;
  title: string;
  policy: string | null;
  criteria: string;
  reviewBy: string;
  status: DecisionStatus;
  closes: string | null;
  line: number;
  file: string;
}

export interface ParsedDecisions {
  decisions: Decision[];
  problems: Problem[];
}

export const DEFAULT_CLASSES: readonly string[] = ["cash", "equity", "fund", "property", "gold", "debt", "other"];

/**
 * The five files as text: the whole state of a household. `null` is a
 * file that does not exist (the CLI's FILE-MISSING; for rates.csv, which
 * is optional, an empty table); "" is a file that exists and is empty.
 */
export type HouseholdText = { [K in FileName]: string | null };
