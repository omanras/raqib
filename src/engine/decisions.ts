// decisions.yml: decisions taken, each with a review date (reference engine
// ADR section 7, qayd/decisions.py). A YAML list; each entry needs id, date,
// review_by and status (open | closed); `policy` and `closes` must name a
// declared policy, and `closes` a kill policy. A decision with a problem is
// dropped, its line named, and the run continues.
import { daysBetween } from "./dates";
import { fileProblem, INVALID, problem } from "./loader";
import { isMap, isStr, pyRepr, type PyValue } from "./py";
import { parseIsoDate } from "./text";
import type { Config, Decision, DecisionStatus, ParsedDecisions, Problem } from "./types";
import { loadYaml, yNull, yStr } from "./yaml";

export const DECISION_KEYS = ["id", "date", "title", "policy", "criteria", "review_by", "status", "closes"] as const;

function asDate(v: PyValue | undefined): string | null {
  return isStr(v) ? parseIsoDate(v) : null;
}

function textOr(v: PyValue | undefined, dflt = ""): string | null {
  if (v === undefined || v === null) return dflt;
  return isStr(v) ? v : null;
}

function validate(
  raw: PyValue,
  index: number,
  policyIds: ReadonlySet<string>,
  killIds: ReadonlySet<string> | null,
  file: string,
  line: number,
  problems: Problem[],
): Decision | null {
  const field = `decisions[${index}]`;
  const bad = (code: string, sub: string, reason: string): void => {
    problems.push(problem(file, line, code, reason, INVALID, { field: field + sub }));
  };
  if (!isMap(raw)) {
    bad("BAD-FIELD", "", "decision must be a mapping");
    return null;
  }
  let ok = true;
  for (const key of Object.keys(raw).filter((k) => !(DECISION_KEYS as readonly string[]).includes(k)).sort()) {
    bad("BAD-FIELD", "." + key, `unknown key ${pyRepr(key)}`);
    ok = false;
  }
  const id = raw["id"];
  if (!isStr(id) || id.trim() === "") {
    bad("BAD-FIELD", ".id", "id is missing or not text");
    ok = false;
  }
  for (const name of ["date", "review_by"]) {
    if (!(name in raw)) {
      bad("MISSING-FIELD", "." + name, `${name} is missing`);
      ok = false;
    }
  }
  const date = "date" in raw ? asDate(raw["date"]) : null;
  if ("date" in raw && date === null) {
    bad("BAD-DATE", ".date", `date ${pyRepr(raw["date"])} is not YYYY-MM-DD`);
    ok = false;
  }
  const reviewBy = "review_by" in raw ? asDate(raw["review_by"]) : null;
  if ("review_by" in raw && reviewBy === null) {
    bad("BAD-DATE", ".review_by", `review_by ${pyRepr(raw["review_by"])} is not YYYY-MM-DD`);
    ok = false;
  }
  if (date !== null && reviewBy !== null && reviewBy < date) {
    bad("BAD-DATE", ".review_by", `review_by ${reviewBy} is before date ${date}`);
    ok = false;
  }
  const status = raw["status"];
  if (status !== "open" && status !== "closed") {
    bad("BAD-STATUS", ".status", `status must be open or closed (got ${pyRepr(status)})`);
    ok = false;
  }
  const title = textOr(raw["title"]);
  if (title === null) {
    bad("BAD-FIELD", ".title", "title must be text");
    ok = false;
  }
  const criteria = textOr(raw["criteria"]);
  if (criteria === null) {
    bad("BAD-FIELD", ".criteria", "criteria must be text");
    ok = false;
  }
  const policy = raw["policy"] ?? null;
  if (policy !== null && (!isStr(policy) || !policyIds.has(policy))) {
    bad("UNKNOWN-POLICY", ".policy", `policy ${pyRepr(policy)} is not a declared policy id`);
    ok = false;
  }
  const closes = raw["closes"] ?? null;
  if (closes !== null) {
    if (!isStr(closes) || !policyIds.has(closes)) {
      bad("UNKNOWN-POLICY", ".closes", `closes ${pyRepr(closes)} is not a declared policy id`);
      ok = false;
    } else if (killIds !== null && !killIds.has(closes)) {
      bad("BAD-CLOSES", ".closes", `closes ${pyRepr(closes)} names a policy that is not of type kill`);
      ok = false;
    }
  }
  if (!ok) return null;
  return {
    id: id as string,
    date: date as string,
    title: title as string,
    policy: policy as string | null,
    criteria: criteria as string,
    reviewBy: reviewBy as string,
    status: status as DecisionStatus,
    closes: closes as string | null,
    line,
    file,
    cite: `${file}:${line}`,
  };
}

/**
 * Parse decisions.yml (`null`: the file does not exist). The config gives
 * the declared policy ids and the kill policies `closes` may name; without
 * one, no policy is declared. Never throws.
 */
export function parseDecisions(text: string | null, config: Config | null, file = "decisions.yml"): ParsedDecisions {
  const ids = new Set(config ? config.policies.map((p) => p.id) : []);
  const kills = config ? new Set(config.policies.filter((p) => p.type === "kill").map((p) => p.id)) : null;
  return loadDecisions(text, ids, kills, file);
}

export function loadDecisions(text: string | null, policyIds: ReadonlySet<string>, killIds: ReadonlySet<string> | null, file = "decisions.yml"): ParsedDecisions {
  const fatal = fileProblem(text, file);
  if (fatal) return { decisions: [], problems: [fatal] };
  const loaded = loadYaml(text as string);
  if (!loaded.ok) return { decisions: [], problems: [problem(file, loaded.line, "BAD-YAML", loaded.reason)] };
  if (loaded.value === null) return { decisions: [], problems: [problem(file, 0, "FILE-EMPTY", "file holds no YAML document")] };
  const problems: Problem[] = [];
  const doc = loaded.value;
  try {
    if (!Array.isArray(doc)) {
      problems.push(problem(file, 1, "BAD-SHAPE", "decisions.yml must be a list of decisions at the top level", INVALID, { field: "" }));
      return { decisions: [], problems };
    }
    const out: Decision[] = [];
    const seen = new Map<string, number>();
    doc.forEach((raw, index) => {
      const d = validate(raw, index, policyIds, killIds, file, loaded.lineOf(raw) ?? 1, problems);
      if (d === null) return;
      const prior = seen.get(d.id);
      if (prior !== undefined) {
        problems.push(problem(file, d.line, "DUP-ID", `decision id ${pyRepr(d.id)} is already used at line ${prior}`, INVALID, { field: `decisions[${index}].id` }));
        return;
      }
      seen.set(d.id, d.line);
      out.push(d);
    });
    return { decisions: out, problems };
  } catch (e) {
    problems.push(problem(file, 0, "INTERNAL", `loader failed: ${e instanceof Error ? `${e.name}: ${e.message}` : String(e)}`));
    return { decisions: [], problems };
  }
}

/** Days from asOf to review_by; negative when overdue. */
export function daysUntilReview(d: Decision, asOf: string): number {
  return daysBetween(asOf, d.reviewBy);
}

/** DECISION-DUE: open and review_by strictly before asOf (ADR section 7). */
export function isDue(d: Decision, asOf: string): boolean {
  return d.status === "open" && d.reviewBy < asOf;
}

// ---- serializer -----------------------------------------------------------

export interface DecisionFields {
  id: string;
  date: string;
  title: string;
  policy: string | null;
  criteria: string;
  reviewBy: string;
  status: DecisionStatus;
  closes: string | null;
}

function entry(prefix: string, key: string, value: string): string {
  return `${prefix}${key}: ${value}`;
}

export function decisionBlock(d: DecisionFields): string {
  const lines = [
    entry("- ", "id", yStr(d.id)),
    entry("  ", "date", d.date),
    entry("  ", "title", yStr(d.title)),
    entry("  ", "policy", d.policy === null ? yNull() : yStr(d.policy)),
    entry("  ", "criteria", yStr(d.criteria)),
    entry("  ", "review_by", d.reviewBy),
    entry("  ", "status", d.status),
    entry("  ", "closes", d.closes === null ? yNull() : yStr(d.closes)),
  ];
  return lines.join("\n") + "\n";
}

/** decisions.yml text in the reference style; an empty list is `[]`. */
export function serializeDecisions(decisions: readonly DecisionFields[]): string {
  if (decisions.length === 0) return "[]\n";
  return decisions.map(decisionBlock).join("");
}

/** Append one decision to decisions.yml text without rewriting the others. */
export function appendDecision(text: string | null, d: DecisionFields): string {
  const trimmed = (text ?? "").trim();
  if (trimmed === "" || trimmed === "[]") return decisionBlock(d);
  const base = (text as string).endsWith("\n") ? (text as string) : text + "\n";
  return base + decisionBlock(d);
}
