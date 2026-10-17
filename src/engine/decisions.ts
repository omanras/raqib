// decisions.yml: decisions taken, each with a review date (reference engine
// ADR section 7). A list of mappings; `closes` names a kill policy whose
// crossing this decision answers (FAILURE_MODEL "A kill closed by a
// backdated decision").
import { isValidDate } from "./dates";
import { makeProblem, type Config, type Decision, type ParsedDecisions, type Problem } from "./types";
import { isMap, isNullish, isSeq, itemLines, loadYaml, textOf, yNull, yStr } from "./yaml";

export const DECISION_KEYS = ["id", "date", "title", "policy", "criteria", "review_by", "status", "closes"] as const;

/**
 * Parse decisions.yml. A decision the engine cannot read is a problem and
 * is left out (its line is named); the run continues. With a config, the
 * policy names are checked.
 */
export function parseDecisions(text: string, config: Config | null): ParsedDecisions {
  const problems: Problem[] = [];
  const decisions: Decision[] = [];
  const loaded = loadYaml(text);
  if (!loaded.ok) {
    problems.push(makeProblem("BAD-YAML", "decisions.yml", loaded.line, loaded.reason));
    return { decisions, problems, count: 0 };
  }
  const doc = loaded.value;
  if (doc === null) return { decisions, problems, count: 0 };
  if (!isSeq(doc)) {
    problems.push(makeProblem("BAD-FILE", "decisions.yml", null, "decisions.yml must be a list of decisions"));
    return { decisions, problems, count: 0 };
  }
  const lines = itemLines(text, 0);
  const seen = new Set<string>();
  doc.forEach((item, i) => {
    const line = lines.length === doc.length ? (lines[i] as number) : null;
    const where = `decision ${i + 1}`;
    if (!isMap(item)) {
      problems.push(makeProblem("BAD-DECISION", "decisions.yml", line, `${where} must be a mapping`));
      return;
    }
    const id = textOf(item["id"]);
    if (id === null) {
      problems.push(makeProblem("BAD-DECISION", "decisions.yml", line, `${where} has no id`));
      return;
    }
    const date = textOf(item["date"]);
    if (date === null || !isValidDate(date)) {
      problems.push(makeProblem("BAD-DATE", "decisions.yml", line, `${id}: bad date "${date ?? ""}" (YYYY-MM-DD)`));
      return;
    }
    const reviewBy = textOf(item["review_by"]);
    if (reviewBy === null || !isValidDate(reviewBy)) {
      problems.push(makeProblem("BAD-DATE", "decisions.yml", line, `${id}: bad review_by "${reviewBy ?? ""}" (YYYY-MM-DD)`));
      return;
    }
    const status = textOf(item["status"]);
    if (status !== "open" && status !== "closed") {
      problems.push(makeProblem("BAD-STATUS", "decisions.yml", line, `${id}: status must be open or closed (got "${status ?? ""}")`));
      return;
    }
    const title = textOf(item["title"]) ?? "";
    const criteria = textOf(item["criteria"]) ?? "";
    const policy = isNullish(item["policy"]) ? null : textOf(item["policy"]);
    const closes = isNullish(item["closes"]) ? null : textOf(item["closes"]);
    if (config) {
      if (policy !== null && !config.policies.some((p) => p.id === policy)) {
        problems.push(makeProblem("BAD-POLICY", "decisions.yml", line, `${id}: policy ${policy} is not declared in policies.yml`));
      }
      if (closes !== null) {
        const target = config.policies.find((p) => p.id === closes);
        if (!target) problems.push(makeProblem("BAD-CLOSES", "decisions.yml", line, `${id}: closes ${closes}, which is not declared in policies.yml`));
        else if (target.type !== "kill") problems.push(makeProblem("BAD-CLOSES", "decisions.yml", line, `${id}: closes ${closes}, which is not a kill policy`));
      }
    }
    if (seen.has(id)) problems.push(makeProblem("DUP-ID", "decisions.yml", line, `decision id ${id} is declared twice`));
    seen.add(id);
    decisions.push({ line, id, date, title, policy, criteria, reviewBy, status, closes });
  });
  return { decisions, problems, count: doc.length };
}

function entry(prefix: string, key: string, value: string): string {
  return `${prefix}${key}: ${value}`;
}

export function decisionBlock(d: Decision): string {
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
export function serializeDecisions(decisions: readonly Decision[]): string {
  if (decisions.length === 0) return "[]\n";
  return decisions.map(decisionBlock).join("");
}

/** Append one decision to decisions.yml text without rewriting the others. */
export function appendDecision(text: string, d: Decision): string {
  const trimmed = text.trim();
  if (trimmed === "" || trimmed === "[]") return decisionBlock(d);
  const base = text.endsWith("\n") ? text : text + "\n";
  return base + decisionBlock(d);
}
