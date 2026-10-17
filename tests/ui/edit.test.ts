// The forms' changes to the YAML files (src/ui/textEdit.ts, policyModel.ts)
// on the sample household: one block replaced, added or removed, the rest of
// the text untouched; the engine as the validator; the export bundle.
import { describe, expect, it } from "vitest";
import { check } from "../../src/engine/commands";
import { parseDecisions } from "../../src/engine/decisions";
import { loadHousehold } from "../../src/engine/household";
import { parsePolicies, policyById } from "../../src/engine/policies";
import type { Config, HouseholdText } from "../../src/engine/types";
import { sampleHousehold } from "../../src/store/sample";
import { addFromDraft, blankDraft, draftOf, editFromDraft, rawOf, removeAt } from "../../src/ui/policyModel";
import { bundleText, closeDecision, listSection, nextDecisionId, readBundle } from "../../src/ui/textEdit";

const files = sampleHousehold();
const policies = files["policies.yml"] as string;
const decisions = files["decisions.yml"] as string;
const config = parsePolicies(policies).config as Config;

describe("ui/textEdit and policyModel", () => {
  it("finds the block items of the policies list and of decisions.yml", () => {
    const s = listSection(policies, "policies");
    expect([s?.col, s?.starts.map((i) => i + 1)]).toEqual([2, [12, 17, 22, 27, 31, 36, 41, 46]]);
    expect(listSection(decisions, null)?.starts.map((i) => i + 1)).toEqual([2, 10, 18, 26]);
  });

  it("every accepted policy's draft writes back the same policy, touching no other line", () => {
    const strip = (x: Config["policies"][number]) => ({ ...x, raw: {}, line: 0, cite: "" });
    config.policies.forEach((p, i) => {
      const r = editFromDraft(policies, config, i, draftOf(p, config)!);
      if (!r.ok) throw new Error(`${p.id} refused: ${JSON.stringify(r)}`);
      expect(strip(parsePolicies(r.text).config!.policies[i]!)).toEqual(strip(p));
      const a = policies.split("\n");
      const b = r.text.split("\n");
      expect(b.length).toBe(a.length);
      const changed = a.map((l, j) => (l !== b[j] ? j + 1 : 0)).filter((j) => j > 0);
      // only inside the policy's own block; a title with a comma comes back quoted
      expect(changed.every((j) => j >= p.line && j < p.line + 5), p.id).toBe(true);
    });
    expect(editFromDraft(policies, config, 3, draftOf(config.policies[3]!, config)!)).toMatchObject({ ok: true });
  });

  it("adds a cap through the engine; the dashboard has it", () => {
    const d = { ...blankDraft(config, "cap"), id: "WLT-09", title: "food per month", sumGroup: "expense", sumCategory: "food", limitKind: "value" as const, limitValue: "150" };
    expect(rawOf(d)).toMatchObject({ id: "WLT-09", type: "cap", measure: { sum: "expense.food", period: "month" } });
    const r = addFromDraft(policies, config, d);
    if (!r.ok) throw new Error(JSON.stringify(r));
    expect(r.text).toBe(policies + "  - id: WLT-09\n    type: cap\n    title: food per month\n    measure: {sum: expense.food, period: month}\n    limit: {value: 150}\n");
    const h = loadHousehold({ ...files, "policies.yml": r.text });
    expect(check(h, "2026-09-30").policies.find((p) => p.id === "WLT-09")).toMatchObject({ verdict: "hold", measure: { text: "112.416 OMR" }, limit: { text: "150 OMR" } });
  });

  it("refuses what the engine refuses, with its reason", () => {
    const dup = addFromDraft(policies, config, { ...blankDraft(config, "red_line"), id: "WLT-01", title: "dup", tags: "margin" });
    expect(dup.ok === false && dup.problems.map((p) => p.code)).toEqual(["DUP-ID"]);
    const noMatch = addFromDraft(policies, config, { ...blankDraft(config, "red_line"), id: "X-1", title: "nothing" });
    expect(noMatch.ok === false && noMatch.reason).toContain("at least one of");
    const badBand = addFromDraft(policies, config, { ...blankDraft(config, "allocation"), id: "X-2", title: "b", minPct: "40", maxPct: "30" });
    expect(badBand.ok === false && badBand.reason).toBe("band must satisfy 0 <= min_pct <= max_pct <= 100");
    const notNumber = addFromDraft(policies, config, { ...blankDraft(config, "cap"), id: "X-3", title: "c", limitValue: "1,5" });
    expect(notNumber.ok === false && notNumber.reason).toBe("limit.value must be a number");
    const window = addFromDraft(policies, config, { ...blankDraft(config, "kill"), id: "X-4", title: "k", limitValue: "15", windowDays: "9.5" });
    expect(window.ok === false && window.reason).toBe("measure.window_days must be a positive integer");
  });

  it("edits one block and leaves the others as written", () => {
    const i = config.policies.findIndex((p) => p.id === "WLT-07");
    const d = { ...draftOf(config.policies[i]!, config)!, limitValue: "2500" };
    const r = editFromDraft(policies, config, i, d);
    if (!r.ok) throw new Error("refused");
    expect(r.text).toBe(policies.replace("limit: {value: 2400}", "limit: {value: 2500}"));
  });

  it("removes one block; the last policy cannot be removed", () => {
    const i = config.policies.findIndex((p) => p.id === "WLT-04");
    const r = removeAt(policies, config, i);
    if (!r.ok) throw new Error("refused");
    expect(policyById(parsePolicies(r.text).config!, "WLT-04")).toBeNull();
    expect(r.text).toBe(policies.replace("  - id: WLT-04\n    type: red_line\n    title: no margin, no options\n    match: {tags_any: [margin, options]}\n", ""));
    const one = "version: 1\nbase_currency: OMR\naccounts: [cash]\ncategories: {income: [salary], expense: [food]}\nsnapshot_max_age_days: 45\npolicies:\n  - id: A\n    type: red_line\n    title: t\n    match: {tags: x}\n";
    const last = removeAt(one, parsePolicies(one).config!, 0);
    expect(last.ok === false && last.problems.map((p) => p.code)).toEqual(["EMPTY-POLICIES"]);
  });

  it("refuses a layout it cannot edit in place", () => {
    const flow = "version: 1\nbase_currency: OMR\naccounts: [cash]\ncategories: {income: [salary], expense: [food]}\nsnapshot_max_age_days: 45\npolicies: [{id: A, type: red_line, title: t, match: {tags: x}}]\n";
    const c = parsePolicies(flow).config!;
    expect(removeAt(flow, c, 0)).toMatchObject({ ok: false, layout: true });
    expect(addFromDraft(flow, c, { ...blankDraft(c, "red_line"), id: "B", title: "b", tags: "y" })).toMatchObject({ ok: false, layout: true });
  });

  it("closes one decision by its status line; next ids are D-<date>-<n>", () => {
    const d = parseDecisions(decisions, config).decisions.find((x) => x.id === "D-2026-06-01")!;
    const r = closeDecision(decisions, d.line);
    if (!r.ok) throw new Error("refused");
    expect(r.text).toBe(decisions.replace("  review_by: 2026-09-15\n  status: open", "  review_by: 2026-09-15\n  status: closed"));
    expect(parseDecisions(r.text, config).decisions.find((x) => x.id === "D-2026-06-01")?.status).toBe("closed");
    expect(closeDecision(decisions, 3)).toEqual({ ok: false, reason: "layout" });
    expect(nextDecisionId(decisions, "2026-10-01")).toBe("D-2026-10-01-1");
    expect(nextDecisionId(decisions + "- id: D-2026-10-01-1\n", "2026-10-01")).toBe("D-2026-10-01-2");
    expect(nextDecisionId(null, "2026-10-01")).toBe("D-2026-10-01-1");
  });

  it("the export bundle reads back byte for byte", () => {
    const b = bundleText(files);
    expect(b.startsWith("=== policies.yml ===\n# Synthetic example household")).toBe(true);
    const parts = readBundle(b);
    expect(parts.map((p) => p.name)).toEqual(["policies.yml", "ledger.csv", "holdings.csv", "decisions.yml", "rates.csv"]);
    for (const p of parts) expect(p.text).toBe(files[p.name as keyof HouseholdText]);
    const odd: HouseholdText = { "policies.yml": null, "ledger.csv": "no final newline", "holdings.csv": "", "decisions.yml": "[]\n\n", "rates.csv": null };
    const back = readBundle(bundleText(odd));
    expect(back).toEqual([
      { name: "ledger.csv", text: "no final newline" },
      { name: "holdings.csv", text: "" },
      { name: "decisions.yml", text: "[]\n\n" },
    ]);
    expect(readBundle("=== notes.txt ===\nx\n")).toEqual([]);
  });
});
