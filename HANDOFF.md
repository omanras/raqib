# HANDOFF — M1.3  (phase 1: Decisions, Policies, Settings, Arabic)

Task: the remaining screens and the full Arabic interface per
docs/specs/ADR-0001-app.md §3.

Scope:
  src/ui/
  src/i18n/
  tests/ui/
  e2e/
  docs/review/

Exit criteria:
- E1 Decisions: list (open first, days to review, overdue in red, closed
     with the policy they close); "New decision" form (id generated as
     D-<date>-<n>, date, title, policy, criteria, review_by, closes);
     "Close" sets status closed; raw YAML panel.
- E2 Policies: list grouped by type; a form per type covering every
     measure/limit/match/band field of the engine spec with validation
     from the engine (unknown combinations refused with the reason);
     edit, add, remove (remove asks to confirm and shows which verdicts
     disappear); raw YAML panel.
- E3 Settings: base currency (read-only), language en/ar, theme, export
     all (one click copies a tar-like text bundle of the five files with
     `=== filename ===` separators that import accepts back), erase all
     (two-step), about (version, no-network statement).
- E4 Arabic: every string translated (no placeholders left), `dir=rtl`,
     numbers in Latin digits, dates ISO, tables and forms mirror
     correctly; the language choice persists.
- E5 e2e: add a cap policy through the form and see it on the dashboard;
     switch to Arabic and assert `dir=rtl` and a translated heading;
     export-all then erase then import-all restores the counts. Gate green.

Not in scope: Review screen.
Commit: `landed: M1.3 decisions, policies, settings, arabic` or `STOP: M1.3 <reason>`.
Read HANDOFF.md and do only the task it specifies.
