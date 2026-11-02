# HANDOFF — M1.2  (phase 1: rule set v1)

Task: complete rule set v1 (DEVELOPMENT_PLAN M1.2): SCOPE-PATH, NET-TOOL and
DESTRUCT-CMD (from M1.1) plus SECRET-OUTPUT (secret-in-output) and DRIFT-FILES
(scope-drift). Capture records which secret patterns a tool output matched,
by name only, so the rule stays deterministic and offline (A1, A-5).

Scope:
  raqib/rules/
  raqib/hooks/
  tests/test_rules.py
  tests/test_capture.py
  tests/fixtures/
  docs/review/

Exit criteria:
- E1 Five catalog rules, each with ≥1 positive and ≥1 negative fixture and a
     measured fp_rate ≤ fp_budget on its negatives + the benign corpus (A6).
- E2 Post lines carry output_meta.secret_kinds: sorted names of matched secret
     patterns; the secret text never reaches the trace; gate secret scan green.
- E3 DRIFT-FILES fires when one session edits more than 2 distinct files
     outside context "scope"; without a scope it is not-evaluated (A3).
- E4 Benign corpus gains a scoped session; earlier tests pass; gate green.

Not in scope: CLI/report (M1.3), model layer, UI.
Commit: `landed: M1.2 rule set v1` or `STOP: M1.2 <reason>`.
Read HANDOFF.md and do only the task it specifies.
