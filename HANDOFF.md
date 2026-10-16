# HANDOFF — M1.1  (phase 1: rule schema + loader + fixture runner)

Task: rules as YAML, one file per rule (ADR-0001 §4), loaded with a stdlib
YAML-subset parser (A-7), evaluated by a pure engine, and checked by a fixture
runner that measures each rule's false-positive rate against its budget (A6).

Scope:
  raqib/rules/
  tests/test_rules.py
  tests/fixtures/
  docs/review/

Exit criteria:
- E1 Loader: stdlib-only YAML subset; anything outside the subset is an error
     naming file and line, never a silent misread.
- E2 Schema: id, title, class (SCOPE|NET|DESTRUCT|SECRET|SILENCE|DRIFT), match
     (declarative over trace fields), severity, fp_budget, fixtures{positive[],
     negative[]}; an invalid rule fails to load, naming the field.
- E3 Engine: pure `(rules, trace lines, context) -> findings`; a finding is
     {ts, rule_id, class, severity, session_id, cited_seq[], summary}; one
     without cited_seq is rejected (A5); no rule consults a model (A1).
- E4 Runner: positives fire, negatives are counted as false positives; a rule
     over its fp_budget must be `status: disabled` (A6). 3 rules ship, each
     with ≥1 positive and ≥1 negative fixture; gate green.

Not in scope: capture, CLI, model layer, UI.
Commit: `landed: M1.1 rule schema + loader + runner` or `STOP: M1.1 <reason>`.
Read HANDOFF.md and do only the task it specifies.
