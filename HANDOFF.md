# HANDOFF — M7.18  (ADR-0007 Amendment AT: an unknown tree with an agent's rhythm is high)

Task: HOST-RHYTHM's severity becomes high (AT-1). Nothing else of the rule changes.

Scope:
  raqib/rules/catalog/HOST-RHYTHM.yaml, tests/ (the rule's fixtures included), tools/gate.py, docs/GUIDE.md, docs/THREAT_MODEL.md, docs/review/2026-11-13-M7.18-questions.md

Exit criteria:
- E1 `severity: high` in HOST-RHYTHM.yaml. K, W, R, the match, fp_budget, bounds, once per streak: unchanged, and a test says so (the rule's match and thresholds equal what main has).
- E2 The fixtures of the rule are generated again only where a severity is written in them; `raqib check-rules` gives the same counts (8 positive, 10 measured, fp 0). Every other rule's fixtures are byte for byte what they are (tested or shown by `git diff --stat`).
- E3 Through rounds (tests/test_rhythm.py, tests/test_host_quiet_rhythm.py): the finding is `[high]`; it knocks by the path it already knocks by; the report's and the window's lines say high; a named tree is still not judged by rhythm; NEW-AGENT-UNKNOWN is still medium.
- E4 tools/gate.py's own count of HOST-RHYTHM lines reads the new level (and the test that pins that line follows).
- E5 The rule's comment on its budget gains AT's measure in two lines (four real agent trees fired, none of the runners' own; three short turns: none). The hole "a benign program that polls one server and spawns helpers" says "a high finding, not a verdict" and that the field measure on an IDE is still owed.
- E6 docs/GUIDE.md and docs/THREAT_MODEL.md say high where they say medium of this rule (THREAT_MODEL: no milestone tokens; the guide's pinned sentences in tests/test_readme_top.py follow by the test's own rule).
- E7 Gate green; ASCII; no new test reads docs/review.
Not in scope: raqib/host.py, raqib/app.py, raqib/ui.py, any other rule, README.md, the catalog of agents.
If a file outside Scope must change for an exit criterion: STOP and say which (the questions file).
Commit: `landed: M7.18 an unknown tree with an agent's rhythm is high` or `STOP: M7.18 <reason>`.
Read HANDOFF.md and do only the task it specifies.
