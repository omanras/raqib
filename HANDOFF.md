# HANDOFF — M7.18 again  (ADR-0007 Amendment AT, AT-5 on the STOP 3eabb97)

Task: HOST-RHYTHM's severity becomes high (AT-1). Nothing else of the rule changes.

Scope:
  raqib/rules/catalog/HOST-RHYTHM.yaml, tests/ (the rule's fixtures included), .github/workflows/gate.yml (the HOST-RHYTHM count only), docs/GUIDE.md, docs/THREAT_MODEL.md, docs/review/2026-11-13-M7.18-questions.md

Exit criteria:
- E1 `severity: high` in HOST-RHYTHM.yaml. K, W, R, the match, fp_budget, bounds, once per streak: unchanged, and a test says so (the rule's match and thresholds equal what main has).
- E2 No fixture changes (the STOP found none writes a severity): `git diff --stat` shows nothing under tests/fixtures; `raqib check-rules` gives the same counts (8 positive, 10 measured, fp 0).
- E3 Through rounds (tests/test_rhythm.py, tests/test_host_quiet_rhythm.py): the finding is `[high]`; it knocks by the path it already knocks by; the report's and the window's lines say high; a named tree is still not judged by rhythm; NEW-AGENT-UNKNOWN is still medium.
- E4 (AT-5) .github/workflows/gate.yml: the count of HOST-RHYTHM lines on the runner's own watch matches the rule at any level (`^  \[[a-z]+\] HOST-RHYTHM `); its assert is unchanged; tests/test_rhythm.py's pin follows, and a test shows the pattern counts a `[high]` and a `[medium]` line and not another rule's.
- E5 The rule's comment on its budget gains AT's measure in two lines (four real agent trees fired, none of the runners' own; three short turns: none). The hole "a benign program that polls one server and spawns helpers" says "a high finding, not a verdict" and that the field measure on an IDE is still owed.
- E6 docs/GUIDE.md says high where it says medium of this rule (its pinned sentences in tests/test_readme_top.py follow by the test's own rule). docs/THREAT_MODEL.md names no level for the rule: unchanged.
- E7 Gate green; ASCII; no new test reads docs/review.
Not in scope: raqib/host.py, raqib/app.py, raqib/ui.py, any other rule, README.md, the catalog of agents.
If a file outside Scope must change for an exit criterion: STOP and say which (the questions file).
Commit: `landed: M7.18 an unknown tree with an agent's rhythm is high` or `STOP: M7.18 <reason>`.
Read HANDOFF.md and do only the task it specifies.
