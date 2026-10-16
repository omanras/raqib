# HANDOFF — M1.3  (phase 1: findings format + report CLI)

Task: `python -m raqib` CLI over the pipeline files (ADR-0001 §1, §6): `rules`
writes findings.jsonl from a trace; `report` shows findings with the exact
trace lines they cite (A5), every rule's fp_budget (A6), and everything that
did not run or could not be read (A3); `check-rules` runs the fixture runner.

Scope:
  raqib/
  tests/test_report.py
  tests/fixtures/
  README.md
  docs/review/

Exit criteria:
- E1 `rules TRACE -o FILE` writes silence + catalog findings, one per line, each
     passing check_finding; scope from --scope or a HANDOFF's Scope: block;
     RAQIB_GAP_SECONDS honoured.
- E2 `report TRACE [--findings FILE]` prints, for each finding, the file line
     numbers and content of every cited seq; a cited seq with no line, or a
     finding without cited_seq, is an alarm (A5).
- E3 Report lists rules with class/severity/fp_budget/status; empty trace,
     corrupt lines and unrun rules are never shown as clean; exit 0 clean,
     1 alarms, 3 incomplete, 2 usage.
- E4 `check-rules` prints measured fp_rate vs fp_budget; tests; gate green.

Not in scope: model layer, UI, capture changes.
Commit: `landed: M1.3 findings + report CLI` or `STOP: M1.3 <reason>`.
Read HANDOFF.md and do only the task it specifies.
