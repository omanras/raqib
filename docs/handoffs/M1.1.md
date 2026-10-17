# HANDOFF — M1.1  (phase 1: verdicts and the check command)

Task: implement `qayd/rules.py`, `qayd/report.py`, `qayd/cli.py` with the
`check` command per docs/specs/ADR-0001 §6, §8.

Scope:
  qayd/
  tests/test_rules.py
  tests/test_cli.py
  tests/fixtures/
  docs/review/

Exit criteria:
- E1 `rules.verdict(policy, ctx, as_of)` for cap (measure <= limit ->
     hold), floor (>=), allocation (within band), red_line (no matching row
     ever -> hold; else breach citing every matching row), routine (a
     matching row in the current period -> hold; else missing), kill
     (threshold crossed on any snapshot date in the window -> kill, and it
     stays kill until a decision with closes=<id> dated after the crossing).
     Every verdict carries measure, limit, and the rows it rests on.
- E2 Silence findings: EMPTY-PERIOD when the current period has no ledger
     rows at all; STALE-SNAPSHOT when a holdings-based policy finds the
     snapshot older than allowed; both red, cited by period or date.
- E3 `python3 -m qayd check [--dir DIR] [--as-of DATE] [--json]`: one line
     per policy `<verdict> <id> <title> <measure> vs <limit>` then indented
     citations, reds first; JSON per ADR §8; exit 0 green, 1 red, 2 usage,
     3 unreadable/unparseable file. `main(argv, stdout, stderr)` never
     raises; tests call it directly (no subprocess).
- E4 Tests: a holding and a breaching fixture for every rule type, the
     kill-persists-until-closed sequence, both silence findings. Gate green.

Not in scope: routine/decisions commands, review page, example household.
Commit: `landed: M1.1 verdicts and check` or `STOP: M1.1 <reason>`.
Read HANDOFF.md and do only the task it specifies.
