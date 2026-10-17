# HANDOFF — M1.2  (phase 1: routine and decisions commands)

Task: add the `routine` and `decisions` commands and the DECISION-DUE
finding per docs/specs/ADR-0001 §7-§8.

Scope:
  qayd/cli.py
  qayd/rules.py
  qayd/decisions.py
  qayd/report.py
  tests/test_cli.py
  tests/test_decisions.py
  tests/fixtures/
  docs/review/

Exit criteria:
- E1 `python3 -m qayd routine [--dir DIR] [--period 2026-10]`: every
     routine policy for that period (default: the period of today) with
     done | missing and the matching row cited; exit 0 only if all done.
- E2 `python3 -m qayd decisions [--dir DIR] [--as-of DATE]`: open decisions
     with days until review (negative = overdue), closed ones with the
     policy they closed; DECISION-DUE for every open decision whose
     review_by < as_of; exit 1 if any is due.
- E3 `check` includes DECISION-DUE in its findings and in `green`.
- E4 A decision with `closes` naming a policy that is not `kill` type is a
     problem; a kill closed by a decision dated before the crossing stays
     kill (the decision does not count).
- E5 `--json` for both commands in the ADR shape with a `command` key.
     Tests for every path. Gate green.

Not in scope: review page, example household.
Commit: `landed: M1.2 routine and decisions` or `STOP: M1.2 <reason>`.
Read HANDOFF.md and do only the task it specifies.
