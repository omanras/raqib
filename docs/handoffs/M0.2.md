# HANDOFF — M0.2  (phase 0: policies, decisions, periods)

Task: implement `qayd/policies.py`, `qayd/decisions.py` and
`qayd/periods.py` per docs/specs/ADR-0001 §5, §7 and the period rules.

Scope:
  qayd/policies.py
  qayd/decisions.py
  qayd/periods.py
  tests/test_policies.py
  tests/test_periods.py
  tests/fixtures/
  docs/review/

Exit criteria:
- E1 `policies.load(path)` returns Config (version, base_currency, accounts,
     categories by group, classes, snapshot_max_age_days, policies) or
     problems; each policy validated by type: cap/floor need measure+limit,
     routine needs match+period, red_line needs match, kill needs
     measure(drawdown)+limit(pct), allocation needs measure(share)+band.
     Unknown type/measure/limit -> the policy is kept with status
     `unknown` and the reason; the file is not rejected for it.
- E2 Duplicate policy ids, undeclared categories in measures, empty
     policies list, missing base_currency -> problems naming the field.
- E3 `decisions.load(path, policy_ids)`: id, date, title, policy (optional),
     criteria, review_by, status open|closed, closes (policy id or null);
     problems for bad dates, unknown policy, unknown status.
- E4 `periods`: `period_of(date, kind)` -> (start, end) for month, quarter,
     year; `parse(text)` for `2026-10`, `2026-Q3`, `2026`; `trailing(as_of,
     months)`; `periods_between(first, last, kind)`. Pure date math, tested
     at year and quarter boundaries and on leap days.
- E5 Gate green.

Not in scope: measures, verdicts, CLI.
Commit: `landed: M0.2 policies, decisions, periods` or `STOP: M0.2 <reason>`.
Read HANDOFF.md and do only the task it specifies.
