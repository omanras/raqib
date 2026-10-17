# HANDOFF — M0.3  (phase 0: measures, limits, rates)

Task: implement `qayd/measures.py` and `qayd/rates.py` per
docs/specs/ADR-0001 §5: every measure and limit, in base currency, with
citations.

Scope:
  qayd/measures.py
  qayd/rates.py
  tests/test_measures.py
  tests/fixtures/
  docs/review/

Exit criteria:
- E1 `rates.load(path)` reads `date,currency,rate` (rate = base units per
     one unit of currency); `convert(amount, currency, date)` uses the
     latest rate on or before the date; no rate -> Unknown(reason). Base
     currency needs no table.
- E2 `measures.evaluate(measure, ctx, period)` returns Value(amount
     Decimal, rows cited as file:line) or Unknown: `sum: group.category`
     over the period (expense sums reported positive), `income`, `expense`,
     `holdings: class.X | account.X` as of the period end (latest
     snapshot; stale by snapshot_max_age_days -> Stale with the age),
     `share: class.X` (debt class excluded from the total), `drawdown:
     account.X` over window_days of snapshots (peak to latest, pct).
- E3 `measures.limit_value(limit, ctx, period)` -> Decimal or Unknown:
     `value`, `pct_of: income`, `months_of: expense` (trailing 12 months
     average, fewer months -> the months available, cited), `pct`.
- E4 Transfers (tag `transfer`) never count as income or expense; a row in
     a foreign currency is converted per E1; an Unknown anywhere makes the
     measure Unknown (never a partial sum).
- E5 Tests with hand-computed expected Decimals for every measure and
     limit, a foreign-currency row, a missing rate, a stale snapshot. Gate green.

Not in scope: verdicts, CLI.
Commit: `landed: M0.3 measures, limits, rates` or `STOP: M0.3 <reason>`.
Read HANDOFF.md and do only the task it specifies.
