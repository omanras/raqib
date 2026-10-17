# HANDOFF — M0.1  (phase 0: ledger and holdings loaders)

Task: implement `qayd/ledger.py` (+ `qayd/__init__.py`, `qayd/__main__.py`
stub) reading ledger.csv and holdings.csv per docs/specs/ADR-0001 §3-§4.

Scope:
  qayd/
  tests/test_ledger.py
  tests/fixtures/
  docs/review/

Exit criteria:
- E1 `ledger.load_ledger(path, accounts, categories)` returns rows (date,
     amount Decimal, currency, account, category, tags tuple, note, line)
     plus a problems list ({line, reason}); never raises; header must match
     exactly; unknown account/category, bad date, bad amount, wrong column
     count are problems naming the line; the run continues past them.
- E2 Exact duplicate rows (same seven fields) yield a DUP-ROW note with
     both line numbers; neither row is dropped.
- E3 `ledger.load_holdings(path, accounts, classes)` the same way for the
     holdings header; `latest_snapshot(rows, as_of)` returns the rows of the
     latest date <= as_of and that date (or None).
- E4 Amounts are Decimal everywhere (no float, the gate checks); UTF-8 with
     optional BOM; CRLF tolerated; a 1 MiB line or 64 MiB file is a problem.
- E5 Fixtures: valid ledger and holdings, and one file per problem class;
     a test per fixture; gate green.

Not in scope: policies, measures, CLI.
Commit: `landed: M0.1 ledger and holdings loaders` or `STOP: M0.1 <reason>`.
Read HANDOFF.md and do only the task it specifies.
