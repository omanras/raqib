# HANDOFF — M1.1  (phase 1: fixtures, test and match commands)

Task: implement `mizan/fixtures.py`, `mizan/report.py`, `mizan/cli.py` with
the commands `test` and `match` per docs/specs/ADR-0001 §6, §8, §9.

Scope:
  mizan/
  tests/test_fixtures.py
  tests/test_cli.py
  tests/fixtures/
  docs/review/

Exit criteria:
- E1 `fixtures.judge(rule)` reads `<name>.positive.jsonl` and
     `<name>.negative.jsonl` next to the rule file; returns a result with
     status pass | fail | unknown | invalid and citations `<file>:<line>`
     for every wrong or unjudgeable line; missing or empty sidecar -> fail
     with the file named (A2); malformed JSON line -> unknown citing it (A7).
- E2 Line and file limits of ADR §4 enforced and cited.
- E3 `python3 -m mizan test RULE.yml` prints `<status> <id> <title>` then
     indented citations; `--json` prints the result object; exit 0 pass,
     1 otherwise, 2 usage, 3 unreadable path.
- E4 `python3 -m mizan match RULE.yml EVENTS.jsonl` prints the line numbers
     that match (and `unknown` lines separately); same flags and exit codes.
- E5 Tests run the CLI through `mizan.cli.main(argv)` (no subprocess) on
     fixture rules: pass, fail, unknown, missing sidecar; gate green.

Not in scope: corpus and budget (M1.2), check command, export.
Commit: `landed: M1.1 fixtures, test and match` or `STOP: M1.1 <reason>`.
Read HANDOFF.md and do only the task it specifies.
