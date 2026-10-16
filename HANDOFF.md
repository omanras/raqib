# HANDOFF — M1.1  (REDO: docs/review/2026-10-16-M1.1.md)

Task: fix the M1.1 review findings in the YAML subset, the engine and the
fixture runner, plus the M0.2 residuals the same packet found.

Scope:
  raqib/rules/
  tests/test_rules.py
  tests/test_silence.py
  tests/fixtures/
  docs/review/

Exit criteria:
- E1 yamlite: quotes open only where a scalar starts (Y1); plain keys must be
     strings (Y2); control chars and non-ASCII spaces are errors, lines split
     on \n (Y3); the Y4 and Y5 inputs are errors.
- E2 engine: three-valued predicates, so `not` cannot turn "cannot judge"
     into a match (MS1, PA3); rules for a cwd at / or a home dir and for a
     cwd that moves (PA1); SILENCE class means severity high; check_finding
     checks class and ts; skipped lines, bad context and an empty catalog
     leave a note or an error (3h).
- E3 runner: fixtures must be sound traces (A6-2); a context rule is measured
     only where its context is given, and fails if nowhere (A6-1); budget < 1.
- E4 silence: every finding has a ts (S14); gap limit at most 7 days (S15).

Commit: `landed: M1.1 REDO` or `STOP: M1.1 <reason>`.
Read HANDOFF.md and do only the task it specifies.
