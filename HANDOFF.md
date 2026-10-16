# HANDOFF — M2.1  (REDO: docs/review/2026-10-16-M3.2-questions.md F1)

Task: a failure of a model backend that is not an API error (for example
the anthropic SDK raising TypeError when no credentials are set) crashes
`raqib suspect` with a traceback and writes nothing. Every backend failure
must become an error line (A3), as M2.1 promised.

Scope:
  raqib/suspect/
  tests/test_suspect.py
  docs/review/

Exit criteria:
- E1 Any exception from a backend's judge() becomes an error line with the
     exception type; `suspect` exits 1 and writes its file and run record.
- E2 The anthropic backend names the missing-credentials case.
- E3 Tests for both; the real `suspect --backend anthropic` run without a
     key is repeated and recorded; gate green.

Commit: `landed: M2.1 REDO backend failures are error lines` or `STOP: ...`.
Read HANDOFF.md and do only the task it specifies.
