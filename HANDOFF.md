# HANDOFF — M0.1  (phase 0: capture)

Task: implement `raqib/hooks/capture.py` so that, installed as a Claude Code
PreToolUse + PostToolUse hook, it appends one JSON line per tool call to
`$RAQIB_LOG` (default `./raqib.log.jsonl`) following docs/specs/ADR-0001 §3.

Scope:
  raqib/hooks/
  tests/test_capture.py
  tests/fixtures/
  tools/gate.sh
  docs/review/

Exit criteria:
- E1 `echo '<PreToolUse json>' | python raqib/hooks/capture.py` appends a line
     with fields: ts, session_id, phase, tool, input_sha256, cwd, seq.
- E2 PostToolUse line carries the same seq as its PreToolUse line and adds
     output_sha256 and ok (bool).
- E3 If $RAQIB_LOG is unwritable, capture.py exits 0 (never blocks the agent)
     AND writes one line to stderr starting with `RAQIB-SILENCE:`.
- E4 tests/test_capture.py covers E1–E3 with fixtures; `tools/gate.sh` green.

Not in scope: rules, model, UI, proxy, any network code.
Commit: `landed: M0.1 capture hook` or `STOP: M0.1 <reason>`.
Read HANDOFF.md and do only the task it specifies.
