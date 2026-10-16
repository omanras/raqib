# HANDOFF — M0.3  (phase 0: install + quickstart)

Task: `tools/install-hooks.sh <watched-project>` writes/merges the Raqib hook
entries (PreToolUse, PostToolUse, PostToolUseFailure, SessionStart,
SessionEnd, Stop: six per Amendment A-4) into that project's
`.claude/settings.json`, pointing at raqib/hooks/capture.py; capture.py
records session events (A-3) and error_class (A-4); README quickstart true.

Scope:
  tools/install-hooks.sh
  raqib/hooks/
  README.md
  tests/test_install.py
  tests/test_capture.py
  tests/fixtures/
  docs/review/

Exit criteria:
- E1 Running the script on an empty temp project creates a valid settings.json
     with the six hook entries; running it twice is idempotent (no duplicates).
- E2 Running it on a project that already has other hooks preserves them.
- E3 README quickstart: fresh clone → install → one real Claude Code tool call
     → one `pre` and one `post` line in raqib.log.jsonl (documented, with the
     exact command used).
- E4 A-3 session lines and A-4 error_class covered by tests; gate green.
Not in scope: rules, model, UI.
Commit: `landed: M0.3 install + quickstart` or `STOP: M0.3 <reason>`.
Read HANDOFF.md and do only the task it specifies.
REDO: per docs/review/2026-10-16-M0.3.md: B1 exit 2, E3 exact command + fresh clone, M1-M8, Q1-Q3, EC1-EC2.
