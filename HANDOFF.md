# HANDOFF — M0.1b  (phase 0: pairing key + command_head)

Task: apply ADR-0001 Amendment A-1 and A-2 to `raqib/hooks/capture.py`:
carry `tool_use_id` in every tool trace line and pair post→pre by it; write
`input_meta.command_head` for Bash.

Scope:
  raqib/hooks/
  tests/test_capture.py
  tests/fixtures/
  docs/review/

Exit criteria:
- E1 Pre and post lines carry `tool_use_id` (string) when the hook input has
     it; a post pairs with the pre that has the same tool_use_id, regardless
     of input hash. Fallback to (tool, input_sha256, oldest-open) only when
     tool_use_id is absent on either side.
- E2 For tool "Bash", `input_meta.command_head` = basename of the first
     whitespace-separated token of tool_input.command, skipping leading
     `NAME=value` assignments (e.g. `FOO=1 /usr/bin/git x` → "git"). Absent for
     other tools. Never more than 64 chars.
- E3 Fixtures: two identical commands in flight pair correctly by tool_use_id
     (positive); an updatedInput-rewritten pre still pairs (positive); a post
     with unknown tool_use_id falls back and is logged (negative, no crash).
- E4 All M0.1 tests still pass; gate green.

Not in scope: session events (M0.3), rules, model, UI.
Commit: `landed: M0.1b pairing key + command_head` or `STOP: M0.1b <reason>`.
Read HANDOFF.md and do only the task it specifies.
