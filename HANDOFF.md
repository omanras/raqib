# HANDOFF — M4.3  (phase 4: the tree as anchor, from files only)
Task: at session_start, stop and session_end the hook records the local git
state READ FROM FILES (the hook executes nothing: no `git` process); two
anchor rules read it (ADR-0002 candidates; ratio after: 4 : 7 : 6).
Scope:
  raqib/hooks/common.py, raqib/hooks/capture.py, raqib/rules/catalog/, raqib/rules/engine.py,
  raqib/report.py (ids), README.md, docs/THREAT_MODEL.md, .github/workflows/gate.yml, tests/,
  docs/specs/ADR-0002-rule-kinds.md (note under the table), docs/review/
Exit criteria:
- E1 `git_state(cwd)` in common.py, 50 ms budget, reads only: `.git/HEAD`
     (a `.git` file pointing to a gitdir is followed once), the ref it names
     (loose ref, else packed-refs), `.git/index` (sha256 of its bytes). Records
     `git_head` (40-hex or null), `git_index_sha256` (64-hex or null),
     `git_error` naming why (no repo, unreadable, budget). Never a subprocess
     (a test asserts it). Written on session_start, stop, session_end only.
- E2 HEAD-UNMOVED (anchor, medium, `holes:`): ok Edit/Write/MultiEdit/
     NotebookEdit in the session and the closing `git_head` equals the
     starting one (edits never committed); null on either side = unknown;
     no start record = unknown. Fixtures both ways + unknown.
- E3 INDEX-UNTOUCHED (anchor, medium, `holes:`): ok edits in the session and
     `git_index_sha256` unchanged from start to close (edits never staged);
     same unknown rules. Fixtures both ways + unknown. Reuse `require:` or a
     code rule; a new engine construct needs a STOP with the question.
- E4 README Seventeen rules (5 + 1 + 11), rows; ADR note rows + "Ratio after
     M4.3: 4 : 7 : 6."; kinds anchor=6; THREAT_MODEL paragraph on what the tree
     anchor sees and cannot (edits outside the repo, a second repo, a worktree,
     `GIT_DIR` set, an index rewritten by the agent). Gate green ubuntu + windows.
Not in scope: executing git (STOP-DIRTY-TREE awaits a ruling), hash chain, suspicion, UI.
Commit: `landed: M4.3 tree anchor` or `STOP: M4.3 <reason>`.
Read HANDOFF.md and do only the task it specifies.
