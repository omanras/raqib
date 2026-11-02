# HANDOFF — M4.2b  (phase 4: `require:` construct; LANDED-NO-GATE, EDIT-NO-TEST)
Task: the engine learns demands that need evidence on another line; the two
demands split out of M4.2 (ADR-0002 Amendment D, D-1, D-10, D-11). Requires
M4.2 landed. Preliminary Table answers below; return what does not hold.
Scope:
  raqib/hooks/capture.py, raqib/rules/catalog/, raqib/rules/engine.py, raqib/report.py (ids only),
  README.md, .github/workflows/gate.yml, tests/, docs/specs/ADR-0002-rule-kinds.md, docs/review/
Exit criteria:
- E1 `require: {before: <node>}` and `require: {after: <node>, until: <node>}`
     on kind demand only, never with aggregate; three-valued (unknown = partial
     note, never a finding; a deadline that never comes = unknown);
     `under_any: [..]` placed like outside_any. Tests both ways.
- E2 capture: `input_meta.commit_prefix` = first literal word of the first
     -m/--message of a `git commit` simple command, also inside a quoted-
     delimiter `$(cat <<'EOF' ... EOF)` read statically; -F/-C/-c/--amend and
     merge not read (evasions). `input_meta.command_scripts` (Q-A, preliminary
     YES): basename of the first literal .py/.sh argument after python(3)/bash/sh.
- E3 LANDED-NO-GATE (demand, high): `landed:` commit with no earlier-or-same
     line ok Bash whose programs or scripts hold gate.sh/gate.py; stale gate
     accepted in v1 and listed. Fixtures both ways (incl. `&&` same line).
- E4 EDIT-NO-TEST (demand, medium): ok Edit/Write under raqib/ or tests/ and,
     before every stop or session_end, no later ok Bash with programs or scripts
     in {pytest, python, python3, gate.sh, gate.py}. Benign eval b11-refactor
     flips: README baseline line and M2.2-baseline.md corrected by dated note.
- E5 README 14 rules; gate.yml count derived; ADR table note extended; kinds
     line demand=7. Gate green ubuntu + windows.

Not in scope: M4.3 anchors, suspicion, UI, watch.
Commit: `landed: M4.2b require + two demands` or `STOP: M4.2b <reason>`.
Read HANDOFF.md and do only the task it specifies.
