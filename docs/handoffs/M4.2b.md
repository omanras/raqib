# HANDOFF — M4.2b  (phase 4: `require:` construct; LANDED-NO-GATE, EDIT-NO-TEST) — REDO
Task: the engine learns demands that need evidence on another line; the two
demands split out of M4.2. Binding: ADR-0002 Amendments D, G and
docs/review/2026-11-03-M4.2b-ruling.md (G-1..G-11).
Scope:
  raqib/hooks/common.py, raqib/hooks/capture.py, raqib/rules/catalog/, raqib/rules/engine.py,
  raqib/report.py (ids only), README.md, docs/THREAT_MODEL.md, .github/workflows/gate.yml,
  tests/, docs/specs/ADR-0002-rule-kinds.md (note under the table), docs/review/
Exit criteria:
- E1 `require: {before: <node>}` and `require: {after: <node>, until: <node>}`
     on kind demand only, never with aggregate; three-valued (unknown = partial
     note, never a finding; no deadline = unknown); `under_any: [..]` placed
     like outside_any; `holes:` key on demand/anchor rules (G-6). Tests both ways.
- E2 common.py (capture re-exports): `input_meta.commit_prefix` (G-3, G-4),
     `input_meta.command_scripts` (G-2, G-9), command_head leading-redirect
     fix (E-12); hook fixtures byte-for-byte except the new keys; tests per form.
- E3 LANDED-NO-GATE (demand, high): trigger = commit post line ok with
     commit_prefix `landed:`; evidence = an earlier-or-same ok Bash whose
     programs/scripts/head hold gate.sh or gate.py (G-7, G-8); holes G-5
     listed. Fixtures both ways incl. `&&` same line and the stale gate.
- E4 EDIT-NO-TEST (demand, medium): ok Edit/Write/MultiEdit/NotebookEdit
     under raqib/ or tests/ and, before every stop or session_end, no later ok
     Bash with programs/scripts/head in {pytest, python, python3, gate.sh,
     gate.py} (G-10). b11-refactor flips: README baseline + M2.2 dated note (G-11).
- E5 README Fifteen rules (5 + 1 + 9), rows; ADR note rows + "Ratio after
     M4.2b: 4 : 7 : 4."; kinds demand=7; THREAT_MODEL section 4 list and the
     holes; gate.yml count derived (already). Gate green ubuntu + windows.
Not in scope: M4.3 anchors, suspicion, UI, watch, proxy, os.
Commit: `landed: M4.2b require + two demands` or `STOP: M4.2b <reason>`.
Read HANDOFF.md and do only the task it specifies.
