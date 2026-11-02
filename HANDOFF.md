# HANDOFF — M4.2  (phase 4: programs in Bash, first demands, SILENCE-EMPTY)

Task: capture records every program a Bash command runs; two demand rules
that need it; the empty-session demand seen in the field (ADR-0002;
docs/review/2026-11-02-field-note-empty-session.md).

Scope:
  raqib/hooks/capture.py, raqib/rules/catalog/, raqib/rules/engine.py, raqib/rules/silence.py,
  raqib/report.py (ids only), tests/, docs/specs/ADR-0002-rule-kinds.md, docs/review/

Exit criteria:
- E1 `input_meta.command_programs`: program names across `|`, `&&`, `||`, `;`,
     `$(...)` and the string after `bash -c`/`sh -c` (one level); deterministic,
     no execution, never the arguments; `command_head` unchanged. Tests: pipeline,
     chain, bash -c, quoted `;`, glued `ls;rm`, and `python3 -c 'import urllib'`.
- E2 Match op `{field: input_meta.command_programs, has_any: [..]}`; DESTRUCT-CMD
     and NET-TOOL gain a branch on it; their `evasion` lists shrink (ADR table
     corrected by a dated note under it).
- E3 LANDED-NO-GATE (demand, high): capture adds `input_meta.commit_prefix` (first
     word of a git -m message only); fires when a `landed:` commit has no earlier
     ok Bash with tools/gate.sh or tools/gate.py among its programs. Fixtures both ways.
- E4 EDIT-NO-TEST (demand, medium): ok edits under raqib/ or tests/ and no later ok
     Bash with pytest or python before stop. Fixtures both ways.
- E5 SILENCE-EMPTY (demand, medium, silence.py): session_start + session_end (or
     start alone) with zero tool records. Fixtures: empty-session shape (positive),
     quickstart trace (negative). Kinds line: demand > signature. Gate green.

Not in scope: git state capture (M4.3), suspicion layer, UI, watch.
Commit: `landed: M4.2 bash programs + demands` or `STOP: M4.2 <reason>`.
Read HANDOFF.md and do only the task it specifies.
