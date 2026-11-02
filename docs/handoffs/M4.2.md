# HANDOFF — M4.2  (phase 4: programs in Bash, has_any, SILENCE-EMPTY) — REDO
Task: capture records every program a Bash command runs; the two command
rules branch on it; the empty-session demand seen in the field. Binding:
ADR-0002 Amendment D and docs/review/2026-11-03-M4.2-ruling.md (D-1..D-13).

Scope:
  raqib/hooks/capture.py, raqib/rules/catalog/, raqib/rules/engine.py, raqib/rules/silence.py,
  raqib/report.py (ids only), README.md, .github/workflows/gate.yml, tests/,
  docs/specs/ADR-0002-rule-kinds.md (note under the table only), docs/review/

Exit criteria:
- E1 `input_meta.command_programs`: basenames across `|`, `&&`, `||`, `;`,
     `$(...)` and the string after `bash -c`/`sh -c` (one level); D-9 parse
     limits; absent when unreadable; no execution, never arguments;
     `command_head` unchanged. Table test per clause: pipeline, chain, bash -c,
     quoted `;`, glued `ls;rm`, `python3 -c 'import urllib'`, `$X`, 65 names.
- E2 Op `{field: input_meta.command_programs, exists: true, has_any: [..]}`;
     DESTRUCT-CMD and NET-TOOL gain the branch (D-3 guard + evasion line);
     evasion lists shrink; dated note under the ADR table (D-8); tests read
     table plus note; "Ratio after M4.2: 4 : 5 : 3."
- E5 SILENCE-EMPTY (demand, high, silence.py, RULE_KINDS, report ids), D-6
     shape; fixtures: tests/fixtures/field-2026-11-02.log (D-4, recreated, no
     real paths; expects GAP s3, SCOPE-PATH s5, NET-TOOL s6, EMPTY s1 s2),
     end-without-start (positive), quickstart (negative), start-alone-at-end
     (OPEN only). README: 12 rules (5 + 7), row added; gate.yml and
     test_packaging derive the catalog count (D-2). Kinds line demand=5. Gate green.

Not in scope: LANDED-NO-GATE, EDIT-NO-TEST, `require:` (M4.2b), M4.3, suspicion, UI, watch.
Commit: `landed: M4.2 bash programs + SILENCE-EMPTY` or `STOP: M4.2 <reason>`.
Read HANDOFF.md and do only the task it specifies.
