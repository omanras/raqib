# HANDOFF — M4.1  (phase 4: rule kinds)

Task: implement ADR-0002: every rule declares `kind` (signature | demand |
anchor); signatures declare `evasion`; the gate prints the ratio.

Scope:
  raqib/rules/engine.py, raqib/rules/silence.py, raqib/rules/catalog/, raqib/watch.py (kind in
  findings only), raqib/report.py, raqib/ui.py, tests/, tools/gate.py, docs/specs/ADR-0002-rule-kinds.md, docs/review/

Exit criteria:
- E1 Loader: `kind` required, one of the three; `evasion` (non-empty list
     of one-line strings) required iff kind is signature. Any other shape
     is a load error with the rule id and field named. Tests for all four
     error cases and the three valid kinds.
- E2 Every catalog rule carries `kind`, and each signature its `evasion`
     list, per the ADR table; if your reading of a match block disagrees
     with the table, keep the table and write the disagreement in
     docs/review/<date>-M4.1-questions.md (do not reclassify).
- E3 Silence rules expose kind "demand" in their findings; every finding
     dict (catalog and silence) carries `kind`. `raqib report` shows it.
- E4 tools/gate.py prints one line `rule kinds: signature=N demand=N anchor=N`
     and fails if any rule has no kind. Gate green ubuntu + windows.
- E5 ADR-0002 status line changed to "accepted (M4.1, <date>)".

Not in scope: new rules, capture changes, suspicion layer, UI.
Commit: `landed: M4.1 rule kinds` or `STOP: M4.1 <reason>`.
Read HANDOFF.md and do only the task it specifies.
