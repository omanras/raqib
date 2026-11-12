# HANDOFF — M7.17 REDO  (ADR-0007 Amendment AR on review 2026-11-13-M7.17.md)

Task: the REDO of M7.17 (1a3ef49). AP-2's one road (`_tree_line`), AQ-2 and AQ-3 stand as built. Rulings AR-1 to AR-5.

Scope:
  raqib/host.py, raqib/rules/fixturegen.py, raqib/rules/catalog/HOST-RHYTHM.yaml, tests/ (the rule's fixtures and tests/fixtures/host/make.py included), tools/rig/check.py, docs/THREAT_MODEL.md, docs/review/2026-11-13-M7.17-questions.md

Exit criteria:
- E1 (AR-1) A tree's ring has one entry for every round of the watch from its first line on (an empty entry, with that round's own interval, for a round with no line); `_bin` and `rhythm_of` are otherwise unchanged. Tested through rounds and the report with the packet's case (a candidate in round 1, no beat in rounds 2-11, one cycle in each of intervals 11, 12, 13): HOST-RHYTHM fires in round 14, as on a tree that is a candidate every round, and each cycle cites the round of its beats. The test of AQ-4's merge (two cycles count once) now shows two. Not touched, tested: a tree with a line in every round has the ring it had; every generated fixture is byte for byte what it is, or the questions file names the one that changed and why.
- E2 (AR-2) A gone tree whose source gained a beat gets its line (class gone) in the round that reads it, by `_tree_line`; HOST-RHYTHM's match takes class gone; a tree that makes K cycles in its last intervals and exits fires. A gone tree with no new beat has no line. NEW-AGENT, NEW-AGENT-UNKNOWN and HOST-UNWATCHED make nothing of a gone line (through rounds).
- E3 (AR-3) A line for a tree not in the round has empty acts, endpoints and cites of the sample; its input_meta.rhythm names the beats this round read from its sources (count and cites). A candidate's line is unchanged.
- E4 (AR-4) tools/rig/check.py X12 is n/a without --sysmon; tests/test_rig_check.py follows.
- E5 (AR-5) Through rounds: a tree that arrived in the watch, goes quiet and has beats makes no NEW-AGENT(-UNKNOWN) finding; a quiet line's finding equals a candidate's of the same beats by value (rounds, cites); a gone tree's waiting beats are in the report where no round read them.
- E6 The rule's holes and description, and THREAT_MODEL (no milestone tokens), say AR-1 and AR-2 and no longer the loss; fp_budget measured again with a gone positive and a gone negative. Gate green; ASCII; no new test reads docs/review.
Not in scope: raqib/discover.py, raqib/app.py, the clipboard, new rules, W-4, W-5.
Commit: `landed: M7.17 REDO the rhythm of a quiet tree` or `STOP: M7.17 REDO <reason>`.
Read HANDOFF.md and do only the task it specifies.
