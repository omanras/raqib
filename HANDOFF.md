# HANDOFF — M10.2 REDO  (ADR-0011 Amendment G on review 2026-11-13-M10.2.md)

Task: the REDO of M10.2 (a9667eb). Amendment F stands as built except where G changes it. Rulings G-1 to G-12. Main was merged into this branch after a9667eb (the examples of docs/specs/EVENT.md regenerated).

Scope:
  raqib/eventlog.py, raqib/host.py (the pass and what it needs), raqib/event.py (G-1's, G-4's keys and check), raqib/cli.py (`events` only), docs/specs/EVENT.md, docs/THREAT_MODEL.md, README.md and docs/GUIDE.md (the Commands tables: `events`, by tests/test_readme_top.py's own rule), tools/rig/check.py, tests/, docs/review/2026-11-13-M10.2-questions.md

Exit criteria:
- E1 (G-1) The folded entry of a pair the report's listing joins (host.told_twice) is said with alarm false and evidence.same_as; the pairs are found once a pass; a pair found later is the folded one's next rev. Through a fixture watch that makes such a pair (tests/test_acts_judged.py or tests/test_host_sources.py have one: grep "taken for the same act"): one alarm for the act. tools/rig/check.py X18 by things, of the report's run only (G-1's words); tests/test_rig_check.py: MET with a pair, MISSED with a pair and one event missing.
- E2 (G-2, G-3) A tree's evidence and a blind spot's count make no new rev at a beat; each is said once at the finish; the file read back still equals event.snapshot of the final state apart from id, n, rev and time. A later rev's time is the pass's time. On the fake clock: N rounds across several beats write, for a tree that only gained record lines, exactly two events (its first and the finish's).
- E3 (G-4) result.word of the end is the watch's own word, one of four; result.suppressed; event.py's check and EVENT.md follow; tested on a NONE-SEEN fixture watch and on a clean one with an overlay that suppresses a finding (tests/test_overlay.py shows how).
- E4 (G-6) (a) each entry inside its own guard, a ledger that raises does not stop the next or the beat, a failing pass is not retried every tick (tested by making one ledger's naming raise); (b) a file that does not end in a newline gets one before the next line (tested on a file left torn), and a failed write is not recorded as said; (c) between beats only what is new or can still change is looked at, everything at a beat and at the finish; one table for knocked.for a pass; the longest pass's time in the state and on the EVENTS line (tested: a pass between beats over a watch with 2000 notes builds no event for an unchanged note - count the builder calls).
- E5 (G-7, G-8, G-9, G-10) EVENT.md and THREAT_MODEL (no milestone tokens) say G-7; the state's tree has no candidate_by (tests/test_round_channel.py's assertion looks at state["host"]["trees"] and holds); knocked.for only for a thing said in the file; one end, last, and the EVENTS line counts it.
- E6 (G-11) README.md's and docs/GUIDE.md's Commands tables name `events`; tests/test_readme_top.py's exception is removed and the test passes by its own rule.
- E7 (G-12) Each test G-12 lists.
- E8 Gate green; ASCII outside docs; no new test reads docs/review; no real host, user or address.
Not in scope: sending anything, raqib/app.py, raqib/ui.py, raqib/watch.py, raqib/notify.py, the rules.
If an exit criterion needs a file outside Scope: STOP and say which (the questions file). Do not change a guard test to pass.
Commit: `landed: M10.2 REDO the watch writes its events` or `STOP: M10.2 REDO <reason>`.
Read HANDOFF.md and do only the task it specifies.
