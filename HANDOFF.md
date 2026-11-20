# HANDOFF — M14.1c REDO  (ADR-0007 Amendment BZ, BZ-1 to BZ-12: the review of M14.1c)

Task: the review's findings, as the Table ruled them. Read docs/review/2026-11-20-M14.1c.md (the packet: its file:line cites are of b6b6c84; main has been merged in since, so find each place by its name) and ADR-0007's Amendment BZ, then do each item below. Nothing else changes.

Scope:
  raqib/discover.py, raqib/host.py, raqib/procevents.py (only `Helper`), raqib/own.py, raqib/ruleform.py (only the sentence of BZ-11), raqib/rules/catalog/DESTRUCT-CMD.yaml, NET-TOOL.yaml and HOST-RHYTHM.yaml (only the sentence of BZ-11 in each: no match, no number), tools/rig/workload.py and tools/rig/check.py (X36), tests/test_procevents_round.py, tests/test_host_procevents.py, tests/test_procevents_helper.py, tests/test_rig_check.py, docs/specs/PROC-EVENTS.md, docs/GUIDE.md, docs/THREAT_MODEL.md, docs/review/2026-11-20-M14.1c-redo-questions.md; and a test of tests/ or a rule's fixture ONLY where it holds, word for word or by count, a line this task changes (named in the questions file; no other assertion weakened; no fixture's finding changes).

Exit criteria:
- R1 (BZ-1) The search for act-roots takes as a root only a process a sample held. Test: a sampled terminal shell under which the reader alone gives a user-folder tool, a shell with a command and git gives no act-root and no tree; every existing act-root test and the byte-for-byte test pass unchanged.
- R2 (BZ-2) After an answered ask, a watch that was not whole says what was heard and judged and why it was not whole; the sentence "the rounds read /proc only ..." is said only where no ask was answered. Tests: one late round after answered ones; no answer at all.
- R3 (BZ-3) The words: the section's judged and not-judged lists, the note, GUIDE, THREAT_MODEL and PROC-EVENTS name as not judged: a program a process changes to after its line was written and its earlier programs; a child whose parent was given in an earlier round and ended before the sample; that a child is named by its program's file (a link's target), not by the name it was called by. "A program not read ... in no round" is put right (it is in the round and counted; it gets no line). A test holds the sentences.
- R4 (BZ-4) A time the round cannot read, or that raises in its reading, and a pid at or above discover's bound for keying instances apart, make a line not a line in the watch's taking of an answer and in `parse_procevents`; neither raises. Tests: each, through the watch (the round is kept, the line counted as not a line) and through the parser.
- R5 (BZ-5) A record without ticks joins a sampled process by pid only where the sample read no start for it. Test: the sample's ticks read, the reader's not: kept apart.
- R6 (BZ-6) An answer that holds back a rest is a hole of the result of that round (kind procevents), said once an episode as BY-5's are. Test.
- R7 (BZ-7) The watch's own processes stay its own across a late answer and a rest held back (test: an answer taken a round late carries the socket tool of two rounds before: no "did not start" hole), bounded; the section says how many of its own were left out.
- R8 (BZ-8) No read of /proc for the start of a process the reader said ended; THREAT_MODEL's sentence put right. Test: the reads made for a round with ended reader children.
- R9 (BZ-9) The full-input test fails where the ask's write can block (show it in the questions file: what you changed in the code to see it fail, then put back); a test that needs what Windows lacks is skipped there by name.
- R10 (BZ-10) The stand-in's wget is given one try; X36 is MET only where the tool's line cites the process events as its source, says "the sample's own" and is not MET where it does not. Tests in tests/test_rig_check.py.
- R11 (BZ-11, BZ-12) The words of BZ-11 in raqib/host.py, the three rules' YAML, raqib/ruleform.py and THREAT_MODEL; the socket tool killed on any error of its reading; a pipe that cannot be made unblocking is the helper not started, said.
- R12 Gate green in the foreground; ASCII outside docs; no fixture's finding changes; Windows unchanged (no Windows test edited but to skip what it cannot run).
Not in scope: BZ-3's three silences themselves and BZ-13 (M14.1d, measured first); the version and CHANGELOG.md (the Table's at the merge).
If an item needs a file outside Scope: STOP and say which file and which line.
Commit: `landed: M14.1c REDO the review's findings` or `STOP: M14.1c REDO <reason>`.
Read HANDOFF.md and do only the task it specifies.
