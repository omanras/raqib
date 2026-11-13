# HANDOFF — M7.27  (ADR-0007 Amendment BH: the watch's own tree is what the watch started)

Task: the watch leaves out only what it started itself: its pid, its launchers proven and themselves only, the helpers it recorded, and what those started (BH-1 to BH-3); no walk of parents passes through that tree (BH-4); the link holes say what was read (BH-5).

Scope:
  raqib/own.py (new: the record of what this process started), raqib/discover.py (the snapshot's helpers, the self tree and line of _acts_core, ancestors and _descendants, _link_holes, run_ss's record), raqib/hostwin.py (the snapshot line, self_tree), raqib/hooks/os_sysmon.py (only where it starts wevtutil: the record), raqib/notify.py (only where it starts the notifier: the record), tests/, docs/THREAT_MODEL.md, docs/review/2026-11-13-M7.27-questions.md

Exit criteria:
- E1 (BH-1) Every place under raqib/ that starts a program records the child (its pid, the time) in raqib/own.py's record when it starts it; a test reads the code (AST) and fails for a subprocess.Popen or subprocess.run that is neither recorded nor in a short list the test names with the reason (raqib/doctor.py and raqib/cli.py are other commands: say each). raqib/own.py imports nothing but the standard library and no network module.
- E2 (BH-2) The Windows reader's "# raqib-snapshot" line and the Linux snapshot's first line carry the recorded pids alive in the sample (`helpers`); parse_win_process and parse_proc read them; a text without them parses as before, and every existing fixture under tests/fixtures and raqib/rules/hostdata gives the inventory it gave (the pins untouched).
- E3 (BH-3) Through the parsers, on rows as the live readers write them, each a talker with a child that must be a candidate: (a) under a process that names the reader as its parent, started after the reader, not recorded - also where its image is powershell.exe or wevtutil.exe from System32; (b) under another child of the reader's launcher (the launcher's image python.exe), beside the reader; (c) under an old chain whose starts read younger than the reader's (a clock set back). And the negatives: a recorded helper and the conhost it started are in no tree and nobody's act; the launcher itself is no candidate.
- E4 (BH-3) A sample with no record (an export; a text of before this task): the tree is M7.26's, and the hole says the record was not there. hostwin.self_tree takes the starts as a required argument (tests/test_hostwin.py's test_a7 is given starts; what it pins stays).
- E5 (BH-4) A process under a recorded helper by a link not dated, where the reader's own pid talks (a model call): it is nobody's act, the reader is no candidate, and it is named in the hole. No act's `via` holds a pid of the watch's tree. The bridge: an orphan chain that hangs under the reader's pid by links not dated gives its acts to no ancestor of the reader.
- E6 (BH-5) The broken-link hole's words; the reader marked as the child of a broken link too; the count whole, at most 20.
- E7 (BH-6) One test through hostwin.process_text with a host stand-in (a process that cannot be opened: start ""; pid 0), one through the channel's path (parse_sysmon keyed, a parent timed by the channel and its child by the sample), and one for each of _act_roots' two parent walks that fails when the walk ignores a broken link.
- E8 docs/THREAT_MODEL.md (no milestone tokens): what the watch takes for its own and how it is proven; what is left (the record lives in the watch's memory: a watch started again does not know the helpers of the one before; a program started by a helper is taken by dates).
- E9 Gate green in the foreground; ASCII outside docs; no real address, host or user name; no test reads docs/review.
Not in scope: raqib/host.py, raqib/event.py, raqib/eventlog.py, raqib/rules/, how a start is read, what the notifier or the channel's reader runs, the tree key.
If an exit criterion needs a file outside Scope: STOP and say which. Do not change a guard test to pass.
Commit: `landed: M7.27 the watch's own tree is what it started` or `STOP: M7.27 <reason>`.
Read HANDOFF.md and do only the task it specifies.
