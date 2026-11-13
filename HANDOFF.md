# HANDOFF — M10.3 REDO 3  (ADR-0011 Amendments J to N: the forwarder over HTTP)

Task: on claude/M10.3, build what Amendment N rules on the review docs/review/2026-11-13-M10.3-redo2.md. The machine of the cursor stands as it is: each change is local.

Scope:
  raqib/forward.py, tools/rig/check.py and tools/rig/forward_run.py (only if the state's new keys need it), tests/test_forward.py, tests/test_forward_rig.py, docs/specs/FORWARD.md, docs/THREAT_MODEL.md, docs/review/2026-11-13-M10.3-redo3-questions.md

Exit criteria:
- E1 (N-1) A collector whose answer to a batch of 100 comes after the bound (bounds injected) and to 50 within it: the next try sends 50, and they are taken; sizes then go 100, 50, 100 no more: a taken send doubles (50, 100), a late one halves, down to one. No batch is sent twice at one size after being late.
- E2 (N-2) r1 to r101, r100 of a refused kind, `--once`: r101 arrives and the exit is 1 only for the line still in question at the end; the loop's wait after a try that moved is none (the injected wait is not called between such tries); a try that moved nothing waits as J-10 says. `refusing` is in the state while a line is in question.
- E3 (N-3) The state holds the head's sha256 and length; a file replaced at cursor 0 (the first build's case: a long tail, then another file shorter than what was looked through) counts a restart and loses no line of the new file; a file cut to the cursor, or replaced by one with the same lines up to the cursor, while lines are in question: the reach, the count, the proof and the tail's mark go back to the cursor, and no line of the new part is counted refused after one refusal. A file that only grew: nothing is given up (tested: no extra request).
- E4 (N-4) The pid file removed while running: written again, said, the run goes on; unreadable once (injected): the run goes on; holding another live pid: the run ends with 1 and the reason printed once.
- E5 (N-5) `in_question` {count, since} in the state; `--status` is 1 while a line has been in question longer than a beat, also while settling; 0 once settled. `sent` is not counted twice for a proof across a restart (the packet's finding 1, its sequence as the test).
- E6 (N-6) A state whose failing.error is a list, and one nested 100000 deep: `--status` 3 and a start 2, no traceback (through cli main).
- E7 (N-7) The fixture: a thread left by one test fails that test and no later one, and the teardown of later tests does not wait for it (tested with a stand-in thread). No f.run() on a test's own thread. A test where the first line in question is taken on its re-ask and the next one is refused: nothing is passed on that take. The cursor helper fails a made-up trace in which the only take between a line's two refusals is of an earlier line.
- E8 (N-8) A line of 64 MiB (pieces and the clock injected, the file sparse or the reads stubbed): the state is written each beat and a Stop ends the walk within the bound, in looking for its end, in hashing it, and in `behind`.
- E9 (N-9) docs/specs/FORWARD.md and docs/THREAT_MODEL.md (no milestone tokens) say N-9's four things; a test holds FORWARD.md's table of what `--status` says in each state to judge's own words.
- E10 Gate green in the foreground; ASCII outside docs; loopback and documentation addresses only; no test reads docs/review; X19 to X22 still MET by forward_run over a made-up events file.
Not in scope: raqib/cli.py, raqib/host.py, raqib/eventlog.py, raqib/event.py, docs/specs/EVENT.md, tests/test_rhythm.py, .github/workflows/, the way lines in question are settled (M-1, M-2), syslog, a service.
If an exit criterion needs a file outside Scope: STOP and say which. Do not change a guard test to pass.
Commit: `landed: M10.3 REDO 3 the forwarder over HTTP` or `STOP: M10.3 REDO 3 <reason>`.
Read HANDOFF.md and do only the task it specifies.
