# HANDOFF — M10.3 REDO  (ADR-0011 Amendments J, K and L: the forwarder over HTTP)

Task: on claude/M10.3, build what Amendment L rules on the review docs/review/2026-11-13-M10.3.md. Everything else of the first build stands.

Scope:
  raqib/forward.py, tools/rig/collector.py, tools/rig/forward_run.py, tools/rig/check.py (X19 to X22 only), .github/workflows/rig.yml (the forwarder's steps and the check step's condition), tests/test_forward.py, tests/test_forward_rig.py, tests/test_rig_check.py (only for X19 to X22), docs/specs/FORWARD.md, docs/GUIDE.md (the forwarder's rows), tests/test_readme_top.py (only the text of those rows in its lists), docs/THREAT_MODEL.md, docs/review/2026-11-13-M10.3-redo-questions.md

Exit criteria:
- E1 (L-1) Against the in-test collector: [a, b, c] with b refused alone: a taken, b counted and passed only after c is taken, c taken, in that order at the collector; a collector that refuses every line (404, and a 400 for each): the cursor does not move at all, the state says failing `refusing` with the status, `--once` exits 1, and when the collector is put right every line arrives once, in order; a refused last line of the file is passed once a line appended after it is taken. No taken line is sent before an earlier line that is neither taken nor in question.
- E2 (L-2) `--status`: 1 while refusing; 0 only where nothing is failing and nothing has waited longer than a beat; the refused count on every status; a state written in the future is 3. FORWARD.md and the guide's row say the same rule (a test holds the two to the code's words).
- E3 (L-3) A token file made readable by others, and one emptied, while the forwarder runs: a failed try `token-file`, the state written, nothing moved; corrected, the next try sends. An error the forwarder did not foresee (injected in a test) ends it with the state written and no traceback text or token in any output.
- E4 (L-4) A collector that answers one byte every few seconds is `late` within the bound (a short bound injected), and so is one that never ends its handshake; Stop during such a send, between the lines of a refused batch, and in a wait ends the forwarder within 2 s with the state written. The waits use a clock that does not step: a wall clock set back an hour in a test delays nothing.
- E5 (L-5, L-6) SSLKEYLOGFILE set: no file is written (tested where the https test can run). The usage errors of L-6, each exit 2 with its reason, before any send; a damaged state with `--from end` is exit 2, never a first run. The state is flushed before the rename.
- E6 (L-7, L-8) The pid file is never seen empty by a second forwarder (the two steps are one: tested by a second start between them, injected); an empty pid file refuses the name. A tail of more than 512 KiB with no newline: failing `file`, memory bounded (the read is counted in the test), and sent when its newline comes.
- E7 (L-10) forward_run.py with no events file, and with a forwarder that cannot start, exits 0 and writes facts; check.py then says X19 to X22 MISSED or n/a with the reason and the rest of the table stands; rig.yml's check step runs always. X21 is MISSED for a forwarder that sends the first batch again; its kill is by the collector's count. X22 looks for both tokens and reads the system's process list (each MISSED when broken: tested).
- E8 (L-11) Stop by signal on a real process (SIGTERM off Windows; CTRL_BREAK_EVENT on Windows) writes the state. The token grep covers the outputs of L-11's paths. No test sleeps on the wall clock for its verdict or uses a port it did not see bound.
- E9 (L-9, L-5) docs/THREAT_MODEL.md and FORWARD.md say L-9 and L-5 (no milestone tokens); FORWARD.md no longer says the cursor moves only past taken lines where a refused or skipped line is passed.
- E10 Gate green in the foreground; ASCII outside docs; loopback and documentation addresses only; no test reads docs/review.
Not in scope: raqib/cli.py (if an option must change: STOP and say which), raqib/host.py, raqib/eventlog.py, raqib/event.py, docs/specs/EVENT.md, tests/test_rhythm.py (the guard is the Table's), syslog, a service.
If an exit criterion needs a file outside Scope: STOP and say which. Do not change a guard test to pass.
Commit: `landed: M10.3 REDO the forwarder over HTTP` or `STOP: M10.3 REDO <reason>`.
Read HANDOFF.md and do only the task it specifies.
