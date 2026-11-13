# HANDOFF — M10.3 REDO 2  (ADR-0011 Amendments J, K, L and M: the forwarder over HTTP)

Task: on claude/M10.3, build what Amendment M rules on the review docs/review/2026-11-13-M10.3-redo.md. Everything else of the build stands.

Scope:
  raqib/forward.py, tools/rig/collector.py, tools/rig/forward_run.py, tools/rig/check.py (X19 to X22 only), tests/test_forward.py, tests/test_forward_rig.py, docs/specs/FORWARD.md, docs/GUIDE.md (the forwarder's rows), tests/test_readme_top.py (only the text of those rows in its lists), docs/THREAT_MODEL.md, docs/review/2026-11-13-M10.3-redo2-questions.md

Exit criteria:
- E1 (M-1) Against the in-test collector that refuses one kind of line: 250 lines of that kind, then one of another: the other line arrives (within three tries; at most 100 sends of a line alone in a try; no line already asked alone in this run is asked again except the first in question, once a try), and then the 250 are settled. A collector that refuses everything: `refusing`, the cursor unmoved, each try at most 101 requests; put right, every line arrives, none counted refused. Memory for the lines in question does not grow with their number (a reach and a count: read in the test).
- E2 (M-2) [a, b, c], b refused once and then taken when asked again: b is taken (arrives after c), refused count 0. b refused twice: counted and passed as before. The cursor never passes a line that was neither taken nor refused twice with a take between.
- E3 (M-3) A line of 2 MiB with its newline: passed, counted refused, named by its offset; the test counts the bytes read at once (never more than a piece); the lines after it arrive.
- E4 (M-4) During a send that takes three beats (beats and bounds injected), during a try of 100 slow refusals, and during a walk over 50000 lines that are not events: the state is written at least once a beat and a Stop ends each within the bound. A request that is `late` while being sent: the next try sends half the lines, down to one, and a taken send restores the size.
- E5 (M-5) A collector whose name never resolves or whose connect never returns (injected): after four abandoned sends no fifth starts, the state says `stuck`; when one ends, sending goes on. No socket is closed by another thread than the one using it (read in the code and say how in the questions file).
- E6 (M-6, M-7, M-8) An OSError from the directory or the pid file at the start: exit 2 with the reason, no traceback (tested through cli main). `--status` on a state with beat 0, with `failing` a list, with an offset above 0 and no hash: 3. A restarted forwarder whose state said `refusing` says it until its first answer. A forwarder whose pid file is replaced by another's stops at its next state write with the reason. Port 0 and a tab in the URL: exit 2. The file replaced by another during a try: the try ends, the next pass counts a restart.
- E7 (M-9) No test leaves a thread: every run() started in a test thread is a daemon ended in a finally (a fixture asserts no forwarder thread is alive after each test). The pid-file test asserts what the second start read. No assertion of "under 2.0 s" on real time remains: a real-time bound is at least 5 times the mechanism's own.
- E8 (M-10) docs/specs/FORWARD.md and docs/THREAT_MODEL.md (no milestone tokens): each line of the packet's R1 corrected; the order at the collector; `stuck`; the halved batch. A test holds FORWARD.md's list of failing words to the code's.
- E9 Gate green in the foreground; ASCII outside docs; loopback and documentation addresses only; no test reads docs/review; X19 to X22 still MET by forward_run over a made-up events file.
Not in scope: raqib/cli.py, raqib/host.py, raqib/eventlog.py, raqib/event.py, docs/specs/EVENT.md, tests/test_rhythm.py, .github/workflows/, syslog, a service.
If an exit criterion needs a file outside Scope: STOP and say which. Do not change a guard test to pass.
Commit: `landed: M10.3 REDO 2 the forwarder over HTTP` or `STOP: M10.3 REDO 2 <reason>`.
Read HANDOFF.md and do only the task it specifies.
