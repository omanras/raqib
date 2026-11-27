# HANDOFF — M12.4c2b3  (ADR-0013 Amendment ZB: the service of Windows raises its check-point while its check walks)

Task: at every start Raqib's Windows service asks the check of its own code before it says RUNNING (ADR-0013 T). Over a very large tree that walk takes tens of seconds, the check-point stays 0, and `net start` says the service could not be started though it starts (measured). Make the runner tell START_PENDING again every 2 s with a rising check-point while the check runs, exactly as docs/specs/ADR-0013-the-service-under-the-system.md Amendment ZB rules (read ZB-1 to ZB-4 whole; also T-1, T-2 and U-3 above it).

Scope:
  raqib/winservice.py, tests/test_winservice.py

Exit criteria:
- E1 (ZB-1) `System.set_status` takes the check-point (default 0) and puts it in the structure; `Runner._status` passes it; CHECK_BEAT = 2.0 beside CHECK_WAIT_HINT; while `own_check()` runs START_PENDING is told every beat with 1, 2, 3 ... and CHECK_WAIT_HINT; every other status is told with 0.
- E2 (ZB-2) the raising is a thread begun just before the check; it tells under `self.lock` and not once a Stop was asked or STOPPED told; it is ended and waited for (at most the beat and 5 s; one line if it did not end) before `_own_code` writes its line or returns - on a pass, a refusal, and an exception out of the check alike.
- E3 (ZB-3) a raising not taken or raising an exception: the first said in one line, the rest counted and said in one line after the check; a thread that cannot be begun: one line, the check runs; the exit and the check's answer unchanged in each. `_status`'s own notes must not write a line per beat.
- E4 (ZB-4) tests for each sentence of ZB-4, on events and a small beat, never on sleeps that could race; the made-up system in tests/test_winservice.py records each status's check-point; every existing test still passes unchanged in what it asserts.
- E5 the module's own first lines and comments say what is built and what was measured as ZB's first paragraph says it (the candidate's numbers are the candidate's; this branch itself is not yet asked on a real machine).
Not in scope: raqib/wincode.py; install, remove and status; docs/, tools/rig, .github (the Table's: X55 and the documents); the version and CHANGELOG.md.
A candidate of the idea, never merged, is at `git show origin/claude/M12.4c2b3-cand:raqib/winservice.py` (fetch it if you want to read it): it shows the shape only; it has no bounded wait, no ZB-3 and no tests.
If an exit criterion needs a file outside Scope: STOP and say which file and which line.
Commit: `landed: M12.4c2b3 the service of Windows raises its check-point while its check walks` or `STOP: M12.4c2b3 <reason>`.
Read HANDOFF.md and do only the task it specifies.
