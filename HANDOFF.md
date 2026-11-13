# HANDOFF — M7.21a REDO  (ADR-0007 Amendment BM: the tracing reader, every way out)

Task: on claude/M7.21a, build what Amendment BM rules on the review docs/review/2026-11-13-M7.21a.md. The reader read real traffic in the field as built: its structures, calls and parsing stand - change none of them.

Scope:
  raqib/etwnet.py, tests/test_etwnet.py, tools/rig/etw_read.py, docs/review/2026-11-13-M7.21a-redo-questions.md

Exit criteria:
- E1 (the packet's R1) No test reads the real system: every test of the tool gives its live pids (or their failure) by injection; `test_e7_a_loss_not_known_and_live_pids_not_known_are_said` passes on Windows as on Linux for that reason. Say in the questions file which tests you checked for it.
- E2 (BM-1) Reader.start(): anything raised after the session began (KeyboardInterrupt, SystemExit, any BaseException, at each step) stops the session and is raised again; tests for each step. A reader started and not stopped is stopped at the interpreter's exit (atexit; unregistered by stop(); a test calls the registered function, and one shows stop() then leaves nothing registered).
- E3 (BM-2) start() for the process's own pid that is refused because the name is there (183): the session of that name is stopped, the start tried once more, and the reader says it (a `said` list in counts(), and the tool prints it). For a `pid` that is not this process's, 183 stays a refusal. Tests for both, and for the second start failing too.
- E4 (BM-3) leftovers takes a callable for the live pids and calls it only after the sessions were listed (a test holds the order); the tool passes its snapshot that way.
- E5 (BM-4) An event of ids 10, 11, 26, 27 whose version is not 0 is unread ("version N"), never parsed; tests.
- E6 (BM-5) counts(): `events` (all events of the provider seen), `other_ids` {id: n} for ids that are not the four, `unread` only for the four not read (its reasons kept). The tool's last line gains `events=N other=N`, and it prints no `said: unread` line for other ids. Tests.
- E7 (BM-6) Events of the tracing's own lost-event provider ({6A399AE0-4BC6-4DE9-870B-3657F8947E7E}) are counted in `lost` as `notices`; a test. If you are not certain of that GUID, say so in the questions file: the Table checks it.
- E8 (BM-7) At most 65536 connections (a constant a test lowers); an event of a new connection beyond it is counted in `beyond`, existing connections still count; tests.
- E9 The stop()'s failure branches the packet names have tests (the stop refused or raising, the close failing, the consumer not ended in time: each said, none raising). Gate green in the foreground; ASCII; documentation addresses only.
Not in scope: the structures, constants and calls the field proved; raqib/host.py, raqib/hostwin.py, raqib/cli.py, the documents, .github/workflows/, tests/test_rhythm.py.
If an exit criterion needs a file outside Scope: STOP and say which. Do not change a guard test to pass.
Commit: `landed: M7.21a REDO the tracing reader, every way out` or `STOP: M7.21a REDO <reason>`.
Read HANDOFF.md and do only the task it specifies.
