# HANDOFF — M7.21b  (ADR-0007 Amendment BO: the watch takes the tracing's counts)

Task: a live watch on Windows reads each connection's bytes from raqib/etwnet.py's reader and hands them to the watch through the door Linux's counts use (`conn_bytes`). The reader itself stands: change nothing in it but what a criterion names.

Scope:
  raqib/host.py, raqib/etwnet.py (a function that sums counts() a pid and a remote, if you want it there; nothing else), tests/test_host_bytes_win.py (new), tests/test_etwnet.py (only for that function), tests/hostthreads.py (only if a fake reader must live there), docs/THREAT_MODEL.md, docs/GUIDE.md, tests/test_readme_top.py (only the guide's new or changed lines in its registry), docs/review/2026-11-13-M7.21b-questions.md

Exit criteria:
- E1 (BO-1) On win32 a round's inventory holds `conn_bytes` {"from", "hole", "by"} in Linux's shape, from the reader's counts; REMOTE is spelled as that round's talks spell it (v4 and v6: a test compares against what raqib/hostwin.py's tcp table text gives the inventory). `_bytes_of` and K-5 are not changed: a kept connection whose counts moved between two rounds is a talk of change "bytes" on Windows as on Linux (a test through the watch with a fake reader).
- E2 (BO-2) The reader is made by one injectable factory (default: etwnet.Reader under os.getpid()); a live win32 watch stops leftovers, then starts it once; every way out of the watch stops it (the normal end, Stop, an error in a round, KeyboardInterrupt: tests with the fake). No reader on Linux, for exports, or for an inventory that is not a watch (tests).
- E3 (BO-3) A refused start: the blind spot `bytes` detail starts with host.WIN_BYTES_HOLE exactly as today and the reason follows it; said once a run; the result and exit code of the watch are what they are today (tests/test_rhythm.py's test of that blind spot passes unchanged).
- E4 (BO-4) A round after which lost events, buffers or notices grew, or `beyond` grew, or the consumer ended: that round's `conn_bytes` has a hole with the reason and no counts, the blind spot `bytes` names the reason and its rounds, and no talk of change "bytes" or its absence is derived from the round before to this one (a test for each of the five causes; and that the round after a loss compares with nothing older than it).
- E5 (BO-5) The reader saw no event at all since its start while the tree's connections changed in the table: said as the reader's hole (a test, and its negative: a quiet machine with no connection change says nothing).
- E6 (BO-7) Leftovers stopped at the start are a note of the run by name; a leftovers problem is a note too, never a failure.
- E7 (BO-6) docs/THREAT_MODEL.md and docs/GUIDE.md say BO-6's sentences where the Windows byte counts are spoken of today (find them: "no byte counts", "bytes"), with no milestone token in the threat model; a test holds the sentences that matter (administrator; one session named for the watch; a killed watch leaves it until the next start; sums since the watch began; UDP not counted).
- E8 Gate green in the foreground; ASCII outside docs; documentation addresses only; no network import in host.py; the capture path stays offline (the reader listens to the kernel, it calls nothing on any network).
Not in scope: the rules, raqib/rhythm code paths' meaning, raqib/event.py, raqib/hostwin.py, raqib/cli.py, tests/test_rhythm.py, .github/workflows/, the rig's tools.
If an exit criterion needs a file outside Scope: STOP and say which. Do not change a guard test to pass. The field check on a Windows runner is the Table's.
Commit: `landed: M7.21b the watch takes the tracing's counts` or `STOP: M7.21b <reason>`.
Read HANDOFF.md and do only the task it specifies.
