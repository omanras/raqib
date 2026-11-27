# HANDOFF — M12.4c2b3 fixes  (ADR-0013 Amendment ZC; the review: docs/review/2026-11-27-M12.4c2b3.md)

Task: M12.4c2b3 was reviewed NEXT with thirteen findings and asked on real Windows (it works: `net start` ends with 0 after the whole walk). Build the rulings ZC-1 to ZC-5 at the end of docs/specs/ADR-0013-the-service-under-the-system.md, each as its words say, and nothing else. The packet's "Findings" list names file and line for each.

Scope:
  raqib/winservice.py, tests/test_winservice.py

Exit criteria:
- E1 (ZC-1) `_own_code`: the raising closed (`checked` set) the moment the check ends; the answer worked out with nothing written; on a refusal `self.code = EXIT_NOT_ALONE` before `_end_raising` writes anything; then the raising's lines, then the check's line; whatever `_end_raising` raises (BaseException) leaves the answer and the exit as they are, with one line where one can be written; `began` read after the thread is begun. Tests: a refusal whose raising failed has 15 set before the raising's first line is written; an exception out of `_end_raising` on a pass still ends RUNNING, on a refusal still 15.
- E2 (ZC-2) the did-not-end line says the start goes on once the raising's call returns; after the bound passed a late failure writes no line and the count's line says "at least N"; the docstrings say what is promised as ZC-2 reads it.
- E3 (ZC-3) CHECK_RAISE_MAX = 300.0 beside CHECK_BEAT: after that many seconds of beats no more is raised, one line at that moment, the check goes on (a test with the value made small); and where at least one raising was taken, one line when the check is over: how many were taken and the last check-point (a test; the existing three-beat test reads it too).
- E4 (ZC-4) the words of finding 9 righted; a failure's words through `_exc_said` (a test with a newline in the exception's text: still one line); the whole of the thread's body guarded so that an exception outside a beat is one line, never a silent end.
- E5 (ZC-5) the five tests of findings 5, 6, 7, 8 and 11, on events, none on timing.
Not in scope: raqib/wincode.py; tools/rig, .github, docs/ (the Table's); the version and CHANGELOG.md. tests/test_rig_check.py and tools/rig/check.py hold a new claim X55 the Table wired: leave them.
If an exit criterion needs a file outside Scope: STOP and say which file and which line.
Commit: `landed: M12.4c2b3 fixes - the order at the check's end, the raising bounded and said (ADR-0013 ZC)` or `STOP: M12.4c2b3 <reason>`.
Read HANDOFF.md and do only the task it specifies.
