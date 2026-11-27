# HANDOFF — M12.4c2b4 fixes  (ADR-0013 Amendment ZF; the review: docs/review/2026-11-27-M12.4c2b4.md)

Task: M12.4c2b4 was reviewed NEXT with eighteen findings and asked on real Windows at eight moments (it removes what it should and leaves what it should). Build the rulings ZF-1 to ZF-6 at the end of docs/specs/ADR-0013-the-service-under-the-system.md, each as its words say, and nothing else. The packet's "Findings" list names file and line for each.

Scope:
  raqib/wininstall.py, tests/test_wininstall.py, raqib/cli.py (ONLY the help's sentences about --purge on Windows), docs/GUIDE.md and docs/specs/SERVICE.md (ONLY the sentences about --purge on Windows), tests/test_readme_top.py (ONLY where it holds those sentences word for word)

Exit criteria:
- E1 (ZF-1) `_one_name` also refuses a name ending in a dot or a space and a device's name (the forms ZF-1 lists, any case, with or without an extension); each refused form has a test of its own (remove one form from the code and one test fails); the tests' stand-in judges every part of a handed path under the place, not its prefix alone.
- E2 (ZF-2) before the place is touched, `place.held(path)` is asked (raqib/winservice.py System.held, the runner's own call: read raqib/host.py's holder() for what it answers); held fresh -> one line with the state's age, nothing removed, RESULT saying the record NOT removed: a watch still holds the place, exit 1; an exception out of it -> said, nothing touched, exit 1; not held -> as built. The stand-in place answers it in every test.
- E3 (ZF-3) where this command's own remove ended "removed" and a removal inside answers 32, it is asked again every 0.5 s for at most 20 s on the system object's own clock and sleep (the ones the remove's wait uses), then counted; never where the service was not removed by this command; tests on the stand-in clock, none on real time.
- E4 (ZF-4) error 5 inside the place: "access denied: a read-only file, or a name the system holds" and no word of an administrator; nothing sets an attribute. 32 is said with words too ("in use by another process").
- E5 (ZF-5) the words as ruled: the place read again (place_judged "absent") before "is gone", else what was answered and exit 1; "to be removed"; the untouched line; the RESULT for a place that could not be read; the docstring's measured sentence. Every RESULT word the rig reads stays as it is: `RESULT: the service removed; the record removed` and `the record NOT removed: not the place as Raqib's service makes it` for a place read and refused.
- E6 (ZF-6) the documents' sentences and the tests it names (findings 6 to 11 and 15), the measured paragraph now saying what ZF's first paragraph says of this command on real Windows.
Not in scope: the runner, the reader, the check; tools/rig, .github, tests/test_rig_check.py (the Table's: X56 is wired); the version and CHANGELOG.md.
If an exit criterion needs a file outside Scope: STOP and say which file and which line.
Commit: `landed: M12.4c2b4 fixes - names the system rewrites, a watch that still holds the place, words that say what is known (ADR-0013 ZF)` or `STOP: M12.4c2b4 <reason>`.
Read HANDOFF.md and do only the task it specifies.
