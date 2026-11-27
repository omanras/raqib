# HANDOFF — M12.4c2b4  (ADR-0013 Amendment ZE: `raqib service remove --purge` on Windows removes the record too)

Task: on Windows `raqib service remove --purge` is refused today ("not built", raqib/wininstall.py PURGE_REFUSED). Build it exactly as docs/specs/ADR-0013-the-service-under-the-system.md Amendment ZE rules (read ZE-1 to ZE-4 whole, its first paragraph for what was measured, and X-6 and Y-3 above it for the remove as it is and the place's judgement).

Scope:
  raqib/wininstall.py, tests/test_wininstall.py, raqib/cli.py (ONLY the help's sentences about --purge on Windows), docs/GUIDE.md and docs/specs/SERVICE.md (ONLY the sentences that say --purge is not built on Windows), tests/test_readme_top.py and tests/test_service.py (ONLY where they hold those sentences word for word)

Exit criteria:
- E1 (ZE-1, ZE-3) `remove(system, out, reader=None, purge=False, place=None)`: the service's remove first, unchanged; the record touched only where it ended with exit 0 (gone, or none installed); then `place_judged` (the function as it is - do not copy its logic): "absent" -> one line, nothing to remove, exit 0; "refused" -> its words, the name left, exit 1; "taken" -> removed as E2. cli_run passes --purge to remove and still refuses it with any other action. PURGE_REFUSED goes.
- E2 (ZE-2) the removal through new calls on wininstall's System (list a folder's names with each one's attributes without following a link, remove a file, remove an empty folder) that a test's stand-in answers; bottom up; a reparse point inside neither entered nor removed, counted, and the place then left; each error counted by the system's number, the first one's path kept; nothing outside the place is ever named in a call (a test asserts every path handed to the stand-in begins with the place's own path).
- E3 (ZE-4) the lines and the exit: what was read of the place; removed (how many folders, how many files, the place gone) with exit 0 and a RESULT that says the service and the record removed; or what is left, RESULT saying the record NOT removed, exit 1; error 5 said with "an administrator is needed"; without --purge the record's line says that --purge removes it; every path printable ASCII (`_error_said`).
- E4 tests for each sentence of ZE-1 to ZE-4 on stand-ins (the existing made-up system and reader in tests/test_wininstall.py extended, not replaced), the judgement's words tied to winservice.prepare's as the install's test ties them; every existing test of remove still passes with what it asserts unchanged except the record's line.
- E5 the documents in Scope say what is built, each sentence true to the code; what was measured named as ZE's first paragraph names it (this branch itself is not yet asked on a real machine).
Not in scope: the runner, the reader (raqib/winmanager.py), the check; tools/rig, .github (the Table's: X56); the version and CHANGELOG.md.
If an exit criterion needs a file outside Scope: STOP and say which file and which line.
Commit: `landed: M12.4c2b4 raqib service remove --purge on Windows removes the record too` or `STOP: M12.4c2b4 <reason>`.
Read HANDOFF.md and do only the task it specifies.
