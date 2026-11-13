# HANDOFF — M7.20 REDO  (ADR-0007 Amendment AW on review 2026-11-13-M7.20.md)

Task: the REDO of M7.20 (09c1eb5, 6eb77fe). AU-1 and AU-2 stand as built. AU-3 is withdrawn (AW-1); the key is written only where asked (AW-2); the note (AW-3); tests (AW-4).

Scope:
  raqib/hooks/os_sysmon.py (the net line's meta, and the argument that asks for it), raqib/host.py (the rhythm's beats and destinations, and the follow's call), raqib/rules/fixturegen.py, raqib/rules/catalog/HOST-RHYTHM.yaml (fixtures list, holes, description, the budget's comment), tests/ (fixtures and their generators included), docs/THREAT_MODEL.md, docs/review/2026-11-13-M7.20-questions.md

Exit criteria:
- E1 (AW-1) `server_of` and `one_server` are gone from raqib/host.py; `_rhythm` and `rhythm_of` are what main has except that an os talk's destination comes from dest_sha256 where the line has it (AU-2). The -split-sources fixtures, the "mixed" scenario and their tests are removed; `raqib check-rules`: 9 positive, 11 measured, 0 fire; the YAML's lists, its budget comment (keep AV's corrected field numbers as merged from main) and every count pin in tests/ follow.
- E2 (AW-2) dest_sha256 is written by os_sysmon only when its caller asks (one argument through follow/build to the net line; default: not written). The host watch's os follow asks. Then: tests/fixtures/rules/NET-TOOL/*-os-process.json, DESTRUCT-CMD/*-os-process.json and tests/fixtures/cross/*.log are byte for byte main's (restore them; `git diff main -- <those paths>` is empty), their generators are main's, and tests/test_event_logged_time.py is main's (FIXTURES_BUILT with no stripping). A new test: a build that asks differs from one that does not only by that key on net lines.
- E3 (AW-3) The note for os net lines without the key: once per source object with its count, as the note for a process line without an image is made (host.py, grep "pre_m78_said"); its words name both causes and that an old and a new line to one server are two destinations. Tested with two trees and with a source attached again.
- E4 (AW-4) tests/test_os_sysmon.py's dest_sha256 assertions compare with literal hashes, not with the function itself; the redundant parameter of the K-1 test is gone; a through-rounds test: a connection the os source places in round m and the sample first sees in round m+1 gives one talk on each of two destinations and, with one act, never two cycles on one destination.
- E5 The rule's holes and description, and docs/THREAT_MODEL.md (no milestone tokens): AU-3's words removed; "an os talk and a host talk to one server are two destinations" true again; AW-2's two statements about the server hash; "said once per source" true; os_sysmon's docstring says the key is absent when the address, the port or the protocol does not parse, or when it is not asked for.
- E6 Gate green; ASCII outside docs; no new test reads docs/review; no real address.
Not in scope: raqib/discover.py, raqib/app.py, raqib/ui.py, raqib/event.py, severity, any other rule's YAML.
If an exit criterion needs a file outside Scope: STOP and say which (the questions file).
Commit: `landed: M7.20 REDO one server, one os destination` or `STOP: M7.20 REDO <reason>`.
Read HANDOFF.md and do only the task it specifies.
