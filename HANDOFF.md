# HANDOFF — M7.14 REDO  (ADR-0007 Amendment AJ on review 2026-11-12-M7.14.md)

Task: the REDO of M7.14 (2b8b746). AI-1's bounded pass stands. AI-2's counting of passes is withdrawn: a tree whose
source is os always has the host's own record beside it (AJ-1). Rulings AJ-1 to AJ-5.

Scope:
  raqib/hooks/os_sysmon.py, raqib/host.py, tests/, docs/THREAT_MODEL.md, docs/GUIDE.md, docs/review/2026-11-12-M7.14-questions.md

Exit criteria:
- E1 (AJ-1) Under the host watch a tree attached as os has the host's own record from its attach (as a hooks tree has); the pass counters and the two AI-2 texts are gone. Tested through rounds and the report, each against the same rounds without Sysmon, the findings of the host's record equal: a follow that never reads; one that read once and then fails; one attached again; a channel cleared under it. Not touched, tested: no round read the channel (AF-1, AG-1); a hooks tree; a tree known only from the channel has no host line; HOST-RHYTHM counts an act two sources saw once.
- E2 (AJ-2) A rule firing on a HostChild line and on the os line of the same child (rule, tree, child pid and image) is one entry of SOURCE FINDINGS naming both lines, counted once - only if done in the listing without touching the act registry or a knock; else leave two, say it in THREAT_MODEL and return it in the questions file. Either way a test shows no second knock with the catalog's rules.
- E3 (AJ-3) A finding's source is the source of the line it cites, for an os tree; a hooks tree's labels are byte for byte as before.
- E4 (AJ-4) A follow attached again knows the earlier follow's tree (a child's event 3 after the attach is its act); a ProcessGuid given in another case or without braces joins; when the round's read restarts, the follows' bounds restart with it and read on, said in the restart's hole. A test each, through the real follow.
- E5 (AJ-5) THREAT_MODEL, the guide (and HOST_UNREAD) and os_sysmon's docstrings are true of the code: W-1 to W-6 of the packet.
- E6 Existing tests that change do so only because an os tree now has host lines too; each such change is listed in the questions file under "REDO: tests changed" with its reason. If more than about thirty tests change, STOP and list them.
- E7 Gate green; code and tests ASCII; no test reads docs/review; no test asserts the real clock.
Not in scope: raqib/hostwin.py, raqib/app.py, README.md, new rules, the act registry's keys, ADR-0011.
Commit: `landed: M7.14 REDO a follow that returns` or `STOP: M7.14 REDO <reason>`.
Read HANDOFF.md and do only the task it specifies.
