# HANDOFF — M7.16 REDO  (ADR-0007 Amendment AN on review 2026-11-13-M7.16.md)

Task: the REDO of M7.16 (4278453). AM-1 to AM-3 stand as built. Rulings AN-1 to AN-6.

Scope:
  raqib/hooks/os_sysmon.py, raqib/discover.py, raqib/host.py, tests/, docs/THREAT_MODEL.md, docs/review/2026-11-13-M7.16-questions.md

Exit criteria:
- E1 (AN-1) A TimeCreated that is there and does not parse: the follow writes one RAQIB-SILENCE line per event kind saying the logged time was not read and UtcTime is used unchecked; the round's record has a problem saying the same; tested through the follow and through a round (the hole is in the report). An event with an unreadable UtcTime and a readable logged time is a line timed from the log. Not touched, tested: no TimeCreated at all gives no word and the same lines.
- E2 (AN-2) Within one pass, an event keyed by ProcessGuid joins the tree if its guid is in the tree by the end of the pass; an event 1 if its parent is. Tested with the packet's R-2 case through the real follow (a child's event 1 logged 61.1 s late, its event 3 logged 59 s late: both lines are written), and a grandchild's subtree. Not touched, tested: the existing fixtures and exports give byte for byte the lines they gave; pid-only events as before.
- E3 (AN-4) The beats read by the final poll are judged by HOST-RHYTHM before the report, by the code that judges a round's beats: a rhythm completing in the last round is a finding (and its knock) where the same beats one round earlier are; RHYTHM BEATS no longer reports them as "in no round" unjudged. Not touched, tested: a watch whose final poll reads no beat; no finding is made twice. If it needs a second road: questions file, no guess.
- E4 (AN-5) The ALARMS line's count of source findings is the listing's, and says the number of findings behind it when a pair was joined; RESULT and the exit code unchanged. Tested through a watch where one curl is seen by both sources.
- E5 (AN-3, AN-6) THREAT_MODEL says AN-3's three cases and AN-6's cause-not-established; os_sysmon's docstrings are true; the note names the record its skew was measured on where read. Event 1 beyond 60 s has a test that states what happens (two trees or one).
- E6 Gate green; code and tests ASCII; no test reads docs/review or asserts the real clock.
Not in scope: the clipboard, docs/GUIDE.md, README.md, raqib/app.py, raqib/hostwin.py, new rules, ADR-0011.
Commit: `landed: M7.16 REDO an event's time is when it was logged` or `STOP: M7.16 REDO <reason>`.
Read HANDOFF.md and do only the task it specifies.
