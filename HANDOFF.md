# HANDOFF — M7.16  (an event's time is when it was logged: ADR-0007 Amendment AM)

Task: on the commander's machine Sysmon stamps its network events weeks behind the time they were logged, and Raqib
takes that stamp: every connection is "before the watch's start", history, never knocked
(docs/review/2026-11-13-the-elevated-watch.md, F1 to F3). Rulings AM-1 to AM-4.

Scope:
  raqib/hooks/os_sysmon.py, raqib/discover.py, raqib/host.py, raqib/rules/engine.py, raqib/rules/tree.py, raqib/rules/cross.py (the not-judged note only), tests/, docs/THREAT_MODEL.md, docs/review/

Exit criteria:
- E1 (AM-1) Wherever a Sysmon event's time is taken (the follow's lines, the round's records, a tree's talks and acts), it is the logged time (System/TimeCreated SystemTime) when that is read and UtcTime is more than 60 s from it, else UtcTime exactly as before; a line timed from the log carries input_meta.time_from "logged" and the skew in seconds. Tested with a made-up export of the field's shape (events 1 and 11 at the watch's minute, events 3 logged then and stamped 26 days earlier): through the follow, the net lines are live, in order with the process lines; through the rounds, a tree's talk is in its round and the report's window does not start weeks back. Not touched, tested: an export whose two times agree, and one with no TimeCreated, give byte for byte the lines they gave (the existing fixtures unchanged); event 1's match with a sampled CreationDate.
- E2 (AM-2) One note per event kind per watch naming the kind and the skew (days, hours), saying the logged time is used; not a hole, not a knock; a watch with only that note can end CLEAN (exit 0). Tested through rounds and the report. Not touched: no skew, no note.
- E3 (AM-3) A rule's "could not judge N line(s)" note for one tree's file is one note with the latest count across passes; two rules or two files are two notes; the JSON's and the state's counts unchanged. Tested through a follow of three passes.
- E4 (AM-4) A test states RHYTHM BEATS for the made-up export before the fix's times and after. If "beats after the last round" is not explained by the times: change nothing, write docs/review/2026-11-13-M7.16-questions.md.
- E5 THREAT_MODEL says it (no milestone tokens): a Sysmon that stamps events behind the log; which time Raqib uses; that the lag itself is a note. Gate green; code and tests ASCII; no test reads docs/review or asserts the real clock; the made-up export uses documentation addresses and no name of the field.
Not in scope: the clipboard (M7.10), docs/GUIDE.md, README.md, raqib/app.py, raqib/hostwin.py, new rules, ADR-0011.
Commit: `landed: M7.16 an event's time is when it was logged` or `STOP: M7.16 <reason>`.
Read HANDOFF.md and do only the task it specifies.
