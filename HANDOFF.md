# HANDOFF — M10.1 REDO 2  (ADR-0011 Amendment D on review 2026-11-13-M10.1-redo.md)

Task: the second, narrow REDO of M10.1 (eabca24). Amendments B and C stand as built except where D changes them. Rulings D-1 to D-6.

Scope:
  raqib/event.py, docs/specs/EVENT.md, tests/test_event.py (and helpers under tests/ it needs), docs/review/2026-11-13-M10.1-questions.md

Exit criteria:
- E1 (D-1) `snapshot` names a watch's hole "hole:i" and a notifier's hole "notifier-hole:i", each counted in its own list (the notifier's entry is the one that holds `count`); a note "note:i" over the notes, and the lost-words note "note:lost-words" when its text is given by a new argument. Tested through fixture watches: a notifier hole, then a watch hole made after it: across two snapshots no name moves and none is reused; the same for a note made after the lost-words note.
- E2 (D-2) EVENT.md's mapping and the test's literals: "<watch.run>/<about>" -> OCSF finding_info.uid and metadata.correlation_uid; id -> OCSF metadata.uid and ECS event.id; hole.kind -> finding_info.title for a hole; for Base Event kinds id -> metadata.uid and summary -> message. The rev and kind rows stay. The document says `about` is a name within one run.
- E3 (D-3) `watch.host` required: check refuses an event without it; `facts` raises ValueError without a host.
- E4 (D-4) A heartbeat's state is one of WATCHING, SILENT, AGENT GONE, CAPTURE FAILED, FINISHED (the band's word without its number); check knows the list; tested on a state whose band is "SILENT for N s" made by a fixture watch or by ui.status on a state the watch made.
- E5 (D-5) Each point of D-5, each with its test (a cite lacking src or line left out whole; an empty string not held; negative numbers and a repeated technique id refused; a blind spot's hole.count; the document's five statements).
- E6 (D-6) The three weak tests replaced as D-6 says.
- E7 The document's examples are again what the module builds (regenerate them: the first REDO's generator is /tmp/claude-0/-home-claude/b4da06b5-6736-59f0-88a3-8f32e41e2ac5/scratchpad/probe/make_doc.py, outside the tree; say in the questions file how they are made).
- E8 Gate green; ASCII outside docs; no new test reads docs/review; no real host, user or address.
Not in scope: raqib/host.py, raqib/notify.py, raqib/ui.py, raqib/watch.py, the rules, any writer, sink or forwarder; what D records for M10.2.
If an exit criterion needs a file outside Scope: STOP and say which (the questions file).
Commit: `landed: M10.1 REDO 2 the event` or `STOP: M10.1 REDO 2 <reason>`.
Read HANDOFF.md and do only the task it specifies.
