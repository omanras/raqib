# HANDOFF — M7.24 REDO  (ADR-0007 Amendments BB and BC: a mark, not an omission)

Task: on claude/M7.24 (2f4c5e0, merged with main), rebuild what BC rules: an os follow writes every event as on main and marks those under another tree's root (BC-1, BC-2); a marked line gives its tree no beat (BC-3); the note and the empty block go (BC-4).

Scope:
  raqib/hooks/os_sysmon.py, raqib/host.py (what the watch tells each follow; where a source's lines become a tree's beats), raqib/rules/catalog/HOST-RHYTHM.yaml (holes, description), tests/, docs/THREAT_MODEL.md, docs/review/2026-11-13-M7.24-redo-questions.md

Exit criteria:
- E1 (BC-1) With a root told, a follow writes the same lines as with none, in the same order, except that each line of an event at or under the told root carries `input_meta.under_root` (the root's pid); the root's own event 1 does not. No event is left out in any case; no session_start key; no block without an event. With no root told the bytes are main's (the every-fixture hash test, untouched). The argument's name says what it now does.
- E2 (BC-2) Told and matched by ProcessGuid only: a root with no ProcessGuid is not told (through rounds), a pid-only entry given to the follow is ignored, an event with no ProcessGuid is not marked; a process that once had the root's pid, and its children, are not marked (the packet's F1 case, tested). One parents map keyed by ProcessGuid; pid_of and ident_of_pid go.
- E3 (BC-2) The watch tells a root only while the other follow lives, read when the follow asks. Through rounds, each a test that fails without the reading: a follow that raised, one that returned, one stopped - each while its root is still sampled - is no longer told at the asking that follows; a round that failed (no applied round) does not keep it told.
- E4 (BC-2) A process born under the root before the root was told: its later events are marked once told; when the root is no longer told its later events are unmarked; nothing is written twice or lost across either change (compared with the same channel and no root told: the same lines but for the mark).
- E5 (BC-3) Through rounds with follows that write what os_sysmon would (the built E5 shape): the ancestor's ring gains no act, no talk and no destination from marked lines and makes no HOST-RHYTHM; the nested tree makes its own; with no root told the ancestor does (main's result). A NET-TOOL command among the marked lines is still found, once, as on main.
- E6 (BC-4) A marked line passes `trace.strict_problem`; the watch's feed reads marked lines with no finding of their own, no hole and no "could not judge" note.
- E7 (BC-5) The rule's holes and description and docs/THREAT_MODEL.md (no milestone tokens) say BC-5 and no more; HOST-RHYTHM's holes stay counted by tests/test_rhythm.py (change its pin only by the number of holes you add or remove, and say it).
- E8 Gate green, run in the foreground (never under nohup); ASCII outside docs; no real address; no test reads docs/review.
Not in scope: raqib/rules/trace.py, raqib/discover.py, raqib/event.py, raqib/eventlog.py, `_give_held`, the rhythm's counting (K, W, R, severity), the "judged on another tree" machinery.
If an exit criterion needs a file outside Scope: STOP and say which. Do not change a guard test to pass.
Commit: `landed: M7.24 REDO a mark, not an omission` or `STOP: M7.24 REDO <reason>`.
Read HANDOFF.md and do only the task it specifies.
