# HANDOFF — M7.26  (ADR-0007 Amendment BE: a reused pid is not a parent)

Task: in raqib/discover.py a parent link holds only where the holder of the parent pid did not start after the child (BE-1); the watch's own tree is made only of links whose two starts were read (BE-2); what was broken or kept unread is said (BE-3).

Scope:
  raqib/discover.py (ancestors, _descendants, the self tree and line of _acts_core, the walks of _act_roots, the holes' texts), raqib/hostwin.py (only where the reader walks up to its launchers: the same rule), tests/, tests/fixtures/discover/ (new files only; synthetic.py may gain a case, its existing outputs unchanged), docs/THREAT_MODEL.md, docs/review/2026-11-13-M7.26-questions.md

Exit criteria:
- E1 (BE-1) ancestors() and _descendants() do not cross a link whose parent started after the child, both starts read (started_of): tested on processes of one source (any later start), of two sources (the sample and the channel's event 1: broken only above GUID_SAME_SECONDS), and with a start unread on either side (kept). A chain broken in the middle ends there: nothing above it is an ancestor.
- E2 (BE-4) The field shape, through build() on records made as tests/fixtures/discover/synthetic.py makes a Windows sample: the reader's pid is the parent pid of an old chain (started hours before the reader) under which a talker with a child lives. The talker is a candidate with its child as an act; the reader's own child, started after it, is nobody's act and in no tree. In the questions file: what main's code gives for the same records (no candidate at all).
- E3 The same where the reused pid is a launcher's (ADR-0007 A-7: the snapshot's launchers); the Windows reader names as its launcher no process that started after the one below it in the chain (a stale parent pid held by a younger python or raqib is not a launcher: tested on the walk with made-up process rows, no Windows call needed); and where the stale link is not the reader's: a child whose parent pid a younger stranger holds goes to no ancestor through it (its act is not the stranger's).
- E4 (BE-2) A process under the reader by pid whose own start was not read, and one whose start was read while the reader's was not: neither is in the reader's tree; each is judged as any other process (a talker among them with a child is a candidate).
- E5 (BE-3) The inventory's holes: one that counts the links broken and names their pids (sorted, at most 20, the count whole), saying "the reader's own pid" where the younger process is the reader or its launcher; one that counts the links kept with a start unread. No such hole where there is none. The hole "reparented acts" no longer says a reused pid is only "not attributed".
- E6 Every existing fixture under tests/fixtures/discover and tests/fixtures/host gives the inventory it gave: the existing pins and hash tests pass untouched. If one changes, do not change the pin: STOP and say which fixture, which process, which two starts.
- E7 Through the host watch: rounds built by discover from E2's records (a reader stand-in that returns them): the report lists the talker's tree and the result is not NONE-SEEN.
- E8 docs/THREAT_MODEL.md (no milestone tokens): what a reused pid could do, what is now proven by dates, what is left (a link whose starts are not both read).
- E9 Gate green in the foreground; ASCII outside docs; no real address, host or user name; no test reads docs/review.
Not in scope: raqib/host.py, raqib/hooks/, raqib/event.py, raqib/eventlog.py, raqib/rules/, how a start time is read (the readers), the tree key (pid, image, started).
If an exit criterion needs a file outside Scope: STOP and say which. Do not change a guard test to pass.
Commit: `landed: M7.26 a reused pid is not a parent` or `STOP: M7.26 <reason>`.
Read HANDOFF.md and do only the task it specifies.
