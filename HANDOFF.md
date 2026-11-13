# HANDOFF — M10.2 REDO 2  (ADR-0011 Amendment H on review 2026-11-13-M10.2-redo.md)

Task: the second, narrow REDO of M10.2 (bc57cc9). Amendments F and G stand as built except where H changes them. Rulings H-1 to H-9.

Scope:
  raqib/eventlog.py, raqib/host.py (the pass and what it needs), raqib/event.py (H-6's and H-7's keys and arguments, check), docs/specs/EVENT.md, docs/THREAT_MODEL.md, tools/rig/check.py (only if an event's keys change what it reads), tests/, docs/review/2026-11-13-M10.2-questions.md

Exit criteria:
- E1 (H-1) Every pass looks at every finding, source finding, hole of the watch, hole of the notifier, knock row and tree; at the notes that are new or replaced in place since the last pass (the watch records the index wherever it assigns `self.notes[i]`: three places). Per entry the writer keeps the values the event is built from and builds nothing where they are unchanged. Tests: (a) for each kind, changing any one value the builder reads (drive it from the builder itself: build, change one key of the entry, build again; where the two events differ, what the writer keeps must differ) is seen; (b) through a fixture watch, a source finding that changes after it settled (its standing moves to another tree; its fold is decided; it grows) is said in the next pass, between beats, at once; (c) a pass over a watch with 2000 notes and 2000 settled source findings, none changed, builds no event (count builder calls).
- E2 (H-2) EVENT.md says H-2's sentence. Where the kept half of a pair has no line in the file (not built, or its write failed), the folded half is said unfolded (alarm as its state says, no same_as) until the kept half is said. Tested in each order: host first; os first (rev 1 alarm true, rev 2 folded); the pair found a round later; the kept half unbuildable.
- E3 (H-3) A knock row (or any entry) that raises when read stops only itself; the rows after it are said; a list's own failure makes one hole for the watch's life, not one a pass. Tested with one bad row among good ones, over three passes.
- E4 (H-4) The file's end is checked before every append (tested: a fragment appended by another writer between two lines of one watch; the next line starts on its own line). A failed write of a first saying, a later rev, the start is said at the next pass (tested each, with the file unwritable for one pass); a heartbeat never reuses a rev.
- E5 (H-5) The state is written before the result the end says is computed: a state file that cannot be written makes the end say INCOMPLETE with the report's exit (tested). EVENT.md says what the end cannot hold.
- E6 (H-6, H-7) `watch.beat` on every event (event.py's facts, check, EVENT.md's rows, required keys and examples: regenerate the examples with the Table's tool named in the launching message); `snapshot` takes the pairs and says same_as; the file-equals-snapshot test runs on a watch with a pair.
- E7 (H-8) EVENT.md's section for a reader of the file, each statement of H-8; the stale sentence gone.
- E8 (H-9) The host-name line asserted in the output of the watch's real start; the weak tests replaced.
- E9 Gate green; ASCII outside docs; no new test reads docs/review; no real host, user or address.
Not in scope: sending anything, raqib/cli.py, raqib/app.py, raqib/ui.py, raqib/watch.py, raqib/notify.py, the rules, README.md, docs/GUIDE.md.
If an exit criterion needs a file outside Scope: STOP and say which (the questions file). Do not change a guard test to pass.
Commit: `landed: M10.2 REDO 2 the watch writes its events` or `STOP: M10.2 REDO 2 <reason>`.
Read HANDOFF.md and do only the task it specifies.
