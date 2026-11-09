# ADR-0007 - The host, not the name: Raqib watches a machine, not an agent it was told about

Status: accepted (M7.3, 2026-11-04; Amendment G). Proposed 2026-11-03 on the commander's order.
Amendments appended, never edited in place.

## Problem
The commander's verdict after M6.4 (2026-11-03, 22:04): a watcher that
must be told which agent to watch, and which project, is not a watcher.
"How do I know there is no other agent on it?" Raqib has the mechanism
(ADR-0004: an agent is a process tree that talks to a model and acts on
the machine; `raqib discover`; AGENT-DARK), but it is a separate command,
on Windows it needs a PowerShell loop run by hand, it runs once, and
neither `raqib watch` nor the window starts from it. Everything that
watches starts from a name the commander already knows.

## Decision
Raqib's unit of watching becomes the host. The commander names nothing.
1. **Discovery is live and in-process on every platform.** On Windows
   the host's own records (processes and their parents, TCP connections
   with their owning process, DNS names where the host recorded them) are
   read through the OS API from Python's standard library (ctypes),
   read-only, with the least process right there is; no PowerShell, no
   loop by hand. Linux keeps /proc. The PowerShell loop stays as the
   fallback that an export can be repeated from (A5, A8).
2. **The host is watched continuously.** `raqib watch --host` (and the
   window) discovers at intervals for as long as it runs. A tree that
   starts talking and acting is a finding, NEW-AGENT, with a knock, named
   if the catalog knows it and "unknown" if not: an unknown agent is a
   finding, never a nothing. An agent footprint with no live tree is
   AGENT-DARK, live. "No agent seen" is said with the window and the
   records read, every time, never by silence (A3).
3. **Sources attach themselves.** For every tree discovered, Raqib
   attaches what it can without being told: a Claude Code image -> the
   hooks into the project that tree's cwd names; a Sysmon channel on
   the host -> the os source rooted at that tree; otherwise the host's
   own record of the tree (its connections, its children, its writes
   where the OS shows them) is a source of its own, judged by the rules
   that need no hook (NET-TOOL, DESTRUCT-CMD by program names, the
   silence rules, CROSS-SOURCE where two sources overlap). Nothing is
   signalled, attached to, or written to (A4).
4. **The unknown is judged by rhythm.** A tree that talks to an endpoint
   the catalog does not know is judged by the think-act cycle alone:
   periodic outbound traffic to one destination interleaved with process
   creation (ADR-0004 layer 3), thresholds not a model; the suspect layer
   may raise suspicion on it and never acquit (A2).
5. **The window starts from the host.** Its first screen is the machine:
   the agents found, each with its band, and one Start. The project
   field remains for a watch of one project.

What this does not promise, said now (A7): an agent that runs entirely
inside another program and acts only through that program's own hands
(a library in an IDE that never spawns a shell and never writes outside
its config) shows as a talker without an act, listed, not a candidate;
an agent that talks only to a local model with no socket at all is
invisible to layer 1 and 2 and is a named hole until layer 3 reads the
process's own file activity. These are recorded, not hidden.

## Consequences
- New `raqib/hostwin.py` (Windows live reader, ctypes), `raqib/host.py`
  (continuous discovery, NEW-AGENT, AGENT-DARK live, source attachment),
  the host record as a source (`source: host`), the rhythm anchor, the
  window's host screen. `raqib discover` with no files runs live on
  Windows as it does on Linux.
- CI: the live reader runs on both runners for a short window and must
  produce an inventory in which the reader itself is not a candidate.

## Candidates
- M7.1 Windows live discovery in-process (`raqib discover` live on
  Windows; `--save` keeps the samples as the CSV shapes).
- M7.2 `raqib watch --host`: continuous discovery, NEW-AGENT, AGENT-DARK
  live, source attachment, the host record as a source.
- M7.3 The window starts from the host.
- M7.4 Rhythm (layer 3) and suspicion on unknown trees.
Order: M7.1, M7.2, M7.3, M7.4. M5.4 (Kimi hooks) is no longer needed
for Kimi to be watched; it stays as a later convenience.

## Amendment A (the Table, 2026-11-04) - rulings on review 2026-11-03-M7.1.md (fff37b6)
Builder's record: docs/review/2026-11-03-M7.1-questions.md (Q-1..Q-13).
CI run 41702279079 for fff37b6: six jobs success on the first commit. On the
windows install job the live reader ran through the real API: 469 records,
14 named holes, the reader (pid 524) no candidate, and four candidate trees
nobody named to it - runner.worker, runner.listener, hosted-compute-agent,
waappagent: GitHub's own Actions agents, which talk to a remote service and
spawn shells. The ADR-0004 definition found agents it had never heard of.
Verdict: REDO on P1; the Table's choices A-2..A-13; the rest recorded.
- A-1 (P1, P13) Every cap, skip and truncation in the reader is a hole with
  its count: DNS_NAMES_MAX reached (how many more were there), NULL names
  skipped, names truncated at NAME_MAX. Nothing is dropped in silence (A3).
- A-2 (P2) A record list returned by DnsQuery_W is freed whenever the
  pointer is non-NULL, whatever the status. Test with a fake that returns a
  list with a non-zero status.
- A-3 (P3, Q-3) The command line is not read live (A4): ratified. The
  NOT_READ hole says the consequence in one sentence: argv-based names and
  the --type helper check are not available live, so a Claude Code run as
  node shows as "node" and its footprint as AGENT-DARK beside it; the
  hand-off falls back to the os source. M7.2 takes it from there.
- A-4 (P4) The benign negatives go through the fake API too: the live path
  gives the same inventory as the CSVs on every discover fixture, positive
  and negative, so the act-root budget is shown to hold live.
- A-5 (P5) The CI replay step asserts that replay.json equals live.json in
  candidates, act_roots, act_root count and hole count.
- A-6 (P6) LiveRefused covers the API load only. Any exception inside the
  reader ends the run with "live reader failed at <step>: <type>: <text>",
  exit 2, never "the API cannot be loaded".
- A-7 (P7) The reader's own tree is its pid plus its launcher ancestors: the
  unbroken chain of ancestors whose image is raqib*.exe, python*.exe or
  pythonw*.exe (the console script and the venv redirector). The self line
  and run.json carry all of them; none is an act or an act-root. The CI step
  asserts the parent pids too.
- A-8 (P10) A pid whose image basename at OpenProcess differs from the
  snapshot's szExeFile is "pid reused in the gap": the path and time are
  dropped and a hole counts it. Two holes from two layers for a denied pid
  (hostwin's and G-4) are accepted: not silence.
- A-9 (P11, Q-1) parse_win_process honouring "# raqib-snapshot self=" in an
  export is the same trust as proc.txt's self: accepted and recorded.
  run.json carries `self` (the pids of A-7) as well, so the CSV line is not
  the only record. The doctor code change is accepted.
- A-10 (P12) An AF_INET6 table failure is a hole; the IPv4 rows stand (as
  Linux, ADR-0004 D-2). Test.
- A-11 (P14) Samples are T seconds apart start to start; sample_times stay
  the record.
- A-12 (P15, Q-9) doctor `host` on macOS is UNSURE: "homes only; no live
  reader".
- A-13 (P16) The test's constant is named right (DNS_INFO_NO_RECORDS 9501).
- A-14 Accepted as built: Q-4 (GetProcessTimes, ISO UTC), Q-5, Q-6 (refuse),
  Q-7 (a later failed snapshot: hole + incomplete), Q-8 (with A-1), Q-10,
  Q-11, Q-12. Q-13: ADR-0004 gets a dated note under A-1 that "Windows is
  read from exported files only" is superseded by ADR-0007 M7.1 (the Table
  writes it in this commit).
- A-15 Recorded: P8 (the host's own logs see the reader's handle opens and
  DNS calls: a watcher that is logged is right; a THREAT_MODEL line at the
  docs pass), P9 (NO_WIRE_QUERY rests on the API's word; the DnsCache
  service's behaviour is not observed), P17, P18 (no cwd live on Windows:
  M7.2's hook attachment on Windows needs another source for the project).
- A-16 Every REDO change carries a test for the behaviour it adds (D-8).

## Amendment B (the Table, 2026-11-04) - judgement on M7.1 (fff37b6 + 32332d6)
- A-1..A-13 MET as cited in the REDO section of
  docs/review/2026-11-03-M7.1-questions.md; the Table read the A-1 delta
  (every cap a counted hole: over_cap, null_names, truncated, the process
  cap as "more") and the A-7 delta (the LAUNCHER chain raqib*/python*/
  pythonw*.exe on the self line and in run.json). Every REDO change names
  its test (A-16, D-8).
- CI, read from api.github.com: run 41702279079 (fff37b6) and run
  41714365523 (32332d6), six jobs success each. On the windows install job
  of the second run the live reader's self chain held raqib.exe and the
  reader, none an act, and replay.json equalled live.json (A-5, A-7 on a
  real host).
- Gate on the branch: 2496 passed, 16 skipped. Scope clean. Two commits
  (G-8).
- R-1 (the launcher chain stops at a "parent" created after its child: a
  reused pid) accepted. R-2 (agent_dark on the M5.0 windows fixture is
  compared live with the CSVs as the API gives them) accepted, A-3's
  consequence. R-3 (the cap counts entries, not distinct names) accepted.
  R-4 (the step text names the sample) accepted. R-5 (A-12's UNSURE line
  applies to every platform that is neither Linux nor Windows) accepted.
- Decision 1 of this ADR is built. Status: proposed until M7.2 lands.
- Verdict: **NEXT**. Merge --no-ff into main under the commander's order
  ("complete the project").
- Table ledger for M7.1: one review, one REDO, no CI follow-up. The Table's
  own misses: the HANDOFF said "one line" for doctor and meant one line of
  output (P11); the handoff needed three trims and one RED push (16862b5).

## Amendment C (the Table, 2026-11-04) - rulings on review 2026-11-04-M7.2.md (1aa2eb2)
Builder's record: docs/review/2026-11-04-M7.2-questions.md (Q-1..Q-12).
CI run 41731699480 for 1aa2eb2: six jobs success on the first commit. On the
windows install job the host watch ran two rounds (240 records, 13 named
holes each) and listed four trees, all unknown to the catalog, as history
and not knocked. Verdict: REDO on P1 and P2; the Table's choices C-3..C-8;
the rest ruled or recorded. Scope widened by this amendment to
raqib/rules/fixtures.py (one rule), raqib/rules/engine.py (CLASSES),
raqib/discover/endpoints.yaml (one block), docs/specs/ADR-0002 (the Table).
- C-1 (P1, A6) Budgets are measured, never guessed. (a) fixtures.py: a
  negative fixture with no line that passes a rule's tool/source gate is
  unmeasured for that rule, not measured. (b) The negatives of NEW-AGENT and
  AGENT-DARK-LIVE are host-line fixtures in which the benign desktops' trees
  arrive after round 1 (the make.rounds_of pattern the reviewer probed).
  (c) Severity: a named new tree is high; an unknown new tree is medium.
  (d) endpoints.yaml gains `benign_images` (a signature with its evasion
  listed: an agent that takes a benign program's name; the match needs the
  image path under the system or program-files directories, and a denied
  path never matches): a new tree whose image is benign is listed with
  `benign`, not knocked; the evasion is in the rule's holes. (e) fp_budget
  is what (b) measures after (d), declared in the YAML with the fixture it
  came from.
- C-2 (P2, A5) Every host watch has a run id (start time and pid) carried
  on every line of rounds.jsonl, inventory.json and the state; seqs
  continue from the record's last line, read at the start; a cited seq is
  (run, seq) and resolves to one line. A second host watch on the same home
  while the state's heartbeat is fresh is refused with one line (one host
  watch per home).
- C-3 (P3) --rounds and Stop end the watch at the outstanding reader's
  deadline (2 x T) at the latest; a reader still out is a hole in the
  report; never a wait beyond the deadline.
- C-4 (P4) A round-1 act-root that becomes a candidate later knocks:
  ratified. B-3's history is the state at the start, not a transition that
  happened under the watch.
- C-5 (P5, Q-3) Each tree knocks under its own rate-limit id ("NEW-AGENT
  pid N"); on_folds is set and folded_waiting is in the report, as in
  ADR-0005 D-4.
- C-6 (P6) Each host line in rounds.jsonl carries the text of the record
  lines it cites (bounded, _safe): the record stands alone (A5). Only the
  latest inventory is kept: recorded.
- C-7 (P7) The band after a failed or late round reads HOST READER FAILED /
  READER LATE, ordered before WATCHING (as I-3 orders capture states).
- C-8 (P8) The CI step runs `raqib discover --json` in the same job and
  asserts that every discover candidate pid appears in the watch report's
  trees; stderr is captured for the Traceback check.
- C-9 (P9) `started` on candidates and act-roots in --json: accepted (API).
- C-10 (P10, Q-7) Exit codes: trees listed and nothing new = 0 (CLEAN with
  the trees named); a NEW-AGENT or AGENT-DARK-LIVE finding = 1 (ALARM); a
  round that could not be read = 3 (incomplete). The presence of a known or
  history tree is not an alarm; a new one is.
- C-11 (P11, Q-5) ADR-0002's table gains the two anchor rows and "Ratio
  after M7.2: 4 : 7 : 8" by the Table on the branch, where the rules are
  (on main the table must match the catalog); the REDO removes the
  set-aside in test_rules.py.
- C-12 (P13) A test ties DARK_ROUNDS to the YAML's `eq: 3`; "3 rounds" as
  the unit stays, recorded (a time-based streak is a later task).
- C-13 (Q-1) One sample per round on Windows: accepted. (Q-4) engine.py
  CLASSES gains HOST; both rules move to class HOST. (Q-12) recorded.
- C-14 Every REDO change carries a test for the behaviour it adds (D-8).

## Amendment D (the Table, 2026-11-04) - rulings on review 2026-11-04-M7.2-redo.md (b8e798a)
CI run 41750630942 for b8e798a: six jobs success. The REDO met C-1a/b/c,
C-2, C-4..C-9, C-11..C-13; two must-fixes remain. Verdict: REDO-2.
- D-1 (R1, C-3, A3) `--rounds N` counts rounds attempted: a reader that
  reaches its deadline is one attempted round (a reader-late hole), so the
  watch ends at N whatever the reader does. Test: rounds=2 with a reader
  that never returns ends at the second deadline.
- D-2 (R2, C-10, rule 4) A round whose discover result says nothing was read
  is an unread round: exit 3. A round with lines that could not be read is
  a hole: exit 3 unless a finding makes it 1. "No agent seen" is said only
  of a round that read records. Tests for both.
- D-3 (R3, C-1d) The benign directories are the system drive's only: the
  Windows globs are rooted at the SystemRoot drive the reader recorded in
  run.json (no `?:`), and the user-writable places under it are excluded
  by name (windows/temp, windows/tasks, windows/tracing,
  windows/registration, windows/system32/tasks, windows/system32/spool,
  windows/syswow64/tasks). Both evasions join the catalog's list and the two
  NEW rules' holes. Test: an image under windows/temp is not benign.
- D-4 (R4, C-1e, builder's R-1) Accepted as stated: NEW-AGENT-UNKNOWN fires
  on both benign arrivals (1.0 on the arrivals, 0.4 on the measured set),
  because per-user IDE installs live where agents live; widening
  benign_images to user directories would hand agents their evasion. The
  YAML keeps both numbers. Whether medium is the right weight for an
  unknown tree on a desktop is the commander's field decision, beside the
  act-root budget already on his list (night-status 2026-11-03).
- D-5 (R9) The third rule NEW-AGENT-UNKNOWN, its ADR-0002 row and "Ratio
  after M7.2: 4 : 7 : 9" are confirmed by the Table. Ledger: the Table's
  ADR-0002 note on the branch broke the starting gate (the table parser
  took its rows as M4.3's); the REDO's parser fixed it.
- D-6 (R7) A heartbeat that cannot be parsed refuses the second watch with a
  line naming the state file (an unknown state is not clearance, A3). Two
  watches started in the same instant are a recorded hole.
- D-7 (R8) The CI step compares discover's candidates with the report's
  trees over pids alive in both snapshots; a pid gone between the two is
  printed as "gone between", not a failure.
- D-8 Recorded: R5, R6, R10, R11 (exe_from in --json: API).
- D-9 Every REDO-2 change carries a test (rule D-8 of ADR-0005).

## Amendment E (the Table, 2026-11-04) - judgement on M7.2 (1aa2eb2 + b8e798a + 3324ef1)
- C-1..C-13 and D-1..D-7 MET as cited in the REDO and REDO-2 sections of
  docs/review/2026-11-04-M7.2-questions.md; the Table read the D-1 delta
  (done_rounds: attempted rounds, reader-held holes, never two readers) and
  the D-2 delta (round-unread / lines-unread holes; NOTHING READ vs NO AGENT
  SEEN, "Not a clearance" on both). The second review's R1 and R2 are
  closed by them. Every REDO change names its test (D-8/D-9).
- CI, read from api.github.com: runs 41731699480 (1aa2eb2), 41750630942
  (b8e798a) and 41758469242 (3324ef1): six jobs success each. On the
  windows install job the host watch found the runner's trees by shape,
  listed them as history, exited 0 (CLEAN with the trees named, C-10), and
  discover's candidates matched the report's trees over pids alive in both
  (D-7).
- Gate on the branch: 2568 passed, 16 skipped; kinds 4 : 7 : 9 (NEW-AGENT,
  NEW-AGENT-UNKNOWN, AGENT-DARK-LIVE). Scope as widened by C and D. Three
  landed commits plus the Table's note (G-8). One builder was lost to two
  container restarts; its draft on disk was verified by the next (A8) and
  found complete.
- S-1 (a held round writes no round line; it is a hole in the report and
  state): accepted for v1, recorded. S-2 (the README loop's exports carry
  no drive, so `--from` them treats no Windows image as benign): accepted;
  the README loop gains a drive line at the next docs pass. S-3 (the
  discover API grows): recorded.
- Decision 2 of this ADR is built; decision 3 (source attachment) is M7.2b,
  decision 5 (the window) is M7.3, decision 4 (rhythm) is M7.4. Status of
  this ADR: proposed until M7.3 lands.
- Verdict: **NEXT**. Merge --no-ff into main under the commander's order.
- Table ledger for M7.2: two reviews, two REDOs; the Table's own misses:
  the ADR-0002 note broke the starting gate on the branch (D-5); the
  HANDOFF said nothing of exit codes, so Q-7/P10 had to be ruled (C-10).

## Amendment F (the Table, 2026-11-04) - rulings on review 2026-11-04-M7.3.md (38a01e9)
Builder's record: docs/review/2026-11-04-M7.3-questions.md (Q-1..Q-11).
CI run 41762820973 for 38a01e9: six jobs success; on windows the Tk
host-screen test and the three M6.4 Tk tests PASSED and the real tray came
up. Verdict: REDO on P1 and P2; C-3..C-8 the Table's; the rest ruled or
recorded. Scope widened to raqib/host.py (F-9) and raqib/ui.py (F-6 only
if the Log pane needs it).
- F-1 (P1, A3) The first look's level is not read from discover's result
  word: it is incomplete whenever any source was unread or partly read or
  any line could not be parsed, and its holes are listed in the body, with
  their count; AGENT-DARK footprints are shown as their own lines. Tests
  with an incomplete inventory and a dark one.
- F-2 (P2, E3) Both screens are reachable at any time: a header with
  "Host" and "Project" that switches between them while their watches run;
  a refused Start names the running watch and switches to its screen.
  Test: both watches running, switch back and forth, every control present.
- F-3 (P3) The first look's holes persist (footer and app.log) until the
  host watch's first round replaces them, and that round waits for the
  look's reader: never two readers. Test.
- F-4 (P4, A5) A host finding line cites (run, seq) as the project's
  finding_line cites seqs.
- F-5 (P5, A2) The kind word order is named, unknown, benign; a named tree
  is never shown as benign.
- F-6 (P6, Q-9) The host watch has a Log pane as the project watch has
  (ADR-0006 A-5).
- F-7 (P9) Colours follow the exit codes of C-10: 0 green, 1 red, 3 amber,
  at open and at Stop alike. The first look is one round: green only when
  it read records with no unread source and found no tree; "Not a
  clearance" stays printed in every green state.
- F-8 (P10) A refused host watch is exit 2 (a refusal, not a finding);
  every watch's final report is appended to app.log, never replaced.
- F-9 (P15, host.py) HostWatch.result: any unread or partly read source in
  any round makes the result incomplete (3) unless a finding makes it 1;
  a tree beside a partly read source is never CLEAN. Test.
- F-10 (Q-1) The first look is written to ~/.raqib/host/look.json (latest,
  with its holes and the reader's timing); it is not round 1, and history
  begins at "Watch this host": accepted.
- F-11 (Q-8) An "Open page" button on the host screen, as the project
  screen has (ADR-0006 A-13).
- F-12 Recorded: P7 (closed by F-10), P8 (closed by F-11), P11..P14; the
  `ss` call on Linux stays named in the docstring and enforced by
  test_discover's guard.
- F-13 Every REDO change carries a test for the behaviour it adds (D-8).

## Amendment G (the Table, 2026-11-04) - judgement on M7.3 (38a01e9 + afe7a7b)
- F-1..F-11 MET as cited in the REDO section of
  docs/review/2026-11-04-M7.3-questions.md; the Table read the F-1 delta
  (probe_view: level from the look's own sources - unread, partly read,
  parse problems, nothing read, late - code 3 when blind; dark lines) and
  the F-9 delta (host.unread_sources; HostWatch.result incomplete on any
  unread or partly read source unless a finding). Every REDO change names
  its test (F-13).
- CI, read from api.github.com: runs 41762820973 (38a01e9) and 41768524237
  (afe7a7b), six jobs success each; on windows the two Tk host-screen
  tests (the look, "Watch this host"; both watches running, switching
  back and forth with every control present) PASSED, with the three M6.4
  Tk tests and the real tray.
- Gate on the branch: 2602 passed, 18 skipped. Scope clean (widened by F
  to host.py). Two commits (G-8).
- R-1 (the look turns amber on any discover `incomplete` reason, while
  HostWatch.result counts unread or partly read sources only): accepted
  for v1, recorded; the stricter look is the right side to err on. R-2 (a
  look with trees and an unread source is amber, not red: it knocks
  nothing) accepted. R-3 (round 1 waits for the look's reader; HostWatch's
  own deadline still marks it late) accepted. R-4, R-5 accepted.
- Decisions 1, 2 and 5 of this ADR are built: `raqib discover` live on
  Windows; `raqib watch --host` with NEW-AGENT, NEW-AGENT-UNKNOWN and
  AGENT-DARK-LIVE; the window opens on the host. Decisions 3 (M7.2b) and
  4 (M7.4) remain. Status of this ADR: **accepted (M7.3, 2026-11-04)**;
  the decision text stands; Amendments A-G are the record.
- Verdict: **NEXT**. Merge --no-ff into main under the commander's order.
- Table ledger for M7.3: one review, one REDO; the Table's miss: the
  HANDOFF let the look's level come from discover's result word by not
  saying where the level comes from (F-1); the exit-code colours were not
  in the HANDOFF either (F-7).

## Amendment H (the Table, 2026-11-04) - decision 3 narrowed before M7.2b is built
The first M7.2b builder stopped before writing code (its response was cut
by a safety classifier during the read-through; it did not retry, and the
Table does not ask it to) and raised a design point that stands on its
own: E1(a) as written would have Raqib write `.claude/settings.json` into
any project a discovered Claude Code tree works in, though nobody named
that project. `raqib watch` makes that write only where the commander
pointed it (ADR-0005 decision 1, A4's one permitted write).
- H-1 Decision 3 is narrowed: the sources that only READ (the os source
  where Sysmon is; the host's own record of the tree) attach themselves.
  A source that WRITES into a project (the hooks) attaches only with the
  commander's word for that watch: `raqib watch --host --attach-hooks`
  (and the window's checkbox "attach hooks to Claude Code projects", off
  by default). Without it, a Claude Code tree is watched by the os or host
  source like any other, and the report says "hooks: not attached (no
  --attach-hooks)". The decision text above stays; this amendment is the
  record of the narrowing.
- H-2 The host source lines are judged by the existing rules where their
  fields fit; to make them fit honestly, NET-TOOL.yaml and DESTRUCT-CMD.yaml
  accept `source: host` lines of tool HostChild on their command_programs
  (scope widened to those two YAMLs); the silence rules do not run over host
  lines (silence.py gains one exemption by source; the host's own quiet is
  the rounds' business, M7.2 E4); CROSS-SOURCE over host lines is a later
  task (recorded, not built). No host line is ever labelled tool Bash.
- H-3 HOST-UNWATCHED is the fourth host anchor: kinds 4 : 7 : 10; the
  Table writes the ADR-0002 row and "Ratio after M7.2b" on the branch; the
  builder extends test_rules.py's note parser as M7.2 did.
- H-4 Windows has no cwd live (Amendment A-15): with --attach-hooks a
  Claude Code tree on Windows is a hole for hooks and falls to the os or
  host source; recorded.
- Table ledger: the HANDOFF as first written let a discovered tree cause a
  write into an unnamed project; corrected here before any code.

## Amendment I (the Table, 2026-11-04) - rulings on review 2026-11-04-M7.2b.md (86c4518 + c3c96ab)
Builder's record: docs/review/2026-11-04-M7.2b-questions.md (Q-1..Q-9).
CI: run 41783688289 (86c4518) four success, both windows gate jobs failed
six windows-only tests (Tk tests with options None; path separators in
asserts); run 41784559628 (c3c96ab, the follow-up) six jobs success.
Verdict: REDO on P1, P2, P3; the Table's choices I-4..I-11; the rest ruled
or recorded. The two A4 findings are the kind this amendment series exists
for: under the flag, a project the agent controls could steer Raqib's
writes. Scope: as HANDOFF M7.2b, plus raqib/install.py for I-1 if the check
must live there.
- I-1 (P1, A4, Q-3) Under --attach-hooks the hooks are written only when
  every path component from the project to `.claude/settings.json` is a
  real directory or file (lstat, no symlink or junction at any step) and
  the settings file's realpath lies under the project's realpath; else
  "hooks: not attached (.claude is a link / outside the project)", a hole,
  and the os or host source. Test: the reviewer's symlink probe (`.claude`
  -> `~/.claude`) writes nothing to the home settings.
- I-2 (P2, A4) An attached tree's trace is always Raqib's own default
  under ~/.raqib/traces; a trace the project's existing settings name is
  never used and no directory is created outside ~/.raqib; such an entry is
  reported "foreign" (doctor's word) and replaced as `raqib watch` replaces
  one. Test: a settings.json naming an arbitrary trace path creates nothing
  there.
- I-3 (P3, A3, ADR-0005 B-1) A source's SILENCE-OPEN or SILENCE-HALF still
  pending at Stop is "pending for good": counted as an alarm of that tree
  in source_alarms and result (exit 1), listed as "pending at exit". Test.
- I-4 (P4, P5) A hooks source with no line after two rounds is a hole
  "hooks attached, no line yet" (silence, A3); the gone-and-back text names
  the real reason, never "None".
- I-5 (P6) wevtutil runs with a timeout per pass (10 s, as the notifier's);
  a pass that does not return is a hole and the helper - Raqib's own child,
  never the agent's - is terminated and recorded; nothing of Raqib's outlives
  the watch unrecorded.
- I-6 (P7, P8, P14) Aggregate findings of a source hand over as ADR-0005
  C-2/E-2 (grown, not knocked again); context rules that cannot run on a
  source are listed once per source as a note; knocks follow ADR-0005 A-4:
  high findings, plus the first finding of each tree (FirstFinding).
- I-7 (P11) The remote host:port of a HostConnection line stays in clear:
  it is the field the NET rules read and the hook source already keeps the
  URL host (ADR-0001); the os source hashes because Sysmon gives it
  differently. Accepted and recorded.
- I-8 (P12) Per-tree source files are keyed by (run, pid, started), never
  pid alone. Test: a pid reused within a run gets its own file.
- I-9 (P10) The fake-filesystem test also traps io.open, pathlib's
  write_text/write_bytes/open/mkdir/touch, os.symlink/link/truncate,
  shutil, tempfile and subprocess with file arguments, and runs with the
  notifier on (fake runner) and a fake Sysmon channel.
- I-10 (P17) Stop leaves attached hooks in place, as `raqib watch` does;
  the report says so per project; an uninstall is a later task (recorded).
- I-11 (P15) Judging under the watch lock: accepted for v1, recorded.
- I-12 Recorded: P9/P16 (argv is never read live because cite texts are
  cut, so the node+cli.js branch is dead in practice - the safe side;
  stated in the questions file), P13 (DESTRUCT-CMD's measured denominator
  grew by the `any`; no unintended match found), P18, P19.
- I-13 The ADR-0002 note for HOST-UNWATCHED and the M4.2 "lines beyond the
  table now" line are written by the Table on the branch in this ruling's
  merge (main's table must match main's catalog).
- I-14 Every REDO change carries a test for the behaviour it adds (D-8).

## Amendment J (the Table, 2026-11-04) - judgement on M7.2b (86c4518 + c3c96ab + 29222d2)
- I-1..I-12 MET as cited in the REDO section of
  docs/review/2026-11-04-M7.2b-questions.md; the Table read the I-1 delta
  (link_in_path: lstat of every component, symlink, junction and other
  reparse points refused; the settings realpath under the project's
  realpath; the check repeated after the write) and the I-2 delta
  (choose_trace gone from host.py; the default trace only; a foreign
  entry replaced, nothing created where it pointed). Every REDO change
  names its test (I-14).
- CI, read from api.github.com: runs 41783688289 (86c4518: four success,
  the windows gate jobs failed six windows-only tests), 41784559628
  (c3c96ab: six success) and 41795872435 (29222d2: six success). On the
  windows gate jobs the symlinked-`.claude` and the real NTFS-junction
  tests PASSED: nothing reached the home settings.
- Gate on the branch: 2657 passed, 19 skipped; kinds 4 : 7 : 10. Scope as
  widened by H and I. Three builder commits plus the Table's ADR-0002 note
  (G-8). The first M7.2b builder stopped before code (Amendment H).
- S-1 (install.write_atomically still follows a symlink for `raqib
  install-hooks` and `raqib watch`, where the commander named the project):
  recorded; the same link check belongs there at the next installer task.
  S-2 (the old foreign trace file is left in place, unread): accepted.
  S-3 (pending at exit does not knock at the end): accepted, as `raqib
  watch`. S-4 (run() keeps the 600 s reader): recorded for the os-source
  task. S-5 (the first-finding knock is per tree): ratified. S-6 (I-4's
  "two rounds" counted after the attach round): accepted. P6's remainder
  (each follow exports the whole channel per pass): recorded.
- Decision 3 of this ADR is built as narrowed by Amendment H. Decision 4
  (rhythm) is M7.4, the last of the phase.
- Verdict: **NEXT**. Merge --no-ff into main under the commander's order.
- Table ledger for M7.2b: one builder lost to a classifier stop before
  code, one review, one CI follow-up, one REDO; the Table's own misses:
  the first HANDOFF's E1(a) (Amendment H); the HANDOFF's "nothing else is
  written anywhere" without naming links and foreign traces (I-1, I-2).

## Amendment K (the Table, 2026-11-04) - rulings on review 2026-11-04-M7.4.md (46bfbce, local)
Builder's record: docs/review/2026-11-04-M7.4-questions.md (Q-1..Q-10).
CI: not run - pushes held by the commander's order (Actions minutes
exhausted, 2026-11-04); the local gate is the gate until he decides.
Verdict: REDO on P1, P2, P3; the Table's choices K-4..K-9; the rest ruled.
- K-1 (P1, A3) Every host line of an unknown tree is sent exactly once:
  a call sends a bounded window (40 lines) and `suspect_upto` advances only
  to the last seq actually sent; the next call continues from there; lines
  never sent when the watch ends are a hole "N lines not judged by the
  suspect layer" on the tree and in the report. Test with 120 lines.
- K-2 (P2, A3) The suspect job reads the tree's own source file whatever
  its source (host, os, hooks); a record shape the prompt builder cannot
  send is a hole "source X not sendable" on the tree, once. Test per source.
- K-3 (P3) Never two calls in flight: the backend call carries the 120 s
  budget as its own timeout (urllib timeout; Ollama's 300 s does not
  apply), a call still out blocks the next R-th round's call with a
  "suspect-held" hole, and a thread is never left running unrecorded.
  Test with a slow fake backend: one call in flight at most.
- K-4 (P4) What leaves the machine carries no pid and no reversible hash:
  the session id is an opaque per-run index of the tree; every hash sent
  is salted with the run id (the tree's own file keeps its unsalted
  hashes for the rules). Test on the prompt text.
- K-5 (P5, Q-3) A talk beat is a connection NEW in this round, or an
  established one whose bytes moved since the last round where bytes are
  read; where no bytes are read, an established connection is at most one
  talk (when first seen), and the evasion "repeated talks on one long
  connection are unseen without bytes" is named in the YAML. The act's
  time on Linux is the child's /proc/PID/stat starttime turned into wall
  time (btime), so W is real; the round time only when stat is unreadable
  (a note). Tests for both.
- K-6 (P6) A HostConnection line is written on change only (new, closed,
  bytes moved); the ring, not the file, carries the streak. Test: a
  long-lived connection writes no line per round.
- K-7 (P7, A5) Rhythm cites carry round and seq ("round 4 win-tcp:2").
- K-8 (P8, Q-6) The bytes and start-time gaps are holes of a named class,
  "blind spot", said once per run, counted apart, shown with "(does not
  change the result)"; never exit 3 on their own.
- K-9 (P9, Q-5) HOST-RHYTHM's negatives are the four synthetic cases; the
  arrivals are not listed (they cannot fire). The YAML says the budget is
  measured on synthetic fixtures only and that the field source - an IDE
  that polls and builds for hours - is the commander's to measure (as the
  act-root budget).
- K-10 (Q-1, Q-4) The name HOST-RHYTHM stands (beside HOST-UNWATCHED). A
  history tree that cycles under the watch fires: the cycle is live (C-4
  of ADR-0007 F reasoning). Benign-image trees are judged by rhythm and
  never sent to the suspect layer in v1: accepted, recorded.
- K-11 (P16) The AST guard covers urllib, http.client, socket, ssl and
  subprocess with curl/wget in every module; the suspect thread is the
  one allowed caller.
- K-12 (P17) The Table writes the ADR-0002 M7.4 note on the branch and
  deletes the two dead set-asides in test_rules.py in the same commit.
- K-13 (P18) The CI host step also asserts that check-rules lists
  HOST-RHYTHM with its budget (the rule loaded), beside the zero count.
- K-14 Every REDO change carries a test for the behaviour it adds (D-8).

## Amendment L (the Table, 2026-11-04) - judgement on M7.4 (46bfbce + fd61db3, local)
- K-1..K-13 MET as cited in the REDO section of
  docs/review/2026-11-04-M7.4-questions.md; the Table read the K-1 delta
  (a cursor per source file; suspect_upto advances past sent lines only;
  "suspect-unsent" hole), the K-2 delta (host, os and hooks sources each
  with an allow-list; "suspect-unsendable" once per tree), the K-3 delta
  (the budget as the backend's own timeout; "suspect-held"; "suspect-out"
  at Stop) and the K-4 prompt text (opaque tree index; salted hashes;
  finding summaries not sent). Every REDO change names its test (K-14).
- Gate on the local branch, run by the Table: 2721 passed, 19 skipped;
  kinds 4 : 7 : 11. CI NOT RUN: pushes are held by the commander's order
  (Actions minutes exhausted, 2026-11-04); the windows jobs have not seen
  M7.4 or this REDO. The merge into main is local; the push and the CI
  run wait for the commander's decision, and this ADR's record says so.
- S-1 (continued suspect calls run back to back on a backlog): accepted
  for v1, recorded; pacing is a later task. S-2 (history lines of a hooks
  trace are sent too): accepted - the model may raise suspicion on what
  was there at the start, never acquit it. S-3 (the SDK's own retries
  inside the budget per request): recorded; the holes name a call that
  overran. S-4 (Windows: a connection closed and reopened between rounds
  is unseen): a named hole of the host source, recorded. S-5 (the window's
  band does not show blind spots): a later docs/window pass.
- The builder's addition (a failing backend is not retried at every tick;
  continued calls wait for the next R-th round) accepted: tested.
- Decision 4 of this ADR is built. All five decisions of ADR-0007 are
  built: live discovery on Windows (M7.1), the host watch (M7.2), the
  window from the host (M7.3), reading sources attached (M7.2b, hooks
  only with --attach-hooks per H), rhythm and suspicion (M7.4). Phase 7
  exit awaits two things that are the commander's: the CI run of the
  held commits, and the field test on his machines (Windows + Kimi:
  `raqib app` on the host, NEW-AGENT when Kimi starts, HOST-RHYTHM over a
  session, and `--suspect ollama` if he has it).
- Verdict: **NEXT** (local). Merge --no-ff into local main under the
  commander's order; push held.
- Table ledger for M7.4: one review, one REDO, no third review; the
  Table's miss: the HANDOFF said "every unknown tree's source file" and
  did not say "every line, once" nor "every source" (K-1, K-2).

## Amendment M (the Table, 2026-11-04, 19:10) - the first field run (the commander's Windows machine, Kimi)
Recorded from the commander's report, verbatim in substance; figures are
his, not the Table's. Installed from main d30f6da; `raqib-app` opened on
the host; "Watch this host" with hooks not attached; Kimi started in a
terminal with a task that runs shell commands.
- Two toasts arrived and NEW-AGENT fired on the Kimi tree: `kimi pid 9176,
  named (new, gone), 6 acts, source os, endpoint 104.18.17.93:443, first
  seen 18:10:30Z`, cited run ...-14608 seq 16, round 10. The catalog named
  it (the Moonshot endpoint or the image), so it was NEW-AGENT (high), not
  NEW-AGENT-UNKNOWN. The terminal it ran from was listed as history
  (`powershell pid 5888, unknown (history), 1 act, source os`), not
  knocked, as B-3 says.
- The source attached by itself was `os` (Sysmon is on that machine):
  decision 3 as narrowed by H, on a real host, with no project named.
- AGENT-DARK-LIVE fired twice, rounds 3 and 13, on the `~/.kimi` footprint
  with no live tree for 3 rounds: once before Kimi started (right: an
  installed, silent agent), once after it ended (right by the rule, yet
  the same footprint that had just been a named tree - the second knock is
  the one a person will call noise). Both toasts were the AGENT-DARK-LIVE
  ones the commander saw; the NEW-AGENT knock is "[sent]" in the report.
- HOST-RHYTHM did not fire on a Kimi session of a few minutes (the report
  shows "rhythm / suspicion: -"); the os source carried the acts (6), the
  rhythm ring reads the host source's beats. Whether rhythm should read
  the os source's children too is a question for M7.5 (below).
- Exit: three findings, ALARM. The report's own lines are the citation.
What the run teaches (for the next handoff, M7.5 "after the first field
run"): (1) AGENT-DARK-LIVE must not re-fire for a footprint whose tree was
live in this watch and ended normally (gone-and-dark is the agent's
normal end): a streak after a live tree is a note, not a knock, unless
the tree was never seen in the watch; (2) the rhythm ring must take act
beats from whichever source the tree has (os children as well as host
children), else rhythm is blind exactly where Sysmon makes the source
richer; (3) the catalog named Kimi, so NEW-AGENT (high) was right; the
unknown path remains to be seen on a tree the catalog does not know -
the commander's act-root/UNKNOWN budgets are still unmeasured; (4) the
NEW-AGENT knock did not reach the commander as a toast while the two
AGENT-DARK-LIVE ones did - to verify from app.log and the notifier's
counts (folded? rate-limited behind the first AGENT-DARK-LIVE within the
same minute? the per-tree id C-5 should have prevented that).

## Amendment N (the Table, 2026-11-09) - rulings on review 2026-11-09-M7.5.md (178adc5)
Builder's record: docs/review/2026-11-09-M7.5-questions.md (Q-1..Q-11).
CI run 42566014129 for 178adc5: six jobs success on the first commit.
The review found no must-fix; the Table makes one, because it trades an
alarm for silence. Verdict: REDO on N-1; N-2..N-5 the Table's; the rest
ruled or recorded.
- N-1 (P1, Q-1, Q-2, A3) `was_live` is not sticky and history does not
  count: a footprint is "live" for AGENT-DARK-LIVE only when a candidate
  tree linked to it was seen under the watch (live, not history) within
  the last R_dark rounds (R_dark = 3 x the streak, 9 by default, declared
  in the YAML); after that window a 3-round dark streak knocks again. A
  history-only link never makes a footprint live. Tests: the reviewer's
  case (a history candidate, then an agent that runs only between rounds)
  ALARMS as on main; Kimi's case (live tree, gone, then dark) is a note
  within the window and a knock after it. The YAML's hole for "runs once
  briefly to mark itself live" is replaced by the window's text.
- N-2 (P2) AGENT-DARK-LIVE's measured negatives exclude lines its match
  cannot see (`was_live: true`), as K-9 did for HOST-RHYTHM; the YAML
  states the measured count honestly.
- N-3 (P3) A fixture of the field run's own shape: host talks plus os
  acts (Amendment M's Kimi tree, synthetic), positive at 3 cycles.
- N-4 (P4) Beats of the final poll are placed in a closing round or
  counted as "beats after the last round: N" in the report; never dropped
  silently.
- N-5 (P5) The KNOCKS ledger is bounded (the newest 200; the count of
  older ones kept) in the state; the report prints all of this watch's.
- N-6 (P6) The replay test gains the field run's history powershell tree
  and an os source; the questions file's clock times are corrected to
  what Amendment M records (18:10:30Z and round numbers only).
- N-7 (Q-7) ADR-0005 A-4 is amended by this ruling: the title is
  "Raqib: <event>[ <subject>]", subject = the cleaned image name for the
  host rules, at most 40 characters, same alphabet, 120 in all.
- N-8 (Q-10, P10) The field conclusion stands as the record supports it:
  the NEW-AGENT toast was handed to Windows ("sent") and what happened
  after is unknown; the AppUserModelID idea is unsourced and is struck
  from the questions file as a cause (kept as a question). The next field
  run compares the KNOCKS ledger with the Windows notification centre,
  toast by toast; a registered app id for toast.ps1 is a later decision
  of the commander's (it changes A-4).
- N-9 (P11, Q-6) One child counted as an act by two sources: acts are
  keyed by (pid, started) across sources so a child counts once; os and
  host talks to one server stay two destinations (under-counts, safe).
- N-10 (Q-5) Source beats counted one round late: accepted, recorded.
- N-11 Every REDO change carries a test for the behaviour it adds (D-8).
