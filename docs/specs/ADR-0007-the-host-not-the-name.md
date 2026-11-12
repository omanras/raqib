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

## Amendment O (the Table, 2026-11-09) - judgement on M7.5 (178adc5 + 1e7b012)
- N-1..N-9 MET as cited in the REDO section of
  docs/review/2026-11-09-M7.5-questions.md; the Table read the N-1 delta
  (live_window read from the YAML's eq, 9; was_live recomputed each round
  from a live candidate link only, never history; the streak restarts when
  the window closes). Every REDO change names its test (N-11). N-7 is
  recorded as ADR-0005 Amendment L.
- CI, read from api.github.com: runs 42566014129 (178adc5) and 42568560843
  (1e7b012), six jobs success each.
- Gate on the branch: 2758 passed, 19 skipped; kinds 4 : 7 : 11. Scope
  clean. Two commits (G-8). The REDO was built in a second worktree
  because the Table had the main checkout busy: accepted and recorded.
- The builder's open question (os_sysmon writing the ProcessId on process
  lines, so N-9's act key is exactly (pid, started) on every source):
  yes, a later task on raqib/hooks/os_sysmon.py (recorded for M7.7); the
  image-plus-1-second match stands until then and the report counts the
  duplicates it merges.
- The field lessons of Amendment M are closed: dark-after-live is a note
  within a 9-round window and a knock after it; rhythm reads every source;
  the NEW-AGENT toast was sent by Raqib and the KNOCKS ledger now lets the
  next field run compare toast by toast.
- Verdict: **NEXT**. Merge --no-ff into main under the commander's order.
- Table ledger for M7.5: one review (no must-fix found), one REDO made by
  the Table (N-1, an alarm traded for silence); the Table's miss: the
  HANDOFF's E1 said "was live in this watch" without a window, which is
  exactly the sticky flag the builder built.

## Amendment P (the Table, 2026-11-10) - the second field run (the commander's Windows machine) and what it opens
Recorded from the commander's report (the watch's own printed lines; his
machine, his figures). Installed from main after M7.6d; `raqib-app`,
"Watch this host", no --attach-hooks, no --suspect, overlay empty; 40
rounds of 10 s, ended by Stop in the window; Sysmon present, so every
tree's source was `os`. 14 holes in every round.
- The unknown path fired in the field for the first time:
  NEW-AGENT-UNKNOWN (medium, sent) on `powershell pid 5888` in round 2 (in
  the first run the same shell was history), and on `msmpeng pid 9952` in
  round 16. The second is Windows Defender's engine: a false positive of
  the benign list (its image is under ProgramData, not under a listed
  directory).
- NEW-AGENT (high, sent) on `kimi pid 9176` in round 16, the footprint's
  AGENT-DARK-LIVE cleared by the link; round 22 gave the M7.5 note "dark
  after a live tree (note)", not a knock (N-1 holds in the field); round
  30, the window closed, AGENT-DARK-LIVE knocked again as N-1 says.
- AGENT-DARK-LIVE knocked in round 3, before Kimi was started: an
  installed agent that is not running reads as dark 30 s into every
  watch. Right by the rule; the person's answer is the Rules panel.
- The shell's tree was "gone" and "back" in alternate rounds thirteen
  times, and each time its os source was ended ("the tree is gone") and
  attached again "after a hole", while the process (pid 5888) lived the
  whole watch. Kimi's tree was a tree of rounds 16 and 19 only in a
  session of minutes. A tree stops being listed when it does not talk at
  the sample's instant; the watch calls that gone.
- No finding came from any source line. The Table read why in the tree:
  on a host with Sysmon the source is `os`, and no catalog rule judges an
  os line - NET-TOOL excludes source os, DESTRUCT-CMD matches tool Bash or
  HostChild only, and an os line keeps the image name as Sysmon logged it
  (`curl.exe`), which no list holds. Where the record is richest, the
  acts are recorded, counted for the rhythm, and judged by nothing.
- The commander's question that day: does Raqib only watch, or can it stop
  an agent? It only watches (A4; ADR-0001 section 7: Raqib is not a
  sandbox and blocks nothing); the answer stands and no task changes it.
- Beside the run the commander showed an agent's own account of a paste
  test (text an agent stages in the clipboard, which the person pastes
  into a console that runs each line). Nothing of that account is copied
  here. What it teaches Raqib is two holes, P-4 and P-5.

Rulings and what they open:
- P-1 (M7.8) An os line's acts are judged: os_sysmon writes the image
  name in the one normalised form discover uses, NET-TOOL and DESTRUCT-CMD
  judge os `process` lines by it, and their lists gain the Windows
  programs of each kind, each with fixtures and a measured budget (A6).
- P-2 (M7.8) Gone means the root process is gone. A tree seen before whose
  root is still in the round's process sample and does not talk now is
  `quiet`: listed, its source kept, never "gone", never "back", no hole.
- P-3 (M7.8) Windows Defender's engine under the system drive's
  ProgramData\Microsoft\Windows Defender is benign by image and directory,
  with its evasion line; the benign fixture measures it.
- P-4 (M7.9) The round reads the channel. Where Sysmon is readable, a
  round's inventory is the sample plus the channel's events since the
  previous round began, so a tree that starts, talks, acts and ends
  between two rounds is a tree of that round, marked as seen in the
  channel only. Linux and a Windows host without Sysmon keep the hole,
  said in the watch's first lines and in THREAT_MODEL.
- P-5 (recorded, no rule yet) The person's hands. Text an agent hands to
  a person (the clipboard, a chat, a file) which the person then runs is
  the person's act: it runs under the person's shell, outside every agent
  tree. No timing rule is sound: a pasted burst and a batch file run from
  the same prompt write the same process record. Raqib does not read the
  clipboard's text and will not (section 1 of THREAT_MODEL: Raqib must not
  become a second place where secrets leak). What the record can hold is
  WHO wrote the clipboard: Sysmon event 24 names the process. Candidate
  M7.10: an agent tree that writes the clipboard is a finding of that
  tree (AGENT-CLIPBOARD), the event's header only; where the channel
  holds no event 24 the watch says so once (Raqib never configures Sysmon,
  A4). It waits for the commander's word on whether his Sysmon records
  event 24, and for a real export to measure it on (A6, A7).
- Open, for the commander: what ran in the shell pid 5888 (the unknown
  path's first field firing is on it); the KNOCKS ledger of this run
  against the notification centre.

## Amendment R (the Table, 2026-11-10) - rulings on review 2026-11-10-M7.8.md (416dfa4)
(The letter Q is skipped: Q-n are the builders' questions.) Builder's
record: docs/review/2026-11-10-M7.8-questions.md (Q-1..Q-8). CI run
42877858974 for 416dfa4: six jobs success. Verdict: REDO on R-1, R-2 and
R-3; the Table's rulings R-4..R-10; the rest recorded.
- R-1 (P1, must; C-1d) Benign means not judged, and the tree says so. A
  benign tree gets no source: no os follow, no host lines, no finding, no
  knock; it is listed `benign (not sourced: its acts are not judged)` in
  the report, the state and the page, and HOST-UNWATCHED never judges it.
  A candidate or act-root nested under a benign root is its own tree with
  its own source, as today. The person's own programs under explorer are
  then under no sourced tree, which is what THREAT_MODEL says. Tests: the
  benign desktop with ssh and curl under explorer gives no finding and no
  knock; an agent tree nested under explorer is still sourced and judged.
- R-2 (P17, must; I-3, B-3) An act from before the watch is history. An
  os line whose time is before the watch's start is listed as history on
  its tree, never knocked, never an alarm, whenever its tree was first
  seen (round 1 or later): a shell that became a tree in round 5 does not
  knock for what it ran yesterday. The count of such lines is said per
  tree. Test: a tree first seen in round 3 whose channel past holds a
  listed program from before the start gives a history line and no knock;
  the same program after the start knocks as I-6 says.
- R-3 (P6, must; A6) One act, one finding, one knock. The same os event
  read by two feeds (the same time, tool and input hash) is one finding:
  it is shown on the nearest tree (the feed where the line's depth is
  least), the outer tree lists it as "judged on tree pid N", and it knocks
  once whichever feed delivers it first. Test with the nested fixture.
- R-4 (P2, P11) Quiet says what was seen. A tree absent from the round
  whose root is in the sample is `quiet (its root alive in round N; not
  seen talking with an act at the sample; source kept)` - "source kept"
  only when a source is attached and running, else its real state. In a
  round whose connection record was unread (F-9's blind set) a tree keeps
  the state it had and the round says `not judged this round (connections
  unread)`. README, the help text and THREAT_MODEL use the same words.
- R-5 (P3) The start time decides, where it can be read. The Linux
  snapshot carries each process's start time (optional in the text, so
  every shipped fixture reads as before) and the tree's key and the sample
  use it; where it is unread on either side (old snapshots, Windows with
  the process's times denied) a quiet tree's line ends "start time unread:
  a process of the same image holds the pid" and THREAT_MODEL says the
  hole. With --window S the last snapshot of the window is the sample.
- R-6 (P4; N-1) A quiet tree is a live tree for its footprint: a
  footprint that linked to a tree which is now quiet is linked (the dark
  streak is cleared, the live window runs on); it is dark only when its
  tree is gone. Test: the field run's shape - Kimi quiet for twelve
  rounds - gives no AGENT-DARK-LIVE; Kimi gone gives the M7.5 note, then
  the knock after the window, as N-1 says.
- R-7 (P5, Q-1) The lists are accepted as built, with one change: an os
  process line carries `input_meta.parent_image` (the parent's image in
  the same normalised form; a name, never an argument), and NET-TOOL's os
  branch does not fire on ssh whose parent_image is git: git over SSH is
  git, which the rule leaves out on every source. The evasion line says
  it (an agent that reaches the network through git is not seen, as
  before). certutil, the shells, the cmdlets and the rest stay out for
  the reasons the builder gave. Fixture pair for the ssh-under-git case.
- R-8 (P7, P8, P10, P14, P15, P16) THREAT_MODEL's sentences made true (ss
  on Linux; "no watched process is signalled"; Raqib ends only its own
  helpers); the dropped "ALARMS: 0" check restored in another form;
  PRE_M78_NOTE says what the beat does with an old line; the temporary
  catalog goes to tmp_path; the Defender fixtures' run.json carry
  system_drive so the export itself reads benign; the evasions name wsl
  and a multicall binary.
- R-9 (Q-5; scope widened by this ruling) raqib/rules/catalog/NEW-AGENT.yaml
  and NEW-AGENT-UNKNOWN.yaml gain the P-3 evasion line only. Only msmpeng
  is pinned: the field showed that one (A7); the others wait for a run.
- R-10 Accepted as built: Q-3 (a quiet round writes no closed-connection
  line; recorded with P12 as an under-count of rhythm, the safe side);
  Q-4; Q-6; Q-7 (the sample in inventory.json is pid, image name and start
  time: THREAT_MODEL section 4 names it among what is stored); Q-8 (the
  trailer names the model that built the commit). P9 (the fixture runner
  compares seq numbers only) and P13 (ADR-0002's "now" line: +8 and +7
  after M7.8) are the Table's and are recorded at the judgement. Q-2 (the
  window's word for a quiet tree) is built when M8.1 and M7.8 meet on main.
- R-11 Every REDO change carries a test for the behaviour it adds (D-8).

## Amendment T (the Table, 2026-11-10) - rulings on review 2026-11-10-M7.8-redo.md (45ef2df)
(The letter S is skipped: S-n are the REDO review's findings.) CI run
42886121515 for 45ef2df: four jobs success, both windows gate jobs
failed on one test (os.sysconf, which Windows does not have). R-2, R-5,
R-6, R-7, R-8, R-9 MET; R-1, R-3, R-4 PARTLY. Verdict: REDO on T-1, T-2
and T-6; the Table's rulings T-3..T-9.
- T-1 (S1, must; R-3, I-6) The knock belongs to the act, and is decided
  on the finding as it stands, not on the feed read first. For os lines
  history is one thing only: the event's time against the watch's start
  (R-2); the attach-time rule of I-3 no longer applies to them, so two
  copies of one event always agree. The copies of one act are merged
  first; the entry that stands is on the nearest tree; then it goes
  through I-6 on THAT tree, once: it knocks if that tree's rules say so
  (its FIRST-FINDING if unspent, its own rule if high), whichever feed
  was read first, and it never knocks twice. The notice and the KNOCKS
  row name the tree the finding is shown on. Tests: the outer tree's
  FIRST-FINDING spent and the nested tree's not; each poll order; a copy
  arriving after the knock.
- T-2 (S2, S3, S12, must; R-1 is amended) A benign tree keeps its source,
  and what its acts match is a note. R-1's "no source" made the commonest
  agent of all - one inside an editor or a browser, whose root is the
  benign program - judged by nothing; that trade is taken back. A benign
  tree is sourced like any other. A catalog finding on a benign tree is
  listed on the tree and in the report under "on benign trees (noted, not
  knocked)", counted apart; it is not an alarm, does not change the exit
  code, never knocks and never spends FIRST-FINDING. One act under a
  benign tree and a nearer non-benign tree is the nearer tree's finding
  (T-1). HOST-RHYTHM judges a benign tree as K-10 ruled, and knocks. The
  tree's word is `benign (its acts are noted, not knocked; its rhythm is
  judged)`. HOST-UNWATCHED judges a benign tree as before R-1. Tests: the
  person's ssh under explorer is a note, exit 0, no knock; an agent's
  curl under an editor's own process is a note on that tree; rhythm on a
  benign tree still knocks.
- T-3 (S4; R-2) A clock that steps back does not make acts history. The
  watch keeps its start on both clocks; each round the start is taken as
  the earlier of the wall clock at the start and (the wall clock now
  minus the monotonic time elapsed); a step of more than a round is said
  once as a hole, with its size. THREAT_MODEL says what remains (an act
  in the seconds before the start reads as live after a step: the alarm
  side).
- T-4 (S5; R-5) The Linux key is the kernel's own number: a process's
  start as /proc/PID/stat gives it (ticks since boot), which a step of
  the wall clock does not move; the time shown is computed from it for
  display only. No os.sysconf on a platform that lacks it: the Windows
  jobs run every test.
- T-5 (S9) R-2 judges acts. A silence rule's finding is about Raqib's own
  record during the watch and keeps I-3's rule; the event's time makes
  only a catalog finding history.
- T-6 (S6 and the crash on af808a1, must) No thread outlives its test.
  Every HostWatch a test starts is ended in the test (finish, the
  sources' threads joined, bounded), by a fixture that fails the test if
  a thread named for Raqib is alive after it; the fakes wait on the stop
  they are given, never on a time.
- T-7 (S7, S10) NET-TOOL's evasion says the parent is known by its name
  only, and that git starts ssh with what the agent configures. The act
  key gains the image and the parent image.
- T-8 (S8, S11, S13, S14, S15) The help text and THREAT_MODEL say what
  the code does (the four sentences S13 names; quiet's round and source;
  "not judged this round"); the report's SOURCE FINDINGS line adds up
  with the entries judged elsewhere and the notes on benign trees named;
  the pids whose start time was unread are counted and said once per
  round; the test that asserts nothing asserts something.
- T-9 Recorded for later tasks: a benign program that talks to a model
  endpoint the catalog names is still listed only as benign (a browser
  or an editor hosting an agent: the hole C-1d names); a candidate is
  "a benign host of a model client", listed with that word (M7.11).
  S16's SEVERITY_RANK is the window's, built when M8.1 and M7.8 meet.
- T-10 Every REDO change carries a test for the behaviour it adds (D-8).
- Table ledger so far for M7.8: R-1 was the Table's own trade of an
  alarm for silence, written to cure a false positive (the person's
  programs under explorer) without asking what else has a benign root;
  the reviewer's S2 caught it. A note, not silence, is the cure.

## Amendment V (the Table, 2026-11-11) - rulings on review 2026-11-11-M7.8-redo2.md (e1974cc)
(The letter U is skipped: U-n are the second REDO review's findings.) CI
run 42892952899 for e1974cc: six jobs success. T-3..T-8 MET; T-1 and T-2
PARTLY. Verdict: REDO on V-1; the Table's rulings V-2..V-6.
- V-1 (U1, U2, U3, U4, U5, U6, must) T-1 is restated as a thing that can
  be tested in every order, because two builds of it were right in one
  order and wrong in another. An act is one os event: its key is the
  event's (time, tool, input hash, image, parent image), the same whether
  one half-line of it or both were read. The watch keeps, per act, the
  copies seen (which tree's feed, at what depth) and one fact: whether a
  knock for it was actually SENT. From the copies alone, by one pure
  function: the standing tree is the nearest tree that is not benign,
  and only when every tree that read the act is benign, the nearest of
  those (then the finding is a note). Whenever the copies of an act
  change and no knock has been sent for it, I-6 is asked on the standing
  tree; "not notified" is an answer, not a sent knock, and does not close
  the act. A sent knock closes it: never a second. Everything shown - the
  finding's status, its KNOCKS row, a fold's outcome, "judged on tree pid
  N" on the other trees, the tree that knocked - is read from the act,
  so two lines about one act cannot disagree. An act is never left
  without a word: what a poll cut short (a judge that raised, a Stop) is
  settled by the next poll or by finish, and an entry finish cannot
  settle says so in the report. Test, the one that matters: for two and
  for three nested trees, benign and not, FIRST-FINDING spent and not,
  EVERY order of arrival over separate polls gives the same standing
  tree, the same exit code, the same counts, at most one knock, and a
  knock whenever some order gives one.
- V-2 (U4) A note cannot hide an agent's act: an act is a note only when
  every tree above it is benign. An agent that starts a benign program
  and acts through it has its act on the agent's tree, in every order.
  THREAT_MODEL says both directions.
- V-3 (U7, U8, U9) What is said once is said right: the count of lines
  written before M7.8 is the report's final count; a benign tree's word
  says what happened to it (a knocked act after a round that lost the
  system drive; a rhythm that knocked) and never "not knocked" beside a
  knock; the page lists notes under their own heading; "not judged by
  <id> (off)" and the suppressed count count acts, not copies, and name
  the would-be notes apart.
- V-4 (U11; scope widened for one line) The Linux tree shows its start
  as a time where the tick rate is known, beside the key; THREAT_MODEL
  says what is shown; NEW-AGENT.yaml and NEW-AGENT-UNKNOWN.yaml's "Linux
  /proc gives no creation time" is made true.
- V-5 (U12) The fixture that ends every HostWatch and fails a leaked
  thread serves every test file that starts one (test_host_sources.py,
  test_rhythm.py, test_field_run.py too), from one helper module under
  tests/ (not conftest.py, which M8.1 adds); no fake waits on a time;
  a teardown whose finish raises still stops the rest.
- V-6 (U10) Recorded: the clock-step hole is said again when a later step
  is larger by more than a round; nothing else of U10 needs building.
- V-7 Every REDO change carries a test for the behaviour it adds (D-8).
- Table ledger: R-3 and T-1 were the Table's words, and both described an
  outcome without saying it must hold in every order of arrival; the
  builder built the orders the tests named. V-1 names the property.

## Amendment W (the Table, 2026-11-11) - judgement on M7.8 (416dfa4 + 45ef2df + e1974cc + 7055026)
- V-1..V-6 MET as cited in the "## REDO 3" section of
  docs/review/2026-11-10-M7.8-questions.md. The Table ran the REDO 3
  tests itself (10 passed) and read the registry: an act's key is its
  events; `sent` is set only by a knock really made; _standing is a pure
  function of the copies (the nearest tree that is not benign, else the
  nearest benign one); what is shown is derived when it is shown. The
  test V-1 named runs 416 watches (two and three nested trees, benign or
  not, FIRST-FINDING spent or not, every order of arrival over separate
  polls); on e1974cc's code it failed exactly where the reviewer's U1 and
  U4 said, and it passes now.
- One thing is not as V-1 was worded, and the builder is right: "I-6 is
  asked on the standing tree" alone cannot hold in every order (an inner
  tree whose FIRST-FINDING is spent, read first, would silence an outer
  tree that would have knocked). As built: I-6 is asked on the standing
  tree, then on each other non-benign tree that read the act, nearest
  first; the first that knocks sends it. Which tree's FIRST-FINDING the
  one knock spends still depends on arrival; the number of knocks does
  not. Accepted; V-1 is amended by this line.
- CI, read from api.github.com: 416dfa4 six success; 45ef2df four (the
  os.sysconf test on windows); e1974cc six; 7055026 five, the windows 3.11
  gate failing twice on tests/test_app.py::test_a2_a_watch_stuck_under_
  its_lock..., a test and a file M7.8 does not touch, with "Exception
  ignored in Variable.__del__ ... main thread is not in main loop" beside
  it: Tk Variables left by the Tk tests before it were finalised in the
  watch's worker thread, where tkinter waits a second each, so the
  heartbeat came late. The Table's commit 0c74ade (tests/conftest.py:
  the garbage of a Tk test is collected on the main thread; ADR-0009
  A-16's smallest form, M8.1 brings the whole) - run 42902624296, six
  jobs success.
- Gate on the branch: 2982 passed, 22 skipped; kinds 4 : 7 : 11 (no rule
  added; ADR-0002's note for the two evasion lines is on the branch).
  Scope clean as widened by R-9 and V-4 (one line in each NEW-AGENT
  YAML); raqib/app.py and raqib/rules/hostdata untouched. Four builder
  commits (G-8), three packets, four sets of rulings.
- What M7.8 leaves true: on a host with Sysmon an agent's children are
  judged by NET-TOOL and DESTRUCT-CMD by image name, Windows programs
  included; ssh under git is git; an act from before the watch is
  history; one act is one finding and at most one knock in every order;
  a benign tree is sourced and its acts are notes unless a tree above it
  is not benign; a living tree is quiet, not gone, and live for its
  footprint; Defender's engine is benign in its own directories only; a
  clock that steps back makes nothing history; the Linux key is the
  kernel's start tick; THREAT_MODEL has the host watch's section.
- Still open, recorded: the budgets are a synthetic desktop's (A7: the
  commander's machine is the measurement); the window's word for a quiet
  tree and its severity rank for "judged on another tree" and "noted
  (benign)" (ADR-0009 A-13(d); when M8.1 and M7.8 meet on main); M7.9
  (the round reads the channel), M7.10 (the clipboard's writer), M7.11 (a
  benign host of a model client).
- Verdict: **NEXT**. Merge --no-ff into main under the commander's
  standing word.
- Table ledger for M7.8: three reviews, three REDOs, one CI follow-up by
  the Table. The Table's misses, each caught by a reviewer: R-1 (an alarm
  traded for silence to cure a false positive); R-3 and T-1 (an outcome
  described without the property that it holds in every order); V-5's
  "no conftest.py", which the next commit had to unsay. The lesson kept:
  where a ruling is about order, the ruling names the property and the
  test enumerates the orders.

## Amendment X (the Table, 2026-11-11) - rulings on review 2026-11-11-M7.9.md (000b1bb)
Builder's record: docs/review/2026-11-11-M7.9-questions.md (Q-1..Q-8). CI
run 42911290444 for 000b1bb: four jobs success, both windows gate jobs
failed 3 tests (a `channel=` argument given to a stand-in reader).
Verdict: REDO on X-1, X-2, X-3 and X-5; the Table's rulings X-4, X-6..X-9.
- X-1 (P1 and the CI failure, must) The channel belongs to the live
  reader, not to its caller. Whoever asks for the live reader of a
  Windows host with Sysmon gets rounds that read the channel: the CLI,
  the window (which passes its own reader and is not changed by this
  task), a test's stand-in. What the channel read, could not read, and
  how far behind it is travels with the round's inventory, where the
  watch already reads everything else; no caller passes a channel and no
  stand-in needs to accept one. Its helper is ended with the reader it
  belongs to. Tests: the round a window-style caller gets (a wrapped
  live_reader) reads the channel on win32; the three tests of
  tests/test_host.py pass unchanged on the windows jobs.
- X-2 (P2, must) Two records are one process only when everything read
  agrees: the pid, the image, and the start within the tolerance, the
  start read on BOTH sides; otherwise they are two processes, keyed
  apart, and when a start was unread on a side the tree says so. A root
  carries its OWN ProcessGuid or none. Named as a property and tested by
  enumeration, as V-1 was: for a pid held by one process, by two in
  turn (another image; the same image again), with the event 1 read or
  not, sampled or not, in every order of the records and over one round
  and two - one tree per process, never one for two, never two for one,
  and its source rooted at its own guid.
- X-3 (P3, must; A3) The channel's silence is said. (a) What comes back
  is checked against what was asked: a record whose number is not above
  the bound, or whose time is before the start, is dropped and is a hole
  (the bound was not applied). (b) A process the round's sample shows
  created since the previous round, with no event 1 for it in what the
  channel gave, while the channel has given event 1 before, is a hole:
  "the channel is behind, stopped or cleared" - with the count, each
  round it holds. (c) When the channel's numbers are seen to restart
  (a record numbered at or below the bound by (a), or (b) for three
  rounds) the read starts again from the round's time, said as a hole.
  THREAT_MODEL says the hole is closed only while none of these stands.
- X-4 (P4, P13) The lag has a size: each round that was cut, or that read
  events older than the previous round, says how far behind the newest
  event read is; a tree read late says by how much and is never "back"
  from events older than its going; at Stop the report says the backlog
  left unread. `after` moves only when the round that read is kept (a
  reader that fails afterwards loses nothing).
- X-5 (P5, must; A6, A7) The false positive this task opens is measured
  before it ships, and bounded. Fixtures dated AFTER the watch's start:
  a benign program that starts, talks, writes and ends between rounds
  (an updater; git over https with its credential helper), repeated, and
  a living agent's short-lived child. Ruling on what the measurement
  will show, since each run is a new pid: a brief tree the catalog does
  not name is listed and sourced like any tree, but NEW-AGENT-UNKNOWN
  knocks for its IMAGE once per watch; later brief trees of the same
  image grow that finding ("seen 14 times, last at ...") and are not
  knocked again (C-2 / E-2's rule for a finding that grows). A brief
  tree the catalog names knocks NEW-AGENT each time: a named agent that
  ran is news each time. The budgets are measured with these fixtures
  and the numbers said; C-1b's arrivals are measured again with the
  channel in.
- X-6 (P6) A brief child's act is at its event's time, counted once with
  its os line (the same event), and the "start unread" blind spot is not
  said for a start that was read.
- X-7 (P7; scope widened for one sentence each) Every sentence about
  "between two rounds" says what is true now: README, THREAT_MODEL's
  "what a round sees", the rhythm's first-line hole, and the lines in
  NEW-AGENT.yaml, NEW-AGENT-UNKNOWN.yaml, HOST-RHYTHM.yaml, NET-TOOL.yaml
  and DESTRUCT-CMD.yaml (holes and evasions only; no match is touched).
- X-8 (P8, Q-1) No probe at the start. What the channel holds is learned
  from what the rounds read: a kind not yet read after three rounds with
  the channel is said once ("no event 3 read so far: talk between rounds
  may be unseen"), and the report says which kinds were read. The start
  blocks on nothing.
- X-9 (P9, P10, P11, P12; Q-2..Q-7) The channel's start is the adjusted
  start (T-3). History is one rule for both readers: a tree whose start
  was read and is before the watch's start, or, where no start was read,
  a tree of the first round (B-3); Q-2 accepted in that form, and the
  sampled side follows it. A tree is never replaced in a round without a
  hole. The tests P12 names are written (one knock asserted; a stand-in
  that honours the query; brief then alive; a benign brief tree; a brief
  tree nested under a living one; the helper at Stop). Q-3 (behind, never
  skipping) accepted with X-4; Q-5, Q-7 accepted; Q-6 (a brief tree's
  follow reads the whole channel) recorded for the task that gives
  os_sysmon its ProcessId and a bounded follow (M7.7).
- X-10 Every REDO change carries a test for the behaviour it adds (D-8).
- Table ledger: the HANDOFF said "NOT raqib/app.py" and "a host round's
  inventory", and did not say that the window starts the watch with its
  own reader; the builder wired the channel where only the CLI passes.
  The Table should have named the window's path as the one that matters:
  it is the commander's.

## Amendment Z (the Table, 2026-11-11) - rulings on review 2026-11-11-M7.9-redo.md (da7e007)
(The letter Y is skipped: Y-n are the REDO review's findings.) CI run
42918574979 for da7e007: six jobs success. X-1 and X-8 MET; the rest
PARTLY. Verdict: REDO on Z-1 and Z-2, both of which undo words of the
Table's own in Amendment X; the Table's rulings Z-3..Z-9.
- Z-1 (Y1, must; X-9 is withdrawn where it said more than B-3) History
  is a thing of the first round only, as B-3 and C-4 ruled and the field
  showed. X-9's "history is one rule: a tree whose start is before the
  watch's start" made every process older than the watch history for
  good - an agent that sat idle at the start and acted later would never
  be new. The rule: a candidate of the FIRST round is history, unless
  its start was read and is at or after the watch's start (then it is
  new: it began while Raqib watched). In every later round a candidate
  that was not a candidate before is new, whatever its start (C-4: an
  act-root that becomes a candidate knocks). Tests with starts the live
  reader gives (ISO UTC): an act-root of round 1 that talks in round 3;
  a shell older than the watch that becomes a tree in round 2; the
  existing two tests fed a start the reader can read.
- Z-2 (Y2, must; X-3(b) is restated) Silence is the channel giving
  nothing, not one process without its event. The hole "the channel is
  behind, stopped or cleared" is said when, for three rounds in a row,
  the sample showed processes created at least one full round earlier
  and the channel's reads in those rounds held no event 1 at all, though
  the channel gave event 1 before in this watch; then the read restarts
  (Z-5). One process, or one image, whose event 1 never comes while the
  channel gives others is a NOTE, once per image per watch ("no event 1
  from the channel for <image>: its configuration may leave it out; its
  runs between rounds are not seen"), never a hole, never INCOMPLETE. A
  process is looked for in every read so far, not in this round's alone,
  and only after the channel has had a full round to deliver it. Tests
  through a watch, with fixture times that are true (an event is dated
  before the read that returns it): a healthy channel over ten rounds
  says nothing; a filtered image is a note; a stopped channel is the
  hole in the third round.
- Z-3 (Y3) The channel is read from the making of the reader: the
  reader's own start is taken when it is made (the window makes one at
  each Start and one for the look), not at its first call, so nothing
  between the watch's start and round 1's read is left unread. What is
  older than the watch is history by its time (R-2) and by Z-1.
- Z-4 (Y4, A5) An image is its path where the path was read: the knock
  for a brief unknown tree is once per image PATH per watch (the name
  alone where no path was read, said). The finding says how many runs it
  holds and cites each (A5); the report's line prints "seen N times" and
  the last. NEW-AGENT-UNKNOWN's holes, README and THREAT_MODEL say that a
  second run of the same program is not knocked, and what still is (its
  acts, by the catalog).
- Z-5 (Y5, Y6, Y12; identity and restarts) A ProcessGuid joins a tree of
  an earlier round only when that tree's process is in THIS round's
  sample with the same image, and no event of the guid is older than the
  sampled start; a guid with no start read and no such process is its
  own brief tree. In one round the one-side-unread merge (Q-9, accepted
  as the builder built it) needs uniqueness on BOTH sides, and with the
  sampled start unread it does not merge at all. The enumeration test
  covers two rounds, a sample without a CreationDate, and asserts the
  source's guid. A restart says from when to when nothing was read, and
  does not read a record twice. Reads that return only records older
  than their start for two rounds restart, said.
- Z-6 (Y8, Y11, Y13) No test reaches the live host: live_reader takes
  the Sysmon check as an argument and the six tests that name "win32"
  give a stand-in. A channel leaves OPEN_CHANNELS when its reader's watch
  stops or the reader is dropped; a closed channel starts no helper; a
  reader still out at Stop finds its channel closed. The between-rounds
  note is said once; one Sysmon check decides (the reader's).
- Z-7 (Y7) README and THREAT_MODEL say X-5 and Z-4 (a brief unknown image
  knocks once), X-8 (kinds said after three rounds), Z-3 (the start), Q-9
  (when a guid is merged), and "closed where Sysmon is, while the channel
  is not said to be behind, stopped or cleared"; HOST-RHYTHM's sentence
  is made plain.
- Z-8 (Y9, Y14) The tests Y9 names are written and the three weakened
  assertions restored (NET-TOOL on kimi's tree; no early return; exactly
  one). channel-behind is a hole only when the newest event read is
  older than the previous round by more than one round's length; less
  than that is the log's ordinary delay and is not said.
- Z-9 Recorded: Y10 (the living tree's curl is judged on the code path; a
  test now shows it with a follow that passes); Q-6 and the whole-channel
  follow (M7.7); the 2 s tolerance and whether wevtutil applies the
  query as Python passes it are the commander's machine's to say (A7).
  Every REDO change carries a test (D-8).
- Table ledger: Z-1 and Z-2 are the fourth and fifth time in this run
  that a ruling of the Table's, written to settle a reviewer's finding,
  was itself the next must-fix (R-1, T-1, B-5, X-9, X-3(b)). Each time
  the ruling stated a general rule where the finding needed a narrow
  one. From here a ruling that changes when something knocks, or when a
  watch is INCOMPLETE, names the case it is for and the cases it must
  not touch, and the builder tests both.

## Amendment AA (the Table, 2026-11-11) - rulings on review 2026-11-11-M7.9-redo2.md (a8d1620)
CI for a8d1620 and for e1671ae (merged onto main with M8.1): six jobs
success each. Z-1 and Z-2 MET; the rest PARTLY. Verdict: REDO on AA-1,
AA-2 and AA-3. Each ruling names the case it is for and what it must not
touch (Z-9).
- AA-1 (W11, W6; X-5 and Z-4 are superseded where they said "knocks")
  What the channel alone shows of a program nobody named is listed, not
  knocked - until it is measured. The reviewer's question has no answer
  in the tree: on a real Windows desktop, how many ordinary programs
  connect and start a child between two rounds? Nobody has counted (A6,
  A7), and before M7.9 such a tree was seen only if it happened to be
  doing both at the sample's instant. FOR: a tree the catalog does not
  name that is a candidate ONLY by what the channel gave (it was never a
  candidate at a sample) - brief, or long-lived and seen to talk and act
  between rounds. It is listed with the word `by the channel`, sourced,
  and its acts are judged by the catalog as any tree's (those findings
  knock by I-6); but it is no NEW-AGENT-UNKNOWN finding, no knock, no
  alarm by itself. The report counts them by image path with the last
  five runs' cites ("unknown, by the channel: 14 runs of <path>, last
  at ..."), the state holds the count and those five, never the whole
  list. MUST NOT TOUCH: a tree the catalog names knocks NEW-AGENT each
  time, brief or not; an unknown tree that is a candidate at a sample
  knocks NEW-AGENT-UNKNOWN exactly as before M7.9, and one first listed
  by the channel that is later a candidate at a sample knocks then, once.
  The watch's first lines and THREAT_MODEL say it. The commander's field
  run gives the count; a later ruling decides whether these knock.
- AA-2 (W1, must) The restart Z-5 ruled for a clock that stepped back
  works and is tested: reads that return only records older than their
  start, for two rounds, restart, said. The counter counts.
- AA-3 (W4, must; D-8 and Z-9) Both sides of each rule are tested: for
  the grouping by path - two programs of one name in two directories
  are two groups, and a run with no path read is grouped by its name and
  says so; for the lag threshold - a read less than a round behind says
  nothing; for AA-1 - each of its four cases.
- AA-4 (W2, W5) A process is not new twice when the records tell: a
  guid whose every event lies between a tree's first sight and its last
  sample, with the tree's pid and image, is that tree, whether or not
  the tree's start was read. Outside that span, or with another image,
  it is another tree. MUST NOT TOUCH: Z-5's reuse cases (a pid held by
  two processes in turn stay two trees); the enumeration test grows by
  these cases over two rounds.
- AA-5 (W3, W7, W9) The words say what is closed. README and THREAT_MODEL
  no longer call the between-rounds hole closed: it is "narrowed where
  Sysmon is read", and they say exactly when a stopped or cleared
  channel is said (three rounds in a row, each with a process due) and
  when it is not (a quiet desktop: unsaid, a hole that remains). The
  note for an image without its event 1 reads "left out by its
  configuration, or late", and is withdrawn in the report if the event
  came. THREAT_MODEL's old X-3(b) text goes; history "by its time" is
  said for round 1 only. Scope widened for the two sentences in
  NEW-AGENT.yaml and NEW-AGENT-UNKNOWN.yaml that describe the first round.
- AA-6 (W8) One Sysmon check decides, the reader's: the watch takes
  what its first lines, its sources and its report say of Sysmon from
  the round's inventory. A channel is closed by its watch's Stop and by
  nothing else (no finalizer on another thread); a helper started as the
  channel closes is ended by the close. Tested: a channel leaves the open
  set at Stop; a closed channel reads nothing and starts nothing.
- AA-7 Recorded: W10 (a restart may re-read the records of the span
  between the round's time and its query: a tree in it is "read late",
  never new twice by AA-4); W12 (a step back smaller than a round before
  round 1 is not said); Q-12's two tests (the tree-key hole is not
  reachable by any path found; a benign brief tree is listed benign,
  sourced, its findings notes - a test of it is written now that AA-1
  names the cases); Q-13 accepted with AA-5's words.
- AA-8 Every REDO change carries a test of its case and of what it must
  not touch (D-8, Z-9).
- Table ledger: X-5 ruled a knock "once per image" for a class of trees
  whose number on a real machine nobody knew, and Z-4 refined the key of
  that knock. The reviewer's W11 asked the question that should have
  come first. AA-1 answers it the only way the tree can: show, count,
  and wait for the field.

## Amendment AB (the Table, 2026-11-11) - rulings on review 2026-11-11-M7.9-redo3.md (9f2f665)
CI run 42931681216 for fc37517 (9f2f665 merged onto main): six jobs
success. AA-2 and AA-3 MET; AA-1, AA-4, AA-5, AA-6 PARTLY. Verdict: REDO
on AB-1, AB-2 and AB-3. Each ruling names the case it is FOR and what it
MUST NOT TOUCH, and both are tested (Z-9, AA-8).
- AB-1 (V1, V12, must) The by-the-channel record is derived from the
  trees, never accumulated. A tree is "listed by the channel" from the
  first round it is an unknown, non-benign candidate only by the channel
  (that round is kept on the tree) until it is knocked; the report's and
  the state's count per image path is the number of such TREES, and the
  five kept are the five latest such trees. FOR: one long-lived tree that
  is a candidate only by the channel in every round of a watch is 1, not
  one per round; the 36-order pairs assert the count. A tree that is
  knocked (a candidate at a sample, before or after) is never tagged
  `by the channel`, on the page or anywhere, and is not in the count.
  MUST NOT TOUCH: two runs of one path that are two trees count 2; a tree
  first listed by the channel and later a candidate at a sample knocks
  then, once (AA-1 case 4). `by_channel_text` (written, never read) goes.
- AB-2 (V2, must) Exit 0 stays (AA-1); the words do not lie. FOR: a watch
  whose only news is unknown trees listed by the channel ends with
  "CLEAN: N tree(s) listed, none knocked; M unknown tree(s) seen a
  candidate only by the channel, listed and not knocked (AA-1): <paths
  with counts>", the RESULT line's reason says the same M, and the state
  carries M and that sentence for the window (the Table joins the window
  at the merge; app.py stays out of Scope). MUST NOT TOUCH: with M = 0
  both lines read exactly as before M7.9.
- AB-3 (V6, V7; Q-14 ruled, must) E4 stands: the first lines say the
  hole. The first lines speak from the watch's own check at its start,
  and say that it is that check. FOR: on Linux, and on Windows where that
  check finds no Sysmon, the between-rounds hole is a `hole:` line of the
  first lines, as before M7.9, and a test pins those first lines on each
  platform. Where the reader's check at round 1 differs from the watch's
  own (either way), the round's printed line says so once, with what the
  sources now are; the "sources:" first line is then not left standing
  as the last word. The hole is said once per watch in all (first lines
  or round 1, never both). MUST NOT TOUCH: Windows with Sysmon by both
  checks prints no between-rounds hole and no such round line.
- AB-4 (V3) "No alarm by itself" also means no silence by itself. FOR: a
  tree listed by the channel and not knocked does not make a footprint
  live: the link is shown, `live_key` is not set by it, and the
  footprint's dark streak knocks AGENT-DARK-LIVE at the round it did
  before M7.9. MUST NOT TOUCH: a footprint linked by a knocked tree
  (named, or a candidate at a sample) is live as before.
- AB-5 (V4; A1) The rule says it, not the host code. Scope is widened to
  NEW-AGENT-UNKNOWN.yaml (match, description, holes) and its fixtures.
  FOR: the match carries the by-the-channel condition, so the engine does
  not fire on such a line, the host's `continue` is gone, a rule switched
  off does not count such lines as findings it would have made, and a
  negative fixture holds a by-the-channel line. The hole "knocks once per
  program path" and the description's "never a nothing" are rewritten to
  AA-1. MUST NOT TOUCH: a HostTree line with no by-the-channel key (every
  record written before M7.9, Linux, no Sysmon) is judged and fires as
  before - the existing fixtures pass unchanged, and a test says it.
- AB-6 (V9; Q-15 confirmed with this) `candidate_by` is "sample" exactly
  when the tree is a candidate in the round built WITHOUT the channel's
  records; else "channel". FOR: a talker at the sample whose only sampled
  descendant hangs under a process known from the channel alone is "by
  the channel". MUST NOT TOUCH, as a property over every fixture round
  with a channel: the trees labelled "sample" are the candidates of the
  same round built without it, no more and no fewer.
- AB-7 (V10; AA-4 for W5) The span of AA-4 ends at THIS round's sample
  for a tree whose root is in this round's sample. FOR: a live process
  whose sampled start was not read and whose guid's events come in the
  same round is one tree, in that round and after. MUST NOT TOUCH: Z-5's
  reuse cases stay two trees; a guid whose events begin after the root
  left the sample is another tree. The enumeration (FORMS) grows by the
  case, and AA-4's start-unread side gets its test.
- AB-8 (V11) The note for an image without its event 1 is said per
  episode: after a withdrawal, the next miss of that image is said again,
  and the report's last word on an image is its present state. Any event
  1 of the image withdraws the note (it shows the configuration does not
  leave the image out); the words say "an event 1 of <image> came".
  MUST NOT TOUCH: an image missing in every round is one note, not one
  per round.
- AB-9 (V15) A channel is closed by its owner: a watch's Stop closes the
  channels of that watch's reader and no other; the reader gives a close
  for a single look. The Table calls it from the window at the merge.
  The double end of one helper (a Stop between the registration and the
  closed check) is recorded once. Tested with two open channels.
- AB-10 (V5, V13, V17) Each sentence V5 lists is made true or removed;
  each test V13 lists is written (AA-7's benign brief tree among them;
  the no-path grouping through a round; Q-15's case under AB-6); case 2's
  fixture is what its comment says; agentx_events' second run has its own
  guid. The shape changes outside Windows-with-Sysmon (V17) are accepted
  and said in the builder's record.
- AB-11 Recorded, said in THREAT_MODEL, not built: V8 (the tree ledger
  grows by one entry per by-the-channel tree: a program that runs every
  minute for a day is 1440 entries in the state and the report; a bound
  is a later task, M7.12, because it touches the tree key; TREES SEEN's
  line gets the words `by the channel` now, the window's row at the
  merge); V14 (a pid reused by a process of an image without event 1,
  wholly inside the seconds between a sample and its round's end, joins
  the earlier tree); V16 (an unknown program that repeats as brief runs
  is judged only by its acts: each run is its own tree, so HOST-RHYTHM
  and HOST-UNWATCHED never see the repetition; the count is the trace).
- Table ledger: AA-1 said "counted" without saying WHAT is counted, and
  the build counted sightings; AA-6 said "from the round's inventory"
  for lines printed before any round. A ruling that orders a count names
  its unit; one that orders words names when they are printed.

## Amendment AC (the Table, 2026-11-11) - rulings on review 2026-11-11-M7.9-redo4.md (814a355)
CI runs 42941269218 (814a355) and 42941342463 (merged onto main): six
jobs success each. AB-1, AB-2, AB-3, AB-5..AB-9, AB-11 MET; AB-4 and
AB-10 PARTLY. Verdict: REDO on AC-1 and AC-2. Each ruling names the case
it is FOR and what it MUST NOT TOUCH, and both are tested (Z-9).
- AC-1 (A1, must; AB-4 restated as a property) A footprint's state in a
  round is the state it has in that round with the unknown trees listed
  by the channel and not knocked taken away. So such a tree neither makes
  a footprint live (AB-4) nor takes the link from a tree that would hold
  it. FOR: a footprint that a tree knocked at a sample links, and that a
  by-the-channel tree also links, is linked by the knocked tree and is
  live, whichever of the two has the lower pid - both orders are tested;
  AGENT-DARK-LIVE does not fire. MUST NOT TOUCH: AB-4's own case (the
  by-the-channel tree is the only linker: dark, the knock at the round
  it came before M7.9); a named tree known only from the channel links
  as any knocked tree does. THREAT_MODEL's sentence follows.
- AC-2 (A2, must) README's exit table and the help say what exit 0 is
  now: no knock and no hole; trees listed, and unknown trees seen a
  candidate only by the channel are listed and counted, not knocked.
  "Nothing new" goes wherever it stands beside exit 0.
- AC-3 (A3; Q-19 ruled) History is what the first round's SAMPLE shows
  (with Z-1's exception). FOR: a process older than the watch that is no
  candidate at round 1's sample and is a candidate in round 1 only by
  channel events at or after the watch's start is not history: unknown,
  it is listed by the channel, tagged and counted, and a later candidacy
  at a sample knocks once, as it did before M7.9; named, it knocks
  NEW-AGENT as a named tree by the channel does in any round. MUST NOT
  TOUCH: a tree that is a candidate at round 1's sample is history, with
  or without events of it in the channel; round 1 still reads nothing
  older than the watch's start. Tested with the look's wider first span.
- AC-4 (A5; Q-16 ruled) N-2 holds: a negative the match cannot fire on
  by a field is not a measured negative. The by-the-channel line leaves
  the rule's measured fixtures for the place N-2 gave such lines; the
  measure stays 2 of 5 = 0.4 = fp_budget; the two special cases in
  tests/test_host.py go; AB-5's test reads the line from its new home;
  the budget comment (A12) is as it was.
- AC-5 (A4, A11; Q-18 accepted) The benign brief tree's test asserts its
  note positively (the catalog judged its act, as a note). A run with
  neither path nor name read is called that ("no path and no name
  read"), and AA-3's "grouped by its name" has a case with a real name
  or is said not to be reachable, with the reason.
- AC-6 (A6, A7, A8, A9, A14) Words and fields: the report says the
  between-rounds hole once where the reader's check differs (one note,
  not two); the line names the round in which the reader's check was
  made; the YAML's description says the mark is the key's presence, and
  a test pins that no code writes it false; a state field that is
  written and never read, or goes stale, is updated or removed; the
  count's time is named for what it is ("first listed at").
- AC-7 (A10; Q-17) Scope is widened to the one sentence of
  AGENT-DARK-LIVE.yaml's description that says when a footprint is dark;
  README and the help follow in the same words. That inventory.json
  (discover's own record) still shows the link is said in THREAT_MODEL.
- AC-8 Recorded: Q-20 accepted as built. Q-21 and A13: the Table calls
  the look's close from the window at the merge.
- Table ledger: AB-4 ruled for "a tree" linking "a footprint" and the
  record holds several linkers; the sixth time. AB-6 was ruled as a
  property (the round without the channel) and held. AC-1 is AB-4 in
  that form: where a ruling takes something out of a judgement, it says
  the judgement is what it would be without it.

## Amendment AD (the Table, 2026-11-11) - rulings on review 2026-11-11-M7.9-redo5.md (f5a0da5)
CI runs 42946728174 (f5a0da5) and 42946732057 (merged onto main): six
jobs success each. AC-2, AC-4..AC-7 MET; AC-1 and AC-3 PARTLY. Verdict:
REDO on AD-1 and AD-2. The Table stops ruling this case by case:
- AD-1 (B1, B3, B4, B9; Q-24; supersedes AB-4 and AC-1) M7.9 does not
  change how a footprint is judged. In a round that reads the channel,
  the footprints the watch judges - state, link, live, streak, and so
  every AGENT-DARK and AGENT-DARK-LIVE knock and note - are those of the
  same round built WITHOUT the channel's records (the build AB-6 already
  makes). No tree known or grown only by the channel links a footprint,
  makes it live, or takes a link away: not an unknown one, not a named
  one, not a benign one. `held_link`, the trees "taken away" and the
  inventory's `links` go. FOR, as a property over every fixture watch
  with a channel: its HostFootprint lines, round by round, are the lines
  of the same samples watched without the channel (where the linking
  tree is part of a larger tree in the channel's round, the link names
  that tree). B1's case is dark and knocks at round 3; B3's case stays
  linked and never knocks; a benign brief tree makes nothing live. MUST
  NOT TOUCH: rounds that read no channel; the trees themselves, their
  sources, acts and knocks (NEW-AGENT for a named brief tree still
  comes). What this gives up is said in THREAT_MODEL: a footprint whose
  agent ran only between rounds is judged dark as before M7.9, though
  the tree was seen; joining the two is a later task (M7.12).
- AD-2 (B2; AC-3 narrowed) In round 1, a tree known by its guid whose
  pid and image are those of a tree of that round's sample whose start
  was not read takes that tree's history: they are taken for one
  process. FOR: B2's inputs - the guid tree is history, not tagged, not
  counted, not knocked, unknown or named. MUST NOT TOUCH: AC-3's own
  case (no candidate of that pid and image at the sample: not history),
  with the start read and with it unread. That the two are still listed
  as two trees, in round 1 and in the first round of any tree whose
  start is unread, is recorded with the tree-key task (M7.12).
- AD-3 (B5; Q-22) NEW-AGENT.yaml's first-round sentence is AA-5's
  sentence and in Scope: it says AC-3 and AD-2.
- AD-4 (B6, B7, B8) Words and fields: "the reader's first check", not
  "at round 1", wherever it is said; exit 0 is "nothing knocked, and no
  round or source that could not be read" - the standing holes the first
  lines print do not change the exit, and the table says so; the state's
  `candidate_by` on a tree (written, never read, wrong for an act-root)
  is removed.
- AD-5 Recorded: Q-23 as built (a tree's acts on os lines are history by
  their own time; the reviewer's reading, not the builder's). The
  "no event 11" line (the reviewer's D): it is judged on the whole read,
  so where Sysmon logs no file-create event at all, every os source says
  so and the watch ends INCOMPLETE - as it did before M7.9 (M7.2b); the
  commander's field run says whether his configuration logs event 11.
- Table ledger: AB-4 and AC-1 each tried to say which channel trees may
  touch a footprint, and each left a case; AC-3 moved history and met a
  split the keys already had. The seventh and eighth time. AD-1 is the
  form the reviewer's own table pointed at (AB-6's): one judgement, made
  on one build, with nothing of the channel in it. Where a milestone
  adds a source, what the source may NOT change is ruled first, as a
  property against the build without it.

## Amendment AE (the Table, 2026-11-11) - rulings on review 2026-11-11-M7.9-redo6.md (ede13c3), and the judgement on M7.9
AD-3..AD-5 MET; AD-1 and AD-2 PARTLY. Six REDOs, seven packets. The
reviewer's three must-fixes are of two kinds, and the Table rules them
apart: a wrong SILENCE is closed now; a knock MORE than the watch
without the channel gives, in a case nobody has met outside a
constructed fixture, is said and recorded (A3: where the two differ, the
alarm is the side to err on).
- AE-1 (C1(b), must; the Table's own commit) AD-2 is for a guid with no
  start of its own. FOR: a guid tree whose event 1 the round read, at or
  after the watch's start, beside a sampled tree of its pid and image
  whose start was not read (the pid taken again by the same program) is
  new by Z-1: an unknown one is listed by the channel and knocks at its
  first sample, once. MUST NOT TOUCH: AD-2's own case (B2: no start of
  the guid read: history) - its test is unchanged and passes.
- AE-2 (C3, C8(iv); the Table's own commit) The help says AD-2 beside
  AC-3; `_history`'s docstring says it.
- AE-3 (C1(a); accepted in words) Where the guid lets the watch know one
  process across a start read late, that process is ONE tree and is
  history from round 1: no NEW-AGENT comes for it in a later round (the
  watch without the channel knocks there only because it splits the
  process in two), and by N-1 its link never makes a footprint live, so
  the footprint's dark rounds knock where the split watch would note
  them. This is where AD-1's property yields to AD-2, and it is the
  more exact reading of one process. Said in THREAT_MODEL.
- AE-4 (C2; Q-25 ruled "stands") A sampled program taken for a helper by
  a command line only the channel gives is no act-root in that round;
  the footprint it links by name is not held quiet by it and knocks
  after its dark rounds. A knock more, said in THREAT_MODEL; the holder
  of such a link is the tree-key task's (M7.12).
- AE-5 Q-26 confirmed (the round's read window is one for all its
  lines). Q-27 confirmed: the quiet / kept handling is what the property
  needs and is no rule; C4's one word ("kept" for "quiet" in a round
  partly read) is said in THREAT_MODEL. Q-28 confirmed. C5, C7, C8(i)-
  (iii) recorded for M7.12 with C6, whose wider sentence is now in
  THREAT_MODEL (the live sample reads no command line, so a link whose
  only evidence is in the channel is given up for sampled trees too).
- Judgement: NEXT for M7.9, on six CI jobs green for the Table's commit
  and for the merged branch. P-4 is met as far as this ADR now says:
  where Sysmon is read, a tree that starts, talks, acts and ends between
  two rounds is a tree of that round, sourced, its acts judged; a named
  one knocks; an unknown one known only from the channel is listed and
  counted, not knocked, until the field gives the number (AA-1); history
  is what the first sample shows (AC-3, AD-2, AE-1); footprints are
  judged without the channel (AD-1), with AE-3 and AE-4 said. Not
  reviewed by a fresh reviewer: the Table's own commit (AE-1, AE-2) and
  its commit joining the window (AB-2, AB-9, AB-11 on the merged
  branch); the field run is their review.
- Table ledger for M7.9: eight rulings of the Table became the next
  packet's must-fix (R-1, T-1, B-5 before it; here X-9, X-3(b), AB-4,
  AC-1, AC-3, and AD-2 in part). What ended it was not a finer case
  rule but two things: a property against the build without the new
  source (AB-6, AD-1), and sorting what was left by its direction -
  silence is fixed, a knock more is said. Both go into the session
  protocol's next revision as how a milestone that adds a source is
  ruled from its first packet.

## Amendment AF (the Table, 2026-11-11) - the third field run (docs/review/2026-11-11-third-field-run.md)
The commander's word ("do it") on F1 to F4 of that note. Each ruling
names the case it is FOR and what it MUST NOT TOUCH; both are tested.
Ruled from the first packet as M7.9 taught: a property against the watch
without the source, and what is left sorted by direction.
- AF-1 (F1; silence, so fixed). The property: on the same rounds, a
  watch whose channel was never read makes every finding and every knock
  that the watch on a machine with no Sysmon makes. So while no round of
  this watch has read the channel, a tree's source is the host's own
  record, and its source text says why (Sysmon is there, its channel was
  not read, the reason). FOR: Sysmon registered, the watch not elevated
  (run 1). MUST NOT TOUCH: a watch whose first round reads the channel
  gives its trees the os source in that round, as today; a machine with
  no Sysmon prints the lines it prints today. Said, not fixed (a hole in
  THREAT_MODEL): a read that fails after rounds that read leaves the os
  sources in place.
- AF-2 (F3). The first round whose channel read fails, where the
  reader's check finds Sysmon and no earlier round of this watch read
  it, knocks once (HOST-HOLE, its own rate-limit id) and says one line
  in the terminal: the channel is not read, the reason, and that an
  elevated terminal reads it. Once for the watch while no read is kept;
  a failure after reads that were kept knocks once for that episode.
  FOR: run 1's round 1. MUST NOT TOUCH: no Sysmon on the machine is a
  note, never this knock; the hole of each round is still recorded.
- AF-3 (F2). The report's SYSMON line says what the rounds did: every
  round read - today's words, not a byte changed; none read - present,
  not read in any of N rounds, the first reason, and that every tree
  was judged by the host's own record; some - read in K of N rounds.
- AF-4 (F4). In the text report, the holes of the round's channel read
  whose words differ only by the round's number and time are one line:
  the kind, the rounds as ranges, how many, the words once, the first
  and the last time. The HOLES count is the number of holes, as today,
  and says how many lines hold them. MUST NOT TOUCH: holes of any other
  kind; two reasons are two lines; rounds.jsonl, the state, the result
  and the exit code.
- AF-5 (Q-2). Not ruled: a test states what the watch does today for a
  program the catalog does not name, under a benign tree, that leaves
  its connection to a child; if the child's act is only a note, the
  builder changes nothing and returns it as a question.
- AF-6 Said in THREAT_MODEL and the guide: the channel needs an
  elevated terminal; what an agent without hooks reads with its own
  code is in no source; in the third field run the watched read the
  watcher's record. Q-1 and Q-3 wait for the commander.

## Amendment AG (the Table, 2026-11-11) - rulings on review 2026-11-11-M7.13.md (3c35d06) and the builder's questions
Sorted by direction: silence is fixed, more said is trimmed where it
is cheap, false words are made true. Each ruling names its case and
what it must not touch; both are tested.
- AG-1 (R-1, Q-C; silence, fixed). AF-1's word is "while". The
  property: from the round after the first kept read, a tree is sourced
  as it is in the watch whose every round read. So a tree that has the
  host's record only because no round had read the channel is attached
  again, as the os source, in the first round it is in after a kept
  read; the lines its host record wrote stay judged; an act both
  sources saw is one act (the registry, as for any second source). FOR:
  round 1's read does not return in time (or wevtutil could not be
  run), round 2 on reads. MUST NOT TOUCH: a tree that has the host's
  record for another reason (no Sysmon, its os source ended with a
  hole) keeps it; a watch that never reads keeps AF-1.
- AG-2 (W-1, W-5, question 3). The cause is one of a few words the
  code decides from the reader's error, not its stderr: denied (exit
  5), not back in time, could not be run, other. The elevated terminal
  is named only for denied. The knock's body is the cause word first
  and fits the notifier's cut with the field's longest reason; the
  full reason is in the hole and the terminal line. MUST NOT TOUCH:
  the hole's own words.
- AG-3 (S-1, W-2, question 5). AF-2's one terminal line also says
  that what lives between two rounds is not seen until a round reads,
  and that trees are judged by the host's own record until then and
  attached again after (AG-1). A tree's own attach line and source
  text name the cause in its few words, never the advice and never the
  full reason again.
- AG-4 (W-3, W-4, W-7, the builder's "after record None"). True
  words: the AB-3 note says the sources the trees now get; the CHANNEL
  line of a watch with no read kept is headed by that fact, not by
  "the rounds read", and says nothing of the channel was read since
  the watch's start, never "record None"; the SYSMON line's N is the
  number of channel reads asked, and says so. MUST NOT TOUCH: both
  lines of a watch whose every round read, byte for byte.
- AG-5 (W-6, Q-D). Q-D confirmed inside one episode: a start that
  moves while no read is kept is a time. One folded line per episode
  (a run of failed rounds with no kept read between), so holes before
  the first kept read and holes after a restart are two lines.
- AG-6 (W-8, W-9, W-10). THREAT_MODEL: the watch never checks
  elevation, it reports the denial; who may read the channel is
  Windows' and Sysmon's configuration (administrators on a default
  install). "Every tree" excepts a Claude Code tree with hooks
  attached and a tree with no source. A file's deletion is in no
  source at all (events 23 and 26 are never asked for); a creation
  only where event 11 is read.
- AG-7 (Q-A). The README is not touched: ADR-0010 E-1's eight lines
  stand, and the guide and THREAT_MODEL say it. The guide gets its
  paragraph in "Watch the host", written to AG-1 to AG-6, and the two
  pins are amended with it by the builder: the paragraph's sentences
  join GUIDE_NEW, the paragraph count is 15.
- AG-8 (Q-B, question 6). The Table's word: the header stays
  "HOLES (A3): N"; the line count is the first line under it, only
  when lines were folded.
- AG-9 (question 2). Confirmed: a denied watch with no finding ends
  INCOMPLETE (exit 3), with its one knock. That is the class.
- AG-10 (TESTS). No test reads a file under docs/review (the Table's
  to edit); E2's one terminal line is shown on a watch with trees;
  E3's "never beside 0 kept" is shown on the CHANNEL line too; E4 has
  two episodes as two lines and the moved-start clause.
- Not ruled, for the commander: question 4 (a channel that goes
  silent or restarts mid-watch is a hole and no knock; an agent with
  administrator rights that stops Sysmon looks like that), and Q-2
  (the child of an unnamed program under a benign tree is a note:
  RESULT CLEAN).

## Amendment AH (the Table, 2026-11-11) - rulings on review 2026-11-11-M7.13-redo.md (7921664), and the judgement on M7.13
The packet finds no silence. Sorted by direction: what is more said is
said and left; the false words are made true by the Table's own commit.
- AH-1 (S-1 to S-5, Q-R1 to Q-R4; more said, left). AG-1's "one act"
  is the rhythm's registry: a child the host record wrote and the
  channel gives again can be two source findings of one act, and no
  second knock with the package's rules. A tree attached again reads
  its past as live for the silence and cross-source rules; a Claude
  Code tree tries its hooks again; a tree quiet or gone at the first
  kept read and never in a round again is never read by os; a child
  new in that round is judged as in the watch whose every round read
  (by its event 1). All said in THREAT_MODEL; the keys that would join
  a host line and an os line are M7.12's (the tree ledger).
- AH-2 (W-1, W-5, W-8, W-9). The attach-again words name the round of
  the attach and say only that a round of the watch read, and only on
  a tree that did get the os source; a tree's source text names the
  cause of the round's own failed read; a start that moved is "between"
  its earliest and latest value; the CHANNEL line never ends on a
  dangling phrase.
- AH-3 (CI, windows). Two tests asserted the tick of the real
  monotonic clock (a start that moved by a millisecond on Linux and
  not on Windows). They now accept it there or not, and the clause's
  words are tested on holes whose starts the test gives.
- AH-4 (W-2, W-3, W-4, Q-R5). The guide and THREAT_MODEL: "while no
  read is kept" before the first knock; one line for the holes "whose
  words differ only by the round and its time"; one act "of the tree's
  rhythm"; a later run of failed reads names its cause and no
  terminal (AG-2 as built; a denial after reads that were kept means
  the rights changed under the watch, and the cause word says it).
- AH-5 (W-6, W-7, Q-R6, the builder's REDO-1 and REDO-4). Recorded,
  not built: the questions file's mechanism sentence is the builder's
  and stays as written beside this ruling; SYSMON's "every tree" with a
  hooked tree that also writes host lines; tests of earlier builds
  that read docs/review (a task of its own, with M7.12).
- Judgement: NEXT for M7.13, on the gate and six CI jobs green for the
  Table's commit. What the third field run found is met as this ADR
  says: a watch that cannot read the channel judges its trees as a
  machine without Sysmon does (AF-1), goes back to the channel when a
  round reads (AG-1), knocks once for it with the cause first (AF-2,
  AG-2), and its report says it truly and in one line (AF-3, AF-4,
  AG-4, AG-5). Not reviewed by a fresh reviewer: this commit of the
  Table (AH-2, AH-3, AH-4); the commander's next watch is its review.
  For the commander: Q-1, Q-2 (a note, RESULT CLEAN), Q-3, and whether
  a channel that goes silent or restarts under the watch knocks.
- Table ledger: AF-1 was ruled as a property against the watch without
  the source from the first packet, and the REDO was one, not six. The
  one must-fix was the Table's own word read too narrowly ("while"
  built as "at the attach"): a ruling that names a duration also names
  what ends it.

## Amendment AI (the Table, 2026-11-12) - the watches of 2026-11-12: a tree's follow that never returns
The commander's two watches on main 33427dd. Not elevated: AF and AG
as built (one knock with the cause first, one terminal line, the
host's record). Elevated: the rounds read the channel (17 of 17, events
1, 3, 11 and 22), and every pass of the one tree's os follow was ended
at its 10 s: a follow's pass asks wevtutil for the whole channel, and
his channel holds four weeks. The tree's acts were judged by nothing;
17 holes said so. F1 again, one level down. His word: start.
- AI-1 (silence, fixed). A follow's pass asks a bounded question, as
  the round's read does: the first pass the events since the watch's
  start, each later pass the records after the highest it has read,
  with the round's cap, a cut being a hole. FOR: a channel that holds
  weeks. MUST NOT TOUCH: `raqib os-sysmon` run by a person (the whole
  channel, or --from a file) reads what it read; no event between two
  passes is lost or read twice. Said, not fixed: a tree's past before
  the watch's start is no longer read by its follow (it was history,
  listed and never knocked); a child that started before the watch is
  known to the follow only if the builder can seed it from the round's
  sample - if not, returned as a question.
- AI-2 (the property, as AF-1 one level down). A tree whose os follow
  has had two passes and none that read is judged by the host's own
  record too, from the next round it is in, and its source text says
  so with the cause word; when a pass reads, it is the os source's
  again. A watch with Sysmon never judges a tree by less than the
  watch without it. MUST NOT TOUCH: a tree whose follow reads.
- AI-3 (the Table's own false words, AF-6). "What an agent without
  hooks reads with its own code is in no source" is false: the proxy
  source records the tool call where the agent is pointed at it
  (ADR-0003). The guide and THREAT_MODEL say: in no source of the host
  watch; the proxy has it; the host watch does not read the proxy's
  trace (ADR-0011 decision 5).
- Recorded, not in this build: a process of another account whose
  start time the reader does not read though the system lists it (it
  knocked as new at round 3, four weeks old); the tree ledger's keys.

## Amendment AJ (the Table, 2026-11-12) - rulings on review 2026-11-12-M7.14.md (2b8b746) and the builder's questions
Three silences (R-1 a follow attached again forgets the tree's
children, R-2 a ProcessGuid compared by its letters' case, R-3 a
cleared channel read as nothing forever) and four more behind them in
the questions. Each is a case in which the os source reads less than
the host's own record would, with nothing to say so. AI-2 tried to
detect that case by counting passes; the packet shows the cases are
many. The Table does not rule them one by one (the ledger of M7.9):
the property is made the structure.
- AJ-1 (the property, by construction). Under `raqib watch --host` a
  tree whose source is os also has the host's own record, from its
  attach, as a tree with hooks has had it. The os source adds what a
  sample cannot see; it never stands in for the sample. So a watch
  with Sysmon judges every tree by at least what the watch without it
  does - whatever the follow missed, and whether or not the watch
  knows it missed. AI-2's counting of passes, and its two source
  texts, are withdrawn. FOR: R-1, R-2, R-3, S-3, S-5 and the packet's
  questions 1, 2, 4 and 5, at once. MUST NOT TOUCH: AF-1 and AG-1 (no
  round read the channel: the host's record alone, then os with it); a
  tree with hooks; a tree known only from the channel (not sampled:
  there is no host line to write); HOST-RHYTHM, which counts an act
  two sources saw once.
- AJ-2 (more said, bounded). The price is one act told twice: a child
  in the sample is a HostChild line, and its event 1 an os line, and a
  rule can fire on both. In the report's SOURCE FINDINGS such a pair
  on one tree (the same rule, the same child pid and image) is one
  entry naming both lines, counted once, if that can be done in the
  listing without touching the act registry or a knock; if it cannot,
  the pair stands as two, is said in THREAT_MODEL, and the join is the
  tree ledger's task. No pair knocks twice with the catalog's rules;
  a test says so.
- AJ-3 (one label, by the line). A finding's source is the source of
  the line it cites: a host line of an os tree says host. A tree with
  hooks keeps today's label (recorded with the ledger).
- AJ-4 (the os source itself, fixed where it is small). R-1: a follow
  attached again is given the tree the earlier follow of the same tree
  had found. R-2: a ProcessGuid is compared as _same_guid compares it
  everywhere, and the root's is kept in that one form. R-3: when the
  round's read restarts, every follow's bound restarts with it at the
  restart's time, and the round's restart hole says so. Each with its
  test; none of them is any longer what keeps a tree from silence.
- AJ-5 (words). W-1 to W-6 made true; the kept tree is never pruned
  for the life of a follow (said); the follow's first pass starts at
  the watch's start and the round's read at the reader's own (said;
  not joined here).
- Answered: the builder's questions 2 (AJ-4), 4 and 5 (AJ-1, AJ-3);
  question 1 stays unseen and said, and the host's record now covers
  what a sample shows of such a child; 3, 6: said.

## Amendment AK (the Table, 2026-11-12) - rulings on review 2026-11-12-M7.14-redo.md (9e1aaa1)
The packet: REDO. AJ-1's property fails where the build gave an os
tree its host lines by another road than the host source's own: one
file and one feed for both kinds of line, a history bound of its own
(host_from), the catalog instead of the host's rules, and a skip when
the follow had ended. Every must-fix and most should-fix are places
where that second road differs from the first. The Table's AJ-1 said
"has the host's own record" and did not say how; a property made the
structure must name the structure.
- AK-1 (one road). The host's record of an os tree is the host source
  itself: its own file, its own feed, the host's rules, the same
  history rule as on a machine without Sysmon (the round-1 rule for a
  tree there at the start, a file that restarts) - the code a tree
  with hooks already has for its host lines, not a copy of it.
  host_from is withdrawn. FOR: R-1, S-2, S-3, S-7 of the packet, at
  once. MUST NOT TOUCH: the os feed's own history, as before M7.14
  (the first pass of a tree there at the start).
- AK-2 (R-2). What becomes of an os follow - an error, an end, a pass
  still out - never stops, skips or delays the tree's host lines.
- AK-3 (S-1; a MUST NOT TOUCH of AJ-1, restored). A host line says
  what the round's sample holds: a tree that is not sampled has none,
  and a child or a talk only the round's channel gave is in no host
  line. The changed test (ab10) goes back to what it asserted. If the
  code cannot tell a sampled child from a channel-only one, returned
  as a question.
- AK-4 (W-1; AJ-3 everywhere). The terminal line and the knock's body
  name the source of the cited line, as the listing does: the words of
  a host-line knock are those of the watch without Sysmon.
- AK-5 (S-6). A follow attached again is given the tree the earlier
  follow published at the end of its last finished pass; nothing is
  read from a follow while a pass runs.
- AK-6 (S-4, S-5; said, left). A restart moves every follow's bound to
  the restart's time whether or not the record numbers restarted: a
  child between the old bound and that time is not read by the follow
  (the host's record has what the sample shows of it). A follow
  attached after a restart says in its source text that it reads from
  the restart's time.
- AK-7 (W-2, W-3, question 8). The listing's join stays, with true
  words: "taken for the same act (one image, starts within 1 s)", not
  "the same act"; the guide says the join is the listing's, that the
  window and the state count both, and that the catalog's rules knock
  for the pair at most once.
- AK-8 (TESTS). The property is tested as written: for each case the
  host-line findings of the watch with Sysmon equal those of the same
  rounds without it in rule, tree, child, lines' history, notice,
  knock and terminal words - with a tree there at the start that has
  a child in round 1, a tree's file that restarts, a follow that ends
  in the round of its attach, a tree known only from the channel
  (through the rounds, not an empty call), a follow attached again
  that knows the earlier one's child (through the watch), and a
  restart through the rounds with its hole's words.

