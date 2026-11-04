# ADR-0007 - The host, not the name: Raqib watches a machine, not an agent it was told about

Status: proposed (the Table, on the commander's order, 2026-11-03).
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
