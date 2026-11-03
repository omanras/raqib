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
