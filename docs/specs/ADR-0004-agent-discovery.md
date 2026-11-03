# ADR-0004 - Agent discovery: find the watched before you know its name

Status: accepted (M5.0, 2026-11-02; Amendment E). Proposed 2026-11-02.
Amendments appended, never edited in place.

## Problem
ADR-0003 adds capture sources, but each one still has to be pointed at an
agent the commander already knows: a hook for Claude Code, a proxy for a
CLI whose base URL is configurable, an os source for a process tree whose
root PID someone typed. A new agent on a machine - installed yesterday,
never heard of - is watched by nobody. The commander's requirement
(2026-11-02): a general mechanism that finds AI agents on a host without
prior knowledge of them.

## Decision
An agent is recognised by what it does, not by what it is called:

> a process tree that talks to a model and acts on the machine.

No browser does the second, no editor does the first; only an agent does
both, in turn. `raqib discover` reads the host's own records of the two
and reports every tree that shows both, with evidence per line (A5). It
is offline, read-only, stdlib-only, and never touches a process (A4).

Four layers, deterministic, from cheapest to deepest; the kinds follow
ADR-0002:

1. **Endpoints (signature).** Outbound connections from a process to a
   known model endpoint or local model port. Names come only from records
   the host already holds (Windows DNS client cache, Sysmon event 22;
   Linux: none offline in M5.0 - a recorded hole); remote IPs and ports
   otherwise. The list of endpoints and ports lives in one YAML with an
   `evasion:` block: private endpoints, tunnels, local models on odd
   ports.
2. **Process tree (anchor).** A process with open outbound TCP that has
   children of the "act" kind (shells, interpreters, git, editors in
   batch mode) or that writes files outside its own config directory.
   Talks + acts in one tree is the agent signature that needs no name.
   The OS writes this record; the agent cannot move it.
3. **Rhythm (anchor, later: M5.4).** Large periodic POST bodies to one
   destination interleaved with process creation: the think-act cycle,
   visible from sizes and times alone, no decryption. Thresholds, not a
   model. Deferred: it needs a traffic record (Sysmon 3 over time or a
   pcap) that M5.0 does not read.
4. **Footprint (signature, supporting).** Known config directories
   (`~/.claude`, `~/.kimi`, `~/.codex`, `~/.gemini`, `~/.cursor`,
   `~/.aider*`), MCP config files, `*_API_KEY` in a process environment.
   Supporting evidence only; and one finding of its own (A3):
   **AGENT-DARK** - an agent footprint on disk with no tree showing
   activity in the window. An installed, silent agent is a finding, not
   nothing.

Output: an inventory, JSON and text, one entry per candidate tree: root
PID and image, children of the act kind, endpoints or remote addresses,
first and last seen, footprint matches, and the record lines behind each
claim. "No agent seen" is said explicitly with the window and the records
read; an empty inventory is never silent.

Hand-off to sources (ADR-0003): a candidate whose image is Claude Code ->
hook; one whose CLI documents a base-URL setting -> proxy; any other ->
os source rooted at its PID. M5.3 takes `--root` from `discover` instead
of from the commander.

## Consequences
- New module `raqib/discover.py` and CLI `raqib discover [--window S]
  [--json]`. No network. Reads: `/proc` and `ss -tnp` on Linux;
  `Get-NetTCPConnection`, `Get-Process`/`Get-CimInstance Win32_Process`
  and `Get-DnsClientCache` output on Windows; Sysmon .evtx/XML when given.
  Each reader is a parser over text, so fixtures are text and tests need
  no live host.
- One catalog file `raqib/discover/endpoints.yaml` (signature, with
  evasion) is the only thing an adversary can read and route around; the
  tree anchor still holds.
- First field test: the commander's Windows machine with Kimi installed,
  with no prior knowledge of Kimi fed to the tool.

## Candidates
- M5.0 discover: layers 1, 2, 4; inventory; AGENT-DARK; Linux + Windows
  text parsers; fixtures. Lands before M5.2 and M5.3.
- M5.4 rhythm (layer 3) once M5.3's os source gives a traffic record.

## Amendment A (2026-11-02) - as built in M5.0 (builder's record, not a ruling)
What M5.0 built, so the review can hold the tree to it. The open design
points are questions in `docs/review/2026-11-02-M5.0-questions.md`, not
settled here.
- A-1 Readers are parsers over text (`raqib/discover.py`): `proc.txt`
  (JSON lines written by `snapshot_proc` from /proc status PPid and Name,
  cmdline, environ NAMES only, cwd), `ss -tnp`/`-tanp` text, the
  Win32_Process, Get-NetTCPConnection and Get-DnsClientCache CSVs, Sysmon
  XML events 1, 3, 11 and 22, and a footprint listing (one path per line).
  `--from DIR` reads them by file name; a live run reads Linux /proc and
  `ss -tanp`. `-a` is there so listening sockets give the direction. `--save DIR`
  keeps the texts, so every cited line can be checked again (A5). Windows
  is read from exported files only in M5.0.
- A-2 Talks: a connected TCP socket that is outbound. That is Sysmon 3
  `Initiated`; otherwise the local port is not a listening port in the same
  text; with no listening sockets, the local port is above the remote one
  (recorded per connection as `basis`, and as a hole).
- A-3 Acts: a process whose image is sh, bash, dash, zsh, ksh, fish, cmd,
  powershell, pwsh, python*, node or git, attributed to its nearest talking
  ancestor; or a Sysmon 11 write by the talker's tree outside config space
  (a dot-directory, AppData, ProgramData, a temp directory, or the
  writer's own program directory). A talker with an act is a candidate. A
  candidate below another is reported `inside` it. The reader's own pid
  and its children are never evidence.
- A-4 The catalog is checked as a signature (`kind: signature`, a
  non-empty `evasion:`). Hosts match only names the host recorded (DNS
  cache, Sysmon 22, Sysmon 3 DestinationHostname). Networks match by IP.
  Ports match on loopback only. Footprints are home-relative paths with
  the program name an agent runs as. A footprint links to a candidate by
  that name or by its path in the tree's argv or cwd. With no linked
  candidate it is AGENT-DARK, but only when a process source and a
  connection source were both read. Without them it is "unjudged", not
  dark.
- A-5 Hand-off: hook when the root runs as claude (also npm
  `claude-code`). Proxy when the root's or a talking ancestor's
  environment names `*_BASE_URL` or `*_API_BASE`. Otherwise os, rooted at
  the root pid.
- A-6 Result and exit as in `raqib report`: alarm (1) for a candidate,
  AGENT-DARK, an unread line, or nothing read. Incomplete (3) when no
  process or connection source was read, or a source failed. none-seen (0)
  otherwise, and printed as "NO AGENT SEEN in window ... Not a clearance".

## Amendment B (the Table, 2026-11-02) - rulings on review 2026-11-02-M5.0-review.md
- B-1 (D4) The connection record on Linux is read from `/proc/net/tcp`
  and `/proc/net/tcp6` first - a kernel file no PATH can replace - with
  socket inodes joined to pids through `/proc/<pid>/fd`. `ss` is a
  fallback only, invoked by absolute path from a fixed list
  (/usr/sbin/ss, /usr/bin/ss, /sbin/ss, /bin/ss) with a minimal
  environment, never by PATH lookup; the path used is printed in the
  inventory. E6 test forbids any subprocess call with a bare program
  name. This restores the claim at line 39.
- B-2 (D1) Exit 3 (incomplete) whenever any read of a process or
  connection source failed, returned no record, or left talking lines
  without an owner; "none-seen" with exit 0 only when every source was
  read, had records, and every talking line had an owner. The text and
  JSON say which condition held.
- B-3 (D2) Every read failure is a hole in the inventory: proc meta counts
  flow into holes; pid 2 is dropped only when /proc/2/status says
  kthreadd; footprint scan notes become hole records, not `#` lines.
- B-4 (D3) The holes text names, every run: liveness (acts seen only while
  alive at a snapshot), sibling talkers, reparented acts, TCP only, one
  network namespace / hidepid. endpoints.yaml `evasion:` gains QUIC/UDP,
  unix-socket relays, reparenting, sibling split. README states them.
- B-5 (D5) README wevtutil export gains `/rd:true`.
- B-6 (D7) The act-name list is a signature: it moves to endpoints.yaml
  under `acts:` with its own `evasion:` (rename-by-copy, custom shells,
  interpreters not listed); the anchor is "talks + has a child", the
  name list only labels the child.
- B-7 (D15) Amendment A-1 (-tanp as live default, -tnp parse kept) and
  A-2 (outbound inference) are ratified. A-5 is rejected: `proxy` is
  suggested only for a root image the catalog marks `proxy_capable`;
  otherwise `os`; `hook` for Claude Code only when the image is a CLI,
  not Claude Desktop (Q-6) - mark by image path containing "claude-code"
  or argv showing a CLI flag; else `os`.
- B-8 (D6, A6) discover declares no fp_budget in M5.0; README says plainly
  that IDE terminals, package managers and CI runners can be candidates,
  and that loopback talk counts. A budget is set from the first field
  runs (M5.4), not guessed.
- B-9 (D14) The REAL Linux fixture is redacted: the `--session` value and
  the scratchpad path replaced by fixed placeholders, header says "REAL,
  identifiers redacted"; environment NAMES stay (they are the point of the
  footprint layer and are not secrets). The capture script joins the tree
  under tests/fixtures/discover/linux/ (D13).
- B-10 (Q-4) The field test on the commander's Kimi machine runs with
  `--catalog` pointing at a copy of endpoints.yaml with the `.kimi`
  footprint removed, so the result rests on the anchor alone.
- Notes D8-D12, D16, D17: D8 and D12 fixed as text in README/holes; D17
  negatives added where cheap; the rest recorded.

## Amendment C (2026-11-02) - the M5.0 REDO as built (builder's record, not a ruling)
Where Amendment B changed Amendment A, B holds. A-3 and A-5 are superseded
by B-6 and B-7, and A-1's live reader is now /proc/net/tcp first. Open
points from the REDO are Q-R1..Q-R5 in `docs/review/2026-11-02-M5.0-questions.md`.
- C-1 A new source, `proc-net.txt`, holds /proc/net/tcp and tcp6 as the
  kernel prints them. `proc.txt` gains `sockets`, the inodes from
  /proc/PID/fd, which build() joins to owners. `ss` runs only for a
  sample whose /proc/net/tcp could not be read, and only by a path from
  SS_PATHS, with env `{LC_ALL: C}`. The inventory's `connections_from`
  names the texts read.
- C-2 `complete` is true only when every process and connection source
  was read in every sample, held its kind of record, and left no talking
  line without an owner and no talking pid without a process record.
  none-seen (exit 0) requires it.
- C-3 Lines that start with `!hole` in proc-net.txt and footprints.txt,
  and the snapshot's counts in proc.txt, become holes citing their line.
  kthreadd is matched by pid 2's status Name.

## Amendment D (the Table, 2026-11-02) - rulings on review 2026-11-02-M5.0-REDO-review.md
- D-1 (R1) Sysmon is complete as a process source only with at least one
  event 1, and as a connection source only with at least one event 3;
  otherwise incomplete (exit 3) with a hole naming the missing event id
  and "Sysmon without -n logs no event 3".
- D-2 (R2) Only ENOENT on /proc/net/tcp6 is a hole ("no IPv6 table");
  any other OSError on tcp or tcp6 is a source error (exit 3).
- D-3 (R3) A readlink failure on any fd is a hole citing the pid; the
  process record then carries `"sockets": null` (unknown), never `[]`;
  cwd and cmdline failures are holes too. Fixture pid 1 must show null.
- D-4 (R4) --save writes a `run.json` with each source's error, the
  connections_from path, and the live holes; --from reads it, so a
  replay of an incomplete run is incomplete and the ss path survives.
- D-5 (Q-R2, R12) Hand-off criteria move to endpoints.yaml under
  `handoff:` with `evasion:` lists, loader enforced: `hook` for a root
  image named claude / claude.exe unless its path matches a listed
  Claude Desktop pattern (AnthropicClaude, Claude.app, claude-desktop);
  `proxy` for proxy_capable images; else `os`. Record: a hook suggested
  for an image that offers no hooks is a signature miss, and `os` still
  watches the tree, so the error is safe-side.
- D-6 (R13) Redact `shell-snapshots/snapshot-*` basenames in the REAL
  fixture to a placeholder; add to capture.py's TOKEN and the test.
- D-7 (R8, R15) Footprint link order recorded here as ratified. The ADR's
  line 20 sentence is superseded by B-6: browsers can be candidates; the
  anchor is wider than the agent on purpose, and the budget comes from
  the field (B-8). Amendment A stays where it is; future amendments
  append after the last.
- D-8 (R7, R9, R10, R11, R16) R7: inode-0 states named in the unowned
  hole and the "opened between snapshots" reason added. R10: --from with
  both proc-net.txt and ss.txt uses proc-net only and notes ss.txt was
  ignored. R11: README and yaml wording fixed. R9, R16: recorded.

## Amendment E (the Table, 2026-11-02) - judgement on d688ff2 (REDO 2)
The Table read the D-1, D-2 and D-5 code paths and the yaml `handoff:` block
itself and takes the builder's cited lines for D-3, D-4, D-6, D-8 after two
independent reviews of the same tree.
- D-1..D-6, D-8 MET as cited; D-7 recorded. Q-R6 (ENOENT skipped only for
  the reader's own /proc/self/fd race) is agreed and recorded here.
- CI for d688ff2, read by the Table from api.github.com: run 41474296355
  success; ubuntu 3.11/3.12 and windows 3.11/3.12 all success. Local gate
  900 passed, 4 skipped. Scope: no file outside HANDOFF M5.0.
- Status of this ADR: **accepted (M5.0, 2026-11-02)**. Lines 1-80 are the
  decision; amendments A-E are the record of how it was built and ruled.
- Verdict: **NEXT**. Merge --no-ff into main under the commander's standing
  word of 2026-11-02 ("افعل وطبّق").
- Field test next: the commander's Windows machine with Kimi installed,
  `raqib discover --catalog <copy without the .kimi footprint>` (B-10),
  Windows exports per README, exit code and inventory recorded in
  docs/review as the first measurement for an fp_budget (B-8).
- Table ledger for M5.0: ADR-0004 line 20 overclaimed (D-7); the handoff
  criteria were left to code in B-7 and had to move to the catalog in D-5;
  two REDO rounds, both from reviewers, none from the Table's own reading.

## Amendment F (2026-11-03) - M5.0b as built (builder's record, not a ruling)
What M5.0b built after the Kimi field test (field note
2026-11-02-field-note-kimi-discover.md), so the review can hold the tree to
it. Open points are questions in `docs/review/2026-11-03-M5.0b.md`, not
settled here.
- F-1 Windows window (E1). The README export is a PowerShell loop of `$N`
  samples `$T` seconds apart (6 and 10), one file per kind and sample:
  `win-process-<k>.csv`, `win-tcp-<k>.csv`, `win-dns-<k>.csv`. It writes a
  `run.json` first, `{"raqib": "discover-run", "version": 1, "export":
  "windows", "samples": N, "seconds_apart": T}`. A sample is a source of its
  own, named like its file (`win-tcp-2`), so every cite names the file it
  is in (A5). The samples are merged by pid, as the Linux window merges its
  snapshots, and a "window merge" hole says a reused pid joins two
  processes. Every sample 1..N needs its process and connection file: a
  missing one is an unread source, a hole and incomplete (exit 3), never
  skipped (A3). N comes from run.json; without one, from the highest sample
  found, and a hole says a loop cut short is then not seen. `--save`'s
  run.json records the sample count too. The M5.0 single files are read as
  before.
  Note (2026-11-03, M5.0b REDO, G-5; corrects this item): a missing sample
  makes the run incomplete (exit 3 unless an alarm); alarm > incomplete
  stays the precedence of M5.0.
- F-2 Recent talk, owner unknown (E2). A TIME-WAIT row with no owner
  (OwningProcess 0; inode 0, so no pid) to a catalog endpoint - by network,
  loopback port, or a name the host's own DNS record gives that IP - and a
  DNS cache row (no pid) for a catalog host whose IPs no known owner talks
  to. One line per remote, or per host name for a DNS row alone, with cites.
  Never a candidate or an act-root, and no alarm. The liveness hole, said
  every run, now names connections and recent talk.
- F-3 Act-root (E3), a signature in the catalog's `act_root` block (kind,
  evasion, fp_budget 0.25, user_dirs, shells, not_images, fixtures; the
  loader enforces them). A process P is an act-root when its image path
  (Windows ExecutablePath; Linux argv[0]) matches a user_dirs glob, none of
  its images is a listed shell or system image, it has a listed shell as a
  child with a command (a process that is no listed shell) below that
  shell, and P owns no talking connection in any sample read. The reader's
  own tree is never evidence. Exit 1, with the same cites as a candidate's
  acts, and the candidate its acts go to. Talk in any sample makes P a
  talker, so it is a candidate instead (the merge); recent talk never does.
  Act-roots are judged only when a process and a connection source both
  hold records; otherwise a hole says they are not judged. A footprint
  links to an act-root (after a candidate whose root has the name), so an
  acting agent's footprint is not AGENT-DARK.
- F-4 `raqib discover --check [--fixtures-root DIR]` (E4) runs every
  fixture the act_root block names: a positive must show its act-root, or
  its program promoted to a candidate; a negative is a benign export. A
  negative is measured when complete or when the class fired on it. Exit 1
  when act-root is over its budget, a positive is missed, or nothing is
  measured. Candidates are counted on the same negatives; the anchor
  declares no budget (B-8). First numbers: act-root 0 of 2, candidates 2 of
  2.
- F-5 Fixtures (E4, E5) are synthetic, made by
  `tests/fixtures/discover/synthetic.py` and held to it by a test, each with
  the B-9 redaction note: `kimi/one-sample`, `kimi/two-samples`,
  `benign/linux-desktop`, `benign/windows-desktop`. The catalog lists the
  Moonshot hosts (api.moonshot.ai, api.moonshot.cn, api.kimi.com) since the
  blind field test has run; a blind run uses a catalog copy, as B-10 did.

## Amendment G (the Table, 2026-11-03) - rulings on the M5.0b review (02958eb)
- G-1 The benign set holds the realistic IDE-terminal cases; act-root
  narrows: parent is a shell or terminal host, no `--type=` helper as root
  or hop, first hop a shell, command outside the root's tree.
- G-2 Linux placement by /proc/PID/exe with argv[0] fallback; unreadable
  exe counted in a hole; a Linux positive added.
- G-3 Recent talk alone ends INCOMPLETE (B-2). G-4 blank image paths are a
  hole. G-5 exit precedence stays, docs say "unless an alarm". G-6 pid +
  CreationDate keys a process. G-7 evasions listed. G-8 `status` carrier
  for act_root. G-9 ui.py discover tab in Scope. G-10..G-14 as in
  docs/review/2026-11-03-M5.0b-ruling.md.

## Amendment H (2026-11-03) - the M5.0b REDO as built (builder's record, not a ruling)
Where Amendment G changed Amendment F, G holds. The record of each G-n,
with file:line, is in `docs/review/2026-11-03-M5.0b.md`.
- H-1 (G-1) act_root gains `launchers` and three conditions: the root's
  own parent is a listed shell or launcher; no process with `--type=` in
  its argv is a root or a hop below the root's shell; the command's image
  is not under the root's own directory. The benign set now holds VS
  Code's terminal running powershell -> node (Windows) and a JetBrains IDE
  under ~/.local whose terminal runs make -> cc (Linux); both measure 0.
- H-2 (G-2) snapshot_proc writes `exe` (the /proc/PID/exe link, null and
  in `unread` when it cannot be read); parse_proc places a process by it,
  argv[0] the fallback; a hole counts the unplaced. Positive:
  tests/fixtures/discover/linux-agent.
- H-3 (G-3, G-4, G-6) recent talk with no candidate and no act-root is
  incomplete; a blank Windows image path (pids 0 and 4 aside) is a hole;
  a Windows process is keyed by pid and CreationDate while the tree is
  built, a reused pid is named in a hole, and the inventory shows OS pids.
- H-4 (G-8) act_root `status: ok | disabled`; disabled judges nothing in
  an inventory (a hole says so) and is still measured by --check, whose
  positives need the image name and a cited SRC:LINE.
- H-5 (G-9, G-10, G-11) the dashboard's discover tab renders act-roots
  and recent talk with their cites; `~/*` left user_dirs; the Sysmon
  export has its own README paragraph; the merged-beside hole is decided
  in build(), so --read files count; the Moonshot hosts carry a comment,
  no note fields.

## Amendment I (the Table, 2026-11-03) - judgement on M5.0b (02958eb + 92d0413)
- G-1..G-14 MET as cited; the Table read `_act_roots` (parent in
  launchers, no `--type=` helper, command outside the root's tree) on the
  branch; --check: act-root 3 of 3 positives found, 0 of 2 realistic
  negatives fired; candidate anchor 2 of 2 benign desktops (no budget, B-8).
- CI runs 41576116481 and 41579737381 success on six jobs each (read from
  api.github.com); gate 1701 passed, 7 skipped; scope clean (widened by
  G-9); fixture leak grep clean (no real IP, user or host).
- RR-1..RR-8 accepted; RR-8 (co-author line) is the serving model's.
- Verdict: NEXT; merge --no-ff under the commander's standing word.
- Open for the field: a second blind run on the Kimi host with the sample
  loop and a catalog copy without the Moonshot hosts and the `.kimi`
  footprint (B-10), to see whether act-root names kimi by shape alone.
