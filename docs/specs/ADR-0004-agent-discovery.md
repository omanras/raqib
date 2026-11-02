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
