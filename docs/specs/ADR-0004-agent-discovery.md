# ADR-0004 - Agent discovery: find the watched before you know its name

Status: proposed by the Table, 2026-11-02. Becomes accepted when M5.0 lands.
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
