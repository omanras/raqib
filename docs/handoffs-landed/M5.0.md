# HANDOFF — M5.0  (phase 5: agent discovery, ADR-0004)

Task: `raqib discover` finds AI agents on a host by what they do - a tree that
talks to a model and acts - with no prior knowledge of their names.

Scope:
  raqib/discover.py (new), raqib/discover/ (new, endpoints.yaml), raqib/cli.py,
  tests/, README.md (one section), docs/specs/ADR-0004-agent-discovery.md, docs/review/

Exit criteria:
- E1 Parsers, text in -> records out, no live host needed: Linux `/proc`
     (cmdline, status ppid, environ keys only, cwd) + `ss -tnp`; Windows
     `Get-CimInstance Win32_Process` (csv) + `Get-NetTCPConnection` (csv) +
     `Get-DnsClientCache` (csv); Sysmon XML events 1, 3, 22. Fixtures: one
     file per parser, captured from a real machine by you (this container
     for Linux; synthetic-but-shaped for Windows, marked as such).
- E2 `raqib/discover/endpoints.yaml`: model hosts + local model ports, `kind: signature`, `evasion:` list.
- E3 Tree anchor: a process with outbound TCP whose tree has "act" children
     (sh, bash, cmd, powershell, python*, node, git) or file writes outside
     its config dir (Sysmon 11 when present) -> candidate, with cited lines.
- E4 Footprint: config dirs and `*_API_KEY` env names (never values).
     AGENT-DARK: footprint on disk, no candidate tree in the window.
- E5 Output: JSON and text inventory; every claim cites record lines (A5);
     an empty result prints the window and records read, never silence (A3);
     suggested source per candidate: hook | proxy | os (ADR-0003).
- E6 Offline, read-only, stdlib-only; no process touched (A4). Gate green on ubuntu + windows.

Not in scope: attaching sources, live Sysmon, rhythm layer (M5.4), UI.
Commit: `landed: M5.0 agent discovery` or `STOP: M5.0 <reason>`.
Read HANDOFF.md and do only the task it specifies.
