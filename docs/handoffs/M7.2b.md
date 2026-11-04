# HANDOFF — M7.2b  (phase 7: sources attach themselves, ADR-0007 decision 3)

Task: for every tree the host watch finds, Raqib attaches what it can without being told: hooks
for a Claude Code tree, the os source where Sysmon is, else the host's own record of the tree as
a source, judged by the rules. A tree with no source is a finding.

Scope:
  raqib/host.py, raqib/hooks/os_sysmon.py (API only), raqib/install.py (API only), raqib/rules/trace.py
  (SOURCES: host), raqib/rules/catalog/ (one YAML), raqib/ui.py, raqib/app.py (per-tree source), raqib/cli.py,
  .github/workflows/gate.yml, tests/, README.md, docs/review/

Exit criteria:
- E1 Attachment per tree, in order, recorded on the tree and in rounds.jsonl: (a) image is Claude
     Code (claude / claude.exe, or node running cli.js where argv is read) and its cwd is a directory
     outside ~/.raqib -> the `raqib watch` hooks into that project (installer API; trace outside the
     project); no cwd (Windows) = hole, next; (b) the Sysmon channel exists -> os-sysmon rooted at
     the tree's root pid, in a thread with a Stop, trace under ~/.raqib/host/sources/; (c) else host.
- E2 The `host` source: each round writes, per tree, lines of source "host" (SOURCES in trace.py):
     new children (image names as command_programs), new connections (remote host:port, hashes
     only), gone ones; cited to round and sample (A5). The existing rules run over them where their
     fields fit (NET-TOOL, DESTRUCT-CMD by programs; the SILENCE rules per tree), CROSS-SOURCE
     where hooks and host overlap; what does not fit is a recorded hole, not silence.
- E3 HOST-UNWATCHED (anchor, high, YAML + fixtures): a candidate tree with no source after one round - seen but unjudged is a finding.
- E4 Every source's findings show on the tree (report, page HOST section, the window's table: a source
     column, findings by severity) and knock as today; Stop ends every source; nothing signalled or written to a tree (A4).
- E5 Tests on fake trees/readers for (a), (b), (c), the host lines, the rules over them, HOST-UNWATCHED
     +/-, Stop ending sources; CI ubuntu + windows: two rounds, every tree has a source or HOST-UNWATCHED. README: 3 lines.
Not in scope: rhythm (M7.4), proxy attachment, other new rules, macOS.
Commit: `landed: M7.2b sources attach themselves` or `STOP: M7.2b <reason>`.
Read HANDOFF.md and do only the task it specifies.
