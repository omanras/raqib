# HANDOFF — M7.2b  (phase 7: reading sources attach themselves, ADR-0007 decision 3 as narrowed by H)

Task: for every tree the host watch finds, Raqib attaches the sources that only read, without
being told: the os source where Sysmon is, else the host's own record of the tree as a source,
judged by the rules. Hooks attach only with `--attach-hooks` (H-1). A tree with no source is a finding.

Scope:
  raqib/host.py, raqib/hooks/os_sysmon.py (API only), raqib/install.py (API only), raqib/rules/trace.py
  (SOURCES: host), raqib/rules/catalog/ (HOST-UNWATCHED new; NET-TOOL, DESTRUCT-CMD: source host), raqib/rules/
  silence.py (host exemption), raqib/ui.py, raqib/app.py, raqib/cli.py, .github/workflows/gate.yml, tests/, README.md, docs/review/

Exit criteria:
- E1 Per tree, recorded on the tree and in rounds.jsonl: (a) the Sysmon channel exists -> os-sysmon
     rooted at the tree's root pid, in a thread with a Stop, trace under ~/.raqib/host/sources/;
     (b) else the host source; (c) only with --attach-hooks (CLI) or the window's checkbox (off by
     default): a Claude Code tree (claude / claude.exe, or node + cli.js where argv is read) with a
     cwd read outside ~/.raqib gets the `raqib watch` hooks into that project (installer API); no
     cwd or no flag = "hooks: not attached (<why>)" and (a)/(b). Nothing else is written anywhere (A4).
- E2 The host source: per round, per tree, lines of source "host" (SOURCES): tool HostChild with
     command_programs = new children's image names; tool HostConnection with the remote host:port
     (hashes only); gone ones; cited to round and sample (A5). NET-TOOL and DESTRUCT-CMD accept
     source host on command_programs (two YAMLs, fixtures); silence rules skip source host; what
     does not fit is a recorded hole. No host line is labelled Bash.
- E3 HOST-UNWATCHED (anchor, high, YAML + fixtures): a candidate tree with no source after one round. E4 Every source's findings show on the tree (report, page, window: source column, findings by severity) and knock; Stop ends every source thread.
- E5 Tests on fakes for (a), (b), (c) with and without the flag, the host lines, the two rules over
     them, HOST-UNWATCHED +/-, Stop; CI ubuntu + windows: two rounds, every tree has a source or
     HOST-UNWATCHED; kinds 4 : 7 : 10. README: three lines.
Not in scope: rhythm (M7.4), proxy attachment, CROSS-SOURCE over host lines, macOS.
Commit: `landed: M7.2b reading sources attach themselves` or `STOP: M7.2b <reason>`.
Read HANDOFF.md and do only the task it specifies.
