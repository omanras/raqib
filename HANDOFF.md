# HANDOFF — M5.3  (phase 5: os source from Sysmon + CROSS-SOURCE anchor)
Task: add the `os` capture source from Sysmon on Windows (ADR-0003) and the
first rule that reads the gap between what was asked and what happened.
Scope:
  raqib/hooks/ (new os_sysmon.py; common.py reuse), raqib/cli.py (os-sysmon subcommand),
  raqib/rules/trace.py, raqib/rules/catalog/, raqib/rules/engine.py, raqib/report.py (ids),
  tests/, README.md, docs/THREAT_MODEL.md, docs/specs/ADR-0002-rule-kinds.md (note under
  the table), docs/specs/ADR-0003-capture-sources.md, docs/review/
Exit criteria:
- E1 `python -m raqib os-sysmon --root PID --log PATH [--from FILE.xml]`: reads
     Sysmon events 1, 11, 3 for the tree under PID (live: the operational
     channel through `wevtutil qe` by absolute path, read-only; `--from`: an
     exported XML, offline). Each event -> `pre`+`post`, `source: "os"`, tool
     `process` | `file` | `net`, hashes of command line / path / destination,
     input_meta via common.py (program names only). Never the arguments.
- E2 Fixture: a synthetic Sysmon XML in the shape discover.parse_sysmon already
     reads (user `user`, host `host`, documentation IPs); parsing tests on it.
     The real export under the default config is the commander's field test.
- E3 CROSS-SOURCE (anchor, high): with proxy/hook and os records in one window,
     a `pre` for a shell tool with no os `process` within W seconds, or an os
     `process` whose program is in no shell `pre` within W. W declared in the
     rule (default 10 s); unknown when either source is absent (A3 note, never
     a finding). Fixtures: asked-not-done, done-not-asked, matched (negative).
- E4 Gate kinds line anchor=4; README counts 13 rules, row added; the ADR-0002
     table note gains the row; THREAT_MODEL: os records are the only ones the
     agent does not write, and what they still miss (in-process actions,
     memory-only tools, Sysmon config gaps). Gate green ubuntu + windows.
Not in scope: Linux os source, blocking (A4), UI beyond the source tag.
Commit: `landed: M5.3 os source + cross-source` or `STOP: M5.3 <reason>`.
Read HANDOFF.md and do only the task it specifies.
