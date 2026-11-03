# HANDOFF — M6.2  (phase 6: dashboard v2, ADR-0005)
Task: the read-only page becomes a live window for `raqib watch`: band,
findings by severity, live silence, several projects, a discover tab.
Binding: ADR-0005 Amendment I / docs/review/2026-11-03-M6.2-ruling.md (I-1..I-12).

Scope:
  raqib/ui.py, raqib/watch.py (serve wiring + registry), raqib/cli.py (--refresh only),
  tests/, README.md (one paragraph), docs/review/, docs/specs/ADR-0005-*.md (A-6 note only)

Exit criteria:
- E1 No script, no external load: the Content-Security-Policy is unchanged;
     liveness comes from `<meta http-equiv="refresh" content="N">` with N
     from `--refresh` (default 5). A test asserts the CSP and the absence
     of `<script`.
- E2 Status band at the top: WATCHING / SILENT for N s / AGENT GONE /
     CAPTURE FAILED, notifications on|off, trace path, last line time.
- E3 Findings first, grouped by severity, each with its cited lines as now;
     open silence windows drawn live in the timeline.
- E4 Several `watch` processes register in `~/.raqib/watches.json` (pid,
     project, port, trace); the page links the others; stale entries (pid
     gone) are shown as GONE, not dropped (A3).
- E5 Discover tab: when `<trace dir>/discover.json` exists (from
     `raqib discover --json`), render its candidates, holes and cited lines
     with the same escaping rules as the trace view.
- E6 Every value from trace, inventory or registry escaped and stripped of
     control characters; tests with hostile strings. Gate green ubuntu + windows.

Not in scope: control actions, remote access, authentication, tray icon.
Commit: `landed: M6.2 dashboard v2` or `STOP: M6.2 <reason>`.
Read HANDOFF.md and do only the task it specifies.
