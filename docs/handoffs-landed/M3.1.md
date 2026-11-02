# HANDOFF — M3.1  (phase 3: minimal read-only web UI)

Task: a minimal read-only view of one trace (DEVELOPMENT_PLAN M3.1):
timeline, findings and silence windows. `python -m raqib ui TRACE -o FILE`
writes one static HTML file; `--serve` shows it on localhost.

Scope:
  raqib/
  tests/test_ui.py
  README.md
  docs/review/

Exit criteria:
- E1 One self-contained HTML file: result, alarms, findings with the trace
     lines they cite (A5), rules that did not run (A3), suspicion lines,
     and a timeline of every trace line.
- E2 Silence is visible in the timeline: gaps over the limit, pres without
     a post, sessions that never closed, corrupt lines (A3).
- E3 Read-only and safe: no script, no external resource (CSP), every trace
     value escaped; --serve binds 127.0.0.1 and answers GET only (A4).
- E4 Tests on the real traces and on a hostile trace; gate green.

Not in scope: editing traces, live updates, new rules, auth.
Commit: `landed: M3.1 read-only web UI` or `STOP: M3.1 <reason>`.
Read HANDOFF.md and do only the task it specifies.
