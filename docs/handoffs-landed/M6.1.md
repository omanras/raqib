# HANDOFF — M6.1  (phase 6: `raqib watch` + OS notifications, ADR-0005)

Task: one command watches a project: install hooks if missing, tail the trace,
run rules incrementally, notify the OS on findings and silence, serve the page.

Scope:
  raqib/watch.py (new), raqib/notify.py (new), raqib/cli.py, raqib/ui.py (serve hook
  only), tools/install_hooks.py (API only), tests/, README.md, docs/specs/ADR-0005-*.md, docs/review/

Exit criteria:
- E1 `raqib watch [PROJECT] [--log PATH] [--no-open] [--no-notify] [--port N]`:
     installs hooks via install_hooks (idempotent, prints changes), tails the
     trace by polling, evaluates rules on new lines only, keeps findings and
     silence windows in memory and in `<trace>.watch.json`, opens the page
     once, runs until Ctrl-C, prints the final report. Writes nothing into
     the project but the hook settings; never signals a process (A4).
- E2 Live silence: no line for RAQIB_GAP_SECONDS opens a window (A3), the next closes it; both notified.
- E3 `raqib/notify.py`: windows (PowerShell + WinRT toast, text via a temp
     file, never in the command string), linux (`notify-send` by absolute
     path, else bell + stderr), darwin (`osascript`). Text = rule id, project,
     seq - never agent content. One per rule per 60 s, rest folded into a
     count. Delivery failure -> hole in watch.json and in the page band.
- E4 Tests: tail on a growing file; incremental == batch on the final file;
     silence open/close; backends with a fake runner (file, not string); limit.
- E5 README "Watch a project": three lines. Gate green ubuntu + windows;
     notifier disabled under CI (no toasts).

Not in scope: dashboard v2 (M6.2), packaging (M6.3), tray, page controls.
Commit: `landed: M6.1 raqib watch` or `STOP: M6.1 <reason>`.
Read HANDOFF.md and do only the task it specifies.
