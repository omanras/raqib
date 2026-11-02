# ADR-0005 - One command, a window, and a knock: raqib watch, dashboard, notifications

Status: proposed by the Table, 2026-11-02. Becomes accepted when M6.1 lands.
Amendments appended, never edited in place.

## Problem
The commander's verdict after the first field day (2026-11-02): Raqib's
fatal point is use. Watching one agent takes a clone, a venv, an
installer, a trace path, three subcommands and a browser opened by hand;
a finding is a line in a terminal nobody is looking at. A watcher that is
hard to start is not started; one that cannot interrupt is not a watcher.

## Decision
Three things, each its own milestone, all under the Constitution as it
stands (A1 deterministic, A3 silence is an alarm, A4 never touch the
watched, A5 cite, A8 tree is truth) and under the stdlib-only, offline
rule of the capture path.

1. **`raqib watch <project>` - one command.** Installs the hooks if they
   are missing (idempotent, M5.1 installer), chooses the trace path
   outside the agent's tree, tails the trace as it grows, runs the rules
   incrementally on each new line, keeps the inventory of findings and
   silence windows in memory and in a small JSON next to the trace, opens
   the dashboard once, and keeps running until Ctrl-C. On exit it prints
   the final report. `raqib watch` with no project watches the current
   directory. It reads; it never writes into the project except the hook
   settings the installer already writes, and never signals the agent.
2. **Dashboard - the existing read-only page, live.** `raqib watch`
   serves it on 127.0.0.1 (the serve() that exists) and the page refreshes
   itself by `<meta http-equiv="refresh">` so the no-script, no-load
   Content-Security-Policy stays as it is: the page that shows an
   adversary's data must not run code. It gains: a status band (watching
   / silent for N s / agent gone), findings first by severity, the
   silence windows as they open, a list of watched projects when more
   than one `watch` runs, and a `discover` tab when an inventory JSON is
   present. No form changes state; the dashboard is a window, not a
   control panel. Control stays in the terminal, by design: a page that
   can stop or steer the agent is a page the agent can use (A4).
3. **Notifications - the knock.** A new finding of severity high, a
   silence window opening, and capture failure (RAQIB-SILENCE seen) each
   raise one OS notification: Windows through the WinRT toast API called
   from PowerShell with the text passed as a file, never as a command
   string (no injection surface from trace content); Linux through
   `notify-send` when present, else the terminal bell and a line on
   stderr; macOS through `osascript display notification`. Notification
   text carries the rule id, the project, and the cited seq; never the
   path, command or output content the agent produced (the toast is a
   world-readable surface). A notification that cannot be delivered is
   written to the trace-side JSON as a hole (A3), and the dashboard shows
   "notifications: off" in its band.

Deterministic, no model, no network. Rate-limited: one toast per rule per
minute, the rest folded into a count; silence of the notifier is itself
shown.

## Consequences
- New module `raqib/watch.py` (tail + incremental rules + notify), new
  `raqib/notify.py` (per-OS backends, text-by-file), `raqib/ui.py`
  extended (band, refresh, projects, discover tab). CLI gains `watch`.
- Packaging: `pyproject.toml` so `pip install .` (or `pipx install`)
  puts a `raqib` command on PATH; the quickstart becomes
  `pipx install raqib && raqib watch ~/my-project`. No wheel on PyPI
  until a third reader has run it.
- `raqib doctor`: checks Python, Claude Code on PATH, hook settings,
  notifier availability, and prints what is missing in one screen.
- Out of scope, recorded: a tray icon (needs a non-stdlib toolkit; a
  later decision), remote dashboards (127.0.0.1 only), any control
  action from the page.

## Candidates
- M6.1 `raqib watch` + `raqib/notify.py` + Windows/Linux/macOS backends.
- M6.2 dashboard v2 (band, refresh, projects, discover tab).
- M6.3 packaging (`pyproject.toml`, `raqib` entry point, `raqib doctor`,
  README rewritten around `watch`).
Order: M6.1, M6.3, M6.2. The Phase 5 items M5.0b/M5.1b/M5.2 resume after.
