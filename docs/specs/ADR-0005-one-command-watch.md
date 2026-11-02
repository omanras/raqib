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

## Amendment B (the Table, 2026-11-02) - rulings on review 2026-11-02-M6.1.md
- B-1 (W1) A pending finding (SILENCE-HALF, SILENCE-OPEN) is settled - and
  knocks if high - when its session shows a later stop or session_end, or
  when the live silence window for the trace opens. "Pending for good" is
  silence (A3). Test on the blocked-calls fixture: both halves notified.
- B-2 (W2) The finding key is (rule id, session, cited seqs, summary). Two
  findings never share a key; a test with the two SILENCE-ORDER shapes.
- B-3 (W3) On start, lines already in the trace are history: parsed,
  judged, shown in the page and the final report, counted in one line
  ("N prior findings in the trace, not knocked"), never notified. Knocks
  start at the first line appended after start. Recorded in README.
- B-4 (W5, W6) Live parse problems knock as TRACE-HOLE (one per minute).
  watch.json carries a heartbeat timestamp on every poll; the loop is
  wrapped so any exception ends with finish(status="crashed", error) and
  the final report; "watching" without a fresh heartbeat reads as
  crashed on the page (A3 for the watcher itself).
- B-5 (W8) Script files (toast.ps1, notify.applescript, the notify-send
  wrapper) are verified by sha256 against the in-code constant before
  every use and rewritten if they differ, with a hole recorded. Temp
  files live under ~/.raqib/tmp, never the cwd. SystemRoot is taken from
  the environment but must be an existing directory whose basename is
  Windows, else notifications are off with a hole.
- B-6 (W13) `raqib watch` reads `<project>/HANDOFF.md` when present and
  passes its Scope as context, exactly as `report --handoff` does; a
  watch of a Raqib-style project can then end CLEAN. Still no --scope
  flag (not in HANDOFF).
- B-7 (W11) If the requested port is busy, watch prints a WARNING line
  naming the other port and writes it to watch.json; never silent.
- B-8 (W17) README: "high findings knock" -> "high findings knock once
  settled"; the trace path line says "by default".
- B-9 (W7, W9, W10, W12, W14, W15, W16, W18, W19) recorded; W14 is
  M6.3's; W18's three local choices are ratified as recorded (pending
  highs now knock on settle by B-1; TRACE-HOLE knocking accepted;
  whole-list re-run accepted until cost shows in the field).
