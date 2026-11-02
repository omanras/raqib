# ADR-0005 - One command, a window, and a knock: raqib watch, dashboard, notifications

Status: accepted (M6.1, 2026-11-03; Amendment F). Proposed 2026-11-02.
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

## Amendment A (2026-11-02) - as built in M6.1 (builder's record, not a ruling)
What M6.1 built, so the review can hold the tree to it. The open design
points are questions in `docs/review/2026-11-02-M6.1-questions.md`, not
settled here.
- A-1 `raqib watch [PROJECT] [--log PATH] [--no-open] [--no-notify]
  [--port N]` (`raqib/watch.py`, `raqib/cli.py`). The trace is --log, else
  the one trace an earlier install chose if it is outside the project,
  else `~/.raqib/traces/<name>-<sha256(project)[:12]>/raqib.log.jsonl`.
  A --log inside the project is refused (exit 2); an earlier install's
  trace inside the project is replaced by the default (the old file is
  left as it is, and a note says so). The hooks go in through
  `install_project()` of `tools/install_hooks.py`, a new API beside the
  unchanged command; its lines are printed. disableAllHooks (installer
  exit 3) is a capture failure.
- A-2 Incremental: every 0.5 s the bytes appended since the last poll are
  read; complete lines are parsed by the batch parser with line numbers
  continued, so the records equal `trace.read_numbered` of the final file.
  When lines arrived, the silence rules and the catalog are re-run on the
  whole growing record list (they are pure functions over a list) and each
  finding is keyed - (epoch, rule, session) for the aggregate rules and
  SILENCE-OPEN, (epoch, rule, session, cited_seq) for the others - so a key
  is reported and notified once. SILENCE-OPEN, and SILENCE-HALF on a seq
  with more pres than posts, are pending: not notified, dropped when later
  lines take them back, marked "pending at exit" otherwise.
- A-3 Silence: no new line for RAQIB_GAP_SECONDS (wall clock, from the last
  line seen or from the start of the watch) opens a live window
  (SILENCE-LIVE open); the next non-blank line closes it (SILENCE-LIVE
  closed). A trace line starting with RAQIB-SILENCE is a capture failure
  (RAQIB-SILENCE). A trace that shrank, was replaced (device and inode),
  was rewritten in its first 64 bytes, was removed, or cannot be read is a
  hole (TRACE-HOLE); after the first four, reading starts again at line 1
  in a new epoch, and settled findings of the old content stay as
  "finding-before-hole" alarms. Windows and holes are alarms of the final
  report.
- A-4 Notifications (`raqib/notify.py`): new settled findings of severity
  high, both edges of a live window, capture failures and trace holes.
  Text: "Raqib: <event>" and "project <name>, <seq or line>", in the
  alphabet [A-Za-z0-9 ._,:+()-], at most 120 characters. Windows: the
  PowerShell of %SystemRoot%\System32\WindowsPowerShell\v1.0 with
  -NoProfile -NonInteractive -ExecutionPolicy Bypass -File toast.ps1
  TEXTFILE, the WinRT ToastNotificationManager, PowerShell's AppUserModelID.
  macOS: /usr/bin/osascript notify.applescript TEXTFILE. Elsewhere:
  /usr/bin/notify-send or /bin/notify-send through /bin/sh -c and a
  constant script that reads TEXTFILE with `read`; with none of these, the
  bell and a line on stderr. The scripts are constant and the text is only
  in TEXTFILE; programs get a minimal environment and are run by absolute
  path through one `subprocess.Popen` call. Delivery is synchronous, with
  a 10 s limit; a program that does not exit in time is left running and
  recorded, never signalled. A failed delivery is a `notify-failed` hole
  (watch.json, the page band, the final report) and falls back to the
  bell. One per event id per 60 s; the rest are folded into a count sent
  after the minute, or carried by the next one. Off when CI is set or with
  --no-notify, and shown as off.
- A-5 `<trace>.watch.json` (written atomically when something changed):
  project, trace, pid, url, times, gap, status (watching / silent /
  finished), epoch, line and record counts, last line, every finding entry
  (key, state, notice, first_seen, present), every silence window, every
  hole, and the notifier's state and counts.
- A-6 The page: `ui.render(..., band=[(level, text)])`, the serve hook; the
  page without a band is unchanged byte for byte, and the CSP and the
  no-script rule are unchanged. The band says watching or SILENT for N s,
  the notifier state, and the number of holes. No refresh yet (M6.2).
- A-7 The page is opened once: /usr/bin/xdg-open or /bin/xdg-open (PATH set
  to /usr/local/bin:/usr/bin:/bin), /usr/bin/open, or
  %SystemRoot%\explorer.exe, without waiting; not under CI or --no-open.

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

## Amendment C (2026-11-02) - the M6.1 REDO as built (builder's record, not a ruling)
What the REDO on Amendment B built; Amendment A stands where this does not
change it. Recorded points are in `docs/review/2026-11-02-M6.1-questions.md`.
- C-1 (B-1) A pending SILENCE-HALF settles when a stop or session_end of its
  session comes after its first pre; every pending finding settles when the
  live silence window opens. Settling knocks if the finding is high and not
  history; the entry records `settled_by`. Tested on the blocked-calls
  fixture: seq 2 knocks, seq 3 is folded and sent after the minute.
- C-2 (B-2) The key is (epoch, rule id, session, cited seqs, summary). The
  epoch is kept so content read after a reset is never merged with content
  that is gone. An aggregate finding or a SILENCE-OPEN whose key changed as
  it grew takes over the entry of the same rule and session whose key is
  gone (`grown` counts it): it is not knocked again.
- C-3 (B-3) The trace's size at the start is the history boundary. A line
  that ends within it is history, and a finding is history when every line
  of every seq it cites is. History is judged, shown and counted in one
  printed line, but never notified: not its findings, its RAQIB-SILENCE
  lines or its parse problems.
- C-4 (B-4) Each live line that does not parse knocks once as TRACE-HOLE.
  watch.json is written on every poll, with `heartbeat` and
  `stale_after_seconds` (30). Any exception in the loop ends in
  finish(status="crashed", error), a `watch-crashed` alarm and the final
  report. The band reads a heartbeat older than 30 s as "CRASHED or stuck".
  A page that cannot get the state within 15 s is answered with the error
  page ("not responding"), not left waiting.
- C-5 (B-5) toast.ps1 and notify.applescript are hashed and checked against
  SCRIPT_SHA256 (the sha256 of their in-code text) right before every use.
  A script that differs or is gone is rewritten, and that is a
  `script-changed` hole. The notify-send wrapper stays inline (`sh -c`
  constant): it never exists as a file. Temp files go under
  ~/.raqib/tmp/raqib-notify-*; a temp root that is not absolute fails the
  delivery (a hole). A SystemRoot that is unset, not a directory, or not
  named Windows turns notifications off with a `notify-off` hole.
- C-6 (B-6) `<project>/HANDOFF.md`, when present, goes through the same
  `_context()` as `report --handoff`, read once at the start. The scope is
  printed and kept in watch.json. A clean watch of such a project ends
  CLEAN (exit 0, POSIX). On Windows the HANDOFF's root is a drive path,
  which the engine reports as bad-context until M5.1b.
- C-7 (B-7) A requested port (--port N, or 8765) that cannot be bound gives
  a free port, a `WARNING:` line, a band item, `port.warning` in watch.json
  and a line in the final report.
- C-8 (B-8) README lines reworded ("knock once settled", "by default", the
  history line).

## Amendment D (the Table, 2026-11-03) - rulings on review 2026-11-03-M6.1-redo.md
- D-1 (X1) History is a property of epoch 0 only. `_restart` clears
  history_line, history_bytes and problem_notices; in any later epoch
  every line is live. Test: truncation of a trace that had history, then
  a line that must close the open window and a RAQIB-SILENCE line that
  must knock.
- D-2 (X2, C-2) `_grown` may hand an entry over only while the old entry
  is still present and not settled. A settled or vanished entry is never
  adopted; a new key after a stop is a new finding. Test: the long-call /
  window / stop / next-turn sequence yields a second SILENCE-OPEN that is
  printed and knocks when its window opens.
- D-3 (R-1, X9) The inline `sh -c` wrapper for notify-send is accepted:
  nothing on disk to swap, text passed as a file argument, sh by absolute
  path. B-5's list is corrected by this ruling. open_page validates
  SystemRoot the same way notify does (existing dir named Windows).
- D-4 (X3) tick()'s result is written back to the entry (sent | failed |
  folded-sent-as "N more"); a fold names its first and last seq.
- D-5 (X5) A finding whose pre predates the start but whose settling line
  is live knocks: history applies to findings settled by history only.
- D-6 (X6, X7) A live RAQIB-SILENCE line is labelled live and knocks as
  RAQIB-SILENCE; tail holes and parse problems get separate rate-limit ids.
- D-7 (X4, X8, X10, X11, X12) recorded. X10: the scope note is passed
  through _safe like every other line. X8: finish() guards _write_state,
  report() and summary_text() too, so a final report always prints or a
  one-line reason does. X12: the REDO starting gate is run and recorded.
- D-8 Reviewer's observation accepted into the Table's ledger: both X1 and
  X2 were introduced by the REDO, not present at 9ae221c. A REDO must
  carry a test for the behaviour it adds, not only for the finding it
  closes; the Table will ask for that line in every REDO message.

## Amendment E (2026-11-03) - the M6.1 REDO 2 as built (builder's record, not a ruling)
What REDO 2 built on Amendment D; Amendments A and C stand where this does
not change them. The starting gate, the tests by name and the recorded
points (R-8, R-9) are in `docs/review/2026-11-02-M6.1-questions.md`.
- E-1 (D-1) `_restart` sets history_line and history_bytes to 0 and empties
  the problem notices: after a reset every line is live.
- E-2 (D-2) `_grown` takes over only an entry that is pending and was present
  until this evaluation. A settled entry whose key is gone keeps its place,
  with present false; a new key after it is a new finding. For SILENCE-OPEN
  that means a new turn's finding. For the aggregate rules, which settle
  when first seen, every growth is a new finding (R-8).
- E-3 (D-3) `notify.windows_root()` is the one SystemRoot check (an
  existing directory named Windows); `Notifier` and `open_page` both use it.
  The notify-send wrapper stays inline, as ruled.
- E-4 (D-4) Every knock carries a token, (container, key), naming the
  field that holds its notice. When a fold is delivered, by tick() or by
  the next notification of its rate-limit id, `on_folds` writes "folded:
  <status> as N more" into each folded notice. Fold text: "1 more (seq 3)",
  "N more (first seq 2, last seq 4)".
- E-5 (D-5) While pending, a finding is history if its cited lines are; when
  it settles, it is history only if the settling line (a stop or
  session_end) was there at the start too. A finding settled by the live
  silence window keeps the history of its cited lines (R-9).
- E-6 (D-6) `trace_problems` and `holes` carry history, knocked_as and
  notice. Parse problems knock as TRACE-HOLE under the rate-limit id
  "TRACE-HOLE (line)"; tail holes keep the id TRACE-HOLE.
- E-7 (D-7) The start lines go through `_safe`. finish() guards the state
  write, the report and the summary, and sets final_text and final_exit;
  `command` prints final_text, or one line if finish itself raises.

## Amendment F (the Table, 2026-11-03) - judgement on 331136d (REDO 2)
The Table read the D-1 (`_restart`, watch.py:323-333) and D-2 (`_grown`,
:398-406) code paths itself; D-3..D-7 are taken on the builder's cited
lines and named tests after two independent reviews of the same tree, and
every REDO 2 change carries a test for the behaviour it adds (D-8).
- D-1..D-7 MET. R-8 (aggregate rules reprinted on each growth, older
  entry kept as not present; none high) accepted and recorded. R-9 (a
  finding settled by the live window, all lines history, stays history)
  accepted: the alternative knocks a stale SILENCE-OPEN at every start.
- Gates: starting 948 passed (recorded, D-7/X12), closing 960 passed,
  4 skipped, exit 0. CI for 331136d, read by the Table from
  api.github.com: run 41519103474 success on ubuntu 3.11/3.12 and
  windows 3.11/3.12. Scope: no file outside HANDOFF M6.1.
- Status of this ADR: **accepted (M6.1, 2026-11-03)**. Decision text
  unchanged; amendments A-F are the record.
- Verdict: **NEXT**. Merge --no-ff into main under the commander's
  standing word ("do and apply").
- Table ledger for M6.1: three reviews, two REDOs; both REDO-1 defects
  came from the REDO itself and were caught by review 2, which produced
  rule D-8. The Table's own misses: B-5 named a wrapper that is not a
  file (corrected D-3); B-3 said nothing about epochs (corrected D-1).

## Amendment G (the Table, 2026-11-03) - rulings on review 2026-11-03-M6.3.md
- G-1 (P1) README and the questions file state the truth per platform: on
  POSIX a moved package makes the hook wrapper print RAQIB-SILENCE; on
  Windows a moved venv makes the hook a Claude Code hook error with no
  line (test_install.py:780-787). One sentence each.
- G-2 (P2, P3) The install CI job runs the console script with output the
  console cannot encode (a path with a non-cp1252 character on Windows) and
  asserts no crash; `python -m zipfile -l` on the built wheel asserts
  raqib/hooks/capture.py, the 7 catalog YAMLs and endpoints.yaml are
  present; the doctor CI step asserts exactly the expected MISSING lines
  (hooks, notifier), not any count. Tests where in-process is possible.
- G-3 (P4) doctor treats a relative `python3` resolution like a relative
  claude: MISSING with "may shadow"; test.
- G-4 (P5) doctor runs `claude --version` with cwd set to a fresh temp
  directory and a PATH filtered to absolute entries outside the project.
- G-5 (P6) On Windows, writable() reports "not checked (os.access cannot
  tell on Windows)" as a hole-style line, never OK; E2's no-probe rule
  stands. P7: the choose_trace notes are printed by doctor.
- G-6 (P9) eval --help says "a checkout's tests/fixtures/eval/events.json
  or --events FILE"; installed raqib without --events exits 2 with that
  sentence. P12: build/ and *.egg-info added to .gitignore (.gitignore is
  added to Scope by this ruling). P16: the ADR line 61-62 is superseded by
  this amendment: install from a git URL or a local path until a PyPI name
  is owned; LICENSE is the commander's decision (recorded, not built).
- G-7 (P10, P11, P13, P14, P15, P17) recorded; P10 accepted (Q-1 keep);
  P11: README first screen gains the Windows path-rules caveat line.
- G-8 Two commits on the branch (builder cannot force-push) are accepted
  for this milestone and merged as they are; the rule "one commit" is
  read as "one landed task" when the builder's settings forbid rewriting.

## Amendment H (the Table, 2026-11-03) - on the M6.3 REDO (94479be + aac6054)
- G-1..G-7 MET as cited; CI run 41530961557 success on six jobs (read by
  the Table from api.github.com); gate 1033 passed, 6 skipped; scope
  clean; four commits on the branch (G-8 extended to them: the builder's
  settings forbid rewriting).
- H-1 (G-5 reading) A line that cannot be checked is a third class,
  `UNSURE`, printed as such and counted separately: "raqib doctor: N
  MISSING, M UNSURE"; exit 1 only on MISSING. A doctor that is always red
  on Windows tells the commander nothing. The HANDOFF's "OK / MISSING" is
  amended by this ruling. Test: Windows trace line is UNSURE, exit 0 when
  nothing else is MISSING.
- H-2 (G-4 addition) A `claude` found inside the project is MISSING and
  never run: ratified.
- H-3 Verdict after H-1 lands: NEXT; merge --no-ff under the commander's
  standing word. The Table reads the H-1 delta itself (one class, one
  exit rule, one test) rather than a third review.
