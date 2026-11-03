# ADR-0006 - The window: Raqib as an ordinary desktop program

Status: accepted (M6.4, 2026-11-03; Amendment B). Proposed 2026-11-03.
Amendments appended, never edited in place.

## Problem
After M6.1-M6.3 the commander can start Raqib with one command, but it is
still a terminal command: a console window, Ctrl-C to stop, a browser tab
that is a window and nothing more (ADR-0005: no control from the page). A
person who does not live in a terminal does not start it, so does not have
a watcher. ADR-0005 recorded the tray icon as out of scope because it
needed a toolkit outside the standard library.

## Decision
Raqib gets a native desktop application, `raqib app`: an ordinary program
window like any other Windows or Linux program, not a web page.
- Toolkit: tkinter from the Python standard library. No dependency is
  added; `pip install .` stays enough; python.org Python on Windows ships
  tkinter, Linux distributions ship it as python3-tk and the app says so
  in one sentence when it is missing.
- First screen: what `raqib doctor` says, so the first thing the person
  sees is whether watching can work on this machine, and a Start button.
- Watching: the same watch as `raqib watch` (hooks, trace, rules, silence,
  page on 127.0.0.1, notifications). Start and Stop control Raqib's own
  watching and nothing else; the agent is never signalled, steered or
  written to (A4). The web page stays a window; control lives in the
  program the person is sitting at, which no agent reaches.
- The knock: the moment the first finding of a watch lands, one OS
  notification, whatever its severity, so the person learns that Raqib
  sees something before the severity rules decide whether to knock again.
- Tray: on Windows the program keeps a system-tray icon (Win32
  Shell_NotifyIcon through ctypes, stdlib) with Show / Stop / Quit; closing
  the window while watching hides it to the tray. On Linux there is no
  tray in v1; the window stays open. A tray that fails is reported in
  the window as a hole (A3), never a crash.
- Platforms: Windows (python.org Python 3.14) and Linux. Tests run the
  logic without a display; interface tests skip where there is none.

## Consequences
- New `raqib/app.py` (window, screens, worker thread over `watch.Watch`),
  new `raqib/tray.py` (Windows only), a `raqib-app` gui-script (no console
  window on Windows), a `tkinter` line in doctor, one README section.
- Out of scope, recorded: macOS tray, start with the OS, installers
  (.msi/.deb), any control on the web page.

## Candidate
- M6.4 `raqib app` + tray + first-finding knock (docs/handoffs/M6.4.md).

## Amendment A (the Table, 2026-11-03) - rulings on review 2026-11-03-M6.4.md (5b844ff)
Builder's record: docs/review/2026-11-03-M6.4-questions.md (Q-1..Q-12).
CI run 41662623060 for 5b844ff: six jobs success; the two Tk tests PASSED
on windows (read by the Table from the job log). Verdict: REDO.
- A-1 (P1, P12) The tray's window is a hidden top-level window (its own
  class, WS_OVERLAPPED, never shown), not HWND_MESSAGE, so TaskbarCreated
  (RegisterWindowMessageW) reaches it and the popup menu has a real owner.
  A failed re-add after an Explorer restart turns tray_up() false with a
  hole; close then stops instead of hiding. Fake-API test of the message.
- A-2 (P2) The band's age is computed at every tick from the cached
  heartbeat and the wall clock, never frozen; a state older than
  stale_after_seconds reads as "CRASHED or stuck" (C-4), with the seconds.
- A-3 (P3) Quit waits JOIN_SECONDS; a worker still alive after that brings
  the window back with a hole "the watch did not end in N s"; the process
  never exits with a watch it has not concluded, and never kills anything.
- A-4 (P4, P21) Under the gui-script the tee and the final report go to
  ~/.raqib/app.log (truncated at start, bounded); a failure before Tk is
  up is one MessageBoxW (ctypes, stdlib) on Windows and stderr elsewhere;
  report_callback_exception records a hole and a log line. The exit-2
  sentence is shown the same way.
- A-5 (P5, P13) The watching screen shows "first finding: <rule> <status>"
  and the log is viewable at any time (a Log pane). A high first finding
  knocks once: the rule's own knock is recorded as the first knock (status
  "by the rule"), FIRST-FINDING is not sent after it.
- A-6 (P6, P11) A tray thread that ends from outside stop() records a hole
  "tray ended: <reason>", shown in the footer; a tray that comes up after
  its start timed out deletes its icon and ends (cancelled flag).
- A-7 (P7, P8) Tests: fake-API test of _up/_pump/WM_CLOSE/_down; on win64
  sizeof(WNDCLASSEXW) == 80 and sizeof(NOTIFYICONDATAW) == 976; the real
  tray test passes only when the icon came up and SKIPS with the reason
  otherwise (visible in -rsxXp). The install job asserts the raqib-app
  launcher in the venv and gui_scripts in entry_points.txt.
- A-8 (P9, P10) conclude()'s text and code are kept before close() runs;
  tick failures and LogBuffer errors are holes, deduplicated, never
  overwritten.
- A-9 (P15, Q-8) In `raqib doctor` a missing tkinter is UNSURE with the
  sentence "the window needs it (python3-tk); watch does not"; exit 1 on
  MISSING only. CI expectations updated.
- A-10 (P16) --log applies only to the project named on the command line;
  a project chosen by Browse gets its default trace. The four flags are
  accepted as built and recorded.
- A-11 (P17) The docstring says what runs: doctor's `claude --version`
  and nothing else; the AST guard lists PostMessageW, SendMessageW,
  TerminateProcess, kill, killpg as forbidden names.
- A-12 (Q-2, Q-3; P14) `raqib watch` in a terminal knocks on the first
  finding too (FirstFinding as loop's default on_step); watch.json carries
  `first_knock`. The Scope word "loop split only" is widened by this
  ruling to Stop, loop(stop, on_step) and the first_knock field (Table's
  ledger: the Scope word, again).
- A-13 Accepted as built: Q-1 (pending and history findings do not
  knock), Q-4 (no tray on Linux is a note), Q-5 (close without a tray
  stops and keeps the report; a second close quits), Q-7 (exit code and
  stdout contract, with A-4), Q-9 (CI plus the commander's field test is
  the acceptance; no screenshot), Q-10, Q-11, Q-12 (P20). Q-6: an "Open
  page" button through watch.open_page (the person clicked; A4 holds).
- A-14 Recorded: P18 (a same-user process can post WM_CLOSE: a hole for
  THREAT_MODEL at the next docs pass), P19 (3.14 is proven by the
  commander's field test, not by CI), P20.
- A-15 Every REDO change carries a test for the behaviour it adds (D-8).

## Amendment B (the Table, 2026-11-03) - judgement on M6.4 (5b844ff + bccdb75 + 0987591)
- A-1..A-13 MET as cited in the REDO section of
  docs/review/2026-11-03-M6.4-questions.md; the Table read the A-1 delta
  itself (tray.py: a hidden top-level window of its own class, WS_OVERLAPPED,
  HWND_MESSAGE no longer used; TaskbarCreated registered and handled; a
  failed re-add turns the tray off with a hole; stop() by a thread message)
  and the A-5/A-12 delta (notify.FirstFinding.by_the_rule; watch.first_step
  as loop()'s default on_step; `first_knock` in watch.json). Every REDO
  change names its test (A-15, D-8).
- CI, read by the Table from api.github.com: run 41662623060 (5b844ff) six
  jobs success; run 41675043956 (bccdb75) five success, both windows gate
  jobs failed on one assertion (the Open page test expected the fake
  opener's note while the code rightly refuses under CI); run 41676368785
  (0987591, the one-assertion fix) six jobs success. On windows the two Tk
  window tests PASSED, and test_e4_real_tray_starts_and_stops_or_says_why
  PASSED, which after A-7 means the icon came up on the runner.
- Gate on the branch: 2448 passed, 14 skipped. Scope clean (widened by
  A-4, A-12, A-13). Three commits on the branch (G-8: the builder's settings
  forbid rewriting; the follow-up is a CI fix of one assertion).
- R-1 (stop() and WM_NULL by PostThreadMessageW to the tray's own thread)
  accepted: nothing is posted to any window. R-2: with the rule's knock off
  (--no-notify, CI), FIRST-FINDING is "off" too, not "by the rule";
  accepted, the record says "off". R-3: run() waits for an unconcluded
  worker without limit, 30 s at a time, saying so each time: accepted (the
  alternative is a watch that ends by being killed, A3/A4). R-4: no
  message box for an ALARM exit; the window already showed the report:
  accepted.
- Status of this ADR: **accepted (M6.4, 2026-11-03)**. Decision text
  unchanged; Amendments A and B are the record.
- Verdict: **NEXT**. Merge --no-ff into main under the commander's
  standing word ("do it / merge").
- Table ledger for M6.4: one review, one REDO, one CI follow-up. The
  Table's own misses: the Scope word "loop split only" could not hold the
  E3 hook the HANDOFF itself asked for (corrected A-12); the reviewer agent
  has no write tool, so the packet was filed by the Table; the HANDOFF
  needed three trims to fit 30 lines. Field items for the commander: the
  tray on a real desktop (icon, right-click menu, close hides, Explorer
  restart re-adds); python.org 3.14 on Windows (P19); the knock under
  pythonw reaches ~/.raqib/app.log (A-4).
