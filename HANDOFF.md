# HANDOFF — M6.4  (phase 6: the window - a native desktop app, ADR-0006)

Task: `raqib app [PROJECT]` opens an ordinary program window (tkinter, stdlib
only): doctor first, Start/Stop, a Windows tray icon, a knock on the first finding.

Scope:
  raqib/app.py (new), raqib/tray.py (new), raqib/cli.py, raqib/doctor.py, raqib/watch.py (loop
  split only), raqib/notify.py, pyproject.toml, .github/workflows/gate.yml, tests/, README.md, docs/review/

Exit criteria:
- E1 `raqib app [PROJECT]` + a `raqib-app` gui-script (pythonw on Windows). First
     screen: the doctor lines (OK / MISSING / UNSURE), a project field with Browse,
     Start. Watching screen: band, findings by severity, holes, page URL, Stop.
     Stop and window-close end the watch like Ctrl-C (finish(); final report in
     the window). `dependencies = []` stays.
- E2 Start runs the same Watch as `raqib watch` (hooks, trace, state JSON,
     registry, page on 127.0.0.1) in a worker thread; the window reads state
     under the Watch lock by `after()`, never from the page. Nothing in the
     window signals or writes to the agent (A4).
- E3 First finding of a watch (any severity, live, once) knocks via the Notifier, own limit id, A-4 text.
- E4 Windows tray: ctypes Shell_NotifyIcon, icon drawn in code, menu Show / Stop /
     Quit; close hides to the tray while watching. Linux: no tray, recorded.
     A tray failure is a hole shown in the window, never a crash.
- E5 No tkinter or no display: `raqib app` exits 2 naming python3-tk; doctor
     gains a `tkinter` line. Logic tested with fakes; Tk tests skip without a
     display. Nothing deprecated before 3.14. CI six jobs green; install job
     runs `raqib app --help`. E6 README: section "The window", three lines.
Not in scope: macOS tray, autostart, installers, page controls, M5.4.
Commit: `landed: M6.4 the window` or `STOP: M6.4 <reason>`.
Read HANDOFF.md and do only the task it specifies.
