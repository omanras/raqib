# ADR-0006 - The window: Raqib as an ordinary desktop program

Status: proposed (the Table for the commander, 2026-11-03; M6.4).
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
