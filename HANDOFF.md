# HANDOFF — M10.4b REDO  (ADR-0011 Amendments R-2 to R-4, S, T, U: the window's Link screen)

Task: the window shows the forwarders' link: a rail item that carries the worst word at all times, and a Link screen that lists each forwarder as raqib/link.py read and judged it. The window starts nothing and judges nothing itself.

Scope:
  raqib/app.py, tests/test_app_link.py (new), docs/GUIDE.md, tests/test_readme_top.py (only the guide's new or changed lines in its registry), docs/THREAT_MODEL.md, docs/specs/FORWARD.md (one sentence), docs/review/2026-11-17-M10.4b-questions.md

Exit criteria:
- E1 (T-2, U-1) Done by the Table on this branch: each row of `link.read` carries "age", "to", "facts" and "why" (raqib/link.py `_parts`, FACTS). Use them; raqib/link.py and tests/test_link.py are not in scope any more.
- E2 (T-1, T-3) Pure functions in raqib/app.py, tested with no Tk: `link_view(rows, age=None)` gives the verdict's word, level and detail and one item a forwarder (name, word, level, its lines); levels by `level_of` of the row's code, but OK is `note`; no row and no problem is the plain "no forwarder: nothing leaves this host by Raqib" at `note` with the command as text (T-5); `rows.problem` or `rows.rest` is `incomplete` and said (S-1, S-2); a read late by more than 10 s is `incomplete` and said with its age, but stays `alarm` where the last read held FAILING or BEHIND (U-2). Every text of a state passes through one function that removes control characters and bounds a line (a test with escape sequences, a newline inside a value, a line of 10000 characters).
- E3 (R-3) `rail_link(rows, age=None)` gives the rail's one bounded line and its level: how many forwarders and the worst word among them ("Link: 2 forwarders, 1 failing, 1 behind": each word at the worst code counted, U-3; "Link: none"; "Link: not read"); the rail shows it on every screen, coloured as the rail's other lines are.
- E4 (R-2) A rail item "Link" and its screen: the verdict header, then each forwarder's name and word and its lines, as text (selectable, read-only). No control on the screen starts, stops or configures a forwarder; the screen holds no token and no field. The screen follows the window's existing styles (no new colour; the palette's pair test passes unchanged).
- E5 (T-4, R-4) The states are read by a worker thread through `link.read`, at most once a second, never two reads at once, started with the window and waited for at its end for at most 2 s (U-4: it is no part of "the watch did not end"); clock and reader injected. A read that has not returned in 10 s: the view is `incomplete` and says for how long nothing was read. Tests with a reader that blocks, one that raises, and the rate (a clock, no sleeps).
- E6 (R-2, J-1) No result, exit code, finding, report or knock of a watch changes with the link: a test runs the controller's exit code and a watch's view with a failing, a silent and no forwarder and finds them equal.
- E7 raqib/app.py imports raqib.link and never raqib.forward by any spelling (tests/test_rhythm.py's guard passes unchanged; a test of this file's own by ast).
- E8 Tk tests (skipped without tkinter or a display, as tests/test_app.py's are): the rail's Link item opens the screen; the screen fills from rows of each word; it leaves no thread behind at destroy.
- E9 docs/GUIDE.md says the Link screen where the window's screens are said (what it shows, that it starts nothing, the levels' meaning, T-1's sentence); docs/THREAT_MODEL.md says T-3's limit and that the window reads the states and holds no token (no milestone token); docs/specs/FORWARD.md names the Link screen where it names the window as the state's reader (U-5). Gate green in the foreground; ASCII outside docs.
Not in scope: raqib/link.py, tests/test_link.py, raqib/forward.py, raqib/cli.py, raqib/host.py, raqib/ui.py (the local page), the tray, tests/test_rhythm.py, tests/test_forward.py, the rig.
If an exit criterion needs a file outside Scope: STOP and say which. Do not change a guard test to pass.
Commit: `landed: M10.4b REDO the window's Link screen` or `STOP: M10.4b REDO <reason>`.
Read HANDOFF.md and do only the task it specifies.
