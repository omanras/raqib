# HANDOFF — M8.1  (the look: ADR-0009 decisions 1-3)

Task: rebuild the window's presentation as ADR-0009 decisions 1-3 describe, over the same Controller, Session,
HostSession and RulesPanel. No behaviour changes; the report, the page and the terminal keep their texts.

Scope:
  raqib/app.py (presentation), raqib/host.py (ONLY a per-round result list in the state, if the strip needs it), tests/, README.md (the window's section), docs/review/

Exit criteria:
- E1 THEME holds ADR-0009's tokens for light and dark and stays the only place a colour lives (the AST test holds); fonts by pick_font from the ADR's families; every text/ground
     pair THEME pairs has contrast >= 4.5:1 in both modes (tested; a failing value is adjusted in lightness, not hue); every level is a colour and its word.
- E2 Shape on all four screens: the rail (name, the watch's state in words, Host / Project / Rules / Log, "N rules off" red when suppressed > 0, Open page), a verdict header (one
     sentence in sentence case, the level's pill with its word, the screen's one primary action), cards. First-run lines, the doctrine sentence and "Not a clearance." in every
     green state stay (ADR-0008 C-1..C-3 tests hold; a text changes only where this handoff says).
- E3 The round strip under the host verdict: a pure function from the watch's state to cells (clean / finding / not read or late / before the watch) and its sentence ("40 rounds:
     36 clean, 3 with findings, 1 not read"), newest right, as many as fit; a round not read is drawn, never skipped (A3). Tested without Tk and drawn on a Canvas.
- E4 Controls: ttk styles for a filled primary and flat secondary buttons, entries, tables (tall rows, no grid lines, quiet header, tinted selection, sort kept), thin scrollbars;
     a Switch, a Pill and a disclosure drawn by the window; Tab reaches each, Space or Enter acts, focus is visible. Doctor's checks are rows (pill, name, sentence), not a text
     dump. Holes live in "could not see (N)": every hole, one click, never dropped (this replaces ADR-0008 C-5's three-line footer). The watch options sit in a disclosure, closed
     by default.
- E5 Rules screen: one row per rule - switch (the same RulesPanel.set), name, the YAML's title, pills for kind, severity and origin, each declared threshold as a stepper within
     its bounds (the same RulesPanel.threshold; the measurement's words beside it), a filter box, "Add rule file..." kept. It scrolls and works from the keyboard.
- E6 Windows only, own process and window only (A4): DPI awareness declared before Tk starts and every pixel size through one scale function (tested at 1.0, 1.25, 1.5); the title
     bar follows dark mode. A failure of either is a line in app.log and the window opens as before. Minimum size 900x600 at scale 1.0; every screen fits it, light and dark,
     measured on windows-latest (the run of record).
- E7 Tests: helpers without a display; Tk tests build every screen in both modes, toggle a switch, step a threshold, open each disclosure; no old test is deleted without its
     replacement named in the questions file; the AST guard admits only E6's two calls. Gate green, CI six green. README's window section rewritten for what a person sees.
Not in scope: the rule form and Remove (M8.2), any behaviour, the tray menu, the web page, macOS, a translation.
Commit: `landed: M8.1 the look` or `STOP: M8.1 <reason>`.
Read HANDOFF.md and do only the task it specifies.
