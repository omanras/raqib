# ADR-0009 - The window a person likes to open, and a rule made from a form

Status: proposed (the Table, 2026-11-10, on the commander's order of that day).
Amendments appended, never edited in place.

## Problem
The commander, after the second field run: the window looks classic and
does not sit beside modern programs; and adding a rule should be easy
from the window. Both are true of the tree. The window is correct and
plain: a row of grey buttons, a band, a table, text boxes of report
lines; on a scaled Windows display Tk draws it blurred, because the
process never says it is DPI-aware. Adding a rule means writing a YAML
file and its fixture files by hand and pointing at them (ADR-0008
decision 4): a person who can say "tell me when an agent runs ssh" cannot
say it to Raqib without learning the engine.

## Decision
1. **The look is rebuilt, the behaviour is not.** Still tkinter and ttk
   from the standard library, no dependency (ADR-0006). Everything
   ADR-0006 and ADR-0008 ruled stands: one THEME table is the only place
   a colour lives; every level is a colour AND its word; "Not a
   clearance." in every green state; "Rules decide; a model may only
   raise suspicion."; dark and light follow the OS; every screen fits
   900x600, measured on windows-latest (ADR-0008 D); holes are never
   hidden (A3), though they may be folded behind a counted control.
2. **The design** (tokens are starting values; the contrast test decides,
   and a value that fails is adjusted in lightness, not in hue):
   - Shape: a navigation rail on the left (the name, the watch's state
     in words, Host / Project / Rules / Log, "N rules off", Open page)
     and one content column: a verdict header (one sentence in sentence
     case, the level's pill with its word, the one primary action of the
     screen on the right), then cards.
   - The round strip, the window's own mark: under the host verdict, the
     last rounds of the watch as a row of small squares, newest at the
     right - filled green for a round read with nothing new, red for a
     round with a finding, an amber outline for a round not read or late
     (silence is drawn, A3), grey outline before the watch - with its
     words beside it ("40 rounds: 36 clean, 3 with findings, 1 not
     read"). It is what Raqib is: a watchman's rounds, each accounted for.
   - Colour, light / dark: ground #F4F6FA / #111620; card #FFFFFF /
     #1A2130; ink #18212F / #E7EBF3; muted #566179 / #9AA6BA; the rail
     #141C2B in both; action blue #2B59D9 / #7AA2FF for the primary
     button, the selection and focus. Blue is the only accent because
     green, red and amber already mean exit 0, 1 and 3 and stay theirs.
   - Type: Segoe UI Variable, else Segoe UI, on Windows; Inter, Noto Sans,
     DejaVu Sans elsewhere; Cascadia Mono, Consolas, DejaVu Sans Mono for
     record lines and the log only. Four sizes: verdict, card title,
     body, meta. Sentence case; no all-capital labels.
   - Controls: flat buttons, one filled primary per screen; tables with
     tall rows, no grid lines, a quiet header, a tinted selection;
     thin flat scrollbars; a switch for on/off; pills for levels and
     kinds; a disclosure for the watch options and for "could not see
     (N)". Every control is reachable by keyboard and shows focus.
   - Windows: the process declares itself DPI-aware before Tk starts, so
     text is drawn sharp; the title bar follows dark mode. Both act on
     Raqib's own process and window only (A4); where they fail the
     window opens as before and the log says so.
   - Words: the window says things as a person would ("2 trees on this
     host", "14 things Raqib could not see"); the report, the page and
     the terminal keep their texts, which other programs and tests read.
3. **The Rules screen is a list a person can work**: one row per rule
   with a switch, its name and one line of what it watches for, pills
   for kind, severity and origin, its thresholds as steppers within the
   YAML's bounds (the measurement's words beside them, ADR-0008 E), a
   filter box, and "New rule".
4. **A rule made from a form** (amends ADR-0008 decision 4, which stays:
   a YAML file can still be added). The form asks, in a person's words:
   what to watch for - a program is run; a file under a place is
   touched; a network host is reached; a tool is used - the names or
   places; the severity; and two examples, one that must fire and one
   that must not. From these the package writes the rule's YAML (kind
   signature, with the evasions that form always has, stated), and its
   positive and negative fixtures; the loader and the fixture runner
   judge it exactly as they judge a hand-written rule (A6), and it joins
   `~/.raqib/rules.d/` only when they accept it. Before Add, the form
   shows the YAML it will write and what the rule would have fired on in
   the records already under `~/.raqib` ("on your last watches: 3 lines
   of 1,204"): information for the person, read-only, never a gate.
   A user rule can be removed from the same screen; a package rule
   cannot (it is switched off instead). `raqib rules --new ...` and
   `--remove ID` do the same in the terminal.
5. **Nothing here reaches the watched** (A4, ADR-0005): the form writes
   under `~/.raqib/rules.d/` only, through the checks ADR-0008 A-1 set for
   every user rule; a rule of class HOST still cannot be added.

## Consequences
- raqib/app.py's presentation is rewritten over the same Controller,
  Session and RulesPanel logic; custom-drawn controls (switch, pill,
  round strip) live in the window code and are tested without a display
  where they compute, with a display where they draw.
- A new module without Tk for the form's logic (YAML and fixtures from
  the answers); `raqib rules --new` / `--remove`; README's two sections.
- The Table judges the look from screenshots it takes itself (Tk 8.6
  under Xvfb here, the same Tk as windows-latest; the fonts differ) and
  the commander judges it on his machine; CI on Windows remains the run
  of record for sizes.

## Candidates
- M8.1 the look (decisions 1-3).
- M8.2 the rule form and remove (decisions 4-5), after M8.1.

## Amendment A (the Table, 2026-11-10) - rulings on review 2026-11-10-M8.1.md (978ea51)
Builder's record: docs/review/2026-11-10-M8.1-questions.md (Q-1..Q-9).
CI run 42881535680 for 978ea51: four jobs success, both windows gate jobs
failed. Verdict: REDO on A-1..A-4; the Table's rulings A-5..A-15.
- A-1 (CI, must) The window opens on Windows. `ISO_Left_Tab` is an X11
  keysym; Tk on Windows refuses the bind and every screen fails to build.
  Shift-Tab is bound in a form every Tk knows, and a test binds every key
  sequence the window uses through one table whose names are checked
  against the keysyms Tk documents for all platforms. The windows jobs are
  the proof.
- A-2 (P1, must; A3, C-1) The verdict of a running watch is the level of
  the code the watch would end with now, through level_of: a finding,
  alarm; no finding and a hole of the watch, incomplete; neither, clean
  with "Not a clearance.". It is computed by the watch's own rule, not a
  second one: where no pure function gives the code of a state, one is
  added beside finish() / conclude() (scope widened to raqib/host.py and
  raqib/watch.py for that function only, their behaviour untouched) and a
  test holds it equal to the code the watch ends with on every fixture
  state. The sentence says it too ("Watching this host: 3 findings so
  far"). A suspicion never changes the level and is named apart (A2).
- A-3 (P2, must; A3) An overlay's hole is counted where every hole is:
  a malformed rules.yaml, an entry refused at load, a user rule refused
  at load and RulesPanel.error are in "Could not see (N)" on every screen;
  on the Rules screen the verdict is incomplete while any stands, and the
  rail's rules line says "rules: N refused" beside "N off".
- A-4 (P3, must; A3) The strip skips nothing: the round whose reader was
  still out at the end is a not-read cell and is counted; test on the
  finished state. M in "the last N of M" counts the rounds drawn; a round
  in progress is named apart; a round with a suspicion is said in the
  sentence ("2 with a suspicion"), its cell as its findings say (P16).
- A-5 (P4) A failed tick adds its hole to the list it had; nothing leaves
  "Could not see" because a tick failed.
- A-6 (P5) A refused switch or stepper shows the rule's real state at
  once, and the reason beside the row. Test with a refused set.
- A-7 (P6, Q-8) Checks, like every disclosure, open only on a click. This
  supersedes M7.3 E1's "MISSING still shown open": the Table said so to
  the builder on the first screenshot, outside the tree, and says it here.
  The missing count stays in the disclosure's title in the alarm colour
  and each MISSING check is a line of "Could not see". Docstring and test
  name made true.
- A-8 (P7) The rail says the watch's state on every screen: under the
  name, for each running watch, its state in words and its level's pill
  ("Watching the host", "alarm, 3 findings"; "silent for 40 s"), so a
  watch that goes wrong while the person reads the Rules or the Log is
  seen there. Open page is in the rail on every screen.
- A-9 (P8) No test stands on a helper the window does not call: the dead
  helpers go, and C-3's tests assert the paths the window draws, every
  green state of both screens.
- A-10 (P9, P14) The fit is measured on what is drawn: the rail's content
  included, every screen in both modes, each disclosure open on each
  screen that has it; the rail's rules line is bounded (the rest is in
  "Could not see"); the leftover literal pixels go through the scale
  function.
- A-11 (P10) The trees table uses the card's whole width (columns
  stretch with the window); at 900x600 no heading is cut and no level or
  state word ("(new)", "quiet", "gone") is cut; a cell that must be cut
  ends in an ellipsis and its full text is in "Selected tree"; "first
  seen" shows the time (with the date only when it is not today's), as
  the record's own UTC.
- A-12 (P11, P13, P15, P17, P18, P19; Q-3) The table shows focus and is
  in the keyboard test with the nav; pills are not Tab stops (accepted).
  The guard refuses WinDLL, CDLL and __import__ forms outside _win_api,
  and the two calls declare argtypes and restype. THEME's pairs are the
  pairs the styles use (the three missing added). A threshold's value
  can be typed (Enter sets it, measured as a step is). One doctor result
  has one level on both screens. README, docstrings and test names true.
- A-13 (the Table's reading of the screenshots; decision 2)
  (a) A finding is an item, not a report line: the severity's pill with
  its word, the rule's id, its sentence, and a quiet line of where and
  when (round or seq, knock status, cite - A5 keeps the cite). No red
  paragraphs; a status that is absent is not printed (no "[None]").
  (b) Badges: a clean badge is quiet text (no green, no level word); a
  badge that is not clean keeps its colour and its word. Green is the
  verdict's and the strip's. This amends ADR-0008 C-2 for clean badges.
  (c) An open "Could not see" or Checks panel shows as many lines as the
  screen can give (not two) and scrolls beyond; the line its title names
  (the unsure or missing check) is in view when it opens.
  (d) A tree the state marks quiet (ADR-0007 P-2: the tree's `quiet`
  true, with `quiet_round`) is shown with the word `quiet`, never
  `gone`; M7.8 writes the field, M8.1 reads it; a test on a state that
  carries it.
- A-14 Accepted as built: Q-1 (RulesPanel.titles), Q-2, Q-4 with P12 (the
  first-run lines fold while a disclosure is open or the host is
  watched; "Not a clearance." is on every green state without them), Q-5,
  Q-6, Q-7. Q-9 (Windows unverified here): CI's windows jobs for sizes
  and the title-bar call; the commander's machine for what a person sees
  on a scaled display.
- A-15 Every REDO change carries a test for the behaviour it adds (D-8).
