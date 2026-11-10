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
