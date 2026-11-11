# ADR-0009 - The window a person likes to open, and a rule made from a form

Status: accepted for decisions 1-3 (M8.1, 2026-11-11; Amendment D); decisions 4-5 open (M8.2). Proposed 2026-11-10 on the commander's order of that day.
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
- A-16 (added 2026-11-11; given to the builder by message during the
  REDO, written here now) No thread outlives a Tk test: each Tk test ends
  the sessions it started and joins their threads (bounded; a failed join
  is an assertion); the shared teardown destroys the root and collects
  garbage on the main thread; a test asserts it. In the window no Tk
  object is created, dropped or finalised from a worker thread. Cause: a
  windows gate job on the M7.8 branch died with a fatal exception while a
  reader thread of a finished Tk test was still running.

## Amendment B (the Table, 2026-11-11) - rulings on review 2026-11-11-M8.1-redo.md (9ba8969)
CI run 42890893708 for 9ba8969: four jobs success, both windows gate jobs
failed on the fit alone (4 failed, 2937 passed). A-1 MET on Windows; A-4,
A-5, A-6, A-8, A-16 MET; the rest PARTLY. Verdict: REDO on B-1, B-2, B-3;
the Table's rulings B-4..B-10.
- B-1 (CI, must; decision 1) The window fits 900x600 on Windows. Measured
  there: the host and project screens ask for 982 and 973 px of width, an
  open "Could not see" for up to 650 px of height. No width in the content
  column may come from a font: entries stretch to their container and ask
  for almost nothing, sentences wrap or end in an ellipsis inside the
  width they are given, rows of controls flow to a second line, the
  table's columns sum to what the card gives. An open panel's height is
  the pixels left on the screen divided by the font's own line height,
  read at run time, never a count of lines assumed from another font.
  When the fit test fails it prints the five widgets that ask for the
  most width and height (class, Tk path, the first words of their text),
  so the windows log names the cause. The windows jobs are the proof.
- B-2 (F1, must; A3) A level that is not known is never clean. While the
  code is not known (the lock held, the first ask) the pill keeps the
  last code known; before any is known it is incomplete, "not judged
  yet". A code that cannot be computed is a hole of the window and the
  watch's own answer for a report it cannot build: alarm. The two tests
  that held a clean pill beside findings are made right, and the
  project path with a known code is tested.
- B-3 (F2, must) On the Rules screen an overlay hole decides the verdict
  before the last change's word does: incomplete while any stands.
- B-4 (F9, F4; A-2 is amended) The code is the watch's, written by the
  watch. The worker writes into its state, where it writes the rest, the
  code it would end with if stopped now (one field; raqib/watch.py and
  raqib/host.py, the state only), computed where the watch already
  builds its report or its result, not a second time for the window; the
  window reads the field and builds nothing on the Tk thread. The field
  says what it is: the code of what has been read so far (finish may
  still add a reader that is out, the last source poll, pending
  findings), and the sentence keeps "so far". Tests on every host
  fixture, with sources, and on the fixture traces.
- B-5 (F3; A-2's guess withdrawn) The pill follows the watch's own rule,
  and the words say why. A-2's "no finding and a hole: incomplete" was
  the Table's guess; where the watch would end with 1 for another reason
  the sentence names it ("1 hole", "1 suspicion"). One state is the
  window's to soften: a project watch that has read no line yet and is
  not yet SILENT by the watch's own state is incomplete, "no line read
  yet", not an alarm at the moment of Start. A raised suspicion makes
  the host watch's code 1 by the host watch's own rule: accepted (A2: the
  model may raise; it raised), named as a suspicion, never as a finding.
- B-6 (F5) One count. The findings the verdict, the rail, the card's
  title and the tray count are the same list from one function, and a
  source's live finding is an item of the card with its cite (A5).
- B-7 (F6, F15, F16) With any disclosure open the table still takes the
  card's width and cuts no state or severity word (the test opens each
  and reads the kind and findings columns); a panel grows with the lines
  that arrive and is scrolled to its named line only when it opens; a
  finished watch's holes are in "Could not see", so the strip's amber
  cell and the count agree.
- B-8 (F7, F8, F13, F12, F14) The test the docstring cites exists: every
  green state of both screens asserts "Not a clearance.". Docstrings
  true; dead code out; the weakened assertions restored (the
  never-a-command-line check reads findings and holes; the empty-trees
  text; no assertion on a constant; no loop over nothing; an exact
  count); the refused step and the typed values that are not a number,
  out of bounds or empty are tested in the window; the fit covers the
  finished screens in both modes.
- B-9 (F10, F11, F17) Recorded: the portable key list is proved on the
  windows jobs, which is where an X11-only name fails. The ctypes guard
  also refuses getattr(ctypes, ...) and ctypes.pythonapi. A refused user
  rule is said as refused in the rail, not also as off, where the
  overlay's own description lets the window tell them apart; else
  recorded for the overlay.
- B-10 Every REDO change carries a test for the behaviour it adds (D-8).

## Amendment C (the Table, 2026-11-11) - rulings on review 2026-11-11-M8.1-redo2.md (claude/M8.1-meet 273f568)
CI: 9024c95 (M8.1 alone) six jobs success; 273f568 (merged with M7.8)
six jobs success: A-1 and B-1 are proven on Windows. B-3, B-6, B-8, B-9
MET; the rest PARTLY. Verdict: REDO on C-1; the Table's rulings C-2..C-8.
- C-1 (G1, must; B-5 was the Table's and it traded an alarm) The one
  softening is narrowed to what it meant: a project watch that has NEVER
  read a line, whose state holds no hole and no finding, and whose own
  word is WATCHING, is incomplete, "no line read yet". A trace that was
  read and is now empty (removed, truncated: the watch restarts and says
  a hole) is the alarm its code says, and the sentence says "the trace
  was emptied or replaced". The state says which: the watch writes
  whether it ever read a line (one field beside `lines`). Tests: Start,
  the first line, then the trace truncated and removed.
- C-2 (G2) A code that cannot be computed is said: the watch writes why
  beside the code (one field), with alarms() and the key inside the
  guard, and the window lists it in "Could not see" and says "the watch
  could not judge itself" - never "its report says".
- C-3 (G3) A red pill names its cause from the watch's own alarms: the
  silence windows, closed ones too ("1 silence window, closed"), and the
  trace's problems ("1 line that could not be read"), counted from the
  state; "Could not see" lists a closed window as it lists an open one.
- C-4 (G5, G6, G7, G11) A badge too long for its line ends in an
  ellipsis and its whole text is a line of "Could not see". A window that
  comes back on the screen re-lays its open panel (the Map event, from
  KEYS). A finished watch's holes are read from the watch's final state,
  not from the last tick that happened to read it. A failure inside the
  panel's layout cannot stop the tick: the tick always schedules the next.
- C-5 (G9, G10; where the window meets M7.8) The Selected tree pane
  counts what its row counts (source findings by their words, notes on a
  benign tree as notes) and says the tree's own words from the state:
  the benign word and what knocked on it, quiet and its round, "not
  judged this round", the events before the start. A source finding
  pending at exit is the alarm the watch counts. The Final report pane
  colours SOURCE FINDINGS and NOT SETTLED as it colours FINDINGS.
- C-6 (G4, recorded with a number asked for) The host's state computes
  its result on each read. Before it is changed it is measured: a test
  times state() on a watch with a thousand source findings and says the
  figure in the questions file; the Table rules from the figure (A7).
- C-7 (G8, G12, G13, G14, G16) The host's finished sentence is the
  host's. The held-lock path has a test with a real lock; the argv check
  reads the detail too; the typed value is tested through the Enter
  binding; real HostWatches in the window's tests are ended by M7.8's
  helper. The strip's docstring true. The rhythm cell shows a suspicion
  first when there is one, so an ellipsis cannot hide it (A2). The guard
  refuses an alias of ctypes.windll.
- C-8 Accepted or recorded: G15 (pre-existing: the Rules verdict after a
  change; with C-1's care, later), G17 (answered in the packet's
  addendum), G18 (measured at two fonts; the commander's display is the
  third). Every REDO change carries a test (D-8).
- Table ledger: B-5's softening was the Table's own, and it made a
  deleted trace amber. Third time in this run the Table cured a false
  alarm by loosening a rule without asking what else the looser rule
  lets through (R-1, B-5). The cure is always the narrowest state that
  is known to be harmless, named by the watch, not inferred by the window.

## Amendment D (the Table, 2026-11-11) - judgement on M8.1 (978ea51 + 9ba8969 + 80ccc04 + 30d194e; the Table's 9024c95, 273f568)
- C-1..C-5 and C-7 MET as cited in the "## REDO 3" section of
  docs/review/2026-11-10-M8.1-questions.md. The Table read C-1 and C-2 in
  the code: the watch writes `ever_read` (true at the first line, never
  reset by a restart) and `code_error`; the window softens only
  never_read(state, word) - ever_read False said by the watch, no hole,
  no finding, the word WATCHING - and a state without the field is not
  softened; alarms() and the key are inside the guard. C-1's test drives
  a real watch through Start, the first line, a truncated trace and a
  removed one.
- C-6: HostWatch.state() with a thousand source findings takes about
  1.1 ms (median of five, this box). Nothing is changed (A7: measured).
- CI, read from api.github.com and the job logs. 978ea51: both windows
  jobs failed (the X11-only keysym; the window did not build). 9ba8969:
  the window builds on Windows, the fit fails (982 px of 900; up to 650
  of 600). 80ccc04: the width fits, the height does not (up to 687 with
  "Could not see" open). 9024c95 (the Table: off the screen a panel takes
  the minimum size's lines): six jobs success. 273f568 (merged with M7.8):
  six success. 30d194e (REDO 3): five success, the windows 3.12 gate
  failing one test this task does not touch, tests/test_rhythm.py::
  test_e3_named_and_benign_trees_are_never_sent, which looks for the
  digits of a pid in a prompt that carries sha256 hashes: one hash held
  "5500" by chance. The Table's fix looks outside the hashes; the commit
  with this amendment is the run of record.
- Gate on the merged branch: 3056 passed, 62 skipped; with Tk 8.6 under
  Xvfb 3104 passed, 14 skipped. Scope: raqib/app.py, tests/, README, and
  in raqib/host.py and raqib/watch.py the state's fields only
  (code_so_far, code_error, ever_read), as A-2, B-4, C-1 and C-2 widened
  it. Four builder commits (G-8), three packets, three sets of rulings,
  and three commits by the Table.
- What M8.1 leaves true: a rail, a verdict in a sentence with its level
  and one primary action, cards; the round strip, every round accounted
  for; a running watch's level is the level of the code it would end
  with, written by the watch, never clean while unknown; every hole is
  counted in "Could not see"; findings are items with their cites; rules
  are rows with a switch and steppers; the window opens and fits 900x600
  on Windows, sharp on a scaled display by the two calls on its own
  process and window; no thread outlives a Tk test; the window reads
  M7.8's state as the watch's own rule counts it.
- Not proven by anything here, the commander's to see: what the window
  looks like on his display (the screenshots are Tk 8.6 under Xvfb with
  another font); DPI awareness on a scaled display; the dark title bar;
  an open panel's height in a window that is on the screen (CI measures
  a withdrawn one).
- Recorded for later: Q-10 (a column to drop at 900 px); G15 (the Rules
  verdict after a change, with a rule off); G18 (rows that take their
  width from their words at a larger system text size); a way for the
  person to name a program benign (ADR-0007 X-5's knock per image is the
  stopgap).
- Verdict: **NEXT**. Merge --no-ff into main under the commander's
  standing word. Decisions 1-3 are built; decisions 4-5 are M8.2.
- Table ledger for M8.1: three reviews, three REDOs, three Table commits.
  The Table's misses: the HANDOFF's E6 asked for the fit "measured on
  windows-latest" and nothing asked that the window be BUILT there first
  - the first Windows run of a rewritten window found it could not open;
  B-5's softening keyed on a count (C-1); A-2's guess about a hole's
  level (B-5). What worked: CI's windows jobs as the run of record, and
  a fit test that names the widest widget when it fails.

## Amendment E (the Table, 2026-11-11) - rulings on review 2026-11-11-M8.2.md (9616878)
Builder's record: docs/review/2026-11-11-M8.2-questions.md (Q-1..Q-7). CI
run 42925338265 for 9616878: six jobs success on the first commit.
Verdict: REDO on E-1 and E-2; the Table's rulings E-3..E-10. Each ruling
names the case it is for and what it must not touch (ADR-0007 Z-9).
- E-1 (P1, must) Nothing a person types can end the form in anything but
  an answer. For: every typed text (the title, a name, a place, a host,
  a tool, an example) is checked to be text the rule file can carry and
  read back; what is not is a refusal beside its field ("a character
  this file cannot hold: ..."). And whatever fails inside the form that
  is not a refusal becomes one ("the form could not write this rule:
  <why>"), in the window and in the terminal (exit 2), never a traceback.
  Must not touch: text the file can carry stays allowed as typed.
- E-2 (P2, must; scope widened to raqib/host.py for this) A rule judges
  the lines it says it reads. For: the host watch gives a file of host
  lines to every rule whose match names the tool HostChild - NET-TOOL,
  DESTRUCT-CMD and a person's program rule alike - chosen by that
  property, not by a list of ids. Must not touch: a rule that does not
  name HostChild is still not run on host lines (it could only say it
  cannot judge); the package rules' findings on the shipped host fixtures
  are unchanged. "On your records" judges a file only with what a watch
  would judge it with. The tool form says the lines it reads (a hook's
  and a proxy's tool lines), not "every tool line".
- E-3 (P3) A program is matched as typed and as capture lower-cases it:
  where the two differ the rule holds both, and the field says so ("also
  matched as r"). Must not touch: a name typed in lower case makes the
  rule it made before.
- E-4 (P4) A place a person can type fires where a tool is aimed: a
  place beginning with ~ is written both as typed and with the home it
  stands for on this machine, said beside the field; the hint's example
  is a whole path. Must not touch: an absolute place is written as typed.
- E-5 (P5) Removing takes a deliberate second act: the confirmation's
  focus is on "Keep it"; Enter on Remove opens the confirmation and never
  deletes; leaving the screen withdraws a pending confirmation. Tested
  with key events.
- E-6 (P6, P12, P13, P14) A user rule that did not load is still a row
  ("refused at load: <why>") with its Remove. Remove drops the overlay's
  lines first and the folder second, and says exactly what remains if
  the second fails; it refuses when rules.d or its parent is a link or a
  reparse point, as staging does. Ids are compared without regard to
  case against the folders in rules.d and the package's ids.
- E-7 (P7, Q-1; scope widened to raqib/rules/engine.py for the word) A
  person's rule is of class USER: the word joins engine.CLASSES before
  HOST, and the form's rules carry it. Must not touch: every package
  rule's class; a rule of class HOST is still refused for a person.
- E-8 (P8, Q-2; A6) A person's rule declares what its fixtures can
  measure: it must fire on its firing example and on none of its quiet
  ones, and it says so (fp_budget 0 on its own examples; the report and
  the form say "measured on the examples you gave, not on a corpus"). A
  quiet example that this form's rule could never fire on (another
  system's path, a thing of another kind) is refused beside its field:
  a negative must be able to fire.
- E-9 (P9, P10, P11) Reading the records refuses reparse points as the
  fixture paths do, walks a bounded number of entries (said), and the
  form says "testing..." before it reads. Staging folders left by a
  crash are swept at the next Test, and their count said.
- E-10 (P15, P16) The tests P15 names are made true (a host-source file
  of real HostChild lines; the dry run on fixture traces; a running
  watch; rmdir in the census; an allow-list guard on ruleform). The
  words P16 names are made true ("fixtures", "1 file", the staging
  place said); the form never shows "not tested yet" beside an enabled
  Add; the YAML preview can be reached and read by keyboard; --json with
  --new is refused; --remove's help says it deletes without asking, and
  --dry-run says what it would delete; the missing evasions are written.
  The form's pill says "passed" or "refused", not the exit code's words.
  Q-3, Q-5, Q-6, Q-7 accepted as built with the above; Q-4 (`.exe` on
  Bash lines) is E-3's rule: as typed and as lower-cased, no suffix
  guessed.
- E-11 Every REDO change carries a test for the behaviour it adds, and
  for the case it must not touch (D-8, Z-9).

## Amendment F (the Table, 2026-11-11) - rulings on review 2026-11-11-M8.2-redo.md (4710945)
CI run 42931272861 for 4710945: both windows gate jobs failed one test
(the path form). E-1, E-4, E-5, E-7 MET; the rest PARTLY. Verdict: REDO
on F-1..F-4. Each ruling names the case it is FOR and what it MUST NOT
TOUCH, and both are tested (ADR-0007 Z-9).
- F-1 (CI, must) A `~` place on Windows is one path, not two halves. The
  home a `~` place stands for is written with the separators of that
  home throughout, and the prefilled examples are of the same system as
  the place. `home_of` takes the home and the system as arguments, so
  the Linux gate tests the Windows shape and the Windows jobs the POSIX
  one. FOR: `~/.aws` with a home `C:\Users\user` is held as typed and as
  `C:\Users\user\.aws`. MUST NOT TOUCH: on POSIX exactly as now.
- F-2 (R1, must; Q-4 as ruled) A program is matched as typed, as typed in
  lower case, and as capture names an image (discover.image_name); the
  distinct ones, in that order of need. FOR: `curl.exe` passes Test with
  its own prefilled example, fires on a Bash line `curl.exe ...` and on
  an os or host line whose image is curl. MUST NOT TOUCH: `terraform`
  gives [terraform] and `R` gives [r, R], the rules they gave before.
- F-3 (R2, must) Remove acts on the row's own place, never on a name
  looked up again. A row carries the place it came from (a folder or a
  loose file of rules.d); its widgets are keyed by that place; Remove
  deletes that place and nothing else, and drops an overlay entry only
  when the place removed is the loaded rule's. `taken_ids` counts loose
  files, so the form cannot make an id a loose file holds. The terminal's
  `--remove NAME` takes the exact name first; with no exact match, one
  match without regard to case; with several, it refuses and lists them.
  FOR: a refused loose MY-TF.yaml beside the loaded MY-TF/ - Remove on
  the refused row deletes the file; the loaded rule, its folder and its
  entry stay. And MY-TF beside my-tf on a file system that keeps both.
  MUST NOT TOUCH: one rule, one row, removed as now. A row that is not a
  rule file or a rule folder Raqib could have written (a folder whose
  name is no id) gets no Remove: the row says to delete it by hand, with
  its path. Ids are folded as the engine folds them (ASCII, C-11).
- F-4 (R3, must) A Remove that deletes nothing changes nothing, and says
  so. Order: every check first (links, the real place) with nothing
  written; then the rule file, so the rule can no longer load; then the
  rest; the overlay entry is dropped only once the rule file is gone.
  FOR: a rule switched off whose folder cannot be deleted at all stays
  off, its folder and entry whole, and the words are "nothing was
  removed: <why>". A removal that fails midway says what is gone and
  lists what remains; that rule no longer loads. MUST NOT TOUCH: a
  removal that succeeds reads as now. The dry run says what the real
  run would do, a refusal included (R18).
- F-5 (R7) Remove follows what Add follows. A linked ~/.raqib or rules.d
  (a folder kept on another disk) is followed by both, and Remove names
  the real place it deleted in; a link BELOW rules.d is refused by both,
  nothing written or deleted. This supersedes E-6's refusal of a linked
  ~/.raqib. FOR: with ~/.raqib a link, the form adds and Remove removes.
  MUST NOT TOUCH: _delete_tree's checks below the rule's folder.
- F-6 (R4; scope: raqib/host.py, that filter only) The pre-M7.8 note
  hides only the notes of the rules it names. FOR: a person's rule that
  could not judge old os lines keeps its "could not judge N lines".
  MUST NOT TOUCH: NET-TOOL's and DESTRUCT-CMD's same-cause notes stay
  folded into that one note.
- F-7 (R5, R6, R11) "On your records" says what it read and what it did
  not. A file is a file of host lines by its lines, not by its folder:
  an os source file is judged as the watch judges it and its lines are
  counted. Every link, unreadable entry and bound met is counted and
  said ("3 file(s) not read: a link"); never "no file yet" when files
  were refused. A failure while reading the records is words of that
  step ("your records could not be read: <why>") and never undoes a
  passed Test. The sweep of left-over form-* folders says what it could
  not remove and leaves a folder younger than ten minutes alone (another
  Test may own it). MUST NOT TOUCH: the bounds, and a folder not named
  form-*.
- F-8 (R8) Every user rule's line at the watch's start and in the report
  says how it was measured: "measured on its own examples only (N), not
  on a corpus". MUST NOT TOUCH: a package rule's line.
- F-9 (R16) A person's home does not travel in a title. The default
  title and the description name the place as typed (`~/.aws`); the home
  is in the match only, in the file under ~/.raqib. Tested: no default
  title or description holds the home. A title the person typed is theirs.
- F-10 (R10, R17, R18) The words are true: the `~` evasion is rewritten
  (it now names what is still missed: another user's home, a relative
  path); the docstring, cli.py:25 and :127 and the usage line follow the
  code. `~user/...`, a home that cannot be carried and a home too long
  are refusals or said notes, never silence. The form's header says "changed since the
  test: test again" once a field is edited after a passed Test. The tool
  form refuses HostChild, process, net and file as tool names with words
  (those lines are not hook lines). No call deprecated in Python 3.12.
- F-11 (R9, R13, R14, R15) Tests: a Tk test with a watch running (P15);
  "testing..." shown; a failure after staging began (E-1's unstaging,
  not vacuous); the package-findings test pins findings, not a list
  recomputed beside itself; test_e3's count is exact again; the dead
  helper goes. The allow-list resolves import aliases and has no entry
  the module does not use. A gate test: no catalog rule declares class
  USER. Link refusals on Windows are tested where the job can make a
  junction (mklink /J needs no privilege) and skipped with the reason
  where it cannot.
- F-12 Recorded: R12 (a hand-written rule that names HostChild shares
  the host-line poll with NET-TOOL; a regex that never ends stalls that
  poll, as it already could on a trace feed: the Table writes the line in
  THREAT_MODEL at the merge); R15's rest (`--add FILE` of any class but
  HOST is accepted, as before M8.2).
- Table ledger: E-6 ordered "the overlay entry first" for a crash and
  made a failed Remove switch a rule back on; and it refused a linked
  home in Remove alone. A ruling about an order names what holds if the
  second step never happens.

## Amendment G (the Table, 2026-11-11) - rulings on review 2026-11-11-M8.2-redo2.md (5e5c956)
CI run 42940006079 for 5e5c956: both windows gate jobs failed one test
(S1). F-1, F-2, F-4, F-6, F-8, F-9, F-10 MET; F-3, F-5, F-7, F-11 PARTLY.
Verdict: REDO on G-1..G-4. Each ruling names the case it is FOR and what
it MUST NOT TOUCH, and both are tested (ADR-0007 Z-9).
- G-1 (S1, must) A test of two names a case apart asks the file system
  first: where it does not keep both, the test skips and says so, before
  it makes anything. The builder's record then says which tests depend on
  the system that runs them, truly.
- G-2 (S2, must; Q-10 ruled) The terminal removes what was named, never
  a neighbour of it. `--remove NAME` names one entry of rules.d as it is
  listed: a NAME without a suffix is a folder, a NAME ending .yaml is a
  loose file; the exact name first, else the one entry of that kind that
  matches without regard to case; several: refused, all listed, none
  suggested. A stem is never matched across kinds. FOR: `--remove
  MY-TF.yaml` with no such file and a loaded MY-TF/ removes nothing and
  says there is no such file. And Q-10: a NAME that is a package rule's
  id removes the entry of rules.d of exactly that name where there is
  one, saying "the package rule NAME is untouched" - its overlay entry
  (the package rule's own setting) is never dropped by this. MUST NOT
  TOUCH: `--remove MY-TF` of one loaded rule reads as now; a package id
  with no such entry in rules.d is refused as now.
- G-3 (S3, must) "On your records" never says more than it read. "read:
  every file" is said only when nothing was refused, cut or bounded;
  each bound met is said also when no file was judged; what was not
  read is counted as what it is (a file, a folder: "1 folder not read: a
  link"); a file is called by what it holds, not by where it lies. FOR:
  the three cases of S3, each with its exact words. MUST NOT TOUCH: with
  nothing refused and no bound met the words read as now.
- G-4 (S4, must) README says the Remove that is built: the rule file
  first, the overlay entry after, and which rows have no Remove.
- G-5 (S5, S8) Remove never walks into a link. The plan looks at each
  directory before it enters it and refuses at a link, a junction or any
  reparse point, by its own name; and whatever fails in Remove or in
  drawing the rows that is not a refusal becomes one, with words, in the
  terminal (exit 2) and in the window - never a traceback, never
  nothing. FOR: a junction inside a rule's folder, tested on Windows
  with a junction made by the test whether or not the job can make
  symlinks; a path on another drive; an entry that cannot be read.
  MUST NOT TOUCH: nothing is deleted in any refused case; a folder with
  ordinary sub-folders is removed as now.
- G-6 (S6, S7, S12; Q-15 ruled) The words of a Remove fit its case: a
  loose file is not "its folder and its overlay entry"; a folder that
  had no rule file is not said to "no longer load"; an overlay entry
  that could not be dropped is listed with what remains; a stop midway
  is not shown under a word that says it was removed whole. A link named
  as a rule in rules.d is said as a link (the test matches those words,
  not a folder's name). The Rules header names a refused loose file by
  its file name. The real place is said wherever it differs from the
  path written (Q-15: always).
- G-7 (S10, S11) After a change the preview and "on your records" are
  marked as the last test's, not the form's present state. A row that
  says "delete it by hand" can be reached by Tab and its path can be
  selected and copied. MUST NOT TOUCH: the fit at 900x600.
- G-8 Questions ruled as built: Q-8 (image, lower case, typed: F-2's
  "in that order" was the Table's loose wording); Q-11 (the entry of a
  refused place is left alone and said); Q-13; Q-14. Q-9: the words are
  "measured on its own fixture files only (N), not on a corpus" - a
  count is named by its unit (ADR-0007 AB ledger). Q-12: accepted; the
  test proves the window's words, and that a running watch keeps the
  rules it started with is the watch's own, recorded for M8.3.
- G-9 Recorded: S9 (two Tests at once in two processes can remove the
  staging root between one's makedirs and its mkdtemp; that Test ends as
  "the form could not write this rule" and can be run again); S13's
  three notes are tidied where the builder passes.
- Table ledger: F-3 gave the terminal "the exact name first" and did not
  say what a name with a suffix names; the build matched stems across
  kinds. A ruling that takes a name from a person says what kind of
  thing each form of the name can be.
