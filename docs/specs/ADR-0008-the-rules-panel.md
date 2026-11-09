# ADR-0008 - The rules panel: the person chooses what Raqib watches for, and Raqib says what is off

Status: accepted (M7.6b, 2026-11-09; Amendment D). Proposed 2026-11-09 on the commander's plan of 2026-11-04.
Amendments appended, never edited in place.

## Problem
The commander's plan after the first field run: a control panel in the
window to add and enable Raqib's rules for watching, with improvements
to the window's look. Today the catalog is read from the package; a rule
is on unless its YAML says `status: disabled` (engine, A6); the thresholds
that matter in the field (HOST-RHYTHM's K/W/R, AGENT-DARK-LIVE's streak
and window, NEW-AGENT's benign list) are declared in the YAML and read
from it, so the only way to change them is to edit a file inside the
installed package. A person who cannot turn a noisy rule off turns Raqib
off.

## Decision
1. **A rules panel in the window** (and `raqib rules` in the terminal):
   every catalog rule listed with its id, kind, class, severity, budget,
   status (on / off), and the thresholds its YAML declares as `eq`
   values; on/off per rule and a threshold edit per declared value, with
   the YAML's own bounds. The engine's existing `status: disabled` is the
   switch; nothing new is invented in the engine.
2. **The person's choices live outside the package**, in
   `~/.raqib/rules.yaml`: an overlay (rule id -> status, thresholds), never
   a copy of the catalog. The catalog stays the package's and is read as
   today; the overlay is applied on top at load, and every applied line
   is printed at the start of a watch and kept in watch.json / the host
   state under `rules_overlay`. A malformed overlay is a hole and is
   ignored, never half-applied.
3. **A rule off is said, not silent (A3, A6):** the report, the page's
   band and the window's header carry "N rules off: <ids>"; the final
   report lists each with who turned it off (the overlay) and since when;
   a watch with every rule of a kind off says so in words; the exit code
   is unchanged by the overlay (off rules do not make a watch CLEAN of what
   they would have found: the report says "not judged by <id> (off)").
4. **Adding a rule** means pointing at a YAML the person wrote: the panel
   takes a file, validates it with the engine's loader and the fixture
   runner (every rule has fixtures, positive and negative, with a
   measured budget - A6 holds for the person's rules as for ours), and
   copies it under `~/.raqib/rules.d/`; a rule that fails validation is
   refused with the loader's reason. Rules under rules.d join the catalog
   at load, marked `origin: user` everywhere they are shown.
5. **Control stays in the program the person sits at** (ADR-0005): the
   page shows the overlay and never edits it; the panel edits the overlay
   file only; nothing in it reaches a watched process or project (A4).
6. **The window's look**: one pass over spacing, typography, the band and
   table colours by the exit-code scheme (F-7), the tray tip, and a
   first-run text that says in three lines what the window shows; the
   deterministic doctrine is on the first screen in one sentence.

## Consequences
- New `raqib/overlay.py` (read, validate, apply, write); `raqib rules
  [--set ID on|off] [--threshold ID FIELD VALUE] [--add FILE]`; the
  panel in app.py; `rules_overlay` in watch.json and the host state; the
  band item; the report lines.
- CI: a test that an overlay turning a high rule off still lists what
  that rule would have found as "not judged (off)" on the fixtures.

## Candidates
- M7.6 the overlay, `raqib rules`, the panel, "rules off" everywhere.
- M7.6b the window's look pass (after M7.6, so the look is of the real
  screens).

## Amendment A (the Table, 2026-11-09) - rulings on review 2026-11-09-M7.6.md (5dca13a)
Builder's record: docs/review/2026-11-09-M7.6-questions.md (Q-1..Q-14).
CI run 42571454875 for 5dca13a: six jobs success on the first commit (the
Tk Rules test ran on windows). Verdict: REDO on P1; the Table's rulings
A-2..A-9; the rest recorded.
- A-1 (P1, A4, decision 5) `--add` copies nothing whose destination is not
  under `~/.raqib/rules.d/<rule>/` by realpath after joining: fixture paths
  in a user YAML must be relative, contain no `..`, no drive, no `\\` or `/`
  root, no reparse point on the way (the M7.2b I-1 check), on every OS
  (ntpath rules checked too); a YAML that names any other path is refused
  whole with the path quoted. Every later load reads fixtures only from
  under rules.d by the same check. Tests with the reviewer's probes
  (`..\..\AppData\...\Startup\x.json`, `C:/Users/Public/x.json`) under both
  path rules; the A4 AST test asserts the realpath guard, not a text match.
- A-2 (P2, Q-4) A watch where an off rule would have fired is not CLEAN:
  the result word is "CLEAN (N findings suppressed by the overlay)" with
  exit 0 kept (the person turned it off), the band item turns red while
  the suppressed count is non-zero, and the final report's RULES OFF
  section comes first when it suppressed anything. The exit code stays the
  person's choice; the words do not.
- A-3 (P3, P4, A6) A changed threshold is measured: on `--threshold` and
  at load, the overlaid rule is run on its own fixtures; a threshold under
  which a positive no longer fires, or a negative fires, is refused with
  the fixture named ("k=5: positive-3-cycles no longer fires"). A rule
  that can never fire under its thresholds (k > the rounds r can hold) is
  refused the same way. r's second role (how often the suspect layer is
  asked) is split: the suspect period is its own eq field, `suspect_every`.
- A-4 (P5) A user rule listing one fixture as both positive and negative
  is refused (the loader's check; budgets do not excuse it).
- A-5 (P6) A user rule refused at load is counted in "N rules off" with
  the reason "(refused: <why>)" in the band, header and report.
- A-6 (P7) A HOST-class user rule is refused at `--add` with "host rules
  are fixed in v1" until the host watch loads user rules (a later task).
- A-7 (P8) `raqib rules TRACE`, `report` and `ui` print one line when an
  overlay file exists: "an overlay exists at <path>; this command judges
  the catalog as declared" - the line the Table's Q-2 ruling owes.
- A-8 (Q-1) The built-in bounds stand for v1; the YAML `bounds:` block is
  the Table's later task; recorded. Q-2 (which commands apply the overlay)
  ratified with A-7. Q-3, Q-5, Q-6, Q-7 ratified. Q-8's `--remove`: a
  later task. Q-9..Q-14 recorded; Q-12 (the panel's plain look) is M7.6b.
- A-9 Every REDO change carries a test for the behaviour it adds (D-8).

## Amendment B (the Table, 2026-11-09) - judgement on M7.6 (5dca13a + 6b9f1c2)
- A-1..A-7 MET as cited in the REDO section of
  docs/review/2026-11-09-M7.6-questions.md; the Table read the A-1 delta
  (fixture_file: both ntpath and posixpath joins, no link at any step,
  realpath under the rule's own directory; engine.py refusing roots,
  colons and `..` under either separator) and the A-2 delta ("CLEAN (N
  findings suppressed by the overlay)"). Every REDO change names its test.
- CI, read from api.github.com: runs 42571454875 (5dca13a) and 42573710061
  (6b9f1c2), six jobs success each; the Tk Rules test ran on windows.
- Gate on the branch: 2826 passed, 20 skipped; kinds 4 : 7 : 11. Scope as
  widened by A (engine.py's path check; HOST-RHYTHM.yaml's suspect_every).
  Two commits (G-8).
- Q-15 (the Table's own consequence): A-3 measures a changed threshold on
  the rule's fixtures, and the fixtures encode the exact declared values
  (k=3, w=30, r=10, streak 3, window 9), so every change to them is
  refused, and an installed raqib has no fixtures at all. As merged, the
  panel can turn rules off and set suspect_every; it cannot tune the
  thresholds the commander asked to tune. Ruling: this is honest (A6) and
  stands for this merge; the way through is M7.6c "thresholds that can be
  measured": fixtures generated at the new values by make.py's generators
  (the host fixtures are synthetic and parametric already), shipped with
  the package as package data so an installed raqib can measure, and the
  bound of each threshold declared in the YAML (`bounds:`, the Table's
  block). Until then the panel says "thresholds: measured against the
  shipped fixtures; a change that the fixtures cannot carry is refused".
- Q-16 (engine.py writes the Windows path rules out by hand; `\` in a
  user fixture path refused): accepted. Q-17 (flat-layout rules from
  5dca13a are refused and counted off): accepted, nothing shipped between.
- Decisions 1-5 of this ADR are built; decision 6 (the look) is M7.6b.
  Status: proposed until M7.6b lands.
- Verdict: **NEXT**. Merge --no-ff into main under the commander's order.
- Table ledger for M7.6: one review, one REDO; the Table's miss: A-3 as
  written made the panel's thresholds unchangeable in practice (Q-15) -
  the ruling measured without providing what to measure against.

## Amendment C (the Table, 2026-11-09) - rulings on review 2026-11-09-M7.6b.md (a059505)
Builder's record: docs/review/2026-11-09-M7.6b-questions.md (Q-1..Q-10).
CI run 42577138324 for a059505: six jobs success on the first commit (the
Tk look tests ran on windows under Tk 8.6). Verdict: REDO on P1, P2 and
P5; the Table's rulings C-4..C-6; the rest recorded.
- C-1 (P1, F-7) Every band and badge level comes from one function of the
  exit code (0 clean, 1 alarm, 3 incomplete) and the result word - the
  project watch's FINISHED band included; "[alarm]" never stands beside
  an INCOMPLETE report. Test on exit 3.
- C-2 (P2, A-2) The (level, text) badges keep their level: each badge is
  its own label in its level's colour with its word; the suppressed badge
  is red on the project and host screens as in the header. Test.
- C-3 (P5, A3, Q-1) "Not a clearance." stands in every green state on
  every screen: the project screen's WATCHING clean and FINISHED exit 0,
  and FINISHED with suppressed findings reads "[clean] (N findings
  suppressed by the overlay). Not a clearance." Test per state.
- C-4 (P3, Q-2) The tip is the host watch's: "Raqib: N trees, K new, F
  findings" only while the host is watched; with a project watch only,
  "Raqib: project <name>, F findings"; "Raqib: idle" otherwise; F counts
  findings, and suspicions are named apart ("+S suspicions") when any.
  The test's name is true again.
- C-5 (P4, Q-3, F-3) The footer keeps F-3: the look's holes persist there,
  each one, until round 1 replaces them - in a scrollable footer bounded
  to three lines with "(N more)" and the full list one click away on the
  Host screen; the one counted line is not enough for a hole (A3).
- C-6 (P6, E6) The colour test matches Tk's full colour-name list (the
  names Tk documents, including grayN/greyN) and refuses a colour built
  by string formatting outside THEME (any f-string or % or .format whose
  result is passed to a colour option). A dark-mode Tk test builds each
  screen once in dark mode; the selected red row in dark mode gets a
  contrast of at least 4.5:1 (THEME value adjusted).
- C-7 (P8) The window's sort goes through the tested sort_rows; "-" sorts
  last in both directions; the selection survives a refresh (test).
- C-8 (P7, P9..P14) Recorded: the 900x600 margin measured on windows is
  this CI run's; the trailing blank lines; the detail pane shows what the
  table printed before.
- C-9 Every REDO change carries a test for the behaviour it adds (D-8).

## Amendment D (the Table, 2026-11-09) - judgement on M7.6b (a059505 + c9486c4 + b5dc8b4)
- C-1..C-7 MET as cited in the REDO section of
  docs/review/2026-11-09-M7.6b-questions.md; the Table read the C-1 delta
  (level_of(code, word): the one function; exit 3 is incomplete, amber)
  and the C-3 texts. Every REDO change names its test (C-9).
- CI, read from api.github.com: run 42577138324 (a059505) six success; run
  42579340870 (c9486c4) four success and both windows gate jobs failed one
  test - the 900x600 fit: on Windows Tk 8.6 the project watching screen
  with its log requested 897x628 where Xvfb/Tk 9 had measured 728x511 (the
  test was right, the screen clipped on the commander's OS); run
  42580221150 (b5dc8b4, the layout follow-up: shared panes, fewer fixed
  lines, no change to the minimum size or the test) six success.
- Gate on the branch: 2854 passed, 22 skipped; kinds 4 : 7 : 11. Scope
  clean (presentation only; the one logic touch, the tip's condition, was
  ruled back to the host's by C-4). Three commits (G-8).
- Lesson for the ledger: Xvfb with Tk 9 is not the run of record for the
  look; windows-latest with Tk 8.6 is, and every size claim is measured
  there (the follow-up's table of Windows numbers is the record).
- Decision 6 is built. Status of this ADR: **accepted (M7.6b, 2026-11-09)**;
  decisions 1-6 stand; Amendments A-D are the record; M7.6c (thresholds
  that can be measured, Amendment B) is the open candidate.
- Verdict: **NEXT**. Merge --no-ff into main under the commander's order.
- Table ledger for M7.6b: one review, one REDO, one CI follow-up; the
  Table's miss: the HANDOFF's E5 "900x600 without clipping" did not say
  "measured on windows", so the builder measured under Xvfb.

## Amendment E (the Table, 2026-11-09) - rulings on review 2026-11-09-M7.6c.md (7e36dec)
Builder's record: docs/review/2026-11-09-M7.6c-questions.md (Q-1..Q-14).
CI run 42584260231 for 7e36dec: install jobs success; all four gate jobs
failed one test - the byte-for-byte check of the shipped host data, which
embeds the builder's absolute checkout path (P1; the follow-up was ordered
before this ruling). Verdict: REDO on P1 (in flight) and P2; the Table's
rulings E-3..E-8; the rest recorded.
- E-1 (P1, A9, E1/E5) Every path in generated or shipped data is relative
  to the repository root, from one helper; a test greps package data and
  fixtures for `/home/`, `/Users/`, `C:\Users` and refuses any.
- E-2 (P2, A6) "Measured" means sensitive: a threshold is editable only
  when at least one generated fixture changes outcome across the field's
  bounds (the generator must produce, for each editable field, a positive
  that stops firing just past the value and a negative that starts firing
  just short of it - the edge pair); a field with no edge pair is FIXED,
  shown as such in `raqib rules` and the panel, and refused on set with
  "not measurable: no fixture is sensitive to <field>". By the review's
  probes that makes live_window, suspect_every, w and r FIXED until the
  generator earns them edge pairs: w needs an act at W+1 (Q-3) and an act
  at W; r needs a cycle that falls out of the window at r-1; live_window
  needs a dark streak that starts inside vs outside the window;
  suspect_every is not a rule threshold at all (E-3). k keeps its edges
  and stays editable. The words "measured at <field>=<v> ... fp rate 0" are
  printed only for a sensitive field.
- E-3 (Q-7) suspect_every leaves the rule: it is a watch option
  (`--suspect-every N`, the window's suspect field), not an eq value of
  HOST-RHYTHM; the YAML line goes; the overlay does not carry it.
- E-4 (P3, Q-2, A8) The arrivals are SYNTHETIC (their run.json says so);
  the HANDOFF's "real exports" was the Table's error, recorded here. "Would
  fire on a benign desktop" is a measure only when a real desktop's export
  exists: the commander's Windows machine is the first (Amendment M's
  machine); until a real export is shipped with his consent the arrivals
  are named "synthetic desktops" everywhere they are counted.
- E-5 (P4, K-9) Fixtures that cannot fire a rule are not counted among its
  measured negatives (HOST-RHYTHM back to 5; AGENT-DARK-LIVE likewise).
- E-6 (P5, Q-4) The bounds are the fence and the measurement the gate;
  a refusal names both the fixture and the condition ("r must be >= k+2:
  an os act is read one round late"); `raqib rules` shows the effective
  range the measurement accepts beside the declared bounds.
- E-7 (P6, Q-10, A3) The measurement at load runs only when the overlay
  changed since the last measure (a hash of the overlay file and the
  catalog kept in ~/.raqib/rules.measured.json with the result); while it
  runs the watch prints "measuring the overlay's thresholds..." and the
  window shows it in the band; the Rules panel measures on set, not on
  every reload.
- E-8 (P7, A1, Q-11) raqib/rules/ does not import the model layer:
  fixturegen takes the round builder as a parameter (host.py passes it;
  the rules package never imports host, suspect, notify, subprocess or
  http); the A1 test walks the import graph of raqib.rules after a
  generate (sys.modules diff), not the file text; `_socket` and
  `socketserver` join the forbidden names.
- E-9 (P8) The README assertion is restored as a test, not a comment.
- E-10 (P17) raqib/rules/hostdata/ is ratified into Scope by this ruling.
- E-11 Every REDO change carries a test for the behaviour it adds (D-8).

## Amendment F (the Table, 2026-11-09) - judgement on M7.6c (7e36dec + 819f5f3 + 42f457f)
- E-1..E-9 MET as cited in the REDO sections of
  docs/review/2026-11-09-M7.6c-questions.md; the Table read the E-2 tests
  (an edge pair per editable field, generated at the low end, the declared
  value and the high end, and run at both neighbours: k 2/5/8, w 1/30/3600,
  r 5/10/200, streak 2/5/9, live_window 3/9/300) and HOST-RHYTHM.yaml
  without suspect_every. The builder earned edge pairs for all five host
  thresholds, so they are editable on a measurement that is sensitive to
  them; HOST-UNWATCHED's none_rounds and any user rule's fields are FIXED.
  Every REDO change names its test (E-11).
- CI, read from api.github.com: run 42584260231 (7e36dec) four gate jobs
  failed on the absolute-path test; run 42588931814 (42f457f) six jobs
  success (the follow-up 819f5f3 had no run of its own read by the Table;
  its tests are in this run).
- Gate on the branch: 2897 passed, 22 skipped; kinds 4 : 7 : 11. Scope as
  widened by E (hostdata, host.py and cli.py for E-3/E-7, app.py). Three
  commits plus a cherry-pick onto the Table's merge (Q-19: accepted; the
  ruling reached the branch after the builder had read it from main).
- Q-16 (r max 200, live_window max 300, for the measuring cost): accepted;
  the fence can widen when the generator is faster. Q-17 (HOST-RHYTHM's
  measured negatives are 7: its 5 plus the two edge negatives that can
  fire it): accepted - E-5 excludes what cannot fire, and these can. Q-18
  (one neighbour at a bound end): accepted. Q-20 (the page-url entry
  narrowed to keep the host row in 900 px; measured green on windows):
  accepted. P16 (AGENT-DARK-LIVE's hole text carries numbers that are
  wrong under a changed streak or window): the hole text is rendered from
  the values at load - a later docs/catalog pass; recorded.
- With this merge the commander's plan of 2026-11-04 is built: (1) the
  field runs await his machine; (2) the rules panel with on/off, measured
  thresholds and user rules; (3) M7.5's lessons. Status of this ADR stays
  accepted; Amendments A-F are the record.
- Verdict: **NEXT**. Merge --no-ff into main under the commander's order.
- Table ledger for M7.6c: one review, one CI follow-up, one REDO; the
  Table's misses: "real exports" in the HANDOFF (E-4) and the first
  measurement rule that was not a measurement (A-3 -> E-2).
