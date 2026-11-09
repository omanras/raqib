# ADR-0008 - The rules panel: the person chooses what Raqib watches for, and Raqib says what is off

Status: proposed (the Table, on the commander's plan of 2026-11-04, written 2026-11-09).
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
