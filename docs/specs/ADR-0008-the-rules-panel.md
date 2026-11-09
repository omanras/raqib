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
