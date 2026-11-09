# HANDOFF — M7.6b  (the window's look, ADR-0008 decision 6)

Task: one pass over the window's look on the real screens (host, project, rules, log): spacing, type,
colours by the exit-code scheme, the tray tip, a first-run text, the doctrine in one sentence. No behaviour changes.

Scope:
  raqib/app.py (presentation only), raqib/tray.py (tip text only), tests/, README.md, docs/review/

Exit criteria:
- E1 One theme table in app.py (colours, fonts, paddings; ttk style names) used by every screen;
     the exit-code scheme everywhere a level is shown: 0 green, 1 red, 3 amber, notes grey, holes
     amber (F-7, A-2 of ADR-0008 for the suppressed badge in red); dark and light follow the OS
     where Tk can read it, else light; no colour alone carries meaning (a word is beside it).
- E2 Host screen: the tree table in a ttk.Treeview with sortable columns (image, pid, kind, source,
     findings, rhythm/suspicion, first seen, endpoints), the selected tree's findings and notes in
     a detail pane below; the empty state and NOTHING READ as before, with "Not a clearance." kept.
- E3 Project and Rules screens aligned to the same grid; the Rules table a Treeview with the
     overlay state per row; the Log pane monospace; the header one bar: Host | Project | Rules |
     Log, the running watches, "N rules off" (red when suppressed > 0), Open page.
- E4 First run (no ~/.raqib/host/look.json yet): three lines in the first screen's top - what the
     window shows, that Raqib reads and never touches an agent, that "no agent seen" is never a
     clearance; and one sentence under the band: "Rules decide; a model may only raise suspicion."
- E5 Tray tip "Raqib: N trees, K new, F findings" while watching, "Raqib: idle" else; every screen renders at 900x600 without clipping.
- E6 Tests: the theme table is the only place colours live (AST: no literal colour outside it);
     level->colour mapping; the Treeview columns and sort; the first-run text appears and then
     does not; Tk tests skip without a display; the AST guard of M6.4/M7.6 still holds (no new
     writes, no new programs). CI six green. README: the window section's three lines refreshed.
Not in scope: thresholds that can be measured (M7.6c), new screens, macOS, the web page's look.
Commit: `landed: M7.6b the window's look` or `STOP: M7.6b <reason>`.
Read HANDOFF.md and do only the task it specifies.
