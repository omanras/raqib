# HANDOFF — M1.4  (phase 1: the Review screen)

Task: the Review screen per docs/specs/ADR-0001-app.md §3, mirroring the
CLI review page (reference engine ADR §9).

Scope:
  src/ui/
  src/engine/review.ts
  src/i18n/
  tests/ui/
  e2e/
  docs/review/

Exit criteria:
- E1 Period picker: month, quarter, year (ISO), default the current
     quarter; the eight sections in the CLI order: period header, policy
     board, income vs expense per month, spending by category, allocation
     by class with band lines, findings, decisions open and due, details
     table of every cited row.
- E2 Charts are inline SVG drawn by the app's own code: viewBox, text in
     currentColor, ticks at real values, amounts printed from Decimal;
     readable in light and dark; no chart library.
- E3 "Copy as HTML": one self-contained page with no script, the same
     sections, theme tokens on :root; "Download" link as well.
- E4 Unit tests on the review data model (per-month sums, category
     ordering, allocation shares) with Decimal expectations; e2e: the
     2026-Q3 review of the sample shows the WLT-01 breach of 2026-07 in
     the findings section and the planted decision due. Gate green.

Not in scope: new engine measures.
Commit: `landed: M1.4 review screen` or `STOP: M1.4 <reason>`.
Read HANDOFF.md and do only the task it specifies.
