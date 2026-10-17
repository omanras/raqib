# HANDOFF — M2.1  (phase 2: the review page)

Task: implement `qayd/review.py` and the `review` command per
docs/specs/ADR-0001 §9: one self-contained HTML page for a period.

Scope:
  qayd/review.py
  qayd/cli.py
  tests/test_review.py
  docs/review/

Exit criteria:
- E1 `python3 -m qayd review [--dir DIR] --period 2026-Q3 -o FILE.html`
     (also `2026-10`, `2026`); exit 0 when written, 3 on unreadable input.
- E2 The page has no `<script>`, no external resource, no inline event
     handlers; all numbers are HTML-escaped; it renders in light and dark
     (prefers-color-scheme) with every colour as a CSS token on :root.
- E3 Sections, in order: period header (base currency, as-of, data files
     and their row counts); policy board (every policy with verdict,
     measure vs limit, coloured by verdict); income vs expense per month
     (SVG bars); spending by category (SVG bars, sorted); allocation by
     class (SVG, with band lines of allocation policies); findings of the
     period with citations; decisions open and due; details table of every
     row that a verdict cites.
- E4 SVG drawn by Python with viewBox, text in currentColor, axis ticks
     at real values; float allowed in review.py for pixel geometry only,
     every printed amount still comes from Decimal.
- E5 Tests parse the output with html.parser: no script, the eight
     sections present, the planted 2026-07 breach visible in the 2026-Q3
     page of examples/. Gate green.

Not in scope: new measures or rule types.
Commit: `landed: M2.1 review page` or `STOP: M2.1 <reason>`.
Read HANDOFF.md and do only the task it specifies.
