# ADR-0001 — Qayd Web application

Status: accepted (2026-10-17). The engine semantics are NOT redefined here:
they are `reference/spec/ADR-0001-qayd-engine.md` (sections 3-7) and the
oracle files. This ADR covers what the browser adds.

## 1. Shape
One static HTML file (`dist/index.html`, single-file build) that runs
from `file://`, from any static host, and inside a sandboxed iframe. No
server, no network, no cookies. Also served in development by Vite.

## 2. Data
- A "household" = the five files of the CLI (policies.yml, ledger.csv,
  holdings.csv, decisions.yml, rates.csv) held as text in IndexedDB
  (database `qayd`, store `household`, one record per file) plus `meta`
  (last as-of, language, theme). The text IS the state: every edit in the
  UI rewrites the file text through the engine's serializers, so an export
  is byte-identical to what the CLI would read, and an import of CLI files
  needs no conversion.
- Import: file inputs (one per file or a folder), or paste into a text
  area. Export: copy to clipboard per file, and a download link per file
  (which may be inert inside some sandboxes; copy always works).
- First run with no data: an empty state that explains the five files and
  offers "Load the sample household" (the synthetic one, bundled).
- IndexedDB may be unavailable (private mode): the app still runs on the
  in-memory copy and says that nothing will persist.

## 3. Screens
- **Dashboard**: as-of date picker (default today), the policy board (one
  row per policy: verdict chip, title, measure vs limit, period), the
  findings list, a "why" expander per policy showing the cited rows.
  Green/red summary line identical in wording to the CLI's last line.
- **Ledger**: table (newest first, filter by month/account/category/tag/
  text), "Add row" form (date, amount, currency, account, category, tags,
  note) that appends to the CSV text; "Reverse this row" adds the mirror
  row tagged `reversal`; the raw CSV is viewable and editable in a text
  panel with validation errors shown by line.
- **Holdings**: snapshots by date; "New snapshot" pre-filled from the
  latest one; the same raw-text panel.
- **Decisions**: list with days-to-review, open/closed, the policy they
  close; "New decision" form; raw YAML panel.
- **Policies**: list by type with a form per type (cap, floor, routine,
  red_line, kill, allocation) covering every measure/limit/match of the
  engine spec; raw YAML panel; validation errors inline. Saving a change
  re-runs the dashboard.
- **Review**: period picker (month, quarter, year); the same eight
  sections as the CLI's review page, drawn as inline SVG; "Copy as HTML"
  produces the same self-contained page the CLI writes.
- **Settings**: base currency (read-only, from policies.yml), language
  (en, ar with RTL), theme (system/light/dark), export all, erase all
  (two-step), about.

## 4. Engine port
`src/engine/` mirrors the Python modules one-to-one (ledger, holdings,
policies, decisions, periods, rates, measures, rules, findings, report)
with the same function names where sensible, decimal.js for every amount,
and a `check(household, asOf)` that returns the exact JSON shape of the
CLI's `check --json` (version, command, as_of, green, base_currency,
policies[], findings[]), so the differential test is a deep equality.

## 5. Tests
- Unit (vitest): every module, with the Python fixture semantics (bad row,
  duplicate row, foreign currency, missing rate, stale snapshot, kill
  persistence, decision due).
- Differential (vitest): `check` on `reference/examples/` at the five
  oracle dates equals `reference/oracle/check-*.json`; `routine` and
  `decisions` likewise.
- End-to-end (Playwright, Chromium): load the sample, read the planned
  verdicts on the dashboard, add a row that breaches a cap and see the
  red, reverse it and see green, export/import round trip, Arabic RTL
  renders, offline (no network requests at all) asserted by intercepting
  every request.

## 6. Gate
`tools/gate.sh`: secret scan; HANDOFF length; no runtime network APIs in
`src/` (fetch, XMLHttpRequest, WebSocket, sendBeacon, EventSource,
`<link href=http`, `<script src=http`); no `Number(` / `parseFloat(` /
`+x` on amounts in `src/engine/` (lint rule: amounts go through
`Decimal`); `npm ci`; `tsc --noEmit`; vitest; build; `dist/index.html`
exists, is one file under 1.5 MB, contains no `http://` or `https://`
resource references; Playwright e2e once `e2e/` exists.
