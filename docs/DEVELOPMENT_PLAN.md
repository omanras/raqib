# Qayd Web development plan

One micro-task per HANDOFF; `tools/next-task.sh` advances; builder on
branch `claude/qayd-web-v0.1`; the commander merges into `qayd-web`.

## Phase 0 — engine in the browser
- **M0.1** scaffold: Vite + TypeScript strict + Preact + decimal.js +
  js-yaml + vitest + vite-plugin-singlefile; `tools/gate.sh` wired
  (ADR §6); a hello page builds to one file; CI workflow.
- **M0.2** engine part 1: ledger, holdings, policies, decisions, periods,
  rates loaders and serializers (text in, text out, byte-stable), with
  unit tests ported from the Python fixtures' semantics.
- **M0.3** engine part 2: measures, rules, findings, `check`, `routine`,
  `decisions` returning the CLI JSON shapes; the differential test
  against `reference/oracle/` is green (A10).

## Phase 1 — the app
- **M1.1** store + shell: IndexedDB persistence, in-memory fallback,
  import (files, paste) and export (copy, download), sample loader, app
  shell with navigation, theme, empty state.
- **M1.2** Dashboard + Ledger + Holdings screens (ADR §3), raw-text
  panels with line-level validation, reversing rows.
- **M1.3** Decisions + Policies + Settings screens; policy forms for all
  six types; language switch with Arabic RTL (strings for every screen).
- **M1.4** Review screen: the eight sections as inline SVG, "Copy as
  HTML" identical in structure to the CLI page.

## Phase 2 — proof
- **M2.1** Playwright e2e per ADR §5, including the no-network assertion
  and the file:// run of `dist/index.html`.
- **M2.2** README (install from the one file; from source; the five
  files; what the app never does), docs/FAILURE_MODEL.md (browser
  storage loss, private mode, two tabs, pasted files with the wrong
  header, a policy loosened to pass), accessibility pass (keyboard, labels,
  contrast), release build committed as `release/qayd.html`.
- **M2.3** outside user: one person runs `release/qayd.html` on their own
  numbers and files one issue. Open until it happens.

## Exit of v0.1
Phases 0-2 landed except M2.3; gate green; differential test green; e2e
green; `release/qayd.html` opens from file:// with the sample household
and shows the planned verdicts.
