# QAYD WEB — read this first, every session

Qayd Web is the browser app of Qayd: personal finance as code, with no
server. The household's policies, ledger, holdings and decisions live in the
browser (IndexedDB) and in files the person imports and exports; the engine
gives deterministic verdicts and a period review. The reference engine is the
Python CLI on branch `qayd` of this repository; its spec and its example
household are copied under `reference/` and are the oracle this app must
match. Branches `main`, `mizan` and `qayd` are never touched from here.

## Non-negotiable rules
1. Read `HANDOFF.md` and do ONLY the task it specifies. Touch only the paths
   listed under `Scope:`. Anything else is out of scope -> STOP.
2. One micro-task per commit. Every commit message starts with `landed:` or
   `STOP:`. Never leave the tree dirty.
3. Deterministic engine, byte-for-byte agreement with the oracle: on
   `reference/examples/` the app's verdicts, measures, limits and citations
   equal `reference/oracle/*.json`. A disagreement is a bug in the app, not
   a reason to edit the oracle.
4. Money is decimal (decimal.js), never a JS number. Every amount carries a
   currency; conversions use the rates table or the measure is `unknown`.
5. No network at runtime: no fetch, XMLHttpRequest, WebSocket, beacon,
   analytics, fonts from the web. The built app is one HTML file that works
   from `file://`, offline. Dependencies are installed at build time only.
6. Silence is red: an empty period, a stale snapshot, an overdue decision
   are findings. The app never advises and never hides a red.
7. Design questions go to `docs/review/<date>-<task>-questions.md` with the
   most conservative reading taken; keep `HANDOFF.md` <= 40 lines.

## Stack (fixed)
Vite + TypeScript (strict) + Preact; decimal.js; js-yaml; vitest for unit
and differential tests; Playwright (Chromium, already installed at
PLAYWRIGHT_BROWSERS_PATH, never run `playwright install`) for end-to-end;
vite-plugin-singlefile for the one-file build. No CSS framework, no chart
library (inline SVG), no state library.

## Layout
- `src/engine/`  the port of the Python engine (ledger, holdings, policies,
                 decisions, periods, rates, measures, rules, findings)
- `src/store/`   IndexedDB persistence, import/export of the five files
- `src/ui/`      Preact components: Dashboard, Ledger, Holdings, Decisions,
                 Policies, Review, Settings
- `src/i18n/`    English and Arabic strings; RTL layout for Arabic
- `tests/`       vitest unit + differential; `e2e/` Playwright
- `reference/`   examples, oracle JSON, the engine ADR (read-only)
- `docs/`        CONSTITUTION, DEVELOPMENT_PLAN, SESSION_PROTOCOL, specs/,
                 handoffs/, review/
- `tools/`       gate.sh, next-task.sh

## Exit of every task
`tools/gate.sh` must be green. If it is not, the task is not landed.
