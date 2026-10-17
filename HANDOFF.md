# HANDOFF — M0.1  (phase 0: scaffold and gate)

Task: scaffold the app per CLAUDE.md "Stack" and docs/specs/ADR-0001-app.md
§1, §6, so that `tools/gate.sh` runs the full chain on a hello page.

Scope:
  package.json
  package-lock.json
  tsconfig.json
  vite.config.ts
  vitest.config.ts
  playwright.config.ts
  index.html
  src/
  tests/
  .github/workflows/gate.yml
  docs/review/

Exit criteria:
- E1 `npm ci && npx tsc --noEmit && npx vitest run && npx vite build`
     succeed; dist/ contains exactly one file, index.html, with every
     script and style inlined (vite-plugin-singlefile), no remote URL.
- E2 `src/main.tsx` renders a Preact page "Qayd" with the app version from
     package.json; `src/engine/decimal.ts` re-exports a configured
     decimal.js (precision 28, ROUND_HALF_EVEN) and one unit test proves
     `D("0.1").plus("0.2").eq("0.3")`.
- E3 playwright.config.ts uses the preinstalled Chromium
     (PLAYWRIGHT_BROWSERS_PATH), a webServer of `vite preview`, one e2e
     test that opens the page and reads the heading; `npx playwright test`
     green. Never run `playwright install`.
- E4 .github/workflows/gate.yml runs tools/gate.sh on push/PR, Node 22,
     installs Playwright's Chromium in CI only (`npx playwright install
     --with-deps chromium`), no secret.
- E5 tools/gate.sh green end to end.

Not in scope: engine logic, screens, reference/.
Commit: `landed: M0.1 scaffold and gate` or `STOP: M0.1 <reason>`.
Read HANDOFF.md and do only the task it specifies.
