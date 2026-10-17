# HANDOFF — M0.1  (phase 0: scaffold, gate, CI)

Task: scaffold the application per CLAUDE.md "Stack" and
docs/specs/ADR-0001-architecture.md §1, with the gate running end to end.

Scope:
  package.json, package-lock.json, tsconfig.json, tsconfig.*.json
  vite.config.ts, vitest.config.ts, playwright.config.ts
  shared/
  server/
  client/
  tests/
  .github/workflows/gate.yml
  docs/review/

Exit criteria:
- E1 `npm ci`, `npx tsc --noEmit` (one root tsconfig with project
     references or paths for shared/server/client), `npx vitest run`,
     `npm run build` (client to `client/dist`, server to `server/dist`),
     `npm start` (serves the client and `GET /api/health` ->
     {ok:true, version, db:"pending"}) all succeed.
- E2 `server/app.ts` exports `buildApp(options)` returning a Fastify
     instance (so tests use `app.inject`); `server/main.ts` starts it on
     PORT; request ids on every response (`x-request-id`); pino logger
     configured with the redaction paths of ADR §7; security headers of
     ADR §6 applied already (a test asserts them on /api/health).
- E3 Client: Preact app with a router (hand-written, hash or history),
     design tokens on :root (light/dark), `dir`/`lang` wiring for en/ar,
     one screen "Dawr" with the version; built output has no remote URL.
- E4 playwright.config.ts: preinstalled Chromium (PLAYWRIGHT_BROWSERS_PATH),
     webServer `npm start` on a test port with DATA_DIR in a temp dir;
     one e2e test loads the page and reads the heading. Never run
     `playwright install` locally.
- E5 .github/workflows/gate.yml: Node 22, `npx playwright install
     --with-deps chromium` in CI only, runs tools/gate.sh; no secret.
     Gate green locally.

Not in scope: domain, database, auth, screens.
Commit: `landed: M0.1 scaffold, gate, CI` or `STOP: M0.1 <reason>`.
Read HANDOFF.md and do only the task it specifies.
