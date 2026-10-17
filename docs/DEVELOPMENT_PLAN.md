# Dawr development plan

One micro-task per HANDOFF; `tools/next-task.sh` advances; builder on
branch `claude/dawr-v0.1`; the commander merges into `dawr`.

## Phase 0 — foundations
- **M0.1** scaffold: one package, `shared/`, `server/`, `client/`; Vite +
  Preact client; Fastify server serving the built client; vitest;
  Playwright; gate wired (lint-free tsc, tests, build, audit, e2e); CI.
- **M0.2** domain (shared/): money, schedule, ledger hashing and verify,
  lottery (commit, reveal, finalize), state machines; property-style
  tests (random inputs, invariants).
- **M0.3** persistence + logging: SQLite schema and migrations, the
  no-update/no-delete ledger trigger, repositories, pino logging with
  redaction and request ids, audit table and writer, health route.

## Phase 1 — the server
- **M1.1** auth: signup, login, logout, me, recovery codes, sessions,
  CSRF, rate limits, lockout, security headers, error shape; the
  authorization-matrix harness with the auth routes filled in.
- **M1.2** circles: create, list, get, patch (draft), invites (create,
  accept), manual order, start; ledger entries; matrix rows.
- **M1.3** draw: open, commit, close-commits, reveal, finalize; the
  deterministic order; silent-member rule; matrix rows.
- **M1.4** rounds: open/close, contributions (report, confirm, waive,
  partial), payout (record, acknowledge), statements (JSON, CSV with
  injection escape), ledger GET with verify, audit GET; matrix rows.

## Phase 2 — the client
- **M2.1** shell: design tokens, i18n en/ar with RTL, auth screens,
  account screen (recovery codes, sessions), My circles, create circle,
  invite link flow; e2e for the journey.
- **M2.2** circle screens: Overview (this round), Members, Rounds with
  contribution actions, Payout, Settings; e2e organizer + member.
- **M2.3** ledger & trust screens: Ledger with in-browser verify and
  export, Statement, Draw (commit/reveal/result/recompute); e2e tamper
  detection through the API test + UI.

## Phase 3 — proof and operations
- **M3.1** security proof: full matrix green, xss e2e on every free-text
  field, csrf and rate-limit e2e, egress test, logging redaction test,
  npm audit; THREAT_MODEL.md (STRIDE per component, with the test that
  covers each threat or the gap).
- **M3.2** operations: Dockerfile, compose, backup/restore script,
  OPERATIONS.md, README (what Dawr is, 10-minute self-host, how a circle
  runs end to end with screenshots described in text), SECURITY.md
  (reporting), CHANGELOG v0.1; release tag notes.
- **M3.3** outside organizer: one real circle organizer runs a dry
  circle on a test instance and files one issue. Open until it happens.

## Exit of v0.1
Phases 0-3 landed except M3.3; gate green; matrix green; e2e green;
`docker build` documented; a full circle of 4 members can be run from
signup to completion in the e2e suite.
