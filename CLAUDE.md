# DAWR — read this first, every session

Dawr (Arabic: a turn, a round) is a web application that runs a savings
circle, the jam'iyya (ROSCA: a group of people who each pay a fixed amount
every period, and each period one member receives the whole pot). Hundreds
of millions of people run these on WhatsApp and paper, and the recurring
failure is trust: who paid, whose turn it is, what the organizer changed.
Dawr makes the circle transparent and verifiable: an append-only,
hash-chained ledger every member can verify, a turn-order lottery nobody can
rig (commit-reveal with every member's randomness), statements anyone can
export, and an audit log of every change. Dawr records money; it never
moves it. It lives on branch `dawr` of this repository; branches `main`,
`mizan`, `qayd` and `qayd-web` are other projects and are never touched.

## Non-negotiable rules
1. Read `HANDOFF.md` and do ONLY the task it specifies. Touch only the paths
   listed under `Scope:`. Anything else is out of scope -> STOP.
2. One micro-task per commit. Every commit message starts with `landed:` or
   `STOP:`. Never leave the tree dirty.
3. Security is not a phase. Every endpoint lands with its authorization
   test (the matrix in docs/SECURITY_REQUIREMENTS.md), every input with
   its schema, every change of state with its audit entry. A task that
   adds an endpoint without these is not landed.
4. Money is integer minor units (fils, cents) in a declared currency; no
   floats anywhere; totals are recomputed from the ledger, never stored
   as the truth.
5. The ledger is append-only and hash-chained; nothing is updated or
   deleted; a correction is a new entry that references the old one.
6. No outbound network from the server (no email, no SMS, no webhooks, no
   telemetry) in v0.1; invites and resets are links the organizer shares.
   The client loads nothing from the web.
7. Logs are structured, carry a request id, and never carry a password,
   token, session id, or full personal detail; the audit log is for
   members, the application log is for operators.
8. Design questions go to `docs/review/<date>-<task>-questions.md` with the
   most conservative reading taken; keep `HANDOFF.md` <= 40 lines.

## Stack (fixed)
Node 22 LTS, TypeScript strict, Fastify 5, better-sqlite3 (WAL), zod,
pino, node:crypto (scrypt, randomBytes, HMAC, SHA-256) for all crypto;
Preact + Vite for the client (single package, `client/` and `server/`
folders, `shared/` for types and pure domain code); vitest; Playwright
(Chromium preinstalled at PLAYWRIGHT_BROWSERS_PATH, never run `playwright
install` locally); Docker for deployment. No ORM, no CSS framework, no
UI kit, no chart library, no auth library.

## Layout
- `shared/`   pure domain: money, schedule, lottery, ledger hashing
- `server/`   Fastify app: plugins (security, session, csrf, ratelimit,
              logging), routes, repositories, migrations, audit
- `client/`   Preact app: screens, i18n (en, ar RTL), design tokens
- `tests/`    unit (shared, server), api (supertest-like via inject),
              e2e/ (Playwright)
- `docs/`     CONSTITUTION, SECURITY_REQUIREMENTS, DEVELOPMENT_PLAN,
              SESSION_PROTOCOL, specs/ (ADR), THREAT_MODEL, OPERATIONS,
              handoffs/, review/
- `tools/`    gate.sh, next-task.sh
- `deploy/`   Dockerfile, compose.yml, backup script

## Exit of every task
`tools/gate.sh` must be green. If it is not, the task is not landed.
