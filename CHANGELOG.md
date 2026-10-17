# Changelog

All notable changes to Dawr. Versions follow [Semantic Versioning](https://semver.org/);
dates are UTC.

## 0.1.0 — 2026-10-17

The first version: a savings circle can be run from sign-up to completion,
with a verifiable ledger, a draw nobody can rig, statements, English and
Arabic, and a container to self-host it. Built task by task on
`claude/dawr-v0.1`; each line below is one landed task.

**Tag notes (v0.1.0).** Dawr records a savings circle; it never moves
money. One container, one SQLite file, no outbound network. Every member
can verify the hash-chained ledger and recompute the draw in their own
browser. Self-host with `deploy/compose.yml` (docs/OPERATIONS.md); report
security issues as described in SECURITY.md.

### Phase 0 — foundations
- **M0.1 scaffold, gate, CI.** One package with `shared/`, `server/`,
  `client/`; Fastify serving the Vite/Preact build; vitest and Playwright;
  the constitutional gate (secrets, egress grep, float-money grep,
  typecheck, tests, build, `npm audit`, e2e) and a CI workflow running it.
- **M0.2 domain core.** Money in integer minor units with strict parsing
  and checked arithmetic; due-date schedules; canonical JSON and the
  SHA-256 hash chain with verify; the commit-reveal lottery with the
  silent-member rule; circle, draw, round and contribution state machines;
  committed test vectors and property tests.
- **M0.3 persistence, audit, logging.** SQLite (WAL, foreign keys, full
  sync) with checksummed migrations; ledger and audit tables that refuse
  UPDATE and DELETE by trigger; race-free appends proven with four
  processes; the audit writer (IP prefixes, keyed user-agent hash); pino
  with redaction and request ids; configuration that refuses an unsafe
  production start; `/api/health`.

### Phase 1 — the server
- **M1.1 authentication and security plugins.** Sign-up, sign-in,
  sign-out (one or every device), profile, sessions, password change,
  recovery codes; scrypt, a common-password list, lockout and per-address
  limits, hashed sessions with idle and absolute expiry and rotation,
  `__Host-` cookies, session-bound CSRF, security headers and CSP, zod on
  every input, the authorization-matrix harness.
- **M1.2 circles, members, invites, start.** Create, list, read, edit in
  draft; one-time invitation links (hashed, 7 days, revocable); manual
  turn order; start (frozen members, rounds and obligations); leave;
  cancel. Every change a ledger entry and an audit row.
- **M1.3 the draw.** Open with deadlines, commit, close commitments,
  reveal (checked against the commitment), finalize; the order as a pure
  function of the ledger, identical on server and in browser.
- **M1.4 rounds, contributions, payouts, statements.** Rounds open and
  close in order; members report, organizers confirm, waive with a reason
  or record for a member; partial payments; payouts recorded once and
  acknowledged by the recipient; ledger with verification; statements
  (JSON, CSV with formula escaping) recomputed from the ledger; the
  organizer's activity log; the round overview.

### Phase 2 — the client
- **M2.1 client shell, auth, circles.** Design tokens (light and dark,
  one accent), mobile-first shell, English and Arabic with right-to-left
  layout and a key-parity test, the API client with CSRF handling and
  request ids in errors, an offline-honest banner; sign-in, sign-up with
  recovery codes, recovery, account and sessions, my circles, create a
  circle, join by invitation.
- **M2.2 circle screens.** Overview of the round, Members (invitations,
  turn order, start, leave), Rounds and the round page (report, confirm,
  waive, payout and acknowledgement, open and close), Settings, Activity;
  "Share this round" for the group chat.
- **M2.3 ledger, statement, draw screens.** The ledger with in-browser
  chain verification and JSON/CSV export, statements for the circle and
  for one member, the draw (commit with a secret kept on the device,
  reveal, finalize, recompute in the browser); tamper detection end to
  end.

### Phase 3 — proof and operations
- **M3.1 security proof and threat model.** A test named for every
  security requirement; a tour of every route for every role proving no
  outbound network and no secret in the logs; XSS in every free-text
  field, CSRF and rate limits in the browser; a full four-member circle
  from sign-up to completion in the e2e suite; docs/THREAT_MODEL.md. The
  shared round summary carries the ledger head.
- **M3.2 operations, docs, release.** `deploy/Dockerfile` (multi-stage,
  non-root, read-only root filesystem, `/data` volume, health check),
  `deploy/compose.yml` with optional Caddy for automatic TLS,
  `deploy/backup.sh` and `deploy/restore.sh` with a database check that
  recomputes every chain (`deploy/dbtool.mjs`), a container smoke test in
  CI (`deploy/smoke.sh`); docs/OPERATIONS.md, README.md, SECURITY.md,
  this changelog; the gate checks that documented commands exist.
