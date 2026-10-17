# ADR-0001 — Dawr architecture

Status: accepted (2026-10-17). Amendments appended, never edited in place.

## 1. Shape
One Node process serves the API (`/api/*`) and the built client (static
files, SPA fallback) from one origin. SQLite in WAL mode is the only
store. Deployment is one container with one mounted volume (`/data`).
Expected scale: hundreds of circles, thousands of members per instance.

## 2. Domain (shared/)
- **Circle**: id, name, currency (ISO-4217), minor_unit (2 or 3),
  contribution (integer minor units per member per round), period
  (`monthly` | `weekly` | `biweekly`), start_date, due_day rule (for
  monthly: day of month 1-28; for weekly: weekday), member_count (fixed
  once the circle starts), status (`draft` | `drawing` | `active` |
  `completed` | `cancelled`), organizer (a member with role organizer),
  rules_text (free text shown to every member), created_at.
- **Member**: user id + circle id, role (`organizer` | `member`), display
  name within the circle, position (turn number, null until ordered),
  joined_at, left_at (a member who leaves before start is removed by a
  ledger entry; after start, members cannot leave; the organizer may
  record a substitute, which is a ledger entry).
- **Round** n = 1..member_count: due_date (derived from start_date,
  period, due_day), recipient (the member with position n), status
  (`upcoming` | `open` | `closed`), opened_at, closed_at. Round n's pot
  = contribution * member_count (the recipient contributes too, by
  convention; a circle may set `recipient_pays: false`).
- **Contribution** (round, member): amount expected; recorded_at and
  recorded_by (the member self-reporting or the organizer); confirmed_at
  and confirmed_by (organizer); method (free text); reference (free
  text); state derived: `outstanding` | `reported` | `confirmed` |
  `waived` (organizer entry with reason). Partial payments are several
  entries.
- **Payout** (round): amount, paid_at, recorded_by, acknowledged_at by
  the recipient. The pot shown is the sum of confirmed contributions;
  the payout is recorded, not computed.
- **Ledger entry**: seq (per circle, 1..), ts, actor (user id), type
  (one of a fixed enum), payload (JSON, schema per type), prev_hash,
  hash = SHA-256(seq || ts || actor || type || canonical(payload) ||
  prev_hash). The first entry's prev_hash is 64 zeros. Canonical JSON:
  sorted keys, no whitespace, UTF-8. `verify(entries)` recomputes the
  chain and returns the first broken seq or ok.
- **Lottery** (turn order by commit-reveal): the organizer opens the
  draw (ledger entry with a deadline); each member submits
  commit = SHA-256(secret || member_id) (ledger entry); after the
  organizer closes commits, each member reveals the secret (ledger entry,
  verified against the commit); when all have revealed, or at the reveal
  deadline, the order is computed: seed = SHA-256(concat of reveals in
  member-id order || circle id); positions = members sorted by
  SHA-256(seed || member_id). A member who never revealed is placed last
  in member-id order (recorded as such), so one silent member cannot
  block the circle. The result is a ledger entry with the seed and the
  full order; anyone can recompute it from the entries.
- **Schedule**: pure functions from (start_date, period, due_day, n) to
  due dates; tested on month ends and leap years.
- **Money**: integer arithmetic only; formatting per currency minor unit;
  parsing of user input into minor units with explicit rejection of
  more decimals than the currency has.

## 3. Persistence (server/db)
Tables: users, sessions, circles, members, rounds, contributions,
payouts, ledger, invites, audit, recovery_codes, rate_limits (or in
memory), migrations. Every table has created_at. The ledger table has a
UNIQUE(circle_id, seq) and a trigger that forbids UPDATE and DELETE.
Migrations are numbered SQL files applied in order at startup, recorded
in `migrations`.

## 4. API (server/routes), JSON over HTTPS, same origin
Auth: `POST /api/auth/signup`, `/login`, `/logout`, `GET /api/auth/me`,
`POST /api/auth/recovery` (use a recovery code to set a new password).
Circles: `POST /api/circles`, `GET /api/circles` (mine), `GET
/api/circles/:id` (members, rounds, my contributions, status), `PATCH
/api/circles/:id` (draft only: rules, amount, period, dates), `POST
/api/circles/:id/invites` (organizer; returns a one-time link token),
`POST /api/invites/:token/accept`, `POST /api/circles/:id/draw/open`,
`/draw/commit`, `/draw/close-commits`, `/draw/reveal`, `/draw/finalize`,
`POST /api/circles/:id/order` (manual order, draft only), `POST
/api/circles/:id/start`, `POST /api/circles/:id/rounds/:n/open|close`,
`POST /api/circles/:id/rounds/:n/contributions` (report, member) and
`.../contributions/:id/confirm|waive` (organizer), `POST
/api/circles/:id/rounds/:n/payout` (organizer) and `.../payout/ack`
(recipient), `GET /api/circles/:id/ledger` (+ `?verify=1`), `GET
/api/circles/:id/statement[.csv]` (whole circle or `?member=`), `GET
/api/circles/:id/audit` (organizer; application-level audit of who did
what with request ids), `GET /api/health` (no auth; version, db ok).
Every mutating request: session cookie + CSRF token header, zod schema,
authorization check, audit row, ledger entry where A2 applies, 429 under
the rate limit. Errors are `{error: {code, message, requestId}}`; never a
stack trace.

## 5. Client (client/)
Screens: Sign in / Sign up / Recovery; My circles; Circle: Overview (this
round: who pays, who receives, what is outstanding), Members, Rounds,
Ledger (with "Verify chain" running in the browser and a green/red
result, export JSON/CSV), Statement, Draw (commit, reveal, result with
"recompute" button), Settings (organizer: rules, invites, start, close);
Account (name, password, recovery codes, sessions). Languages en and ar
(RTL); amounts always with currency; dates ISO with the circle's
period labels. Mobile-first: the organizer runs this from a phone.
Design: one accent, tokens on :root for light/dark, system font stack
plus an Arabic-capable fallback, no icons from the web.

## 6. Security (see docs/SECURITY_REQUIREMENTS.md for the checklist)
scrypt passwords (N=2^15, r=8, p=1, 32-byte salt), opaque session ids
(32 random bytes, hashed in the sessions table, 30-day idle expiry,
rotation on login), cookies `HttpOnly; Secure; SameSite=Lax; Path=/`,
CSRF double-submit token bound to the session, rate limits per IP and per
account on auth and invite endpoints, lockout after 10 failed logins per
account per 15 minutes, security headers (CSP default-src 'self',
frame-ancestors 'none', nosniff, referrer no-referrer, permissions
policy minimal), request body limit 64 KB, zod on every input, ids are
random (not sequential) in URLs, authorization in one place per route,
audit log of every mutation with user id, circle id, action, request id,
IP (truncated to /24 or /48), user agent hash.

## 7. Logging
pino JSON to stdout: level, time, requestId, method, route (not the raw
URL with ids where avoidable), status, duration, userId (hashed), and
for errors the error code; redaction paths for headers.cookie,
headers.authorization, body.password, body.secret, token fields. Log
levels configurable by LOG_LEVEL. The audit table is separate from logs
and is shown in the app to organizers.

## 8. Configuration
Environment: `DATA_DIR` (default ./data), `PORT` (3000), `SESSION_SECRET`
(required in production, generated and written to DATA_DIR on first run
in development), `BASE_URL` (for invite links), `LOG_LEVEL`,
`NODE_ENV`. The server refuses to start in production without
SESSION_SECRET and without HTTPS awareness (`TRUST_PROXY=1` when behind
a reverse proxy).

## 9. Deployment
`deploy/Dockerfile` (multi-stage, non-root, read-only filesystem except
/data), `deploy/compose.yml` (app + optional Caddy for TLS),
`deploy/backup.sh` (sqlite `.backup` to a dated file, keep 30),
`docs/OPERATIONS.md` (run, upgrade, backup, restore, rotate secret, read
logs, retention).
