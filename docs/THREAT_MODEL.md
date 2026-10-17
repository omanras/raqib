# Dawr threat model (v0.1)

Dawr records a savings circle's money; it never moves it. The assets worth
attacking are therefore not funds but **the truth of the record** (who
paid, who received, what the rules were, what the turn order is), the
members' **accounts**, and their **privacy** (names, who is in which
circle). This document walks every component with STRIDE (Spoofing,
Tampering, Repudiation, Information disclosure, Denial of service,
Elevation of privilege). Each threat names its control and the test that
proves the control, or says **open** and the plan.

Tests are named by their requirement id (docs/SECURITY_REQUIREMENTS.md);
"matrix" is `tests/api/authz.matrix.test.ts`, "e2e security" is
`tests/e2e/security.spec.ts`.

## Trust boundaries

```
member's browser ──https── reverse proxy (TLS) ──http── Dawr (Node) ── SQLite file (/data)
     │                                                │
     └ Web Crypto: verifies ledger and draw itself    └ stdout: operator log
```

- The browser trusts nothing it can check: it re-verifies the ledger chain
  and recomputes the draw with its own SHA-256.
- The server trusts the reverse proxy for TLS and for the client address
  (only with `TRUST_PROXY=1`, and only the immediate hop).
- The operator who runs the server and holds the database file is trusted
  for availability, not for honesty: tampering by them must be detectable.

## 1. Client (Preact app in the browser)

| | Threat | Control | Proof |
|---|---|---|---|
| S | A page on another site acts as the member (CSRF) | Session-bound token in `X-CSRF-Token` on every non-GET; SameSite=Lax cookie; JSON-only bodies | S2.3 csrf.* (`tests/api/auth.test.ts`), csrf.e2e (e2e security) |
| T | Injected markup or script through names, rules, methods, references, reasons | Preact text rendering only, no raw HTML (gate grep), CSP `script-src 'self'`, no inline style or script | S4.3 xss.* (e2e security: payload in every free-text field, no execution, no element, no CSP violation) |
| T | A third-party script or font changes the page | Nothing is loaded from the web; CSP `default-src 'self'` | smoke "own origin only" e2e, "built client references no remote URL" e2e, gate grep |
| R | A member denies having reported a payment | Every report is a ledger entry with the actor's user id, time and seq; audit row with request id | S6.1 audit.coverage, ledger entries in `tests/api/rounds.test.ts` |
| I | Stale data shown as current after the server went away | Offline banner with the time of the last answer; ledger screen labels its copy "may not be current" | A10 offline step in `tests/e2e/trust.spec.ts` |
| I | Session token read by script | HttpOnly cookie; no token in JS-readable storage | S2.2 session.cookie, session.e2e |
| I | The draw secret on the device read by a script | localStorage under CSP with no third-party code; secret useless after the reveal | xss.* (no script runs) — **open**: a malicious browser extension can read it; plan: document, keep the reveal window short |
| D | — | (a client cannot deny service to others) | — |
| E | Clickjacking the organizer into an action | `frame-ancestors 'none'`, `X-Frame-Options: DENY` | S5.1 headers.csp |
| E | Open redirect after sign-in (`?next=`) | Only same-origin paths starting with a single `/` (`safeNext`) | `tests/unit/client-safety.test.ts` |

## 2. API (Fastify server)

| | Threat | Control | Proof |
|---|---|---|---|
| S | Guessing passwords | scrypt N=2^15; 10 failures per login per 15 min -> 423; 30 auth POSTs per IP per 15 min -> 429 | S1.2 auth.hash, S1.4 auth.lockout, S1.4 auth.ratelimit (API and e2e) |
| S | Learning which logins exist | Same answer and timing class for unknown login and wrong password (dummy scrypt); lockout counted per typed login | S1.3 auth.enumeration; lockout on unknown login test. Accepted: sign-up necessarily says "login taken" |
| S | Weak or common passwords | 10-128 code points, not in the bundled 1,000 most common, not the login | S1.1 auth.password-policy |
| T | Changing someone else's contribution, another circle, a closed round | One access helper per circle route (401/404/403), members act on their own lines only, state machines enforced server-side | S3.1 S3.2 authz.matrix (every route x 4 roles), S3.3 state.* |
| T | Over-reporting, floats, malformed amounts | zod on every body, params and query (unknown keys refused), integer minor units, over-payment refused | S4.1 input.strict, `tests/api/rounds.test.ts` over-payment, gate "no float money" grep |
| T | Mass assignment / unknown fields | `z.strictObject` everywhere through one route helper | S4.1 input.strict |
| R | An organizer denies an action | Audit row for every mutating route: actor, circle, action, target, request id, IP prefix, UA hash | S6.1 audit.coverage (tour of every mutating route) |
| I | Reading a circle one is not in (IDOR) | Random 128-bit ids, and a membership check on every access; 404 not 403 for others' circles | S3.1 matrix, idor.e2e, S8.1 errors |
| I | Stack traces, SQL or paths in errors | Error handler sends only `{code, message, requestId}` | S8.1 errors.shape, logging "500 sends only the error shape" |
| D | Large or deep bodies | 64 KB body limit, JSON only, bounded strings and arrays | S4.2 input.limit |
| D | CPU exhaustion through scrypt (many logins) | Per-IP auth limit before any hashing | S1.4 auth.ratelimit — **open**: a distributed attacker with many addresses; plan: per-instance global login budget in v0.2, and Caddy rate limits in the deployment guide |
| E | Becoming organizer, acting on a circle via an invite | Role fixed at creation; invites create plain members only, once | S3.2 invites.*, matrix |
| E | Outbound requests from the server (SSRF, data exfiltration) | No outbound network code at all | S5.3 egress.none (fetch, DNS, sockets, TLS, http clients stubbed during the full tour: zero calls), gate grep |

## 3. Session store

| | Threat | Control | Proof |
|---|---|---|---|
| S | Session fixation | A new session at every sign-in; the old one revoked | S2.1 session.* "rotated on login" |
| S | Stolen cookie replayed after sign-out | Server-side revocation; sign out everywhere | S1.6 auth.logout, session.e2e (copied cookie -> 401) |
| T | Forging a session id | 256-bit random tokens | S2.1 session.* |
| I | Database read discloses live sessions | Only SHA-256 of the token is stored | S2.1 "stored only as a hash" |
| I | Sessions living forever | Idle expiry 30 days, absolute 90 days; password change and recovery revoke all | S2.1 idle/absolute expiry, password-change test, S1.5 auth.recovery |
| E | Cookie sent to other hosts or over http | `__Host-` prefix, Secure in production, no Domain, Path=/ | S2.2 session.cookie |

## 4. SQLite database file

| | Threat | Control | Proof |
|---|---|---|---|
| T | SQL injection | Prepared statements only; the one dynamic column name comes from a fixed map | code review; S4.1 input.* |
| T | Editing rows through the application | No UPDATE or DELETE route for the ledger; triggers forbid both | `tests/unit/db.test.ts` "raises on UPDATE and on DELETE" |
| T | Editing the file directly (operator, attacker with disk access) | Hash chain: any edit breaks verification at that entry, in the server and in every member's browser | S6.3 ledger.tamper (unit, API), e2e raw-SQL tamper in `tests/e2e/trust.spec.ts` |
| T | Rewriting the *whole* chain consistently (recomputing every hash) | Members keep the head: "Share this round" carries the latest entry number and hash into the group chat; exports can be kept | **partly open**: detection relies on members comparing an old head; plan: periodic signed head snapshots members can keep (v0.2) |
| I | Theft of the file or a backup | Passwords scrypt-hashed, session tokens and recovery codes hashed, no contact data stored | S1.2, S1.5 — **open**: names and circle records are readable; plan: OPERATIONS.md requires encrypted disks and backups with restricted permissions |
| D | Corruption or loss | WAL, `synchronous=FULL`, backups (`deploy/backup.sh`, M3.2) | db tests; M3.2 |
| E | Running edited migrations | Checksummed migrations; startup refused if an applied one changed | `tests/unit/db.test.ts` "refuses to start when an applied migration was edited" |

## 5. Ledger (the record)

| | Threat | Control | Proof |
|---|---|---|---|
| S | Entries written as someone else | Actor = the signed-in user id (or `system`); never taken from input | ledger entry tests in `tests/api/*.test.ts` |
| T | Reordering, deleting, inserting entries | seq contiguity and prev-hash links checked by `verify`; UNIQUE(circle_id, seq); concurrent appends serialized | `tests/unit/ledger.test.ts` (removed, reordered, re-hashed forgery), concurrent-append test (four processes) |
| T | Totals that do not match the entries | Statements and overview are recomputed from the entries by `shared/books.ts`; the browser can run the same fold | `tests/unit/books.test.ts`, "indexes agree with the books" |
| R | "I never confirmed that" | Confirmations are entries with the organizer's id and the report ids they confirm | `tests/api/rounds.test.ts` |
| I | Members seeing what they should not | The ledger is the same for every member by design (A1); invitations not yet accepted are kept out of it | invite tests (token never in the ledger) |
| E | — | (no privilege in the ledger beyond its writer) | — |

## 6. Draw (turn order)

| | Threat | Control | Proof |
|---|---|---|---|
| S | Committing or revealing for someone else | Commitment binds the member id: SHA-256(secret || member_id); routes act for the caller only | `tests/unit/lottery.test.ts` "wrong member", matrix |
| T | The organizer choosing the order | The order is a deterministic function of every member's secret; the organizer cannot close commitments early unless everyone committed, nor finalize before everyone revealed or the deadline | `tests/api/draw.test.ts` (commits_pending, reveals_pending), S3.3 determinism |
| T | Changing one's secret after seeing others | Reveal checked against the commitment; reveals only after commitments close | "wrong secret refused and audited" |
| T | The server recording a different order | Every member can recompute it in the browser from the ledger's reveals and commitments | `tests/unit/browser-verify.test.ts`, e2e recompute in `tests/e2e/trust.spec.ts` |
| T | Last revealer withholding to pick between two outcomes | Silent members are placed last (recorded), and reveals close at their deadline | silent-member tests in `tests/api/draw.test.ts`, `tests/unit/lottery.test.ts` — **residual**: the choice "reveal or be last" remains; it can only hurt the withholder |
| R | Denying a commitment | Commitments are ledger entries | draw tests |
| D | One member blocking the draw by silence | Commitments close by themselves at the deadline; finalize allowed after the reveal deadline | "silence is visible" test |
| E | Joining during a draw to influence it | The member set is frozen when the draw opens; joins refused while drawing | "freezes the member set" test |

## 7. Invitations

| | Threat | Control | Proof |
|---|---|---|---|
| S | Guessing an invitation link | 256-bit tokens, rate-limited preview and accept (per IP and account), 404 for every invalid state | S3.2 invites.*, "rate-limits invite creation and acceptance" |
| T | Reusing a link, using it after start | One use; refused after the draw opens, after start, after cancel; expiry 7 days; revocable | S3.2 invites.* |
| I | The link leaking through logs or referrers | Token stored hashed, never in the ledger or logs (route pattern logged, not the URL); `Referrer-Policy: no-referrer` | invite tests, S6.2 logging.redaction (tour) |
| D | Flooding a circle with invites | At most 50 open per circle, 100 actions per account per 15 min | "caps open invitations at 50" |
| E | An invite making someone organizer | Invites only add members | matrix |

## 8. Logs

| | Threat | Control | Proof |
|---|---|---|---|
| I | Secrets in the operator log | pino redaction of cookies, authorization, CSRF, passwords, secrets, tokens, recovery codes; bodies never logged; route patterns not raw URLs | S6.2 logging.redaction (unit with known secrets, and the full tour at debug level: none of 100+ known secrets appear) |
| I | Personal data in logs | User ids hashed with a key; IP addresses truncated to /24 or /48 in audit; no names | `tests/unit/audit.test.ts` |
| T | Log injection through request ids | Request ids generated by the server; client-sent ones ignored | health test "ignores a client-sent one" |
| R | Losing who did what | Audit table (append-only, triggers) separate from the operator log, shown to organizers | S6.1, db audit trigger test |

## 9. Deployment

| | Threat | Control | Proof |
|---|---|---|---|
| S | Clear-text traffic, cookie theft on the network | Production refuses to start without TRUST_PROXY=1 and an https BASE_URL; HSTS; Secure cookies | `tests/unit/config.test.ts`, S5.2 headers.hsts |
| S | Spoofed client addresses | X-Forwarded-For trusted only with TRUST_PROXY=1 and only from the immediate hop | `tests/api/proxy.test.ts` |
| T | A weak or default session secret | Production requires SESSION_SECRET of 32+ characters; development generates one (0600) | `tests/unit/config.test.ts` |
| T | Vulnerable dependencies | `npm audit --audit-level=high` in the gate; lockfile; `npm ci` | S7.1 deps.audit, S7.2 deps.lockfile |
| E | Container escape surface | Non-root user, read-only root filesystem, only /data writable | S7.3 container.non-root (runs once `deploy/` exists, M3.2) |
| D | Exhausting the disk | One SQLite file and logs to stdout; OPERATIONS.md (M3.2) covers retention | **open** until M3.2 |

## What Dawr cannot protect against

- **A dishonest organizer lying about cash.** Dawr records claims, not
  money. If the organizer confirms a payment that never arrived, or records
  a payout that was never made, the ledger shows exactly that claim, who
  made it and when — nothing more. The recipient's acknowledgement (or its
  absence) is the counterweight: a payout without acknowledgement stays
  visibly unacknowledged.
- **Members who collude off the record.** Side agreements, cash changing
  hands without a report, a member paying another's share: the ledger only
  knows what someone wrote into it.
- **An operator who rewrites the entire chain and every member who never
  kept anything.** The chain makes edits detectable, not impossible; it
  needs someone to compare against an earlier head (shared round summaries,
  exports). A member who never looks cannot be protected by a hash.
- **A compromised device.** Malware or a hostile browser extension on a
  member's phone sees what the member sees and can act as them.
- **Losing both the password and every recovery code.** There is no
  e-mail reset by design (no outbound network); the account cannot be
  recovered.
- **Coercion.** Dawr cannot tell a payment reported under pressure from any
  other.
