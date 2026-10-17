# Security requirements (checked by tests, reviewed at every ruling)

Derived from OWASP ASVS 4.0 level 1 plus the parts of level 2 that a
self-hosted single-tenant-per-instance app can meet. Each item names the
test or gate step that proves it. "T:" = automated test id prefix.

## S1 Authentication
- S1.1 Passwords >= 10 characters, <= 128, any characters, checked
  against a list of the 1,000 most common passwords bundled in the repo.
  T: auth.password-policy
- S1.2 scrypt (N=2^15, r=8, p=1, 32-byte random salt, 64-byte hash);
  constant-time compare. T: auth.hash
- S1.3 Login errors do not reveal whether the account exists; same
  timing class (dummy hash on unknown user). T: auth.enumeration
- S1.4 Lockout: 10 failures per account per 15 min -> 423 with retry
  time; per-IP limit on /api/auth/*: 30 per 15 min. T: auth.lockout,
  auth.ratelimit
- S1.5 Recovery codes: 8 codes generated at signup, shown once, stored
  hashed, single use; recovery sets a new password and revokes all
  sessions. T: auth.recovery
- S1.6 Logout revokes the server-side session; "sign out everywhere"
  revokes all. T: auth.logout

## S2 Sessions
- S2.1 Opaque 256-bit session id, stored hashed (SHA-256) server-side,
  idle expiry 30 days, absolute expiry 90 days, rotated on login and on
  password change. T: session.*
- S2.2 Cookie: HttpOnly, Secure (in production), SameSite=Lax, Path=/,
  no Domain. T: session.cookie
- S2.3 CSRF: double-submit token derived with HMAC(SESSION_SECRET,
  session id), required in `X-CSRF-Token` on every non-GET; GET is
  side-effect free. T: csrf.*

## S3 Authorization (the matrix)
For every route and every role in {anonymous, member of circle A,
organizer of circle A, member of circle B}, the expected status is listed
in `tests/api/authz.matrix.ts` and asserted by one test that iterates
the whole matrix; adding a route without a matrix row fails the test.
- S3.1 Object references are random ids; guessing is infeasible; still
  every access checks membership. T: authz.matrix
- S3.2 Members act on their own contributions only; organizers on their
  circle only; nobody on another circle; invites accepted only by a
  signed-in user, once. T: authz.matrix, invites.*
- S3.3 State transitions are enforced server-side (draft -> drawing ->
  active -> completed; rounds open/close in order). T: state.*

## S4 Input and output
- S4.1 zod schema on every body, params and query; unknown keys rejected;
  string lengths bounded; amounts parsed as integers in minor units.
  T: input.*
- S4.2 Body limit 64 KB; JSON only. T: input.limit
- S4.3 All HTML is rendered by Preact (auto-escaped); no innerHTML with
  user data; CSP blocks inline script. T: xss.* (e2e injects
  `<img src=x onerror=...>` into every free-text field)
- S4.4 CSV export escapes formula-leading characters (=, +, -, @) with a
  quote prefix. T: export.csv-injection

## S5 Headers and transport
- S5.1 CSP: default-src 'self'; script-src 'self'; style-src 'self'
  'unsafe-inline' only if the build needs it (document); img-src 'self'
  data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none';
  form-action 'self'. T: headers.csp
- S5.2 X-Content-Type-Options nosniff, Referrer-Policy no-referrer,
  Permissions-Policy (camera=(), microphone=(), geolocation=()),
  Strict-Transport-Security in production. T: headers.*
- S5.3 No outbound network from the server (grep gate + a test that
  stubs global fetch/dns and asserts no call during a full API tour).
  T: egress.none

## S6 Logging and audit
- S6.1 Every request logged with requestId; every mutation writes an
  audit row (actor, circle, action, requestId, ip prefix, ua hash).
  T: audit.coverage (every mutating route appears in audit after the tour)
- S6.2 Redaction: no password, secret, token, cookie or session id in
  logs. T: logging.redaction (captures the log stream during the tour
  and greps for the known secrets)
- S6.3 Ledger chain verification endpoint and in-browser verification
  agree; a tampered row (test modifies the DB directly) is detected.
  T: ledger.tamper

## S7 Dependencies and build
- S7.1 `npm audit --audit-level=high` clean, or each finding documented
  in docs/review with reason. Gate step.
- S7.2 Lockfile committed; CI installs with `npm ci`.
- S7.3 Container runs as non-root, read-only root filesystem, /data
  writable. Documented in OPERATIONS; checked by `docker run` in CI if
  Docker is available, else documented as manual.

## S8 Errors
- S8.1 No stack traces to clients; error shape {code, message,
  requestId}; 404 for objects the caller may not see (not 403), except
  for the caller's own circle where 403 is informative. T: errors.*
