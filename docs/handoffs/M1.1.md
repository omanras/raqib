# HANDOFF — M1.1  (phase 1: authentication, sessions, CSRF, limits)

Task: the auth routes and the security plugins per ADR §4, §6 and
docs/SECURITY_REQUIREMENTS.md S1, S2, S4, S5, S8, plus the
authorization-matrix harness.

Scope:
  server/
  shared/
  tests/api/
  tests/unit/
  docs/review/

Exit criteria:
- E1 `POST /api/auth/signup` (display name, login, password), `/login`,
     `/logout`, `/logout-all`, `GET /api/auth/me`, `POST
     /api/auth/recovery`, `POST /api/auth/password` (change); scrypt per
     S1.2; password policy with the bundled common-password list (S1.1);
     no enumeration (S1.3); lockout and per-IP limits (S1.4) with an
     in-memory store that has a test clock; recovery codes (S1.5);
     session rotation and revocation (S1.6, S2.1); cookie flags (S2.2).
- E2 CSRF plugin (S2.3): token endpoint `GET /api/auth/csrf`, header
     check on every non-GET, bound to the session with HMAC.
- E3 zod on every input, 64 KB body limit, error shape of S8.1, 404 for
     invisible objects; security headers (S5.1-S5.2) with CSP as strict
     as the client build allows (document any 'unsafe-inline').
- E4 `tests/api/authz.matrix.ts`: a table of every route x role
     (anonymous, memberA, organizerA, memberB) -> expected status, and
     one test iterating it; a test that lists Fastify's routes and fails
     if any route is missing from the matrix. Filled for the auth and
     health routes now.
- E5 Tests for every S-item named above by its id in the test name.
     Gate green.

Not in scope: circles, client.
Commit: `landed: M1.1 authentication and security plugins` or `STOP: M1.1 <reason>`.
Read HANDOFF.md and do only the task it specifies.
