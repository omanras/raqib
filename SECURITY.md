# Security policy

Dawr holds the record of people's money. A flaw that lets someone read
another circle, act as another member, alter the record without the chain
showing it, or bias a draw matters to real families. Thank you for
reporting one privately.

## Reporting a vulnerability

- Use GitHub's private vulnerability reporting on this repository:
  **Security → Report a vulnerability**
  (<https://github.com/omanras/raqib/security/advisories/new>).
- If that form is not available to you, open a public issue that says only
  "Dawr: security contact requested" — no details, no proof of concept —
  and you will be given a private channel.
- Please include the version (`GET /api/health` shows it), what an
  attacker needs (an account? a member of the circle? access to the
  server?), the steps, and what they gain.
- Do not test against an instance you do not run, and do not access or
  keep other people's data. A local instance (README, "Try it on your own
  computer") has everything needed.

What to expect: the maintainer aims to acknowledge a report within 7 days
and to assess it within 30, then to ship a fix or a documented decision,
crediting you (unless you prefer otherwise) in CHANGELOG.md.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | yes |

Self-hosters: follow the `dawr` branch or its release tags, and upgrade as
described in docs/OPERATIONS.md ("Upgrade").

## In scope

The server, the web client, `shared/`, and the deployment files in
`deploy/`: authentication and sessions, authorization between members and
circles, CSRF, injection (XSS, CSV formula), the hash chain and its
verification, the draw (commit-reveal), rate limits, secrets in logs, and
anything that makes the server reach the network.

## Out of scope

What docs/THREAT_MODEL.md lists under "What Dawr cannot protect against"
(for example an organizer confirming money that never arrived, or a
compromised phone), denial of service by sheer volume, and findings that
need root on the host or write access to the database file (those are
caught by the chain check, which is the point of it: see
docs/OPERATIONS.md, "If the ledger check is red").
