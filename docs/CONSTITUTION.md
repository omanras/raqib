# Dawr Constitution (public doctrine)

Dawr keeps a savings circle honest. It records; it never moves money, and
it never decides for the members.

## Articles
- **A1 Transparent by construction.** Every member of a circle sees the
  same ledger, the same turn order, the same statements. There is no view
  the organizer has that members cannot have, except invitations not yet
  accepted.
- **A2 Append-only, hash-chained.** Every event that matters (a member
  joins, a contribution is recorded or confirmed, a payout, a turn-order
  draw, a rule change) is a ledger entry with a SHA-256 over its content
  and the previous entry's hash. Entries are never edited or deleted; a
  correction is a new entry referencing the old. Any member can verify the
  chain in the browser and export it.
- **A3 Fairness is verifiable.** The turn order is either agreed by hand
  (recorded) or drawn by commit-reveal: each member commits a hash of a
  secret, then reveals; the order is a deterministic function of all
  reveals. Nobody, organizer included, can bias it after commits close.
- **A4 Money is exact and never touched.** Amounts are integer minor
  units of one declared currency per circle. Dawr holds no funds, calls no
  bank, and makes no payment; it records what members report and what the
  organizer confirms, and it shows the difference.
- **A5 Silence is visible.** A contribution not recorded by the due date
  is shown as outstanding with its age; a round not closed is shown as
  open; a reveal not made is shown as missing. Nothing is assumed paid.
- **A6 Least privilege.** Members act only on their own contributions;
  organizers act on the circle; nobody acts on another circle. Every
  endpoint is covered by the authorization matrix test.
- **A7 Privacy.** Dawr stores what the circle needs: a display name, a
  login, the circle's records. No phone book import, no contacts, no
  tracking, no third-party scripts, no outbound network. Logs never carry
  secrets or full personal details.
- **A8 Evidence over narrative.** A statement cites ledger entry ids. An
  audit log line names who, what, when, from which request id.
- **A9 Public and synthetic.** The repository holds no real circle. The
  seed data is synthetic. Secrets never enter the tree; the gate scans.
- **A10 Offline-honest.** When the server is unreachable the client says
  so and shows the last verified ledger it has; it never shows cached data
  as current.

## Roles
Builder (Claude Code, cloud), Reviewer (read-only), Judge (NEXT/REDO/STOP),
Commander (the Table, acting for the owner): as on the other branches.
