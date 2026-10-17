# HANDOFF — M1.4  (phase 1: rounds, contributions, payouts, statements)

Task: the money-recording routes per ADR §2 (Round, Contribution,
Payout) and §4, with statements, ledger and audit reads.

Scope:
  server/
  shared/
  tests/api/
  tests/unit/
  docs/review/

Exit criteria:
- E1 Rounds: `POST /api/circles/:id/rounds/:n/open` (organizer; in order;
     one open round at a time; ledger round.opened), `.../close`
     (organizer; allowed with outstanding contributions, which the ledger
     entry lists). Round 1 opens at start when start_date <= today.
- E2 Contributions: `POST .../rounds/:n/contributions` (member for self,
     or organizer for any member: amount, method, reference; partial
     allowed; over-payment refused; ledger contribution.reported),
     `POST .../contributions/:cid/confirm` (organizer; ledger
     contribution.confirmed), `.../waive` (organizer; reason required;
     ledger contribution.waived). State derived per ADR.
- E3 Payout: `POST .../rounds/:n/payout` (organizer; amount; ledger
     payout.recorded), `.../payout/ack` (recipient; ledger
     payout.acknowledged).
- E4 Reads: `GET /api/circles/:id/ledger?from=&verify=1` (entries and
     the verification result), `GET /api/circles/:id/statement` (per
     round: expected, confirmed, outstanding per member; totals; every
     line cites ledger seqs) and `.csv` with S4.4 escaping, `?member=`
     for one member's statement (a member may fetch only their own;
     organizer any), `GET /api/circles/:id/audit` (organizer; paged).
- E5 Overview data for the client: `GET /api/circles/:id/overview`
     (this round: recipient, due date, each member's state, pot
     confirmed vs expected, outstanding with age in days). Matrix rows,
     tests, audit coverage test (S6.1) now spans all routes. Gate green.

Not in scope: client.
Commit: `landed: M1.4 rounds, contributions, payouts, statements` or `STOP: M1.4 <reason>`.
Read HANDOFF.md and do only the task it specifies.
