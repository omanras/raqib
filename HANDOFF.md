# HANDOFF — M2.2  (phase 2: circle screens)

Task: the circle screens per ADR §5: Overview, Members, Rounds (with
contribution and payout actions), Settings.

Scope:
  client/
  tests/e2e/
  docs/review/

Exit criteria:
- E1 Overview: this round at a glance: round n of N, recipient, due
     date and days left or overdue, pot confirmed / expected, a member
     list with state chips (outstanding with age, reported, confirmed,
     waived), my action button (Report my payment) when applicable;
     "share this round" copies a plain-text summary for a messaging app.
- E2 Members: positions, names, role, joined date; organizer tools
     (invites: create, copy link, revoke; set manual order in draft with
     drag or up/down buttons; start circle with the state-machine
     reasons shown when refused).
- E3 Rounds: list with status; a round page: contributions table with
     organizer actions (confirm, waive with reason) and member action
     (report with amount, method, reference, partial allowed); payout
     record (organizer) and acknowledge (recipient); open/close round.
- E4 Settings (organizer): rules text, amount, period, dates (draft
     only), cancel circle (two-step), and the read-only summary after
     start; the audit log viewer (paged) for organizers.
- E5 e2e, two browsers (organizer A, member B): A sets order and starts;
     A opens round 1; B reports a payment; A confirms; A records payout;
     the recipient acknowledges; Overview reflects every step; Arabic
     pass on the Overview. Gate green.

Not in scope: Ledger, Statement, Draw screens.
Commit: `landed: M2.2 circle screens` or `STOP: M2.2 <reason>`.
Read HANDOFF.md and do only the task it specifies.
