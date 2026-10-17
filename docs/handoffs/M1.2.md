# HANDOFF — M1.2  (phase 1: circles, members, invites, start)

Task: circle lifecycle routes per ADR §4 with ledger entries, audit rows
and matrix rows.

Scope:
  server/
  shared/
  tests/api/
  tests/unit/
  docs/review/

Exit criteria:
- E1 `POST /api/circles` (creator becomes organizer; ledger entry
     circle.created), `GET /api/circles` (mine, with my role and status),
     `GET /api/circles/:id` (members with positions, rounds, my
     contributions summary, outstanding counts), `PATCH /api/circles/:id`
     (draft only; every changed field is a ledger entry circle.rule_changed).
- E2 Invites: `POST /api/circles/:id/invites` (organizer; one-time token,
     expiry 7 days, max 50 active per circle) returning a link
     `${BASE_URL}/join/<token>`; `POST /api/invites/:token/accept`
     (signed-in user; once; refused after start or at member cap);
     ledger entry member.joined; `DELETE` is not offered (revoke = POST
     /invites/:id/revoke, audit only).
- E3 `POST /api/circles/:id/order` (organizer, draft, a full permutation
     of member ids; ledger entry order.set with the permutation), `POST
     /api/circles/:id/start` (organizer; requires >= 2 members, an
     order, a start date; freezes member_count; creates rounds; ledger
     entry circle.started), `POST /api/circles/:id/leave` (member,
     draft only; ledger entry member.left), `POST /api/circles/:id/cancel`
     (organizer, draft or drawing; ledger entry).
- E4 Every route: zod, matrix rows for all four roles, audit row, state
     machine refusal reasons in the error message.
- E5 Tests per route (happy path, each refusal, matrix). Gate green.

Not in scope: draw, rounds, client.
Commit: `landed: M1.2 circles, members, invites, start` or `STOP: M1.2 <reason>`.
Read HANDOFF.md and do only the task it specifies.
