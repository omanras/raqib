# Qayd development plan

One micro-task per HANDOFF. Prepared handoffs live in `docs/handoffs/`;
`tools/next-task.sh` advances `HANDOFF.md` after a `landed:` commit. The
builder works on branch `claude/qayd-v0.1`, one commit per task; the
commander merges into `qayd`.

## Phase 0 — the books
- **M0.1** ledger + holdings loaders (ADR §3-§4): strict CSV, Decimal,
  named problems with file:line, DUP-ROW, never raises.
- **M0.2** policies + decisions loaders (ADR §5, §7) and period math
  (month/quarter/year, trailing windows, as-of).
- **M0.3** measures and limits (ADR §5): sum, income, expense, holdings,
  share, drawdown; absolute, pct_of income, months_of expense, pct; rates
  table; `unknown` on anything undeclared.

## Phase 1 — the verdicts
- **M1.1** rule types cap, floor, routine, red_line, kill, allocation ->
  verdicts with citations (ADR §6); `check` command, text and JSON, exit
  codes; silence findings (empty period, stale snapshot).
- **M1.2** `routine` and `decisions` commands; DECISION-DUE; kill persists
  until closed by a decision.
- **M1.3** example household: `tools/make_example.py` (fixed seed) writes
  examples/ with 24 months of rows, 8 policies, 4 decisions, one planted
  breach and one planted kill in the past that was closed; `init` copies
  it; gate runs `check` on examples/ and asserts the planned verdicts.

## Phase 2 — the review
- **M2.1** `review` HTML page (ADR §9), no script, inline SVG by Python.
- **M2.2** README quickstart proven from a fresh clone; docs/FAILURE_MODEL.md
  (how the books lie: missing months, category drift, self-reported
  values, transfers counted as spending, stale snapshots, rates missing;
  what Qayd does today, what is open); CI workflow.
- **M2.3** outside reader: one person outside the project runs the
  quickstart on their own numbers and files one issue. Open until it happens.

## Exit of v0.1
Phases 0-2 landed except M2.3; gate green; `python3 -m qayd check --dir
examples/` gives exactly the planned verdicts; one independent review
packet in `docs/review/`.
