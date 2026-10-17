# HANDOFF — M0.3  (phase 0: engine part 2, verdicts and the oracle)

Task: port measures, rules, findings and the three command results
(`check`, `routine`, `decisions`) and prove byte-level agreement with
`reference/oracle/*.json` (Constitution A10).

Scope:
  src/engine/
  tests/engine/
  tests/differential/
  docs/review/

Exit criteria:
- E1 `measures.ts` (sum, income, expense, holdings, share, drawdown;
     limits value, pct_of income, months_of expense, pct; rates
     conversion; Unknown/Stale propagation, never a partial sum) and
     `rules.ts` (cap, floor, routine, red_line, kill with persistence
     until a later closing decision, allocation) with citations.
- E2 `findings.ts`: EMPTY-PERIOD, STALE-SNAPSHOT, DECISION-DUE, DUP-ROW
     (warn), invalid rows, in the same ids and texts as the CLI.
- E3 `check(household, asOf)`, `routine(household, period)`,
     `decisions(household, asOf)` return exactly the CLI JSON shapes
     (keys, order of policies, verdict strings, measure/limit objects with
     amount as string, cites, text, findings, the summary line).
- E4 tests/differential/oracle.test.ts: for each file in reference/oracle,
     run the matching command on reference/examples and `expect(result)
     .toEqual(oracle)` (deep equality, no normalisation other than the
     two documented exceptions below, if any arise; each must be listed
     in the questions file with the reason).
- E5 Unit tests for every rule type (holding and breaching), kill
     persistence, backdated closing decision, missing rate, stale
     snapshot. Gate green.

Not in scope: UI, storage.
Commit: `landed: M0.3 engine part 2 and oracle` or `STOP: M0.3 <reason>`.
Read HANDOFF.md and do only the task it specifies.
