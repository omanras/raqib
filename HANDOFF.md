# HANDOFF — M0.2  (phase 0: engine part 1, files in and out)

Task: port the loaders and serializers of the Python engine
(reference/spec/ADR-0001-qayd-engine.md §2-§5, §7) to `src/engine/`.

Scope:
  src/engine/
  tests/engine/
  docs/review/

Exit criteria:
- E1 `ledger.ts`: parseLedger(text, config) -> {rows, problems, dupNotes};
     rows carry line numbers; amounts are Decimal; header must match
     exactly; BOM and CRLF tolerated; a malformed row is a problem naming
     the line and the run continues; exact duplicates noted, not dropped.
     serializeLedger(rows) returns the canonical CSV text (same header,
     same column order, amounts as written).
- E2 `holdings.ts` the same for holdings; latestSnapshot(rows, asOf).
- E3 `policies.ts`: parsePolicies(text) -> Config or problems, validating
     each type as the Python loader does (unknown type/measure/limit kept
     with status unknown and the reason); serializePolicies(config) round
     trips reference/examples/policies.yml semantically.
- E4 `decisions.ts`, `rates.ts`, `periods.ts` (periodOf, parsePeriod,
     trailing, periodsBetween; tested at year/quarter boundaries and leap
     days) ported one-to-one.
- E5 Unit tests cover every problem class with hand-written fixtures and
     parse all five reference/examples files without problems. Gate green.

Not in scope: measures, rules, UI.
Commit: `landed: M0.2 engine part 1` or `STOP: M0.2 <reason>`.
Read HANDOFF.md and do only the task it specifies.
