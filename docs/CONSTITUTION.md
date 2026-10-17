# Qayd Web Constitution (public doctrine)

The same nine articles as Qayd (reference/spec/ADR-0001-qayd-engine.md
and branch `qayd`), restated for a browser:

- **A1 Deterministic.** Same files, same verdicts, in every browser.
- **A2 Policies are declared, not inferred.** The app edits policies.yml;
  it never invents a policy from the data and never suggests one.
- **A3 Silence is red.** Empty period, stale snapshot, overdue decision.
- **A4 Evidence cites.** Every verdict shows the rows behind it, one click
  away, with the same `file:line` references as the CLI.
- **A5 Money is exact.** decimal.js everywhere; a JS number never holds an
  amount.
- **A6 The ledger is ground truth.** Rows are appended, never edited in
  place; a correction is a reversing row. Deleting is a reversing row too.
- **A7 Offline and silent.** No network at runtime; the one-file build runs
  from `file://`; data stays in this browser unless the person exports it.
- **A8 Never advises, never executes.** No tips, no "you could save", no
  links to products.
- **A9 Public and synthetic.** The bundled sample is the synthetic
  household from `reference/examples/`; nothing real enters the repo.
- **A10 Oracle agreement.** On the sample, verdicts, measures, limits,
  periods and citations equal `reference/oracle/*.json`; the test that
  checks it is part of the gate.

## Roles
Builder (Claude Code, cloud), Reviewer (read-only), Judge (NEXT/REDO/STOP),
Commander (the Table): as on the other branches.
