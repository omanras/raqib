# HANDOFF — M2.2  (phase 2: quickstart, threat model, CI)

Task: make the README quickstart true from a fresh clone, write
docs/THREAT_MODEL.md, and add a CI workflow that runs the gate.

Scope:
  README.md
  docs/THREAT_MODEL.md
  .github/workflows/gate.yml
  docs/review/

Exit criteria:
- E1 README: what Mizan is (five lines), quickstart (clone branch mizan ->
     tools/gate.sh -> write a rule with two sidecars -> `mizan test` ->
     `mizan check`), the command table, statuses and exit codes, the
     supported Sigma subset and what is `unknown`.
- E2 The quickstart was executed from a fresh clone in a temp directory and
     the exact transcript is in docs/review/<date>-M2.2-quickstart.md.
- E3 docs/THREAT_MODEL.md: how the gate is fooled and what it does about
     it: happy-path-only fixtures, too-clean corpora, match-everything
     wildcards, budgets raised to pass, evasions a rule does not cover,
     malicious fixture files (A7); each with the status Mizan gives today
     and what is open.
- E4 .github/workflows/gate.yml runs tools/gate.sh on push and pull request
     on Ubuntu with Python 3.11 and 3.12; it must not need any secret.
- E5 Gate green.

Not in scope: engine or rule changes.
Commit: `landed: M2.2 quickstart, threat model, CI` or `STOP: M2.2 <reason>`.
Read HANDOFF.md and do only the task it specifies.
