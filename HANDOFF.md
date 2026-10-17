# HANDOFF — M2.2  (phase 2: quickstart, failure model, CI)

Task: make the README quickstart true from a fresh clone, write
docs/FAILURE_MODEL.md, and add a CI workflow that runs the gate.

Scope:
  README.md
  docs/FAILURE_MODEL.md
  .github/workflows/gate.yml
  docs/review/

Exit criteria:
- E1 README: what Qayd is (five lines; it never advises, never moves
     money, never connects); quickstart (clone branch qayd -> tools/gate.sh
     -> `qayd init --dir ~/money` -> edit policies.yml -> append rows ->
     `qayd check` -> `qayd review`); the file formats in brief; the
     command table; verdicts and exit codes; what is `unknown`.
- E2 The quickstart was executed from a fresh clone in a temp directory
     and the exact transcript is in docs/review/<date>-M2.2-quickstart.md.
- E3 docs/FAILURE_MODEL.md: how the books lie and what Qayd does today:
     missing months, category drift, transfers logged as spending,
     self-reported holdings, stale snapshots, missing rates, a kill
     "closed" by a backdated decision, a policy loosened to pass; each
     with the finding Qayd raises or the gap that is open.
- E4 .github/workflows/gate.yml runs tools/gate.sh on push and pull request
     on Ubuntu with Python 3.11 and 3.12; no secret needed.
- E5 Gate green.

Not in scope: engine changes.
Commit: `landed: M2.2 quickstart, failure model, CI` or `STOP: M2.2 <reason>`.
Read HANDOFF.md and do only the task it specifies.
