# HANDOFF — M3.2  (phase 3: docs)

Task: the v0.1 documents (DEVELOPMENT_PLAN M3.2): a README a stranger can
read in two minutes, a threat model, and the constitution linked.

Scope:
  README.md
  docs/THREAT_MODEL.md
  docs/review/

Exit criteria:
- E1 README: what Raqib is, the quickstart, what it catches and what it
     cannot see, each command once; readable in about two minutes.
- E2 docs/THREAT_MODEL.md: assets, the adversary (the watched agent),
     trust boundaries, what the trace holds and leaks, and every known gap
     recorded in docs/review (each with its source).
- E3 CONSTITUTION and ADR linked; Linux/macOS only, Windows unsupported (A-6).
- E4 Every command shown in the README is run and its output checked;
     gate green.

Not in scope: code changes, new features.
Commit: `landed: M3.2 docs` or `STOP: M3.2 <reason>`.
Read HANDOFF.md and do only the task it specifies.
