# HANDOFF — REDO 3  (M1.3, M2.1, M2.2, M3.1, M3.2 review packets)

Task: fix what the packets docs/review/2026-10-16-M1.3-M2.1-review.md and
-M2.2-M3.1-M3.2-review.md raise inside these tasks' components; record the
rest. Two commits: M1.3+M2.1, then M2.2+M3.1+M3.2.

Scope:
  raqib/
  tests/
  README.md
  docs/THREAT_MODEL.md
  docs/review/

Exit criteria:
- E1 report: findings tied to their trace; text output printable; cited
     lines show cwd; bad sidecars and run records are alarms, not crashes.
- E2 suspect: no label or framing outside the data tags; only allow-listed
     metadata leaves; fallback answers named; bad findings refused; exit 3
     when windows failed.
- E3 eval: opaque session ids; errors cost on benign events; rules row
     counts incomplete events; silence false positives measured.
- E4 ui: run record shown; serve errors are alarm pages; unique anchors;
     escaping tests for every value. Docs: every packet item fixed or
     recorded; README numbers tested. Gate green.

Commit: `landed: REDO 3 ...` (twice) or `STOP: ...`.
Read HANDOFF.md and do only the task it specifies.
