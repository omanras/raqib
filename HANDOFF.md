# HANDOFF — M1.1+M1.2 REDO 2  (docs/review/2026-10-16-M1.1-M1.2-REDO.md)

Task: fix the findings of the review of the first M1.1+M1.2 REDO that can
be fixed inside its components; record the rest.

Scope:
  raqib/
  tools/install-hooks.sh
  tests/
  README.md
  docs/review/

Exit criteria:
- E1 4.1: no secret pattern backtracks; the private_key case and the other
     adversarial inputs scan in well under a second.
- E2 4.3, 4.5, 4.12, F1, F12: placeholder checks look at the secret only;
     key-like heads and secret-bearing paths are left out; null output is
     scan "none".
- E3 Y3/SU2, Y2, A6-2, MS1, 4.7, 4.9, 4.10, B4, F10 residuals fixed.
- E4 The surviving mutants (a)-(k) are killed by tests; gate green.

Commit: `landed: M1.1+M1.2 REDO 2 ...` or `STOP: ...`.
Read HANDOFF.md and do only the task it specifies.
