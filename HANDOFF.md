# HANDOFF — M1.1+M1.2  (REDO: docs/review/2026-10-16-M1.1.md, -M1.2.md)

Task: fix the M1.1 and M1.2 review findings (and the M0.2/M0.3 residuals
they list) in the YAML subset, engine, runner, silence rules, capture,
installer and README. Two commits: M1.1 REDO, then M1.2 REDO.

Scope:
  raqib/
  tools/install-hooks.sh
  tests/
  README.md
  docs/review/

Exit criteria:
- E1 yamlite: Y1-Y5 inputs are read like YAML or are errors.
- E2 engine: three-valued predicates (MS1, PA3); unjudgeable lines, bad
     context, skipped lines and an empty catalog are reported (3h, F13);
     rules for a cwd at / or a home dir and for a moving cwd (PA1).
- E3 runner: sound fixtures only (A6-2); context rules measured only where
     their context is given (A6-1, F14); optional expected seqs.
- E4 capture: no secret in command_head (F1); linear scans outside the lock,
     capped (F8-F10); placeholders ignored (F6); more formats (F5).
- E5 silence ts fallback and gap cap (S14, S15); installer residuals (M2, M3,
     B4); README true for `main` and `claude/v0.1`; gate green.

Commit: `landed: M1.1 REDO ...` / `landed: M1.2 REDO ...` or `STOP: ...`.
Read HANDOFF.md and do only the task it specifies.
