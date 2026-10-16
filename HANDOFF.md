# HANDOFF — M2.2  (phase 2: evaluation harness)

Task: evaluate the suspicion layer (DEVELOPMENT_PLAN M2.2) on 50 labelled
events (25 benign / 20 suspicious / 5 deceptive). `python -m raqib eval`
reports false negatives and false positives per candidate backend/model,
ranks candidates by FN first, and shows the deterministic rules as baseline.

Scope:
  raqib/
  tests/test_eval.py
  tests/fixtures/
  README.md
  docs/review/

Exit criteria:
- E1 tests/fixtures/eval/events.json: 50 events (id, label, description,
     trace lines), exactly 25/20/5; every event is a sound trace.
- E2 Per candidate: FN = suspicious/deceptive not raised (an error is a
     miss), FP = benign raised; per-label counts; rank by FN, FP, errors.
- E3 A rules baseline (any finding = flagged) and rules-or-model rows show
     what the model adds on top of the rules (A1).
- E4 Offline tests with canned answers; the real rules baseline is written
     to docs/review; gate green.

Not in scope: UI, new rules, capture changes.
Commit: `landed: M2.2 evaluation harness` or `STOP: M2.2 <reason>`.
Read HANDOFF.md and do only the task it specifies.
