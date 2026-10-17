# HANDOFF — M1.3  (phase 1: the example rule set and self-gate)

Task: ship a synthetic example rule set with fixtures and corpora, and make
the repository gate itself with `python3 -m mizan check rules/`.

Scope:
  rules/
  corpus/
  tools/make_corpus.py
  tests/test_examples.py
  docs/review/

Exit criteria:
- E1 Ten rules in rules/, Sigma-valid: windows/process_creation (4),
     linux/auth (3), webserver (3); synthetic (no real hosts or users, IPs
     from documentation ranges, no copied public rules); each with fp_budget.
- E2 Every rule has positive (>= 2 lines) and negative (>= 2 lines)
     sidecars; at least one negative line is a near miss (one field differs).
- E3 `tools/make_corpus.py` generates corpus/windows-process_creation.jsonl,
     corpus/linux-auth.jsonl, corpus/webserver.jsonl with >= 1000 benign
     events each from a fixed seed; the committed files equal its output.
- E4 `python3 -m mizan check rules/ --corpus corpus/` is green; at least two
     rules have non-zero fp/10k (so the budget mechanism is exercised) and
     every rule is within budget without raising budgets above 50.
- E5 tests/test_examples.py asserts E3 (regenerate and compare) and E4
     through `mizan.cli.main`; tools/gate.sh (already wired) is green.

Not in scope: engine changes (write a questions file if a rule needs one).
Commit: `landed: M1.3 example rule set` or `STOP: M1.3 <reason>`.
Read HANDOFF.md and do only the task it specifies.
