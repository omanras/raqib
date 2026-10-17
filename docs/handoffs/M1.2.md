# HANDOFF — M1.2  (phase 1: corpus, budget, check)

Task: implement `mizan/corpus.py` and the commands `corpus` and `check` per
docs/specs/ADR-0001 §7-§9.

Scope:
  mizan/
  tests/test_corpus.py
  tests/test_cli.py
  tests/fixtures/
  docs/review/

Exit criteria:
- E1 Corpus files: first line `{"_mizan": {"logsource": {...}}}`; a file
     without it, empty, or unparseable is named and makes its rules `unknown`.
- E2 Corpus selection: `x-mizan.corpus` if set, else every corpus file whose
     declared logsource agrees on every key the rule's logsource sets; none
     -> status no_corpus.
- E3 fp_per_10k = matches * 10000 / events; each match cited `<file>:<line>`;
     above `fp_budget` -> over_budget; an Unknown on any corpus line ->
     unknown citing it.
- E4 `python3 -m mizan corpus [RULES_DIR] [--corpus DIR]` prints per rule
     `<status> <id> fp/10k=<n> budget=<b> events=<e>`; `--json`.
- E5 `python3 -m mizan check [RULES_DIR] [--corpus DIR]` = fixtures + corpus
     for every `*.yml` (recursive); green (exit 0) only if every rule is pass
     and within budget; red rules first; `--json` as ADR §9. Tests; gate green.

Not in scope: the example rule set (M1.3), export.
Commit: `landed: M1.2 corpus, budget and check` or `STOP: M1.2 <reason>`.
Read HANDOFF.md and do only the task it specifies.
