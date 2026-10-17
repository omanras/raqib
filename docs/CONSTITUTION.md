# Mizan Constitution (public doctrine)

Mizan weighs detection rules. It admits a rule on evidence, not on the
author's word.

## Articles
- **A1 Deterministic.** Matching is exact and reproducible. The same rule on
  the same event gives the same answer on every machine, every run. There is
  no model, no heuristic score, no "probably".
- **A2 No evidence, no rule.** Every rule ships with at least one positive
  fixture (an event it must match) and at least one negative fixture (an
  event it must not match). A rule without both is red.
- **A3 Budget declared, budget measured.** Every rule declares its
  false-positive budget (`x-mizan.fp_budget`, matches allowed per 10,000
  benign events of its logsource). The budget is measured on the benign
  corpus. A rule above budget is red; it is not tuned by hand in the report.
- **A4 Silence is red.** A rule whose fixtures did not run, a corpus file
  that is empty or unreadable, a modifier or condition Mizan does not
  support: each is a finding of status `unknown`, and `unknown` is red.
  Nothing is green by default.
- **A5 Evidence cites.** Every result names the rule id and the file and line
  of the fixture or corpus event it rests on. A result without a citation is
  not a result.
- **A6 Offline.** `check`, `test`, `match` and `corpus` make no network call.
  Export to a SIEM language is optional, lives in one module, and may import
  pySigma; nothing else may.
- **A7 Logs are untrusted.** Fixtures and corpora are data, never code: no
  eval, no exec, no format strings built from events, size limits on every
  line and file, and a malformed line is reported with its number, not
  skipped silently.
- **A8 Tree is ground truth.** What is not in git did not happen. The gate
  runs the whole rule set on every commit; a reviewer's error is recorded in
  `docs/review/`, never absorbed.
- **A9 Public and clean.** Nothing from private projects or private networks
  is copied here. Example rules and corpora are synthetic. The secret scan is
  mandatory.

## Roles
- **Builder** (Claude Code, cloud): executes HANDOFF tasks in order.
- **Reviewer** (read-only agent): compares the diff to HANDOFF and this
  constitution; raises findings; never edits.
- **Judge**: NEXT / REDO / STOP only. In doubt, STOP.
- **Commander** (the Table, acting for the owner): the only party that may
  widen scope, change the plan, or merge into branch `mizan`.
