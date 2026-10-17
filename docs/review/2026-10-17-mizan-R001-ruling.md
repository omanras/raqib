# Ruling R#001 — Mizan v0.1, branch claude/mizan-v0.1 @ c837e22

Reviewer: the Table, in a session that had not seen the builder's context,
on a clean worktree of the branch.

## Witnessed (not taken from the builder's report)
- `tools/gate.sh`: GREEN. pytest 295 passed, 6 skipped (4 real-pySigma
  tests skip without pySigma, 2 need a non-root user).
- `python3 -m mizan check rules/ --corpus corpus/`: green; ten rules pass;
  six at non-zero fp/10k, all within budget, no budget above 40.
- GitHub Actions run 39013977987 on 6b7e95a: completed, success.
- Static: no eval/exec/subprocess/urllib/socket in `mizan/` (A6, A7).
- Adversarial, by hand: unsupported modifier (`base64offset`) -> unknown,
  named; aggregation (`| count() > 5`) -> unknown, named; a rule whose
  logsource has no corpus -> no_corpus (red); a match-everything rule
  (`message: '*'`) -> over_budget with 1000/1000 corpus lines cited.
  Exit codes 1 on every red. Nothing green by default (A4 holds).

## Findings (suspicion only)
- F1 Regex backtracking has no timeout (builder's own open item, M0.2). A
  hostile `re` pattern can stall `check`. Recorded; v0.2.
- F2 The builder's report counts 299 passed / 2 skipped; this review saw
  295 / 6 because pySigma is not installed here. Not an error, but the
  report should state the environment the count came from.
- F3 `check --json` nests fp figures under `corpus`; the text output
  prints them on one line. Fine, but the README should show the JSON
  shape once.

## Process (A8)
- Eight tasks, one commit each, advanced by `tools/next-task.sh`; every
  task has a questions file with the conservative reading stated. The
  protocol was followed as written.
- Cost: the single cloud session ran about two hours.

## Verdict
**NEXT.** `mizan` fast-forwarded to c837e22. Open: M2.3 (outside reader),
F1-F3 as a v0.2 handoff when the owner resumes.
