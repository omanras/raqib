# Ruling R#001 — Qayd Web v0.1, branch claude/qayd-web-v0.1 @ fa7db96

Reviewer: the Table, in a session that had not seen the builder's context,
on a clean worktree of the branch.

## Witnessed (not taken from the builder's report)
- `tools/gate.sh`: GREEN end to end here: npm ci, tsc strict, vitest 1,462
  tests in 23 files (including tests/differential/oracle.test.ts, deep
  equality against reference/oracle/*.json), vite build, release check,
  Playwright 39 e2e tests in 15 specs (offline, file://, private mode,
  mobile, a11y, every screen), 1.3 minutes.
- Build: dist/ has one file; release/qayd.html is byte-identical to this
  commit's build; 281,583 bytes (limit 1.5 MB); no remote URL in it.
- Opened release/qayd.html from file:// in Chromium by hand: empty state,
  "Load the sample household", dashboard with the policy board and the
  CLI summary line verbatim, Review with the eight sections and "Copy as
  HTML"; Arabic switch sets dir=rtl.
- Static: no fetch/XHR/WebSocket in src/; no parseFloat/Number/toFixed in
  src/engine/; reference/ untouched since the kit commit.

## Findings (suspicion only)
- F1 Inherited from Qayd F2: `months_of` limits print the full Decimal
  (3695.678618181818...). Display rounding to the currency's minor units
  in both the CLI and the app; the oracle must be regenerated together.
- F2 The sample household ends at 2026-09, so "as of today" shows four
  `missing` verdicts on first load. Correct (A3), but the empty state
  should say the sample's last month, or default as-of to 2026-09-30 when
  the sample is loaded.
- F3 Visual: the app is functional and clear but plain; a design pass
  (type scale, spacing rhythm, chip contrast in dark mode) is v0.2 work.

## Process (A8)
- The scheduled builder session was stopped after M0.2 to save the
  owner's weekly plan usage; a cloud-credit session (claude --cloud)
  resumed from the branch and finished M0.3-M2.2 plus the report.
- Branch `qayd-web` carried one commit the builder branch did not
  (docs/BUILDER_PROMPT.md), so this is a merge commit, not a fast-forward.

## Verdict
**NEXT.** Merged into `qayd-web`. Open: M2.3 (outside user), F1-F3 as a
v0.2 handoff.
