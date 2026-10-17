# HANDOFF — M1.2  (phase 1: Dashboard, Ledger, Holdings)

Task: the three data screens per docs/specs/ADR-0001-app.md §3.

Scope:
  src/ui/
  src/i18n/
  tests/ui/
  e2e/
  docs/review/

Exit criteria:
- E1 Dashboard: as-of date input (default today, persisted in meta); the
     policy board (verdict chip coloured by verdict, title, measure vs
     limit text exactly as the CLI prints it, period); findings list;
     per-policy "why" expander listing the cited rows (file:line and the
     row itself); the CLI summary line verbatim (e.g. "RED as of ...").
- E2 Ledger: table newest first with filters (month, account, category,
     tag, text); "Add row" form validated by the engine before appending
     (date, amount, currency defaulting to base, account, category, tags,
     note); "Reverse" on a row appends the mirror row tagged `reversal`
     with a note citing the original line; raw CSV panel with line-level
     problems, Save only when parse has no problems.
- E3 Holdings: snapshots grouped by date, "New snapshot" pre-filled from
     the latest, stale indicator vs snapshot_max_age_days; raw panel.
- E4 Every change writes the file text through the serializer and re-runs
     `check`; the dashboard reflects it without reload.
- E5 e2e: load sample; dashboard at 2026-09-30 shows 8 hold + 1 red
     finding; add a discretionary row of 200 OMR dated 2026-09-28 ->
     WLT-01 breach; reverse it -> hold again; holdings stale after setting
     as-of to 2026-12-31. Gate green.

Not in scope: Decisions, Policies, Settings, Review.
Commit: `landed: M1.2 dashboard, ledger, holdings` or `STOP: M1.2 <reason>`.
Read HANDOFF.md and do only the task it specifies.
