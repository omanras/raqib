# HANDOFF — M5.0b  (phase 5: discover after the Kimi field test, ADR-0004)
Task: close the anchor's first measured false negative (field note 2026-11-02
kimi-discover): an agent between requests owns no connection; its acts go to an ancestor.
Scope:
  raqib/discover.py, raqib/discover/endpoints.yaml, raqib/cli.py (discover options only),
  README.md (discover section), docs/specs/ADR-0004-agent-discovery.md, tests/, docs/review/, raqib/ui.py (discover tab)
Exit criteria:
- E1 Windows window: the README export becomes a PowerShell loop (N samples,
     default 6, 10 s apart) writing win-process-<k>.csv / win-tcp-<k>.csv in
     one folder; `--from` reads every sample and merges them as the Linux
     window does; run.json records the sample count; one sample still works.
- E2 Recent talk: a TIME_WAIT row (owner 0) to a catalog endpoint IP, or a
     DNS cache row for a catalog host, is an evidence line "recent talk, owner
     unknown" with cites, never a candidate by itself; holes text names it.
- E3 Class `act-root` (kind signature, evasion listed): image under a user
     directory (Users\<name>, AppData, ~, /home), not a known shell or system
     image, descendant chain shell -> ... -> command, no live talk. Weaker
     class, exit 1, same cites; a later sample showing talk promotes it to a
     candidate (E1 merge). fp_budget 0.25, measured.
- E4 First fp numbers: synthetic benign exports as fixtures (Linux desktop +
     IDE terminal; Windows desktop + editor under AppData\Local\Programs +
     browser); `raqib discover --check` prints candidates and act-roots per
     fixture against the budget; README "no fp_budget" line replaced (B-8 test).
- E5 Kimi fixture, synthetic (no real export in the tree): kimi.exe under
     .kimi-code\bin, cmd parent, bash chain to ping, TIME_WAIT owner 0 to the
     api endpoint, DNS row; expects act-root naming kimi + the recent-talk
     line; a second sample with ESTABLISHED expects a candidate. Gate green.
Not in scope: proxy source (M5.2), Sysmon os source (M5.3), live Windows collection.
Commit: `landed: M5.0b discover window + act-root` or `STOP: M5.0b <reason>`.
Read HANDOFF.md and do only the task it specifies.
