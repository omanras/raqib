# Resume note (the Table, 2026-11-04, 15:55) - for the next Table session

State: main = d30f6da, pushed (the repo was made public by the commander
today; Actions minutes no longer metered). Phase 7 (ADR-0007) is built:
M7.1, M7.2, M7.3, M7.2b, M7.4 merged with --no-ff, each after review and
rulings recorded as ADR-0007 Amendments A-L. Gate on main: 2721 passed,
19 skipped; kinds 4 : 7 : 11. HANDOFF.md: none pending.

Pending, in order:
1. CI for d30f6da: the first run to see M7.4 and its REDO on windows. Read
   the six jobs from api.github.com (runs?head_sha=d30f6da). If a windows
   job fails, the pattern so far has been windows-only test shapes (Tk
   fakes, path separators): a follow-up commit on a branch, then merge.
2. The commander's field test (ADR-0007 Amendment L): Windows + Kimi,
   `raqib-app` on the host, NEW-AGENT / NEW-AGENT-UNKNOWN when Kimi starts,
   HOST-RHYTHM over a session, `--suspect ollama` if present; Ubuntu with
   python3-tk. The real false-positive budgets (act-root, NEW-AGENT-UNKNOWN
   on per-user IDE installs, HOST-RHYTHM) are his to measure.
3. Recorded later tasks: CROSS-SOURCE over host lines; the install-hooks
   link check for `raqib watch` (I-10/S-1 of M7.2b); pacing of suspect
   calls (M7.4 S-1); the README loop recording the system drive (M7.1
   S-2); THREAT_MODEL lines for P8/P18 of M6.4/M7.1; the window's band
   showing blind spots (M7.4 S-5); M5.4 Kimi hooks (optional now).

Standing rules that governed this run: CLAUDE.md rule 8 (the Table writes
HANDOFF, ADRs, handoffs, docs/review); the loop = builder on claude/<task>
with one landed:/STOP: commit -> read-only reviewer -> ruling as an ADR
amendment -> REDO -> six CI jobs via api.github.com -> merge --no-ff; rule
D-8 (every REDO change carries a test); HANDOFF <= 30 lines; never a real
host, user name or IP in the tree; nothing from the private Haris tree.
Known hazards of the box: container restarts kill long agents (resume
from the draft on disk, verify it, A8); the stop hook's "unpushed" count
is a stale tracking ref in the shallow clone; `tools/gate.sh | tail`
hides the exit code - capture it.
