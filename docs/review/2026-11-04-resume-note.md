# Resume note (the Table, 2026-11-04, 15:55) - for the next Table session

State: main = d30f6da, pushed (the repo was made public by the commander
today; Actions minutes no longer metered). Phase 7 (ADR-0007) is built:
M7.1, M7.2, M7.3, M7.2b, M7.4 merged with --no-ff, each after review and
rulings recorded as ADR-0007 Amendments A-L. Gate on main: 2721 passed,
19 skipped; kinds 4 : 7 : 11. HANDOFF.md: none pending.

Pending, in order:
1. CI for d30f6da: DONE - run 41824346486, six jobs success (read by the
   Table from api.github.com at 16:10): M7.4 and its REDO are verified on
   windows. Phase 7's tree is green on both platforms.
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

## The commander's plan for the next session (said 2026-11-04, 19:12)
Recorded in his words' substance; the next Table writes the handoffs from it.
1. Install several other agents on the Windows machine and run them under
   Raqib: the unknown path (NEW-AGENT-UNKNOWN, act-root, HOST-RHYTHM) has
   not been seen on a tree the catalog does not know; each run is a field
   measurement for ADR-0007 (Amendment M is the first: Kimi, named).
2. The control panel: add and enable Raqib's rules for watching from the
   window (which rules run, their thresholds where the YAML declares
   them, on/off per rule), with improvements to the window's look. Under
   ADR-0005: control stays in the program the person sits at, never on
   the web page; a rule switched off is recorded in the report as off
   (A3: a silenced rule is said, not silent).
3. Then the rest of the recorded tasks (resume note above; Amendment M's
   three lessons for M7.5: AGENT-DARK-LIVE after a live tree is a note not
   a knock; the rhythm ring takes acts from every source of the tree; why
   the NEW-AGENT toast did not reach the commander beside the two
   AGENT-DARK-LIVE ones - read app.log first).
Order the Table suggests: M7.5 (the three lessons) first, since every
agent test after it would otherwise repeat the same noise; then the rules
panel; the agent runs interleaved as the commander installs them.

## Recorded 2026-11-09 (M7.6c follow-up, builder's Q-15): a sandbox path in a real export
tests/fixtures/discover/linux is an M7.1 live capture of the build sandbox
and names its home directory in cwd and socket paths; five rule fixtures
built from it (NEW-AGENT positive-new-named, negative-history-only;
HOST-UNWATCHED's three) carry the same. It is a build-sandbox user name,
not a person's, and it predates M7.6c. Task for the Table: redact the
export to a placeholder home (as the Windows exports use `user`/`field`),
regenerate the five fixtures, re-measure the M7.1/M7.2 budgets, and then
make the whole-tree "no absolute home" test (E-1's wider form) pass.

## State at the end of the 2026-11-09 session (the Table)
main = f9618f9, pushed; CI run 42592946947 six jobs success; gate 2902
passed, 22 skipped; kinds 4 : 7 : 11;
HANDOFF.md none pending. Landed today, each after review and rulings:
M7.5 (ADR-0007 N, O: dark-after-live a note within a 9-round window;
rhythm reads every source; the KNOCKS ledger; the lost toast was sent by
Raqib, lost on Windows' side), M7.6 (ADR-0008 A, B: the overlay,
`raqib rules`, the panel, "N rules off" everywhere, CLEAN with suppressed
findings said), M7.6b (C, D: the look; Windows Tk 8.6 is the run of
record), M7.6c (E, F: thresholds editable only where an edge pair makes
the measurement sensitive - k, w, r, streak, live_window; suspect_every a
watch option), M7.6d (G: the M7.1 linux export redacted to /home/user).
The commander's plan of 2026-11-04 is built except the field runs.

Pending, for the commander: the field runs on the Windows machine - more
agents (the unknown path: NEW-AGENT-UNKNOWN, act-root, HOST-RHYTHM have
not fired on a tree the catalog does not know); compare the KNOCKS ledger
with the notification centre toast by toast; try the Rules panel (turn
AGENT-DARK-LIVE off, set HOST-RHYTHM k to 4, watch the measurement words).
Recorded later tasks (ADR amendments name them): a real desktop export
shipped with the commander's consent (ADR-0008 E-4); the AGENT-DARK-LIVE
hole text rendered from live values (F, P16); os_sysmon writing ProcessId
(ADR-0007 O); CROSS-SOURCE over host lines; the install-hooks link check
for `raqib watch`; pacing of suspect calls; the README loop's system
drive; THREAT_MODEL lines; the capture helper redacting homes by default
(G, Q-5); docstring example homes (G, Q-4); `--remove` for user rules.
