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

## State at the end of the 2026-11-11 session (the Table)
The commander's order of 2026-11-10 (the correction after the second
field run; an easy way to add rules in the window; a modern look) is
built in four tasks, each after review and rulings, all on main:
M7.8 (ADR-0007 P, R, T, V, W: os lines judged by NET-TOOL / DESTRUCT-CMD
with Windows programs, one act one finding in every order, benign trees
noted, quiet is not gone, Defender benign), M8.1 (ADR-0009 A-D: the
look), M8.2 (ADR-0009 E-H: `raqib rules --new / --remove`, the form with
Test and "on your records", Remove by the row's own place), M7.9
(ADR-0007 X, Z, AA-AE: the round reads the Sysmon channel).
HANDOFF.md none pending. Not reviewed by a fresh reviewer, and said so
in the amendments: the Table's own last commits on M8.2 (H-1..H-4), on
M7.9 (AE-1, AE-2) and the window's meeting with M7.9 (AB-2, AB-9, AB-11).

Pending, for the commander - the third field run on the Windows machine:
1. The look on his display: DPI, the dark title bar, the open "Could not
   see" panel on a visible window, the form at his window size.
2. Kimi (or any agent) running curl / ssh / a destructive command: a
   NET-TOOL or DESTRUCT-CMD finding on its tree, knocked once.
3. MsMpEng no longer an unknown agent; a benign tree's finding is a note.
4. The channel: does real wevtutil accept the round's query (no
   channel-unread hole)? Does his Sysmon log events 3, 11, 22 (the first
   lines and the SYSMON line say; with no event 11 at all every os source
   says so and the watch ends INCOMPLETE, as before M7.9)? The count of
   "unknown, by the channel" trees after an hour of ordinary use: AA-1
   waits for this number to rule whether such a tree knocks.
5. A brief agent: start Kimi, let it act, close it inside one round: a
   NEW-AGENT with the word `brief`, its acts judged.
6. Rules -> New rule: a program rule (terraform), Test, "on your
   records", Add, then Remove; `raqib rules --new` / `--remove` in the
   terminal; a second watch says the rule and how it was measured.
7. The KNOCKS ledger against the notification centre, toast by toast.
Still open from the second run: what ran in PowerShell pid 5888; whether
his Sysmon records event 24 (M7.10 waits for it and a real export).

Recorded later tasks: M7.10 AGENT-CLIPBOARD; M7.11 a benign host of a
model client; M7.12 the tree ledger and its keys (AB-11, AD-1, AD-2, AE-3,
AE-4: a bound on by-the-channel trees, one tree across an unread start,
the holder of a helper's link, a footprint whose agent ran only between
rounds); M8.3 the window's notes (ADR-0009 H: a log of what the
catch-alls caught, the orphan overlay entry's words, a real watch under
the form's "running" test, a way to name a program benign, Q-10's
column, G15, G18); M7.7 ProcessId on os lines and a bounded follow; the
session protocol's next revision (ADR-0007 AE ledger: a milestone that
adds a source is ruled first by a property against the build without
it, and what remains is sorted by direction - silence fixed, a knock
more said).

## Later the same day (2026-11-11): the outsider's rehearsal (ADR-0010)
The commander handed the Table an outsider's rehearsal of main 0e8b007
(docs/review/2026-11-11-outsider-rehearsal.md) with "fix the errors",
and named the licence. Built, each after review and rulings, all on
main: M9.1 (a watch asked to stop - SIGTERM, SIGHUP, Ctrl-Break - ends
with its report, its record and its code; a terminal that is gone costs
the words only; `raqib --version`; doctor's notifier line; a finding
names the program that made it; the ALARMS lines; the quickstart),
M9.2 (the README is one page, the rest word for word in docs/GUIDE.md),
M9.3 (CC0 1.0 Universal: LICENSE, the package field, README).
HANDOFF.md none pending. Not reviewed by a fresh reviewer: the Table's
wording commits on M9.1 (D-1, D-2) and M9.2 (F-1), and M9.3.

Added to the commander's third field run: `raqib --version`; stop a
watch by closing its console window (Windows ends it before the report:
said in the guide) and by Ctrl-Break; whether a watch that is not
elevated reads the Sysmon channel (said nowhere: ADR-0010 F-3).
Open with him: his name in the licence's dedication (none is written);
a licence for the other branches (mizan, qayd, qayd-web, dawr have none).

Recorded later task: M9.4 the terminal's knock and its page (a bell rung
on a terminal that is gone is a failed knock; the page shows the
lost-words note; the record written once more after the report; three
docstrings that still say "the README").

## The third field run's first minute (2026-11-11, evening)
The commander opened the window from main 082aad6 on his Windows machine
(Python 3.14): white, Not Responding. M8.4 (ADR-0009 Amendment I,
docs/review/2026-11-11-M8.4.md): ttk tiles an image element's middle and
the middles were two pixels; measured on windows-latest, the window was
white for 19 to 118 s by scale and Python, and about a second after the
fix. The Table's own fix, not yet read by a fresh reviewer. Recorded:
M8.5 (a timing probe of the opening in CI; Python 3.14 in the matrix).
The rest of the third field run's checklist above still stands.

