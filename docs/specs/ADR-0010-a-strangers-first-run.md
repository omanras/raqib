# ADR-0010 - A stranger's first run

Status: proposed 2026-11-11 on the commander's order of that day ("fix the errors" of the outsider's rehearsal). Decisions 1-6: M9.1. Decision 7: M9.2. Decision 8 waits for the commander's word.
Amendments appended, never edited in place.

## Problem
A session that knew nothing of the project followed the README from a
clean home on main 0e8b007 and wrote two issue drafts
(docs/review/2026-11-11-outsider-rehearsal.md). Most of the story went
well: install in seconds, no dependency, the six hooks, the rules firing
as documented, no secret and no command text in the trace, the gate
green. What did not: a watch that is stopped the way services, containers
and closed terminals stop a program ends with no verdict; and seven small
things each cost a newcomer a moment of doubt. The Table checked each
against the tree before ruling; all eight hold.

## Decisions
Each names the case it is FOR and what it MUST NOT TOUCH (ADR-0007 Z-9).

1. A watch that is asked to stop, stops as Ctrl-C does. `raqib watch` and
   `raqib watch --host`, run from the terminal, take SIGTERM and SIGHUP
   (where the platform has them) and Ctrl-Break on Windows (SIGBREAK) as
   a stop: the line "stopped (SIGTERM)" (the signal's name), the final
   report, the registry row finished, and Raqib's exit code 0 / 1 / 3. A
   second such signal while the report is being written does not cut it
   short. FOR: `kill`, `systemctl stop`, `docker stop`, a closed terminal,
   a dropped ssh. MUST NOT TOUCH: Ctrl-C's words and code; the window
   (`raqib app` runs its watches in threads and installs no handler); A4 -
   Raqib still signals no process; a command with no final report keeps
   its default. What stays out of reach is said in the README: SIGKILL,
   and on Windows TerminateProcess (taskkill /F, the Task Manager): such a
   watch prints nothing, and `raqib report <trace>` gives the findings.
2. `raqib --version` (and `-V`) prints `raqib <version>` and exits 0.
   MUST NOT TOUCH: `raqib` with no command still exits 2 with its usage.
3. A notifier that works is not MISSING. Where the knock still reaches
   the person by the terminal (bell and stderr) and no desktop notifier
   was found, doctor says UNSURE with what is and is not there, and that
   line never fails doctor's exit (ADR-0006 A-9's precedent: watch does
   not need it). MUST NOT TOUCH: MISSING where notifications are off (CI
   is set, SystemRoot not trusted) - as now, exit included; what
   `raqib watch` says of its own notifier at its start.
4. A finding names the program that made it. DESTRUCT-CMD's and
   NET-TOOL's sentence names the program(s) of the line that the rule's
   own list holds, not the command's first word: for programs
   ["curl", "bash", "rm"], DESTRUCT-CMD says rm. The engine gives the
   sentence what matched (A1, A5: deterministic, from the cited line).
   MUST NOT TOUCH: which lines fire (every fixture, budget and kind count
   as now), the cited lines, and whatever keys a finding for the act
   registry, the knock ledger and the folding of notifications - a
   finding is the same finding, with a truer sentence.
5. The report says what its ALARMS line counts. The line itself stays
   (tools and tests read it); one line under it, in the text report only,
   says that it counts the trace's own alarms (A3 silence, A5 a record
   that cannot be cited) and that every finding below also makes the
   RESULT an ALARM. MUST NOT TOUCH: the JSON report, the counts, the exit
   codes, the page.
6. The quickstart's first command succeeds. The README's install block
   is clone, install, `pipx ensurepath` (said as what puts `raqib` on
   PATH), `raqib watch`. `raqib doctor` follows as the command for "what
   is missing", with the sentence that before the first watch it reports
   the hooks MISSING and exits 1, because `raqib watch` is what installs
   them. MUST NOT TOUCH: the three first headings (tests pin them) and
   what doctor does.
7. (M9.2, after M9.1 lands) The README's top is one screen: what Raqib
   is, the install block, and a sample final report. The ruling-by-ruling
   detail moves under docs/, sentence for sentence; every test that pins
   a README sentence follows it to where it went. No sentence is lost and
   none is left untested.
8. (the commander's) A LICENSE file and the `license` field. Without one
   the default is all rights reserved, whatever the README says of the
   project. Which licence is his decision alone; the Table writes the
   file and the field when he names it.

## Consequences
- The exit code becomes a contract a supervisor can use; the README stops
  promising more than the code does.
- Decision 4 touches the engine's sentence builder: every rule's summary
  is re-rendered in its tests, and the catalog's two summaries change.
- Decision 3 lowers one doctor line from MISSING to UNSURE: a headless
  box passes doctor; a desktop with no notifier also passes, and reads
  the line that says its knocks reach the terminal only.

## Amendment A (the Table, 2026-11-11) - decision 8, the commander's word
The commander, the same morning: CC0. The Table wrote it (M9.3): `LICENSE`
is the CC0 1.0 Universal legal code, unedited, as SPDX publishes it
(spdx/license-list-data, text/CC0-1.0.txt); `pyproject.toml` says
`license = {text = "CC0-1.0"}`, the table form, because every setuptools
from 61 on reads it and the tests build a real wheel offline with the one
at hand (68 here refuses PEP 639's string; 84 reads the table with a
deprecation warning - when a setuptools drops it, the field becomes the
string and the build needs 77: recorded); README's last section
says it in plain words, with what CC0 does not give (a warranty, a patent
or trademark right). A test pins the three. No name is written in the
dedication: the commander adds his if he wishes. The other branches of
the repository (mizan, qayd, qayd-web, dawr) carry no licence; this one
covers what is on main.

