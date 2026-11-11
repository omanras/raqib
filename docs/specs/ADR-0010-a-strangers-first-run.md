# ADR-0010 - A stranger's first run

Status: accepted for decisions 1-6 (M9.1, 2026-11-11, Amendment D) and decision 8 (M9.3, 2026-11-11, Amendment A: CC0); decision 7 open (M9.2). Proposed 2026-11-11 on the commander's order of that day ("fix the errors" of the outsider's rehearsal).
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

## Amendment B (the Table, 2026-11-11) - rulings on review 2026-11-11-M9.1.md (9846a52)
E2, E3, E4, E5, E6 MET; E1 and E7 PARTLY. Verdict: REDO on B-1 and B-2.
Each ruling names the case it is FOR and what it MUST NOT TOUCH.
- B-1 (D1, must) A stop never depends on its own words being written.
  When a watch is stopped - by a signal or by Ctrl-C - what it keeps is
  written first and whatever it prints is written after, and no failure
  to write to the terminal (a hung-up tty, a closed pipe) skips the
  record or changes the code: watch.json finished, the registry row
  finished, the host watch's sources and channel closed, and the exit
  code 0 / 1 / 3 - not 1 from a traceback, not 120 from a last flush.
  FOR: decision 1's own case, a closed terminal or a dropped ssh. Tested
  in process with an `out` that raises on every write after the signal,
  for `raqib watch` and `raqib watch --host`, and with a real child whose
  output pipe the test closes before the SIGHUP. MUST NOT TOUCH: with a
  terminal that takes the words, the words and their order are as now.
- B-2 (D2, must; the Table's own sentence in decision 1) What a killed
  watch leaves is said per watch. A killed `raqib watch PROJECT` prints
  nothing, and `raqib report <trace>` gives its findings. A killed
  `raqib watch --host` prints nothing, and no command re-prints its
  report: what it had found up to its last round is in its state file
  and its rounds record under ~/.raqib/host/, named by path. README and
  the help say exactly that, after the builder reads what those two
  files hold.
- B-3 (D4, D6; Q-2 confirmed) The words name every case. README's
  out-of-reach list gains: on Windows, closing the console window,
  logoff and shutdown end the process before the report (Ctrl-Break is
  what stops it there); and a signal that was already ignored when the
  watch started (nohup) is left ignored. The watch's first lines say
  which signals stop it and which were left ignored (A3).
- B-4 (D3, D7) The real-child test sends one signal; "a second signal
  does not cut the report short" is tested in process, where it can be
  timed. The two narrow windows - a signal before the handlers are set,
  and one after they are restored at the very end - are recorded: the
  second gives 143 or 129 after a complete report.
- B-5 (D8; Q-6: the Table's wording in decision 5) The line under ALARMS
  says what is counted truly: the alarms of the trace and of the watch
  itself - what could not be read, cited or kept - and that every
  finding below also makes the RESULT an ALARM.
- B-6 (D10) Scope is widened to one line of raqib/ruleform.py: a
  person's program rule made from the form names the matched program in
  its sentence, as DESTRUCT-CMD and NET-TOOL now do. MUST NOT TOUCH: the
  other three forms; a rule already in rules.d is not rewritten.
- B-7 Questions ruled. Q-1: confirmed as built - the two keys that hold
  the sentence live within one run and nothing reads them back (the
  reviewer traced each); decision 4's "no key changes" is read as "no
  key that outlives a run or decides a knock", and those are shown
  equal. Q-3 confirmed (single-value tests count). Q-4, D5: confirmed as
  built - a signal ends a host watch at once, as Ctrl-C does; a round
  whose reader is still out is a hole and the exit is 3. It does not
  wait for the round as the window's Stop does, because a supervisor's
  grace before SIGKILL (ten seconds by default for docker stop) is
  shorter than a reader's deadline and a watch killed there says
  nothing; README says it. Q-5: answered by B-1. D9 and D11 recorded
  (NET-TOOL fired by a host alone says "program -" beside the programs
  list: true, and plain enough).
- Table ledger: decision 1 listed "a closed terminal" among the cases
  and asked for no test of a terminal that is gone; decision 1's
  out-of-reach sentence named `raqib report` for both watches without
  reading what the host watch leaves. A FOR case is tested as the person
  meets it, not in its easiest form.

## Amendment C (the Table, 2026-11-11) - rulings on review 2026-11-11-M9.1-redo.md (84a2907)
B-2, B-3, B-4, B-6 MET; B-1 PARTLY (its own test cannot pass on Windows);
B-5 met as worded, and the words were the Table's. Verdict: REDO on C-1
and C-2. Each ruling names the case it is FOR and what it MUST NOT TOUCH.
- C-1 (F3, F5; Q-7; B-1's first sentence withdrawn) The words of a stop
  are said as they come. B-1 said "what it keeps is written first and
  whatever it prints after"; built as written, a person who presses
  Ctrl-C on a host watch can wait ten seconds for "stopped (Ctrl-C)",
  and a second press in that silence cuts the conclusion. The record's
  safety does not need the order: a write that cannot raise cannot skip
  the conclusion. So the hold, the queue and the release go; every word
  is written at once, guarded. FOR: "stopped (...)" is on the terminal
  before the conclusion begins, as it was before M9.1 - tested by its
  place among the calls, not by a clock. MUST NOT TOUCH: B-1's own case
  (a terminal that is gone loses the words and nothing else: the record,
  the row, the sources and the code), and close(running) runs on every
  path of the finally. README and the help drop the sentence about the
  order.
- C-2 (F1, must) The test of "a terminal that takes the words gets them
  as before" passes on Windows: it compares the watch's words with what
  the tree before M9.1's REDO printed for the same watch (the words and
  their order), and where it must hide a path it hides it in every
  spelling the code prints (the hook command on Windows writes forward
  slashes).
- C-3 (F2; Q-8 ruled "note it") Words that were lost are said where they
  can still be read. The terminal's guard keeps the first failure (when,
  which stream, why) and a count; the watch's state file and its
  registry row carry it as a note ("N writes to the terminal were lost
  since <time>: <why>"), and the final report says it if it can be
  printed at all. It is a note, not a hole: the code does not change
  (B-1). FOR: a watch whose terminal went away mid-watch. MUST NOT
  TOUCH: a watch that lost no word has no such note. What this does NOT
  yet do is said in README and recorded as M9.4: a knock whose only
  road is the terminal's bell, rung on a terminal that is gone, is
  still written down as delivered ("terminal") - making it a failed
  knock, and so a hole, is notify.py's and was out of Scope here.
- C-4 (F4; the Table's words in B-5, again) The line under ALARMS names
  what is counted: silence, a crash of the watch, a knock that did not
  arrive, and what could not be read, cited or kept - the trace's and
  the watch's own - and that every finding below also makes the RESULT
  an ALARM. Two lines if one is too wide. A test pins a silence window
  and a crash under it.
- C-5 (F6, F7, F9, F12) Words and one test: on Windows the first line
  names what can reach the watch there (Ctrl-C and Ctrl-Break), not a
  signal no other process can send; README's out-of-reach list gains a
  terminal that stops reading (Ctrl-S, a full pipe: the stop waits until
  it drains) and says "its newest knocks" of the host state; test_b6
  pins the sentence on a HostChild line.
- C-6 Recorded for M9.4: the terminal knock on a dead stream (C-3); F10
  (`raqib watch P >&-`: no stdout at all crashes at the start, as
  before); Q-10 (signals after the first are counted and said nowhere);
  F8; a second Ctrl-C during the conclusion still cuts it, as before
  M9.1.
- Table ledger: B-1's "kept first, printed after" was an order nobody
  needed, ruled because it sounded safe; B-5 rewrote decision 5's line
  and again did not read what the count holds. Two more of the Table's
  sentences read exactly. A ruling states the property it protects (a
  write cannot skip the record), not a sequence that happens to give it.

## Amendment D (the Table, 2026-11-11) - rulings on review 2026-11-11-M9.1-redo2.md (30ab1a4), and the judgement on M9.1
C-1..C-5 MET; no must-fix; the reviewer's verdict is NEXT on Windows CI.
- D-1 Questions ruled as built: Q-12 (the project state's "notes" key
  is there only when words were lost; the page shows it in M9.4), Q-13
  (the count is of failed writes and flushes: a lower bound, and the
  note says "writes"), Q-14 (the first line and the stop line use one
  name, SIGBREAK, with the key beside it). Q-11 (G1): the note counts
  what was lost up to the moment the record was kept; the report printed
  after it may be lost too and the record cannot say so - README and the
  help now say "up to the moment the record was kept" (the Table's
  commit, with its test); writing the record once more after the report
  is M9.4's, with the page.
- D-2 (G3; the Table's commit) README and the help no longer say that a
  terminal which stops reading "prints nothing": it holds the stop until
  it drains and then says its words; "prints nothing" is said of the
  watch that is killed or whose console is closed. The test pins both
  sentences and their order.
- D-3 Recorded for M9.4 (the terminal's knock and its page): G2, G4
  (the first lines are matched as a subsequence), G5, G6 (the note of a
  terminal gone and still gone), G7, G8 (the ALARMS lines read loosely
  for the model layer's alarms and are printed by `raqib report` too),
  with C-6's list.
- Judgement: NEXT for M9.1, on six CI jobs green for the Table's commit.
  Decisions 1-6 are accepted with Amendments B-D: a watch asked to stop
  ends with its report, its record and its code, and a terminal that is
  gone costs the words only; `raqib --version`; doctor's notifier line;
  a finding names the program that made it, in the catalog and from the
  form; the ALARMS lines say what is counted; the quickstart's first
  command succeeds. Not reviewed by a fresh reviewer: the Table's own
  wording commit (D-1, D-2).
- Table ledger for M9.1: two REDOs. Of five must-fixes, three were the
  Table's sentences (decision 1's untested "closed terminal" and its
  `raqib report` for both watches; B-1's order nobody needed) and two
  were tests that could not pass on Windows. The reviewer's first
  question from now on is the one that found them soonest: can every
  new test pass on the other system, read line by line.

## Amendment E (the Table, 2026-11-11) - rulings on review 2026-11-11-M9.2.md (4cf5064)
E2 MET; E3, E4 met as tested; E1 PARTLY; no sentence lost. Verdict: REDO
on E-1. The Table read the new README as a stranger before the reviewer
did, and the two agree: the HANDOFF's "move, do not rewrite" was right
for the guide and wrong for the first page - a sentence cut from its
paragraph keeps its words and loses its subject.
- E-1 (H1, H2, H4, H8; Q-4; must) "Where it runs" is written fresh, in
  at most eight lines, and each fact in it is pinned by a test against
  the code or the guide: Linux and Windows (and WSL: install on the side
  that runs the agent); Python 3.11 or newer, the standard library only;
  Claude Code for `raqib watch PROJECT`; `raqib watch --host` names no
  agent, and on Windows reads Sysmon where it is installed (what it
  misses without it: a link to the guide); the window, `raqib app`,
  needs tkinter and `raqib watch` does not; macOS as the tree stands -
  what is written for it, that the host watch has no reader there, and
  that no test runs there. The two sentences copied from the guide leave
  the README; the guide keeps them where they were. MUST NOT TOUCH: the
  first screen and its pins.
- E-2 (H6; Q-2, Q-7) The sample is an alarm about an agent's act. A new
  fixture trace of one short session in which a Bash command is caught
  by DESTRUCT-CMD and NET-TOOL (the rehearsal's own case: curl piped to
  a shell that runs rm), ended properly so that silence is not the
  story. The README's block is the code's own report of it with ONE
  marked cut: the rows of the RULES table become a single line that says
  so; the test derives the block from the code's output by exactly that
  rule and compares. One sentence before the block says which commands
  print it. Lines at most 120. Decision 7's "top" is read as the README
  itself; the sample stays after Doctor.
- E-3 (H7; Q-5) The Commands table is for a person, so new rows are
  allowed here and in the guide's table, each row's words checked
  against the help: `raqib app` first (the window), `raqib watch`,
  `raqib watch --host`, `raqib doctor`, `raqib report`, `raqib rules`
  (list, switch, add, remove), `raqib discover`, `raqib --version`, and
  the rest in one row that points at the guide. A row's command, typed
  as shown with real values for its capital words, runs; TRACE is said
  in one line under the table.
- E-4 (H10; Q-6) Scope is widened to the words in raqib/cli.py and
  raqib/discover.py that send a person to "the README" for what now
  lives in docs/GUIDE.md: help text, messages, hole text, and the
  docstrings that instruct. They name the guide. The E5 test covers
  every such string in raqib/, not cli.py's help alone. History (ADRs,
  review notes, THREAT_MODEL's past tense) is left.
- E-5 (H5; Q-3) G-7's first-screen property is retired on record: the
  Windows install line is in "Where it runs" (E-1), the path-rules
  sentence is the guide's, and the test's comment says so.
- E-6 (H9) The nothing-lost test counts: a code or table line that the
  old README had n times is in the two files at least n times; a
  sentence is found under its own heading where that heading is in the
  guide; and the other way round, every piece of the guide is from the
  old README except a listed few (its title, the linking lines of E-7,
  the rows of E-3).
- E-7 (H14) Where a section was split, the guide's part begins with one
  line that says the start is in the README, with the link; "this
  quickstart" names where the quickstart is.
- E-8 Ruled as built: Q-1 (tables and code keep their width; E3's wrap
  is for prose), Q-8, Q-9. H11-H13 recorded.
- Table ledger: the handoff forbade new words everywhere to keep the
  move honest, and so made the first page say that Raqib needs tkinter.
  A constraint that protects one property (nothing lost) is not applied
  where another matters more (what a stranger reads is true).

## Amendment F (the Table, 2026-11-11) - rulings on review 2026-11-11-M9.2-redo.md (83bd583), and the judgement on M9.2
E-1..E-7 MET; no must-fix; no sentence of the old README lost (the
reviewer found 15 more pieces by hand); the verdict is NEXT on CI.
- F-1 (J1, J2, J12; the Table's own commit, each with its pin) Three
  sentences of the first page said less than the tree: tkinter is
  python.org's Python's own, and `python3-tk` is Debian's and Ubuntu's
  package for it; on macOS the hooks and doctor are written for it as
  well as the notifications and the page opener, `raqib discover` has no
  live reader there either, and none of it is tested; and the rules row
  names `--new ID`, the terminal's twin of the form.
- F-2 (Q-10, ruled while the build ran; J7) E-2's "lines at most 120"
  and the handoff's E1 give way inside the sample's fence: a cited line
  is what the code prints (142 characters at the least for a Bash line,
  220 here) and is not cut a second time; every line outside the fence
  keeps 120. The test's cap on a fenced line is the report's own.
- F-3 Recorded: Q-11 and J10 (three docstrings, never printed, still say
  "the README" for what the guide now holds; they are listed in the
  test, and go with the next change to those files); J3 (whether a watch
  that is not elevated can read the Sysmon channel is said nowhere: the
  commander's field run answers it); J4, J5, J13 (four pins hold words
  or help text, not a fact of the code); J6 (the sample trace has the
  rule fixtures' older shape: no source key, no git keys; the report is
  the same); J9 (`discover --read` is in the help and not in the guide);
  J11 (the nothing-lost test checks membership, not count, in the
  reverse direction, and not order).
- Judgement: NEXT for M9.2, on six CI jobs green for the Table's commit.
  Decision 7 is accepted with Amendments E and F: the README is one
  page a stranger can read - what Raqib is, how to start it, what an
  alarm about an agent's act looks like (the code's own report, tested),
  where it runs, the commands with the window first - and everything
  else it said is in docs/GUIDE.md word for word, each pin following its
  sentence. With it ADR-0010 is accepted whole. Not reviewed by a fresh
  reviewer: the Table's wording commit (F-1).
- Table ledger for M9.2: one REDO, and its cause was the handoff. "Move,
  do not rewrite" was applied to the one section that had to be written.
