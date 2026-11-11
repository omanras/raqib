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
