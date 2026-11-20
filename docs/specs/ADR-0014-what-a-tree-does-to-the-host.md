# ADR-0014 — What a tree does to the host: the first rules of behaviour

Status: accepted (the Table, 2026-11-20, under the commander's word of 2026-11-18: "rules of behaviour beside the
rhythm", and on his field test of 2026-11-20). Date: 2026-11-20.

## Context
Raqib finds an agent by what its tree does: it talks and it acts (ADR-0007). What the tree then does to the host
is judged by rules that know program names (NET-TOOL, DESTRUCT-CMD), or that need a project's hooks (the SCOPE
and DRIFT rules). Under `raqib watch --host` with the os source alone, a file line and a net line are written
and judged by no rule.

On 2026-11-20 the commander ran a named agent on Windows against a prompt that made it do three things: write a
file under TEMP by a powershell under a cmd; set an autostart value of the user's (a value under
`HKCU\...\CurrentVersion\Run`); open a TCP connection to port 22 of another machine of his network. Raqib named
the agent's tree and knocked (NEW-AGENT, high). Of the three acts it said nothing. His copy of Raqib was an
older one (its own words say so: no `events` line at its start, the `bytes` blind spot with no reason after
it); the rules that judge these lines have not changed since, and the repeat below is on main.

## Measured before ruling (the probe branch 2cd543d, GitHub's Windows machine, main c596cbf merged, never merged)
Sysmon logged every event of the kinds Raqib reads (1, 3, 11, 22) and the registry's events under
`\CurrentVersion\Run` and `\Schedule\TaskCache\Tree`. The rig's stand-in agent (a process that keeps a connection
and starts children) did, each harmless and each undone at the end: (1) a file under TEMP by a powershell under
a cmd; (2) an autostart value by reg.exe and one by PowerShell, a file in the user's Startup folder, a scheduled
task; (3) a connection to port 22 of the machine's own private address from PowerShell's own socket, and one by
ssh.
- What the watch said: NEW-AGENT-UNKNOWN on the stand-in; NET-TOOL (medium) for ssh, as for its curl. Nothing
  for the file, the autostart entries, the task, or the connection that no ssh made.
- What the stand-in's os source held, judged by no rule: the file line of act 1 with its path; the process lines
  of reg, powershell and schtasks (the programs, never what they wrote: a command line is a hash); the file line
  of the Startup file with its whole path; a net line with `dest_port` 22 and `dest_private` true for each of the
  two connections. A net line names no program, and says a private address the same for loopback.
- What the host's own record held: one connection line (the stand-in's talk). The two short connections to 22
  were in no sample.
- What Sysmon said that Raqib does not read: event 13 (a value set) for each autostart value, with the program
  that set it (reg.exe, powershell.exe), its process id and ProcessGuid, the value's whole name under
  `HKU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\`, and the command in `Details`. About twenty seconds
  later Windows' own sihost.exe set values under `...\CurrentVersion\RunNotification\`: a key that begins with
  the same letters. The scheduled task was written by the Schedule service (svchost, SYSTEM), 24 ms after
  schtasks started: a key under `...\Schedule\TaskCache\Tree\` and a file under `System32\Tasks\`, neither by a
  process of the tree. Event 3 says who made a connection (`Initiated`) and by which program; the machine's own
  sshd had the same two connections as events with `Initiated: false` and port 22 as their destination.
- Not measured: Linux (no os source there); a value under the machine's hive or under RunOnce; a file moved into
  the Startup folder; a Sysmon whose configuration logs none of this; the commander's own Sysmon.

## Decision
- A-1 (what is judged). A tree's lines are judged for what they do to the host, beside what the program is
  called: deterministic rules over the lines the sources write. Where a line does not carry the fact a rule
  needs, the source is made to write that fact - a fact of the event, never an argument's or a value's text -
  and a line written before it is not judged by that rule (partial, and said), never guessed. FOR: an agent
  nobody has named, running a program no list holds, is judged by the act. MUST NOT TOUCH: nothing is written in
  the clear that was a hash (a command line, a value's text, an address).
- A-2 (stages; each lands by the loop, each measured on the rig first). S1: two rules over the os source's file
  and net lines, PERSIST-AUTOSTART and NET-ADMIN-PORT, and what a net line must carry for the second. S2: the
  registry's autostart values (Sysmon event 13) read as os lines and judged by PERSIST-AUTOSTART. S3: what the
  system's own services write for a tree (a scheduled task, a service), joined to the tree by time and by its
  program; the autostart places read by Raqib itself each round against what they held at the watch's start,
  so that the rule does not hang on Sysmon's configuration; one connection told by the host's sample and by the
  os source counted once, so that NET-ADMIN-PORT can judge the host's own lines too (Linux). S4: Linux's
  places.
- A-3 (PERSIST-AUTOSTART, S1). An os file line, or a file tool of the hooks (Write, Edit, MultiEdit,
  NotebookEdit), whose path is a file directly in a Startup folder of Windows
  (`...\Microsoft\Windows\Start Menu\Programs\Startup\`, a user's or all users'), `desktop.ini` left out. Class
  PERSIST (new), kind signature, severity high, ATT&CK T1547.001. FOR: an agent that leaves something to run at
  the next logon is said when it leaves it. MUST NOT TOUCH: on a benign tree a source finding is noted, not
  knocked, as before.
- A-4 (NET-ADMIN-PORT, S1). An os net line of a connection the process itself made, to port 22, 23, 135, 445,
  3389, 5900, 5985 or 5986 of a private address that is neither loopback nor link-local, unless the process is
  ssh started by git (NET-TOOL's own exception, ADR-0007 R-7). Class NET, kind signature, severity high, ATT&CK
  T1021. FOR: reaching another machine's login or administration port is said whatever program opened the
  socket (the measured case: PowerShell's own socket, no ssh). MUST NOT TOUCH: NET-TOOL as it is (ssh by its
  name stays its finding: the two say two things, that a program ran and that a port was reached); a loopback
  destination (WSL, a forwarded port) is not this rule's.
- A-5 (what an os net line carries, from S1). `initiated` (true where the process made the connection, false
  where it accepted one, as Sysmon says it; null where unread); `dest_scope` (loopback, link-local, private or
  public; null where the address is not one); `image` and `parent_image` (the names of the process the event
  names and of its parent, where the follow holds that process's start; through the gate a process line's names
  go through). `dest_port`, `dest_private` and the hashes stay as they are. Recorded, not ruled here: a line of
  an accepted connection says the listener's own port as its destination, and the rhythm reads os net lines as
  talks; whether an accepted connection is a talk is in the plan, to be measured.
- A-6 (what is not a finding). A file under TEMP, and a shell under a shell, are an agent's ordinary work. They
  are recorded (the lines are in the tree's source) and judged by no rule: a rule that fired on them would fire
  on every agent, every minute. The case file (the plan's smaller item) is where a person reads them beside a
  finding.
- A-7 (the registry, S2, ruled now so that S1 is built toward it). Event 13 only. A line of tool `registry`
  carries: `autostart` (run or runonce) only where the target is a value directly under `...\CurrentVersion\Run`
  or `...\CurrentVersion\RunOnce` of a user's hive or the machine's, the 32-bit view too - the match is on the
  key, never on a part of its name (measured: RunNotification); `hive` (user or machine); the value's name
  (redacted, bounded); the name of the program the value would run (through the gate of command_head); `image`
  and `parent_image`. The target and the value's text are in the line's hash, not in the clear. The round reads
  these events by a bounded read of their own, so a Sysmon that logs every key takes nothing from the events 1,
  3, 11 and 22; at its bound it says so, a hole of its kind. To be measured in S2: how many such events a round
  holds under a common public configuration of Sysmon.
- A-8 (the two rules' ways round are said). Each is a signature and lists its evasions in its YAML (ADR-0002),
  among them: every autostart place the rule does not read yet; a file moved or renamed into the folder; a
  Sysmon that logs no file creation or no connection there (nothing is then there to read, and Raqib cannot
  tell that from nothing done); a port not on the list; a public address; a relay or a tunnel; the host's own
  sample of a connection, not judged until S3 (Linux, and Windows without Sysmon); this machine's own private
  address, which a line cannot tell from another machine's.

## Consequences
- Two more YAML rules (16), a new class (PERSIST), four more keys on an os net line. Every guard that counts or
  lists the rules moves with them (ADR-0002's table gets its dated note).
- With the os source alone, of the commander's three acts: the connection is a finding after S1; the autostart
  value after S2; the file under TEMP is recorded and stays unjudged, by A-6.
- A scheduled task is not a finding until S3: measured, it is the system's service that writes it.
- Linux has no os source: neither rule judges anything there until S3 and S4. The window and the guide say so
  through the rules' own words.
- Recorded for its own ruling, not ruled here: Windows' own service hosts were knocked as unknown agents in both
  runs (svchost twice, an updater once).

## Amendment A (the Table, 2026-11-20) - the review of M15.1 (docs/review/2026-11-20-M15.1.md)
The reviewer said NEXT: the two rules do what A-3 and A-4 rule and the four keys are captured soundly; nine
things were to be put right first, each a few lines, and the Table made them in this commit. In the field (the
probe branch ff32c42, GitHub's Windows machine, the build of 0cc2831): the stand-in's Startup file was a
PERSIST-AUTOSTART finding, and its two connections to port 22 - PowerShell's own socket, and ssh - were each
a NET-ADMIN-PORT finding that names the program and what started it; each high, each knocked.
- AA-1 (F1: the kernel's own connections). Windows' SMB client connects to 445 as System, not as a process of
  the tree: a share, a named pipe, sc or schtasks against another machine are outside NET-ADMIN-PORT. Said in
  the rule's evasions and in the threat model; the documents say "whatever program of the tree". Not measured.
  It is S3's to measure with what else the system does for a tree.
- AA-2 (F2: link-local). A-4 left link-local out with loopback and gave a reason for loopback only. It stays
  out in S1 and is said as a way round; it is ruled again with S3, where the host's own lines are judged.
- AA-3 (F3: an unread Initiated is a silence). A net line whose Initiated was not read is not judged and no
  note says so. Real Sysmon writes it always, so the reach is small; it is still a silence (A3). S2 makes such
  a line the rule's partial note. Recorded in the threat model until then.
- AA-4 (F11: a Sysmon that gives no file event). Under the watch the follow is bounded and the round's check
  names events 1, 3 and 22: a channel that never gives event 11 is not said, and PERSIST-AUTOSTART's os branch
  hangs on it. The rule's words no longer say it is said. S2 closes it in the watch (it reads the registry's
  events there anyway).
- AA-5 (F4, F5, F12: said as it is). The rule's evasions gain: a file changed in place, a hard link, a hooks
  path not in its plain form, a file tool of another name. A move into the folder is "not measured", not a
  fact. The pattern has no anchor on its left: a copy of a profile fires, and so does another machine's
  folder through a share (the second is right).
- AA-6 (Q-1, F16: the budgets are not measured). Both rules read 0.000 on the benign corpus, and the corpus
  holds no os line of a desktop's ordinary work: the budgets stand on nothing a desktop does. Only a real
  recording measures them. Until one is in the corpus the threat model says so, with what would fire (a
  deploy over ssh inside one network, an editor's remote session, a local virtual machine, a profile's copy).
- AA-7 (recorded, not built). The generator's synthetic os talk lines keep the shape from before the four keys
  (Q-2): they read as older lines. A finding of NET-ADMIN-PORT cites the net line and not the start its names
  came from (F14). The four keys enter the watch's key of an act (F15): two feeds of one event that hold
  different starts would be two acts; not shown reachable. Port 139 is not on the list (F10).

## Amendment B (the Table, 2026-11-20) - S2 measured and ruled: the registry's autostart values (M15.2)
Measured before ruling (the probe branch cd55ab0, GitHub's Windows machine, main fbf7090 merged; twice: under
the rig's own configuration, and under a public configuration of Sysmon that many use, fetched there and never
kept in this tree). The stand-in set five harmless values, each undone: two under its user's Run key (by reg.exe
and by PowerShell), one under RunOnce, one under the machine's Run key, one under the machine's 32-bit view.
- Sysmon's event 13 named each one, with the program that set it (`Image`), its process, the command in
  `Details`, and the value's whole name in `TargetObject`, in these four shapes:
  `HKU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\<name>`, the same with `RunOnce`,
  `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\<name>`, and
  `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run\<name>`.
- Under the public configuration all five were logged, and they were the only events 13 of the 91 seconds (230
  events in all; the registry's are a few among them there, because that configuration names the keys it logs).
  Under it the two rules of S1 fired as on the rig's configuration (the Startup file; the two connections to 22).
- On a fresh machine the user's Run key was not there at all: the first value made the key (an event 12) and
  then set the value (an event 13). A value's removal is an event 12 (`DeleteValue`).
- A value under `...\Schedule\TaskCache\Tree\` is set by the Schedule service for every task, the system's own
  among them; its `Details` is a number, an id or `Binary Data`, never a command.
- Not measured: a configuration that logs every key (how many events 13 a pass then holds); a value set by a
  hive loaded from a file; a rename of a value or a key (event 14); the commander's own Sysmon.
- AB-1 (a rule of its own). A value set under Run or RunOnce is PERSIST-RUN-KEY, not PERSIST-AUTOSTART: a
  rule says one thing in one sentence, and its ways round are its own (ADR-0002). This replaces the words of
  A-2 and A-7 that named PERSIST-AUTOSTART for it. Class PERSIST, kind signature, severity high, ATT&CK
  T1547.001. FOR: the commander's second act (a value under the user's Run key) is said when it is set, whatever
  program set it. MUST NOT TOUCH: PERSIST-AUTOSTART and its fixtures stay as they are; on a benign tree a
  source finding is noted, not knocked, as before.
- AB-2 (the line). An os line of tool `registry` is written for an event 13 whose target is a value directly
  under `\Microsoft\Windows\CurrentVersion\Run` or `\RunOnce` of `HKU\<a SID>\SOFTWARE` or `HKLM\SOFTWARE`,
  with or without `\Wow6432Node` after `SOFTWARE`, in any case of letters: the four measured shapes and the two
  they imply. The match is on the whole key: `RunNotification`, `RunOnceEx`, `RunServices`, and a value of a
  key under Run are not it. The line carries `autostart` (run or runonce), `hive` (user or machine), `view32`
  (true under Wow6432Node), `value_name` (redacted and bounded as a path is), `program` (the name of the
  program the value would run, through the gate a command's head goes through; null where `Details` is not a
  command), `image` (the name of the program the event names, through the gate a process line's name goes
  through) and `parent_image` (as an os net line's: from that process's own start, null where the follow holds
  none). The target and the text of `Details` are in the line's hash and never in the clear (A-1). An event 13
  of any other key is not a line in S2. FOR: the rule reads facts of the event; nothing an agent wrote is
  copied into a finding. MUST NOT TOUCH: a process, file or net line, byte for byte.
- AB-3 (the read). Under the watch each pass of a tree's follow asks a second bounded question, for event 13
  alone, after its first: its own cap, its own highest record (kept with the tree the follow keeps, so that a
  follow attached again reads none twice), the same restart. The first question is what it was, to the byte.
  A second read that reaches its cap is said once, a hole of its kind; one that fails is said once as a
  silence and takes nothing from the pass's other lines. An event 13 is the tree's where its process is in the
  tree as the pass's first read left it. An export read by `raqib os-sysmon` gives its events 13 as lines too,
  in their time's order; `missing_events` stays a word about events 1, 11 and 3, so every line an export gave
  before is the line it gives now. FOR: a Sysmon that logs many keys takes nothing from the events Raqib
  already reads. Cost, measured only under the two configurations above: a second short read per tree per
  pass; what it costs beside a configuration that logs every key is to be measured (the plan).
- AB-4 (the watch). A registry line is an os line like the other three: the watch's key of an act, its word
  for an event's kind, and the rules of a tree's sources read it; it is paired with no line of the host's own
  record (told twice is a process's matter).
- AB-5 (what waits). AA-3 (an unread Initiated is the rule's partial note) and AA-4 (a channel that gives no
  event 11, and now none 13, said by the watch) are M15.2b, after this lands: until then the threat model
  says both. The rig's own claim for this rule is the Table's to add after the landing.

## Amendment C (the Table, 2026-11-20) - the review of M15.2 (docs/review/2026-11-20-M15.2.md): STOP, ruled
The reviewer said STOP: a pass asked its two questions one after the other, each with its own bound, and a value
set by a process whose start the first answer did not yet hold was dropped for good, with nothing said. AB-3's
word "after its first" was the Table's, and it was wrong. Measured before this ruling (the probe branch, GitHub's
Windows machine, the build of 8a262e3; the stand-in set 40 more values under its user's Run key, each by a
fresh reg.exe at a moment of its own, each undone):
- In 19 of 21 runs each of the 40 was a line and a PERSIST-RUN-KEY finding. In two runs 38 were: the two
  missing values' programs were all there as process lines, and the passes' own bounds show the cause - the
  second read's highest record was ahead of the first's (924 and 930; 1011 and 1014; 1190 and 1192): F1 as
  the reviewer read it.
- A value whose name holds a backslash (F5): Sysmon wrote its target as `...\CurrentVersion\Run\<part>\<part>`,
  the shape a value of a key under Run would have. The build did not make it a line, and said nothing.
- In two other runs every line of the stand-in's tree stopped about thirty seconds before the tree ended, its
  process lines too, and nothing said so; the tree was then quiet in the rounds while it still worked. Not seen
  in nine runs of main's build under the same acts. Its cause is not found yet (AC-9).
- AC-1 (F1: the order of a pass's two questions). The question for event 13 is asked first; then the first
  question, to the byte what it was. Every event 13 the pass takes was then logged before the other question
  was asked, so the start of the process that set it is in that answer or an earlier one. Where the other
  answer is cut at its cap, the pass takes no event 13 above the cut's last record, and the registry's bound
  stops there; where the other read fails, the pass takes none and the bound does not move. FOR: no value set
  by a tree's process is passed over because of when two reads happened. MUST NOT TOUCH: the first question's
  arguments; what a pass writes for events 1, 11 and 3.
- AC-2 (F3: a root not found yet). In a pass whose root is not found the registry's bound does not move.
- AC-3 (F5: a backslash in a value's name). An event 13 whose target is anything below a Run or RunOnce key
  of AB-2 is a line: `nested` is true where what follows the key holds a backslash, and `value_name` is all of
  what follows it. The event cannot tell a value whose name holds a backslash from a value of a key under
  Run; the rule fires for both and its sentence says that it cannot tell. `RunNotification`, `RunOnceEx` and
  `RunServices` are other keys and stay out. FOR: a name chosen to look like a key is not a way round. The
  cost is a finding for a value of a real key under Run, which Windows does not use; not measured on a desktop.
- AC-4 (F6: the value's name in a sentence). `value_name` is bounded at 80 characters, and a sentence shows it
  between double quotes, a double quote inside it written as an apostrophe. FOR: text an agent chose cannot
  pass for the sentence's own words.
- AC-5 (F2: the watch asks). The watch gives its follow the word to read the registry as it gives every other
  word; a test holds it; where a follow given to the watch does not take that word, the source's own words
  say that the registry is not read.
- AC-6 (F7: the sentences this stage made false). Every sentence of the tree that says the registry is not
  read, or names the os source's events and tools without event 13, is put right, the ones outside the first
  HANDOFF's Scope too (named in the REDO's Scope).
- AC-7 (F4, F8, F10, F12, F13: said, not built). An event 13 named by a pid alone; a value the system sets on
  a tree's behalf; a second read's problem at a line number said before; two follows that hold different
  starts; whether Windows runs a value under a user's 32-bit view, and how Sysmon writes SYSTEM's own hive:
  each is said in the threat model as not measured or not shown reachable.
- AC-8 (the rig). X34 is MISSED, not OPEN, where the stand-in set the value and no finding names its tree.
- AC-9 (the lines that stopped). M15.2 does not merge until the two runs' cause is found, or shown to be main's
  own (then it is recorded and ruled apart). The probe branch carries, for the probe only, one line for each
  pass of a follow and for each round's sources.

## Amendment D (the Table, 2026-11-20) - the second review (docs/review/2026-11-20-M15.2-redo.md): M15.2 lands
The reviewer said NEXT: the REDO does what Amendment C rules, the questions are asked in the ruled order, and
the fake channel of its tests grows between the two questions of a pass. In the field (the probe branch
f94b9bd, GitHub's Windows machine, the build that lands): thirteen runs, 40 values each by a fresh reg.exe at
a moment of its own - every one a line and a PERSIST-RUN-KEY finding, where the first build lost one to three
in four runs of seventeen; a value whose name holds a backslash was a finding that says so.
- AD-1 (AC-9 is met). The lines that stopped were Sysmon's empty ProcessGuid, main's own fault, found and
  ruled as ADR-0007 Amendment BV; its fix rides on this branch and was read by the same reviewer. With it, a
  run whose channel held eleven such starts wrote every child (the probe's build of the same change).
- AD-2 (said as it is; the review's must-fix items). The order Sysmon logs a process's start and its value in
  is not measured: AC-1 closes F1 where the start is logged first, and the documents say that, not more. A
  value whose name ends with a backslash is no line and nothing says so: said, not measured. The round counts
  an event of any kind that named its process by an empty ProcessGuid, not a start alone. What BV's join by
  pid costs is said whole (ADR-0007 BV-3). An empty ProcessGuid is a GUID of zeros and nothing else.
- AD-3 (recorded, each for its own measurement or ruling). Whether Sysmon ever logs a value before its own
  process's start; whether Windows runs a value under a key below Run, one whose name holds or ends with a
  backslash, or one under a user's 32-bit view; whether the follow's word on an empty ProcessGuid belongs in a
  tree's source only where that tree's own event was joined by pid; whether a child joined by its parent's pid
  should carry that parent's mark of a nested root; a placeholder of the rules' sentences chosen by a boolean
  (the nested clause is printed on every finding until then); AA-3 and AA-4 (M15.2b).

## Amendment E (the Table, 2026-11-20) - M15.2b: what was not read is said (AA-3, AA-4)
Two silences of the rules of behaviour were recorded when they landed (AA-3, AA-4) and left for this task.
Neither needs a measurement to rule: each is a fact the watch already holds and does not say.
- AE-1 (AA-3: an unread Initiated). An os net line whose `Initiated` was not read carries no `initiated` key
  (it carried null). A fact that is not there is unknown to the engine, so NET-ADMIN-PORT cannot judge the
  line and says so in its partial note, as it does for a line written before the four keys. FOR: a connection
  the rule could not judge is never counted as judged. MUST NOT TOUCH: a line whose Initiated was read, to the
  byte.
- AE-2 (AA-4: a channel that gives no event 11). The watch already says, once, when its rounds have read no
  event 1, 3 or 22 of the channel. It says the same of event 11: no file a tree makes is then seen, and
  PERSIST-AUTOSTART's os lines have nothing to read.
- AE-3 (AA-4: a channel that holds no event 13). The rounds do not read event 13 (a follow does, for its
  tree). At its first read the round's channel asks one bounded question more: the newest event 13 the
  channel holds, whatever its key. Where it holds none, that is a blind spot of the run, said once:
  PERSIST-RUN-KEY has nothing to read on this machine unless this Sysmon's configuration is changed. Where it
  holds one, the inventory carries its time and nothing is said: it shows that this Sysmon logs some registry
  values, not that it logs the Run keys, and the documents say that limit. Where the question cannot be
  asked, that is said as not known. FOR: a person learns at the start of a watch that a rule of his is blind
  here, not after an agent has used it. MUST NOT TOUCH: the round's own question each round, to the byte; the
  result and the exit code (a blind spot is counted apart).
- AE-4 (recorded). The certain cure is ADR-0014 S3: the autostart places read by Raqib itself each round, so
  that no rule of persistence hangs on Sysmon's configuration. It is the next stage of this track (M15.3).

## Amendment F (the Table, 2026-11-20) - the review of M15.2b (docs/review/2026-11-20-M15.2b.md): M15.2b lands
The reviewer's verdict is NEXT with five must-fix items, all words. Measured before ruling (the probe branch
10e54be, GitHub's Windows machine, two Sysmon configurations): under one that logs no file and no registry value
the watch said at round 3 that no event 11 was read and, at round 1, the blind spot `registry`, and its result
was what it was. Under one that logs the Run keys, on a fresh machine, the blind spot was said at round 1 and
stood for the whole watch though a value was logged seconds after the question.
- AF-1 (AE-2's words). Three rounds that read no event 11 are a Sysmon that logs no file creation, or three
  rounds in which no file was made: the watch cannot tell the two apart. Its sentence says what may be unseen,
  as the sentences of events 1, 3 and 22 do: a file a tree makes may be unseen, and PERSIST-AUTOSTART's os lines
  may have nothing to read. FOR: the watch never states as fact what it only failed to see. MUST NOT TOUCH: the
  rule that says it (once, after three rounds with the channel) and the three older sentences.
- AF-2 (AE-3's words). The question is asked once, at the watch's first read of the channel. Its answer is a
  fact of that moment, so the blind spot is said in the past tense and of that read: the channel held no event
  13 then; this Sysmon's configuration may log no registry value, or none was set under a key it logs in what
  the channel then held (a channel that wrapped or was cleared holds its latest part only); PERSIST-RUN-KEY may
  have nothing to read here; a value logged after it does not take the sentence back. Not ruled here: asking
  again each round, or taking the blind spot back when a tree's follow reads an event 13. That is a change of
  what a blind spot is (said once a run) and belongs with M15.3, where the autostart places are read by Raqib
  itself and the question is no longer needed. FOR: a sentence a later minute makes false is not said as a
  standing fact. MUST NOT TOUCH: when the question is asked, its arguments, the result and the exit code.
- AF-3 (the catalog). PERSIST-AUTOSTART's and PERSIST-RUN-KEY's lines that said the watch does "not say yet"
  what AE-2 and AE-3 now say are put right. NET-ADMIN-PORT says what AE-1 left unsaid: a line written by an
  earlier build with a null `initiated` is judged as not initiated, and nothing says so (a null is a value to
  the engine; such lines are in events files written between M15.1 and this build, and real Sysmon writes
  Initiated always).
- AF-4 (what the question costs, said and not measured). It is asked once: one that fails is not asked again,
  and the run says not known. It runs inside the first round that reads the channel, after its read, with the
  round's own timeout: a slow answer delays that round and can make it late; one that did not return is ended
  and recorded, and the next round carries that record as a hole of the channel's read (named as that round's),
  so the result is then incomplete; a run with no next round makes no hole. THREAT_MODEL says all of it. How
  long the question takes on a full channel that holds no event 13 is not measured (the runners' channels are
  minutes old): it is the first thing to measure on a real desktop, and where it is slow the cure is AF-2's.
- AF-5 (an answer that is not none). An answer that holds no event and is not empty (wevtutil's own words on
  its standard output, an encoding the reader cannot cut) is not "none": it is said as not known, with its
  length. FOR: silence is an alarm; a blind spot is never said from an answer that was not read.
- AF-6 (recorded). The blind spot's kind `registry` shares its word with the hole kind of the watches'
  registry in one report; the start line's and the guide's "one bounded wevtutil" a round is two in the first
  round; the answer's event is not checked to be Sysmon's event 13 (the round's read checks what it asked);
  a stand-in channel with no question says nothing. Each waits for M15.3, which removes the question.

## Amendment G (the Table, 2026-11-20) - S3 measured and ruled: the autostart places read by Raqib itself (M15.3)
The three rules of persistence hang on Sysmon and on its configuration: where it logs no file or no registry
value there is nothing to read (Amendments E and F only say so), and what the system's own services write for
a tree (a service, a scheduled task) no line of the tree tells at all. A-2's S3 answers both: Raqib reads the
places itself.

Measured before ruling (the probe branch 80eee27, GitHub's Windows machine, the standard library alone, no
helper process, no right asked):
- Every place read in 0.07 s (0.24 s the first time): the Run and RunOnce values of every loaded hive and the
  machine's, both views (2 entries); the two Startup folders (3); the scheduler's tree in the registry (236
  tasks, 26 of its keys refused) and its folder of files (212); the services' key (687 with an ImagePath);
  Winlogon's Shell and Userinit.
- A quiet minute and a half, a read every 5 s: nothing changed in any place.
- Four acts by the system's own tools, each harmless and undone (a Run value, a file in the Startup folder, a
  scheduled task, a service never started): each was in the first read after it (under 0.1 s) and gone from
  the first read after its undoing; nothing was left. The user's hive is read twice by two names (HKCU, and
  HKU under its SID) and its Run key is one key in both views: an entry must be counted once.
- Under a token whose Administrators group is deny-only: the Run keys, the Startup folders, the services and
  Winlogon are read as before; the scheduler's tree and its folder are refused whole.
- Not measured: a real desktop's churn (an updater that makes its own task or service); the scheduler's own
  query tool under fewer rights (the probe is extended for it); how long the read takes on a machine with
  thousands of services.

- AG-1 (what is read). On Windows, by the standard library, in the watch's own process: the values under Run
  and RunOnce of every loaded user's hive (by its SID, never twice) and the machine's, the 32-bit view where it
  is another key; the files directly in a user's and all users' Startup folder (`desktop.ini` left out, as
  A-3); each service's ImagePath, Start and Type; each scheduled task's actions and triggers where the watch's
  rights give them; Winlogon's Shell and Userinit. An entry is its place, whose it is (user or machine), its
  name (bounded and redacted as a value's name is, AB-2 and AC-4) and the hash of its content; where the content is a
  command, the name of the program it would run, through the same gate as PERSIST-RUN-KEY's. FOR: persistence
  is seen where Sysmon logs nothing, and where no line of the tree could tell it. MUST NOT TOUCH: a value's
  text, a file's content, a SID and a user's name are never written (A-1).
- AG-2 (what is said of the read). A place the watch's rights do not give is said as such (the scheduler's
  tasks under a plain user's rights), never read as empty; a read that fails is said with its reason; a place
  whose keys are refused in part says how many. A place unread in either of two reads gives no change.
- AG-3 (a change). Two reads are compared: an entry added, changed (its hash) or removed. The watch will
  compare each round's read with the one before it, the first with the read made at its start: what was
  there when the watch began is never said (a limit, said), and a change made and undone between two reads
  is not seen by this read (Sysmon's lines see it).
- AG-4 (stages). M15.3a: the read standing alone (raqib/autostart.py, `python -m raqib.autostart`), its own
  tests on a made-up registry, its spec, and the rig running it beside the stand-in (X37). Nothing of the
  watch changes. M15.3b: the watch reads at its start and each round, writes a change as a host line (tool
  HostAutostart) and three rules judge it - an entry of the Run keys, the Startup folders or Winlogon; a
  service; a scheduled task - each medium, each only where no line of a tree in those rounds tells the same
  act (PERSIST-RUN-KEY's and PERSIST-AUTOSTART's findings stand and are counted once) and where a tree was
  alive. The read does not say who made a change, and Raqib does not guess it: the finding names the entry
  and the trees alive then, and accuses none. The ruling of M15.3b is written after M15.3a's review, with
  what the rig showed.
- AG-5 (recorded). An entry removed is recorded and judged by no rule yet (removing a security tool's own
  autostart is an act of its own kind). The places not read are the rule's ways round and are listed: Image
  File Execution Options, AppInit_DLLs, a WMI subscription, the policies' Run keys, Active Setup, a service's
  ServiceDll, a driver, a COM object, a hive that is not loaded. Whether the question of AE-3 is still needed
  once the watch reads the Run keys itself is ruled with M15.3b. Linux's places are S4 (M15.4).
