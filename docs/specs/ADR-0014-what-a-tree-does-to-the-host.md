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
