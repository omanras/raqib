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
