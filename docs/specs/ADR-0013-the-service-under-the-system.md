# ADR-0013 — The service: Raqib under the system

Status: accepted (the commander's word, 2026-11-18). Date: 2026-11-18.

## Context
Raqib runs as the person who starts it. So does the agent it watches. That agent can then stop the watch, write
its events file again, and put entries in the journal that say raqib (ADR-0011 X-7, Z); and an agent that makes
itself another user leaves the watch's sight. The commander named that case on 2026-11-12: Raqib must sit at a
deep layer of the system, so that a suspect agent is still seen when it makes another user.

The Table asked whose rights the service runs with - the user's own, or the system's - and set both out. The
commander approved the Table's proposals of 2026-11-18, all of them in the Table's order; the first is the
service with the system's rights, built in stages, the smallest first.

## Measured before ruling (a Linux runner, the probe branch, never merged)
- The watch as a unit of the system's saw another user's agent: `NEW-AGENT-UNKNOWN ... unknown agent tree python3`
  for a stand-in agent run as a second user. The same watch run as a plain user did not: 3 trees, no finding, and
  the blind spot `bytes` (it cannot read another user's sockets). That is the commander's case, shown.
- The unit ran with the hardening below (systemd-analyze: exposure 2.8, "OK"; the plain unit 9.6, "UNSAFE") and
  wrote only under its state folder (/var/lib/NAME, root's, mode 0700).
- The runner's /opt is root's and writable by everyone. A venv made there by root is code any user can change -
  and a unit of the system's would run it as root.

## Decision
- A-1 (the posture). The service runs with the system's rights. FOR: the watched agent cannot stop it, cannot
  write its record or its events again, and cannot leave its sight by another user. The cost is said in A-3.
- A-2 (stages; each lands by the loop, each with its own review of what the system's rights open). S1: on
  Linux, the watch's unit - install, removal, status. S2: the forwarder as a unit of its own (its entries in
  the journal then carry a unit nobody else has, ADR-0011 X-7). S3: what a person without rights reads of the
  service (the window, the status). S4: Windows. Nothing of a later stage is built in an earlier one.
- A-3 (the code a unit of the system's runs is the system's). The install refuses unless the interpreter, every
  folder Python loads from, Raqib's own files, and every folder above each of them up to the root are root's
  and writable by nobody else; it says which path is not. The unit starts that interpreter by its whole path,
  in Python's isolated mode, with no environment of the installer's. FOR: a unit that runs a file a user can
  write gives that user the system. MUST NOT TOUCH: a user's install - `raqib watch` as a person runs it is
  unchanged, and needs none of this.
- A-4 (an explicit command, an administrator's; ADR-0011 W-0). `raqib service install` and `raqib service
  remove` do nothing unless run as root, and say so; they ask for no elevation. Install writes one file, the
  unit, marked as Raqib's; a unit of that name without the mark is not Raqib's and is not touched. Removal
  stops and disables the unit and removes that one file; the service's record stays, its path said, unless
  `--purge` is given.
- A-5 (the service's home is its own). The unit's state is /var/lib/raqib, root's alone; its rules and its
  overlay are there. No user's ~/.raqib is read by it: an agent that turns a rule off in its user's overlay
  turns nothing off in the service.
- A-6 (hardened as measured). The unit carries the directives the probe ran with: no new privileges; the
  system and the homes read-only; private temporary files and devices; kernel tunables, modules, control
  groups, clock and host name protected; no realtime, no set-id, no new namespaces; the address families
  unix, netlink, inet and inet6 with every address denied but the local host's (the watch calls no network:
  CLAUDE.md rule 5); the capabilities to read other users' processes and sockets and no others; the system
  calls of a service. A directive a system's systemd does not know is that system's to ignore, said by the
  status.
- A-7 (the system's own tools, by their whole path). systemctl is run from a fixed list of paths, never
  found by the installer's PATH; the unit's text is constant but for the interpreter's path, and a path that
  holds anything but letters, digits and `/._+-` is refused, not quoted.
- A-8 (the status). `raqib service status` says whether the unit is installed, enabled and active, and why
  not, by the system's own word; it needs no rights for that. Exit 0 active, 1 installed and not active, 3
  not installed.
- A-9 (the rig). On the Linux machine: an install from a place a user can write is refused (X28); an install
  from root's own place gives an active unit that sees a second user's stand-in agent (X29); the removal
  leaves no unit (X30).

## Consequences
- Raqib's code runs as root where the service is installed: a defect in it is the system's. Each stage's
  review reads for that first.
- The service's record is not readable by the person at the host until S3.
- Two watches may run on one host, the service's and a person's own; they do not know each other.

## Amendment A (the Table, 2026-11-18) - the builder's STOP on M12.1 (95cd5de), and its questions
The builder stopped before writing code, rightly: a new command needs the README's row of commands, which a
guard holds to the parser, and that file was not in its scope. The scope was the Table's to make whole.
- AA-1 (the README's row). README.md joins the scope for that row alone: `service` is named among "the rest".
- AA-2 (systemctl is not the watch's helper). The guard that every program Raqib starts is recorded exists
  so that the watch knows its own helpers from the trees it judges (ADR-0007 BH). `raqib service` is a
  command of its own that takes no process sample: its one function that runs systemctl is listed among the
  starts that are not recorded, with that reason, as `raqib doctor`'s is. The module stays the standard
  library's alone.
- AA-3 (the rig's workflow is the Table's). The builder writes the rig's tool and the check; the Table wires
  them into the workflow when the task lands, and the field's word comes then.
- AA-4 (the check's words). MISSED where a criterion is not met, n/a where it is not run, as X26 and X27.


## Amendment B (the Table, 2026-11-18) - the builder's second STOP on M12.1 (d663662)
The builder stopped again before code, rightly again: AA-1 could not be done as ruled. The README's row of the
rest was 120 characters already, and two guards hold every line of the README and every row of its Commands
table to 120. The Table ruled AA-1 without measuring the row. The fault is the Table's, twice on one task.
- AB-1 (the rest is cut into rows; the width is kept). The 120 is for a person's screen and is not raised, for
  one row or for any. The rest of the commands is told in as many rows as it needs: the first begins
  "the rest: ", a later one "and: "; each points at the guide, names at least one command, and none is named
  twice. FOR: a new command never again meets a full row. MUST NOT TOUCH: the eight ruled rows and their
  order, the 120, the rule that the table names the parser's commands and nothing else.
- AB-2 (the Table wrote it). README.md's row `and: service` and the guard's change in
  tests/test_readme_top.py are the Table's, made in this commit. README.md leaves the builder's scope; in
  tests/test_readme_top.py its scope stays the registry of the guide's lines. Until the parser has `service`
  one test of that file fails on this branch, by design: the builder's command makes it pass.
- AB-3 (what the check of ownership reads, beyond the letter of A-3). The builder asked for two things and has
  them. `owned_by_root(paths, stat=os.stat, readlink=os.readlink)`: a link is checked as itself (its owner;
  a link's mode bits say nothing) and then as what it points to, whole, with a bound on the depth; a loop or a
  link past the bound is a refusal, never a pass. And the install's list of paths also holds what the
  interpreter reads as code or as where code is before Raqib's first line runs: `pyvenv.cfg` beside the
  interpreter or one folder above it, and every `*.pth` file in each folder of sys.path. FOR: `-I` does not
  stop a `.pth` file's lines from running. MUST NOT TOUCH: nothing is read or run to find these; they are
  named by where they are.
- AB-4 (a lesson, recorded). Before a HANDOFF names a file's line to change, the Table measures that line
  against its guards, not only which guards exist.

## Amendment C (the Table, 2026-11-18) - the review of M12.1 REDO 2 (docs/review/2026-11-18-M12.1.md)
The reviewer said STOP, and its two blockers are the Table's: A-3's letter fell short of its purpose, and this
ADR said no person without rights reads the service's record while the watch serves its page to every user.
Measured before these rulings (GitHub's Linux machine; the rig and the probe branch): X28, X29 and X30 MET;
every directive of the unit loaded as written and none was warned of; a user without rights read the root
service's page (http 200, the finding on it); an agent whose program and folder are in /tmp was found under
PrivateTmp; a stop after a finding leaves the unit `failed` (the watch's own exit 1, ALARM); ss gives the same
lines with AF_NETLINK alone; the watch reads the same with CAP_SYS_PTRACE and CAP_DAC_READ_SEARCH as with
CAP_NET_ADMIN beside them, and with one of the two alone it sees no tree and says so (INCOMPLETE).
- AC-1 (F2: the service serves no page). A task of its own, first: `raqib watch --host --no-page` opens no
  listener and says so. The unit's ExecStart carries it; RestrictAddressFamilies=AF_UNIX AF_NETLINK;
  IPAddressDeny=any and no IPAddressAllow. FOR: no person and no agent without rights reads what root's watch
  sees, root parses no user's request, and there is no port to take first. What a person reads of the
  service is stage S3's to design. MUST NOT TOUCH: a person's own watch keeps its page as it is.
- AC-2 (F1, F3, F6: everything the interpreter may load, whole). Every entry of sys.path is walked whole, as
  the package is: every file and folder below it; a link by AB-3's rule, and where it points to a folder that
  folder whole too, each real folder once; past WALK_MAX entries the install refuses and says so. An entry
  that does not exist: the folders above it that do are checked. AB-3's "nothing is read" is amended for one
  thing: a `.pth` file, once found root's alone, is read as text, and each line of it that is a path is
  taken as an entry, existing or not. Nothing is run. FOR: the letter of A-3 now reaches its purpose.
- AC-3 (F4: the install sees what the unit will). Refused where the install's interpreter runs without its
  site (`-S`), and where the raqib package it runs from is not in one of that interpreter's own site folders
  (a checkout run by -m, an editable install). The unit's `-I` only takes entries away, so what the install
  walked holds all the unit will load from.
- AC-4 (F5: what else root runs or trusts). The list also holds the systemctl found, each path of the watch's
  ss that exists (a constant here, held equal to the watch's by a test), and the unit's folder.
- AC-5 (F7: capabilities as measured). CAP_NET_ADMIN leaves the unit: CapabilityBoundingSet=CAP_SYS_PTRACE
  CAP_DAC_READ_SEARCH. The threat model says what these two still open to a defect in the watch (every
  file read; other processes reached), as the kernel's rules read, not as measured.
- AC-6 (F12, the builder's Q1: the word after the start). After `enable --now` the install waits START_WAIT
  (3 s) and asks systemctl: active is said as active, with the wait; anything else is exit 1 with the state
  and the result. An install over Raqib's own running unit restarts it (`systemctl restart`); with
  `--no-start` it says the running watch keeps the text it started with.
- AC-7 (the restart, the stop). Restart=always: a watch ended by anything but systemctl's stop comes back,
  whatever its exit. No SuccessExitStatus: a crash is exit 1 too. The status shows systemctl's NRestarts and
  says of exit status 1 what it is: the watch's own ALARM at its end, or an error; the journal says which.
- AC-8 (F13: evidence, not a sentence). The install says how many paths it checked, of which kinds.
- AC-9 (F11, F14, F19: no state said that was not read). `remove` with no file asks systemctl; a unit of the
  name still loaded is said and is exit 1. `status`: a file that cannot be read is NOT KNOWN (3), never NOT
  INSTALLED; a FragmentPath that is not the unit's path, or any drop-in, is said and is not exit 0. The
  unit's head is read without waiting and only from a regular file. A systemctl that ran and timed out, or
  ran and failed, is not said as "not run".
- AC-10 (F15 to F18, Q2: the rig proves what it says). X28's place is a folder every user can write, not
  sticky, under a folder root's alone; the check requires the refusal to name that place or a path below it.
  X30 requires the unit not active and the record's folder gone. n/a only where the platform is not Linux.
  X29's facts carry systemd's own word on the unit (its directives as loaded, the manager's lines that name
  the unit and say unknown, ignored or invalid): any such line is MISSED. A-6's "said by the status" is
  withdrawn for S1: the rig says it. The rig's tool runs only with `--throwaway`, and says why.
- AC-11 (F7 to F10, F20: the documents say what is so). Who can stop it: root, which a user with sudo or a
  polkit rule is; a watch made to exit comes back after 5 s, a gap each time. Not checked: shared libraries.
  The check guards the unit's starts, not the install itself: an install run from code a user can write has
  already run it. An agent in a network namespace of its own: not measured. ACTIVE says the unit runs, not
  that the watch writes: S3.
- AC-12 (open, recorded in the plan). The unit as a user of its own holding the two capabilities, not root:
  to be measured before it is ruled.
- AC-13 (the builder's stop on M12.1p, before its commit; docs/review/2026-11-18-M12.1p-questions.md). The
  builder is right that `--no-page --refresh 5` cannot be told from no `--refresh` while the parser's default
  is the number. The scope of raqib/cli.py gains that one line: `watch`'s `--refresh` defaults to None, which
  both of its readers already take as the default's 5; `raqib app`'s own option is not touched. Its other
  choices stand: the guide's sentence at the end of the `--attach-hooks` paragraph; `--no-open` beside
  `--no-page` is accepted and changes nothing; with no page the loop says no line of how the watch ends
  beyond what the start and the stops' line already say.

## Amendment D (the Table, 2026-11-18) - the second review (docs/review/2026-11-18-M12.1-redo3.md)
The reviewer said NEXT with what must be fixed first: from reading, a user without rights has no way to run
code as root, to choose a file root writes or removes, or to make the three commands lie; what it found
needs root, or a user who is root by sudo or polkit. The field (the rig, commit d804836): X28, X29 and X30
MET with the unit of Amendment C - no page, AF_UNIX and AF_NETLINK alone, two capabilities. These are fixed
before the merge, in one more round:
- AD-1 (G1, G3: systemd is asked before a state is said or a file written). `remove` with no unit file: a unit
  of the name that systemd holds as anything but not-found and not active is said, exit 1, nothing touched,
  nothing purged. `status` with no unit file asks too, and says a unit of the name that runs. `install` with
  no unit file asks first: a unit of the name loaded from another place, or running, is a refusal (A-4 is for
  the name, not only for the path).
- AD-2 (G2: "as installed" is the text). `status` compares the whole unit file with the text this Raqib
  writes for the interpreter the file names, and reads systemd's NeedDaemonReload: a different text, or a
  file changed since it was loaded, is NOT AS INSTALLED and not exit 0. FOR: a change of the unit shows as a
  stop does. The documents say what still does not show: a change of Raqib's own code by root.
- AD-3 (G4: the install does not start what is not as installed). After the reload and before the start the
  install reads FragmentPath and DropInPaths: not as installed is exit 1, not started, and the RESULT says
  it. The drop-in folders are not walked; the documents say that they are root's by default and not checked.
- AD-4 (G5, G7, G8: the install sees what the unit will, more exactly). Refused where PYTHONHOME or
  PYTHONPLATLIBDIR is set and the interpreter does not ignore the environment; where the package's folder is
  not itself directly in a site folder; and a `.pth` file that holds a byte outside printable ASCII, tab and
  the two line ends is refused, not read (the versions of site split and decode such a file differently).
- AD-5 (G10: the end of a removed unit). `remove` asks systemd to forget a failed state of the removed unit
  (`reset-failed`), and says so. That a stop after a finding reads as `failed` - the watch's own exit 1 -
  stays for S1 and is said; a stop that systemd reads as a stop is S3's to rule, with what a person reads.
- AD-6 (G11: the rig measures what is in force). X29's facts carry the main process's own word from /proc:
  its bounding set of capabilities, its seccomp mode and its no-new-privileges bit; X29 is MET only where
  they are the unit's. The journal's words gain "not support". The documents say X29 reads these and
  systemd's warnings, not every directive in force.
- AD-7 (G6, G9, G12: the documents and the words). Said: a missing path under a place the system makes for
  a user (a login's run folder, a mounted medium, a new home) can become that user's; who reads the journal
  reads the findings' lines the unit prints; a link is checked by its owner. No line says a thing was done
  before it was.

## Amendment E (the Table, 2026-11-27) - M12.4: the watch as a service of Windows, measured before it is ruled
ADR-0013 is the watch under the system on Linux. On Windows the watch had run with the system's rights only from
a scheduled task (measured 2026-11-26: the same reads, its notice reaches nobody, its record in the system's own
profile). Measured for a real service (the probe branch 0126f69 to c7e9b55; GitHub's Windows machines, x64 and
ARM64, Python 3.12; main's Raqib plain and packed by PyInstaller 6.11.1; a candidate of 150 lines with the
standard library alone):
- The shape works, plain and packed, on both machines: the system's control dispatcher
  (StartServiceCtrlDispatcherW, by ctypes) in a second thread, the watch in the main thread as it runs from a
  console, and a Stop from the system turned into the interrupt a person's Ctrl+C is
  (`signal.raise_signal(SIGINT)` from the handler). The system started it in 0.56 to 0.71 s plain and 0.08 to
  0.09 s packed; RUNNING was reported before Raqib was imported (0.14 to 0.16 s); a Stop took 0.25 to 0.27 s,
  the watch ending 0.01 to 0.03 s after the control with its final report ("stopped (Ctrl-C)") and code 0; the
  state read Stopped, exit code 0.
- As a service the process is the system's own account in session 0, its folder System32, and its three standard
  streams are None. Run with no service manager, the dispatcher fails at once with error 1063.
- With USERPROFILE and HOME set by the candidate to a folder under ProgramData, the watch's whole record
  (events, rounds, sources, state) was written there.
- Killed, with the system told to start it again after 2 s: the system said so (event 7031) and started it, and
  the new watch refused - "another raqib watch --host is watching this home (... heartbeat 3 s ago)" - and
  ended; the service read Stopped and was not started again. A killed watch leaves its state unfinished, and a
  watch takes an unfinished state for a living one until its heartbeat is 30 s old (STALE_SECONDS). The Linux
  unit meets the same refusal and is started again every 5 s until it passes.
- Who may touch it, tried as a plain user made for the run and removed after it. The service: a Stop is refused
  (access denied), and so is ending its process. Its folder as ProgramData makes one: the plain user wrote into
  it, read the service's log and listed its record. The folder given the access list
  `D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)` (the system and the administrators, whole; nothing inherited) by the
  system's own calls from Python (no outside program), read back as text and equal to what was asked: all
  refused, for a file and a folder that were in it before too (they took the new list); an administrator still
  read it.
- A folder a plain user made first, where the service's would be: ProgramData let him make it, and he is its
  owner. After it was closed as above, its maker gave the users the folder again and wrote into it. After the
  administrators were made its owner and it was closed again: refused.
Ruled. M12.4 is three tasks, each small enough for one builder: M12.4a the runner; M12.4b a watch killed and
started again; M12.4c `raqib service install | remove | status` on Windows.
- AE-1 (the runner). `raqib service run`, on Windows: the host watch under the system's service manager, in the
  measured shape, by the standard library alone (ctypes; no new dependency), every call of the system through
  one object a test replaces, nothing of Windows touched at import. It reports RUNNING before the watch's own
  start. Started by anything but the service manager it says so on its error stream, starts no watch, exit 2.
  Elsewhere than Windows it says that this command is Windows', exit 2. FOR: a service the system starts at
  boot, stops at shutdown and a plain user cannot stop. MUST NOT TOUCH: the watch (it is run by Raqib's own
  entry, with the Linux unit's arguments, `watch --host --no-page --no-notify`); the Linux unit and its three
  commands; D-1 of nothing - it observes.
- AE-2 (a place of its own, closed before anything is written). The place is `Raqib` under the folder the system
  names ProgramData to its services. Refuse rather than repair: absent, it is made, given the measured access
  list and read back; present, it is refused where it is a link, where its owner is neither the system nor the
  administrators (measured: its maker opens it again), or where its list is not the closed one and it is not
  empty (what a stranger may have left is not adopted); present, empty and open, it is closed and read back.
  After any of these the list read back must be the closed one and the owner the system or the administrators,
  or no watch starts. The process's HOME and USERPROFILE are then the place, as the Linux unit's HOME is its
  state directory. FOR: the watched user can neither read nor rewrite the watch's record (A-1). MUST NOT TOUCH:
  any folder but the place; an existing closed place's contents.
- AE-3 (no standard streams). The runner gives the watch a text file in the place for its report and its errors,
  begun anew at each start with the one before kept once, and bounded: past its bound no more is written and its
  last line says so (rule 4), the record goes on. Nothing in the process may fail because a standard stream is
  None.
- AE-4 (a Stop is the watch's own stop). Stop and Shutdown: STOP_PENDING, then the watch's own interrupt; the
  watch ends with its final report; then STOPPED. A watch's result (0 clean, 1 an alarm, 3 incomplete) is no
  failure of the service: exit code 0 to the system, the result in the text file. A refusal (the place; the
  watch refusing to start; a watch that ended without being asked) is STOPPED with a code of the service's own
  (the system's "service-specific" exit), one number for each, listed in the spec, so that the system's own log
  tells them apart.
- AE-5 (the field's word). Before the merge the Table runs the branch's `raqib service run` on GitHub's Windows
  machines as the probe ran the candidate: started and stopped by the system, plain and packed; the place's
  owner and list read back; a plain user's four attempts on the place and two on the service; the place made
  first by a plain user refused. A claim on the rig comes with M12.4b.
- AE-6 (recorded for M12.4b and M12.4c, not built in M12.4a). A watch started while the one before left its
  state unfinished: how long the service waits, and the new watch saying that the one before ended without its
  end and from when nothing was watched. The install: the service made, its start at boot, the system told to
  start it again, a refusal where the code it would run is not the system's alone, the event log. Not measured:
  a shutdown of the machine (the control was not sent); a service's start at boot; the manager's limit of 30 s
  under a slow start; another account than the system's; a place on another volume, or one with a file held open
  by another process; Windows before the runners' versions.

## Amendment F (the Table, 2026-11-27) - the review of M12.4a (docs/review/2026-11-27-M12.4a.md) and the field's word: REDO
The field's word on c125f62 (AE-5; the probe branch 27d5477; GitHub's Windows machines, x64 and ARM64): the
runner's 42 tests passed on real Windows, the real object's among them. As a real service, plain and packed: run
by hand it refused with its line, exit 2, and made nothing; the place absent, it was made with the
administrators its owner and the closed list, the watch ran, a Stop took 0.26 s with the final report and the
run's chain whole, the state Stopped with exit 0; a plain user's write, read, listing, Stop and ending of its
process were each refused; started again, the text before was kept once; the place made first by a plain user
was refused with 13 and left untouched; open with a file in it, refused with 14, the file left; open and empty,
closed and taken; a junction, refused with 11, nothing written where it points. Two flaws: the system's log gave
each refusal's number the system's own words for that number (13 "The data is invalid", 14 "Not enough memory
resources", 11 "incorrect format"); and the start command said it succeeded for a service that then refused,
because RUNNING is reported before the place is read.
The reviewer's verdict is REDO with two blockers, both in what Amendment E ruled. Measured before this ruling
(the probe branch 66dec1a, the same machines):
- A folder made by the one call that makes it with the closed list (CreateDirectoryW with a security
  descriptor), as an administrator and as the system's own account in a service: made; read back, its owner the
  administrators and its list `D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)` - the closed list, written without the mark
  of inheriting that a list set on an existing folder carries (`D:PAI`); made again where it is, error 183. A
  plain user's write, listing, renaming and removal of it: each refused, with no handle held.
- Read through one handle on the name itself (CreateFileW with the flag that does not follow a link;
  GetFileInformationByHandle; GetSecurityInfo): a folder; a junction and a link to a folder, each a folder that
  is a reparse point; a file; an absent name, error 2; the owner and the list from the same handle.
- A handle with the right to read the list alone does not hold a name: while it was held, the plain user who
  made the folder gave it another name.
- A refusal reported from START_PENDING: the start command fails at once. From RUNNING: it says ok, and the
  state reads Stopped a moment later. A number of the service's own of 14 is written in the system's log with
  the system's words for 14; 20014 and 536870926 (0x20000000 + 14) are written as themselves ("%%20014",
  "%%536870926").
- AF-1 (the place, ruled again; it replaces AE-2's closing of a folder that exists). The runner never sets an
  owner or a list on anything that exists. Absent, the place is made by the one call that gives it the closed
  list. Then, made or found, it is read through one handle on the name itself, and taken only where that one
  read says: a folder and no reparse point; its owner the system or the administrators; its list the closed one,
  in one of the two forms the system writes it (`D:P...` as made, `D:PAI...` as set). Anything else is refused
  and left exactly as it is - open, whatever it holds or does not hold: an administrator removes it. FOR: there
  is no moment when the place is open; what was checked is one object; a refusal holds at every start, and
  nothing a stranger left is ever inside a place that is taken (the review's items 7 and 8). MUST NOT TOUCH: no
  call that sets security on an existing object stays in the runner. Not relied on, and said: holding a handle
  (measured: it holds nothing); what keeps a taken place's name is its own list and owner (measured: a plain
  user can neither rename nor remove it).
- AF-2 (START_PENDING until the place and the text file are ready). The runner reports START_PENDING, prepares
  the place and begins its text file, and only then reports RUNNING and starts the watch; a refusal before that
  is STOPPED from START_PENDING. FOR: an administrator who starts it sees at once that it did not start. The
  manager's limit is 30 s; the measured preparing is milliseconds.
- AF-3 (numbers the system has no words for). Each exit number of the service's own is 0x20000000 + n, the range
  the system leaves to applications; the spec lists each in decimal and in hexadecimal with its words. FOR: the
  system's log says the number itself and never a sentence about memory.
- AF-4 (the review's other items). A Stop that comes before the watch gave any result (its item 4): the system
  is told 0, a Stop asked was obeyed, and the text file says in one line that the watch was stopped before it
  gave a report; the unfinished state such a watch may leave is M12.4b's. A Stop after the watch returned raises
  no interrupt, and one that still surfaces in the runner is caught (5). The platform is said before any other
  refusal of the command's arguments (6). A write to the text file that fails ends it with one last line where
  that can still be written, and the runner keeps that it happened (13). An exception of the runner's own has a
  number of its own and its trace in the text file where one is begun (15); STOP_PENDING is never reported after
  STOPPED (16). Tests: the text file's refusal, a handler that is not registered, the dispatcher that does not
  connect, a stand-in watch ended by a real interrupt (17, 18). The documents say what the field read on c125f62
  and what this amendment measured, each named so, and nothing more (21, 22). Kept: `service --help` naming
  `run` on every system (2); ProgramData as the system gives it to its services, its drive and its parents the
  administrators' and said so (11, Q8); the name RaqibWatch, the 8 MiB bound, the three waits (Q4 to Q6); 20 for
  a watch that refuses to start (Q9).
- AF-5 (the field's word again). Before the merge the Table runs the REDO's commit as AE-5 did, with: the place
  a plain user made (13), an administrator's open place with and without a file (refused both, left as they
  are), a junction, a link and a file at the place's name, a closed place holding the record of a run before
  (taken), the start command failing at once on a refusal, and the system's log's own words for it. Not measured
  still: AE-6's list; a place whose list is closed in meaning but written otherwise (refused, by the letter); a
  place on a volume that keeps no owners.

## Amendment G (the Table, 2026-11-27) - the review of M12.4a REDO (docs/review/2026-11-27-M12.4a-redo.md) and its field run: lands
The field's word on f8af8f5 (AF-5; the probe branch 1104096; GitHub's Windows machines, x64 and ARM64, plain and
packed): the gate green on six jobs and the rig green; as a real service, run by hand it refused with its line
and made nothing; the place absent, it was made owned by the administrators with the list
`D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`, the watch ran, a Stop took 0.26 s with the final report and the run's
chain whole; a plain user's write, read, listing, Stop and ending of its process were each refused; started
again, the text before was kept once; a place a plain user made first (13, twice in a row), an administrator's
open place with a file and without one (14), a junction and a link at the name (11), a file there (12): each
refused, the start command failing at once, the system's log saying the number itself (`%%536870925` and so on),
each left exactly as it was and nothing written where a link points.
The second reviewer's verdict is NEXT. Measured for its findings 3 and 15 (the probe branch 4007788, the same
machines):
- The making call (CreateDirectoryW) where the name is a junction or a link, its target there or absent, or a
  file: error 183 each time, and nothing made where they point - an absent target stayed absent. (Another call
  that makes a folder and is told not to follow a link answered error 80 in the same cases; it is not needed.)
- A plain user's file left in a folder that was closed afterwards (the administrators made its owner, the closed
  list set, read back `D:PAI...`): the file took the folder's list and kept the plain user as its owner. His
  reading it by its whole path, his giving the users the file again with the system's own tool, and his writing
  to it were each refused. A call that asks only for an owner's right to change his file's list was not tried.
- Found on the way: the runner's real-object test passed in the gate and failed in the field's step on the same
  machine as the same administrator - a folder made by the same call was owned by the administrators where the
  process was started from PowerShell, and by the user himself where it was started from Git's bash.
- AG-1 (the closed list is taken in one form). A place is taken only where its list reads as a folder MADE
  closed reads, `D:P...`. The same list set on a folder that existed (`D:PAI...`) is refused with 14: such a
  folder was open once, what was put in it then keeps its own owner, and the refusals measured above rest on one
  tool, not on what an owner may ask of the system. FOR: what is in a taken place was put there by the system or
  the administrators (the review's finding 15, and the first review's 7 whole). MUST NOT TOUCH: the making call
  and the text it is handed (R4); AF-1's one read through one handle.
- AG-2 (the watch's end is always decided and always said). An interrupt that surfaces in the runner outside the
  watch's call no longer skips the watch's trace and the runner's last line, and after a Stop it is never told
  as the runner's own failure (the review's finding 9). Tests for the three places it can surface.
- AG-3 (the making call stays). Measured: it follows no link at the name and makes nothing elsewhere (finding
  3); the documents say so with this source.
- AG-4 (kept, or said). 18 for a text file ended by a failed write where the system would be told 0, and the
  bound reached stays 0 (R3); 17 and 23 (R1, R2); a Stop while START_PENDING obeyed, not measured (R5); the
  owner and the list split at the first `D:` after `O:`, an owner written as a whole SID refused (R6); 21 for a
  watch that returned nothing after a Stop (R7); standard input left None (R10); a junction made in the test by
  CPython's own private call, absent or changed it is not read (R9). The documents' sentences the review names
  are narrowed (findings 10, 15, 16). A RUNNING the system does not take leaves the service START_PENDING, said
  only in the text file: recorded as not measured (finding 7).
- AG-5 (who makes the place matters, and it is the install's). The runner is started by the system, and the
  place it made was the administrators' in every run. An administrator's own process may make a folder that is
  his and not the administrators' (measured above): the install (M12.4c) names the owner in the call that makes
  the place, measured first, and the runner's test says the owner it met instead of failing.
- AG-6 (lands). M12.4a lands as 0.9.0 after the Table's field run of the commit to be merged. Next: M12.4b (a
  watch killed and started again: the wait, and the new watch saying the one before ended without its end; a
  claim on the rig), M12.4c (install, remove, status; the place's owner named; a refusal where the code is not
  the system's alone; the start at boot; the system told to start it again; the event log). Not measured: AE-6's
  list; a Stop while the service is START_PENDING; where the Stop's interrupt surfaces after the watch's call on
  a real machine; an owner's own call for the right to change his file's list; a place on a volume that keeps no
  owners; reparse points other than a junction and a link.
