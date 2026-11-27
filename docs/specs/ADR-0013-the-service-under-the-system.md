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

## Amendment H (the Table, 2026-11-27) - M12.4b: a watch started after one that ended without its end
Measured for Amendment E and not yet ruled (the probe branch 02de365; GitHub's Windows machines, x64 and ARM64):
the service's process ended from outside, with the system told to start it again after 2 s - the system said so
(event 7031) and started it, and the new watch refused: "another raqib watch --host is watching this home (run
..., pid ..., heartbeat 3 s ago): one host watch per home; stop it first". It ended with 2, the service read
Stopped, and the system did not start it again. Read in the code, not measured: a watch refuses an unfinished
state until its heartbeat is `stale_after_seconds` old (30 s), by the heartbeat alone; a watch that starts over
a stale unfinished state takes the home and says nothing of the watch before it. The Linux unit meets the same
refusal and is started again every 5 s until it passes.
- AH-1 (a watch that ended without its end is said by the next one; every system). A host watch that starts over
  a state another watch left unfinished says so once, at its start, as a hole of its own run: the run before,
  its pid, its last heartbeat, and how many seconds lie between that heartbeat and this start, in which nothing
  was watched from this home. It is a hole and not a blind spot: a watcher that was ended from outside, a crash,
  a power loss - each is a gap in the record, and the result of the run that found it is not clean (rule 4).
  FOR: the gap is in the record itself, and in the events a collector takes, not only in the system's own log.
  MUST NOT TOUCH: the rule by which a second watch is refused (the heartbeat and its staleness, D-6); a state
  that is finished; a state whose heartbeat cannot be parsed (refused as today).
- AH-2 (the service waits for a state to go stale). Before it starts the watch, the runner asks the engine
  whether another watch still holds the home (one function of raqib/host.py, the same test the watch itself
  makes). Where one does, it says so in its text file and waits until that heartbeat is stale - the state's own
  staleness and no longer, with a bound - and then starts the watch, which says AH-1's hole. A Stop during the
  wait is obeyed at once: no watch is begun, the system is told 0. A state still fresh after the wait is a
  living watch: the watch's own refusal stands (20). The service reads RUNNING while it waits (AF-2's order is
  kept), and the text file says it is waiting, for what, and for how long. FOR: a service ended from outside
  watches again without a person. MUST NOT TOUCH: the Linux unit (systemd starts it again until it passes; AH-1
  gives it the same line).
- AH-3 (a claim on the rig, the Table's wiring). The rig's Windows job makes the service from the installed
  Raqib, tells the system to start it again, ends its process, and keeps what it read; X48 is MET where the
  service ran again with another pid, and the place's events hold two runs, the second with AH-1's hole naming
  the first, the first with no end. `tools/rig/check.py` reads it from the files the job keeps.
- Recorded, not ruled: taking over at once where the process the state names is no longer there (the gap would
  be seconds, not half a minute) - not before it is measured that a pid and its start can be told on every
  system a home may be shared across; the system told to start the service again on an exit of the service's own
  (the install's, M12.4c). Not measured: a power loss; a machine's shutdown without a Stop; a clock set back
  between the heartbeat and the start (the seconds said are then wrong, and said as read).

## Amendment I (the Table, 2026-11-27) - the review of M12.4b (docs/review/2026-11-27-M12.4b.md) and its field run: REDO
The field's word on 8914d37 (the probe branch 241e04f; GitHub's Windows machines, x64 and ARM64; the branch's
`raqib service run` as a real service, the system told to start it again after 5 s; its process ended from
outside): the gate green on six jobs and the rig green; the system said the end (event 7031) and started the
service; the runner's text said the state still held the place ("heartbeat 5 s ago, stale after 30 s ... waiting
up to 25.6 s"), waited, and the watch read its first round 31 to 32 s after the end; the place's events held two
runs, each chain whole, the later with the hole `watch-unended` naming the earlier, which has no end; the rig's
own check read X48 MET from what was kept; after a Stop and one more start, no second such hole. What the probe
02de365 ran, which Amendment H cites: the candidate of Amendment E, not the runner. Seen in the field's text:
the hole is not among the lines the watch says at its start.
The reviewer's verdict is NEXT with no blocker, and a list to fix before the merge. Ruled:
- AI-1 (the hole is in the events before the state that named the run before is gone; finding 5). A watch that
  found an unfinished state writes AH-1's hole to its events file before it writes its own state over that one.
  FOR: a watch ended again in its first seconds still leaves the earlier gap in a record that lasts. MUST NOT
  TOUCH: the events' chain (the hole is a line of this run's chain like any other); the order of everything else
  at the start.
- AI-2 (a state that cannot be read is said; finding 25). A state file that is there and cannot be read as a
  state (empty, torn, not text, refused) is taken as it is today - the watch starts - and is said as a hole of
  its own kind at the start: the state the watch before left cannot be read, and whether a watch ended without
  its end is not known. D-6's refusals are as they are. A state that is absent says nothing: a first watch is no
  gap. Not measured: what a power loss leaves of the state on NTFS or ext4.
- AI-3 (the words say what was read; findings 3, 4, 27, Q3). The run and the pid are cut as the heartbeat is.
  The hole says what was found - a state left unfinished and its heartbeat stale - and what that is: a watch
  that ended without its end, or one that stopped writing. A heartbeat ahead of the clock is said as ahead,
  never as "0 s". The seconds are those the refusal's own reading took, and the spec says so. The hole is said
  at the start with the other holes the watch says there, and is in the final report.
- AI-4 (the runner's wait; findings 6, 7, 9, Q6). Whatever numbers the state holds, the wait is within its bound
  and ends as the runner's own road, never as its exception. The line before the wait gives the age as read,
  ahead of the clock where it is. One line after the wait: how long it lasted and how it ended - stale,
  finished, gone, unreadable, still fresh, or a Stop.
- AI-5 (X48 rests on the end the job made; findings 12, 13, Q1, Q8). `--service-run` and `--service-events` are
  the names (E4 said otherwise; `--service` was taken). X48 is MET only where the hole's pid is `killed-pid` and
  the later run is the one `again-pid` wrote; a byte-order mark before the first key is not a missing key.
- AI-6 (kept, or said). No list of the host watch's holes exists in the specs: none is begun (Q2). A heartbeat
  that cannot be parsed gets no wait: the watch's refusal stands and the service stays stopped until an
  administrator acts, said in the spec (Q5). The documents name Amendment H's source as it is (the candidate)
  and this amendment's field run for what the runner did; the 30 s is read in the code; the runner reads one
  more name, the state inside its place (findings 18 to 22). On Linux a unit stopped after such a start ends
  with 3, and systemd may read that as failed: said, not measured. The wiring of the rig's Windows job for X48
  is the Table's, after the REDO.

## Amendment J (the Table, 2026-11-27) - the review of M12.4b REDO (docs/review/2026-11-27-M12.4b-redo.md) and its field run: lands
The field's word on 054ef34 (the probe branch 607b75c; GitHub's Windows machines, x64 and ARM64; the branch's
`raqib service run` as a real service, its process ended from outside): the gate green on six jobs and the rig
green; the runner's and the hole's 125 tests passing on real Windows; the system started the service again; its
text said the state still held the place and that it would wait ("heartbeat 5 s ago, stale after 30 s ...
waiting up to 25.6 s"), then "the wait ... lasted 25.1 s and ended: stale"; the watch said the hole `watch-
unended` at its start, naming the run before and its pid, its last heartbeat 30 s before the start; the first
round was read 31 s after the end; the events held the hole in the same words, both chains whole; X48 read MET
with the hole's pid the ended one and the later run the new process's; after a Stop and one more start, no
second such hole.
The second reviewer's verdict is NEXT with no blocker. Ruled, and done by the Table's hand:
- AJ-1 (a start that said the watch before and then failed; finding 7). Such a start leaves its start line and
  the hole in the events with no end, and the state still names the run before, so the next watch says the run
  before again: two holes for one gap, each true to what its run found, and the failed run itself a run with no
  end in the events. Kept as it is: nothing is taken back from a record, and the service's own road serves no
  page and cannot fail there. A test holds it and the spec says it.
- AJ-2 (the early write that fails; finding 6). The watch starts: a watch that cannot write its events still
  watches, and says so as the hole it already has for that. The earlier gap is then in this run's state and
  final report only; the spec says the case instead of promising the events.
- AJ-3 (said as it is; findings 2, 10, 11, 18, 25, R4). The test of a refused start that writes nothing is
  restored. A value JSON holds is named in JSON's words. A watch over a state it cannot read "starts over it";
  it is not said to take a home it may not get. A number cut for a line is marked as cut. The fresh refusal's
  run and pid are cut as the hole's are - its words are otherwise as they were. The rig's check says in its own
  usage what X48 now asks.
- AJ-4 (the rig keeps it). The rig's Windows job makes the service from the Raqib it installed, ends its process
  once and keeps what X48 reads (tools/rig/service_again.ps1), at every run of the rig.
- AJ-5 (kept, and said in the spec as not said or not measured). A state removed before a start leaves the watch
  before said nowhere, also where an administrator removes it as the unparsed refusal advises (R8); an object at
  the state's path that is no host watch's is nothing held (finding 12); a state with a negative or NaN
  staleness written by a living watch is said as one that ended or stopped writing (14); a state nested past the
  parser's limit stops every start until an administrator acts, loudly (R3); the wait's asks lie outside its
  bound by one read of a local file (first review, 8). On such a start only, the start's other holes are written
  with the early write and the heartbeat counts from the start (R1). Not run on a real machine: the hole of a
  state that cannot be read; a start ended before its first round; how systemd reads a unit that ends with 3
  after such a start; what a power loss leaves of the state.
- AJ-6 (lands). M12.4b lands as 0.10.0 after the gate and the rig, X48 among its claims, on the commit to be
  merged. Next: M12.4c (install, remove, status; the place's owner named in the call that makes it; a refusal
  where the code is not the system's alone; the start at boot; the system told to start it again; the event
  log).

## Amendment K (the Table, 2026-11-27) - measured before M12.4c: whose the code is on Windows; the task in two
A service of Windows runs as the system what its command names, so A-3's question stands there too: is the code
it would run the system's alone? Measured before any ruling (the probe branch a42f5a6 and the two runs before
it; GitHub's Windows machines, x64 and ARM64, the same on both unless said). Every owner and list was read
through one handle on the name, whole; the texts are the fixtures of this task.
- A service made, read, started, stopped and removed by the system's own calls, from a standard-library
  process: done on both machines; a killed one was started again by the system after 5 to 6 s. Kept for M12.4c2.
- The Python GitHub installs: every file and folder of it gives all signed-in users modify
  (`(A;ID;0x1301bf;;;AU)`). A plain user wrote beside the interpreter, into its site folder and into the raqib
  package there: DONE, all three.
- A Raqib packed with its own runtime, copied into `C:\Program Files` by an administrator: owner BA, its list
  inherited from Program Files (the system, the administrators and the system's installer hold everything;
  users and app packages read and execute; the creator's entry is inherit-only). A plain user: write beside the
  program, into its folder of modules, to the program itself, give its folder another name, give Program Files
  another name - REFUSED, all five. The service ran from there.
- `C:\` itself: owner the system's installer; signed-in users may add a folder to it (`(A;;LC;;;AU)`), and a
  folder so added is the user's own, open to all users. A plain user made one: DONE. So the Linux rule (no folder
  on the way writable by another) cannot be carried over word for word: it would refuse every path of Windows.
- `C:\ProgramData`: users may add files and folders. `D:\` (x64 only): owner the network service. A user's own
  folders: the user or the administrators as owner, and the user's own account holding everything.
- K-1 (who the system is). Three names and no other: the system (SY), the administrators (BA), and the system's
  installer (TrustedInstaller, by its whole SID). An administrator's own account, a domain's group, any other
  service's name: not the system. FOR: one small set, each measured as the owner of what Windows itself runs.
  MUST NOT TOUCH: OWNERS of the place (AG-1: SY or BA; the installer never makes the place).
- K-2 (the code itself). Every file and folder the service would load from - the root and everything below it,
  whole - is taken only where: it is no reparse point; its owner is of K-1; its list is there (no null list); and
  every allowing entry for a name outside K-1 holds nothing but reading and executing (the bits 0x1, 0x8, 0x20,
  0x80, 0x20000, 0x100000, and GR, GX). This is a list of what is allowed, not of what is refused: a bit not on
  it refuses. An inherit-only entry counts as any other - what the folder would give to what is made in it later
  is judged now - but for the creator's own (CO), which is taken only where it is inherit-only. Denying entries
  give nothing and are not counted. An entry of any other kind, one with more than its six fields, an object or
  inherited-object field that is not empty, a rights word this Raqib does not know: refused, with the entry
  said. FOR: nobody but the system can change, add to, or take from what runs as the system.
- K-3 (the folders above, up to the drive). Each folder above a root, the drive's own included, is taken only
  where: it is a folder and no reparse point; its owner is of K-1; its list is there; and every allowing entry
  for a name outside K-1 that is not inherit-only holds nothing but K-2's bits and these four: add a file (0x2),
  add a folder (0x4), write extended attributes (0x10), write attributes (0x100). So nobody but the system may
  delete or rename what the folder holds (0x40), delete or rename the folder (0x10000), or change its list or
  owner (0x40000, 0x80000, GA); GW is refused too, not measured. Inherit-only entries are not read here: what a
  folder on the way gives to new things beside the code is not the code. FOR: adding a thing beside does not
  replace what is there, and that is what lets `C:\` and Program Files pass and refuses GitHub's Python, a
  user's folders and `D:\`. MUST NOT TOUCH: the Linux rule and its walk (raqib/service.py), which stay.
- K-4 (the path). A root is judged only where its whole path begins with a drive's letter (`X:\`) and holds no
  `..`; any other form (a share, a device path) is refused. A name longer than the system opens plainly, a name
  that cannot be opened or read, a folder that cannot be listed: refused as not read - what was not read is
  never the system's. A walk past WALK_MAX names is refused (the Linux number).
- K-5 (what is walked: the packed road only, now). Packed with its own runtime (`sys.frozen`): the root is the
  folder the program file is in, whole. Where the runtime says its modules are unpacked somewhere outside that
  folder (a one-file packing unpacks into a temporary folder at each start), refused: what would run is not
  there to be read. A plain interpreter (not packed) is refused for now with its own words: its roads (the
  interpreter's folder, a venv's base, every entry of sys.path, the lines of *.pth files) are not ruled before
  an install for all users is measured - GitHub's own Python can only ever be refused.
- K-6 (one command that changes nothing). `raqib service check` (Windows): says whether the code a service
  would run is the system's alone - what it walked, by count, or the first name refused, in which of the two
  roles (K-2, K-3), and why, with the owner or the entry as read. Exit 0 the system's alone; 1 not, or not
  read; 2 not Windows, or not packed. It asks for no rights: a plain user can read these lists (measured). FOR:
  an administrator, a package and the rig can ask before anything is installed, and M12.4c2's install asks the
  same function.
- K-7 (one reader). The name is read by the function that reads the place (one handle: its kind, owner and
  list); there is no second copy of those calls in the tree.
- K-8 (a claim on the rig, the Table's wiring after the task lands). The rig's Windows job packs Raqib, asks the
  check of the copy an administrator put in Program Files and of the copy in the job's own folder, and keeps
  both answers; X49 is MET where the first is 0 and the second is 1 with the name refused said.
- K-9 (the task in two). M12.4c1: K-1 to K-7 and X49's reading. M12.4c2, after it: `raqib service install |
  remove | status` on Windows by the system's own calls, the place made with its owner named (AG-5), the start
  at boot, the system told to start it again, the command quoted, a refusal's number said with its words.
- Not read by this check, and said so in the spec: rights a user holds apart from any list (backup and restore,
  taking ownership, debugging programs); the system's PATH (this Raqib loads no library by a bare name that
  System32 does not hold - to be pinned by a test in M12.4c2); the labels of a system list; what changes after
  the check (it is a reading at one moment, as the Linux one is). Not measured: the kind of the drive (a
  removable or shared drive, a volume with no lists - being measured, ruled with M12.4c2); a machine joined to a
  domain; Program Files on a machine whose lists an administrator changed; an install of Python for all users.

## Amendment L (the Table, 2026-11-27) - the review of M12.4c1 (docs/review/2026-11-27-M12.4c1.md) and its field run: lands
The builder ended with STOP (bb5aa89): the work whole and inside its scope, the gate red on one test - the scan of
tests/fixtures for a person's home folder refused the made-up name the Table had put in the measured file. The
fault was the Table's; the name is now the placeholder that scan allows (ce2eac8), and the gate is green.
The field's word on the branch (the probe branch 0a59bbc; GitHub's Windows machines, x64 and ARM64, the same on
both; the branch's Raqib packed by the rig's packer): the check's tests passed there, the one real reading among
them. A copy an administrator put under Program Files: taken, about 150 names and 2 folders above in under half a
second; a plain user who asked got the same sentence and exit 0 (K-6's "measured" rests on this run, not on the
runs before K). In that copy, one thing changed at a time and undone: a file users were let modify - refused, the
file and the entry said; the same file, users given reading and executing by an entry of its own - taken; the file
owned by the administrator's own account - refused; a junction inside - refused; a folder and a file an
administrator added - taken, two names more. A copy in a folder an administrator made at the drive's root: refused
(it inherits modify for signed-in users); under ProgramData: refused; in the job's own folder: refused (x64 `D:\`,
its owner; ARM64 the job's folder on `C:\`, which signed-in users may delete); three folders deep under Program
Files with a space in a name: taken, 5 folders above; packed as one file: refused, its modules under the user's
temporary folder (K-5's sentence rests on this run); a plain interpreter: exit 2. X49 read MET on both.
Measured since K (the probe branch cf233f5, 4de9aec): a volume that keeps no lists (FAT32, exFAT) reads as a fixed
drive and gives every name the owner `WD` and a null list - refused by K-2 and K-3 as they are; a letter given to
a folder (`subst`) reads as a fixed drive too, and only its device's name tells it apart (`\??\...` where a disk's
is `\Device\...`); python.org's installer for all users put an interpreter under Program Files, owned by the
system (the interpreter, its library, its site folder) and the administrators (its Scripts folder), Program
Files' list inherited, no reparse point, its `-I` path wholly inside its folder; an administrator's copy of a
Python there refused a plain user's six writes and one renaming, and the watch ran as a service from it by
`python -I -m raqib service run`.
The reviewer's verdict is NEXT: no text, path or listing found that is taken where K says refuse. Ruled, and done by
the Table's hand:
- L-1 (K-3 narrower; the review's reading of K against the fixture, b). K-3 allowed a name outside the system's to
  write a folder's own extended attributes and attributes (0x10, 0x100) on a folder above. Nothing measured what
  the two give, K's own reason covers adding a thing beside only, and K-2 says a bit not on the list refuses. They
  are taken out: a folder above may give another name K-2's bits, add a file (0x2), add a folder (0x4), and no
  other bit. `C:\ProgramData` is then refused as a folder above (it gives users both); `C:\` and Program Files
  pass as before. FOR: no bit is allowed that was not measured as harmless. MUST NOT TOUCH: K-2.
- L-2 (the words say what was judged; findings 1, 3, 4, 5, 9). The pass says that the creator's own inherit-only
  entry was left apart, that above only the entries that apply to the folder itself were read, and "to the
  drive's letter". The spec says the program's folder is judged as code and the folders above it begin above it;
  the guide says what the field run gave and no more; K's sentence on a user's folders is corrected in the spec
  (the profile read was the built-in administrator's, owned by the system; a plain user's profile was not read),
  and K-1's "each measured as the owner of what Windows itself runs" is true of the system's installer only: the
  system and the administrators were measured as owners of the system's folders and of what an administrator or
  an installer put. A name or text said is cut at 200 (the entry that decides is said whole); the spec says the
  shorter cuts inside.
- L-3 (said as not read or not measured; findings 2, 12, 13, Q2, Q8). The packed runtime's own roads outside the
  program's folder; what a drive's letter names (refused with the install: the device's name must be a disk's -
  M12.4c2); the order below the root is the file system's; a file the system itself marks as a reparse point; a
  denying entry that still lets the asker read (the one tried took reading from the asker, and was refused as
  not read).
- L-4 (small, by hand; findings 6, 7, 10, Q11). An error's number said is the system's own where there is one; the
  test of "nothing at import" takes only a docstring as a bare expression and reads every call inside an
  assignment; the command's help and docstring say the Windows actions and who imports the Linux module.
- L-5 (the builder's questions, kept as built). A packed runtime that does not say where its modules are: refused
  (Q1). Two names of one folder that differ only in case, a name ending in a dot or a space, a device's name, a
  path past 259 characters, a flag, a rights form or a list flag not known, a short form of the modules' folder:
  each refused, none repaired (Q3, Q4, Q5, Q7, Q9). Breadth first below the root (Q8). Three sentences left as
  they were stay true (Q11). E5 ran on both machines in the field run, and on x64 at every gate (Q12).
- L-6 (the rig, K-8; Q10). The rig's Windows job packs with the same pinned packer and pack.sh's arguments
  (tools/rig/service_check.ps1), for the check only; the test that held "no packer in the Windows job" now holds
  one pinned packer there and no packed watch. X49 asks only for a path of a drive and a role in the refusal: on
  x64 it is `D:\`, on ARM64 the job's own folder.
- L-7 (lands, and next). M12.4c1 lands as 0.11.0 after the gate and the rig on the commit to be merged. Next:
  M12.4c1b, a plain interpreter's road (its folder whole, a venv's base and the venv, every entry of the `-I`
  path, the lines of *.pth files as on Linux), on the measurements above; then M12.4c2 (K-9), with the drive's
  device and the test of the libraries loaded by name.

## Amendment M (the Table, 2026-11-27) - M12.4c1b: the check's road for a plain interpreter
K-5 refused a Raqib that a plain interpreter runs until a Python for all users was measured. Measured since (the
probe branch cf233f5 and 4de9aec; GitHub's Windows machines; the texts are tests/fixtures/wincode/python.txt):
python.org's installer for all users (3.10.11 on x64, 3.11.9 on ARM64) puts the interpreter under Program Files,
everything of it owned by the system or the administrators, Program Files' list inherited, no reparse point;
asked with `-I`, its whole path lies in its own folder (its zip, which is not there; DLLs; Lib; the folder; its
site folder), and its site folder holds one *.pth file of one `import` line. A copy of a Python an administrator
put under Program Files reads the same; a venv made from it under Program Files adds its own folder and site
folder to the base's four entries and names the base in pyvenv.cfg and in the base executable. Without `-I` the
path begins with the folder the interpreter was started in and the user's site is on. A plain user's six writes
into the copy and the venv and one renaming were refused. The watch ran as a service from the copy by `"...
python.exe" -I -m raqib service run`.
- M-1 (asked as the service will be run). The service's command for a plain interpreter is the interpreter, `-I`,
  `-m raqib service run` (measured; M12.4c2 writes it). So the check takes a plain interpreter only where it was
  itself started with `-I` and with its site (no `-S`): then the path it walks is the path the service gets.
  Otherwise exit 2, with the words to ask it by: the interpreter's own path, `-I -m raqib service check`. FOR: one
  path, read from the running interpreter, never worked out. MUST NOT TOUCH: the packed road (K-5), which stays
  as it is and is chosen first.
- M-2 (what is walked, each by K-2 and whole, the folders above each by K-3 as L-1 left it). The folder the
  interpreter is in; where the interpreter says a base executable in another folder (a venv), that folder too; the
  interpreter's prefix and its base prefix; every entry of its path; the folder of the raqib package. An entry
  that is a folder is walked whole; one that is a file is judged as itself. Each real folder is walked once, and
  WALK_MAX bounds the whole walk.
- M-3 (an entry that is not there). The path names things that do not exist (the zip of the library; a line of a
  *.pth file). Whoever may add the missing thing decides what runs, so the deepest folder of it that exists is
  judged as the code itself (K-2: nobody but the system may add to it), itself only, and the folders above that
  by K-3. FOR: `C:\made-later\x` on a path is refused because signed-in users may add a folder to `C:\`.
- M-4 (*.pth files, as on Linux). In every entry that is a folder, each *.pth file is read only once it was found
  the system's alone, whole and at most PTH_MAX bytes; a byte outside printable ASCII, tab, LF and CR refuses
  (AD-4); its lines that are paths, by site's own rule (not blank, not `#`, not `import`), are made whole against
  the entry and become entries, there or not (M-3). Nothing of a *.pth file is run. An `import` line is code that
  the file's owner put there: the file was found the system's alone, and no more is said of it.
- M-5 (the words and the exits). Exit 0 with the counts: names by kind, entries, entries not there, *.pth files
  read and their lines taken as entries, folders above. Exit 1 with the first name refused, its role and why, as
  now; an entry that is not there is said as such with the folder judged for it. Exit 2: not Windows; a plain
  interpreter not started with `-I`, or started with `-S`.
- M-6 (a claim on the rig, the Table's wiring after the task lands). The rig's Windows job copies its Python under
  Program Files as an administrator would, installs Raqib into the copy, and asks the copy with `-I` and the job's
  own Python with `-I`; X50 is MET where the first is 0 and the second 1 with the name refused said.
- Not read, and said so: what the system's own account would add to the path that the asker's does not (a path
  the registry gives under the asking user's own key is on the asker's path and is walked; one under the system
  account's own key is not seen - only the system writes there); a finder or hook a package installs (an editable
  install is met only as its *.pth file and the package's folder). Not measured: whether `-I` reads the
  registry's paths at all; python.org's installer with a plain user's writes tried against it (tried against the
  copy); the Store's Python (its interpreter is a reparse point: refused); an embedded distribution with a `._pth`
  file; Python older than 3.10.

## Amendment N (the Table, 2026-11-27) - the review of M12.4c1b (docs/review/2026-11-27-M12.4c1b.md) and its field run: REDO
The reviewer's verdict is STOP, and it is right: the code does what M says, and M is wrong. M-2 judges the folders
above the interpreter's folder by K-3, whose reason is that adding a thing beside does not replace what is there.
But a plain interpreter looks, at every start, for files of fixed names beside and above its own folder, and
what it finds there changes what it runs. Read in the interpreter's own source (CPython 3.11.9, 3.12.10, 3.13.9
and 3.14.0, Modules/getpath.py and Lib/site.py), not measured - no probe plants such a file:
- `pyvenv.cfg` is read from the folder above the folder the executable is in, and else from that folder, with or
  without `-I`; the site module looks in the same two places.
- A build tree is looked for: `pybuilddir.txt` in the real executable's folder, and else the file
  `Modules\Setup.local` two folders above that folder; where it is found, the library is taken from `Lib` two
  folders above. For python.org's own default folder for all users (one folder below Program Files) "two folders
  above" is the drive's root - where signed-in users may add a folder (measured, K).
- A `._pth` file beside the library or the executable replaces the path (inside the folder; walked).
None of the three is asked where the interpreter's home was set by the program that embeds it. Read in the
packer's source (PyInstaller 6.11.1, bootloader/src/pyi_pyconfig.c): it sets the home, the path's entries, an
isolated configuration and no site. So the packed road stands as K and L left it - for this packer, the one the
rig pins.
The field's word on the branch as built (the probe branch f60bbdf; x64 and ARM64): the check's tests passed on
both; python.org's installer for all users (3.11.9, ARM64) with the branch's Raqib installed, asked with `-I`:
taken, 3271 names, 5 entries, 1 not there, in 0.7 s - and that take is the fault above, on a real machine. Without
`-I`, and by the `raqib.exe` beside it: exit 2 with the command to ask by. The job's own Python: refused. A venv
under Program Files: taken. A *.pth line naming a folder not there under the root: refused, the root judged for
it; one naming a folder under Program Files: taken, and the folder was on the interpreter's path; one under
ProgramData: refused; a package file users may modify: refused. Measured on ARM64 (3.11.9): a path the registry
holds under the interpreter's PythonPath key, the user's or the machine's, is on the path without `-I` and not
with it. On x64 the installer ended with 0 and installed nothing (the machine holds that version); a copy stood in.
- N-1 (the names the interpreter itself looks for are judged as entries are; replaces nothing of M, adds to M-2).
  For the folder the interpreter is in, and for its base's: `pyvenv.cfg` in the folder above it; and, two folders
  above it, `Modules\Setup.local` and `Lib`. Each is judged as an entry of the path is: there - as the code itself
  (a file as itself, a folder whole); not there - by the deepest folder of it that is there, as the code itself,
  itself only (M-3: whoever may add the missing thing decides what runs). The refusal says which name, that the
  interpreter looks for it at every start, and the folder judged for it. FOR: nobody but the system can give the
  interpreter a venv file or a build tree. So an interpreter one or two folders below a drive's root is refused
  wherever signed-in users may add a folder to the root - python.org's default folder for all users among them,
  said in the words of the refusal and in the guide; one folder deeper (`C:\Program Files\NAME\Python...`) it is
  taken. MUST NOT TOUCH: the packed road; K-2, K-3, L-1.
- N-2 (who runs the check; finding 3). The check is run by the code it judges: the interpreter that says the pass
  has already run its site and the `import` lines of its *.pth files, as every start of it does. So the pass says
  "none of their lines taken or run by the check", never "nothing of them run"; and the spec, the guide and the
  threat model say that the check is a reading of a tree as its own code tells it - a gate against a tree put in
  the wrong place, not a judgement of a tree another already changed - and that it is asked first by a plain
  user, who needs no rights for it. Said too: the check writes nothing, but the interpreter that runs it may
  write bytecode caches beside what it imports where the asker may write there.
- N-3 (small; findings 4, 5, 6, 7, 9). Only the base executable may be unnamed: a program, a prefix or a base
  prefix the system object does not name is a refusal, never skipped. The exec prefix and the base exec prefix
  are roots too where they are not the prefix and the base prefix. The pass counts apart the folders judged
  themselves only, says "its base's" only where a base was walked, and says an entry beneath a file as judged by
  that file. The documents say both roads, what is taken beneath a file, and that names beginning with a dot are
  read though site skips them. The tests' stand-in listings are named as stand-ins; the X50 test's refusal
  holds the bits the check says.
- N-4 (the builder's questions, kept as built unless N-1 to N-3 say otherwise). A folder met as a folder above
  and as a root is judged in both roles on one reading (Q1; the reviewer traced both orders). An entry on a drive
  that is not there: refused (Q3). *.pth names as site matches them, read in every entry that is a folder (Q4,
  Q5). The raqib package outside every entry is walked where it is (Q6). Roots that must be there are refused
  where they are not (Q7). Lines made whole with ntpath, never repaired (Q9). A *.pth file read to one byte past
  its bound and refused there (Q10). The command to ask by in double quotes (Q11). A short name is not matched
  to its long one: walked twice, never passed for it (Q16). cli.py's docstring is the Table's at the merge (Q12).
- N-5 (the rig, M-6). The copy X50 asks is put one folder deeper (`C:\Program Files\RaqibRig\Py`), by N-1.
- Recorded: a 2 or 3 from a call on an opened handle would be believed as "not there" (finding 8; none known);
  names whose case the file system and the check fold differently (finding 10); a launcher's variable inherited
  by the asker (finding 11). Not measured: N-1's three names on a real machine (read in the source only); the
  registry's paths on x64 and on a version after 3.11; whether bytecode caches are written by an asking
  administrator; a packer other than the one read.

## Amendment O (the Table, 2026-11-27) - the review of M12.4c1b REDO (docs/review/2026-11-27-M12.4c1b-redo.md) and its field run: lands
The field's word on 66c9d5d (the probe branch c2f8854; GitHub's Windows machines, x64 and ARM64): the gate green on
six jobs and the rig green, X49 and X50 MET; the check's tests passed on both. python.org's install for all users
where its installer put it (3.11.9, ARM64; on x64 a copy of a Python one folder below Program Files, the installer
having installed nothing there): refused for `C:\Modules\Setup.local` - and the refusal named the folder
`C:\Modules`, which is there on those machines and gives signed-in users modify. The same tree one folder deeper:
taken (3270 names in 0.9 s; the copy 11140 in 1.3 s). A venv whose base is at the first place: refused, naming the
base executable's folder; with its base one folder deeper: taken. The *.pth lines, the package file users may
modify and the registry's keys read as before the REDO. Nothing was put anywhere that an interpreter reads at its
start: what the interpreter does with those names stays read in its source.
The second reviewer read the interpreter's source line by line and found N-1's three names the whole list under
`-I`; verdict NEXT. Ruled, and done by the Table's hand:
- O-1 (a venv's home; finding 2). The interpreter takes a venv's build tree from the home its `pyvenv.cfg` names,
  not from what it says its base executable is. The base prefix is that folder. So N-1's three names are judged
  for the base prefix too, where it is neither the interpreter's folder nor the base executable's. FOR: no venv
  hides its base's place behind a base executable left unnamed or said as the venv's own.
- O-2 (the packed road and Python 3.14; finding 4). N said none of the three names is looked for where the
  interpreter's home was set. True of the venv file up to 3.13 only: in 3.14.0 it is read though the home is set,
  and the prefix follows it. The packer the rig pins knows Python up to 3.13, so nothing taken so far is touched;
  but the packed road does not judge that name, so a packed runtime that says 3.14 or later - or no version the
  check can read - is refused with those words, until a task makes the packed road judge it. MUST NOT TOUCH: the
  packed road for 3.11 to 3.13, as landed.
- O-3 (what N-1 rests on, said; findings 1, 3, 5, 6). "Two folders above" is the interpreter's compiled-in value,
  now read in its build files at the four versions. The names are made from the paths as the interpreter says
  them, not resolved (a letter given to a folder: L-3, refused with the install). A `._pth` file beside the
  runtime library is covered only where the library lies beside the interpreter. Read: getpath.py at four
  versions, site.py at two; not read: Python 3.10's start, the C code beneath, the venv launcher. "One folder
  deeper it is taken" is now the field's word, and the documents say it as that.
- O-4 (kept, and recorded). N-1 judges more than a venv's start reads - the folder above the base's, the two above
  the venv's own - and so refuses a venv directly under a drive's root that its start would not endanger: kept,
  it errs toward refusal (finding 8). A pyvenv.cfg found above an interpreter makes that folder its prefix, which
  is then walked whole (finding 9). The pass counts among its files and folders the interpreter's own names that
  are there (finding 7). The REDO builder's eight questions stand as built (the first number of the pass is the
  sum the rig reads; "walked as entries"; the order of judging; one branch of the walk that cannot be reached).
  Two test lines that changed which reading they look up, with the same text, were not named in the questions
  file (finding 11).
- O-5 (lands, and next). M12.4c1b lands as 0.12.0 after the gate, the rig and one more field run on the commit to
  be merged. Next: M12.4c2 (K-9), with: the drive's device (L-3), the test of the libraries loaded by name, the
  packed road judging the venv file's name for 3.14 on (O-2), and the service's command for a plain interpreter
  written with `-I` (M-1).

## Amendment P (the Table, 2026-11-27) - M12.4c2 in two; M12.4c2a: the drive, and the libraries loaded by name
Before an install rests on the check (M12.4c2b: `raqib service install | remove | status` on Windows), two things
the check says it does not read are closed, each from what was measured or read.
Measured (the probe branch cf233f5; x64 and ARM64): the system says a disk's letter is of the fixed kind and
names its device `\Device\HarddiskVolumeN`; a letter given to a folder (`subst`) is said of the fixed kind too,
and its device's name is the folder's own path behind `\??\`; a volume that keeps no lists (FAT32, exFAT) is a
fixed disk whose every name reads with the owner `WD` and a null list; a letter that is not there has no root and
no device. Read in the interpreter's library (Lib/ctypes/__init__.py at 3.11.9 and 3.12.10), not measured: a
library asked for by a bare name is searched with the system's default folders - the application's own folder,
System32, and folders the process itself added - and not along the PATH or in the folder the process was started
in.
- P-1 (the drive; closes L-3's "what the drive's letter names"). A path is judged only where the system says of
  its drive: the fixed kind, and a device's name that begins with `\Device\`. A letter given to a folder or to a
  share, a removable disk, a network drive, a disk in the drive of discs, a letter with no device: refused, with
  the kind and the device's name as read - what is above such a letter is not what the check reads, or can be
  changed where the check cannot see. Asked once for each drive met, before any name of it is read; both roads.
  The reading is one function beside the one reader of a name (K-7), with no second copy of its calls. FOR: "to
  the drive's letter" in the pass then means a disk. MUST NOT TOUCH: K-2, K-3, L-1, N-1, O-1, O-2.
- P-2 (the libraries loaded by name; closes K's "the system's PATH"). A test reads every place in raqib/ where a
  library is loaded and holds: the name is a plain name written in the code (no path, no name worked out, no
  folder added to the search, no search mode given), and it is on one list; on Windows the test also finds each
  name of the list in System32. With the reading above, a library Raqib asks for comes from the program's own
  folder - which the check walks as the code itself - or from System32. FOR: nothing Raqib loads is found along
  a path a user can write. MUST NOT TOUCH: any loader's behaviour; this is a test and its list.
- P-3 (a claim on the rig, the Table's wiring after the task lands). The rig's Windows job gives a letter to the
  folder of its packed copy in Program Files and asks the check through that letter; X51 is MET where the answer
  is 1 and names the letter's device.
- Not measured, and said: a network drive, a removable disk and a disc (their kinds are the system's own
  numbers, read in its documents, not seen); a letter the system's account has and the asker has not; a folder
  mounted on a volume with no letter; whether a library's own dependencies are searched as the library is.
- M12.4c2b, after it (K-9, O-5): install, remove and status by the system's own calls, as measured; the install
  asks the check and refuses unless it is taken; the command quoted, and for a plain interpreter with `-I`; the
  place made with its owner named (AG-5); the start at boot; the system told to start it again; a refusal's
  number said with its words.

## Amendment Q (the Table, 2026-11-27) - the review of M12.4c2a (docs/review/2026-11-27-M12.4c2a.md) and its field run: REDO
The reviewer's verdict is STOP on the ruling, and it is right. P-1 took a device's name that begins with
`\Device\`; what was measured of a disk is narrower - `\Device\HarddiskVolume` and a number, with nothing after
it (tests/fixtures/wincode/drives.txt). A letter whose device's name is a volume's followed by a folder's path
begins the same way, and is the very thing P-1 exists to refuse: what is above that folder is never judged. The
code does what P-1 said; P-1 said too much.
The field's word on the branch as built (the probe branch 50baa9d on bed5479; x64 and ARM64): the gate green on
six jobs and the rig green, X49, X50 and X51 MET; the tests of the check, the reader and the libraries passed on
both, the two that read a real machine among them (a disk's reading; each library of the list a file in
System32). The reader said `C:` kind 3 `\Device\HarddiskVolumeN`, x64's `D:` the same form, a letter not there
error 2. A packed copy asked by its disk's letter: taken, the pass naming the drive and its device. Asked through
a letter given to its folder, and through one given to Program Files: refused before any name was read, the
device's name the folder's own path behind `\??\`. On a disk image with lists the drive was taken and the tree
refused by its lists; on one without lists, by the null list.
- Q-1 (the form measured, and no other; replaces P-1's test). A drive is taken only where the system says the
  fixed kind and a device's name that is, whole, `\Device\HarddiskVolume` and a number: nothing before it,
  nothing after it, its letters as written. Every other name refuses, said as read with the form asked for:
  a folder's path behind `\??\`; a volume's name with anything after it; a volume of another kind of disk (not
  measured: refused until it is). FOR: "to the drive's letter" means a volume's root and nothing below it.
  MUST NOT TOUCH: the kind's rule; asked once, before any name; both roads.
- Q-2 (the words; findings 5, 7, 10). A refused drive is said without "first met by", which always named the
  drive's own root; the words for a name of another form say the form asked for and do not say what a share's
  letter reads as (not measured: such a letter is refused by its kind, if the system's documents hold). Where
  the device's name was not read, the kind stays in the reader's own words.
- Q-3 (said in the documents; findings 2, 3, 4, 6, 16, 17). The letter is read as the session that runs the
  check names it - said again; the system's account may name it otherwise or not at all, which the install
  closes by having the service ask the check at its own start (M12.4c2b). The kind is also asked by the
  autostart reader for its own purpose: the device's name has one reader, the kind two. A disk the system calls
  fixed is taken as a disk whatever it is - one carried from another machine, an image attached, a volume a
  program serves: who made its lists is not read. P-2's reading names three places a library is searched; the
  third, folders the process itself added, is what the test's "no folder added" holds for raqib/ and nothing
  holds for what the interpreter's own start adds.
- Q-4 (the tests; findings 8, 9, 11, 13, 15). The measured readings are a fixture (drives.txt), read by the
  tests. The letter-case test reaches the folding. The second-drive case holds that the walk's earlier names
  were read. The scan of the libraries also refuses: a loader asked by index; ctypes' own low loader; a second
  positional argument or `**` in a loading call; a name of a search call written as a string anywhere but where
  it is allowed; a whole-table write to the environment; a table of names changed after it was written; a
  loader handed on as a value; and a second call of the one allowed search call.
- Q-5 (X51). It asks for the kind and a device's name that is not of the form of Q-1; the job's letter is given
  to the job's own copy, and the name's end is not tied to it (kept, said).
- Q-6 (the builder's questions, kept as built unless Q-1 to Q-5 say otherwise). The drives asked on a list the
  caller gives; said at the end of the pass; a refused drive names no role; the stand-in's default for a letter
  a test does not give is a disk of the measured form, said as a stand-in; the buffer's bound; find_library
  refused outright.
- M12.4c2b gains, from this review: the runner asks the check at its start, as the system, and does not watch a
  tree it does not take (its own number for it); the install writes the command by the path the check judged.

## Amendment R (the Table, 2026-11-27) - the review of M12.4c2a REDO (docs/review/2026-11-27-M12.4c2a-redo.md) and its field run: the drive lands; the libraries' hold is re-made
The field's word on f27ccef (the probe branch bcf1a7c; x64 and ARM64): the gate green on six jobs and the rig
green, X49, X50 and X51 MET; the tests passed on both. Measured there, the thing the first review named: a letter
given to a volume's own name followed by a folder's path reads as the fixed kind with exactly that name - P-1
would have taken it - and is refused before any name is read. A letter given to the volume's name alone is
another letter of that volume's root: taken, the whole tree walked from the root, the pass naming the letter and
its device. Letters given to a folder (the `\??\` form), and the disk images with and without lists: as before.
The second reviewer's verdict is REDO, for the libraries' test alone: the drive is built as Q-1 ruled, with no
input found that is taken outside the form; the scan still passes three forms Q-4 named (a folder reaching CI-3's
call through its parameter bound again; a loader lambda handed on inside its own binding line; a table of names
changed from another module), and its list of what it does not see was not whole. Ruled:
- R-1 (the drive lands). P-1 as Q-1 corrected it, with its words, its rig claim and its documents, lands now. It is
  the part an install will rest on, it was measured on real machines in every case ruled, and both reviews found
  it sound.
- R-2 (small, by the Table's hand; findings 7, 8). The system's answer is read only as the plain types - a tuple,
  an int, a str, never a kind of them. The guide, the spec and the threat model say of the libraries' test what
  it holds - the ways it knows - and that the search's three places were read, not measured.
- R-3 (the libraries' hold is re-made, a task of its own: M12.4c2a2). A scan that lists the forms it refuses is
  out-written by the next form; two reviews each found forms the one before had not. The hold is turned round:
  every mention in raqib/ of a word by which a library can be loaded, the search changed, or ctypes reached - as
  a name, an attribute, an import, a keyword or a string, docstrings too - is on a list the test holds, by file,
  function and count, and any other mention fails; every attribute taken of ctypes is on a list of those Raqib
  uses; the one function that calls CI-3's call is held word for word; each table of names is mentioned only
  where the test says. A new load then cannot be written without changing the test's own list, where a reviewer
  reads it. Until it lands, the scan stands as the first hold, its own first lines saying what it does not yet
  hold; nothing in the tree today is one of those forms (two reviewers read every load by hand). FOR: the hold
  no longer depends on knowing every way. MUST NOT TOUCH: any loader.
- R-4 (kept, and recorded; findings 6, 9, 10, 12, 15 and the builder's questions). The lines of the rig's check
  that describe X51 follow its reading. The pattern takes any number of digits; the numbers measured were 3 to 7.
  A volume is taken as the system names it: what can write it beneath its file system is not read. A letter
  given to a disk's own root behind `\??\` is refused by its form (kept: it errs toward refusal). The drives are
  said at the end of the pass; a refused drive names no role; the stand-in's default disk is a stand-in.
- R-5 (lands, and next). M12.4c2a lands as 0.13.0 after the gate and the rig on the commit to be merged. Next:
  M12.4c2a2 (R-3), then M12.4c2b (K-9, O-5, Q's two additions: the runner asks the check at its own start as the
  system and does not watch a tree it does not take; the install writes the command by the path the check
  judged).

## Amendment S (the Table, 2026-11-27) - the review of M12.4c2a2 (docs/review/2026-11-27-M12.4c2a2.md): what the hold on the libraries is for, and where it ends
The third reviewer of this hold found its tables true to the tree, compared exactly both ways, and every one of
the thirty forms the two reviews before had named failing at its own line - and then defeated it again: a
library's object reached from another file, through getattr of its holder, a closure or the heap; the names
CI-3's hand-over reads bound otherwise; the environment written through a name it was bound to; a table changed
by its name written in a string; the interpreter's own loaders of code. Verdict REDO. The findings are right, and
the fault is the Table's: three reviews were asked to defeat a reading of source text, and source text can
always be written to defeat a reading of it. Whoever can write a file of raqib/ can write anything there; a scan
is no wall against that, and R-3's "a new load cannot be written without changing the test's own list" promised
one.
- S-1 (what the hold is for). It guards against a change made in good faith that no reader notices: a new
  library's name, a library loaded by a path, a folder added to the search, the PATH or the whole environment
  set, a loader handed somewhere new, ctypes used in a way the tree did not use it. Each of those, written the
  ordinary way, changes a table of the test, and a reviewer reads the table's change. It does not hold code
  written to get past it, and no later task is asked to make it. FOR: the claim is one that can be kept.
  MUST NOT TOUCH: the tables as built (true, and exact both ways).
- S-2 (said exactly). The test's first lines and the three documents say S-1 in its own words, and name what is
  therefore not held: an object of a library reached outside the function and file that loaded it, or by
  getattr of what holds it, a closure, or the interpreter's own lists of live objects; a name the held
  statements read, bound otherwise elsewhere; a table reached by its name as a string from another module; the
  interpreter's own roads to code that is not a library by name (its import system given a path, sys.path,
  extension modules); what the system's own libraries load by the registry's word; and all that R-3 already
  said. "Any other fails" is said nowhere.
- S-3 (the ordinary forms still missed, closed; findings 3, 6, 7, 8). The environment written through a name
  os.environ was bound to in the same function is an ordinary form: followed and held. getattr of a library's
  object by a name beginning with an underscore is held as any other use. A class pattern's keyword names are
  read as mentions. That `sys.modules` is counted where a file imports sys is proved by a case of its own.
- S-4 (the cost; the builder's question 2 and the review's view). `compile`, `exec` and `eval` reach code only as
  the interpreter's own names: counted as names, as attributes of anything but a module bound by `import re`,
  and in strings that are not docstrings. A new regular expression or a sentence of help no longer changes a
  table.
- S-5 (the builder's questions, kept as built unless S-3 or S-4 say otherwise). The twelve words added; case
  kept; a read of the environment by any key not counted; compound statements held whole; `loader` counted in
  other files; the two tables. The form autostart's reader of a drive's kind has (a library's name bound again)
  is held as it is and stays.
- S-6 (lands after the REDO and a reading of S-2 to S-4 alone; and next). No fourth attempt to defeat it is asked.
  It moves no number (a test and its documents). Next: M12.4c2b1, then M12.4c2b2.
- S-7 (the review of the REDO, docs/review/2026-11-27-M12.4c2a2-redo.md, verdict NEXT; the builder's nine questions;
  the cost). The reviewer kept to S-1's bound and found the four ordinary forms closed, each case proving its form,
  and the narrowing true to the tree row for row; what was left was wording, and the Table made it by hand (below).
  Ruled:
  - Question 1: one rule for `os.environ` and for a name bound to it, as built - a `.get` given a key that is not a
    string written in the code is held by its statement. The HANDOFF's E1 said in its last sentence that the reads the
    tree makes through such names stay uncounted, and in its first that they are held: the contradiction was the
    Table's, and three statements that only read are held. FOR: a hold that does not depend on how a name is spelled.
    Question 2: no list of methods that only read; one row today does not earn a rule.
  - Question 3: the forms followed are the ones the tree uses, as built; a name bound at a file's top is followed
    through the whole file (the review's finding 4), and that is now said where the rule is said. Questions 4 to 6 and
    8: as built. Question 7: the short form in the guide and the threat model said something other than S-2 (finding
    2) and is re-worded: a library's object reached from elsewhere or through what holds it, a name it reads bound
    elsewhere, a table reached from elsewhere. Question 9: the gate's matrix (Python 3.11 and 3.12, Linux and Windows)
    read green on the builder's commit.
  - The cost the reviewer named: the eleven rows added to ENVIRON hold whole statements, and an edit of one for
    another reason (a check added to doctor's list, a keyword added where the watch makes its notifier) changes the
    table. Accepted as built: the change is one row printed by the test's own helper, and a reviewer reads it. If such
    changes become routine, the rows where the name is only handed on are to be held by what it is handed to and not
    by the statement's text - a task of its own then, not now. MUST NOT TOUCH: an ENVIRON row's change is read, never
    passed because it is usual.
  - Made by the Table after the review (findings 1 to 5): "every place a library is loaded" and "every mention" became
    each place in the forms it knows and each mention of a word on its lists, in the test's first lines and the three
    documents; "the PATH is closed by a test" became held by a test; the short form above; the file's top said; and
    the two made-up cases that allowed any other reason at their lines now name the one other reason each may give.
  - It lands as tests and documents; no number moves (ADR-0015). Next: M12.4c2b1.

## Amendment T (the Table, 2026-11-27) - M12.4c2b in two; M12.4c2b1: the service asks the check at its own start
Measured before this ruling (the probe branch b1ee4fb; x64 and ARM64, the same): a service that ends with a
number of its own is not started again by the system - one line in the system's log - unless it was made with
the failure flag, and then it is started again after every such end by the actions it was given (nine times in
twenty seconds with actions of 2 s). A caller with no rights may open the service manager and a service to ask
its state, its making and its description, and is refused (error 5) the start, the stop, the removal and the
change. The system's numbers: a name already there 1073; a stop of one not running 1062; a start of one running
1056; a removal of one running is taken and it runs on, marked - a second removal or a making under that name
1072; gone only when it has stopped and every handle is closed (then 1060); never started reads state 1 with
1077. A description set is read back as set.
And from Amendments Q and R: the check reads a drive's letter as the asking session names it, and the session
that asks is not the system's. Measured for that (the probe branch 25a25a3; x64 and ARM64, the same): asked by
the system's own account, the check says word for word what it says to the user who asked - a packed copy under
Program Files and a Python copied one folder deeper there (asked with `-I`) taken, about 150 names in 0.2 to 0.3
s and about 10000 in 1.1 to 1.9 s; the job's own Python and its own packed folder refused, by the same name and
entry; a letter the user's session gave to a folder is not there for the system at all; and the runner of 0.13.0
serves from both copies (a round read 4 s and 1 s after the start). So on these machines the two answers agree,
and nothing holds that they do on another: the answer an administrator got is not yet the answer for the
service.
- T-1 (the service asks, as the system). At every start the runner asks the check of its own code - the same
  function, the same roads, nothing skipped - after the place is taken and its text file begun, and before it
  says RUNNING. Taken: one line in the text file with the pass's own sentence, and it goes on. Not taken, for any
  reason the check has (a name not the system's alone, a drive that is not a disk's volume, a plain interpreter
  not started with `-I`, a packed runtime it does not walk, a name not read): the whole refusal in the text
  file, no watch begun, and the system told a number of the service's own (15: the code is not the system's
  alone), from START_PENDING, so that the start fails at once and says why in the system's log. FOR: the
  service is never the road by which a user's file runs as the system; and the letter, the path and the lists
  are read by the very account and session that will run. MUST NOT TOUCH: the check itself; the order before
  the check (AF-2); the watch; the Linux unit, whose install checks.
- T-2 (what is said while it walks). Before the check the runner tells the system it is still starting, with a
  wait long enough for a large tree (measured: about 150 names in 0.3 s packed, about 11000 in under 2 s for a
  plain interpreter; a tree near WALK_MAX is not measured, and is said so). The check's time is in the line.
- T-3 (the rig). The rig's service (X48) is made from a Python copied under Program Files, one folder deeper
  (N-1), started with `-I`: its own Python is one a plain user may write, and the service now refuses it. X52 is
  MET where a service made from the job's own Python fails to start with the number 15 and its text file names
  what was refused, and the one from the copy runs and its text file holds the pass. The Table's wiring.
- T-4 (said). A service of Windows made by hand from a tree a user may change, which watched until now, stops
  watching with this version and says why; the changelog says it first. The check at the start is a reading at
  that moment: a tree changed while the service runs is not seen until the next start (recorded; a watch of its
  own tree is another task).
- M12.4c2b2, after it: `raqib service install | remove | status` on Windows (K-9, AG-5, O-5, R-5), with the
  measurements above: the description as Raqib's mark; status with no rights; the failure flag set with actions
  that grow (5 s, 30 s, 300 s; the count forgotten after an hour without a failure), so that a service ended
  from outside is back in seconds and a refusal that cannot pass is asked again every five minutes and said each
  time.

## Amendment U (the Table, 2026-11-27) - the review of M12.4c2b1 (docs/review/2026-11-27-M12.4c2b1.md) and its field runs: what the check at the start gives, said truly; lands as 0.14.0
The builder (a411eda) built T-1 to T-3 and asked ten questions; the reviewer's verdict was NEXT with small
fixes. Both found the Table's own words wrong: T-1's FOR said the service is never the road by which a user's
file runs as the system, and it cannot be - the code that asks the check has run as the system by then. Measured
on real Windows after the build (the probe branch 5bdfbd6 and f01da5c, of a411eda; the rig's own job on 4750b1f;
x64 and ARM64): a service made from the job's own Python, from its own packed folder and from a copy under
Program Files started without `-I` did not run - STOPPED, the system's exit 1066 with the service's own
0x2000000F, two lines in its text file (the place, the refusal with the name and the entry), and event 7024 in
the system's log with the number; from the packed copy and from the Python copied one folder deeper with `-I` it
ran and watched, its line saying the pass in 0.02 to 0.03 s and 0.6 to 1.7 s. Over that copy made large (about
157000 to 161000 names) the check took 9 to 10 s on x64 and 31 to 32 s on ARM64 and the service then ran; past
WALK_MAX it was refused after 40.7 s. While it walked the system said START_PENDING, check-point 0, wait 60 s; a
Stop sent then was refused to its caller (error 1052) and reached nothing; `Start-Service` waited and took both
starts; `net start` took the one of 10 s and gave up on the one of 32 s after about 20 s, saying the service
could not be started while it went on to RUNNING. The rig: X48 to X52 MET.
- U-1 (T-1's reason, corrected; the builder's question 1, the review's finding 1). What the check at the start
  gives: the answer of the very account and session that runs, at every start; a tree that is not the system's
  alone is not watched from, and says so in the text file and the system's log; a tree that stopped being the
  system's alone since it was installed is found at its next start. What it does not give: it does not keep such
  a tree from running as the system - the interpreter, its site, the `import` lines of *.pth files and Raqib's
  modules up to the runner have run by then - and, run by the code it judges (N-2), a tree already changed may
  make its own check pass. Keeping such a tree from being made a service at all is the install's (M12.4c2b2),
  asked by an administrator's session of a tree no user has yet changed. T-1's FOR is read as this. MUST NOT
  TOUCH: no document says the check at the start prevents.
- U-2 (the wait and the check-point; questions 3 and 4, as measured). The wait of 60 s stands: the system took
  it with the check-point left at 0, and a tree at the check's bound took about two thirds of it on the slower
  machine. A Stop does not reach the runner while it starts; the road built for one is kept, tested by the
  stand-in, and said as not taken on the machines measured. Question 5: a Stop before the check does not skip it
  - a refusal hidden behind a Stop would be a finding lost.
- U-3 (the review's small findings, made by the Table). Whatever ends the check is a refusal with 15, every
  BaseException (question 6; nothing legitimate is raised there); the number is set before anything is written;
  X52 reads only the runner's own line, never the command's output; a vacuous assertion out, and the plain
  road's sentence tied to the command's as the packed road's was. Questions 2, 7, 8, 9 and 10: as built (a
  function of wincode that makes the line belongs to a task in which wincode may change; no released version
  told 15).
- U-4 (recorded for a task of its own, after M12.4c2b2). The runner does not raise its check-point while the
  check walks, and a start command that waits for it to move gives up on a long walk (measured: `net start`,
  about 20 s into a walk of 32 s) though the service starts. It touches the status road and its lock, and is
  measured with that command before it lands. Until then the documents say it. Also recorded, not ruled: the
  trace of an exception out of the check is written as it is, not made printable; a Stop asked before a refused
  check is not said in the text file; raqib/cli.py's comment that it alone imports wincode is no longer true.
- U-5 (lands, and next). M12.4c2b1 lands as 0.14.0 after the gate on the tree to be merged. The changelog says
  first that a service of Windows made by hand from a tree a user may change stops watching with this version
  (T-4). Next: M12.4c2b2 (install, remove and status; the install refuses a tree the check does not take, starts
  the service by the system's own call and waits on its state), then the check-point (U-4).

## Amendment V (the Table, 2026-11-27) - M12.4c2b2 in two; M12.4c2b2a: `raqib service status` on Windows, with no rights
Measured before this ruling (the probe branch b1ee4fb, Amendment T's first paragraph; x64 and ARM64, the same):
a caller with no rights may connect to the service manager and open a service to ask its state and its making,
and reads them - the state with the process's id, the system's exit and the service's own; the type, the start,
the account and the command (a first ask with no room answers error 122 and the bytes needed); and its
description, as it was set. A name that is not there answers error 1060. A service never started reads state 1
with the exit 1077. He is refused (error 5) the start, the stop, the removal and the change. Not measured, and
so not read by this task: the delayed start, the failure actions and the failure flag read back by a caller with
no rights; a service marked for removal as such a caller sees it.
- V-1 (the parts). M12.4c2b2a: status, which changes nothing and needs no rights. M12.4c2b2b, after it: install
  and remove (K-9, AG-5, O-5, U-1), which read their own work back through the same reader. Then M12.4c2b3
  (U-4). FOR: the reader of the manager is built and measured alone before anything writes to the manager.
- V-2 (the name and the mark). Raqib's service of Windows is the one named RaqibWatch whose description begins
  with `raqib-service/1` - the mark the Linux unit carries in its first line. A service of that name without the
  mark is not Raqib's, and is said so; nothing else is read as Raqib's. MUST NOT TOUCH: the runner, which serves
  under any name.
- V-3 (what status reads and says). By the system's own calls, opened with the least rights measured (the
  manager to connect, the service to ask its state and its making): whether the name is there; the mark; the
  command as the manager holds it, and whether it is one of the two forms Raqib's install writes (a quoted path
  and `service run`; a quoted path, `-I -m raqib service run`); the type (a process of its own), the start by
  its number and word, the account (the system's); the state by its number and word, with the process's id; and,
  where it is not running, the exit the system holds - 1077 as never started, 1066 with the service's own number
  said in the runner's own words (and, for 15, where its text file is), 0 as stopped. Nothing is said that was
  not read; a call that fails is said with the system's number, and the answer is then NOT KNOWN.
- V-4 (the answers, as on Linux). 0: RUNNING and as installed (the mark, the command's form, a process of its
  own, the system's account). 1: installed and not running, or not as installed. 3: not installed, a service of
  the name that is not Raqib's, or not known. 2: not Windows (the Linux command answers for Linux as before).
  RUNNING says the service runs, not that the watch writes its record - said in the answer, as on Linux. A
  service that is starting is said as starting, with the reason a start may be long (T-2), and is not ACTIVE.
- V-5 (the rig). X53 is MET where the job asks status at three moments and reads: no service of the name - NOT
  INSTALLED, 3; the job's service made with the mark from the copy under Program Files and running - ACTIVE, 0,
  with its command; one made with the mark from the job's own Python, refused at its start - installed and not
  active, 1, with the 15's words. The Table's wiring.
- V-6 (not in this part). Anything that writes to the manager; the place's own list read by status (the
  administrator's check says it); the delayed start and the failure actions, until they are measured as a caller
  with no rights reads them (M12.4c2b2b measures them before it sets them).

## Amendment W (the Table, 2026-11-27) - the review of M12.4c2b2a (docs/review/2026-11-27-M12.4c2b2a.md) and its field run: status says no more than it read; lands as 0.15.0
The builder (152fc91) built V-2 to V-5 on Linux, where none of the system's calls could be run, and said so; the
reviewer read them against the system's documents and found them right as text (verdict NEXT, with small fixes).
Measured on real Windows after the build (the probe branch 23d544f, of 152fc91; x64 and ARM64, the same): the
command asked by an administrator and by a user the probe made outside the administrators' group, at ten moments
- no service of the name; one made without the mark; with it and never started; running; stopped by a Stop; its
start set to automatic; its account set to another; one refused at its start with 15; one whose command lacks
`-I`; one whose description only begins like the mark - and at each the two were answered the same lines and the
same exit, as V-3 and V-4 rule them. The account of a service made with none named reads `LocalSystem`; a
service with no description reads as having none. And the gate's two Windows jobs failed on 152fc91: nine tests
of the Linux command, run on a Windows machine, went through the command's new turn to the real service manager.
The builder's gate is Linux's; the Windows jobs caught it.
- W-1 (the builder's questions, as built). The mark ends at its own end or at white space, so a later mark is
  not read as this one (V-2 is read so). The system's account is `LocalSystem`, in any case, as measured; no
  other text is taken on a guess. A running service that is not as installed is `ACTIVE, NOT AS INSTALLED`, 1,
  as on Linux. A state's number with no word is said as that and is not ACTIVE. A close that fails is a call
  that failed: NOT KNOWN. The bound of 8192 bytes for both asks stands.
- W-2 (nothing said that was not read; the review's findings 1, 2 and 9). "Stopped" is said of a stopped service
  alone; of any other state the exit is the bare number the system holds. The runner's own words for a number,
  the text file named for 15 and the reason a start may be long are said only of a service that carries the
  mark: one without it is not read as Raqib's runner. The line for 15 says where the text file is, not who may
  read the place - status did not read that. MUST NOT TOUCH: the four answers.
- W-3 (a text of another party's; finding 5). What the manager holds of a service was written by whoever made
  it. It is written out as printable ASCII and cut: a character that is not printable as `?`, a printable one
  outside ASCII by its number. FOR: such a text breaks no line and forges no answer, and a path that only looks
  like one under Program Files is seen for what it is.
- W-4 (the calls held; finding 3). The three structures are held field by field in the system's own order, the
  two asks by the bound they go through, and one test runs the real object's own logic against a made-up
  library; the real calls are run on Windows by the rig at every run.
- W-5 (the Windows jobs' failure). A test of the Linux command says which system's command it asks, so that on a
  Windows machine it does not reach the real service manager. Recorded for every task that turns a command by
  the platform: the Windows jobs of the gate are read before a branch is called green, whatever the builder's
  own gate said.
- W-6 (X53; findings 4 and 11). The rig's job makes a user outside the administrators' group, has it ask, says
  in its file who asked, and removes it; X53 is MET only where the asker was no administrator and the lines kept
  are status's own lines of the command and of the exit.
- W-7 (the documents; findings 7 and 8, the builder's question 9). What was measured is said as what it was -
  the manager's answers for a service's state, making and description, and then this command by two askers - and
  the sentences that said the status was not built are righted.
- W-8 (lands, and next). M12.4c2b2a lands as 0.15.0 after the gate on the tree to be merged, its Windows jobs,
  and X53 read on the branch. Not measured: a service that is starting, stopping or paused as status reads it;
  one marked for removal; a machine joined to a domain. Next: M12.4c2b2b (install and remove), which measures
  first what a caller with no rights reads back of the delayed start, the failure actions and the flag; then
  M12.4c2b3 (U-4).

## Amendment X (the Table, 2026-11-27) - M12.4c2b2b: `raqib service install | remove` on Windows, by the system's own calls
Measured before this ruling (the probe branch 639362e and dc172b1, Raqib 0.15.0; x64 and ARM64, the same), each
call by an administrator unless said: the service manager opened to connect and to make a service (rights 0x3);
CreateServiceW of a process of its own (0x10), automatic start (2), error control 1, no account named, shown as
`Raqib watch`, its handle asked with the rights 0x17 (to ask its making and its state, to change its making, to
start it): done, and its account read back as `LocalSystem`. ChangeServiceConfig2W on that handle: level 1, the
mark as its description; level 2, started again after 5000, 30000 and 300000 ms with the count forgotten after
3600 s; level 4, the failure flag: each done. Read back by its maker and by a user outside the administrators'
group (the manager 0x1, the service 0x5): the making, the description (116 bytes), level 2 (64 bytes: 3600 s,
three actions of the kind 1 with those delays), level 4 (True) and level 3 (False: the start is not delayed) -
all of them read with no rights. StartServiceW on the handle: done; the state read START_PENDING with a wait of
5 s, then of 60 s, then RUNNING, 0.6 s and 1.5 s after the call. A service opened with 0x10024 (to ask its
state, to stop it, to remove it): a Stop done, STOPPED 0.2 s later, DeleteService done, and the name asked for
again answered 1060. The same service made from a tree the check refuses ended its first start after 0.2 s with
1066 and its own 0x2000000F, and the system's log said, by the name it is shown as: at 0.2 s event 7031
("terminated unexpectedly. It has done this 1 time(s). The following corrective action will be taken in 5000
milliseconds: Restart the service") and 7024 with the number; at 5.4 s the same for the second time, in 30000
milliseconds; at 35.5 s for the third, in 300000. While it waited for its next start a Stop answered 1062,
DeleteService was done and the name was gone (1060). And from Amendments T, U and W: a Stop sent while a service
starts answers 1052 to its caller; a name already there answers 1073 to a making, and one marked for removal
1072; `raqib service status` reads such a service as ACTIVE where it runs.
- X-1 (the parts). M12.4c2b2b: install and remove. After it, each a task of its own: status reading the failure
  actions and the flag as part of "as installed" (M12.4c2b2c; measured above that a caller with no rights reads
  them), the check-point (M12.4c2b3, U-4), and `--purge` on Windows.
- X-2 (the calls, and a module of their own). The calls that write to the manager live in a new module,
  raqib/wininstall.py, behind one system object, each with the rights measured above and no more.
  raqib/winmanager.py stays the reader that writes nothing, and the install reads its own work back through it.
  FOR: the claim that status changes nothing stays one a test can hold by the module's words. MUST NOT TOUCH:
  the reader, the runner, the check.
- X-3 (install). In this order, and at the first that fails nothing more is made: Windows; the check of this
  process's own code (`raqib service check`'s, the same function), refused in its own words - so the plain road
  is asked as the service will run it, with `-I`; a place that is already there, read as the runner reads it at
  a start and refused where the runner would refuse it (X-8); the manager opened to make (refused: an
  administrator is needed); no service of the name - one there is never changed: Raqib's by its mark is to be
  removed first, another's is said and left; the command written for this very process by the path the check
  judged (a packed program: `"<program>" service run`; a plain interpreter: `"<python>" -I -m raqib service
  run`); the service made; the mark, the failure actions and the flag set - where one of the three fails, what
  was made is removed again and that is said. With a start: the system's own call, a wait on the state (X-4),
  and status's own lines for what it then reads. 0 only where it was made and, with a start, status answers
  ACTIVE; 1 where anything was refused or failed; 2 not Windows or a flag not its own.
- X-4 (the wait). The install waits for RUNNING or STOPPED, asking the state every quarter second, for as long
  as the runner may tell the system it is starting (the 5 s and the 60 s it tells, T-2) and a margin; a service
  still starting then is said as that, 1, and left as it is. It waits on the state, not on the check-point
  (U-4).
- X-5 (what the system is told to do after an end that was no Stop). Start it again after 5 s, then 30 s, then
  every 300 s, the count forgotten after an hour without such an end; and on an exit of the service's own too
  (the flag) - so a service ended from outside is back in seconds, and a start the check refuses is asked again
  and said each time, in the system's log and in the text file, as measured above. FOR: silence is an alarm - a
  watch that ended is not left ended. MUST NOT TOUCH: a Stop, after which the system starts nothing.
- X-6 (remove). The service opened to ask its state and making, to stop it and to remove it: not there is
  nothing installed, 0; one without the mark is not touched, 1. A Stop - 1062 (it does not run) is taken; 1052
  (it is starting) waits for the start to end, within X-4's bound, and asks again - then a wait for STOPPED, the
  removal, and the name asked for again: gone is removed, 0; still there is marked for removal and not yet gone,
  1. The record is never touched and its place is said. `--purge` on Windows is refused, 2, with those words.
- X-7 (the rig). X54 is MET where the job's install from its own Python makes nothing (the check's refusal, 1,
  and status NOT INSTALLED), its install from the copy under Program Files ends 0 with status ACTIVE as a user
  with no rights reads it, and its remove ends 0 with status NOT INSTALLED. The Table's wiring; X48, X52 and X53
  keep making their services by hand, as an administrator may.
- X-8 (the place; AG-5 amended). The install makes no place. The runner makes it at its first start, as the
  system, and in every run measured the place it made was the administrators' with the list ruled (AF-1). AG-5
  had the install make it with its owner named; that is one more write with an administrator's rights, and
  nothing needs it. What AG-5 was for is kept another way: a place that is already there is read at the install,
  by the runner's own reading, and where the runner would refuse it the install says so and makes no service -
  the administrator hears it then, not from a failed start.
- X-9 (the start at boot). Automatic, not delayed: the minutes after a start of the machine are not left
  unwatched. Not measured: a start at boot (the machines measured are not restarted), and what of the system is
  not yet there for the watch so early; the watch's rounds read what is there when they run.
- X-10 (what the install gives; U-1). This is where a tree that is not the system's alone is kept from being
  made a service: the check is asked by an administrator's session before anything is made. It is still run by
  the code it judges (N-2): an administrator who runs the install from a tree a user has already changed runs
  that code as himself - as on Linux, and said. An update over a running service is: remove, then install.

## Amendment Y (the Table, 2026-11-27) - the review of M12.4c2b2b (docs/review/2026-11-27-M12.4c2b2b.md) and its field run: install and remove land as 0.16.0
The builder (d03b9c2) built X-2 to X-8 on Linux and said plainly that no call of the new module had run; the
reviewer read every road by which a service could be made, changed or left (verdict NEXT, with small fixes), and
found one thing no test would have: a percent sign in the path. Measured on real Windows after the build (the
probe branch 460cf42 and 2574ed5, of d03b9c2; x64 and ARM64, the same), by an administrator and by a user the
probe made outside the administrators' group: the install from the job's own Python made nothing (the check's
refusal, 1); from a copy under Program Files without `-I` nothing, with the command to ask it by; with `-I`, by
the plain user, nothing (error 5 at the manager); by the administrator the service was made, set, started and
running 1.75 s later, 0, status ACTIVE as the plain user read it, and the system's log named it as made - the
same from a packed copy, running after 0.5 s. A second install over it: "remove it first", 1, the service
untouched. The plain user's remove: error 5 at the service's opening, nothing touched; `--purge`: 2; the
administrator's remove: a Stop, STOPPED after 0.25 s, removed, the name gone (1060), 0, the record left. A
service installed with `--no-start` read installed and not active, and its remove took the Stop's 1062. With a
place an administrator had made by hand the install named the list it read and the runner's number for it, and
made nothing. Over a service of the name without the mark the install made nothing and the remove touched
nothing. The gate's Windows jobs were green on d03b9c2, and no service of the name was there after its tests ran
on those machines.
- Y-1 (the builder's questions, as built). The made handle is asked with 0x10017 and remove's with 0x10025 - one
  right more on each than was measured before the build, to remove again what a failed setting left and to read
  the mark on the very handle then stopped and removed; the field run showed an administrator is given both. Two
  objects, the writer and the reader (X-2). The name asked before the making. The place read before the manager
  is opened, so that nothing able to make a service is held while it is read (X-3's order). The bounds: 80 s for
  a start and 45 s for a stop - the runner's own hints and a margin of 15 s. In remove, a Stop answered
  otherwise than done, 1062 or 1052, a second 1052 and a service not stopped at its bound each remove nothing
  and say so. `--no-start` ends 0 with no status lines.
- Y-2 (a percent sign; the review's finding 1). A path that holds a percent sign is not written into the
  service's command, and the install makes nothing. The system's documents say a service's command is kept in a
  form whose variables it expands at a start; the check judges the path as it is written, so the two could name
  different programs. Read, not measured - and not to be measured by trying which program the system would then
  run: it is refused whole. FOR: X-10 rests on the command naming what the check judged.
- Y-3 (absence is one error; finding 6). Only the place's own name not there (error 2) is a place for the runner
  to make. A folder above it not there (error 3) is refused: the runner could not make the place either.
- Y-4 (no word that says more than was done; findings 4, 5, 8 and 11). An answer does not say done where the
  exit says 1: a handle that could not be closed is said in the RESULT. Where a setting failed and what was made
  could not be removed, the answer says whether it carries the mark - with it Raqib's remove removes it; without
  it Raqib's remove will not touch it, and the system's own tools do. "Removed again" says that the removal was
  asked and that the service goes when every handle on it is closed. `--no-start` says the start is set to
  automatic, and that a start at boot is not measured.
- Y-5 (texts, and what the tests hold; findings 7, 9 and 10). A path and a command are written out as status
  writes what it reads, printable ASCII (W-3). The tests' stand-in records a call on the service that is given
  another handle than the service's; the list of where the reader is imported is exact.
- Y-6 (X54; the rig). The job asks Raqib's own install and remove as its administrator, and a user it makes
  outside the administrators' group asks status after each; X54 is MET only where status's own line of the
  command names a path under Program Files, so that which copy was installed is read and not taken on the job's
  word.
- Y-7 (the documents; findings 2 and 3). The rights are said as they are - measured before the build, and one
  more on two handles, shown by the field run - and the guide says both halves of X-10: the install asks the
  check first, and the check is run by the code it judges.
- Y-8 (lands, and next). M12.4c2b2b lands as 0.16.0 after the gate on the tree to be merged, its Windows jobs,
  and X54 read on the branch. Not measured: a start at boot; a machine joined to a domain; a remove while the
  service starts or while another program holds it open; a setting that fails on a real machine. With it the
  watch as a service of Windows is installed, asked and removed by Raqib's own commands. Next, each small:
  status reading the failure actions and the flag as part of "as installed" (M12.4c2b2c), the check-point raised
  while the check walks (M12.4c2b3), `--purge` on Windows; then the queue (a live reader for macOS first).
