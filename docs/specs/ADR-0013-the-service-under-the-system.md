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
