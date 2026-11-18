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
