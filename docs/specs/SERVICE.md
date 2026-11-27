# The service: Raqib's watch as a unit of the system's (ADR-0013)

On Linux, an administrator can run the host watch (`raqib watch --host`) as a systemd unit of the system's,
`raqib-watch.service`. It runs with the system's rights, so the agent it watches cannot stop it, cannot write its
record again, and cannot leave its sight by becoming another user (ADR-0013 A-1). This is stage S1: the watch's unit
on Linux. The forwarder as a unit (S2) and what a person without rights reads of the service (S3) come later; Windows
(S4) has its runner, its check and its status in sections of their own below, and no install yet. The watch itself is
unchanged; the unit runs it with `--no-page`, so it serves no page (below).

## The three commands

| Command | Does |
|---|---|
| `raqib service install [--no-start]` | As root only: checks that the code the unit would run is root's alone (below) and says how many paths of which kinds it checked. With no unit file it first asks systemctl whether systemd holds a unit of the name (LoadState, ActiveState, FragmentPath): one loaded from any place, or running, is not Raqib's to replace, and a systemctl that gives no answer is a refusal too. Then it writes the unit, runs `systemctl daemon-reload`, and asks systemctl how the unit is loaded (FragmentPath, DropInPaths, NeedDaemonReload): a unit not as installed is neither enabled nor started (exit 1, `RESULT: the unit is written; NOT AS INSTALLED, not started: ...`). Else it runs `systemctl enable --now raqib-watch.service` (over Raqib's own unit: `systemctl enable` and `systemctl restart`, so no watch keeps the old text), waits 3 s and asks systemctl whether the unit is active and still as installed. `--no-start` writes the unit, reloads and makes the same check after the reload; the unit is neither enabled nor started, and where a watch of Raqib's unit is running it says that watch keeps the text it started with. Exit 0 done (and, started, active and as installed after 3 s: `RESULT: installed, enabled, active 3 s after its start`), 1 the unit written but systemctl failed, or not as installed (then not started), or not active or not as installed after 3 s (said; left as it is), 2 refused (said, nothing written). |
| `raqib service remove [--purge]` | As root only: runs `systemctl disable --now raqib-watch.service` (stops and disables it), removes the unit's one file if it carries Raqib's mark, runs `systemctl daemon-reload`, and asks systemctl for the removed unit's ActiveState: where it is `failed` (a stop after a finding reads so, the watch's own exit 1), it runs `systemctl reset-failed raqib-watch.service` and says so; a reset that fails is said and the exit stays what it was. The record stays and its path is said. `--purge` removes `/var/lib/raqib` too, and only that folder. With no unit file it asks systemctl for the unit's LoadState and ActiveState: LoadState `not-found` with ActiveState `inactive` or `failed` is exit 0 (nothing installed, said); anything else, or no answer, is said and is exit 1, and nothing is touched and nothing purged. Exit 1 also when systemctl or a removal failed (said, left as it is), 2 refused (said, nothing touched). |
| `raqib service status` | Needs no rights: whether the unit is installed (the file with Raqib's mark), enabled and active, by systemctl's own words (`systemctl show`: UnitFileState, ActiveState, SubState), whether it is as installed (below), how many times it was restarted (NRestarts), and the unit's last result (Result, ExecMainStatus) when it is not active. With no unit file it asks systemctl too, and says a unit of the name that systemd holds (`RESULT: NOT INSTALLED BY RAQIB, YET A UNIT OF THE NAME IS ACTIVE`, or `IS LOADED`, exit 3). Exit 0 active as installed, 1 installed and not active, or active but not as installed (`RESULT: ACTIVE, NOT AS INSTALLED`), 3 not installed or not known (a unit file that cannot be read, no systemctl, or no state from it), 2 not Linux. On Windows `status` is the service manager's, with the same four answers (its own section, below). |

`install` and `remove` do nothing unless run as root, and say so; they ask for no elevation themselves (run
them with `sudo`). Off Linux every one of the three is exit 2, but `status` on Windows, which asks the
system's service manager with no rights (below: Windows: the status).

A systemctl that ran and gave no answer in its time is said as "no answer in N s" (what it was asked may still be
done); one that exited non-zero is said with its exit and what it said. Neither is said as not run. No line says
a thing was done before it was.

## As installed

"As installed" means all of these, by systemd's word and the file's: systemd loaded the unit from
`/etc/systemd/system/raqib-watch.service` (FragmentPath) with no drop-in (DropInPaths empty), and has not seen
the file change since it loaded it (NeedDaemonReload=no); and the file's whole text, read at most 16384 bytes
(UNIT_MAX; a longer file is not), is byte for byte the text this Raqib writes for the interpreter its ExecStart
names. A unit changed in place with its first line kept, a file changed and not reloaded, or a drop-in, is
`NOT AS INSTALLED`, and status is not exit 0: a change of the unit shows as a stop does.

What still does not show: a change of Raqib's own code by root, or by a user who is root by sudo or polkit,
after the install (the check is made when it installs); which interpreter the install named, since status takes
it from the file; and the drop-in folders, which are root's by default and are not walked: a drop-in that is
there shows by DropInPaths, a folder that would let a user add one is not checked.

## The unit

`/etc/systemd/system/raqib-watch.service`, root's, mode 0644. Its text is one constant in raqib/service.py.
Its one hole, `PYTHON`, is the whole path of the interpreter that ran the install. A path that holds anything
but letters, digits and `/._+-`, or that is not a plain whole path (an empty part, `.` or `..`), is refused,
never quoted (ADR-0013 A-7). Nothing else in the text comes from an argument, the environment or a file:

```ini
# raqib-service/1
# Raqib's watch of this host as a unit of the system's (ADR-0013). Written by `raqib service install`,
# removed by `raqib service remove`. A unit of this name whose first line is not the mark above is not Raqib's.

[Unit]
Description=Raqib: the watch of this host (raqib watch --host)

[Service]
Type=simple
ExecStart=PYTHON -I -m raqib watch --host --no-page --no-notify
Environment=HOME=/var/lib/raqib
StateDirectory=raqib
StateDirectoryMode=0700
Restart=always
RestartSec=5
KillSignal=SIGTERM
TimeoutStopSec=30
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
RestrictAddressFamilies=AF_UNIX AF_NETLINK
IPAddressDeny=any
CapabilityBoundingSet=CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
SystemCallFilter=@system-service
SystemCallArchitectures=native
UMask=0077

[Install]
WantedBy=multi-user.target
```

The first line is Raqib's mark. A unit of this name whose first line is not the mark is not Raqib's: install
and remove refuse it and leave it as it is, and status says it is not installed. A unit path that is a link is
not Raqib's either. Status reads the unit's head without waiting and only from what is a regular file when it is
opened.

The interpreter runs in Python's isolated mode (`-I`): it reads no PYTHON* variable and no user's site folder,
and the folder it starts in is not on its path. Its environment is systemd's, with HOME set to the service's
own home. The hardening is the set the Table's probe ran with (ADR-0013 A-6), narrowed as measured (ADR-0013
Amendment C):
- no new privileges;
- the system read-only and the homes read-only;
- private temporary files and devices;
- the kernel's tunables and modules, the control groups, the clock and the host name protected;
- no realtime, no set-id, no new namespaces;
- the address families unix and netlink alone, and every IP address denied: the watch serves no page and calls
  no network;
- the capabilities to read other users' processes and sockets (CAP_SYS_PTRACE, CAP_DAC_READ_SEARCH), and no
  others;
- the system calls of a service;
- `Restart=always`, 5 s after any end but systemctl's own stop, whatever the watch's exit.

## No page

The unit's watch runs with `--no-page`: it opens no listener and nothing listens on a port for it. A person's
own watch serves its page on the local host to every user of the machine; root's watch must not, because what it
sees (every user's trees and findings, and what /proc shows only root of other users' processes) is not every
user's to read. So no person and no agent reads root's view over a port, root parses no user's request, and there
is no port for anyone to take first. The record is root's alone (mode 0700). What the watch writes to its output
goes to the system's journal, which root and the groups the system gives the journal to can read; whoever reads
the journal reads the findings' lines the unit prints. What a person without rights reads of the service is
stage S3's to design.

## Who can stop it, and what a stop costs

The watched agent, running as a person without rights, cannot stop, restart or change a unit of the system's.
Root can, and root is also any user with sudo (a password it knows, none asked, or a ticket still valid) and any
user a polkit rule lets manage units: an agent running as such a user can stop it. A watch made to exit comes
back after 5 s, a gap each time; systemd counts the restarts (NRestarts) and `raqib service status` says the
count. A watch ended from outside (killed, not stopped) leaves its state unfinished, and a watch refuses to start
while that state's heartbeat is not older than its `stale_after_seconds` (30 s, read in the code): the unit's next
starts are refused and systemd starts it again every 5 s until one passes (read in the code, as ADR-0013 Amendment H
says; not measured on Linux). The watch that passes says the one before as a hole of its own run, `watch-unended`, and
a watch that finds a state it cannot read says `watch-state-unreadable` (both below under Windows): the gap is in the
record and in the events, not only in the journal. Such a watch's result is incomplete: a unit stopped after such a
start ends with 3, and the unit names no SuccessExitStatus, so systemd may read that stop as failed (said, not
measured; ADR-0013 Amendment I).
A watch's exit status 1 is its own ALARM at its end, or an error; the journal says which
(`journalctl -u raqib-watch.service`). A stop after a finding reads as `failed` to systemd, since the watch's own
exit is 1 then; this stays for S1, and `raqib service remove` clears it (`systemctl reset-failed`). A user who is
root by sudo or polkit can also change the unit or Raqib's code: a change of the unit shows in status (NOT AS
INSTALLED), a change of Raqib's own code does not.

## What install checks, and why

A unit of the system's runs as root what it is told to run. If that code is a file a user can write, the unit
gives that user the system. So before it writes anything, the install refuses (exit 2, nothing written;
ADR-0013 A-3, AB-3, Amendment C) where:
- the interpreter runs without its site (`-S`, `sys.flags.no_site`): what it would walk is not what the unit's
  interpreter loads;
- PYTHONHOME or PYTHONPLATLIBDIR is set and the interpreter reads its environment (`sys.flags.ignore_environment`
  is 0): they move the library the install would walk, and the unit's `-I` ignores them; unset them, or run the
  install with `-I` or `-E`;
- the raqib package's folder is not itself directly in one of that interpreter's own site folders
  (`site.getsitepackages()`): install raqib into this interpreter; a checkout run by `-m`, an editable install,
  or a copy deeper below a site folder is not it;
- a `.pth` file in a folder of sys.path holds a byte other than printable ASCII (0x20 to 0x7e), tab, LF and CR:
  the versions of site split and decode such a file differently, so it is refused, with its path, and not read
  into entries.

With those refused, the unit's `-I` only takes entries away from sys.path, so what the install walks holds all
the unit will load from by its path. Two things are outside that: the environment the unit's own `.pth` import
lines run in, which is the unit's and not the install's, and what such a line may add or reach that is not an
entry of sys.path (a finder that maps names to folders, for one); neither is walked.

Then it walks every path below from `/` down, as the system walks it. Each folder on the way and each path
itself must be owned by uid 0 and writable by neither its group nor others. The first path that is not is said,
with why, and the install is refused:

- the interpreter as it was started (sys.executable), walked to its end through every link;
- `pyvenv.cfg` beside the interpreter or one folder above it, where there is one (it says where a venv's code
  is);
- under every entry of sys.path, made whole against the folder the install runs in, every file and folder,
  whole: the standard library's files and folders, their compiled files, the extension modules, a
  `sitecustomize.py`, and every `*.pth` file;
- the lines of each `*.pth` file in those folders that are paths (not blank, not `#`, not `import`), each made
  whole against the file's folder, as entries too, existing or not; a `.pth` file is read as text only once it
  was found root's alone, and nothing is run (`-I` does not stop a `.pth` file's lines from running);
- every file and folder of the raqib package the install runs from;
- the systemctl it found, each of the watch's own ss paths, and the unit's folder, `/etc/systemd/system`.

A symbolic link is checked as itself, by its owner (a link's mode bits say nothing). Then what it points to is
checked whole, its folders too; where it points to a folder, that folder is walked whole as well, each real
folder once, so a loop of folder links walks nothing twice. A loop of links, or more than 40 links to follow for
one path, is a refusal, never a pass. A walk of more than 200000 entries is refused, and the number said: a walk
that is not whole is not a pass. A path that does not exist (an entry of sys.path, a `.pth` line, the end of a
link) is checked as far as it exists: the folders above it, so that no user can make it there by writing; it is
not otherwise a refusal. A missing path under a place the system makes for a user (a login's run folder, a
mounted medium, a new home) can become that user's when the system makes it, without the user writing in a
folder of root's. A path that cannot be read is a refusal.

The install says what it checked as counts: how many paths, of which kinds (folders, files, links), under how
many entries of sys.path, how many `.pth` files it read and how many of their lines were entries; a link among
them is checked by its owner, and then what it points to.

The install also refuses where:
- the platform is not Linux;
- the caller is not root;
- the interpreter's path holds a character outside `A-Za-z0-9/._+-`;
- no systemctl is at `/usr/bin/systemctl` or `/bin/systemctl` (it is never found by PATH);
- a unit of the name is there without Raqib's mark;
- there is no unit file, yet systemd holds a unit of the name: loaded from any place, or running (its
  FragmentPath is said), or systemctl gives no answer (ADR-0013 AD-1).

A raqib that a person installed for themselves (in their home, or a venv they own) is refused, by design. The
install that passes is root's own: a folder root makes for it, a venv in that folder (`python3 -m venv DIR`),
and `DIR/bin/pip install` run as root, then `sudo DIR/bin/raqib service install`. A venv in a folder a user can
write (on some machines `/opt` is one) is refused. Give pip a copy of the checkout that root made
(`sudo cp -r CHECKOUT DIR/src`, then `sudo DIR/bin/pip install DIR/src`), not the checkout itself: a build as
root leaves root's own `build/` folder in the folder it builds from, and the person's next install from that
checkout then fails (seen in the field, 2026-11-20: `Operation not permitted` under `build/lib`; the remedy
there is `sudo rm -rf build raqib.egg-info` in the checkout). `raqib watch` as a person runs it is unchanged and needs none
of this.

The check guards the unit's starts, not the install itself: an install run from code a user can write has
already run that code as root before it refuses. Not checked: the shared libraries the interpreter and its
extension modules load (libpython and the libraries they name); they are found by reading those files, not by
where they are.

The unit is written beside its place, then renamed over it, so a reader never sees half a unit.

## What the two capabilities still open

As the kernel's rules read, not as measured: CAP_SYS_PTRACE lets a defect in the watch reach other processes,
root's own included, and read and change their memory; CAP_DAC_READ_SEARCH lets it read every file and list
every folder, whatever their modes. The hardening narrows what such a defect does; it does not remove it.

## The helper of the process events

As every watch on Linux, the unit's watch starts the helper of the process events (ADR-0007 Amendments BU and BW;
docs/specs/PROC-EVENTS.md): a child of the unit's process that runs the reader of the kernel's process events and
answers the watch over its own input and output. The unit runs `-I`, so the helper is started with `-I` and the
unit's own import path. It runs under the unit's limits, which already let the reader hear (measured under them:
the two capabilities, AF_NETLINK allowed), and it is ended with the unit: it ends when its input ends, and systemd
ends the unit's processes at its stop. What it heard is counted in the watch's report, not judged. No run of the
rig reads the unit's own watch yet: the rig's X35 reads a user's watch, and whether the unit's watch heard is not
checked (M12.3).

## Where the record is

The service's home is `/var/lib/raqib`: systemd makes it root's, mode 0700 (StateDirectory; ADR-0013 A-5). Its
watch writes there as any watch writes in its home. The record and the events are in
`/var/lib/raqib/.raqib/host/`, and the events file is `/var/lib/raqib/.raqib/host/events.jsonl`. The service's
rules and overlay are there too. No user's `~/.raqib` is read by it, so an agent that turns a rule off in its
user's overlay turns nothing off in the service. `raqib service status` says whether the service runs, and root
reads the record. ACTIVE says the unit runs, not that the watch writes: a blind or a stuck watch is still
active, and reading what it writes is stage S3's.

## What removal leaves

`raqib service remove` stops and disables the unit, removes its one file (only with Raqib's mark), and reloads
systemd; where systemd then holds the removed unit as failed, it runs `systemctl reset-failed` for that unit alone
and says so, so that systemd lists no failed unit Raqib removed. It leaves the record: `/var/lib/raqib`, whose path
it says. `raqib service remove --purge` also removes `/var/lib/raqib` and nothing else. That path is a constant,
never an argument. It must be a real folder owned by root, not a link, and the removal does not follow a link out
of it: a link inside is removed as a link. A state path that is a link, or that is not `/var/lib/raqib`, is refused
before anything is touched. A systemctl that fails is said, and what it did not do is left as it is: the file of a
unit that could not be stopped is not removed.

## What it does not do yet

- It does not say which of the unit's directives the system's systemd ignored. On the rig's machine the rig
  says what systemd warned of and what the main process holds: it reads systemd's own word on the installed
  unit (its directives as `systemctl show` gives them, and the manager's journal lines that name the unit and
  say unknown, ignored, invalid or not support), any such line a finding, and the unit's main process's own
  word from /proc (its bounding set of capabilities, its seccomp mode and its no-new-privileges bit), MET only
  where they are the unit's (X29). That is not every directive in force.
- It installs no forwarder (S2) and gives a person without rights no view of the record (S3), and there is
  nothing for Windows (S4).
- It checks the paths when it installs, not afterwards: a later change that root makes to them is root's own.
- An agent in a network namespace of its own holds sockets the watch, in the host's namespace, may not see: not
  measured.
- The service's watch and a person's own watch do not know each other. Each writes its own record.

## Windows: the runner (`raqib service run`)

ADR-0013 Amendment E (AE-1, AE-3, AE-4), Amendment F (AF-1 to AF-4, which replace AE-2's closing of a folder that
exists), Amendment G (AG-1, AG-2) and Amendment T (T-1 to T-4: the check of its own code at every start). This is the
first part of S4: on Windows the host watch runs as a service of the system's, by the standard library alone (ctypes;
no new dependency), in raqib/winservice.py. Asking the state of the service is here (its own section, below; Amendment
V); installing and removing are not yet (M12.4c2b2b), and until they are, the line above that there is nothing for
Windows is true of `install` and `remove` only. Nine sources are named below and nothing else is called measured:
Amendment E (a candidate of 150 lines in the same shape, not this runner), Amendment F's field run of c125f62 (the
first builder's runner, as a real service), Amendment F's measurements (the calls this runner makes, by a probe),
Amendment G (this runner's own field run as a real service, f8af8f5, and two measurements more by a probe), Amendment
H (the candidate of Amendment E ended from outside, by the probe 02de365, as Amendment I records it), Amendment I's
field run of 8914d37 (the runner with the first build of the wait, before the review's changes, as a real service
ended from outside), Amendment J's field run of 054ef34 (this runner, the same way), the rig's own Windows job, which
ends the service at every run (X48), Amendment T's measurements (the check asked by the system's own account - a task
of the scheduler run as it - and the runner of 0.13.0 serving from two copies, by the probe 25a25a3; the service
manager's answers, by the probe b1ee4fb), and Amendment U's field run of a411eda (this runner asking the check at its
start, as a real service made from five trees and from one made large, by the probes 5bdfbd6 and f01da5c).

**The shape.** `raqib service run` is the command the system's service manager runs; nobody else. Its process hands
the system its service table (StartServiceCtrlDispatcherW) in a second thread, and runs the watch in the main thread
as it runs from a console, by Raqib's own entry with the Linux unit's arguments: `cli.main(["watch", "--host",
"--no-page", "--no-notify"], out)`. When the system calls the service's main, the runner registers its handler and
reports START_PENDING, with no control accepted. The main thread then makes the place ready and begins the text file,
then reports START_PENDING again, with a wait of 60 s, and asks the check of its own code (T-1, below); only then
does it report RUNNING and start the watch (AF-2). A refusal of the place, of the text file or of the check is STOPPED
straight from START_PENDING: no RUNNING is reported for it (Amendment F's measurements: a refusal reported from
START_PENDING makes the start command fail at once; reported from RUNNING, the command said ok, as the field run of
c125f62 showed). A Stop or a Shutdown from the system is reported as STOP_PENDING (with a hint of 30 s), and then
turned into the interrupt a person's Ctrl+C is (`signal.raise_signal(SIGINT)` from the handler); the watch ends, and
then STOPPED is reported. Nothing is reported after STOPPED. The interrupt is raised only while the watch's call runs:
a Stop that comes before it means the watch is not begun, and a Stop after it returned raises nothing; an interrupt
that still surfaces in the runner outside the watch's call is caught and said in the text file, and the watch's end is
still decided and still the text file's last line (AG-2). A second Stop, and every other control, changes nothing; a
control the runner could not act on is said in the text file (the runner's wrapper around the handler swallows every
exception, so that nothing comes out into the system's thread).

Run by anything but the service manager, the dispatcher fails at once with error 1063 (Amendment E): the runner says
so on its error stream (`not started by the service manager (error 1063)`), starts no watch and exits 2; so it does
where the dispatcher fails otherwise, where it does not answer in 25 s, and where the handler is not registered (then
no status can be told at all). Off Windows, `raqib service run` says in one line that it is Windows', with
`--no-start` or `--purge` given or not, and exits 2. Every call of the system goes through one object
(winservice.System) that a test replaces; ctypes is imported inside it, at its first call of Windows, never when the
module is imported, and no program is started.

**The place.** `Raqib` under the folder the environment of the service names `ProgramData`; where that name is
absent, or is not a whole path of a drive (a letter, a colon and a separator; no `..`; not a share), the runner
refuses. ProgramData, its drive and its parents are taken as the system gives them to its services: the
administrators', not checked (AF-4, Q8). The runner never sets an owner or a list on anything that exists (AF-1).
Absent, the place is made by the one call that gives it the closed list as it is made (CreateDirectoryW with a
security descriptor, from the text `D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`: the system and the administrators,
whole, for the folder and everything in it, nothing inherited from above). "It already exists" from that call
(error 183) is the road of a place that is there, not an error. Made or found, the place is then read through ONE
handle on the name itself (CreateFileW with the flag that opens a reparse point and does not follow it): its
kind, its owner and its list come from that one handle, and it is taken only where that one read says so:

| The one read says | The runner |
|---|---|
| a reparse point (a junction, a link) | refuses (11); it is left as it is |
| not a folder | refuses (12); it is left as it is |
| an owner neither the system (SY) nor the administrators (BA) | refuses (13); it is left as it is |
| a list other than `D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`, whatever the folder holds or does not hold - the same list set on a folder that existed, `D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`, among them (AG-1) | refuses (14); it is left as it is |
| a folder, no reparse point, owned by SY or BA, its list `D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)` | takes it; what is in it is not touched |

The closed list is taken in one form only (AG-1): `D:P...`, as the system writes it for a folder made with it. The
same list set on a folder that existed reads back `D:PAI...` (Amendments E and F) and is refused: such a folder was
open once, and what was put in it then keeps its own owner. Amendment G's measurements: a plain user's file left in a
folder closed afterwards kept him as its owner; his reading it by its whole path, his giving the users the file again
with the system's own tool, and his writing to it were each refused - a call that asks only for an owner's right to
change his file's list was not tried, so nothing rests on those refusals. A list closed in meaning but written
otherwise is refused, by the letter. A place that is refused is refused again at every start, for nothing in it was
changed; an administrator removes it. A place is taken only as the making call leaves one, closed from its first
moment, so what is in a taken place was put there by the system or the administrators (AG-1). The making call does not
follow a link at the name: Amendment G's measurements found that at a junction and at a link, its target there or
absent, and at a file, it answered error 183 and made nothing where they point. A handle is not held to keep the
place: Amendment F's measurements found that a handle with the right to read the list alone holds nothing (its maker
renamed a folder while it was held); what keeps a taken place's name is its own list and owner (Amendment F's
measurements: a plain user's write, listing, renaming and removal of a folder so made were each refused). Only then
are the process's `HOME` and `USERPROFILE` the place, as the Linux unit's HOME is its state directory, so the watch's
whole record is written under it. One folder is made, the place; the runner itself reads two names: the place's, and
the state of the watch before inside it (through raqib/host.py's `holder()`, which writes nothing; AH-2, Amendment I);
the check of its own code (T-1, below) reads the names of the code this process runs, and writes nothing.

**The check of its own code (Amendment T, T-1 to T-4; M12.4c2b1).** `raqib service run` runs, as the system, whatever
tree it was started from; `raqib service check` says whether a tree is the system's alone, but only to the session
that asks it. So at every start, after the place is taken and its text file begun and before RUNNING, the runner asks
the check itself: the same function of raqib/wincode.py, on the same road (packed or plain) and with nothing skipped,
through one method of the system's object (`winservice.System.own_check`, which imports raqib/wincode.py at its call
and hands it the check's own system object), by the very account and session that will run the watch - so the drive's
letter, the paths and the lists are read as the service reads them. The order of a start is: START_PENDING (a wait of
5 s); the place made or found and read; the text file begun and its first line (the place); START_PENDING again with a
wait of 60 s (`CHECK_WAIT_HINT`, T-2); the check; RUNNING; the wait for the watch before (AH-2, below); the watch. The
check's seconds are read on the system's object's clock (monotonic), and its line in the text file says them. Taken,
that one line is the pass's own sentence, as `raqib service check` prints it, and the road goes on: "raqib service
run: its own code, checked at this start by this process (ADR-0013 T-1), in 0.31 s: raqib service check: the code a
service would run is the system's alone: checked N names, ..." (with the drives it asked). A start that passes is
otherwise line for line as before. Not taken, for any reason the check has - a name not the system's alone, with its
role; a drive that is not a disk's volume; a plain interpreter not started with `-I`; a packed runtime it does not
walk; not Windows - the line holds the whole refusal, as that command prints it ("...: raqib service check: NOT the
system's alone: NAME, WORDS; no watch is begun; the system is told the service's own exit 536870927 (0x2000000F:
...)"); an answer of a form the runner does not know, and an exception out of the check (its trace first), are refused
the same way with their own words and "what was not read is never the system's". Each part of the answer is made
printable and cut at 4000 characters, the cut marked "...". Then no watch is begun, the wait for the watch before is
not entered, and the system is told the service's own number 15 (0x2000000F), from START_PENDING: the start command
fails at once and the system's log says the number. A Stop that comes during the check is obeyed after it: where the
check passed, no watch is begun and the system is told 0 (AF-4's line, "it was not begun"); where it refused, 15. A
Stop that came before it does not skip it, and no START_PENDING is told after its STOP_PENDING. On the machines
measured no Stop reaches the runner then - the system refuses it to its caller (below) - and the road is kept for a
system that delivers one.

The wait of 60 s (T-2, U-2): Amendment T measured the check asked by the system's own account (a task of the scheduler
run as it; x64 and ARM64, the probe branch 25a25a3): about 150 names in 0.2 to 0.3 s packed and about 10000 in 1.1 to
1.9 s for a plain interpreter, its answers word for word the ones the user who asked got. Amendment U measured this
runner as a real service (the probe branch 5bdfbd6, of a411eda; x64 and ARM64): its line of the check said 0.02 to
0.03 s for the packed copy and 0.6 to 1.7 s for the copied Python; over that copy made large with 150000 empty files
(about 161000 names) it said 9.8 s on x64 and 31.7 s on ARM64, and the service then said RUNNING and watched - the
second START_PENDING told with its check-point left at 0 and the wait of 60 s; and with more files than the check's
bound of 200000 names (WALK_MAX) it was refused after 40.7 s on ARM64, with the number 15. So on the slower machine
measured a tree at the bound takes about two thirds of the wait told; a slower disk is not measured. While the check
walked, the system said of the service START_PENDING with its check-point 0 and the wait of 60 s; a Stop sent then was
refused to its caller (the system's error 1052, "The requested control is not valid for this service") and never
reached the runner - so the service is not stopped through the manager while its check walks, for as long as the walk
takes, which the check's bound bounds; a start command that waits on the state (`Start-Service`) waited the 10 s and
the 32 s and took the start; one that waits for the check-point to move (`net start`) took the start of 10 s and, of
the one of 32 s, said after about 20 s that the service could not be started, while the service went on to RUNNING
(the probe branch f01da5c). The runner does not raise its check-point while the check walks: a task of its own (U-4).
Said (T-4): a service of Windows made by hand from a tree a user may change, which watched until now, stops watching
with this version and says why - in its text file and, by its number, in the system's log (measured: event 7024 of the
Service Control Manager, "terminated with the following service-specific error: %%536870927"). The check at the start
is a reading at that moment: a tree changed while the service runs is not seen until the next start (a watch of its
own tree is another task). What the check at the start does not give, and is said: the code that asks it has already
run as the system by then - the interpreter, its site and the `import` lines of its *.pth files, and Raqib's own
modules up to the runner (N-2), or the packed program and its runtime - so a tree a user may change is refused before
it watches, not before it runs - and, as for the command (N-2), it is a reading of the tree as its own code tells it:
a tree a user already changed may make its own check pass, and is then watched; only a service that is not made from
such a tree (the install's refusal, M12.4c2b2) keeps it from running as the system. The system told to start the
service again after its number 15 is the install's too (M12.4c2b2).

**The text file.** A service has no standard streams (each is None; Amendment E). The runner gives the watch a
text file in the place, `service.txt`, for its report and its errors. It is begun anew at each start; the one
before is kept once, as `service.before.txt` (the field run of c125f62 read it so). It holds at most 8388608 bytes
(8 MiB, its last line included): past that bound nothing more is written to it and its last line says so, once.
A write that fails ends it the same way, with one last line saying a write failed where that line can still be
written, and the runner keeps that it happened: where the system would be told exit 0, it is told 18. The
watch's record goes on in either case. The standard output and error streams, where they are None, are the text
file for the whole process; the standard input stays None. The runner's own lines in it begin
`raqib service run:`: the place, the road it took ("made" or "found") and its owner and list first; then the
check of its own code (T-1); how the watch ended and what the system is told last. A line the runner had to say before the text file was begun (a
status the system did not take) is written in it once it is begun.

**The exits.** Each number of the service's own is `0x20000000 + n`, the range the system leaves to applications
(AF-3), told with STOPPED as the system's service-specific exit (ERROR_SERVICE_SPECIFIC_ERROR, 1066). A watch's
result after a Stop (0 clean, 1 an alarm, 3 incomplete) is no failure of the service: the system is told exit 0,
and the result is in the text file. A Stop that came before the watch gave any result (the watch not begun, or
ended by its interrupt with no result) is told 0 too, and the text file says in one line that the watch was
stopped before it gave a report; the unfinished state such a watch may leave is said by the next watch as a
hole (AH-1, below). Each refusal, a watch
that ended without being asked, an exception out of the watch and one of the runner's own has a number of its
own (the runner's own exception: its trace in the text file where one is begun, its words on the error stream
otherwise):

| n | Number | Hexadecimal | Words |
|---|---|---|---|
| 10 | 536870922 | 0x2000000A | ProgramData is not in the environment, or is not a whole path of a drive |
| 11 | 536870923 | 0x2000000B | the place is a reparse point (a junction or a link) |
| 12 | 536870924 | 0x2000000C | the place is there and is not a folder |
| 13 | 536870925 | 0x2000000D | the place's owner is neither the system (SY) nor the administrators (BA) |
| 14 | 536870926 | 0x2000000E | the place's list is not the closed one, whatever it holds |
| 15 | 536870927 | 0x2000000F | the code it runs is not the system's alone: its own check at this start refused it, or gave no answer it reads |
| 16 | 536870928 | 0x20000010 | the text file could not be begun in the place |
| 17 | 536870929 | 0x20000011 | the place could not be made, or could not be read through one handle on its name |
| 18 | 536870930 | 0x20000012 | a write to the text file failed and ended it (the watch's record went on) |
| 20 | 536870932 | 0x20000014 | the watch refused to start (its result 2) |
| 21 | 536870933 | 0x20000015 | the watch ended without being asked (no Stop or Shutdown came), or with no result of its own |
| 22 | 536870934 | 0x20000016 | an exception came out of the watch |
| 23 | 536870935 | 0x20000017 | an exception of the runner's own (not the watch's) |

15 is the check of its own code (T-1); before Amendment T it was not used (the closing it once named is gone). A
refusal of the check is said in the text file, which is begun by then. The process itself exits 0 where the system was told exit 0, and 2
otherwise. A refusal of the place or of the text file is said on the error stream, and in a service that stream
is None: the words are lost, and the refusal's only trace is its number in the service's state and the system's
log.

**What was measured, and by what.** Amendment E (the candidate, not this runner; GitHub's Windows machines, x64 and
ARM64, Python 3.12, Raqib plain and packed by PyInstaller 6.11.1): the system started it in 0.56 to 0.71 s plain and
0.08 to 0.09 s packed; a Stop took 0.25 to 0.27 s, the watch ending 0.01 to 0.03 s after the control with its final
report and code 0; as a service the process was the system's own account in session 0, its folder System32, its three
standard streams None; with no service manager the dispatcher failed at once with error 1063; with HOME and
USERPROFILE a folder under ProgramData, the watch's whole record was written there; a folder ProgramData makes is open
to every user; a list set as `D:PAI...` on a folder read back so, and a plain user was then refused; a folder a plain
user made first is his, and he opened it again after it was closed; his Stop of the service and his ending its process
were refused. Amendment F's field run of c125f62 (the first builder's runner, which reported RUNNING first and closed
an open empty place; the same machines, plain and packed): run by hand it refused with its line, exit 2; the place
absent, it was made owned by the administrators with the closed list, the watch ran, a Stop took 0.26 s with the final
report, the state Stopped with exit 0; a plain user's write, read, listing, Stop and ending of its process were each
refused; started again, the text before was kept once; a place a plain user made first was refused with 13 and left
untouched, an open one with a file in it refused with 14, a junction refused with 11 with nothing written where it
points; the system's log gave each of those numbers the system's own words for it, and the start command said it
succeeded for a service that then refused. Amendment F's measurements (a probe, the same machines): a folder made by
CreateDirectoryW with the closed list, as an administrator and as the system's own account in a service, read back
owned by the administrators with `D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`, and made again, error 183; read through one
handle on the name itself, a folder, a junction and a link to a folder (each a folder that is a reparse point), a
file, and an absent name (error 2); a refusal from START_PENDING fails the start command at once; a number of 14 is
written in the system's log with the system's words for 14, and 0x20000000 + 14 as itself (`%%536870926`). Amendment
G's field run (this runner, f8af8f5, the same machines, plain and packed; its tests passing on real Windows): run by
hand it refused with its line, exit 2, and made nothing; the place absent, it was made owned by the administrators
with `D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`, the watch ran, a Stop took 0.26 s with the final report and the run's
chain whole, the state Stopped with exit 0; a plain user's write, read, listing, Stop and ending of its process were
each refused; started again on its own place, the text before was kept once; a place a plain user made first, an
administrator's open place with a file in it and without one, a junction and a link at the place's name, and a file
there: each refused with its number (13, 14, 14, 11, 11, 12), the start command failing at once, the system's log
saying the number itself (`%%536870925` and so on), and each left exactly as it was, twice in a row for the first.
Amendment G's measurements (a probe): the making call at a junction, a link and a file, as said above; a plain user's
file inside a folder closed afterwards, as said above; and the same administrator's process making a folder owned by
the administrators when started from PowerShell and owned by the user himself when started from Git's bash - the
service is started by the system, and the folder it made was the administrators' in every run.

**The watch before (AH-1, AH-2, Amendment I; M12.4b).** A service ended from outside (its process killed) leaves the
watch's state unfinished, and a watch refuses such a state until its heartbeat is older than the state's own
`stale_after_seconds` (30 s): read in the code, by the heartbeat alone, not measured (Amendment H). Amendment H
records the probe branch 02de365 (GitHub's Windows machines, x64 and ARM64), which ran the candidate of Amendment E,
not this runner (Amendment I): with the system told to start the service again after 2 s, the system said so (event
7031) and started it, the new watch refused ("another raqib watch --host is watching this home (run ..., pid ...,
heartbeat 3 s ago): one host watch per home; stop it first"), ended with 2, and the service read Stopped and was not
started again. Amendment I records what the runner of 8914d37 did, before the review's changes, in its field run (the
probe branch 241e04f; the same machines; `raqib service run` as a real service, the system told to start it again
after 5 s, its process ended from outside): the system said the end (event 7031) and started the service; the runner's
text said the state still held the place ("heartbeat 5 s ago, stale after 30 s ... waiting up to 25.6 s") and waited;
the watch read its first round 31 to 32 s after the end; the place's events held two runs, each chain whole, the later
with the hole `watch-unended` naming the earlier, which had no end; the rig's own check read X48 MET from what was
kept (X48 as it then was, without the tie to the pids); after a Stop and one more start, no second such hole.
Amendment J records the field run of 054ef34 - this runner, with every change below but Amendment J's own words (the
probe branch 607b75c; the same machines): the text file said the wait before it and after it ("lasted 25.1 s and
ended: stale"), the watch said the hole `watch-unended` at its start in the words below and the events held it, the
first round was read 31 s after the end, X48 read MET with the pids tied, and after a Stop and one more start there
was no second such hole. Not run on a real machine: the hole of a state that cannot be read; a start ended before its
first round.

`holder()`, one function of raqib/host.py, reads whether another host watch holds a home: nothing held (no state, a
finished state, an object that is no host watch's state); a state that cannot be read (there, and an open refused, not
ASCII, not JSON - empty or torn - or a JSON that is no object); held and fresh; unfinished and stale; a heartbeat that
cannot be parsed. It writes nothing; it raises only what the JSON parser raises past its own errors (a state nested
past the parser's limit) and what its clock raises. The watch's own refusal (D-6, unchanged, in the same words) and
the runner rest on it.

Two holes of the watch's own run, on every system, said once at its start with the start's other `hole:` lines, in the
final report, in the state's holes and in the events; the result is then not clean (exit 3 where nothing else makes it
1). `watch-unended`, over an unfinished state whose heartbeat is stale: "the host watch before this one, run RUN (pid
PID), left its state PATH unfinished with its heartbeat stale: its last heartbeat HEARTBEAT, N s before this start; a
watch that ended without its end (ended from outside, a crash or a power loss) or one that stopped writing its state:
for those N s no watch of this home is known to have watched". RUN, PID and HEARTBEAT are made printable and cut to 40
characters (`HELD_SAID_MAX`; a cut one ends with "..."). N is the whole seconds of the age the refusal's own reading
took (`holder()` at the watch's refusal, after the start's clock read and its check of Sysmon, not at the start's
instant), as the wall clock reads them. A heartbeat ahead of that clock (a state whose own staleness is negative or
NaN) is said "its last heartbeat HEARTBEAT, S s ahead of this start's clock; ...: how long no watch of this home
watched is not known", S in six significant digits (`%g`) and never 0. `watch-state-unreadable`, over a state there
that cannot be read: "the state PATH is there and cannot be read as a state (WHY): whether the host watch before this
one ended without its end, and how long no watch of this home watched, is not known; this watch starts over it", WHY
the error's kind with its words cut to 80 characters, or what JSON value the file holds where it is no object (an
array, null, a number, a string); the watch starts as before. None where there was no state (a first watch is no gap),
where the state was finished or no host watch's, or where the watch is refused.

When the hole is written (AI-1): before the watch's own state is first written (by its registration, at its start,
over the state that named the run before), the watch's start line and the holes of its start so far are written to the
events file, lines of this run's chain as any other; a later pass finds them said and writes them no more. Read in the
code and held by a test, not run on a real machine: a watch ended again in its first seconds still leaves the earlier
gap in the events - unless that early write itself fails (a full disk, an events file refused): the watch then starts,
says the failure as a hole of its own (`events-unwritable`) in its state and its final report, and the earlier gap is
in no record that lasts if this watch too is ended in its first seconds (AJ-2). A start that said the watch before and
then fails before it writes any state (the page's port refused; not the service's road, which serves no page) leaves
its start line and the hole in the events with no end, and the state still naming the run before: the next watch says
the run before again - two holes for one gap, each true to what its run found (AJ-1). This early write is made only on
a start that found such a state; every other start's events begin at its first tick, as before.

The runner (AH-2, AI-4): after RUNNING and before the watch, the runner asks `holder()` of the place; where another
watch's state still holds it, fresh, one line of the text file says the run, the pid, the heartbeat's age as read and
how long it will wait ("another host watch's state still holds the place (run ..., pid ..., heartbeat 4 s ago, stale
after 30 s): it was ended without its end, or it still watches; waiting up to 27.0 s for it to go stale, asked again
every 1 s, then the watch"; a heartbeat ahead of the clock: "heartbeat S s ahead of this clock"). It waits the state's
own staleness less its age, plus one second, never more than 60 s whatever numbers the state holds (a staleness too
large for a float, or infinite, waits the 60 s; a boolean or a text as the staleness is read by `holder()` as 30, and
a NaN makes the state stale, so there is no wait; a number said in the line is cut to 40 characters and the cut is
marked), asking again every second, the last pause the part of a second left, on the system's waiting clock
(monotonic), never the wall clock. One line after it: "the wait for the state of the watch before lasted T s and
ended: HOW", HOW stale, finished, gone (the state removed: the watch before's end is then not known), the state cannot
be read, its heartbeat cannot be parsed, no longer held (the state is no host watch's), still fresh after the whole
wait, or a Stop. Then it starts the watch, which says AH-1's hole. The service reads RUNNING while it waits (AF-2's
order kept). A Stop during the wait ends it at once: no watch is begun, the system is told 0, and the text file has
AF-4's line ("the watch was stopped before it gave a report (it was not begun)"). A state still fresh after the wait
is a living watch: the watch is started and its own refusal stands (20). An exception out of `held` (a state nested
past the parser's limit) is the runner's own (23). Not held, stale, a state that cannot be read, or a heartbeat that
cannot be parsed: no wait and no line. A heartbeat that cannot be parsed gets no wait (AI-6): the watch refuses it
(20), and the service stays stopped until an administrator acts (removes that file once no host watch runs, as the
refusal says). The wait goes through the system's object (winservice.System: `held`, `clock`, `pause`); the runner's
tests use a stand-in's clocks (its wall clock and its waiting clock two values where a test sets them) and no real
second. X48 (`tools/rig/check.py --service-run RUNFILE --service-events EVENTSFILE`, AI-5): MET only where the RUNFILE
says Running, an again-pid above 0 that is not killed-pid and an again-seconds from 0 to 90, and the place's events
hold the hole `watch-unended` of a later run whose id ends with "-" and again-pid, naming an earlier run with no end
and the pid killed-pid; a byte-order mark before the first key is read past. The rig's Windows job makes the service,
ends its process once and keeps the two files (tools/rig/service_again.ps1).

**What was not measured.** A place whose list is closed in meaning but written otherwise (refused, by the letter); a
place on a volume that keeps no owners; an owner written as a whole SID and not as SY or BA (refused with 13, by the
letter); a RUNNING the system does not take (the service would stay START_PENDING for the watch's life, said only in
the text file); where the Stop's interrupt surfaces after the watch's call on a real machine; a call by a file's owner
that asks only for the right to change its list, inside a folder closed after he put it there; reparse points of other
kinds than a junction and a link; the runner under Python 3.11 as a service; a Stop that comes while the watch is
still starting (it may end with no final report and an unfinished state, which the next watch says as a hole; nothing
else is built for it); a watch that ignores its interrupt (not built); a shutdown of the machine (the control was not
sent); a service's start at boot; a start that outlasts the wait it told (one of 32 s under a wait of 60 s was taken);
another account than the system's; a place on another volume, or one with a file held open by another process; Windows
before the runners' versions. Of the watch before (Amendment H): a power loss; a machine's shutdown without a Stop; a
clock set back between the heartbeat and the start (the seconds said are then wrong, and said as read); what a power
loss leaves of the state on NTFS or ext4 (AI-2); the Linux unit's exit 3 after such a start, as systemd reads it; the
hole of a state that cannot be read, and the early write on a start ended before its first round, on a real machine; a
state removed before a start - the watch before is then said nowhere, also where an administrator removes it as the
unparsed refusal advises; an object at the state's path that is no host watch's (taken as nothing held, said nowhere);
a state with a negative or NaN staleness written by a living watch (said as one that ended or stopped writing); taking
over at once where the process the state names is gone (recorded, not ruled). Of the check at the start (Amendments T
and U): a disk slower than the two machines measured, on which a tree near WALK_MAX may outlast the wait told; a
machine joined to a domain, or one whose Program Files an administrator's policy lists otherwise; a tree changed
between the check and the watch's own imports. The install, its start at boot, the system told to start it again, and
the event log are M12.4c2b2's.

X52 (`tools/rig/check.py --service-refused FILE`, T-3; the job's wiring is the Table's): FILE holds lines `key: value`
of two services made to run `raqib service run` - `refused-exit`, `refused-own` and `refused-text` of the one made from
the job's own Python, a tree a user may write (its exit as the system gives it, its own number, and its text file's
line of the check), `taken-state` and `taken-text` of the one made from a Python copied under Program Files, one
folder deeper, started with `-I`. MET only where the first did not run - `refused-exit` 1066 (the exit is the
service's own number), `refused-own` 15 as the system gives it (0x2000000F, or 536870927), `refused-text` holding "NOT
the system's alone" and a path of a drive - and the second ran: `taken-state` Running, `taken-text` holding the
pass's sentence with its counts. A byte-order mark before the first key is read past; MISSED with words for each thing
not found, a file given and missing included; n/a where none was given.

## Windows: the status (`raqib service status`)

ADR-0013 Amendments V (V-2 to V-5) and W, in raqib/winmanager.py. On Windows `raqib service status` asks the system's
service manager, by its own calls and with no rights, about the service named RaqibWatch, and changes nothing. What it
rests on was measured before it was ruled (Amendment T's first paragraph and Amendment V's, the probe b1ee4fb; x64 and
ARM64, the same): a caller with no rights may connect to the service manager and open a service to ask its state and
its making, and reads them - the state with the process's id, the system's exit and the service's own; the type, the
start, the account and the command (a first ask with no room answers error 122 and the bytes needed); and its
description, as it was set. A name that is not there answers error 1060; a service never started reads state 1 with
the exit 1077; such a caller is refused (error 5) the start, the stop, the removal and the change. Not measured, and
so not read: the delayed start, the failure actions and the failure flag as a caller with no rights reads them; a
service marked for removal as such a caller sees it. This command itself was asked on real machines after it was built
(Amendment W; the probe branch 23d544f, of 152fc91; x64 and ARM64, the same): by an administrator and by a user the
probe made outside the administrators' group, at ten moments - no service of the name; one made without the mark; with
the mark and never started; running; stopped by a Stop; its start set to automatic; its account set to another than
the system's; one refused at its start with 15; one whose command lacks `-I`; one whose description only begins like
the mark - and the two askers were answered the same lines and the same exit at each. The account of a service made
with none named read `LocalSystem`; a service with no description read as having none. Not measured: a service that is
starting, stopping or paused as status reads it; a service marked for removal; a machine joined to a domain. The rig
reads the command at every run (X53, below).

**Raqib's service.** The one named RaqibWatch whose description begins with `raqib-service/1` - the mark the Linux
unit carries in its first line - the mark ending there or at a space. A service of the name without the mark is said
as not Raqib's; nothing else is read as Raqib's. Raqib's install on Windows is not built yet: until it is, a service
status calls Raqib's is one an administrator made with the mark, as the rig's job does.

**What it reads and says.** The calls, in this order, each opened with the least rights measured: OpenSCManagerW (to
connect, 0x1), OpenServiceW (to ask the state and the making, 0x5), QueryServiceConfig2W at level 1 (the description),
QueryServiceConfigW (the making), QueryServiceStatusEx (the state, at its one level), and CloseServiceHandle for each
handle opened, the service's before the manager's, on every road. The description and the making are each asked twice:
first with no room, which must answer error 122 and the bytes it needs, from the structure's own size to 8192 (the
most QueryServiceConfigW documents), then with those bytes. One line each: whether the name is there; the mark; the
command as the manager holds it, and whether it is, whole, one of the two forms Raqib's install writes - a quoted
path, then `service run` (a packed program's), or a quoted path, then `-I -m raqib service run` (a plain
interpreter's) - with the path it names; the type (0x10, a process of its own); the start by its number and word; the
account (`LocalSystem`, the system's, read without regard to case); the state by its number and word (1 stopped, 2
starting, 3 stopping, 4 running, 5 continuing, 6 pausing, 7 paused), with the process's id; and, where it is not
running, the exit the system holds: 1077 as never started, 1066 with the service's own number - in the runner's own
words where the service carries the mark (its list above; for 15, that what was refused is in `service.txt` in the
place), and as the bare number where it does not (W-2: a service without the mark is not read as Raqib's runner) - 0
as stopped with no failure of a stopped service and as the bare number in any other state, any other as the system's
number. A service with the mark that is starting is said so, with the reason a start may be long (the check of its own
code, T-2, and the wait of 60 s it tells the system). A text read from the manager (the description, the command, the
account) is written as printable ASCII - a character that is not printable as `?`, a printable one outside ASCII as
its number (`\uXXXX`), so that a letter of another script that reads as a Latin one is seen for what it is (W-3) - and
cut at 300 characters, the cut marked. Nothing is said that was not read; a call that fails is said with the call and
the system's number (error 5 says the caller may not ask), and nothing is asked after it but the closes.

| Answer | Exit | Where |
|---|---|---|
| `RESULT: ACTIVE` | 0 | Raqib's, running and as installed: the mark, the command's form, a process of its own, the system's account. ACTIVE says the service runs, not that the watch writes its record. |
| `RESULT: INSTALLED, NOT ACTIVE` | 1 | Raqib's, in any other state, said by its word; `, NOT AS INSTALLED` is added where it is not, each difference said. |
| `RESULT: ACTIVE, NOT AS INSTALLED` | 1 | Raqib's, running and not as installed, each difference said. |
| `RESULT: NOT INSTALLED` | 3 | No service of the name (error 1060). |
| `RESULT: NOT INSTALLED BY RAQIB, YET A SERVICE OF THE NAME IS <its state>` | 3 | A service of the name without the mark. |
| `RESULT: NOT KNOWN` | 3 | A call failed, a close included, or an answer of a shape it does not read. |
| one line, nothing asked | 2 | Not Windows (raqib/winmanager.py's own answer; on Linux `raqib service status` is the Linux command, as before). |

`--no-start` and `--purge` with `status` are refused on Windows as on Linux (exit 2); `install` and `remove` on
Windows answer as before (exit 2, Linux only).

**What it does not do.** It writes nothing to the manager and nothing anywhere: no service is made, started, stopped,
changed or removed; no file is written by it (the interpreter may write its own cache of the modules the command
imports, where their folder lets the asker), no registry read, no program started; one library is loaded, advapi32, by
its name, every call's argument and result types declared. It does not read the delayed start, the failure actions or
the failure flag, the place's own list, or whether the code the command names is the system's alone (the check's to
say: `raqib service check`, and the runner's check at every start). Every call goes through one object
(winmanager.System); the tests hand a stand-in, and one runs the real object's own logic - the two asks, the cast, the
texts read - against a made-up library, so none needs Windows; the real calls are run only on Windows, by the rig at
every run.

X53 (`tools/rig/check.py --service-status FILE`, V-5, W-6; tools/rig/service_status.ps1): FILE holds lines `key:
value` of status asked by a user the job makes outside the administrators' group (`asked-by-administrator: no`) at
three moments - `none-exit` and `none-result` with no service of the name; `active-exit`, `active-result` and
`active-command` of the job's service made with the mark from the copy under Program Files and running;
`refused-exit`, `refused-result` and `refused-words` of one made with the mark from the job's own Python, refused at
its start. MET only where the asker was no administrator; the first is exit 3 and `RESULT: NOT INSTALLED`; the second
exit 0, `RESULT: ACTIVE`, and status's own line of the command, a quoted path under Program Files and then `-I -m
raqib service run`; the third exit 1, a result beginning `RESULT: INSTALLED, NOT ACTIVE`, and words holding status's
own line of the exit with the runner's words for 15, and `service.txt`. A byte-order mark before the first key is read
past; MISSED with words for each thing not found, a file given and missing included; n/a where none was given.

## Windows: the check (`raqib service check`)

ADR-0013 Amendments K (K-1 to K-7), L, M (M-1 to M-5) and N (N-1 to N-3), in raqib/wincode.py. A service of Windows
runs as the system what its command names, so before anything installs one (installing and removing are not built yet:
M12.4c2b2b) Raqib says whether that code is the system's alone: whether anybody but the system could change it, add to
it or take from it. It judges by the owners and access lists Windows gives, read through the runner's one reader (one
handle on the name itself, a link not followed: its kind, its owner and its list; K-7,
`winservice.System.read_place`), and by nothing else. It changes nothing and asks for no right, and the check itself
writes nothing; on the plain road the interpreter that runs it may write bytecode caches beside what it imports, where
the asker may write there (N-2). A plain user asked it and got the administrator's answer, word for word (Amendment L,
measured): ask it first as a plain user, who needs no rights for it.

**The system's three names (K-1).** The system (`SY`, `S-1-5-18`), the administrators (`BA`, `S-1-5-32-544`), and the
system's installer (TrustedInstaller) by its whole SID only,
`S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464`; no other. An administrator's own account, a
domain's group, any other service's name: not the system. The creator's name (`CO`, `S-1-3-0`) is not one of them.

**How a text is read.** The system's text of an owner and list - `O:` the owner, `D:` the list, its flags (P, AI,
AR), then its entries `(kind;flags;rights;object;inherited object;name)` - is read whole, or it is refused. An
entry's flags are two-letter words (OI, CI, NP, IO, ID; IO is inherit-only), its rights hex (`0x1301bf`) or
two-letter words run together (`SDGXGWGR`), its name two letters or a whole SID; the same two letters are read by
their place. The rights words are the file system's: CC 0x1, DC 0x2, LC 0x4, SW 0x8, RP 0x10, WP 0x20, DT 0x40, LO
0x80, CR 0x100, SD 0x10000, RC 0x20000, WD 0x40000, WO 0x80000, GA 0x10000000, GX 0x20000000, GW 0x40000000, GR
0x80000000, FA 0x1f01ff, FR 0x120089, FW 0x120116, FX 0x1200a0. Not read, and so refused, with the entry said: no
owner; no list; a null list (`NO_ACCESS_CONTROL`); anything after the list; an entry of a kind other than allowing
(A) and denying (D); one with more or fewer than its six fields; one whose object or inherited-object field is not
empty; a flag or a rights word this Raqib does not know; a name of neither form.

| Role | Taken only where it is | And every allowing entry for a name outside the three holds nothing but |
|---|---|---|
| the code itself (K-2): each root of the road and every file and folder below it, whole - packed, the program's folder; on the plain road each root of M-2 and each of N-1's three names that is there - and, for an entry of the path or one of those names that is not there, the deepest folder of it that is there, itself only (M-3) | no reparse point; owned by one of the three; its list there | reading and executing: 0x1, 0x8, 0x20, 0x80, 0x20000, 0x100000, GR, GX - its inherit-only entries too (what the folder would give to what is made in it later is judged now), but for the creator's own, taken only where it is inherit-only |
| a folder above (K-3, L-1): each folder above a root, up to the drive's own; a root itself is judged as code | a folder and no reparse point; owned by one of the three; its list there | K-2's bits and adding a thing beside: add a file 0x2, add a folder 0x4, and no other bit - in each entry that is not inherit-only (inherit-only entries are not read here: what a folder on the way gives to new things beside the code is not the code) |

Denying entries give nothing and are not counted. These are lists of what is allowed, not of what is refused: a bit on
neither list refuses. So nobody but the system may delete or rename what a folder above holds (0x40), delete or rename
the folder (0x10000), or change its list or its owner (0x40000, 0x80000, GA); GW is refused too, not measured. Writing
a folder's own extended attributes or attributes (0x10, 0x100) refuses as well: Amendment K allowed the two above,
nothing measured what they give, and Amendment L-1 took them out - so `C:\ProgramData`, which gives users both, is
refused as a folder above. Adding a thing beside does not replace what is there: that is what lets `C:\` and Program
Files pass, and refuses GitHub's Python, the job's own folders and `D:\` - but for the names a plain interpreter
itself looks for beside and above its folder, judged as the code itself (N-1, below). A refusal says the name, its
role, and the owner or the entry as read, with the bits that refuse in hex.

**The path, and what is refused unread (K-4).** The program's path, and the folder its runtime says its modules are in
- on the plain road the interpreter's path, its base executable's, its prefixes, every entry of its path, every line
of a *.pth file made whole, and the raqib package's folder - are judged only where each begins with a drive's letter
(`X:\`) and every part of it is one plain name: a share, a device path (`\\?\`, `\\.\`), `/`, `..`, `.`, an empty
part, a character no name of Windows holds, a name ending in a dot or a space, a device's name (`NUL`, `COM1`; Windows
would open another thing for each of those last two) - each is refused, and nothing is read. A path longer than the
system opens plainly (259 characters), a name that cannot be opened or read, a folder that cannot be listed, a listed
name of the forms above, two names of one folder that differ only in case (a folder that tells case apart: which one
would run is not known), and a walk past 200000 names (WALK_MAX, the Linux number) are each refused as not read: what
was not read is never the system's. A name's kind is the one read through its handle, never the listing's.

**The drive (Amendments P and Q, P-1 and Q-1).** Before any name of a drive is read, the check asks what the drive's
letter names: each drive a path of the walk is on is asked once (its letter compared without case) - on both roads, the
program's or the interpreter's drive first, then each drive of a root, an entry of the path (one that is not there
too), a line of a *.pth file or a name the interpreter itself looks for, as it is met. The letter is read as the
session that runs the check names it: the system's account may name a letter otherwise, or not at all, and the check
does not ask it; the service answers this for itself by asking the check at every start of its own, as the system, and
not watching a tree it refuses (Amendment T, T-1: the runner's section, above; measured there: a letter a user's
session gave to a folder is not there for the system at all). The system's answer is its kind (GetDriveTypeW of `X:\`, a number) and its device's name (the
first name QueryDosDeviceW gives for `X:`), read by one function beside the one reader of a name
(`winservice.System.read_drive`). The device's name has that one reader in the tree; the kind has two, for the
autostart reader asks it too, for its own purpose (`raqib/autostart.py`, AJ-4). A path is judged only where its drive
is of the fixed kind (3) and its device's name is, whole and with its case, `\Device\HarddiskVolume` and one or more
of the digits 0-9 - the form measured of every disk's volume (tests/fixtures/wincode/drives.txt), nothing before it
and nothing after it. Refused, each with its own words, the letter, the kind as a number with the system's word for
it (0 unknown, 1 no root, 2 removable, 3 fixed, 4 remote, 5 a disc, 6 a RAM disk; another number said as it is) and
the device's name made printable: a kind that is not 3; a device's name of any other form, said as read with the form
asked for (`\Device\HarddiskVolumeN`, nothing after it) - a letter given to a folder (its device's name the folder's
own path behind `\??\`), a volume's name with anything after it, a volume of another kind of disk (not measured, and
refused until it is); a device's name not read (the system's number said, the kind in the reader's own words); a kind
or a name of a type the check does not know. A refused drive is exit 1, and nothing of it is read: what is above such
a letter is not what the check reads, or can be changed where the check cannot see. So "to the drive's letter" in the
pass means a volume's root and nothing below it, and the pass ends with the drives it asked, each letter with its
device's name. A disk the system calls fixed is taken as a disk whatever it is - one carried from another machine, an
image attached, a volume a program serves: who made its lists is not read, and its names are judged by K-2 and K-3 as
any other's.

**The roads walked (K-5, M-2).** Two: the packed road, and the plain road below. Packed with its own runtime
(`sys.frozen`, as tools/rig/pack.sh packs it): the root
is the folder the program file is in. The folders above it are read first, from the drive down, then the root and
every file and folder below it, whole; the modules' folder (`sys._MEIPASS`) and the program are then met again and
not read twice (names are compared without case). Where the runtime does not say where its modules are, or says a
folder outside the program's (a one-file packing unpacks into a temporary folder at each start), the check refuses:
what would run is not there to be read. The packed road is chosen first; a plain interpreter takes the plain road.

**The plain road (Amendment M).** A Raqib a plain interpreter runs, as M12.4c2's service will run it: the interpreter,
`-I`, `-m raqib service run` (measured). So the check takes a plain interpreter only where it was itself started with
`-I` and with its site (no `-S`), read from the running interpreter (`sys.flags.isolated`, `sys.flags.no_site`): then
the path it walks is the path the service gets, read and never worked out. Otherwise exit 2, on the error stream,
saying which is missing and the command to ask it by: the interpreter's path, then `-I -m raqib service check` (M-1).
Walked, each by K-2 and whole, the folders above each by K-3, top first, in this order (M-2): the folder the
interpreter is in (`sys.executable`); where it names a base executable (`sys._base_executable`, a venv's base) in
another folder, that one's folder; its prefix and base prefix (`sys.prefix`, `sys.base_prefix`), and its exec prefix
and base exec prefix (`sys.exec_prefix`, `sys.base_exec_prefix`) where they are neither of those, compared without
case (N-3); N-1's three names, below; every entry of its path (`sys.path`), and of the lines its *.pth files add; the
folder of the raqib package (the folder of its `__init__.py`), wherever it is - outside every entry too (an editable
install's finder is met only so). Each real folder is walked once (names compared without case), a name judged in two
roles - a folder above one root that is itself a root - is read once and counted once, as the code itself, and one
WALK_MAX bounds the whole walk. An entry that is a file is judged as itself; an entry that is not a string, not a
whole path of a drive, or of a form K-4 refuses is refused with its own words, and so is a root of any other form.
Only the base executable may be unnamed: a program, a prefix or a base prefix the interpreter gives as None, or as
anything but a string, is refused with its own words, never skipped (N-3). An entry that is not there - the library's
zip, a line of a *.pth file - is judged by the deepest folder of it that is there, as the code itself, itself only,
and the folders above that by K-3: whoever may add the missing thing decides what runs, so `C:\made-later\x` on a path
is refused because signed-in users may add a folder to `C:\` (M-3). "Not there" is the reader's own answer for a
missing name, the system's errors 2 and 3 (file not found, path not found), and nothing else: a name that cannot be
opened for another reason is not read, and refused as such; a name not there whose drive is not there either is
refused, no folder of it being there to judge. An entry beneath a file - a name inside the library's zip - that the
system answers is not there (2 or 3) is taken where that file was taken as the code itself: the file judges it, and
the pass counts it apart (N-3). The refusal names the entry, says it is not there, and names the folder judged for it.
The interpreter's folder, its base's, its prefixes and the package's folder must be there: one not there is not read.
In every entry that is a folder each *.pth file (a name ending in `.pth`, as site and the Linux check read them; one
beginning with a dot, which site skips, is read even so) is read only once it was taken as the code itself, as a file,
with the whole entry: at most 1048576 bytes (PTH_MAX), a longer one refused; a byte outside printable ASCII, tab, LF
and CR refuses, the byte and its offset said (PTH_ODD, as on Linux); a name ending in `.pth` that reads as a folder is
refused. Its lines that are paths, by site's own rule - not blank, not `#`, not `import ` or `import` and a tab -
each, its trailing whitespace stripped, joined to the entry and made whole (with `ntpath`, as
`raqib.service.pth_entries` does with `posixpath`), become entries, there or not; a refusal under such an entry says
the line's *.pth file. The check takes or runs none of a *.pth file's lines as code: an `import` line is code the
file's owner put there, the file was found the system's alone, and no more is said of it (M-4). The bytes are one
bounded read in binary mode through the check's system object, the only file the check opens; the constants are
raqib/service.py's.

**The names the interpreter itself looks for (Amendment N, N-1).** For the folder the interpreter is in, and for its
base executable's where that is another folder, three names are judged as an entry of the path is: `pyvenv.cfg` in
the folder above it, and `Modules\Setup.local` and `Lib` two folders above it (made with `ntpath`; for a folder nearer
the drive's root, the root). A name there is judged as the code itself (a file as itself, a folder whole, in the same
walk and its one WALK_MAX); one not there by the deepest folder of it that is there, as the code itself, itself only,
and the folders above that by K-3. Why: at every start the interpreter looks for a venv's `pyvenv.cfg` in the folder
above its own, and for a build tree's marker `Modules\Setup.local` two folders above it, whose `Lib` there it then
takes as its library - read in its source (CPython 3.11.9, 3.12.10, 3.13.9 and 3.14.0, Modules/getpath.py and
Lib/site.py; Amendment N), not measured. So nobody but the system may be able to put either there. These names are
counted apart from the entries; a refusal for one says the name, which of the three it is, that the interpreter
looks for it at every start, and the folder judged for it. The consequence: python.org's default folder for all
users (`C:\Program Files\Python311`, one folder below Program Files) has the drive's root two folders above it, so
it is refused on a machine whose root lets signed-in users add a folder (GitHub's do: `(A;;LC;;;AU)`, measured, K);
one folder deeper (`C:\Program Files\NAME\Python311`) it is taken.

**What Amendment O added, and what the names rest on.** The three names are judged for the interpreter's base prefix
too, where that is neither of the two folders: the interpreter takes a venv's build tree from the home its
`pyvenv.cfg` names, and the base prefix is that folder whatever the interpreter says its base executable is (O-1).
"Two folders above" is the interpreter's own compiled-in value, read in its build files at the four versions (`..\..`;
another build of Python may hold another, and is not known). The names are made from the paths as the interpreter says
them, not resolved: a letter given to a folder is refused by its drive (P-1, above), and a link on the way is a
reparse point and refused. A `._pth` file beside the runtime library is inside a walked folder where the library lies
beside the interpreter, which is not asked. Read: Modules/getpath.py at 3.11.9, 3.12.10, 3.13.9 and 3.14.0,
Lib/site.py at 3.11.9 and 3.12.10; not read: the start of Python 3.10 and older (another file; Raqib asks for 3.11),
the C code beneath, the venv launcher. A packed runtime is another case: where the program that embeds the interpreter
sets its home, the venv file, the `._pth` file and the build tree are not looked for (read in the same source and in
the packer's, PyInstaller 6.11.1) - up to Python 3.13. From 3.14 on the venv file is read though the home is set (read
in 3.14.0), and the packed road does not judge that name yet: a packed runtime that says 3.14 or later, or says no
version the check can read, is refused with those words (O-2). Asked on GitHub's Windows machines (Amendment O's field
run): python.org's install for all users where its installer put it (3.11.9, ARM64), and a copy of a Python one folder
below Program Files (x64), were refused for `C:\Modules\Setup.local` - on those machines the folder `C:\Modules` is
there and gives signed-in users modify; the same trees one folder deeper were taken; a venv with its base at the first
place was refused for its base, with its base one folder deeper taken.

**Who runs the check (Amendment N, N-2).** On the plain road the check is run by the code it judges: the interpreter
that says the pass has already run its site and the `import` lines of its *.pth files, as every start of it does,
and has imported Raqib from the tree it judges. So the check is a reading of a tree as its own code tells it: a gate
against a tree put in the wrong place, not a judgement of a tree another already changed, which could make it say
anything. Ask it first as a plain user, who needs no rights for it; an administrator who asks of a tree that is not
the system's alone has run that tree's `import` lines as himself. The check writes nothing, but the interpreter that
runs it may write bytecode caches beside what it imports, where the asker may write there.

**The command (K-6).** `raqib service check` (no option; `--no-start` and `--purge` are install's and remove's, exit
2):

| Exit | When | What it says |
|---|---|---|
| 0 | Windows, and every name walked of the road - packed, or a plain interpreter asked with `-I` - is the system's alone | on the output, one sentence with its counts: packed, "raqib service check: the code a service would run is the system's alone: checked N names, each the system's alone (...): under the program's folder, whole, F folders and G files, ..., and A folders above it to the drive's letter, ..."; on the plain road, "... checked N names, each the system's alone (...): under the interpreter's folder, its base's, its prefix and base prefix, E entries of its path and the raqib package's folder, whole, F folders and G files, ...; M of those entries not there, each judged by the deepest folder of it that is there, itself only, and B beneath a file, each judged by that file; O names the interpreter itself looks for at every start for its folder (...), each judged as an entry is, T of them there; P *.pth files read, L of their lines walked as entries, none of their lines taken or run by the check; and A folders above them to the drive's letter, ...; and besides those N names, J folders judged themselves only, as the code itself, ..." ("its base's" said only where a base in another folder was walked, its exec prefixes only where they are roots of their own; N is F + G + A) - never a pass without them; each says the creator's own inherit-only entry was left apart, and that above only the entries that apply to the folder itself were read (M-5); each ends with the drives asked (P-1, Q-1): "; and the drive asked before any name of it was read, each said by the system to be of the fixed kind with a device's name of the form \Device\HarddiskVolumeN: C: "\Device\HarddiskVolume3"" (with two or more, "the drives ... of them", each `LETTER "DEVICE"`) |
| 1 | a name is not the system's alone, or was not read | on the output: "raqib service check: NOT the system's alone: NAME, ROLE: WHY", the first name refused, its role (`as the code itself (K-2)`, `as a folder above it (K-3)`, or none where it is the path's form, the modules' place, a *.pth file's bytes or the walk's bound) and why; an entry not there is said as "ENTRY, not there (error 2): the deepest folder of it that is there, FOLDER, judged for it ROLE: WHY"; one of N-1's names ends with "(the name NAME: WHICH, which the interpreter itself looks for at every start ... above the interpreter's folder FOLDER)"; a drive refused (P-1, Q-1) is said as "X:\, the drive X:, asked before any name of it is read (ADR-0013 P-1, Q-1): the system says kind K (WORD) and names its device "DEVICE"..." with why - for a device's name of another form, the form asked for ("\Device\HarddiskVolumeN, N one or more of the digits 0-9, and nothing after it") |
| 2 | not Windows, or a plain interpreter not started with `-I` or started with `-S` | on the error stream, which, and for a plain interpreter the command to ask it by: `"PATH" -I -m raqib service check` (M-1) |

Names and texts said are made printable (a character that is not is `?`) and cut at 200 characters, the cut marked
`...` (200 and not the runner's 80, so that the entry that decides is said whole; a piece inside a refusal's words - a
flag, a rights word, an error's own words - is cut shorter, at 20, 40 or 80). An error's number is the system's own
where there is one. Below the root the walk goes in the order the file system lists, so the first name refused of
several may differ between two volumes. The rig's Windows job asks it of a packed copy an administrator put in Program
Files and of the copy in the job's own folder, and keeps both answers (K-8; the job's wiring is the Table's): X49
(`tools/rig/check.py --service-check FILE`) is MET only where the first is exit 0 with its counts adding up and the
second exit 1 with a path of a drive and a role in its words. On the plain road the job is to copy its Python under
Program Files as an administrator would, install Raqib into the copy, and ask the copy with `-I` and its own Python
with `-I` (M-6; the wiring is the Table's): X50 (`tools/rig/check.py --service-check-plain FILE`, the same four keys
and the same reading as X49) is MET only where the copy is exit 0 with the plain road's counts adding up and the job's
own Python exit 1 with a path of a drive and a role in its words. Through a letter (P-3; the wiring is the Table's):
the job is to give a letter to the folder of its packed copy in Program Files and ask the check through that letter;
X51 (`tools/rig/check.py --service-check-drive FILE`, keys `letter-exit` and `letter-words`) is MET only where the
answer is exit 1 and its words name a kind (`kind N (WORD)`) and a device's name (`names its device "DEVICE"`) that
is not, whole, of the form `\Device\HarddiskVolumeN` (Q-5), and MISSED where it is (the letter was a disk's); the
device's name is not tied to the job's own copy's folder (kept, and said).

**What Amendment K measured, and by what.** GitHub's Windows machines, x64 and ARM64 (the same on both unless said),
every owner and list read through one handle on the name, whole; the texts are tests/fixtures/wincode/measured.txt,
and each gets the verdict the Table ruled for it in both roles (tests/test_wincode.py). GitHub's Python gives all
signed-in users modify on every file and folder of it (`(A;ID;0x1301bf;;;AU)`), and a plain user wrote beside the
interpreter, into its site folder and into the raqib package there. A Raqib packed with its own runtime, copied into
`C:\Program Files` by an administrator, was owned by the administrators with Program Files' list inherited; a plain
user's write beside the program, into its folder of modules and to the program, and his renaming of its folder and of
Program Files, were each refused; the service ran from there. `C:\` is owned by the system's installer, and signed-in
users may add a folder to it (`(A;;LC;;;AU)`), which is then the user's own, open to all users (a plain user made
one). `C:\ProgramData` lets users add files and folders; `D:\` (x64 only) is owned by the network service. The profile
of the account the job ran as - an administrator's, the machine's built-in one - is owned by the system and gives that
account everything; a plain user's own profile was not read (Amendment L corrects K's sentence here). So the Linux
rule (no folder on the way writable by another) is not carried over word for word: it would refuse every path of
Windows. The real readings a test makes, on Windows only: `C:\Windows\System32\kernel32.dll` taken as the code
itself and each folder above it as a folder above (measured so on both machines); and since Amendment P the system's
drive read as kind 3 with a device's name of the form `\Device\HarddiskVolumeN` (Q-1), and each library of P-2's list
found in System32. Every other verdict here is read from the measured texts by tests on any system, not on a machine; the walk is held by tests on a made-up Windows.

**What the check itself said on real machines (Amendment L).** GitHub's Windows machines, x64 and ARM64, the same on
both: the branch's Raqib packed by the rig's packer. Its tests passed there, the one real reading among them. A copy
an administrator put under `C:\Program Files` was taken (about 150 names, 2 folders above, under half a second), and a
plain user who asked got the same sentence and exit 0. In that copy, one thing at a time, each undone: one file users
were let modify - refused, the file and the entry said; the same file with an entry of its own giving users reading
and executing - taken; the file owned by the administrator's own account - refused; a junction inside - refused; a
folder and a file an administrator added - taken, the counts two more. A copy in a folder an administrator made at the
drive's root was refused (the folder inherits modify for signed-in users), one under `C:\ProgramData` refused, the one
in the job's own folder refused (x64: `D:\`, its owner; ARM64: the job's folder on `C:\`, which signed-in users may
delete); a copy three folders deep under Program Files, a space in a name, was taken with 5 folders above; a one-file
packing was refused, its modules unpacked under the user's temporary folder; a plain interpreter got exit 2 and its
words (0.11.0, before Amendment M). X49 read MET on both.

**What Amendment M measured, and by what.** GitHub's Windows machines (the probe branch's runs; the texts are
tests/fixtures/wincode/python.txt): python.org's installer for all users (3.10.11 on x64, 3.11.9 on ARM64) puts the
interpreter under Program Files, everything of it owned by the system or the administrators, Program Files' list
inherited, no reparse point; asked with `-I`, its whole path lies in its own folder (its zip, which is not there;
DLLs; Lib; the folder; its site folder), and its site folder holds one *.pth file of one `import` line. A copy of a
Python an administrator put under Program Files, Raqib installed into it, reads the same; a venv made from it under
Program Files adds its own folder and site folder to the base's entries and names the base in pyvenv.cfg and in the
base executable. Without `-I` the path began with the folder the interpreter was started in and the user's site was
on. A plain user's six writes into the copy and the venv and one renaming were refused; the watch ran as a service
from the copy by `"...python.exe" -I -m raqib service run`. Every row of that file is taken as the code itself, and
each folder of it as a folder above, by tests on any system; the walk of the installer's tree, the copy and the venv
is held on a made-up Windows built from those rows, with stand-ins said in the test where no machine gave a reading
(the venv's Lib folder, the installer's raqib package and its *.pth file, every *.pth file's bytes, every folder's
listing, and the folder that places the measured trees one folder deeper). Where measured, each of those trees is
refused for `C:\Modules\Setup.local`, judged by `C:\` (N-1); one folder deeper each is taken. The check's plain road
was asked on real machines since (Amendment N's field run, before N-1): X50 is the rig's, wired by the Table.

**What the check does not read, and what was not measured (Amendments K and L).** Not read: rights a user holds apart
from any list (backup and restore, taking ownership, debugging programs); the packed runtime's own roads - an entry of
its sys.path outside the program's folder, a variable or a file it might take one from (the check walks the program's
folder and the folder the runtime names, and takes the packer's word that everything loads from there; not measured
for any packer); the labels of a system list; what changes after the check (it is a reading at one moment, as the
Linux one is). The system's PATH and what the drive's letter names were on this list until Amendment P: both are
closed now (below). Not measured: a denying entry on a real file that still lets the asker read (the one tried took
reading from the asker too, and the file was refused as not read); a file the system itself marks as a reparse point
(it would be refused); a removable or shared drive; a machine joined to a domain; Program Files on a machine whose
lists an administrator changed; a plain user's own profile. Measured since Amendment K and kept for the tasks that
rule them: a volume that keeps no lists (FAT32, exFAT) gives every name the owner `WD` and a null list, and is refused
as it is.

**What Amendment P measured and read, and what it did not.** Measured (the probe branch cf233f5; GitHub's Windows
machines, x64 and ARM64): the system says a disk's letter is of the fixed kind and names its device
`\Device\HarddiskVolumeN` (`C:\` read kind 3 and `\Device\HarddiskVolume3`; the number varies); a letter given to a
folder (`subst`) is said of the fixed kind too, and its device's name is the folder's own path behind `\??\` (as
`\??\C:\ProgramData`) - so the kind alone does not tell them apart, and the device's name does; a volume that keeps no
lists (FAT32, exFAT) is a fixed disk whose every name reads with the owner `WD` and a null list (refused by K-2 and
K-3 as they are); a letter that is not there has no root (kind 1) and its device's name is not read (the system's
error 2). Read in the interpreter's library (Lib/ctypes/__init__.py at 3.11.9 and 3.12.10), not measured: a library
asked for by a bare name is searched with the system's default folders - the application's own folder, System32, and
folders the process itself added - and not along the PATH or in the folder the process was started in. So the system's
PATH is held by a test (P-2, tests/test_libraries.py; what it is for and where it ends is said below): it reads each
place in raqib/ where a library is loaded, in the forms it knows, and holds that each name is a plain name written in
the code, with no path and no name worked out, no folder added to the search and no search mode given, and on one list
(advapi32, dnsapi, dwmapi, iphlpapi, kernel32, shcore, shell32, user32); on Windows it also finds each name of the
list in System32. The one call that changes the search, SetDllDirectoryW with no folder at the entry (ADR-0007 CI-3),
takes the folder searched first back to the system's own. The reading names three places a library is searched: the
program's own folder, which the check walks as the code itself; System32; and folders the process itself added. Of the
third, the test holds since Amendment R (R-3) every mention in raqib/ of a word by which a library can be loaded, the
search changed, the environment set past `os.environ` or ctypes reached by another road - as a name, an attribute, an
import, a keyword, a parameter or a whole word in a string, docstrings too, but `compile`, `exec` and `eval` not in a
docstring or as an attribute of `re` (Amendment S, S-4) - by file, function and count, compared whole and exactly; and
it holds the statement around each load and CI-3's function and `own.library_folder` word for word, every attribute
taken of ctypes on one list, each table of names and each loader as written with every mention of its name, each use
of a library's object in the function and file that loaded it, and each use of `os.environ`, or of a name it is bound
to in a function (bound at a file's top, through the file), but a read of one name, by its statement. What that is for
(S-1): a change made in good faith and written the ordinary way - a new library, a library's path, a folder added, the
PATH or the whole environment set, a loader handed somewhere new, ctypes used as the tree did not use it - changes a
table of the test, and a reviewer reads the change; it is no wall against code written to get past it, so it does not
hold (S-2) a library's object reached outside the function and file that loaded it (by getattr of what holds it, a
closure or the interpreter's own lists of live objects), a name the held statements read bound otherwise elsewhere, a
table reached by its name as a string from another module, the interpreter's own roads to code that is not a library
by name (its import system given a path, `sys.path`, extension modules), what the system's own libraries load by the
registry's word, a word built from pieces at run time that is on no list, or the loads the interpreter itself makes
outside raqib/; nothing holds what the interpreter's own start adds (site, an `import` line of a *.pth file,
sitecustomize), which the check walks as files and does not read for what it adds. The refusals of Amendment Q (Q-4)
stand beneath it:
a loader asked by index, ctypes' low loader and the class its loaders are made by, a loading call given more than its
name, a search call's name written in a string, the environment written whole or by the setters it knows past
`os.environ`, a table of names changed after it was written, a loader handed on as a value, and a second call of
CI-3's call or one given a folder. Not
measured, and said: a network drive, a removable disk and a disc (their kinds are the system's own numbers, read in
its documents, not seen); a letter the system's account has and the asker has not, or names otherwise; a folder
mounted on a volume with no letter; whether a library's own dependencies are searched as the library is.

**What Amendment Q measured, and what it changed.** P-1 took a device's name that begins with `\Device\`; what was
measured of a disk is narrower, and Q-1 takes only that: the readings of x64 and ARM64 (the probe branches cf233f5 and
50baa9d) are tests/fixtures/wincode/drives.txt, read by the tests and never retyped - each disk's volume
`\Device\HarddiskVolume` and a number, nothing after it; a letter given to a folder (three of them, one Program Files
itself) the folder's path behind `\??\`; a disk image made for the run, NTFS or FAT32, a volume of the same form; a
letter that is not there, kind 1 and error 2. Not read on any machine: a network drive, a removable disk, a disc, a
RAM disk; a letter whose device's name is a volume's followed by a folder's path (refused by its form); a volume of
another kind of disk, as a dynamic disk's or a storage pool's (refused by its form until it is measured).

**What the plain road does not read, and what was not measured (Amendment M).** Not read: what the system's own
account would add to the path that the asker's does not (a path the registry gives under the asking user's own key is
on the asker's path and is walked; one under the system account's own key is not seen - only the system writes there);
a finder or hook a package installs (an editable install is met only as its *.pth file and the package's folder); what
an `import` line of a *.pth file would do (the file is the system's alone, and that is all that is said); whether site
would skip a *.pth file (one marked hidden, or a name beginning with a dot, is read even so; a name ending in `.PTH`,
which site does not read either, is judged as code only). Measured since (ARM64, 3.11.9): a path under the
interpreter's PythonPath key, the user's or the machine's, is on the path without `-I` and not with it. Not measured:
whether `-I` reads the registry's paths on x64 or on a later version; python.org's installer with a plain user's
writes tried against it (they were tried against the copy); the Store's Python (its interpreter is a reparse point:
refused); an embedded distribution with a `._pth` file; Python older than 3.11; what a real Windows answers when a
name below a file is opened (2 or 3: judged by that file where it was taken as the code itself; another number:
refused as not read); what the interpreter does with N-1's three names on a real machine (read in its source only: no
probe puts such a file there); whether bytecode caches are written when an administrator asks; a packer other than the
one read.