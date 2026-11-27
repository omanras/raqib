# The service: Raqib's watch as a unit of the system's (ADR-0013)

On Linux, an administrator can run the host watch (`raqib watch --host`) as a systemd unit of the system's,
`raqib-watch.service`. It runs with the system's rights, so the agent it watches cannot stop it, cannot write its
record again, and cannot leave its sight by becoming another user (ADR-0013 A-1). This is stage S1: the watch's
unit on Linux. The forwarder as a unit (S2), what a person without rights reads of the service (S3) and Windows
(S4) come later. The watch itself is unchanged; the unit runs it with `--no-page`, so it serves no page (below).

## The three commands

| Command | Does |
|---|---|
| `raqib service install [--no-start]` | As root only: checks that the code the unit would run is root's alone (below) and says how many paths of which kinds it checked. With no unit file it first asks systemctl whether systemd holds a unit of the name (LoadState, ActiveState, FragmentPath): one loaded from any place, or running, is not Raqib's to replace, and a systemctl that gives no answer is a refusal too. Then it writes the unit, runs `systemctl daemon-reload`, and asks systemctl how the unit is loaded (FragmentPath, DropInPaths, NeedDaemonReload): a unit not as installed is neither enabled nor started (exit 1, `RESULT: the unit is written; NOT AS INSTALLED, not started: ...`). Else it runs `systemctl enable --now raqib-watch.service` (over Raqib's own unit: `systemctl enable` and `systemctl restart`, so no watch keeps the old text), waits 3 s and asks systemctl whether the unit is active and still as installed. `--no-start` writes the unit, reloads and makes the same check after the reload; the unit is neither enabled nor started, and where a watch of Raqib's unit is running it says that watch keeps the text it started with. Exit 0 done (and, started, active and as installed after 3 s: `RESULT: installed, enabled, active 3 s after its start`), 1 the unit written but systemctl failed, or not as installed (then not started), or not active or not as installed after 3 s (said; left as it is), 2 refused (said, nothing written). |
| `raqib service remove [--purge]` | As root only: runs `systemctl disable --now raqib-watch.service` (stops and disables it), removes the unit's one file if it carries Raqib's mark, runs `systemctl daemon-reload`, and asks systemctl for the removed unit's ActiveState: where it is `failed` (a stop after a finding reads so, the watch's own exit 1), it runs `systemctl reset-failed raqib-watch.service` and says so; a reset that fails is said and the exit stays what it was. The record stays and its path is said. `--purge` removes `/var/lib/raqib` too, and only that folder. With no unit file it asks systemctl for the unit's LoadState and ActiveState: LoadState `not-found` with ActiveState `inactive` or `failed` is exit 0 (nothing installed, said); anything else, or no answer, is said and is exit 1, and nothing is touched and nothing purged. Exit 1 also when systemctl or a removal failed (said, left as it is), 2 refused (said, nothing touched). |
| `raqib service status` | Needs no rights: whether the unit is installed (the file with Raqib's mark), enabled and active, by systemctl's own words (`systemctl show`: UnitFileState, ActiveState, SubState), whether it is as installed (below), how many times it was restarted (NRestarts), and the unit's last result (Result, ExecMainStatus) when it is not active. With no unit file it asks systemctl too, and says a unit of the name that systemd holds (`RESULT: NOT INSTALLED BY RAQIB, YET A UNIT OF THE NAME IS ACTIVE`, or `IS LOADED`, exit 3). Exit 0 active as installed, 1 installed and not active, or active but not as installed (`RESULT: ACTIVE, NOT AS INSTALLED`), 3 not installed or not known (a unit file that cannot be read, no systemctl, or no state from it), 2 not Linux. |

`install` and `remove` do nothing unless run as root, and say so; they ask for no elevation themselves (run
them with `sudo`). Off Linux every one of the three is exit 2.

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
count. A watch's exit status 1 is its own ALARM at its end, or an error; the journal says which
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
exists) and Amendment G (AG-1, AG-2). This is the first part of S4: on Windows the host watch runs as a service of the
system's, by the standard library alone (ctypes; no new dependency), in raqib/winservice.py. Installing, removing and
asking the state of the service are not here yet, and neither is what a watch started again after a killed one does
(AE-6); until they are, the line above that there is nothing for Windows is true of `install`, `remove` and `status`
only. Four sources are named below and nothing else is called measured: Amendment E (a candidate of 150 lines in the
same shape, not this runner), Amendment F's field run of c125f62 (the first builder's runner, as a real service),
Amendment F's measurements (the calls this runner makes, by a probe), and Amendment G (this runner's own field run as
a real service, f8af8f5, and two measurements more by a probe).

**The shape.** `raqib service run` is the command the system's service manager runs; nobody else. Its process hands
the system its service table (StartServiceCtrlDispatcherW) in a second thread, and runs the watch in the main thread
as it runs from a console, by Raqib's own entry with the Linux unit's arguments: `cli.main(["watch", "--host",
"--no-page", "--no-notify"], out)`. When the system calls the service's main, the runner registers its handler and
reports START_PENDING, with no control accepted. The main thread then makes the place ready and begins the text file,
and only then reports RUNNING and starts the watch (AF-2). A refusal of the place or of the text file is STOPPED
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
whole record is written under it. One folder is made, the place; one name is read, the place's.

**The text file.** A service has no standard streams (each is None; Amendment E). The runner gives the watch a
text file in the place, `service.txt`, for its report and its errors. It is begun anew at each start; the one
before is kept once, as `service.before.txt` (the field run of c125f62 read it so). It holds at most 8388608 bytes
(8 MiB, its last line included): past that bound nothing more is written to it and its last line says so, once.
A write that fails ends it the same way, with one last line saying a write failed where that line can still be
written, and the runner keeps that it happened: where the system would be told exit 0, it is told 18. The
watch's record goes on in either case. The standard output and error streams, where they are None, are the text
file for the whole process; the standard input stays None. The runner's own lines in it begin
`raqib service run:`: the place, the road it took ("made" or "found") and its owner and list first; how the
watch ended and what the system is told last. A line the runner had to say before the text file was begun (a
status the system did not take) is written in it once it is begun.

**The exits.** Each number of the service's own is `0x20000000 + n`, the range the system leaves to applications
(AF-3), told with STOPPED as the system's service-specific exit (ERROR_SERVICE_SPECIFIC_ERROR, 1066). A watch's
result after a Stop (0 clean, 1 an alarm, 3 incomplete) is no failure of the service: the system is told exit 0,
and the result is in the text file. A Stop that came before the watch gave any result (the watch not begun, or
ended by its interrupt with no result) is told 0 too, and the text file says in one line that the watch was
stopped before it gave a report; the unfinished state such a watch may leave is M12.4b's. Each refusal, a watch
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
| 16 | 536870928 | 0x20000010 | the text file could not be begun in the place |
| 17 | 536870929 | 0x20000011 | the place could not be made, or could not be read through one handle on its name |
| 18 | 536870930 | 0x20000012 | a write to the text file failed and ended it (the watch's record went on) |
| 20 | 536870932 | 0x20000014 | the watch refused to start (its result 2) |
| 21 | 536870933 | 0x20000015 | the watch ended without being asked (no Stop or Shutdown came), or with no result of its own |
| 22 | 536870934 | 0x20000016 | an exception came out of the watch |
| 23 | 536870935 | 0x20000017 | an exception of the runner's own (not the watch's) |

15 is not used: the closing it named is gone. The process itself exits 0 where the system was told exit 0, and 2
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

**What was not measured.** A place whose list is closed in meaning but written otherwise (refused, by the letter); a
place on a volume that keeps no owners; an owner written as a whole SID and not as SY or BA (refused with 13, by the
letter); a Stop that comes while the service is still START_PENDING; a RUNNING the system does not take (the service
would stay START_PENDING for the watch's life, said only in the text file); where the Stop's interrupt surfaces after
the watch's call on a real machine; a call by a file's owner that asks only for the right to change its list, inside a
folder closed after he put it there; reparse points of other kinds than a junction and a link; the runner under Python
3.11 as a service; a Stop that comes while the watch is still starting (it may end with no final report and an
unfinished state; M12.4b's); a watch that ignores its interrupt (M12.4b's); a shutdown of the machine (the control was
not sent); a service's start at boot; the manager's limit of 30 s under a slow start; another account than the
system's; a place on another volume, or one with a file held open by another process; Windows before the runners'
versions. A watch started while the one before left its state unfinished, and how long the service waits then, are
M12.4b's; the install, its start at boot, the system told to start it again, a refusal where the code it would run is
not the system's alone, and the event log are M12.4c's.