# Changelog

Every merge into `main` that changes what Raqib does has a number and an entry here, the newest first (ADR-0015).
`raqib --version`, the first line of a watch's report, the window and every event say the number, so a person
knows which Raqib is running without reading sentences. Each entry says what is new, how to update, and what
was not measured.

## 0.17.0 - 2026-11-27

What is new:
- `raqib service status` on Windows now reads what the install sets for the system to bring the service back,
  and judges it (ADR-0013 Amendments Z and ZA): what the system does after an end that was no Stop, whether an
  end the service itself reports is such an end, and whether the automatic start is delayed. Each is said in a
  line of its own.
- Raqib's service is as installed only where its start is automatic and not delayed, the system starts it again
  after 5 s, 30 s and then 300 s with the count forgotten after 3600 s, and the flag is set - what the install
  writes. Each difference is said by what was read and what the install writes, and the answer is then not
  `ACTIVE` but `ACTIVE, NOT AS INSTALLED`, exit 1.
- A message or a command the system keeps beside those actions is a difference too: the install writes none.
- So a watch that would not come back after it is ended, or would not start with the machine, no longer reads
  as the watch that was installed.
- Measured on GitHub's Windows machines, x64 and ARM64, asked by a user outside the administrators' group: a
  service Raqib's install made read ACTIVE; with each setting changed alone by the system's own tool it read
  not as installed, its difference said; put back, ACTIVE again. The rig reads it at every run (X53, X54).

To update:
- As 0.2.0's entry says, by how Raqib was installed (`git pull`, then `pipx install --force .`, or
  `pip install --upgrade .` in the same venv, or `py -m pip install --upgrade .`; the service's copy as there:
  `sudo cp -r . DIR/src-NUMBER`, `sudo DIR/bin/pip install --upgrade DIR/src-NUMBER`,
  `sudo DIR/bin/raqib service install`). First stop a running watch, window or service.
- Then `raqib --version` says the number at the top of this file.
- Nothing changes for a watch, a window or the Linux service. On Windows, a service made by hand under Raqib's
  name and mark, without those settings, read ACTIVE until now and reads not as installed with this version
  (exit 1, each difference said): remove it by hand and let Raqib's install make it.

Not measured:
- A count that is never forgotten; these settings on a 32-bit Windows; a service marked for removal.
- A start at boot, and a machine joined to a domain, as before.

## 0.16.0 - 2026-11-27

What is new:
- `raqib service install` and `raqib service remove` now work on Windows, by the system's own calls (ADR-0013
  Amendments X and Y). With this, the watch as a service of Windows is installed, asked and removed by Raqib's
  own commands, as on Linux.
- The install asks `raqib service check` of its own code first and makes nothing from a tree the check
  refuses: this is where a tree that is not the system's alone is kept from being made a service at all. The
  check is still run by the code it judges, so install from a copy that was never a user's to change.
- It makes the service `RaqibWatch` for the very program or interpreter that runs it (a plain interpreter is
  asked with `-I`, as the service runs it), with Raqib's mark, an automatic start, and the system told to start
  it again 5 s, 30 s and then every 300 s after an end that was no Stop; it starts it, waits for it to run or
  stop, and says `raqib service status`'s own lines.
- It never changes a service of the name that is there: Raqib's is to be removed first, another's is said and
  left. To update over a running service: remove, then install.
- It makes no folder for the record: the service makes it at its first start, as the system. Where the folder
  is already there and the service would refuse it, the install says so and makes no service.
- A path that holds a quote, a percent sign or a character that is not printable is not written into the
  service's command.
- The remove stops and removes Raqib's service only, asks for the name again, and leaves the record where it
  is, saying where.
- Measured on GitHub's Windows machines, x64 and ARM64, by an administrator and by a user outside the
  administrators' group: every refusal above with nothing made, the install from a copy under Program Files
  (a plain interpreter and a packed program) running within two seconds, the remove leaving nothing. The rig
  asks both at every run (X54).

To update:
- As 0.2.0's entry says, by how Raqib was installed (`git pull`, then `pipx install --force .`, or
  `pip install --upgrade .` in the same venv, or `py -m pip install --upgrade .`; the service's copy as there:
  `sudo cp -r . DIR/src-NUMBER`, `sudo DIR/bin/pip install --upgrade DIR/src-NUMBER`,
  `sudo DIR/bin/raqib service install`). First stop a running watch, window or service.
- Then `raqib --version` says the number at the top of this file.
- Nothing changes for a watch, a window or the Linux service. A service of Windows made by hand keeps running
  and is not changed; to have it as Raqib's install makes it, remove it by hand and install.

Not measured:
- A start at boot: the service is set to start automatically, and the machines measured are not restarted.
- A machine joined to a domain; a remove while the service starts, or while another program holds it open.
- What the system does with a percent sign in a service's command: read in its documents, and refused.
- Removing the record with the service is not built on Windows: the remove leaves it and says where it is.
- `raqib service status` does not yet read the start-again settings the install makes.

## 0.15.0 - 2026-11-27

What is new:
- `raqib service status` now answers on Windows (ADR-0013 Amendments V and W). It needs no rights and changes
  nothing: it asks the system's service manager, by the system's own calls, about the service named
  `RaqibWatch`, and says one line for each thing it read - whether the name is there, Raqib's mark in its
  description (`raqib-service/1`), its command and whether it is one of the two forms Raqib's install will
  write, its type, start and account, its state, and the exit the system holds where it is not running.
- The four answers are Linux's: 0 `RESULT: ACTIVE` (running, and as installed), 1 installed and not active or
  not as installed, 3 not installed, a service of the name that is not Raqib's, or not known, 2 on another
  system.
- A service that stopped with the runner's own number is said in the runner's words; for 15 (the code it runs
  is not the system's alone) status names the text file that holds what was refused.
- Text read from the service manager was written by whoever made the service: status writes it as printable
  ASCII, a letter of another script by its number, and cuts it.
- Measured on GitHub's Windows machines, x64 and ARM64: asked by an administrator and by a user outside the
  administrators' group at ten moments of a service's life, the two were answered the same lines and the same
  exit at each. The rig asks it as such a user at every run (X53).
- Raqib does not install a service of Windows yet: until it does, a service status calls Raqib's is one an
  administrator made under that name with the mark as its description.

To update:
- As 0.2.0's entry says, by how Raqib was installed (`git pull`, then `pipx install --force .`, or
  `pip install --upgrade .` in the same venv, or `py -m pip install --upgrade .`; the service's copy as there:
  `sudo cp -r . DIR/src-NUMBER`, `sudo DIR/bin/pip install --upgrade DIR/src-NUMBER`,
  `sudo DIR/bin/raqib service install`). First stop a running watch, window or service.
- Then `raqib --version` says the number at the top of this file.
- Nothing changes for a watch, a window, the Linux service or a service of Windows that runs.

Not measured:
- A service that is starting, stopping or paused, as status reads it: of those states it says the state and the
  bare number the system holds, no more.
- A service marked for removal; a machine joined to a domain.
- The delayed start, the failure actions and the failure flag are not read: what a caller with no rights reads
  back of them is to be measured before the install sets them.
- Installing and removing the service on Windows: not built.

## 0.14.0 - 2026-11-27

What is new:
- First, for anyone who made a service of Windows by hand: `raqib service run` now asks `raqib service check` of
  its own code at every start, as the system, before it says it is running (ADR-0013 Amendments T and U). A
  service made from a tree a user may change, which watched until now, stops watching with this version. It
  fails to start with a number of its own, 15 (0x2000000F); its text file (`service.txt` in
  `C:\ProgramData\Raqib`) says the whole refusal, with the name and the entry refused; and the system's log
  names the number (event 7024). Make the service from a copy the check takes: a packed Raqib under Program
  Files, or a Python of its own one folder deeper there, started with `-I`.
- Where the check takes the code, the text file gets one new line: the pass's sentence and the seconds the check
  took. Nothing else changes in a start.
- What this gives and what it does not. It is the answer of the very account that runs, at every start, and a
  tree that is not the system's alone is not watched from. It does not keep such a tree from running as the
  system: the code that asks the check has run by then, and the check is run by the code it judges. Refusing to
  make such a service at all is the install's, which is not built yet.
- Measured on GitHub's Windows machines, x64 and ARM64, as a real service: made from three trees the check
  refuses it did not run, with 15 and the log's line; made from two it takes it ran and watched, the check
  taking 0.02 s for a packed copy and 0.6 to 1.7 s for a copied Python. Over a tree made large (about 160000
  names) the check took 10 s and 32 s and the service then ran; past the check's bound it was refused.
- The rig makes its service from a copy under Program Files, and reads a refused and a taken service at every
  run (X52).
- The test of the libraries Raqib loads by name now says what it is for - a guard against a change made in good
  faith that no reader notices, not a wall against code written to pass it - and names what it does not hold
  (ADR-0013 Amendment S).

To update:
- As 0.2.0's entry says, by how Raqib was installed (`git pull`, then `pipx install --force .`, or
  `pip install --upgrade .` in the same venv, or `py -m pip install --upgrade .`; the service's copy as there:
  `sudo cp -r . DIR/src-NUMBER`, `sudo DIR/bin/pip install --upgrade DIR/src-NUMBER`,
  `sudo DIR/bin/raqib service install`). First stop a running watch, window or service.
- Then `raqib --version` says the number at the top of this file.
- Nothing changes for a watch, a window or the Linux service. On Windows, before you update a service made by
  hand, ask the check as the service is run; where it refuses, make the service from a copy it takes.

Not measured:
- A disk slower than the two machines measured: a very large tree may then outlast the wait of 60 s the service
  tells the system while it checks.
- While the check walks, the system refuses a Stop (measured), and a start command that waits for the service's
  check-point to move gave up about 20 s into a check of 32 s although the service then started; the service
  does not raise its check-point yet. Only a very large tree walks that long.
- A machine joined to a domain; Program Files with access lists changed by policy; a tree changed between the
  check and the watch's own start.
- Installing, removing and asking the status of the service on Windows: not built.

## 0.13.0 - 2026-11-27

What is new:
- `raqib service check` (Windows) now asks the system what a drive is before it reads anything on it (ADR-0013
  Amendments P to R). A path is judged only on a disk's volume: the fixed kind, and a device's name of the form
  the system gives a volume (`\Device\HarddiskVolume` and a number, nothing after it). A drive letter given to a
  folder, a letter that names a volume and a folder on it, a network or removable drive, a letter with no device:
  each is refused, with what the system said of it. Before this, such a letter read as a drive of its own, and
  the folders really above it were never judged.
- The pass now ends with each drive it asked and the device the system named for it.
- Measured on GitHub's Windows machines, x64 and ARM64: a packed copy asked by its disk's letter is taken;
  asked through a letter given to its folder, to Program Files, or to the volume's name followed by the folder's
  path, it is refused before any name is read; a second letter of the same volume's root is taken, the whole
  tree walked from the root. A disk image without access lists is refused by its lists, as before.
- A test now reads every place Raqib loads a system library by name and holds the names to one list, each found
  in System32 on Windows, with no folder added to the search by the ways the test knows.
- The rig asks the check through a letter given to a folder at every run (X51).

To update:
- As 0.2.0's entry says, by how Raqib was installed (`git pull`, then `pipx install --force .`, or
  `pip install --upgrade .` in the same venv, or `py -m pip install --upgrade .`; the service's copy as there:
  `sudo cp -r . DIR/src-NUMBER`, `sudo DIR/bin/pip install --upgrade DIR/src-NUMBER`,
  `sudo DIR/bin/raqib service install`). First stop a running watch, window or service.
- Then `raqib --version` says the number at the top of this file.
- Nothing changes for a watch, a window or the Linux service. On Windows, a check that passed before through a
  letter given to a folder (the subst command) is now refused: ask it by the disk's own letter.

Not measured:
- A network drive, a removable disk, a disc: refused by the kind the system's documents give them, not seen.
- A volume of another kind of disk (dynamic, a storage pool): refused until its name is measured.
- A disk the system calls fixed is taken whatever it is - one carried from another machine, an image attached:
  who made its access lists is not read.
- The letter is read as the asking session names it; the system's account may name it otherwise. The install,
  not built yet, is to have the service ask the check again at its own start.
- Where a library asked for by name is searched (the program's folder, System32, folders the process added) was
  read in Python's own library, not measured; and the test of the libraries does not yet hold every way a
  folder could be added - its own text says which, and a task re-makes it as a list of what is allowed.

## 0.12.0 - 2026-11-27

What is new:
- `raqib service check` now also judges a Raqib that a plain Python runs on Windows (ADR-0013 Amendments M to O),
  not only a packed one. Ask it with the interpreter the service would use, started the way the service will
  start it: the interpreter's path, then `-I -m raqib service check`. Asked any other way it exits 2 and says that
  command.
- It walks everything that interpreter would load from: its own folder, a venv's base, every entry of its path,
  the lines of its *.pth files, and Raqib's own folder. A place on the path that does not exist yet is judged by
  the folder that would hold it: whoever may create it decides what runs.
- It also judges three names the interpreter itself looks for at every start outside its own folder - a venv
  file in the folder above, and a build tree's marker and library two folders above. This was read in Python's
  own source (3.11 to 3.14), not measured. The consequence is plain and said in the refusal: a Python where
  python.org's installer for all users puts it (one folder below Program Files) is refused on a machine whose
  drive's root lets signed-in users add a folder, which is the default measured. One folder deeper
  (`C:\Program Files\NAME\Python311`) it is taken.
- Measured on GitHub's Windows machines, x64 and ARM64: python.org's install for all users refused where its
  installer put it, the same tree one folder deeper taken (about 3300 names in under a second), a venv judged
  by where its base is, a *.pth line that leads to a folder a user could create refused, one file opened to
  users refused.
- The pass now says what it is: the check is run by the code it judges, so it is a gate against a tree put in
  the wrong place, not a verdict on a tree someone already changed. Ask it first as a plain user; it needs no
  rights.
- The rig asks it of a Python under Program Files and of its own Python at every run (X50).

To update:
- As 0.2.0's entry says, by how Raqib was installed (`git pull`, then `pipx install --force .`, or
  `pip install --upgrade .` in the same venv, or `py -m pip install --upgrade .`; the service's copy as there:
  `sudo cp -r . DIR/src-NUMBER`, `sudo DIR/bin/pip install --upgrade DIR/src-NUMBER`,
  `sudo DIR/bin/raqib service install`). First stop a running watch, window or service.
- Then `raqib --version` says the number at the top of this file.
- Nothing changes for a watch, a window, the Linux service or a packed Raqib on Python 3.11 to 3.13. A Raqib
  packed with Python 3.14 or later is now refused by the check until its road is walked: that Python reads a
  venv file above the program's folder.

Not measured:
- What the interpreter does with the three names on a real machine: read in its source only, and no test puts
  such a file anywhere. The check's own answers on real machines were measured.
- Whether `-I` keeps the registry's paths off the interpreter's path on x64 and on versions after 3.11 (on
  ARM64 with 3.11.9 it did).
- Python 3.10's start, the Store's Python, an embedded distribution, another build of Python than python.org's.
- Nothing installs a service of Windows yet, so nothing asks the check before a service runs; a person does.
- Still as 0.11.0 says: a machine joined to a domain, a removable or shared drive, a drive letter given to a
  folder, rights a user holds apart from any access list.

## 0.11.0 - 2026-11-27

What is new:
- `raqib service check` (Windows; ADR-0013 Amendments K and L). A service of Windows runs with the system's rights
  whatever its command names, so before one is made to run Raqib, this command says whether the code it would run
  is the system's alone: every file and folder of the packed program, and each folder above it up to the drive,
  by the owners and access lists Windows gives. It changes nothing and needs no rights. Exit 0 with how many
  names it checked, exit 1 with the first name refused and why, exit 2 where it cannot say (not Windows, or not
  packed).
- The rule is a list of what is allowed, written from what real machines gave. The code itself: owned by the
  system, the administrators or the system's installer, and no one else given more than reading and executing.
  A folder above: the same owners, and no one else given more than that and adding a file or a folder beside.
  A link, a path that is not a plain drive path, a list that cannot be read whole: refused, never guessed.
- Measured on GitHub's Windows machines, x64 and ARM64: a copy an administrator put under Program Files is
  taken (about 150 names in under half a second), asked by an administrator or by a plain user; one file opened
  to users, one file owned by a person's account, a junction inside, a copy at the drive's root, under
  ProgramData or in the job's own folder, and a one-file packing are each refused with the name said.
- The rig asks it at every run of a copy in Program Files and of one in the job's folder (X49).

To update:
- As 0.2.0's entry says, by how Raqib was installed (`git pull`, then `pipx install --force .`, or
  `pip install --upgrade .` in the same venv, or `py -m pip install --upgrade .`; the service's copy as there:
  `sudo cp -r . DIR/src-NUMBER`, `sudo DIR/bin/pip install --upgrade DIR/src-NUMBER`,
  `sudo DIR/bin/raqib service install`). First stop a running watch, window or service.
- Then `raqib --version` says the number at the top of this file.
- Nothing else changes for a watch, a window or the Linux service. The new check is asked only when a person
  runs it.

Not measured:
- A Raqib run by a plain interpreter (installed with pip) is not checked yet: the command says so and exits 2,
  never a pass. Its road is the next task; python.org's installer for all users was measured for it.
- Nothing installs a service of Windows yet (`raqib service install` there is still to come), so nothing asks
  the check before a service runs; a person does.
- Not read by the check: rights a user holds apart from any list (backup and restore, taking ownership); the
  packed runtime's own roads outside its folder, if a packer gives it any; the system's PATH; what a drive's
  letter really names (a letter given to a folder reads as a drive of its own).
- A machine joined to a domain, a removable or shared drive, Program Files with lists an administrator
  changed, and a denying entry that still lets the asker read, on a real machine.

## 0.10.0 - 2026-11-27

What is new:
- A watch that starts after one that ended without its end says so (ADR-0013 Amendments H to J), on every
  system. A watcher that was ended from outside, a crash, a power loss: each leaves the watch's state unfinished,
  and until now the next watch took over in silence. It now says a hole of its own at its start - the run
  before, its pid, its last heartbeat, and for how many seconds no watch of this home is known to have watched -
  in its report, in its state and in the events a collector takes. The result of that run is then not clean
  (exit 3 where nothing else makes it 1).
- A state file that is there and cannot be read (empty, torn) is said too: whether a watch ended without its end
  is then not known, and the watch says exactly that instead of nothing.
- The hole is written to the events before the new watch's state replaces the old one, so a watch ended again
  in its first seconds still leaves the earlier gap in a record that lasts.
- The Windows service waits for an old state to go stale instead of stopping: ended from outside and started
  again by the system, it watches again without a person. Measured on GitHub's Windows machines, x64 and ARM64:
  a round was read again 31 s after the process was ended, the text file saying the wait before it and after
  it, the hole in the events naming the ended run.
- The rig ends the service's process at every run and reads all of this as a claim (X48).

To update:
- As 0.2.0's entry says, by how Raqib was installed (`git pull`, then `pipx install --force .`, or
  `pip install --upgrade .` in the same venv, or `py -m pip install --upgrade .`; the service's copy as there:
  `sudo cp -r . DIR/src-NUMBER`, `sudo DIR/bin/pip install --upgrade DIR/src-NUMBER`,
  `sudo DIR/bin/raqib service install`). First stop a running watch, window or service.
- Then `raqib --version` says the number at the top of this file.
- After this update, the first watch on a machine where a watch was once ended without its end (a machine
  switched off while it watched is one way) says the new hole once and ends with 3. That is the gap being said, not a fault.

Not measured:
- The half minute itself: a watch still takes an unfinished state for a living watch until its heartbeat is 30 s
  old, so about 30 s pass unwatched after a watcher is ended. Taking over at once where the old process is gone
  is recorded and not built.
- The hole of a state that cannot be read, and a start ended before its first round, on a real machine; what a
  power loss leaves of the state file; how systemd reads a unit that ends with 3 after such a start.
- A state file removed before the next start: the watch before is then said nowhere.
- There is still no `raqib service install` for Windows: the system is told to start the service again only by
  whoever made the service.

## 0.9.0 - 2026-11-27

What is new:
- On Windows the host watch can run as a real service of the system's: `raqib service run` (ADR-0013 Amendments
  E to G). It is the part the system's service manager runs - there is no `raqib service install` for Windows
  yet, so this number changes nothing a person does by hand; it is the first of three steps.
- It is built with Python's standard library alone: no new dependency, no compiled helper. Measured on GitHub's
  Windows machines, x64 and ARM64, plain and packed: the system starts it in about a second, a Stop takes a
  quarter of a second, and the watch ends with its whole final report, as on Ctrl+C.
- Its record lives in a place of its own, `Raqib` under ProgramData, made closed to everyone but the system and
  the administrators in the one call that makes it. Measured: a plain user could not write into it, read it,
  list it, stop the service or end its process.
- It refuses rather than repairs. A folder already there that it did not find closed and owned by the system
  or the administrators - one a plain user made first, an open one, a link, a file - is left exactly as it is
  and the service does not start. Measured: the start command fails at once, and the system's own log holds the
  refusal's number.
- Nothing changes on Linux or macOS but one line: `raqib service run` says it is Windows'.

To update:
- As 0.2.0's entry says, by how Raqib was installed (`git pull`, then `pipx install --force .`, or
  `pip install --upgrade .` in the same venv, or `py -m pip install --upgrade .`; the service's copy as there:
  `sudo cp -r . DIR/src-NUMBER`, `sudo DIR/bin/pip install --upgrade DIR/src-NUMBER`,
  `sudo DIR/bin/raqib service install`). First stop a running watch, window or service.
- Then `raqib --version` says the number at the top of this file.

Not measured:
- A service killed and started again by the system: measured before this number, the new watch refuses for 30
  seconds because the killed one's state still reads as a living watch, and the service then stays stopped.
  That is the next task; until it lands, do not rely on the system starting it again.
- A shutdown of the machine; the service's start at boot; another account than the system's; a machine joined
  to a domain or with an endpoint protection product; Windows before the versions GitHub's machines run.
- Nothing yet checks that the code the service runs can be written only by the system and the administrators:
  that is the install's, as on Linux.

## 0.8.2 - 2026-11-27

What is new:
- A Raqib packed with its own runtime hands nothing of its packer to the programs it starts (ADR-0007 Amendments
  CI to CK). Measured first on GitHub's Windows, Linux and macOS machines: a packed start reads none of the ten
  interpreter's variables tried, but it adds the packer's own names to its environment - on Linux its own folder
  first on the loader's search path - and on Windows it sets the folder the system searches first for a library
  to its own; both reached what it started. Now the helper is started with the watch's environment as the watch
  was handed it, and on Windows Raqib's entry puts that folder back to none at its start.
- Where that call fails on Windows, the `raqib` command says so at once on its error stream, and the host watch
  says it once at its start as a blind spot that does not change the result. Never silent, never fatal.
- A test reads Raqib's own source and fails on a start of a program that hands on a whole environment by any
  road but that one; it holds the seven starts it finds.
- The threat model says what is not held: the loader's own variables are read by the system before the first
  line of Raqib, packed or plain. The defence is who starts the watch - the system's service manager, not a
  shell an agent holds.
- A Raqib that is not packed does exactly what it did: nothing changes for an install by pip or pipx.
- Measured with this number's code, packed, on the three systems: on Windows the folder searched first was the
  packed program's before the entry ran, none after it, and none for a program started after it; a program
  started with the cleaned environment saw exactly the environment the packed program was handed; on Linux the
  packed helper started as a start of its own and the watch's five asks were answered.

To update:
- As 0.2.0's entry says, by how Raqib was installed (`git pull`, then `pipx install --force .`, or
  `pip install --upgrade .` in the same venv, or `py -m pip install --upgrade .`; the service's copy as there:
  `sudo cp -r . DIR/src-NUMBER`, `sudo DIR/bin/pip install --upgrade DIR/src-NUMBER`,
  `sudo DIR/bin/raqib service install`). First stop a running watch, window or service.
- Then `raqib --version` says the number at the top of this file.

Not measured:
- No package and no installer exists yet.
- The packed window (`raqib-app`): its own entry makes no such call on Windows; a host watch run from it says so.
- The call failing on a real Windows machine; a starter that hands the packer's own names together, an empty
  loader's path, or a loader's variable that names a folder with a library in it.
- Another packer, another version of this one (PyInstaller 6.11.1 was read), or one file instead of one folder.
- On macOS the watch, packed or not, still reads the homes only: it has no reader there yet.

## 0.8.1 - 2026-11-26

What is new:
- A Raqib packed with its own runtime keeps its process events on Linux (ADR-0007 Amendments CG and CH). Packed
  into one folder so that a machine needs no Python - the first step toward packages a person installs with
  one command - the host watch lost the kernel's process events: its helper was started as "this Python, run
  that program", and a packed program is no Python. The watch said so itself (two asks, no answer, a blind
  spot each time). A packed Raqib now starts its helper as itself.
- A Raqib that is not packed starts its helper exactly as before; nothing else changes in this number.
- Measured on GitHub's machines: packed, Raqib is 24.5 MiB on Windows, 59.2 MiB on Linux and 40.4 MiB on macOS,
  starts in 0.1 to 0.2 s, and its watch holds 34 to 39 MiB of memory (read while the Linux helper was dead: a
  living packed helper adds about 34 MB, a plain one about 15). On the rig's Linux machine, as a user that is
  not root, a Raqib packed there answered four asks of four and heard the processes started beside it (the
  claim X47).

To update:
- As 0.2.0's entry says, by how Raqib was installed (`git pull`, then `pipx install --force .`, or
  `pip install --upgrade .` in the same venv, or `py -m pip install --upgrade .`; the service's copy as there:
  `sudo cp -r . DIR/src-NUMBER`, `sudo DIR/bin/pip install --upgrade DIR/src-NUMBER`,
  `sudo DIR/bin/raqib service install`). First stop a running watch, window or service.
- Then `raqib --version` says the number at the top of this file.
- A machine with more than one install (a virtual environment and the system's Python, say) is updated one
  install at a time: `raqib --version` of each says which is which.

Not measured:
- No package and no installer exists yet: this number is the first thing they need, not they.
- What a packed program reads of the environment at its start, and what it hands to the outside programs a
  watch starts: the plain helper is isolated from the environment, the packed one is not.
- The window and the service packed; a packed watch over hours; Windows on ARM64 packed.
- On macOS the watch, packed or not, still reads the homes only: it has no reader there yet.

## 0.8.0 - 2026-11-21

What is new:
- On Linux a short child is judged by everything it ran, and by the name it was called by (ADR-0007 Amendments
  CC to CF). A child's line names every program its process ran while the process events heard it (the newest
  eight; more are counted and said), so the command a shell runs in its own place (`bash -c "...; curl ..."`)
  is judged whenever it runs, in the round of the shell's line or a later one. Where the kernel's name for a
  process differs from its file's, the line names both: `nc`, whose file on Ubuntu is `nc.openbsd`, is judged
  as `nc`.
- A process is its maker's child. Where the process events heard a process made, the process that made it is
  its parent, though a sample already holds it under pid 1: what a tree starts through a shell that returns
  at once - a command left in the background - is the tree's child, is kept, and what it runs later is the
  tree's, also in a round where the tree itself is quiet.
- A program run through `sudo` gets a line. A plain reader cannot read the file of a process that runs as
  another user; until now such a child had no line at all. It is now named by the name the kernel gave it,
  and its line says that its file was not read (`files_unread`).
- Said, not hidden: a tree that has ended is written nothing, and how many processes its kept children were
  heard to start is in the report's PROCESS EVENTS section and is a hole of the result.
- Measured on GitHub's Linux machine (kernel 7.0; the rig's X43 to X46, each by the child's own entry in its
  line and a NET-TOOL finding that cites that line): the fetch a `bash -c` ran in its own pid a round after its
  own line; `nc -z`, named `nc`; the fetch of a bash that outlived the `sh` that started it; the same fetch
  run through `sudo -n`, its file not read. The first run of X45 was MISSED: that is how the maker's rule came.

To update:
- As 0.2.0's entry says, by how Raqib was installed (`git pull`, then `pipx install --force .`, or
  `pip install --upgrade .` in the same venv, or `py -m pip install --upgrade .`; the service's copy as there:
  `sudo cp -r . DIR/src-NUMBER`, `sudo DIR/bin/pip install --upgrade DIR/src-NUMBER`,
  `sudo DIR/bin/raqib service install`). First stop a running watch, window or service.
- Then `raqib --version` says the number at the top of this file.
- Nothing changes on Windows in this number.

Not measured:
- Under an act-root - an agent that holds no connection at a sample - the sample's parent still stands: what
  its shell leaves in the background is nobody's, as before. Ruled so until a desktop's measure; the next task.
- What a short child talks to, and a tree that lives whole between two samples: not seen yet (the next task).
- A tree kept alive by the children it left: today the tree ends and its children's later acts are counted,
  not written.
- A name is the process's own to choose: a tool run through `sudo` under another name is missed, and a
  process can call itself by a tool's name it is not (its tree then alarms by its own doing).
- A desktop's ordinary work for an hour: what these lines add to HOST-RHYTHM's and NET-TOOL's findings.
- Pid reuse, a tree that has gone, the bounds of 8 programs and 512 kept children: on made-up rounds only.
- How often the reader loses its race with a process that ends before it is read. On the rig's last run before
  this number one `nc` of 14 short acts was gone before the reader read anything of it (its record given, its
  program and name said as not read, so no line; the claim X31 MISSED); the same commit run again gave 14 of
  14, as every run before had. The watch counts such a child in PROCESS EVENTS (programs not read); the rate
  on a real desktop is not measured.

## 0.7.0 - 2026-11-21

What is new:
- The read of Windows' autostart places is made fit for a watch (ADR-0014 Amendments I to L). `python -m
  raqib.autostart` now keeps what every place, and every key inside it, last held, and says each change by its
  kind: an entry added, changed or removed; a task rescheduled (its triggers moved, its actions the same); a
  user's hive loaded or unloaded, as one change and not its entries; a Startup file that became a link. It
  still stands alone: the watch does not read it yet, and no rule judges a change (the next task).
- What it cannot say it says. A place the read's deadline cut, a key refused, a key or folder of more than a
  thousand entries, a file held open by its maker: each is said as not read, at each read, and nothing in it is
  said added or removed for having been out of reach. A part read for the first time late is taken as it is and
  said once as that, never as hundreds of entries planted.
- It does not get in the way: a Startup file is opened with every sharing and never through a link, and each
  read begins one place further than the last, so that one slow key cannot keep the others unread.
- A program's name is said `would run` where the text names one program however it is read, `may run` where it
  does not. Every hash is salted anew by each process, so that two runs cannot be set side by side.
- Measured on GitHub's Windows machines: a file held open with no sharing is said as added by the read made
  while it was held and read after it was let go; a real symbolic link is read as a link; a file the module
  holds is renamed and deleted by another call; of 687 services' texts 685 are `would run` (before the ruling
  that measured it, 444 of 689); the stand-in's Run value, Startup file and service each said added and later
  removed in 42 reads, the longest 0.125 s (X37 on the rig).

To update:
- As 0.2.0's entry says, by how Raqib was installed (`git pull`, then `pipx install --force .`, or
  `pip install --upgrade .` in the same venv, or `py -m pip install --upgrade .`; the service's copy as there:
  `sudo cp -r . DIR/src-NUMBER`, `sudo DIR/bin/pip install --upgrade DIR/src-NUMBER`,
  `sudo DIR/bin/raqib service install`). First stop a running watch, window or service.
- Then `raqib --version` says the number at the top of this file.

Not measured:
- No read on a real machine met the deadline or a bound (the longest took 0.219 s): the cut, the turn of the
  places and of the users, the bound of a thousand and a base taken late have run on made-up registries only.
- A real desktop: how often Windows itself changes a service or a task (one change of a service that nobody of
  the rig made was seen once), and so what a rule on these changes would cost.
- An open by another process that asks for no sharing while the read holds a file; a file swapped for a link
  between the listing and the open; a reparse point that is not a symbolic link; a hive loading at a logon.
- Whether a plain user can deny its own Run key to a reader of another identity while Windows still runs it
  (the service's case).

## 0.6.0 - 2026-11-21

What is new:
- Ready content for a SOC's search engine, under `siem/` (ADR-0017 and its Amendments A to C): for Elasticsearch
  and for OpenSearch an ingest pipeline and an index template that turn each line of the events file into one
  document - an event with the fields EVENT.md's Mapping names, or an error document that keeps the whole line
  and says why it is no event; none is dropped. Seven searches: every alarm, one rule's findings, the holes, the
  watches that did not end clean, the lines kept as error documents, the hosts that went silent, and the runs
  that stopped with no end. Nine Sigma rules with a pipeline of names, and a table and an ATT&CK layer of every
  rule the report lists. `siem/README.md` says how to install each and what the content trusts.
- Silence is judged by the engine's own clock against a deadline every line gives - its arrival and two of its
  own heartbeat's interval, an interval counted as a day at most - so no time is given by the person who asks,
  and a host's clock cannot hide it.
- Measured on GitHub's Linux machine against Elasticsearch 8.15.3 and OpenSearch 2.17.1 (the rig's claims X39 to
  X42, each run): 111 lines sent, none refused - the real watch's own file, every example of the spec, made-up
  events of each rule's class with a near miss for each, 23 malformed lines (each an error document with the
  reason the page names, and the line after it kept), and a shipper's own fields kept or moved aside; every
  search equal to a count made apart from the engine, the two searches of silence at four moments; each Sigma
  rule, converted by pinned tools, matching its own event and not its near miss.
- Nothing of the watch itself changes in this number: the same events, the same rules.

To update:
- As 0.2.0's entry says, by how Raqib was installed (`git pull`, then `pipx install --force .`, or
  `pip install --upgrade .` in the same venv, or `py -m pip install --upgrade .`; the service's copy as there:
  `sudo cp -r . DIR/src-NUMBER`, `sudo DIR/bin/pip install --upgrade DIR/src-NUMBER`,
  `sudo DIR/bin/raqib service install`). First stop a running watch, window or service.
- Then `raqib --version` says the number at the top of this file.
- The content is not installed with Raqib: it is files of the checkout, installed on the engine as
  siem/README.md says (the pipeline and the template before the first line reaches the index).

Not measured:
- Splunk, Microsoft Sentinel and Wazuh: no content for them yet (the next tasks), and nothing of this content
  was run on them. The Sigma rules were converted and run for Elasticsearch and OpenSearch only.
- A real shipper tailing the file on a host (Filebeat, Fluent Bit, Logstash): the rig sends the lines itself.
  A shipper's field of another shape than the ones the page names may make an engine refuse a line.
- Volume, more than one node or shard, retention, an engine with its security on, and either search of silence
  run on a schedule with an alert: each engine has its own way, and none was set up here.
- The two days a forged heartbeat can keep a host off the search for silence, and a bound of 10000 hosts or
  runs being met: ruled and said, not run.
- The ATT&CK layer was never loaded into a Navigator.

## 0.5.0 - 2026-11-21

What is new:
- On Linux, a program that starts and ends between two samples is judged (ADR-0007 Amendments BY to CB). The
  watch's helper hears the kernel's process events; each round takes the processes it heard, and one that began
  under a tree that talks at a sample is that tree's child: it gets its line, and NET-TOOL and DESTRUCT-CMD
  judge it by the name of its program's file. Measured on GitHub's Linux machine: a `wget` that lived under a
  second is a NET-TOOL finding of its tree. Until now such a program was not seen at all on Linux.
- The report's PROCESS EVENTS section says what was given to the rounds, what was joined to a tree, what the
  watch left out as its own, and every way the reader was not whole; a reader that was late, ended, lost
  events or held back a rest after it had answered is a hole of the result, so the result says INCOMPLETE
  unless a finding makes it an alarm.
- A line of a tree's children says where each was seen (`command_sources`: the sample, the process events, or
  both), in a round that heard the reader.

To update:
- As 0.2.0's entry says, by how Raqib was installed (`git pull`, then `pipx install --force .`, or
  `pip install --upgrade .` in the same venv, or `py -m pip install --upgrade .`; the service's copy as there:
  `sudo cp -r . DIR/src-NUMBER`, `sudo DIR/bin/pip install --upgrade DIR/src-NUMBER`,
  `sudo DIR/bin/raqib service install`). First stop a running watch, window or service.
- Then `raqib --version` says the number at the top of this file.

Not measured:
- Three things a child can do and not be judged, said in the report and the guide, measured for the next step:
  it changes its program after its line was written (a shell that runs its last command in its own place, in
  a later round); its parent was given in an earlier round and has ended; its program's file is not called as
  the tool is (on Ubuntu 24.04 `nc` is the file `nc.openbsd`, `telnet` is `inetutils-telnet`, `ftp` is
  `tnftp`), so a rule's list of names can miss it.
- A tree that lives whole between two samples, and what a short child talks to: not seen yet (the next tasks).
- A desktop's ordinary work for an hour: how many findings the short children add (HOST-RHYTHM counts them as
  acts now).

## 0.4.0 - 2026-11-21

What is new:
- A chain in the events file (ADR-0016 and its Amendments A and B). Every event a host watch writes names the
  line its run wrote before it by that line's sha256 (`prev`; the run's first line says `first`). `raqib events
  FILE` says of each run whether its chain is whole, where it breaks (a line removed, changed, added or moved),
  which lines stand beside it, whether the run begins before the file, and whether a chain was taken out of a
  run whose version always writes one. A line of an older Raqib holds no `prev`: its run is said as not
  chained, which is not a problem.
- `raqib events FILE --against OTHER`: the lines a collector holds, side by side with the host's file, by host
  and id: which are in the file byte for byte, which are not there, which are there with other bytes. This is
  how a line changed on the host after the collector took it is seen; it needs the collector's lines as they
  were sent.
- No line of the events file can end `raqib events` or the forwarder: a line nested too deep, or with values
  that cannot be checked, is named and passed over.
- The events' schema keeps its name (`raqib-event/1`): `prev` is an addition, and a reader of the file must
  allow a key it does not know (the spec says so now).

To update:
- As 0.2.0's entry says, by how Raqib was installed (`git pull`, then `pipx install --force .`, or
  `pip install --upgrade .` in the same venv, or `py -m pip install --upgrade .`; the service's copy as there:
  `sudo cp -r . DIR/src-NUMBER`, `sudo DIR/bin/pip install --upgrade DIR/src-NUMBER`,
  `sudo DIR/bin/raqib service install`). First stop a running watch, window or service.
- Then `raqib --version` says the number at the top of this file.
- A run that began under an older Raqib and is still in the file stays as it is; the chain begins with the
  first watch started after the update.

Not measured:
- What the chain does not prove is not a measurement, and is said here all the same: the chain holds no
  secret. Whoever can write the file can cut its end, write a tail again with its hashes,
  or take a chain out and write an older version on its lines: the file alone then looks whole. The run's last
  line is named by no line. A collector that kept its lines sees a change of what it holds, by `--against`.
- A real collector's export brought back as lines (Splunk, a syslog server, the journal): whether its bytes are
  the bytes that were sent.
- `raqib events` on a very large file: it holds the file in memory.

## 0.3.0 - 2026-11-20

What is new:
- Raqib can read Windows' autostart places by itself, with no Sysmon and no right asked (ADR-0014 Amendments G
  and H; docs/specs/AUTOSTART.md): the Run and RunOnce values of every loaded user's hive and the machine's,
  the Startup folders, the services, the scheduled tasks where its rights give them, and Winlogon's Shell and
  Userinit. `python -m raqib.autostart --rounds N --every S` says what each read holds and each entry added,
  changed or removed between two reads, by its place, its name and the program it would run; never a value's
  text, a file's content or a SID. A place the rights refuse is said as refused, never read as empty.
- The watch does not read it yet and no rule judges it yet: that is the next step on this track (M15.3b).
- The rig makes a service that is never started, beside its Run value and its Startup file, and claims that
  the read sees each appear and go (X37).

To update:
- As 0.2.0's entry says, by how Raqib was installed (`git pull`, then `pipx install --force .`, or
  `pip install --upgrade .` in the same venv, or `py -m pip install --upgrade .`; the service's copy as there:
  `sudo cp -r . DIR/src-NUMBER`, `sudo DIR/bin/pip install --upgrade DIR/src-NUMBER`,
  `sudo DIR/bin/raqib service install`). First stop a running watch, window or service.
- Then `raqib --version` says the number at the top of this file.

Not measured:
- A real desktop: how often an updater makes its own task or service with nothing done, and how long a read
  takes with thousands of services (on GitHub's machine: 39 reads, the longest 0.157 s).
- What two reads can say that is not so (an entry that first appears while its place is unread; a hive loaded
  between two reads): said in the spec, ruled before the watch reads this.

## 0.2.0 - 2026-11-20

What is new:
- The number itself (ADR-0015). `raqib --version`, the first line a watch prints, the first line of its report
  and the window's title bar say `raqib 0.2.0`. A script that matched one of those lines whole must now match
  its beginning.
- Three rules that judge what an agent's tree does to the host, whatever its programs are called (ADR-0014).
  PERSIST-AUTOSTART: a file written in a Windows Startup folder. NET-ADMIN-PORT: a connection a process of the
  tree makes to a login or administration port (22, 23, 135, 445, 3389, 5900, 5985, 5986) of a private
  address. PERSIST-RUN-KEY: a value set under a Run or RunOnce key of the registry. Each is high and knocks.
  They read Sysmon's events on Windows; on Linux nothing reads for them yet.
- What the watch could not read for those rules is said (ADR-0014 Amendments E and F): once, when three rounds
  read no file event of the channel, and as the blind spot `registry` when the channel held no registry value
  at the watch's first read. Both say what may be unseen, never that nothing was done.
- A fault found and fixed (ADR-0007 Amendment BV): Sysmon can let go of a process that still runs, and then
  names it by an empty ProcessGuid in its children's starts. Raqib took the zeros for a process of its own,
  lost the children's lines and took the tree for quiet, in silence. Such an event is now joined by the pid it
  names, and the watch says so when it happens.
- Linux's process events (raqib/procevents.py, ADR-0007 Amendments BQ to BX): a helper process of the watch's
  own hears the processes that start and end between two samples, with program, parent and exit code, asking
  no right. The report counts them under `PROCESS EVENTS (Linux)` and says what the helper lost. Nothing is
  judged from them yet: on Linux a process that ends between two samples is still not judged.
- The rig asks a stand-in for the three rules on GitHub's Windows machine at every push (X32 to X34), and for
  the reader and its helper on Linux (X31, X35). A claim it misses is reported; it does not fail the push.

To update:
- In the checkout's folder. First stop a running watch, window or service: a running one keeps the number it
  started with.
- `git pull`
- Installed with pipx, on Linux or Windows: `pipx install --force .`
- Installed with pip: `pip install --upgrade .` in the same venv; with Windows' launcher,
  `py -m pip install --upgrade .`
- The Linux service (root's copy, docs/specs/SERVICE.md), with DIR its folder and NUMBER this entry's: a new
  copy of the checkout for each number, `sudo cp -r . DIR/src-NUMBER`, then
  `sudo DIR/bin/pip install --upgrade DIR/src-NUMBER` and `sudo DIR/bin/raqib service install` again (it writes
  the unit again and restarts it).
- Then `raqib --version` says the number at the top of this file. A watch with rules of your own measures its
  thresholds again at its first start after an update, and says so.

Not measured:
- How often the three rules fire on a real desktop's ordinary work (their budgets stand on a corpus that
  holds none).
- Whether Sysmon always logs a process's start before the value it sets.
- How long the watch's one question for the registry's values takes on a full channel that holds none
  (ADR-0014 AF-4): a slow answer can make the first round late.
- The helper under a real desktop's load: on GitHub's machines it missed 0 to 2 of 200 programs that live
  under a millisecond, and it counts what it knows it lost.
- The update steps of the service's copy: written from the service's spec, not run on a machine.

## 0.1.0 - before 2026-11-20

Every copy before this file said 0.1.0, whatever it held: the host watch, the rhythm, the catalog of fourteen
rules, the window, the events and their forwarder, the service's first stage. Two such copies could be told
apart only by their sentences (seen in the field on 2026-11-20). From 0.2.0 on the number moves.
