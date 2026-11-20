# AUTOSTART - the autostart places, read by Raqib itself

Ruling: ADR-0014 Amendment G (AG-1 to AG-5). Stage: M15.3a, the read standing
alone (`raqib/autostart.py`, `python -m raqib.autostart`). Nothing of the watch
reads it yet: the watch's reading, its host lines and the three rules that
judge a change are M15.3b.

## What is read (AG-1)

On Windows, by the standard library alone (`winreg`, imported inside the call;
`os.scandir`), in the reading process, read-only, no helper process, no right
asked:

| place | scope | where | an entry | its content (hashed) | `program` |
|---|---|---|---|---|---|
| `run`, `runonce` | user | `HKU\<SID>\Software\Microsoft\Windows\CurrentVersion\Run` and `\RunOnce`, every loaded hive named by a SID | a value | its type and data | the program its text would run |
| `run`, `runonce` | machine | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` and `\RunOnce` | a value | its type and data | the program its text would run |
| `startup` | user | `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` | a file directly in it | the file's bytes | None |
| `startup` | machine | `%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup` | a file directly in it | the file's bytes | None |
| `service` | machine | `HKLM\SYSTEM\CurrentControlSet\Services\<name>` | a key with an `ImagePath` | `ImagePath`, `Start`, `Type` | the program `ImagePath` would run |
| `task` | machine | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree`, every key with a value `Id`, at any depth | a task | `Actions`, `Triggers` of `...\TaskCache\Tasks\<Id>` | None |
| `winlogon` | machine | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` | `Shell`, `Userinit` | its type and data | the program its text would run |

- The users' hives are read under `HKU` by their SID: a hive named
  `<SID>_Classes` is left out, `HKU\.DEFAULT` is left out (it is the hive of
  `S-1-5-18`, read under that name), and `HKCU` is not read a second time (it
  is one of the SIDs). One hive seen under two names is one entry.
- The Run keys are read in the 64-bit view and the 32-bit view. A user's Run
  key is one key in both views (measured), so its values are counted once. The
  machine's 32-bit view is another key (`Wow6432Node`): a value there is an
  entry (`view32` true) only where the 64-bit view does not hold a value of the
  same name and the same content.
- The Startup folders: the files directly in each (a folder in it is not
  entered), `desktop.ini` left out (as ADR-0014 A-3). The user's folder is the
  reading user's (`APPDATA`); where `APPDATA` or `ProgramData` is not set, the
  place is `failed` and says so.
- The services: every key under `Services` is opened; one with no `ImagePath`
  (a key of settings, a group) runs nothing and is not an entry.
- The tasks: the scheduler's tree in the registry is walked; a task's body is
  the binary `Actions` and `Triggers` of its `Tasks\<Id>` key, hashed as they
  are. The binary is not parsed: a task's `program` is None.

## How an entry is named

An entry is a dict:

- `place`: `run`, `runonce`, `startup`, `service`, `task` or `winlogon`.
- `scope`: `user` or `machine`.
- `view32`: true for a value of the machine's 32-bit view, else false.
- `name`: the value's name, the file's name, the service's key name, or the
  task's path in the tree (`\Folder\Task`), as `os_sysmon.value_name` gives a
  value's name (ADR-0014 AB-2, AC-4): redacted (`common.redact`), one
  printable ASCII line of at most 80 characters (a longer one ends with
  `...`), a double quote written as an apostrophe.
- `program`: where the content is text, the program it would run, as
  PERSIST-RUN-KEY's line names it (`os_sysmon.registry_program`): its first
  word (a double-quoted text, else up to the first blank), its last part, and
  only where that part passes the gate a command's head passes
  (`common.HEAD_NAME`, not key-like). None where the content is not text
  (binary, a number), names no such program, or was not read. An unquoted path
  with a blank in it is named by its first word (`C:\Program Files\x.exe` gives
  `Program`), as the line names it; `Userinit`'s usual text ends with a comma
  and names no program. The name is of the first word only: a Winlogon value
  that lists more than one program, or a text whose first word Windows does not
  run as it stands, can be named by a program that is not the one that runs.
  The change itself is still said, by its hash (AH-3: ruled before a rule's
  sentence names a program from this read).
- `sha256`: of the content (for a value: its registry type, then its data; for
  a file: its bytes; for a service: its three values; for a task: its two).
  None where the content was refused.
- `key`: a sha256 of where the entry is (the place, the hive, the view, the
  name in full), by which two reads are compared. For a user's entry the hive
  is its SID, so the key is a hash over a SID; like `sha256` it has no salt: a
  key or a content's hash can be matched by whoever tries the right SID or
  text. Neither is printed by the command or written by the rig; a stage that
  writes one into a line must rule it first (ADR-0014 AH-6).

A name is text its maker chose. Where it holds a SID (a per-user task of an
updater does), the name shown holds `[sid]` in its place (AH-1); the `key`
holds the name as it is, so two entries that differ only there stay two. A
user's name that a maker put into an entry's name cannot be told from any other
word and is shown as it is.

A value's text, a file's content, a SID and a user's name stay in the reading
process's memory and leave it only as a hash: nothing `read` returns or the
command prints holds them. A reason of a failed read is its error's kind and
number alone (an error's text can hold a path, and a path a user's name).

## What the rights refuse (AG-2)

Each place says how it was read, in `places[place]`:

- `read`: every key asked was given (a key or a folder that is not there is
  empty, and is read).
- `partly`: some keys were refused; `keys_refused` says how many. The entries
  under them are not there; a task whose body is refused is an entry with
  `sha256` None.
- `refused`: every key asked was refused: the place is not read, never read
  as empty. Measured: under a token whose Administrators group is deny-only,
  the scheduler's tree is refused whole.
- `failed`: another error, with its `reason`.

`read` never raises. Off Windows (with no registry handed in) it reads nothing,
and one sentence says so: Linux's places are ADR-0014 S4 (M15.4).

## A change (AG-3)

`changes(before, after)` gives every entry `added`, `changed` (its hash; the
hash it had is `was`) or `removed`, with the entry's fields and `change`. A
place `refused` or `failed` in either read gives no change and is named in
`unread` with the reason. A place read in part in both reads is compared only
where the same keys were refused in both (a hash of the refused keys is kept
for this); else it gives no change, and `unread` says so.

What was there when the first read was made is never said as a change, and a
change made and undone between two reads is not seen by this read (Sysmon's
lines see it where its configuration logs it).

What two reads can say that is not so, or leave unsaid (the review of M15.3a;
each is ruled before the watch reads this, ADR-0014 AH-3):
- An entry that first appears while its place is unread - refused, failed, or
  read in part with other keys refused than before - is in the next read's
  base and is never said as added. A Startup file held open without sharing
  across one read does this, and any process of the user can hold its own file
  so.
- A hive that is loaded or unloaded between two reads (a logon, a task run as
  another account) reads as its entries added or removed, though nobody set or
  removed them.
- A value the machine holds with the same content in both views is one entry;
  when its 64-bit copy changes or goes, the 32-bit copy that was there all
  along is said as added.
- A key deleted while it is read is taken as not there (AH-5); an entry that
  an enumeration skips because another was deleted meanwhile reads as removed
  and then added.
- A read has no bound on its size or its time: every value and every Startup
  file is read whole at each read, and a Startup folder on a share is read
  over the network. The scheduler's folders are walked 32 deep; a deeper one
  is counted as a key not read and the place says `partly` (AH-2).
- While a Startup file is hashed it is held open: a delete or a rename of it
  by another process at that moment may fail (not measured).

## The command

    python -m raqib.autostart [--rounds N] [--every S]

One line of the first read (entries per place, what is refused, what failed,
the seconds it took); then, at each later read, one line per change, as

    CHANGE round 3: added service "RaqibRigService" (would run cmd.exe)
    CHANGE round 3: removed run "RaqibRigValue" of the user (would run cmd)

and one `UNREAD round N:` line where a place gave no change. ASCII. It writes
no file and opens no socket. Exit 0; 2 for an argument it does not take
(`--rounds` below 1, `--every` below 0 or not a finite number).

## What is not read (AG-5)

The rule's ways round, listed: Image File Execution Options, `AppInit_DLLs`, a
WMI subscription, the policies' Run keys, Active Setup, a service's
`ServiceDll`, a COM object, a hive that is not loaded. A driver is not in
this list: it is a key of the services with an `ImagePath`, so it is an entry
of the place `service` like any other (its `Type` is in its hash), and the
stage that judges a service rules whether a driver is said apart. Also not read
by this stage: RunOnceEx and RunServices; a user's `Wow6432Node` Run key named
as such; a user's own Winlogon values; the Startup folder of a user other than
the reading one; the scheduler's folder of task files; a task's program (its
binary `Actions` are hashed, not parsed). An entry removed is recorded and
judged by no rule yet.

## Measured, and not measured

Measured before ruling (ADR-0014 Amendment G; the probe branch, GitHub's
Windows machine, the standard library alone): every place read in 0.07 s (0.24
s the first time): the Run and RunOnce values of every loaded hive and the
machine's, both views (2 entries); the two Startup folders (3); the
scheduler's tree (236 tasks, 26 of its keys refused) and its folder of files
(212); the services (687 with an `ImagePath`); Winlogon's Shell and Userinit.
A quiet minute and a half, a read every 5 s: nothing changed. Four harmless
acts, each undone (a Run value, a Startup file, a scheduled task, a service
never started): each was in the first read after it and gone from the first
read after its undoing. Under a deny-only Administrators group: the Run keys,
the Startup folders, the services and Winlogon read as before; the
scheduler's tree and its folder refused whole.

Not measured: a real desktop's churn (an updater that makes its own task or
service); the scheduler's own query tool under fewer rights; how long the read
takes on a machine with thousands of services; this module's own read on a
real desktop. The rig (`tools/rig/autostart_run.py`)
reads beside a run of the stand-in, which sets a Run value, writes a Startup
file and makes a service that is never started (`cmd.exe /c echo`, start on
demand), and undoes each; X37 is MET where each is an `added` change and later
a `removed` one.

Measured by the rig when this module landed (GitHub's Windows machine): X37 MET, the three acts each added and
later removed, 39 reads of which the longest took 0.157 s, no place unread.
