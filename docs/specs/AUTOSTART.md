# AUTOSTART - the autostart places, read by Raqib itself

Rulings: ADR-0014 Amendments G (AG-1 to AG-5), H (AH-1 to AH-8) and I (AI-1 to
AI-11). Stages: M15.3a, the read standing alone; M15.3b, the read made fit for
the watch (`raqib/autostart.py`, `python -m raqib.autostart`). Nothing of the
watch reads it yet: the watch's reading, its host lines and the three rules
that judge a change are M15.3c.

## What is read (AG-1, AI-7)

On Windows, by the standard library alone (`winreg` and `ctypes`, imported
inside the calls; `os.scandir`), in the reading process, read-only, no helper
process, no right asked, no network call:

| place | scope | where | an entry | its content (hashed) | `program` |
|---|---|---|---|---|---|
| `run`, `runonce` | user | `HKU\<SID>\Software\Microsoft\Windows\CurrentVersion\Run` and `\RunOnce`, every loaded hive named by a SID, one view | a value | its type and data | the program its text would run |
| `run`, `runonce` | machine | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` and `\RunOnce`, the 64-bit view and the 32-bit view, each its own | a value | its type and data | the program its text would run |
| `startup` | user | `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` | a file directly in it | the file | None |
| `startup` | machine | `%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup` | a file directly in it | the file | None |
| `service` | machine | `HKLM\SYSTEM\CurrentControlSet\Services\<name>` | a key with an `ImagePath` | `ImagePath`, `Start`, `Type` | the program `ImagePath` would run |
| `task` | machine | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree`, every key with a value `Id`, to 32 deep | a task | `Actions` of `...\TaskCache\Tasks\<Id>`; its `Triggers` hashed apart | None |
| `winlogon` | machine | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` | `Shell`, `Userinit` | its type and data | the first program its list names |

- The users' hives are read under `HKU` by their SID: a hive named
  `<SID>_Classes` is left out, `HKU\.DEFAULT` is left out (it is the hive of
  `S-1-5-18`, read under that name), and `HKCU` is not read a second time (it
  is one of the SIDs). A user's hive is read in one view (AI-7): its Run key is
  one key in both views (measured).
- The machine's 32-bit view is another key (`Wow6432Node`): its values are
  always entries of their own (`view32` true), never folded with the 64-bit
  view's (AI-7). A value held in both views is two entries; when the 64-bit
  one changes, only it is said.
- The Startup folders: the files directly in each (a folder in it is not
  entered), `desktop.ini` left out (as ADR-0014 A-3). The user's folder is the
  reading user's (`APPDATA`); where `APPDATA` or `ProgramData` is not set, the
  place is `failed` and says so. A folder on a share - a UNC path (`\\host\x`,
  `\\?\UNC\...`), or a drive Windows calls remote (`GetDriveTypeW`) - is not
  listed and no file in it is opened (AI-4; CLAUDE.md rule 5): it is a key not
  read, `on a share`. A folder whose drive's kind cannot be told is not read
  either, and says so.
- A Startup file is opened for reading with read, write and delete sharing
  (`CreateFileW` with `FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE`,
  by `ctypes`), so that another process's delete or rename of it does not fail
  while it is read (AI-3; ADR-0011 A: Raqib does not hinder what it watches).
  Where it cannot be opened so, it is not opened: its content is not read, and
  the place says `it cannot be opened with every sharing`.
- The services: every key under `Services` is opened; one with no `ImagePath`
  (a key of settings, a group) runs nothing and is not an entry.
- The tasks: the scheduler's tree in the registry is walked, 32 folders deep; a
  deeper one is counted as a key not read and the place says `partly` (AH-2). A
  task's body is the binary `Actions` and `Triggers` of its `Tasks\<Id>` key:
  `sha256` is the actions' hash, `triggers` the triggers' (AI-5). The binary
  is not parsed: a task's `program` is None.

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
  (binary, a number), names no such program, or was not read. A Winlogon value
  is a list split on commas outside quotes: its first item is named
  (`C:\Windows\system32\userinit.exe,` names `userinit.exe`).
- `sure` (AI-8): false where the name may not be what runs - an unquoted text
  whose first word holds a separator (`\` or `/`) and is followed by a blank
  (Windows tries the longer paths too: `C:\Program Files\x.exe` names
  `Program`, not sure), or a Winlogon list of more than one program. True for
  a quoted path, a text of one word, and an unquoted text whose first word holds
  no separator (`cmd /c ...`). None where there is no program. A sentence says
  `may run` where it is false, `would run` where it is true.
- `sha256`: the content's hash (for a value: its type and its data; for a
  file: the file; for a service: its three values; for a task: its actions).
  None where the content was not read.
- `triggers`: a task's triggers' hash; None for every other entry.
- `key`: a hash of where the entry is (the place, the hive, the view, the name
  in full), by which reads are compared; `part`: a hash of the key or folder it
  was read from, the base of a comparison (AI-1).

Every hash is keyed (HMAC-SHA256) with a salt (AI-9): a Watcher's own, random
(32 bytes), made when it is made, kept in it alone, never printed, written or
returned; a read made without a watcher takes the process's own salt, made
once. A key or a content's hash therefore cannot be matched by trying a SID, a
name or a text, nor between two machines or two watchers; two reads compare
only under one salt. A content is hashed by its length and its first 64 KiB
(AI-4): a value's data, a file. A file is read no further than that; two
contents of one length that differ only after their first 64 KiB have one hash.

A name is text its maker chose. Where it holds a SID (a per-user task of an
updater does), the name shown holds `[sid]` in its place (AH-1); the `key`
holds the name as it is, so two entries that differ only there stay two. A
user's name that a maker put into an entry's name cannot be told from any other
word and is shown as it is.

A value's text, a file's content, a SID and a user's name stay in the reading
process's memory and leave it only as a salted hash: nothing `read` returns or
the command prints holds them. A reason of a failed read is its error's kind
and number alone (an error's text can hold a path, and a path a user's name).

## What the rights and the bounds do not give (AG-2, AI-4)

Each place says how it was read, in `places[place]`:

- `read`: every key asked was given (a key or a folder that is not there is
  empty, and is read; a key deleted while it is read is not there, AH-5).
- `partly`: some keys were not read; `keys_refused` says how many, and
  `keys_why` how many for each reason: `refused`, `below the depth bound`, `on
  a share: not read (...)`, `whether it is on a share is not known: not read`,
  `it cannot be opened with every sharing: not opened`. A Startup file that is
  listed and whose content is not read is an entry with `sha256` None (AI-2); a
  task whose body is refused is an entry with `sha256` and `triggers` None.
- `refused`: every key asked was refused: the place is not read, never read
  as empty. Measured: under a token whose Administrators group is deny-only,
  the scheduler's tree is refused whole.
- `unread` (AI-4): the read's deadline (5 s by default, `read(deadline=...)`)
  passed before the place was read whole, or no key of it could be read for a
  bound (both Startup folders on a share): `reason` says which. Its entries are
  not given; it is never read as empty.
- `failed`: another error, with its `reason`.

`read` never raises. Off Windows (with no registry handed in) it reads nothing,
and one sentence says so: Linux's places are ADR-0014 S4 (M15.4).

## A change (AG-3, AI-1 to AI-6)

A `Watcher` takes reads one after another (`watcher.read()`, then
`watcher.take(result)`) and gives the changes of each against its base: what
every place, and inside a place read in part every key or folder, last held
when it was read (AI-1). Its first read gives none. A place `refused`, `failed`
or `unread`, and a key not read, keep what they last held; nothing is said of
them but that they are unread. An entry that first appears while its place or
its key is not read is said as added by the first read that reads it, once.
The kinds:

- `added`, `removed`: an entry of a key read now that the key did not hold when
  it was last read, or that it no longer holds. A key or folder no longer
  listed by a parent read now is gone, and its entries are removed. A Startup
  file listed with its content not read is `added` with `sha256` None, said
  `content not read` (AI-2).
- `read`: an entry whose content was not read before is read now (AI-2): not a
  change of its content. An entry whose content is not read now keeps, in the
  base, the content it last had: nothing is said.
- `changed`: its content's hash is not the one it had (`was`); for a task, its
  actions (both its actions and its triggers: one `changed`).
- `rescheduled` (AI-5): a task whose triggers alone changed. Measured: Windows
  moves some of its own tasks by itself.
- `hive loaded`, `hive unloaded` (AI-6): a user's hive listed now that the base
  did not hold (a logon, a task run as another account), or no longer listed.
  It is one change, with the count of the entries it holds (`entries`), and its
  entries are not said one by one: they become the base, or leave it. A hive
  is never named: its change says `a user's hive`, and its `key` is the salted
  hash of its part. A value set in a hive that was already there is `added`.
  The hives are compared only where Run and RunOnce were both read (whole or in
  part). A hive the base never listed is a hive loaded, the first listing after
  the users' hives were refused too.

`changes(before, after)` compares two reads as in M15.3a: every entry added,
changed (its `sha256`) or removed; a place refused, failed or unread in either
read, or whose keys not read are not the same in both, gives no change and is
named in `unread`. It knows no part, no hive, no triggers: the Watcher is what
the watch uses.

What was there when the first read was made is the base and is never said as a
change. A change made and undone between two reads is not seen by this read
(Sysmon's lines see it where its configuration logs it).

What two reads can still say that is not so, or leave unsaid:
- An entry that an enumeration skips because another was deleted meanwhile
  reads as removed and then added (M15.3a's review, F14; not measured).
- An entry added while a key is not read and removed before it is read again is
  never said; an entry whose content changed and changed back while it was not
  read is not said either.
- A hive loaded while the users' hives could not be listed, and an entry set in
  it meanwhile: the entry is part of the hive loaded, not an entry added.

## The command

    python -m raqib.autostart [--rounds N] [--every S]

One line of the first read (entries per place, what is refused, what failed,
the bounds it met, the seconds it took); then, at each later read, taken by a
Watcher, one line per change, as

    CHANGE round 3: added service "RaqibRigService" (would run cmd.exe)
    CHANGE round 3: added run "Helper" of the user (may run Program)
    CHANGE round 3: added startup "held.cmd" of the user, content not read
    CHANGE round 4: content read startup "held.cmd" of the user
    CHANGE round 5: rescheduled task "\Vendor\Update"
    CHANGE round 6: hive loaded (a user's hive, 3 entries)
    CHANGE round 7: removed run "RaqibRigValue" of the user (would run cmd)

and one `UNREAD round N:` line where a place was not read whole, with why
(refused, failed, the deadline, the keys not read and their reasons). ASCII.
It writes no file and opens no socket. Exit 0; 2 for an argument it does not
take (`--rounds` below 1, `--every` below 0 or not a finite number).

## What is not read (AG-5)

The rule's ways round, listed: Image File Execution Options, `AppInit_DLLs`, a
WMI subscription, the policies' Run keys, Active Setup, a service's
`ServiceDll`, a COM object, a hive that is not loaded. A driver is not in
this list: it is a key of the services with an `ImagePath`, so it is an entry
of the place `service` like any other (its `Type` is in its hash), and the
stage that judges a service rules whether a driver is said apart. Also not read
by this stage: RunOnceEx and RunServices; a user's `Wow6432Node` Run key named
as such, and a user's hive in its 32-bit view; a user's own Winlogon values;
the Startup folder of a user other than the reading one; a Startup folder on a
share; the scheduler's folder of task files; a task's program (its binary
`Actions` are hashed, not parsed); a Startup link's target; a content beyond its
first 64 KiB. An entry removed is recorded and judged by no rule yet.

## Measured, and not measured

Measured before ruling Amendment G (the probe branch, GitHub's Windows machine,
the standard library alone): every place read in 0.07 s (0.24 s the first
time): the Run and RunOnce values of every loaded hive and the machine's, both
views (2 entries); the two Startup folders (3); the scheduler's tree (236
tasks, 26 of its keys refused) and its folder of files (212); the services
(687 with an `ImagePath`); Winlogon's Shell and Userinit. A quiet minute and a
half, a read every 5 s: nothing changed. Four harmless acts, each undone (a Run
value, a Startup file, a scheduled task, a service never started): each was in
the first read after it and gone from the first read after its undoing. Under a
deny-only Administrators group: the Run keys, the Startup folders, the services
and Winlogon read as before; the scheduler's tree and its folder refused whole.

Measured by the rig when M15.3a landed (GitHub's Windows machine): X37 MET, the
three acts each added and later removed, 39 reads of which the longest took
0.157 s, no place unread.

Measured before ruling Amendment I (the probe branch, GitHub's Windows machine,
the module of 0.3.0): a Startup file held open with no sharing across one read
was said by no comparison of reads made one after another (the reviewer's
reading, shown); while the module hashed a Startup file of 24 MB, a rename of
it by another handle failed 5406 times of 5406; beside the rig's stand-in, 70
reads a second apart gave the three acts each added and removed, and one change
nobody made - a task of Windows' own
(`SoftwareProtectionPlatform\SvcRestartTask`) said as changed; a quiet 90 s
had shown none.

Not measured: which part of that task changed (its actions or its triggers); a
hive loaded by a logon; a real desktop's churn (an updater that makes its own
task or service); the scheduler's own query tool under fewer rights; how long
the read takes on a machine with thousands of services, and so how often the
deadline is met; a folder of the Startup path that is a link to a share (only
the folder's own drive is asked); whether every opener of a Startup file Raqib
reads with every sharing still gets what it asks; this module's own read on a
real desktop.

The rig (`tools/rig/autostart_run.py`): a Watcher reads; the run makes a file
in the user's Startup folder (a `rem`), holds it open with no sharing across
one read, lets it go and removes it, and writes what each read said of it; then
it reads beside a run of the stand-in, which sets a Run value, writes a Startup
file and makes a service that is never started (`cmd.exe /c echo`, start on
demand), undoes each, and says whether its own delete of its Startup file
failed. X37 is MET where the stand-in's three acts are each `added` and later
`removed`, its delete did not fail, and the held file was said as `added` by the
first read that listed it; its words name every other change by its kind and
place.
