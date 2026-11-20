# AUTOSTART - the autostart places, read by Raqib itself

Rulings: ADR-0014 Amendments G (AG-1 to AG-5), H (AH-1 to AH-8), I (AI-1 to
AI-11), J (AJ-1 to AJ-8) and K (AK-1 to AK-8). Stages: M15.3a, the read standing
alone; M15.3b and its two REDOs, the read made fit for the watch (`raqib/autostart.py`,
`python -m raqib.autostart`). Nothing of the watch reads it yet: the watch's
reading, its host lines and the three rules that judge a change are M15.3c.

## What is read (AG-1, AI-7)

On Windows, by the standard library alone (`winreg` and `ctypes`, imported
inside the calls; `os.scandir`), in the reading process, read-only, no helper
process, no right asked, no network call:

| place | scope | where | an entry | its content (hashed) | `program` |
|---|---|---|---|---|---|
| `run`, `runonce` | user | `HKU\<SID>\Software\Microsoft\Windows\CurrentVersion\Run` and `\RunOnce`, every loaded hive named by a SID, one view | a value | its type and data | the program its text would run |
| `run`, `runonce` | machine | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` and `\RunOnce`, the 64-bit view and the 32-bit view, each its own | a value | its type and data | the program its text would run |
| `startup` | user | `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` | a file or a link directly in it | the file | None |
| `startup` | machine | `%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup` | a file or a link directly in it | the file | None |
| `service` | machine | `HKLM\SYSTEM\CurrentControlSet\Services\<name>` | a key with an `ImagePath` | `ImagePath`, `Start`, `Type` | the program `ImagePath` would run |
| `task` | machine | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree`, every key with a value `Id`, to 32 deep | a task | `Actions` of `...\TaskCache\Tasks\<Id>`; its `Triggers` hashed apart | None |
| `winlogon` | machine | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` | `Shell`, `Userinit` | its type and data | the program it names, where it names one |

- The users' hives are read under `HKU` by their SID: a hive named
  `<SID>_Classes` is left out, `HKU\.DEFAULT` is left out (it is the hive of
  `S-1-5-18`, read under that name), and `HKCU` is not read a second time (it
  is one of the SIDs). A user's hive is read in one view (AI-7): its Run key is
  one key in both views (measured).
- The machine's 32-bit view is another key (`Wow6432Node`): its values are
  always entries of their own (`view32` true), never folded with the 64-bit
  view's (AI-7). A value held in both views is two entries; when the 64-bit
  one changes, only it is said.
- The Startup folders: what is directly in each (a folder in it is not
  entered), `desktop.ini` left out (as ADR-0014 A-3). The user's folder is the
  reading user's (`APPDATA`); where `APPDATA` or `ProgramData` is not set, the
  place is `failed` and says so. A folder on a share - a UNC path (`\\host\x`,
  `\\?\UNC\...`), or a drive Windows calls remote (`GetDriveTypeW` 4) - is not
  listed and no file in it is opened (AI-4; CLAUDE.md rule 5): it is a key not
  read, `on a share`. A folder whose drive's kind cannot be told - no drive
  letter, `GetDriveTypeW` 0 (unknown) or 1 (no root), or no `ctypes` - is not
  read either, and says so (AJ-4). Removable, fixed, CD-ROM and RAM drives (2,
  3, 5, 6) are read.
- A Startup file is opened by the name its folder listed, in the path's long
  form (`\\?\` before the folder's own path made whole), so that Windows reads
  no other name for it - a trailing dot or blank, a device's name (AJ-4). It is
  opened asking Windows not to follow a link (`FILE_FLAG_OPEN_REPARSE_POINT`),
  and a file whose open handle says it is a reparse point is a link, its
  content not read (AK-4). It is opened for reading with read, write and delete sharing (`CreateFileW` with
  `FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE`, by `ctypes`), so
  that another process's delete or rename of it does not fail while it is read
  (AI-3; ADR-0011 A: Raqib does not hinder what it watches). Where it cannot be
  opened so, it is not opened: its content is not read, and the place says
  `it cannot be opened with every sharing`.
- A link in a Startup folder - a symbolic link or another reparse point, told
  by the listing itself (`is_symlink`, `FILE_ATTRIBUTE_REPARSE_POINT`) or by the
  open's handle - is an entry with its content not read, said `a link: not
  opened or followed`: it is never followed (it may lead to a share). A link's
  content is a fixed word of its own, hashed under the salt, so that a file that
  becomes a link under the same name, or a link that becomes a file, is said
  `changed` (AK-4). A file whose open fails for another reason, "not found"
  among them, is an entry with its content not read and that reason; only the
  folder's own listing can fail the place (AJ-4). Two names of one folder equal
  but for case are one key: the first in order is the entry, the second is a
  part not read, said `a second name of one key (equal but for case): not
  read` (AK-4).
- The services: every key under `Services` is opened; one with no `ImagePath`
  (a key of settings, a group) runs nothing and is not an entry. A driver is
  such a key too.
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
  is a list split on commas outside quotes: a list of one names its program
  (`C:\Windows\system32\userinit.exe,` names `userinit.exe`); a list of more
  than one names none (AJ-3).
- `list`: true for a Winlogon value that lists more than one program; its
  line says `(a list of programs)`.
- `link`: true for a link in a Startup folder (its `sha256` is the link's
  fixed word); its line says `a link (not opened or followed)`.
- `sure` (AI-8, AJ-3, AK-3, AL-4): whether the text names one program however it is
  read. A text is split at spaces and tabs alone (taken as how Windows splits
  a command: not measured).
  Not sure: a text that holds a blank other than a space or a tab (a no-break
  space, a line's end); a quoted first word whose name - what follows its
  last separator - holds a `%`; an unquoted first word that holds a `%` (the
  read expands nothing), but for one case (AL-4): a text of the machine's own
  (a service's, the machine's Run or RunOnce key, Winlogon) that begins with
  `%SystemRoot%` or `%windir%` and holds no other `%` in its first word, where
  the reader's own value of that variable holds no blank - the variable is then
  taken as a path with no blank and the rest is judged as any text. A user's
  own text is never taken so: the variable is the user's to set. Measured on
  GitHub's Windows machine before AL-4: of 689 services' ImagePath, 239 were an
  unquoted first word with a `%` and 4 a quoted one, and both of the machine's
  Run values were; each would have been said `may run`. An
  unquoted text where more than one run from its start to a blank or to its end
  ends in a program's extension (`C:\Sites\example.com files\tool.exe`); an
  unquoted first word that holds a separator (`\` or `/`), is followed by a
  blank and ends in none (`C:\Program Files\x\y.exe` and `C:\My Tools.exe` read
  to their first blank). Sure: a quoted first word; an unquoted one that ends in
  a program's extension - `.exe`, `.com`, `.bat`, `.cmd`, `.scr`, `.pif`, in any
  case - where no longer run does too (`C:\Windows\system32\svchost.exe -k
  netsvcs`); any other (`cmd /c ...`). None where there is no program. A
  sentence says `may run` where it is false, `would run` where it is true. The
  program's name itself is still PERSIST-RUN-KEY's reading, which splits at
  every blank (its own debt, ruled with M15.3c).
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
name or a text, nor between two machines or two watchers. A read carries
`salt_id`, a hash of a constant under its salt: it tells two salts apart and
tells neither. A Watcher takes only a read of its own salt; a read of another
is not taken, said, and changes nothing of its base (AJ-6). A content is hashed
by its length and its first 64 KiB (AI-4): a value's data, a file. A file is
read no further than that; two contents of one length that differ only after
their first 64 KiB have one hash.

A name is text its maker chose. Where it holds a SID (a per-user task of an
updater does), the name shown holds `[sid]` in its place (AH-1); the `key`
holds the name as it is, so two entries that differ only there stay two. A
user's name that a maker put into an entry's name cannot be told from any other
word and is shown as it is.

A value's text, a file's content, a SID and a user's name stay in the reading
process's memory and leave it only as a salted hash: nothing `read` returns or
the command prints holds them. A reason of a failed read is its error's kind
and number alone (an error's text can hold a path, and a path a user's name).

## What the rights and the bounds do not give (AG-2, AI-4, AJ-2)

Each place says how it was read, in `places[place]`:

- `read`: every key asked was given (a key or a folder that is not there is
  empty, and is read; a key deleted while it is read is not there, AH-5).
- `partly`: some keys were not read (a Startup file counts as one); `keys_refused` says how many,
  and `keys_why` how many for each reason: `refused`, `below the depth bound`,
  `more than 1000 entries: not read whole`, `the read's deadline (5 s) passed
  before it was reached`, `on a share: not read (...)`, `whether it is on a
  share is not known: not read`, `it cannot be opened with every sharing: not
  opened`, `a link: not opened or followed`, `not found when opened`, or an
  open's error by its kind and number. A Startup file that is listed and whose
  content is not read is an entry with `sha256` None (AI-2); a task whose body
  is refused is an entry with `sha256` and `triggers` None.
- `refused`: every key asked was refused: the place is not read, never read
  as empty. Measured: under a token whose Administrators group is deny-only,
  the scheduler's tree is refused whole.
- `unread` (AI-4): the read's deadline passed before the place was reached, or
  no key of it could be read for a bound (both Startup folders on a share):
  `reason` says which. It has no entries; it is never read as empty.
- `failed`: another error, with its `reason`.

The bounds (AI-4, AJ-2, AK-1, AK-2):
- The deadline (5 s by default, `read(deadline=...)`) is looked at before each
  place and between keys and files - before each Run and RunOnce key, each
  Startup folder and file, each service, each key of the task tree - never
  inside one call: one key's enumeration, one folder's listing, one file's open
  and read run to their end, and their time is not bounded by it. A key's
  enumeration reads each of its values whole (the 64 KiB bounds what is hashed,
  not what is read), and a folder's listing goes over every name in it (the
  bound below is of the entries compared, not of the names listed). A place the
  deadline cuts keeps what it read of itself: the keys and files it reached are
  read, the keys it did not reach are parts not read and the files listed and
  not reached are entries with their content not read, each said with the
  deadline's reason; the place says `partly`.
- There are six steps: `run`, `runonce`, `startup`, `service`, `task`,
  `winlogon`. A read begins with the step after the one the read before began
  with (the Watcher gives the read's number; a read made without a watcher
  begins with the first). Inside a step the machine's key or folder is read
  before the users': both views of the machine's Run or RunOnce key, then every
  user's; the machine's Startup folder, then the user's. The users' hives of a
  step are begun one further at each whole turn of the six steps (AL-2: not at
  each read - a turn of users that moved with the steps would give some pairs
  of step and user never). The users' hives are listed once a read, by
  whichever of `run` and `runonce` is read first.
- What a slow key still delays: in a read that reaches it, the keys after it in
  its step and every step after its step in that read are not reached. In a
  later read those are reached before it - a step that begins the read, or
  comes before the slow key's step; a user's key that the turn puts before the
  slow one. Where the slow keys are one user's own (its Run key, its RunOnce
  key, its Startup folder), every other key is read whole within six reads for
  each user's hive loaded (12 reads on a machine of two hives), unless it is
  slow itself or over the bound. What still has no turn, and is said `in part`
  at each read: a slow key inside the services' or the tasks' step delays the
  keys after it in that step in every read (those keys are the machine's: not
  measured whether a plain user can make one slow). A change is said by the
  first read that reads its key whole; a change made and undone in that time
  is not said.
- Every key whose values the read takes - a Run or RunOnce key, a service's,
  a task's key in the tree and its body, Winlogon's - and every Startup folder
  is read to a bound of 1000 entries (one more is asked, to tell that the bound
  was met; WinRegistry asks no more). Where it is met the first 1000 are given,
  the key or folder is a part not read whole, said each read as `more than 1000
  entries: not read whole`, and none of its entries is compared while it is
  over: none is said added, changed or removed for a value that was only out of
  reach (AK-1). A task's body over the bound is said on its key in the tree.
  The services' key and the task tree's folders are listed whole (each service
  and each task is its own key, under the deadline).
- A step that raises while it reads is `failed`, and the parts it had listed
  are marked not read, so that none of them is new when it is next seen (AK-5)
  - but never a hive's own part (AL-1): a hive first listed in a read whose
  Run step raised is still said `hive loaded` by that read. A `begin` that is
  not a read's number (0 or more), or a salt that is a text, gives a read
  whose places are all `failed`, never an exception.

`read` never raises. Off Windows (with no registry handed in) it reads nothing,
and one sentence says so: Linux's places are ADR-0014 S4 (M15.4).

## A change (AG-3, AI-1 to AI-6, AJ-1, AJ-5, AJ-6)

A `Watcher` takes reads one after another (`watcher.read()`, then
`watcher.take(result)`); it takes no salt and no turn from a caller (AK-5) and gives the changes of each against its base: what
every place, and inside a place read in part every key or folder, last held
when it was read (AI-1). Its first read gives none. A place `refused`, `failed`
or `unread`, and a key not read, keep what they last held; nothing is said of
them but that they are unread.

A part the base does not hold - a place, a key, a folder, a hive's keys - is
of one of three kinds (AJ-1):
- one read for the first time though it was there before (a place the deadline
  or a refusal kept from the first read, a key refused at first and readable
  now): what it holds when it is first read becomes its base, and none of its
  entries is said as added. The Watcher says once that it took a base late, per
  place, with how many keys and entries (`late`; the command's `BASE round N:`
  line), never naming a hive.
- one made under a part read before (a new service's key, a new folder of the
  tree, a Run key made where there was none): its entries are `added`.
- one of a hive loaded now: see `hive loaded`.

What appears in a part that was read before, while it is not read, is said as
added by the first read that reads it, once (AI-1). The kinds of change:

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
- `rescheduled` (AI-5): a task whose triggers alone changed.
- `hive loaded`, `hive unloaded` (AI-6): a user's hive listed now that
  the base did not hold (a logon, a task run as another account), or no longer
  listed. It is one change, with the count of the entries of its keys read now
  (`entries`), and its entries are not said one by one: they become the base,
  or leave it. A key of that hive not read now (its RunOnce failed or was cut,
  its key refused) becomes the base when it is first read, as a base taken
  late (AJ-5). A hive is never named: its change says `a user's hive`, and its `key`
  is the salted hash of its part. A value set in a hive that was already there
  is `added`. A hive listed for the first time after the users' hives could not
  be listed is a base taken late, not a hive loaded.

`changes(before, after)` compares two reads as in M15.3a: every entry added,
changed (its `sha256`) or removed; a place refused, failed or unread in either
read, or whose keys not read are not the same in both, gives no change and is
named in `unread`. It knows no part, no hive, no triggers, no salt: the Watcher
is what the watch uses. Over the bound it compares the first 1000 entries a key
gives: a shift in which 1000 those are is said there as entries added or
removed (the Watcher compares nothing of such a key).

What was there when the first read was made, and what a part held when it was
first read, is the base and is never said as a change (AG-3, AJ-1). A change
made and undone between two reads is not seen by this read (Sysmon's lines see
it where its configuration logs it).

What two reads can still say that is not so, or leave unsaid:
- An entry that an enumeration skips because another was deleted meanwhile
  reads as removed and then added (M15.3a's review, F14; not measured).
- An entry added while a key is not read and removed before it is read again is
  never said; an entry whose content changed and changed back while it was not
  read is not said either.
- An entry set in a part before that part was first read - a key refused or a
  place cut from the watch's first read on - is in its base taken late and is
  never said (AJ-1: said once as a base taken late, with its count).
- A hive loaded and a value set in it within one interval: the value is part
  of the hive loaded, not an entry added (AJ-8).

## The command

    python -m raqib.autostart [--rounds N] [--every S]

One line of the first read (entries per place, what is refused, what failed,
the bounds it met, the seconds it took); then, at each later read, taken by a
Watcher, one line per change, as

    CHANGE round 3: added service "RaqibRigService" (would run cmd.exe)
    CHANGE round 3: added run "Helper" of the user (may run Program)
    CHANGE round 3: changed winlogon "Userinit" (a list of programs)
    CHANGE round 3: added startup "held.cmd" of the user, content not read
    CHANGE round 4: content read startup "held.cmd" of the user
    CHANGE round 5: rescheduled task "\Vendor\Update"
    CHANGE round 6: hive loaded (a user's hive, 3 entries)
    CHANGE round 7: removed run "RaqibRigValue" of the user (would run cmd)

one `BASE round N:` line where parts were taken as a base late (per place, how
many keys and entries), one `UNREAD round N:` line where a place was not read
whole, with why (refused, failed, the deadline, the keys not read and their
reasons), and one `REFUSED round N:` line for a read of another salt. ASCII. It
writes no file and opens no socket. Exit 0; 2 for an argument it does not take
(`--rounds` below 1, `--every` below 0 or not a finite number). Where a reader
is handed in (a test's), the command's Watcher takes the process's own salt,
the salt of a read made without a watcher.

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
share or on a drive whose kind is not known; what a link in a Startup folder
leads to; the scheduler's folder of task files; a task's program (its binary
`Actions` are hashed, not parsed); a Startup link's target; a content beyond its
first 64 KiB; a key's values and a folder's files beyond 1000. An entry removed
is recorded and judged by no rule yet.

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

Measured by the rig on M15.3b's first build (Amendment J; GitHub's Windows
machine): X37 MET - the three acts each added and later removed, the stand-in's
delete of its Startup file did not fail, the held file said as added by the
first read that listed it with its content not read, 41 reads with the longest
0.156 s - and the one change nobody made was a task `rescheduled`: it is that
task's triggers that Windows moves by itself.

What was measured of a held file since the read opens with every sharing is
another call's rename and delete: a test that runs on Windows alone
(`test_aj7_while_the_modules_own_windows_opener_holds_a_file_it_is_renamed_and_
deleted`: while the module's own opener holds a file, another call renames it
and then deletes it, and both succeed; it passed on GitHub's Windows machine)
and the rig's held file and the stand-in's delete (X37). The read does not hold
a file against its maker's rename or delete. An open by another process that
asks for no sharing still fails while the read holds the file, for the instant
of the read: that is Windows' rule for any reader, and it is not measured. It
was not measured on a file of 24 MB again.

Run on Windows since (62e9399, GitHub's Windows machines): a real symbolic
link to a file, made in a temporary folder by the job's user, read as a link by
the listing and by the open's handle. Never run on Windows, given to the code
in tests alone: the long form's effect on a name with a trailing dot or blank
or a device's name; a file swapped for a link between the listing and the open;
a reparse point of another kind; drive kinds 0, 1 and 4; a cut by the deadline;
the turn of the steps and of the users' hives; the bound of 1000; a base taken
late; a step that raises; two names equal but for case.

Not measured: an open by another process that asks for no sharing while the
read holds the file (it fails for that instant, by Windows' rule); whether
Winlogon keeps a quoted comma inside one program's name (the read keeps it);
a hive loaded by a logon, and whether a logon gives the count the
Watcher says (AJ-8); a real desktop's churn (an updater that makes its own
task or service); the scheduler's own query tool under fewer rights; how long
the read takes on a machine with thousands of services, and so how often the
deadline is met; how long one key's enumeration, one folder's listing or one
file's open can be made to take; a folder of the Startup path that is a link to
a share (only the folder's own drive is asked); whether a plain user can deny
its own Run key or Startup folder to a reader of another identity while
Windows still runs them (AJ-8: the place would be read in part for good, and
said); this module's own read on a real desktop.

The rig (`tools/rig/autostart_run.py`): a Watcher reads; the run makes a file
in the user's Startup folder (a `rem`), holds it open with no sharing across
one read, lets it go once and removes it, and writes what each read said of it;
then it reads beside a run of the stand-in, which sets a Run value, writes a
Startup file and makes a service that is never started (`cmd.exe /c echo`,
start on demand), undoes each, and says whether its own delete of its Startup
file failed. X37 is MET where the stand-in's three acts are each `added` and
later `removed`, its delete did not fail, the read that first listed the held
file was the one made while it was held (its content not read) and said it
`added`, a later read, after the file was let go, read its content (AK-7: a
link's fixed word is not a content read), and the held file was removed after;
its words name every other change
by its kind and place, and a place read in part as read in part. A held file
the run could not remove (the run killed) is left in the folder: it holds a
`rem`, and the job's machine is thrown away after it.
