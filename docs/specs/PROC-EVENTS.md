# PROC-EVENTS - the reader of Linux's process events

`raqib/procevents.py` (ADR-0007 Amendments BQ, BR, BS, BT, BU, BW and BY). On
Linux the kernel says, of every process, when it forks, when it changes its
program (exec) and when it exits. The reader listens to that, and to nothing
else: it switches nothing on, asks for no right and reads no argument of any
process. Since M14.1b a live watch on Linux runs it in a helper process of
its own and counts what it gives (see "The helper" below); since M14.1c each
round takes the processes it gave (see "The round" below), so a child that
began and ended between two samples is its tree's child. Only one reader
runs in a process (its bind is on the process's pid).

## The layout

As measured on the probe branch (GitHub's Ubuntu 22.04 with kernel 6.8,
and 24.04 and 26.04 with kernel 7.0), with the standard library alone:

- a socket of AF_NETLINK, SOCK_DGRAM, protocol 11 (the connector), bound to
  the reader's pid and group 1 (the connector's group of process events);
- one message asks to listen: a netlink header of 16 bytes (`=IHHII`:
  length 40, type 3, flags 0, seq 0, the reader's pid), a connector header
  of 20 bytes (`=IIIIHH`: idx 1, val 1, seq 0, ack, len 4, flags 0) and the
  u32 1 (listen). At its stop the reader sends the same message with the
  u32 2 (ignore), then closes the socket;
- the kernel answers the ask: an event of `what` 0 whose u32 at 16 is an
  errno (0: the ask was taken), its connector ack the ask's plus 1. The
  ask's ack is a mark of 4 random bytes (`os.urandom`), and only the answer
  that carries the mark plus 1 is the reader's. `start()` waits up to 2 s
  for it: a kernel that takes the ask and says nothing is a refusal, not a
  silence;
- an event is a netlink header, a connector header, then `what` u32, cpu
  u32 and the kernel's time u64 (`=IIQ`; the reader puts it on the wall
  clock), then its data at 16: fork (`what` 0x1) parent pid, parent tgid,
  child pid, child tgid; exec (0x2) pid, tgid; exit (0x80000000) pid, tgid,
  code (at 24), signal;
- the connector header's seq on an event (at 16 + 8 of the message) is the
  kernel's own count of events on the event's CPU, one count per CPU.

Several messages may come in one datagram, each padded to 4 bytes. A
message shorter than its shape, of another `what` (uid, gid, sid, ptrace,
comm, coredump, nonzero_exit, or a number the reader does not know), of
another connector, of another netlink type, or whose connector length is
longer than its message, is counted as unread by its kind, never guessed.

The exit's code is the kernel's wait status: `code` is the exit status where
the process exited and `signal` the signal that ended it where one did (as
wait(2) reads them: 0x100 is code 1, 9 is signal 9). The event's own
exit_signal is the signal the parent is sent at the end (SIGCHLD, 17), not
what ended the process: it is not kept.

## Threads, and when a process ends

A fork whose child's tgid is not its pid is a thread of the process the tgid
names: it is counted in `threads`, and the reader keeps, for each process it
holds, the threads it heard begin and not end (at most 32768 of one
process). An exit with pid equal to tgid while a thread of it is known to
live is the leader thread's end, not the process's: the process ends at its
last thread's exit, with that exit's code and time. An exec leaves a
process one thread.

An ended record is taken up again by an exec of its pid, with no fork
between, only where its start and the exec's read start are both known and
equal: the process went on. Otherwise the exec makes a new record whose
`unread.began` says what is not known: a thread of the same process called
exec, or another process took the pid and its fork was lost. A read that
was another process's takes nothing up again. A record taken up again
before its end was read withdraws that end; one whose end was read already
says, when it is given again, that the end given before was its leader
thread's (`unread.ended`).

An end the reader gives where the process's threads are not known says it
may be its leader thread's alone (`unread.threads`): the end of a process
it did not hold from its fork, and every end given while events were lost.
Where a thread's exit follows such an end of a process it did not hold, that
exit is given too, in `older`, as the later end of the same pid with its
code (one later end for each read; the latest of them); an exec of that pid
with no fork between is a new record that says what is not known, as
above.

## What is read at an exec, and what never is

At an exec the reader reads at once the link /proc/PID/exe (the program) and
/proc/PID/stat (the parent, the start in clock ticks and the name the kernel
gave the process), and nothing else of the process. No argument, no environment, no working directory and no open
file of a process is ever read, and nothing is read at a fork or an exit.

- `exe` is the program a process has now; `earlier` holds, in order, the
  programs it had before, each with what was unread of it. A record keeps
  its newest 7 earlier programs (EARLIER_MAX); the number of older ones not
  kept is said on the record (`unread.earlier`) and counted (`dropped`): 8
  programs a process at most, the one it has now among them (PROGRAMS_MAX,
  ADR-0007 CC-1).
- `name` is the name the kernel gave the process at that exec (CC-2): the
  last part of the path that was run, cut to 15 bytes, read from the same
  stat (the text between its first "(" and its last ")"); each earlier
  program keeps its own. A name the stat could not give is named in
  `unread.name` with the stat's why. Raw text of the process's choosing: a
  consumer that shows it must escape it. A process given in an
  earlier read that execs again is given again, whole, with its `earlier`.
  A failed read never replaces what an earlier read gave (the start, the
  parent), and is named in `unread` for that exec.
- `exe` is the link as the kernel gives it, raw text of the process's
  choosing in part (a program whose file was removed reads with
  ` (deleted)` after it; a program run from memory as `/memfd:` and a name
  it chose). A consumer that shows it must escape it.
- The start is held against the exec's own time, both on the boot clock
  (the event's stamp is put on the boot clock with the difference of the
  boot and monotonic clocks at the datagram's receipt): a start later than
  the exec by more than 1 s is another process's, and nothing of that read
  is given (`unread` for `exe` and `stat`: "another process held the pid";
  counted in `reused`). A later exec whose start is not the process's own is
  the same. A pid taken again within one second of the exec, before the
  read, is not told apart, and the newcomer's program and start are then
  given as the first process's. Where the boot clock cannot be read, or the
  ticks of a second are not known, the check is off and that is said once
  in `said`.
- The parent is the fork's (the kernel's word at the moment the process
  began) where the fork was heard, else the stat's, which is the parent it
  has now, not its parent at birth (it may be pid 1 or a subreaper).
  The parent is the one the kernel names: a child made to be its maker's
  sibling is given its maker's parent, not its maker.
- A read that fails is counted in `missed` and named in the process's
  `unread` with the system's errno name and every cause it can have: ENOENT
  is a process gone before the read, or hidden from this reader by the
  system; EACCES or EPERM a process not readable by this user, another
  user's or a program that made itself so. A program can keep itself
  unread: by ending before the read, by making itself not readable by this
  user, or by being hidden from the reader by the system.
- A process forked and never heard to exec runs the program of the process
  that made it, which is not read: it is given by its fork, its `exe` none
  and `unread` saying so (the kernel may name another process as its
  parent); where events were lost it says instead that its program is not
  known.

## What read() gives

`read()` returns `{"processes", "ends", "older"}`:

- `processes`: every process that began, or changed its program, since the
  read before, each `{pid, ppid, exe, name, earlier, dropped, started_ticks, began, ended,
  code, signal, unread}`; `ended`, `code` and `signal` where its end was
  heard by then; `unread` is `{field: why}` for what was not read (`{}` when
  whole);
- `ends`: the ends of processes given before, each `{pid, started_ticks,
  began, ended, code, signal, unread}`; a process whose pid began again
  before its end was heard is given here with `ended` none and `unread`
  saying so;
- `older`: the ends of processes the reader never kept, in the shape of
  `ends`: older than the reader, their beginning lost ("no fork heard"), or
  refused by the bound (which the record says), and the later ends of their
  threads.

## Every count, and what it means

`counts()` is a copy, from any thread:

- `since`: when the ask to listen was sent; none before a start and after a
  refused one;
- `last`: when a datagram was last heard (none before any): a source gone
  silent shows here;
- `events`: `{fork, exec, exit}`, every event of the three kinds heard,
  threads too;
- `given`: records given by `read()` (a process given again is counted
  again);
- `missed`: `{exe, stat}`, the reads at an exec that failed. `missed` counts
  reads, not processes: one process can add one to each of `exe` and `stat`.
- `unread`: `{kind: n}`, the messages not read, by kind;
- `threads`: events of threads;
- `older`: ends given of processes never kept, later ends among them;
- `reused`: reads at an exec that were of another process;
- `lost`: `{count, events, why}`: `count` is each time the kernel said
  ENOBUFS (its queue for this socket overflowed); `events` is the events
  lost at least, by the kernel's own count on each CPU: where the count on a
  CPU steps over a number, the step less one is added. In the measured
  words: what the queue held is given; what came while it was full is gone;
  how many: at least the count. A step seen while no ENOBUFS has come since
  the start is a loss the kernel did not tell, and `why` says so; after an
  ENOBUFS a gap is not told apart from it (the ENOBUFS is read before its
  gaps show, and a CPU's gap shows only at that CPU's next event). An answer
  to any listener's ask takes the next number of its CPU's count, as an
  event does, and is counted as one, so another listener's ask is no loss.
  A count
  that does not step forward is not counted and is said once in `said`. A
  CPU heard from for the first time has nothing to compare: the count is
  from below. `why` is none while nothing was lost;
- `beyond`: what was past a bound of the reader's own: `PROCESSES_MAX`
  (32768), a constant, for each of the processes kept, the processes held
  for the next read, the ends held for it, the threads of one process and
  the memories of ended and refused pids and of the ends of processes not
  held (these forget their oldest, and a forgetting is not counted: a pid
  forgotten is then said as one whose fork was not heard);
  CPUS_MAX (4096) CPUs whose count is kept. `beyond` counts events and
  records past the bound, not processes. The bound counts over the reader's
  life: a process whose end was lost never leaves `live`, so after enough
  losses every new process is past the bound.
- `live`: processes kept whose end is not heard yet;
- `refused`: why the start was refused, in the reader's words, or none;
- `ended`: why the reader's thread ended before the stop, or none: every
  way it can end (its receive failed, or anything it raised) is said here,
  and from then on nothing is heard;
- `said`: what the reader had to say of itself, each once: the receive
  queue smaller than asked (the kernel reports it twice the size asked, and
  both numbers are said), the ticks of a second not known, the boot clock
  not readable, the kernel's count not stepping forward.

## The start, the stop

`start()` returns none, `running` for a reader already running (not a
refusal), or its refusal in the reader's own words (beginning "the process
events are not read: ") and raises nothing: not Linux; the socket, the bind
or the ask refused (with the system's errno name); the kernel's answer an
errno; no answer within 2 s (and, where the queue overflowed while the
answer was awaited, that the answer may be among what was lost). `stop()`
ends the thread, asks the kernel to stop sending and closes the socket; a
second `stop()` does nothing; the reader is a context manager; a reader
started and never stopped is stopped at the interpreter's exit. Everything
of the system goes through arguments a test replaces (the socket's maker,
the reads of /proc, the clocks, the random mark, the ticks of a second, the
thread, the exit registry, the platform).

## The helper: the reader in a process of its own

Measured (Amendment BT, BT-6): with the reader's thread inside a process
whose other thread never yields, 158 to 202 programs of 200 not read; with
the reader in a process of its own, 0 to 2. Every fork, exec and exit was
heard in every case: what is missed is the program's name, read too late.
So under the watch the reader runs in a process of its own, never as a
thread of the watch (Amendment BU; its review, Amendment BW).

The serve mode. `python -m raqib.procevents --serve` starts a Reader, then
says `{"ready": null, "v": 1}` on its first line, before any ask; where the
reader's start is refused it says the refusal in `ready` instead and exits
0. Every line it writes carries `"v": 1`, the protocol's version. Then it
answers each line of its standard input with one line of JSON:

- `read` or `read N` -> `{"v", "ask", "processes", "ends", "older",
  "more", "counts"}`: what the Reader's `read()` gave and its `counts()`,
  processes first, then ends, then older, packed until the line would pass
  1 MiB (LINE_MAX, its newline included) and at most 2000 entries in all
  (SERVE_MAX); what does not fit comes with the next `read`, and `more` is
  true. An entry that alone would pass the bound is given with its programs
  unread (TOO_LONG_EXE). A new `read()` of the Reader is taken only when
  what the helper holds from the reads before was given whole, so what it
  holds is bounded by the Reader's own bounds. `ask` is N, or null for a
  bare `read`;
- `stop`, or the end of its input -> it stops the Reader and exits 0;
- any other line, and `read` followed by anything `int()` refuses ->
  `{"error": ..., "v": 1}` (the line is not repeated) and the helper lives
  on.

What it reads and opens: its standard input; its Reader reads the kernel's
socket and, at each exec, that process's /proc/PID/exe and /proc/PID/stat.
It opens no other file, writes only its standard output and starts no
program. Where its output cannot be written it stops the Reader and exits 1.
A Ctrl-C at the terminal does not end it: the end of its input does, so a
watch that dies, however it dies, leaves no helper behind.

What it loads (BW-5, BY-6). The helper is the interpreter the watch runs
under (`sys.executable`), always with `-I` (isolated: no user site folder,
no PYTHON* variable of the environment, no directory of its own before the
import path), and `-c` with a fixed program, a constant of the module: it sets `sys.path` to the list
given as its one argument - the watch's own `sys.path`, its absolute
entries, in order, as JSON - and runs `raqib.procevents.main(["--serve"])`.
Its directory is `/`, its standard error goes to nothing (a crash is said
as an end), and its environment is the watch's, which `-I` does not read. So
it loads Raqib from where the watch loaded it and from nowhere else, and
needs nothing of the user's environment or site folder.

The packed road (M17.2a, ADR-0007 Amendment CG). A Raqib packed into a
program with its own runtime (PyInstaller, for one) has no interpreter to
give `-I` and `-c`: its `sys.executable` is the packed program itself, and
`sys.frozen` is true. Measured before this road (GitHub's Linux machine, and
this task's own run, PyInstaller 6.11.1): such a watch said "rounds asked: 2,
answered: 0", the helper ended twice, and the process events were not read
for the rest of the watch. So where `sys.frozen` is true, the helper is that
same program with one fixed word as its only argument,
`__raqib_procevents_helper__` (`procevents.WORD`), and no import path is
given: a packed program loads Raqib from what it carries. Raqib's entry
(`raqib/cli.py` `main`, so every `raqib` and `python -m raqib`) looks at its
first argument before it reads anything else: the word alone is the helper,
as `python -m raqib.procevents --serve` is (a Ctrl-C does not end it, the
end of its input does), and nothing else of the arguments is read; the word
with anything after it is a usage error, exit 2, said in words that do not
name the word. Where Raqib is not packed, the helper's command is the one
above, byte for byte, and the watch never uses the word; the word is taken
there too (one entry, one behaviour). The word is no command of a person's:
it is in no help text, no usage line and not in the guide's table of
commands. Run by hand it serves until its input ends, as the helper does: it
answers `read` and `stop` on its standard input and writes its lines on its
standard output, and a Ctrl-C does not end it - once it serves: a packed
helper first loads every module Raqib's entry imports (the plain helper
loads the reader alone), and a Ctrl-C in that time is not yet ignored. The
watch's record of its own holds the packed helper as it holds the
interpreter (raqib/own.py: a process is the watch's own by its pid, its
start and the image a sample reads together - the packed program's file,
which is the watch's own image too), so it is never a tree and never an
act; another process of that image that the watch did not start is not its
own. Its cost (measured once, this task's machine): the packed helper held
34.4 MB of memory, the plain one 14.9 MB. What a packed helper
loads: measured on this task's machine (PyInstaller 6.11.1, Python 3.13),
the packed program run from a folder holding a `raqib.py`, a `raqib`
package and a `json` package, with PYTHONPATH naming that folder, loaded
none of them; what else a packed start reads of its environment is the
packer's, and Amendment CI measured what is said below. What the packed
helper is handed (M17.2b, ADR-0007 Amendments CI and CJ). Measured on
GitHub's Windows, Linux and macOS machines (PyInstaller 6.11.1, one folder;
CI): a packed start read none of the ten interpreter's variables tried
(PYTHONPATH, PYTHONHOME, PYTHONSTARTUP, PYTHONVERBOSE, PYTHONINSPECT,
PYTHONOPTIMIZE, PYTHONHASHSEED, PYTHONUTF8, PYTHONDEVMODE, PYTHONWARNINGS),
and it adds its own names to its environment, which reach every program
started with it - `_PYI_ARCHIVE_FILE` and `_PYI_PARENT_PROCESS_LEVEL` on the
three systems, and on Linux its own folder put first in LD_LIBRARY_PATH
(what was handed stays behind it) and LD_LIBRARY_PATH_ORIG holding the value
it was handed; the packer's three names set together make a start take
itself for one started again by itself and skip its own first steps. So the
helper is started with `env=own.handed()` (raqib/own.py, CI-1): where Raqib
is packed, the watch's environment without every name that begins `_PYI_`
and without `_MEIPASS2` (on Windows whatever their case: the system takes a
name in any case; CJ-7), and on Linux with LD_LIBRARY_PATH put back to
LD_LIBRARY_PATH_ORIG's value and LD_LIBRARY_PATH_ORIG removed
(LD_LIBRARY_PATH removed where there is no LD_LIBRARY_PATH_ORIG); Linux
alone has its loader's path put back. Every other name, the DYLD_ names of
macOS among them, stays as handed. So the packed helper is handed the
environment the watch was handed, with two exceptions: a `_PYI_` name or a
`_MEIPASS2` that the watch's starter handed is dropped too; and where the
starter hands LD_LIBRARY_PATH_ORIG itself, the helper is given it as its
LD_LIBRARY_PATH (not measured: whether the packer keeps, overwrites or
clears a handed LD_LIBRARY_PATH_ORIG; CI-4's ground - the environment is
the starter's). Measured on 03e97e8 (CJ, the three systems): `own.handed()`
was the environment handed to the packed program, name for name and value
for value, and a handed `_MEIPASS2` was left out; on Linux the helper's own
record of its environment held `_PYI_PARENT_PROCESS_LEVEL=0`, a start of its
own, and LD_LIBRARY_PATH_ORIG equal to the value handed to the watch. The
packed helper's own start puts its folder first in LD_LIBRARY_PATH again and
adds the packer's names again, as any packed start does: it is not handed
them. Not measured: an LD_LIBRARY_PATH handed empty (tests/test_own_env.py's
fixture for it is made up). Where Raqib is not packed, the helper is given a
copy of the watch's environment, value for value - the one program a plain
Raqib hands its whole environment to; every other program it starts is
given a list of named variables or a fixed environment - and its command is
the one above, byte for byte. A test reads the package's source (CI-2,
CJ-4; tests/test_own_env.py): every start of the kinds tests/test_own_tree.py
lists (subprocess's, os's and asyncio's) fails where its `env` is absent,
None, `os.environ` or a plain copy of it (`dict(os.environ)`,
`os.environ.copy()`), as a keyword or as the value of a dict given with
`**`, and a start that can take no environment (`getoutput`,
`getstatusoutput`, `os.system`, `os.popen`, the fork, spawn and exec
families, `startfile`) fails outright: the only whole environment handed on
is `own.handed(...)`. The test holds the set of starts it finds in raqib/,
by file and function, so a scan gone blind fails. It fails on a start of
the kinds it lists, not on every start that inherits: it does not see a
start reached by `getattr`, a module bound again by assignment,
`functools.partial`, a subclass of Popen, or a start handed to a function
by position. Packed and on Windows, `cli.main` alone calls
SetDllDirectoryW(NULL) at its start (CI-3; measured, CJ: the folder the
system searches first for a library was the packed program's before the
entry ran, none after it, and none for a program started after it); a call
that fails (not measured on a real machine) is said by the entry at once,
one line on its error stream, whatever the command (CJ-3), and by the host
watch once at its start as a blind spot that does not change the result
(CJ-1); a packed entry that made no call is said by the host watch as a
blind spot too (CJ-2). The loader's own variables (LD_PRELOAD,
LD_LIBRARY_PATH as handed, LD_AUDIT) are read by the system's loader before
the first line of Raqib, packed or plain, and are handed on as they were
given (CI-4, not held). Not built here: the package
and its installer, signing, a service on Windows, a reader for macOS
(Amendment CG's last item).

The client. `procevents.Helper` starts it and hands the process at once to
the `started` callable it is given, so the watch records it as its own
(raqib/own.py), and does not wait for it. `ask(timeout)` gives the answer,
or one of `starting`, `late`, `ended`, `not a line` or `refused`, and waits
at most its timeout: a thread reads the helper's output, lines of at most
LINE_MAX bytes (a longer one is `not a line`), at most 4 lines held unread
(HELD_LINES), and an ask reads at most the ready line and one answer. At
most one ask is unanswered: while one is, `ask` writes nothing and waits for
that answer, and an answer that comes after its round is taken by the ask
that reads it, so its numbers count once. The ask is written to the
helper's input made non-blocking (BY-6): it never waits, and an input that
is full (a part of the ask written, or none) is `ended`, said as "its input
was full" (FULL). Before the helper's first line,
`ask` says `starting` for 5 s after the start (STARTING_SECONDS), then
`late`. A line of another version, a number that is no number or another
shape is `not a line`. `stop()` closes the helper's input, waits 2 s
(STOP_SECONDS), then ends it (terminate, then kill after 1 s) and says so.

The watch (raqib/host.py, ProcEvents). On Linux the live reader starts one
helper at its first round, before the round's sample, so the helper is in
that sample as the watch's own; after each sample, and before discover
builds the round, it asks it once and waits at most 2 s and at most a
quarter of the watch's interval. The round's
inventory carries `procevents`: `began` (the processes whose fork was heard
and that were not given before), `inside` (those of them whose end came in
the same answer: they began and ended between two asks), `unread_exe` (the
step of the reader's `missed.exe`: reads, not programs), `beyond` and `lost`
(the reader's, summed over every helper the watch had), `refused`, `hole`,
`more`, `restarts`, `asked` and `answered`: numbers and the reader's or the
watch's own words, never a program. A refusal is final. Before the first
answered ask a hole of the helper is a blind spot that does not change the
result; after it, a late answer, a line that is not the helper's, an end,
a loss, a bound passed or an answer that holds back a rest for a next one
is a hole of the result of the kind `procevents` (BY-5, BZ-6, see "The
round"). A helper that ended,
whose reader ended, or that was late three rounds running is ended and
started again once, and a second end is final; between an end and the next
start nothing is heard, and the report says so. A late answer and a line
that is not the helper's are holes of their round; while an ask is unanswered
the next round writes no new ask and waits again for that answer, and three
rounds late running end the helper. A helper the watch ends inside a round
is ended at once, each wait bounded by the ask's own time, so the round is
not held for it. A line the watch cannot count (a record with no usable pid, counts of
another shape) is `not a line`, never an exception. On Windows and elsewhere
no helper is started and the key is absent.

## The round (M14.1c, ADR-0007 Amendments BY and BZ)

The text. After each answered ask the watch keeps the processes of the
answer (at most SERVE_MAX entries, as an answer is bounded; a process of
another shape, a time the round cannot read or one that is no real
instant, or a pid at or above discover's bound for keying instances apart
makes the answer `not a line`, BZ-4) for that round alone, and gives
discover one text of the kind `procevents`: one JSON line per process
whose fork was heard (since M14.1d `{pid, ppid, programs, dropped, ticks,
began, ended, code}`, see below; `ticks` null where not read). A round whose helper
gave nothing has no such text, and is the round it was, byte for byte. A
process the watch started itself (its pid in the watch's record of what it
started, raqib/own.py, its parent the watch, its program the recorded image
and its fork within the record's window) is the watch's own: it is not
given (BY-6). The watch keeps its copies of that record until the answer
that covers the round they were copied in is taken (a late answer, a rest
held back), at most 1024 (BZ-7), and the section counts the processes of
its own left out. The socket tool the round runs (`ss`) is in that record
when it starts.

The parser. `discover.parse_procevents` makes of each line a process
record as `parse_proc` makes one of a sampled process: the pid, the parent
the kernel named, the image by the same naming of the program's path, that
path as its exe, no argument (the reader reads none), the start key
`boot+<ticks>` where the ticks were read, and the time its fork was heard;
it is marked as the reader's (`created`). A line that is not such a line
(BZ-4 as above) is a problem of the round, never an exception.

The join. A record is one process with the sampled process of its pid
where their start ticks are the same, or where the sample read no start
for that process (as the merge by pid was). A record whose ticks were not
read joins the sampled process of its pid only where the sample read no
start for it; where the sample read one, the two are kept apart (BZ-5: a
line more, never a program named on another process). Otherwise it is
another process, keyed apart. A child the reader gave is linked to the
instance of its parent pid alive when its fork was heard, where the reader
gave that instance. Then the round is built as any: each process goes to
its nearest talking ancestor as an act, and an act is its tree's child and
its HostChild line, so NET-TOOL and DESTRUCT-CMD judge every program it
ran, by its file's name and the name it was called by (CC-1, CC-2). A tree that is a candidate only by what the reader
gave is as one that is so only by the channel on Windows (`candidate_by`
"channel", AA-1), and the footprints are those of the round built without
the reader's records (AD-1). An act-root is made only by what the samples
alone make: its root, the shell under it and a command under that shell are
each a process a sample held (BZ-1, CA-1, CB-1). A chain the reader alone
gave under such a root - a second shell and its command, between two
samples - adds its processes as the act-root's acts, which are judged; under
a root the samples did not make an act-root it adds nothing, and that is not
judged (the act-root's budget was measured on samples; whether the reader's
word may make one is measured first, M14.1d). An end heard from the reader
never ends a process the sample holds: the round's process list is the
sample's. The round reads no /proc
start of a child the reader alone gave and said ended: its start is the
record's (BZ-8), kept in the round's record of starts apart from the /proc
reads (`child_started.events`, "the process events: when its fork was
heard"), and an act timed by it has the basis `events`, never `stat`
(CA-4). A HostChild line of a round that read the reader's text says, in
`input_meta.command_sources` and in the order of `command_programs`, where
each program's children were seen: `sample`, `events` or `both` (CA-2); a
line of a round with no reader's text has no such key, and no rule reads
it. Where one name covers several children of a line, its word is theirs
together (a sampled one and a heard one read `both`). The word is worked out
from the records a child cites: a watch that takes more than one snapshot a
round (`--window`) can say `sample` of a child the reader heard too (CB-3);
a watch as it runs by default takes one.

Every program, the name called by, a parent gone (ADR-0007 CC-1 to CC-4,
M14.1d). A line of the round's text gives every program the process ran
while heard, in order: `{pid, ppid, programs, dropped, ticks, began, ended,
code}`, `programs` 1 to 8 entries of `{exe, name}` (a name of at most 15
characters), `dropped` the earlier ones the reader did not keep; a line of
M14.1c's shape (one `exe`) is read as one program with no name. A child's
line names each program its process ran, in order (`command_programs`, with
`command_sources` beside them), by its file's name and, where it differs,
is shorter than 15 characters and passes the name gate, by the name the
kernel gave it (a file `nc.openbsd` called `nc`: both); the file's name
always stays. A process the watch wrote a line for that runs a program not
yet said, in a later round, gets a line for that program; a program said
of it is not said again. The watch keeps, per tree, the children it wrote
that the process events heard and whose end it has not heard (by pid and
start; at most 512 a tree, passing it said in the section and a hole of the
result); a process whose parent is one of them (that pid, begun before it,
not heard to end before it began) is that tree's child though its parent is
in neither the sample nor the round's text, and so is a kept child given
again. A process is its maker's child (CD-1): where the reader gave a
process, the parent it names (the process that made it, from the kernel's
fork event) is its parent - where that parent is a process of the round,
in its sample or its text (CE-2; else the sample's word stands, and the
watch's kept children carry it, CC-3) - though a sample holds it under
another - the
kernel hands a process whose parent ended to pid 1 or a subreaper; so a
bash that a shell started in the background and that outlived it is the
tree's child from the round it was heard in, is kept, and every program it
runs later is judged as the tree's. A process the reader did not give keeps
the sample's parent. The search for act-roots reads the samples' own parent
links, never one the reader gave over them (CE-2). So under an act-root the
sample's parent stands for every process (CF-1): one the reader heard made
under an act-root's shell that a sample holds under pid 1 is no act of it,
is not kept, and what it runs later is nobody's - as before this task, and
the next task's to take. Only children the process
events heard are kept; a child of a child written from a sample alone is
nobody's once its parent ends. A kept child, or a child of one, is given to
its tree while the tree is quiet by the road a held tree's given children go
(its marks, the test that the tree can be written, the hole where it is not;
CE-1), and only where it ran a program its lines have not named; a tree that
has gone is written nothing, and how many processes its kept children were
heard to start is said in the section and as one hole of the result. A child
whose file the reader could not read and whose kernel name it read is named
by that name, its line saying so (`input_meta.files_unread`, CE-3), counted
apart from the children that got no line. Where `programs` exist, the
child's own image (the samples' name) is still named where no program gives
it, and a file not read is never `unfit` (CE-4). A kept child's tree is found
by the tree's key, and a kept child is let go where the round holds its pid
with another start; Windows and a round with no reader's text write a
child's line as M14.1c did (CE-6). A pid used again with another start is
another child wherever the watch keys a child. The round's standing hole of liveness says, in a round
that read the reader's text, what such a round sees and does not.

What is not judged (BY-3, BZ-3, CC). A tree needs a talker at a sample, and
a connection that opens and closes between two samples is unseen (M14.2): a
tree that lives whole between two samples is in no round, and a child's own
connections are not read. A program past the bound of 8 a process (the
oldest of those run between two asks) is not kept and not judged; it is
counted in the section. A child whose parent the watch never wrote (its
parent in neither the sample, the text nor the kept children) is in no
tree, and so is a process whose maker the reader did not hear (begun before
the reader, or its fork lost) that a sample holds under pid 1 (CD-2). An act-root the reader's word alone would make is not made (CB-1). A
process can be called by a tool's name it is not (a link of its own): it is
then judged by that name, and its tree alarms by its own doing. A child
whose program was not read, and no name of it either, is in the round and
counted; it gets no line and no hole (one whose name alone was read gets
its line by that name, CE-3).

The words (BY-4). A program's name reaches a line's programs only through
the gate a sampled child's name goes through (a plain program name, else
the existing hole); the line's cites hold the reader's record itself, made
printable and cut as a sampled child's is. The helper's lines are its
word: what is judged from them comes from the reader, and the watch does
not check them. The report's PROCESS EVENTS section says what is judged
and what is not, and counts the processes given to the rounds, those
joined to a tree as its child, and of them those with no program read.

When the reader is not whole (BY-5, BZ-2, BZ-6). A refusal at the first
start (a container, a right not given), a helper that could not start (an
input that cannot be made unblocking among the causes, said), or a hole
before its first answer: the blind spot as before, and the rounds are the
sample's alone. After at least one answered ask: a late answer, an end
(and its one restart), a loss of events, a bound passed, a line that is
not the helper's, or an answer that holds back a rest for a next one (a
child among the rest is judged a round late, and one whose parent has left
by then is in no tree) is a hole of the result of the kind `procevents`,
said once per episode with its round; the result is INCOMPLETE as any hole
makes it, unless a finding makes it an alarm. The note of what lives
between two rounds then says what was heard and judged and why the reader
was not whole; "the rounds read /proc only" is said only where no ask was
answered.

## What was measured

Measured (Amendment BQ): for each of 14 short acts - touch (2 to 4 ms), mv,
cp and rm (1 ms each), three curls, wget, getent, nc, Python's own client,
sh, shred, git and its child - the fork, the exec and the exit were heard,
with the exit's code; for every exec the program and the parent were read in
time (0 of 16 to 20 missed; the read 0.02 to 0.13 ms after the event). They
were heard by a plain user on all three kernels, and under the service's own
limits (its seccomp filter, AF_UNIX and AF_NETLINK alone, its two
capabilities).

Measured (Amendment BR; the probe branch, kernels 6.8 and 7.0, a plain
user; all three images agree). After an overflow of the listener's queue
(ENOBUFS) the events went on, for that listener alone and for a second one
opened after it. When a thread that is not the leader called exec, the
kernel sent an exit with pid equal to tgid (code 0), then the exec, then the
process's real exit. When the leader thread ended and another thread lived
on, the kernel sent an exit with pid equal to tgid (code 0) at once, and the
process's own code came on the last thread's exit. The reader's own run, 15
times on those images: no read missed, nothing lost, the start answered
each time. The answer's ack is the ask's plus one there too.

Measured (Amendment BS; the probe branch, kernels 6.8 and 7.0, four CPUs, a
plain user; all three images agree, and so does the builder's sandbox on
6.18). In a quiet run of 300 children the kernel's count on each CPU had no
gap and never went back. At an overflow (a queue of 9216 bytes, 300
children made while nothing was read) the error (ENOBUFS) was read first;
after it the events the queue had held were still given; the events made
while it was full were never given; events made afterwards all came. The
gaps in the kernel's count over the events read added up to 275, 589 and
626 where some 890 events were lost: a count from below, not the whole. A
thread that is not the leader calling exec, with every CPU busy: the exit
with pid equal to tgid came before the exec every time (1800 of 1800 on the
three images; 600 of 600 in the builder's sandbox on 6.18); the other order
was not seen in 2400 runs. If it came, the reader would give the leader
thread's exit as the end of a process that lives on, and its real end as an
end of a process it did not hold. The redone reader's own run, 15 times on
those images: no read missed, nothing lost, none taken for another.

Seen in the builder's sandbox only (kernel 6.18, 2 CPUs, as root; not a
field measure). In the builder's sandbox (kernel 6.18, 2 CPUs, as root) the
first build's rig run was MET once in nine runs; in the other eight, 1 to 3
of 14 programs were not read in time (ENOENT), each counted in `missed`
(touch, mv, cp, nc and sh, each living 1.4 to 5.5 ms). The REDO's runs
there: the real test missed 3 or 4 of 5 programs of `true` in three runs,
and the rig was MET once in three runs, missing 3 of 14 in the other two.
The second REDO's runs there: the real test missed 0, 3 and 1 of 5, and the
rig missed 1 of 14 in each of three runs. In every run every fork, exec and
exit was heard with the right code and parent, nothing was lost (the
kernel's count had no gap), and no read was taken for another. The
reader's thread shares the interpreter with the rest of its process: under
a busy watch its reads may come later than under the rig (to be measured
with the watch).

Measured (Amendment BT; the probe branch 1727304, kernels 6.8, 7.0 and 6.18).
While one listener read, a second asked to listen and to stop, three times:
the first read six answers, each carrying a real CPU and that CPU's next
number of the count; with the answers left out of the count the gaps added
up to six, with them taken as part of it to none. The reader in a process of
its own, 200 short children while the process that started it never
yielded, nine runs on three images: 0, 0, 0, 0, 0, 1, 1, 0 and 0 programs
not read; the reader's thread inside that busy process: 158 to 202 of 200.

## Read in the kernel's source, not measured

Read in the kernel's source, not measured: the kernel sends the answer to
every ask to the whole group (so the reader's mark is random); an ask from
outside the system's first namespaces (as in a container) is not answered;
the event's stamp is on the monotonic clock and stat's start on the boot
clock, in ticks of a second; the kernel's send of an event can fail without
an ENOBUFS (the count's gaps would show it); after an overflow the kernel may
give nothing until the queue has been read empty, not only while it is full
(BS's run read nothing meanwhile and cannot tell the two apart; the count's
gaps count those events either way); a child made with CLONE_PARENT
is named its maker's parent's; a process hidden by the system's /proc
options reads as gone (ENOENT); a process that made itself not dumpable
reads as not readable (EACCES).

## Not measured

Not measured: a kernel older than 6.8 (the connector may be root's there);
whether a plain user hears another user's processes; a machine that starts
thousands of processes a second; a process inside a container; a reader
inside a time namespace; the times of events read after the machine slept.

The rig (`tools/rig/procevents_run.py`, X31 of `tools/rig/check.py`) hears
its own short children through the reader, as the user that runs it, and
states MET where every act that ran was given with its program read, its
parent the run's own process and its end's code, and nothing was lost; its
line names the kernel's release.
