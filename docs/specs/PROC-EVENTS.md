# PROC-EVENTS - the reader of Linux's process events

`raqib/procevents.py` (ADR-0007 Amendments BQ and BR). On Linux the kernel
says, of every process, when it forks, when it changes its program (exec)
and when it exits. The reader listens to that, and to nothing else: it
switches nothing on, asks for no right and reads no argument of any
process. It is the reader alone: no watch reads it yet; until one does,
what a live watch sees on Linux between two samples is what it saw before.
Only one reader runs in a process (its bind is on the process's pid).

## The layout, as measured

Measured on the probe branch (GitHub's Ubuntu 22.04 with kernel 6.8, and
24.04 and 26.04 with kernel 7.0), with the standard library alone:

- a socket of AF_NETLINK, SOCK_DGRAM, protocol 11 (the connector), bound to
  the reader's pid and group 1 (the connector's group of process events);
- one message asks to listen: a netlink header of 16 bytes (`=IHHII`:
  length 40, type 3, flags 0, seq 0, the reader's pid), a connector header
  of 20 bytes (`=IIIIHH`: idx 1, val 1, seq 0, ack, len 4, flags 0) and the
  u32 1 (listen). At its stop the reader sends the same message with the
  u32 2 (ignore), then closes the socket;
- the kernel answers every ask to the whole group: an event of `what` 0
  whose u32 at 16 is an errno (0: the ask was taken), its connector ack the
  ask's plus 1 (its seq is the kernel's own count). The ask's ack is a mark
  of 4 random bytes (`os.urandom`), so only the answer that carries the
  mark plus 1 is the reader's: another process cannot answer for it.
  `start()` waits up to 2 s for it: a kernel that takes the ask and says
  nothing is a refusal, not a silence;
- an event is a netlink header, a connector header, then `what` u32, cpu
  u32 and the kernel's time u64 (`=IIQ`, nanoseconds of the monotonic
  clock; the reader puts it on the wall clock), then its data at 16:
  fork (`what` 0x1) parent pid, parent tgid, child pid, child tgid;
  exec (0x2) pid, tgid; exit (0x80000000) pid, tgid, code (at 24), signal.

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
holds, the threads it heard begin and not end. An exit with pid equal to
tgid while a thread of it is known to live is the leader thread's end, not
the process's: the process ends at its last thread's exit, with that exit's
code and time. An exec leaves a process one thread. An exec of a pid whose
exit was heard, with no fork of that pid between, is the same process going
on: its record goes on, never given as new or as "no fork heard". Where the
kernel's queue overflowed (`lost` not 0), a record says its count of threads
is not known, and its end may be its leader thread's; a process older than
the reader says its threads from before the reader are not known.

## What is read at an exec, and what never is

At an exec the reader reads at once the link /proc/PID/exe (the program) and
/proc/PID/stat (the parent and the start in clock ticks), and nothing else of
the process. No argument, no environment, no working directory and no open
file of a process is ever read, and nothing is read at a fork or an exit.

- `exe` is the program a process has now; `earlier` holds, in order, the
  programs it had before, each with what was unread of it. A process given
  in an earlier read that execs again is given again, whole, with its
  `earlier`. A failed read never replaces what an earlier read gave (the
  start, the parent), and is named in `unread` for that exec.
- `exe` is the link as the kernel gives it, raw text of the process's
  choosing in part: a program whose file was removed reads with
  ` (deleted)` after it, a program run from memory as `/memfd:` and a name
  it chose. Whatever shows it escapes it.
- The start is held against the exec's own time, both on the boot clock
  (the kernel's stamp is on the monotonic one; the reader adds the time the
  machine slept): a start later than the exec by more than 1 s is another
  process's, read because the pid was taken again before the read, and
  nothing of that read is given (`unread` for `exe` and `stat`: "another
  process held the pid"; counted in `reused`). A later exec whose start is
  not the process's own is the same. A pid and its start in clock ticks do
  not always name one holder: a pid taken again within the tick, or a read
  the check cannot hold (no ticks of a second known), is not told apart.
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
- A process forked and never heard to exec runs its parent's program, which
  is not read: it is given by its fork, its `exe` none and `unread` saying
  so; where the kernel's queue overflowed it says instead that its program
  is not known.

## What read() gives

`read()` returns `{"processes", "ends", "older"}`:

- `processes`: every process that began, or changed its program, since the
  read before, each `{pid, ppid, exe, earlier, started_ticks, began, ended,
  code, signal, unread}`; `ended`, `code` and `signal` where its end was
  heard by then; `unread` is `{field: why}` for what was not read (`{}` when
  whole);
- `ends`: the ends of processes given before, each `{pid, started_ticks,
  began, ended, code, signal, unread}`; a process whose pid began again
  before its end was heard is given here with `ended` none and `unread`
  saying so;
- `older`: the ends of processes the reader never kept, in the shape of
  `ends`: older than the reader, their beginning lost ("no fork heard"), or
  refused by the bound (which the record says).

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
- `older`: ends of processes never kept;
- `reused`: reads at an exec that were of another process;
- `lost`: `{count, why}`, each time the kernel said ENOBUFS (its queue for
  this socket overflowed): what was in the queue is gone, and how many
  events is not known; on kernels 6.8 and 7.0 the events went on after it
  (measured); `why` is none while the count is 0;
- `beyond`: what was past the reader's own bound, `PROCESSES_MAX` (32768),
  a constant, for each of: the processes kept, the processes held for the
  next read, the ends held for it, the threads of one process. `beyond`
  counts events and records past the bound, not processes. The bound counts
  over the reader's life: a process whose end was lost never leaves `live`,
  so after enough losses every new process is past the bound.
- `live`: processes kept whose end is not heard yet;
- `refused`: why the start was refused, in the reader's words, or none;
- `ended`: why the reader's thread ended before the stop, or none: every
  way it can end (its receive failed, or anything it raised) is said here,
  and from then on nothing is heard;
- `said`: what the start had to say of itself (the receive queue the system
  kept, when less than the 1 MiB asked; the ticks of a second not known).

## The start, the stop

`start()` returns none, `running` for a reader already running (not a
refusal), or its refusal in the reader's own words (beginning "the process
events are not read: ") and raises nothing: not Linux; the socket, the bind
or the ask refused (with the system's errno name); the kernel's answer an
errno; no answer within 2 s. `stop()` ends the thread, asks the kernel to
stop sending and closes the socket; a second `stop()` does nothing; the
reader is a context manager; a reader started and never stopped is stopped
at the interpreter's exit. Everything of the system goes through arguments
a test replaces (the socket's maker, the reads of /proc, the clocks, the
random mark, the ticks of a second, the thread, the exit registry, the
platform).

## What was measured, and what was not

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

Seen in the builder's sandbox only (not a field measure). In the builder's
sandbox (kernel 6.18, 2 CPUs, as root) the rig's run was MET once in nine
runs; in the other eight, 1 to 3 of 14 programs were not read in time
(ENOENT), each counted in `missed`. The programs missed were of touch, mv,
cp, nc and sh, each living 1.4 to 5.5 ms; every fork, exec and exit was
heard with the right code, and nothing was lost. The reader's thread shares
the interpreter with the rest of its process: under a busy watch its reads
may come later than under the rig (to be measured with the watch).

Not measured: a kernel older than 6.8 (the connector may be root's there);
whether a plain user hears another user's processes; a machine that starts
thousands of processes a second; a process inside a container.

The rig (`tools/rig/procevents_run.py`, X31 of `tools/rig/check.py`) hears
its own short children through the reader, as the user that runs it, and
states MET where every act that ran was given with its program read, its
parent the run's own process and its end's code, and nothing was lost.
