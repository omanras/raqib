# PROC-EVENTS - the reader of Linux's process events

`raqib/procevents.py` (ADR-0007 Amendment BQ, BQ-1 and BQ-2). On Linux the
kernel says, of every process, when it forks, when it changes its program
(exec) and when it exits. The reader listens to that, and to nothing else:
it switches nothing on, asks for no right and reads no argument of any
process. It is the reader alone: no watch reads it yet; until one does, what
a live watch sees on Linux between two samples is what it saw before.

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
- the kernel answers the ask: an event of `what` 0 whose u32 at 16 is an
  errno (0: the ask was taken). The answer's connector ack is the ask's
  plus 1 (its seq is the kernel's own count: seen on kernel 6.18 in the
  builder's sandbox), so the reader puts its own pid in the ask's ack and
  tells its answer from another listener's. `start()` waits up to 2 s for
  it: a kernel that takes the ask and says nothing is a refusal, not a
  silence;
- an event is a netlink header, a connector header, then `what` u32, cpu
  u32 and the kernel's time u64 (`=IIQ`, nanoseconds of the monotonic
  clock; the reader puts it on the wall clock), then its data at 16:
  fork (`what` 0x1) parent pid, parent tgid, child pid, child tgid;
  exec (0x2) pid, tgid; exit (0x80000000) pid, tgid, code (at 24), signal.
  The kernel's union is 24 bytes, so every measured event is 40 bytes and
  every message 76.

Several messages may come in one datagram, each padded to 4 bytes. A thread
(its tgid not its pid) is not a process: it is counted in `threads` and
nothing else. A message shorter than its shape, of another `what` (uid,
gid, sid, ptrace, comm, coredump, nonzero_exit, or a number the reader does
not know), of another connector or of another netlink type is counted as
unread by its kind, never guessed.

The exit's code is the kernel's wait status: `code` is the exit status where
the process exited and `signal` the signal that ended it where one did (as
wait(2) reads them: 0x100 is code 1, 9 is signal 9). The event's own
exit_signal is the signal the parent is sent at the end (SIGCHLD, 17), not
what ended the process: it is not kept.

## What is read at an exec, and what never is

At an exec the reader reads at once the link /proc/PID/exe (the program) and
/proc/PID/stat (the parent and the start in clock ticks), and nothing else of
the process. No argument, no environment, no working directory and no open
file of a process is ever read, and nothing is read at a fork or an exit.

- The program is the link as the kernel gives it: a program whose file was
  removed reads with ` (deleted)` after it (not measured).
- The parent is the fork's (the kernel's word at the moment the process
  began) where the fork was heard, else the stat's.
- The start in clock ticks (the stat's 22nd field) and the pid together name
  one holder of a pid.
- A read that fails is counted in `missed` and named in the process's
  `unread` with the system's errno name: ENOENT is a process gone before the
  read; EACCES or EPERM a process that is not this user's to read.
- A process forked and never heard to exec has its parent's program, which
  is not read: it is given by its fork, its `exe` none and `unread` saying
  so.
- A second exec of one process: the program it became is the one given. A
  process given before that execs again is given again, whole, with the
  program it became (its pid, parent and start as before).

## What read() gives

`read()` returns `{"processes", "ends", "older"}`:

- `processes`: every process that began, or changed its program, since the
  read before, each `{pid, ppid, exe, started_ticks, began, ended, code,
  signal, unread}`; `ended`, `code` and `signal` where its exit was heard by
  then; `unread` is `{field: why}` for what was not read (`{}` when whole);
- `ends`: the ends of processes given before, each `{pid, started_ticks,
  ended, code, signal, unread}`; a process whose pid began again before its
  end was heard is given here with `ended` none and `unread` saying so;
- `older`: the ends of processes the reader never heard begin (older than
  the reader, or their beginning lost or past the bound), in the shape of
  `ends`.

## Every count, and what it means

`counts()` is a copy, from any thread:

- `since`: when the ask to listen was sent (none before a start);
- `events`: `{fork, exec, exit}`, every event of the three kinds heard,
  threads too;
- `given`: processes given by `read()` (a process given again at its second
  exec is counted again);
- `missed`: `{exe, stat}`, the reads at an exec that failed;
- `unread`: `{kind: n}`, the messages not read, by kind (`comm`, `sid`, ...,
  `fork shorter than its shape`, `a netlink message of type 2`, `an answer
  to another listener's ask`, ...);
- `threads`: events of a thread, not a process: not kept;
- `older`: ends of processes never heard to begin;
- `lost`: `{count, why}`, each time the kernel said ENOBUFS (its queue for
  this socket overflowed: the events it held then are gone, and how many is
  not known); `why` is none while the count is 0;
- `beyond`: what was past the reader's own bound, `PROCESSES_MAX` (32768),
  a constant: the processes kept, the processes held for the next read, and
  the ends held for it, each; what is past it is counted, not kept. A
  process past the bound has its later events counted as of one never heard
  to begin;
- `live`: processes kept whose end is not heard yet;
- `refused`: why the start was refused, in the reader's words, or none;
- `ended`: why the reader's thread ended before the stop (its receive
  failed), or none: from then on nothing is heard;
- `said`: what the start had to say of itself (a receive queue the system
  would not enlarge).

## The start, the stop

`start()` returns none or its refusal in the reader's own words and raises
nothing: not Linux; the socket, the bind or the ask refused (with the
system's errno name); the kernel's answer an errno; no answer within 2 s.
The socket's receive queue is asked to be 1 MiB (the system may keep less;
a refusal is said in `said`). `stop()` ends the thread, asks the kernel to
stop sending and closes the socket; a second `stop()` does nothing; the
reader is a context manager; a reader started and never stopped is stopped
at the interpreter's exit. Everything of the system goes through arguments
a test replaces (the socket's maker, the reads of /proc, the clocks, the
thread, the exit registry, the platform).

## What was measured, and what was not

Measured (Amendment BQ): for each of 14 short acts - touch (2 to 4 ms), mv,
cp and rm (1 ms each), three curls, wget, getent, nc, Python's own client,
sh, shred, git and its child - the fork, the exec and the exit were heard,
with the exit's code; for every exec the program and the parent were read in
time (0 of 16 to 20 missed; the read 0.02 to 0.13 ms after the event). They
were heard by a plain user on all three kernels, and under the service's own
limits (its seccomp filter, AF_UNIX and AF_NETLINK alone, its two
capabilities).

Not measured: a kernel older than 6.8 (the connector may be root's there);
whether a plain user hears another user's processes; a machine that starts
thousands of processes a second; a process inside a container.

Seen in the builder's sandbox only (kernel 6.18, as root; not a field
measure): the answer's ack is the ask's plus 1 and its seq the kernel's own
count; `true`, `false` and a shell killed by signal 9 were heard with code
0, code 1 and signal 9; in one run the program of all three (each lived 2
to 4 ms) was not read in time (ENOENT, counted in `missed`), in the next
run every one was.

The rig (`tools/rig/procevents_run.py`, X31 of `tools/rig/check.py`) hears
the stand-in's short acts through the reader, as the watch's own user, and
states MET where every act that ran was given with its program read and its
end's code and nothing was lost.
