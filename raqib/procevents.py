"""Linux: the processes that began, read from the kernel's own process events
(the netlink connector: fork, exec, exit) by a listener of the reader's own
(ADR-0007 Amendments BQ, BR, BS, BT, BU and BW). A live watch on Linux runs it
in a helper process of its own (serve(), started by its client Helper with
the fixed program SERVE_PROGRAM, or `python -m raqib.procevents --serve`;
where Raqib is packed with its own runtime, the packed program with the one
word WORD, which Raqib's entry takes before anything else: Amendment CG),
and counts what it gives; nothing is judged from it yet. The helper reads its
input, the kernel's socket and, at each exec, /proc/PID/exe and
/proc/PID/stat; it writes only its output. docs/specs/PROC-EVENTS.md says all
of it in prose, and keeps what was measured apart from what is read in the
kernel's source.

The messages (measured on kernels 6.8 and 7.0): a socket of AF_NETLINK,
SOCK_DGRAM, protocol 11 (the connector), bound to (the reader's pid, group
1). One message asks to listen: a netlink header of 16 bytes (=IHHII:
length, type 3, flags 0, seq 0, the reader's pid), a connector header of 20
bytes (=IIIIHH: idx 1, val 1, seq 0, ack, len 4, flags 0) and the u32 1.
The ask's ack is a mark of 4 random bytes; the kernel answers the ask (an
event of `what` 0 whose u32 at 16 is an errno) with the ask's ack plus 1
(measured), so only the answer that carries the mark plus 1 is the reader's
(the kernel's source sends every answer to the whole group). start() waits
for it: a kernel that takes the ask and says nothing is a refusal. An event
is a netlink header, a connector header (whose seq is the kernel's own count
of events on the event's CPU), then `what` u32, cpu u32, the kernel's time
u64 (=IIQ), then: fork (0x1) parent pid, parent tgid, child pid, child tgid;
exec (0x2) pid, tgid; exit (0x80000000) pid, tgid, code, signal. Several
messages may come in one datagram, each padded to 4 bytes. A message shorter
than its shape, of another `what`, of another connector or another netlink
type is counted as unread by its kind, never guessed.

Threads (BR-1, BS-3; measured): a fork whose child's tgid is not its pid is
a thread of the process the tgid names; the reader keeps, for each process it
holds, the threads it heard begin and not end. An exit with pid equal to
tgid while a thread of it lives is the leader thread's: the process ends at
its last thread's exit, with that exit's code. An exec leaves one thread. An
ended record is taken up again by an exec of its pid, with no fork between,
only where its start and the exec's read start are both known and equal
(BS-2). An end the reader gives where the process's threads are not known
says it may be the leader thread's alone. The other order of a thread's exec
(the exec before its leader's exit) was not seen in 2400 runs and is not
built: the leader's exit would then be given as the end of a process that
lives on, and its real end as an end of a process the reader did not hold.

What is read at an exec, at once, and nothing else of the process: the link
/proc/PID/exe (the program) and /proc/PID/stat (the parent and the start in
clock ticks since boot). A record's `exe` is the program it has now,
`earlier` its newest EARLIER_MAX programs before (BR-2, BS-4); a failed read
never replaces what an earlier read gave. A start later than the exec by
more than REUSED_SECONDS is another process's, and nothing of that read is
given (BR-3, `reused`); a pid taken again within that second is not told
apart (BS-1).

What it loses and can count is counted: the kernel's ENOBUFS (`lost.count`), the
kernel's own count of events on each CPU stepping over a number (`lost.events`,
at least; BS-5), a read missed, a message unread, a bound passed (`beyond`),
a read of another process (`reused`), a thread that ended before the stop
(`ended`); `last` is when a datagram was last heard. Not counted, and said in
the spec: the last events of a CPU that sends none after them, a CPU first
heard after a loss, a pid a bounded memory forgot.

No rights, no asking: a start the system refuses returns its reason in this
module's words (PREFIX) and raises nothing; a start of a running reader
returns RUNNING. stop() ends the thread, asks the kernel to stop sending and
closes the socket; a second stop() does nothing; the Reader is a context
manager; a reader started and never stopped is stopped at the interpreter's
exit. Only one Reader runs in a process (the bind is on its pid).

Everything of the system goes through arguments a test replaces: the
socket's maker, the reads of /proc, the clocks, the random mark, the ticks
of a second, the thread class, the exit registry, the platform. The
standard library only. It imports `socket` for AF_NETLINK alone; it writes
no file. The Reader and serve() start no program; Helper starts one, the
helper, through the callable the watch gives it (BU-1). It imports on every
system.
"""
from __future__ import annotations

import atexit
import datetime
import errno
import json
import os
import queue
import signal
import socket
import struct
import sys
import threading
import time

AF_NETLINK = getattr(socket, "AF_NETLINK", 16)   # 16 on Linux; the module imports where there is none
NETLINK_CONNECTOR = 11
CN_IDX_PROC, CN_VAL_PROC = 1, 1      # the connector of process events; its group is 1
PROC_CN_MCAST_LISTEN, PROC_CN_MCAST_IGNORE = 1, 2
NLMSG_DONE = 3                       # the netlink type of every connector message
NLMSG = struct.Struct("=IHHII")      # length, type, flags, seq, pid: 16 bytes
CN = struct.Struct("=IIIIHH")        # idx, val, seq, ack, len, flags: 20 bytes
EVENT = struct.Struct("=IIQ")        # what, cpu, the kernel's time in ns: 16 bytes
FORK = struct.Struct("=IIII")        # at 16: parent pid, parent tgid, child pid, child tgid
EXEC = struct.Struct("=II")          # at 16: pid, tgid
EXIT = struct.Struct("=IIII")        # at 16: pid, tgid, code, signal
ANSWER = struct.Struct("=I")         # at 16: the errno of the answer to an ask
WHAT_NONE, WHAT_FORK, WHAT_EXEC, WHAT_EXIT = 0x0, 0x1, 0x2, 0x80000000
KINDS = {WHAT_FORK: "fork", WHAT_EXEC: "exec", WHAT_EXIT: "exit", WHAT_NONE: "answer"}
SHAPE = {"fork": 32, "exec": 24, "exit": 32, "answer": 20}   # the bytes of the event each kind needs
OTHER_WHAT = {0x4: "uid", 0x40: "gid", 0x80: "sid", 0x100: "ptrace", 0x200: "comm", 0x20000000: "nonzero_exit",
              0x40000000: "coredump"}
PROCESSES_MAX = 32768      # the most it keeps of each kind (over its life: see the spec); past it: `beyond`
PROGRAMS_MAX = 8           # CC-1: the programs a record keeps at most, the one it has now among them
EARLIER_MAX = PROGRAMS_MAX - 1   # the earlier programs a record keeps, the newest (BS-4); the rest are counted on it
CPUS_MAX = 4096            # the CPUs whose last count of events it keeps (BS-5)
RECV_BYTES = 65536
RCVBUF_BYTES = 1 << 20     # asked of the socket's receive queue; what the system kept is read back
POLL_SECONDS = 0.25        # the socket's timeout: how soon the thread sees a stop
ANSWER_SECONDS = 2.0       # how long start() waits for the kernel's answer to the ask
JOIN_SECONDS = 5.0
REUSED_SECONDS = 1.0       # a start later than its exec by more than this is another process's (BR-3)
PREFIX = "the process events are not read: "
RUNNING = "running"        # what start() returns for a reader already running: not a refusal
NO_EXEC_EXE = ("no exec heard: it runs the program of the process that made it, which is not read (the kernel may"
               " name another process as its parent)")
NO_EXEC_STAT = "no exec heard: its stat is not read"
LOST_EXEC = "no exec heard, but events were lost (%s): its program is not known"
LOST_THREADS = ("its count of threads is not known: events were lost (%s), so a thread's beginning or end may be"
                " lost and its end may be its leader thread's alone")
NO_FORK = "no fork heard: it began before the reader, or its fork was lost"
NO_FORK_AFTER_END = ("no fork heard after the end of its pid was heard: a thread of the same process called exec, or"
                     " another process took the pid and its fork was lost: not known")
NO_FORK_THREADS = "its threads from before the reader are not known: its end may be its leader thread's alone"
END_NOT_HELD = ("its threads are not known (the reader did not hold this process from its fork): this end may be its"
                " leader thread's alone")
END_LOST = "its threads are not known: events were lost (%s), so this end may be its leader thread's alone"
LATER_END = ("a later end of the same pid: a thread of it ended after the end given before, which was then its"
             " leader thread's alone")
LATER_THREADS = ("its threads are not known (the reader did not hold this process from its fork): this end is one"
                 " thread's, and the process may live on in others")
ENDED_BEFORE = "the end given before was its leader thread's: the process went on with an exec"
EARLIER_DROPPED = "%d earlier program(s) not kept: a record keeps its newest %d (EARLIER_MAX)"
BEYOND_BEGAN = ("past the bound: its beginning was heard and not kept (PROCESSES_MAX, counted over the reader's"
                " life)")
NO_END = "its end was not heard before its pid began again"
ANOTHER = "another process held the pid: its start, read from stat, is later than this exec"
GLOSS = {errno.ENOENT: "gone before the read, or hidden from this reader by the system",
         errno.ESRCH: "gone before the read, or hidden from this reader by the system",
         errno.EACCES: "not readable by this user: another user's process, or a program that made itself so",
         errno.EPERM: "not readable by this user: another user's process, or a program that made itself so"}


def errname(code):
    return errno.errorcode.get(code, "errno %s" % code) if isinstance(code, int) else str(code)


def _why(exc):
    if isinstance(exc, OSError) and isinstance(exc.errno, int):
        return errname(exc.errno)
    return type(exc).__name__


def _flat(exc):
    return "%s: %s" % (type(exc).__name__, " ".join(str(exc).split()))


def stamp(seconds):
    return datetime.datetime.fromtimestamp(seconds, tz=datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def ask(pid, op=PROC_CN_MCAST_LISTEN, mark=0):
    """The message that asks the kernel to listen (op 1) or to stop (op 2): 40 bytes. `mark` is its connector
    ack: the kernel answers with it plus 1."""
    body = CN.pack(CN_IDX_PROC, CN_VAL_PROC, 0, mark & 0xFFFFFFFF, 4, 0) + struct.pack("=I", op)
    return NLMSG.pack(NLMSG.size + len(body), NLMSG_DONE, 0, 0, pid & 0xFFFFFFFF) + body


def refusal(step, exc):
    """The reason, in this module's words, a step of the start was refused."""
    what = {"socket": "the socket (AF_NETLINK, the connector) was refused",
            "bind": "the bind to the connector's group of process events was refused",
            "ask": "the ask to listen was refused",
            "answer": "the kernel's answer to the ask could not be read"}[step]
    more = ""
    if isinstance(exc, OSError) and exc.errno in (errno.EPERM, errno.EACCES):
        more = ("; this kernel keeps its process events from this user (a kernel older than 6.8 may keep them for"
                " root), and no right is asked")
    return PREFIX + "%s (%s)%s" % (what, _why(exc), more)


def parse(data):
    """Every message of one datagram, in order: (kind, time_ns, fields, cpu, seq) - a fork (parent pid, parent
    tgid, child pid, child tgid), an exec (pid, tgid), an exit (pid, tgid, code, signal as the kernel gives them),
    an answer (seq, ack, errno) - or ("unread", why, None, cpu, seq) for what is not read (cpu and seq None where
    the event's header is not there). `seq` is the connector's, the kernel's count on `cpu`. Never guesses, never
    raises on bytes."""
    out, at, n = [], 0, len(data)
    if not n:
        return [("unread", "an empty datagram", None, None, None)]
    while at < n:
        if n - at < NLMSG.size:
            out.append(("unread", "a datagram's tail shorter than a netlink header", None, None, None))
            break
        length, kind = NLMSG.unpack_from(data, at)[:2]
        if length < NLMSG.size or at + length > n:
            out.append(("unread", "a netlink message whose length is not in its datagram", None, None, None))
            break
        body = data[at + NLMSG.size:at + length]
        at += (length + 3) & ~3
        if kind != NLMSG_DONE:
            out.append(("unread", "a netlink message of type %d" % kind, None, None, None))
            continue
        if len(body) < CN.size:
            out.append(("unread", "a connector message shorter than its header", None, None, None))
            continue
        idx, val, seq, ack_, size, _ = CN.unpack_from(body, 0)
        if (idx, val) != (CN_IDX_PROC, CN_VAL_PROC):
            out.append(("unread", "a message of another connector (%d, %d)" % (idx, val), None, None, None))
            continue
        if size > len(body) - CN.size:
            out.append(("unread", "a connector length longer than its message", None, None, None))
            continue
        ev = body[CN.size:CN.size + size]
        if size < EVENT.size:
            out.append(("unread", "an event shorter than its header", None, None, None))
            continue
        what, cpu, when = EVENT.unpack_from(ev, 0)
        name = KINDS.get(what)
        if name is None:
            out.append(("unread", OTHER_WHAT.get(what, "what 0x%x" % what), None, cpu, seq))
        elif len(ev) < SHAPE[name]:
            out.append(("unread", "%s shorter than its shape" % name, None, cpu, seq))
        elif name == "fork":
            out.append((name, when, FORK.unpack_from(ev, 16), cpu, seq))
        elif name == "exec":
            out.append((name, when, EXEC.unpack_from(ev, 16), cpu, seq))
        elif name == "exit":
            out.append((name, when, EXIT.unpack_from(ev, 16), cpu, seq))
        else:
            out.append((name, when, (seq, ack_, ANSWER.unpack_from(ev, 16)[0]), cpu, seq))
    return out


def wait_status(raw):
    """(code, signal) of the kernel's exit code, as wait(2) reads it: the exit status where the process exited,
    the signal that ended it where one did."""
    if raw & 0x7F == 0:
        return (raw >> 8) & 0xFF, None
    return None, raw & 0x7F


def stat_fields(raw):
    """(ppid, starttime in clock ticks since boot) of /proc/PID/stat's bytes; ValueError where they are not."""
    rest = raw.rsplit(b")", 1)[1].split() if b")" in raw else []
    if len(rest) < 20:
        raise ValueError("a stat of %d fields after its name" % len(rest))
    return int(rest[1]), int(rest[19])


def stat_name(raw):
    """CC-2: the name the kernel gave the process at its exec (the last part of the path that was run, cut to 15
    bytes), from /proc/PID/stat's bytes: the text between the first "(" and the last ")"; ValueError where there is
    none. Raw text of the process's choosing: a consumer that shows it must escape it."""
    if b"(" not in raw or b")" not in raw:
        raise ValueError("a stat with no name")
    return raw[raw.index(b"(") + 1:raw.rindex(b")")].decode("utf-8", "surrogateescape")


def _read_bytes(path):
    with open(path, "rb") as f:
        return f.read()


def _boot_ns():
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


class _Proc:
    __slots__ = ("pid", "ppid", "exe", "name", "earlier", "dropped", "started_ticks", "began", "ended", "code",
                 "signal",
                 "unread", "given", "queued", "forked", "execs", "threads", "leader_ended", "end_dropped",
                 "end_pending")

    def __init__(self, pid, ppid, began, unread, forked):
        self.pid, self.ppid, self.began, self.unread, self.forked = pid, ppid, began, unread, forked
        self.exe = self.name = self.started_ticks = self.ended = self.code = self.signal = self.leader_ended = None
        self.end_pending = None      # the end put in `ends` and not read yet
        self.end_dropped = False     # its end was past the bound of `ends`: never given (counted in `beyond`)
        self.earlier, self.threads, self.execs, self.dropped = [], set(), 0, 0
        self.given = self.queued = False

    def public(self, loss):
        unread = dict(self.unread)
        if not self.execs and loss:
            unread["exe"] = LOST_EXEC % loss
        if loss:
            unread["threads"] = LOST_THREADS % loss
        elif not self.forked:
            unread["threads"] = NO_FORK_THREADS
        if self.dropped:
            unread["earlier"] = EARLIER_DROPPED % (self.dropped, EARLIER_MAX)
        return {"pid": self.pid, "ppid": self.ppid, "exe": self.exe, "name": self.name,
                "earlier": [dict(e) for e in self.earlier], "dropped": self.dropped,
                "started_ticks": self.started_ticks, "began": self.began, "ended": self.ended, "code": self.code,
                "signal": self.signal, "unread": unread}

    def end(self):
        out = {"pid": self.pid, "started_ticks": self.started_ticks, "began": self.began, "ended": self.ended,
               "code": self.code, "signal": self.signal, "unread": {}}
        if self.ended is None:
            out["unread"]["ended"] = self.unread.get("ended", NO_END)
        if not self.forked:
            out["unread"]["threads"] = END_NOT_HELD
        return out


class Reader:
    """A listener of the kernel's process events and its thread. start() returns None, RUNNING for a reader
    already running, or the reason it was refused (beginning with PREFIX, also kept in `refused`) and raises
    nothing; read() and counts() are copies, from any thread; stop() returns the problems of the stop ([] when
    clean) and does nothing the second time. sockets: the socket's maker; readlink and read_bytes: the reads of
    /proc; clock: wall seconds; mono and boot: the monotonic and boot clocks in ns; urandom: the mark's bytes;
    ticks_per_second: stat's clock ticks (None: the system's); thread; at_exit; platform."""

    def __init__(self, pid=None, sockets=None, readlink=None, read_bytes=None, clock=None, mono=None, thread=None,
                 at_exit=None, platform=None, boot=None, urandom=None, ticks_per_second=None):
        self.pid = os.getpid() if pid is None else int(pid)
        self.refused = None
        self.ended = None            # why the thread ended before the stop (a hole), or None
        self.stop_problems = []
        self._sockets, self._readlink = sockets, readlink or os.readlink
        self._read_bytes = read_bytes or _read_bytes
        self._clock, self._mono, self._boot = clock or time.time, mono or time.monotonic_ns, boot or _boot_ns
        self._urandom, self._hz = urandom or os.urandom, ticks_per_second
        self._thread_class = thread or threading.Thread
        self._atexit = atexit if at_exit is None else at_exit
        self._platform = sys.platform if platform is None else platform
        self._atexit_registered = False
        self._lock = threading.Lock()
        self._mark = None            # the ask's ack: random, set at the start
        self._sock, self._thread, self._since, self._last, self._asked, self._answer = None, None, None, None, \
            False, None
        self._live, self._pending, self._ends, self._older = {}, [], [], []
        self._gone, self._refused_pids = {}, {}   # pid -> its ended record; pids the bound refused (both bounded)
        self._older_pids = {}        # pid -> (its later end, the read it waits for): ends given of processes not held
        self._seqs = {}              # cpu -> the kernel's last count of events heard on it (bounded)
        self._lost_events = self._untold = self._reads = 0
        self._back_said = self._boot_said = False
        self._events = {"fork": 0, "exec": 0, "exit": 0}
        self._missed = {"exe": 0, "stat": 0}
        self._unread, self._said = {}, []
        self._given = self._threads = self._lost = self._beyond = self._older_n = self._reused = 0
        self._state, self._stopping = "new", False

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.stop()
        return False

    # start -------------------------------------------------------------------------------
    def start(self):
        if self._state == "running":
            return RUNNING
        if self._state != "new":
            return PREFIX + "this reader was started once already (%s)" % self._state
        try:
            why = self._start()
        except Exception as exc:
            why = PREFIX + "the reader failed while starting: %s" % _flat(exc)
        except BaseException:
            self._undo()                 # an interrupt after the socket was made: closed, then let go up
            self._since, self._state = None, "refused"
            raise
        if why:
            self._undo()
            self.refused, self._state, self._since = why, "refused", None
            return why
        self._state = "running"
        self._atexit.register(self._stop_at_exit)   # stop() unregisters it
        self._atexit_registered = True
        return None

    def _start(self):
        if not str(self._platform).startswith("linux"):
            return PREFIX + "this is not Linux (%s): the process events are the Linux kernel's" % self._platform
        if self._hz is None:
            try:
                self._hz = int(os.sysconf("SC_CLK_TCK"))
            except (ValueError, OSError, AttributeError) as exc:
                self._said.append("the clock ticks of a second are not known (%s): no read is held against its"
                                  " exec's time" % _why(exc))
        self._mark = int.from_bytes(self._urandom(4), "little")
        maker = self._sockets or socket.socket
        try:
            sock = maker(AF_NETLINK, socket.SOCK_DGRAM, NETLINK_CONNECTOR)
        except OSError as exc:
            return refusal("socket", exc)
        self._sock = sock
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, RCVBUF_BYTES)
            kept = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
            if kept < 2 * RCVBUF_BYTES:  # the kernel reports twice the size it was asked for
                self._said.append("the socket's receive queue is reported as %d bytes, less than the %d the kernel"
                                  " reports for the %d asked (twice the asked): the system's maximum"
                                  % (kept, 2 * RCVBUF_BYTES, RCVBUF_BYTES))
        except OSError as exc:
            self._said.append("the socket's receive queue is left at the system's size (%s)" % _why(exc))
        try:
            sock.bind((self.pid, CN_IDX_PROC))
        except OSError as exc:
            return refusal("bind", exc)
        sock.settimeout(POLL_SECONDS)
        self._since = stamp(self._clock())
        try:
            sock.send(ask(self.pid, PROC_CN_MCAST_LISTEN, self._mark))
        except OSError as exc:
            return refusal("ask", exc)
        self._asked = True
        deadline = self._mono() + int(ANSWER_SECONDS * 1e9)
        while self._answer is None:      # what comes before the answer is taken as it comes
            if self._mono() >= deadline:
                why = PREFIX + ("the kernel did not answer the ask to listen within %g s (by the kernel's source, a"
                                " process outside the system's first namespaces, as in a container, is not"
                                " answered; not measured)" % ANSWER_SECONDS)
                if self._lost:
                    why += ("; the kernel's queue for this socket overflowed (ENOBUFS) %d time(s) while the answer"
                            " was awaited: the answer may be among what was lost" % self._lost)
                return why
            try:
                data = sock.recv(RECV_BYTES)
            except socket.timeout:
                continue
            except OSError as exc:
                if exc.errno == errno.ENOBUFS:
                    with self._lock:
                        self._lost += 1
                    continue
                return refusal("answer", exc)
            self._take(data)
        if self._answer != 0:
            return PREFIX + "the kernel answered the ask to listen with %s" % errname(self._answer)
        self._thread = self._thread_class(target=self._run, name="raqib-procevents", daemon=True)
        self._thread.start()
        return None

    def _undo(self):
        sock, self._sock = self._sock, None
        if sock is None:
            return
        if self._asked:
            try:
                sock.send(ask(self.pid, PROC_CN_MCAST_IGNORE, self._mark))
            except Exception:
                pass
        try:
            sock.close()
        except Exception:
            pass

    def _stop_at_exit(self):
        """Registered with atexit for a running reader: at the interpreter's exit a reader never stopped is
        stopped. stop() unregisters this."""
        if self._state == "running":
            self.stop()

    # the thread ----------------------------------------------------------------------------
    def _run(self):
        """The thread, guarded whole: whatever ends it before the stop is said in `ended` (BR-5)."""
        try:
            while self._once():
                pass
        except BaseException as exc:
            self._end_early("%s: %s" % (type(exc).__name__, " ".join(str(exc).split())))

    def _end_early(self, why):
        with self._lock:
            if not self._stopping and self.ended is None:
                self.ended = "the reader's thread ended before the stop (%s): from then on nothing is heard" % why

    def _once(self):
        """One datagram: received and taken. False when the thread is to end."""
        if self._stopping:
            return False
        try:
            data = self._sock.recv(RECV_BYTES)
        except socket.timeout:
            return True
        except Exception as exc:
            if isinstance(exc, OSError) and exc.errno == errno.ENOBUFS:
                with self._lock:
                    self._lost += 1
                return True
            self._end_early("its receive failed: %s" % _why(exc))
            return False
        self._take(data)
        return True

    def _count_unread(self, why):
        self._unread[why] = self._unread.get(why, 0) + 1

    def _take(self, data):
        """Every message of a datagram, under the lock. Raises nothing: what it cannot take is counted."""
        with self._lock:
            try:
                wall, mono = self._clock(), self._mono()
                self._last = stamp(wall)
                items = parse(bytes(data))
            except Exception as exc:
                self._count_unread("not read: %s" % type(exc).__name__)
                return
            try:
                offset = self._boot() - mono     # the boot clock less the monotonic one: time asleep
            except Exception as exc:
                offset = None
                if not self._boot_said:
                    self._boot_said = True
                    self._said.append("the boot clock cannot be read (%s): no read is held against its exec's time"
                                      % _why(exc))
            for kind, when, fields, cpu, seq in items:
                try:
                    if cpu is not None:      # an answer too: it takes the next number of its CPU (measured, BT)
                        self._count_seq(cpu, seq)
                    if kind == "unread":
                        self._count_unread(when)
                    elif kind == "answer":
                        self._on_answer(*fields)
                    else:
                        at = stamp(wall - (mono - when) / 1e9)
                        boot_ns = None if offset is None else when + offset
                        getattr(self, "_on_" + kind)(at, boot_ns, *fields)
                except Exception as exc:
                    self._count_unread("not read: %s" % type(exc).__name__)

    def _count_seq(self, cpu, seq):
        """BS-5: the kernel's count of events on a CPU. A step over a number is that many events lost at least;
        one seen while no ENOBUFS has come since the start is a loss the kernel did not tell (after an ENOBUFS a
        gap is not told apart from it: the ENOBUFS is read before its gaps show); a step back is said once and not
        counted. An answer to any listener's ask takes a number of the count as an event does."""
        last = self._seqs.get(cpu)
        if last is None:
            if len(self._seqs) >= CPUS_MAX:
                self._beyond += 1
                return
        else:
            step = (seq - last) & 0xFFFFFFFF
            if 1 < step < 0x80000000:
                self._lost_events += step - 1
                if not self._lost:
                    self._untold += step - 1
            elif step != 1 and not self._back_said:
                self._back_said = True
                self._said.append("the kernel's count of events on CPU %d went from %d to %d: a step that is not"
                                  " forward is not counted (said once)" % (cpu, last, seq))
        self._seqs[cpu] = seq

    def _on_answer(self, seq, ack_, err):
        if self._mark is not None and ack_ == (self._mark + 1) & 0xFFFFFFFF and self._answer is None:
            self._answer = err
        else:
            self._count_unread("an answer to another listener's ask")

    # the bound -----------------------------------------------------------------------------
    def _keep(self, rec):
        if len(self._live) >= PROCESSES_MAX or len(self._pending) >= PROCESSES_MAX:
            self._beyond += 1
            self._remember(self._refused_pids, rec.pid, True)
            return False
        self._live[rec.pid] = rec
        self._queue(rec)
        return True

    def _queue(self, rec):
        if rec.queued:
            return
        if len(self._pending) >= PROCESSES_MAX:
            self._beyond += 1
            return
        rec.queued = True
        self._pending.append(rec)

    def _hold(self, where, item):
        if len(where) >= PROCESSES_MAX:
            self._beyond += 1
        else:
            where.append(item)

    @staticmethod
    def _remember(table, pid, value):
        table.pop(pid, None)
        if len(table) >= PROCESSES_MAX:
            del table[next(iter(table))]       # the oldest: a memory for words, not a record
        table[pid] = value

    # the events ----------------------------------------------------------------------------
    def _on_fork(self, at, boot_ns, parent_pid, parent_tgid, pid, tgid):
        self._events["fork"] += 1
        if pid != tgid:              # a thread of the process tgid names
            self._threads += 1
            rec = self._live.get(tgid)
            if rec is not None:
                if len(rec.threads) >= PROCESSES_MAX:
                    self._beyond += 1
                else:
                    rec.threads.add(pid)
            return
        self._gone.pop(pid, None)    # a new process holds the pid
        self._refused_pids.pop(pid, None)
        self._older_pids.pop(pid, None)
        old = self._live.pop(pid, None)
        if old is not None:          # its end was lost: the pid begins again
            old.unread["ended"] = NO_END
            if old.given and not old.queued:
                self._hold(self._ends, old.end())
        self._keep(_Proc(pid, parent_tgid, at, {"exe": NO_EXEC_EXE, "stat": NO_EXEC_STAT}, True))

    def _read_exec(self, pid, boot_ns):
        """(exe, its why, ppid, ticks, the stat's why, another, name) read at once at an exec; a read of another
        process (its start later than the exec) gives nothing (BR-3) and `another` is True. CC-2: the name the
        kernel gave the process is read from the same stat."""
        exe = exe_why = ppid = ticks = stat_why = name = None
        try:
            exe = self._readlink("/proc/%d/exe" % pid)
        except Exception as exc:
            self._missed["exe"] += 1
            exe_why = self._missed_words(exc)
        try:
            raw = self._read_bytes("/proc/%d/stat" % pid)
            ppid, ticks = stat_fields(raw)
            name = stat_name(raw)
        except Exception as exc:
            self._missed["stat"] += 1
            stat_why = self._missed_words(exc)
            ppid = ticks = name = None
        if ticks is not None and self._hz and boot_ns is not None and \
                ticks / self._hz > boot_ns / 1e9 + REUSED_SECONDS:
            self._reused += 1
            return None, ANOTHER, None, None, ANOTHER, True, None
        return exe, exe_why, ppid, ticks, stat_why, False, name

    def _end_unread(self, end):
        """Whether `end` (a dict) is in `ends` and not read yet."""
        return any(e is end for e in self._ends)

    def _on_exec(self, at, boot_ns, pid, tgid):
        self._events["exec"] += 1
        if pid != tgid:
            self._threads += 1
            return
        exe, exe_why, ppid, ticks, stat_why, another, name = self._read_exec(pid, boot_ns)
        rec = self._live.get(pid)
        if rec is None:
            old = self._gone.get(pid)
            if old is not None and not another and old.started_ticks is not None and ticks is not None and \
                    ticks == old.started_ticks:
                rec = old                # an exec after its end, no fork between, its own start: it went on (BS-2)
            else:
                if pid in self._refused_pids:
                    began = BEYOND_BEGAN
                elif old is not None or pid in self._older_pids:
                    began = NO_FORK_AFTER_END
                else:
                    began = NO_FORK
                rec = _Proc(pid, None, None, {"began": began}, False)
            if not self._keep(rec):
                return
            if rec is old:
                del self._gone[pid]
                if old.end_pending is not None and self._end_unread(old.end_pending):
                    self._ends = [e for e in self._ends if e is not old.end_pending]   # withdrawn (BS-3)
                elif (old.end_pending is not None or (old.given and not old.queued)) and not old.end_dropped:
                    old.unread["ended"] = ENDED_BEFORE   # only of an end that was given: one past the bound never was
                old.end_pending, old.end_dropped = None, False
                old.ended = old.code = old.signal = None
            self._refused_pids.pop(pid, None)
            self._older_pids.pop(pid, None)
        else:
            self._queue(rec)         # given before: given again, with the program it became
        rec.threads.clear()          # an exec leaves one thread
        rec.leader_ended = None
        if rec.execs:                # BR-2: the program it had is kept, in order; the newest EARLIER_MAX (BS-4)
            rec.earlier.append({"exe": rec.exe, "name": rec.name,
                                "unread": {k: rec.unread[k] for k in ("exe", "name") if k in rec.unread}})
            if len(rec.earlier) > EARLIER_MAX:
                del rec.earlier[0]
                rec.dropped += 1
        rec.execs += 1
        rec.exe, rec.name = exe, name
        rec.unread.pop("exe", None)
        rec.unread.pop("name", None)
        if exe_why:
            rec.unread["exe"] = exe_why
        if stat_why:                 # CC-2: the name is read with the stat, and unread with it
            rec.unread["name"] = stat_why
        rec.unread.pop("stat", None)
        if ticks is not None and rec.started_ticks is not None and ticks != rec.started_ticks:
            self._reused += 1        # the start differs from this process's own: another holder was read
            ticks, ppid, stat_why = None, None, ANOTHER
            rec.name, rec.unread["name"] = None, ANOTHER
            if exe_why is None:
                rec.exe, rec.unread["exe"] = None, ANOTHER
        if ticks is not None:
            rec.started_ticks = ticks
        if rec.ppid is None and ppid is not None:
            rec.ppid = ppid          # no fork heard: the parent it has now
        if stat_why:
            rec.unread["stat"] = stat_why

    @staticmethod
    def _missed_words(exc):
        gloss = GLOSS.get(exc.errno) if isinstance(exc, OSError) else None
        return "not read at its exec (%s%s)" % (_why(exc), ": %s" % gloss if gloss else "")

    def _finish(self, rec, at, raw_code):
        rec.ended, (rec.code, rec.signal) = at, wait_status(raw_code)
        self._live.pop(rec.pid, None)
        self._remember(self._gone, rec.pid, rec)
        if rec.given and not rec.queued:
            end = rec.end()
            if len(self._ends) < PROCESSES_MAX:
                rec.end_pending = end
            else:
                rec.end_dropped = True
            self._hold(self._ends, end)

    def _on_exit(self, at, boot_ns, pid, tgid, raw_code, raw_signal):
        self._events["exit"] += 1
        code, sig = wait_status(raw_code)
        if pid != tgid:              # a thread's end; the process's where its leader ended and it was the last
            self._threads += 1
            rec = self._live.get(tgid)
            if rec is not None:
                if pid in rec.threads:
                    rec.threads.discard(pid)
                    if rec.leader_ended is not None and not rec.threads:
                        self._finish(rec, at, raw_code)
                return
            if tgid in self._older_pids:   # BS-3: after an end of a process not held, its thread's end is the later
                later, read_no = self._older_pids[tgid]
                if later is not None and read_no == self._reads and any(e is later for e in self._older):
                    later.update(ended=at, code=code, signal=sig)
                    return
                later = {"pid": tgid, "started_ticks": None, "began": None, "ended": at, "code": code,
                         "signal": sig, "unread": {"began": NO_FORK, "ended": LATER_END, "threads": LATER_THREADS}}
                self._older_n += 1
                self._hold(self._older, later)
                self._older_pids[tgid] = (later, self._reads)
            return
        rec = self._live.get(pid)
        if rec is None:
            self._older_n += 1
            began = BEYOND_BEGAN if self._refused_pids.pop(pid, None) else NO_FORK
            self._hold(self._older, {"pid": pid, "started_ticks": None, "began": None, "ended": at, "code": code,
                                     "signal": sig, "unread": {"began": began, "threads": END_NOT_HELD}})
            self._remember(self._older_pids, pid, (None, self._reads))
            return
        if rec.threads:              # the leader thread's end: the process lives on in its threads (BR-1)
            rec.leader_ended = at
            return
        self._finish(rec, at, raw_code)

    # the reader's face -----------------------------------------------------------------------
    def _loss(self):
        """The words of what was lost, or None where nothing was."""
        if not self._lost and not self._lost_events:
            return None
        return "ENOBUFS %d time(s), at least %d event(s) by the kernel's count" % (self._lost, self._lost_events)

    def read(self):
        """A copy: {"processes": every process that began, or changed its program, since the read before, each
        {pid, ppid, exe, earlier, started_ticks, began, ended, code, signal, unread}; "ends": the ends of
        processes given before, each {pid, started_ticks, began, ended, code, signal, unread}; "older": the ends
        of processes never kept, in the same shape}. Where events were lost, every end says its threads are not
        known (BS-3)."""
        with self._lock:
            loss = self._loss()
            out = []
            for rec in self._pending:
                out.append(rec.public(loss))
                rec.given, rec.queued = True, False
            self._given += len(out)
            ends, older = self._ends, self._older
            self._pending, self._ends, self._older = [], [], []
            self._reads += 1
            if loss:
                for e in ends + older:
                    e["unread"]["threads"] = END_LOST % loss
            return {"processes": out, "ends": ends, "older": older}

    def counts(self):
        """A copy: "since" (the ask's time; None before it and after a refused start), "last" (when a datagram
        was last heard, None before any), "events" ({fork, exec, exit} heard, threads too), "given" (records
        given by read()), "missed" ({exe, stat}: reads at an exec that failed - reads, not processes), "unread"
        ({kind: n}), "threads" (events of threads), "older", "reused" (reads of another process), "lost"
        ({"count": the kernel's ENOBUFS, "events": events lost at least by the kernel's count, "why"}), "beyond"
        (events or records past a bound - not processes), "live" (processes kept whose end is not heard),
        "refused", "ended", "said"."""
        with self._lock:
            parts = []
            if self._lost:
                parts.append("the kernel's queue for this socket overflowed %d time(s) (ENOBUFS): what the queue held"
                             " is given; what came while it was full is gone" % self._lost)
            if self._lost_events:
                parts.append("how many: at least %d event(s) by the kernel's own count on each CPU (a count from"
                             " below)" % self._lost_events)
            if self._untold:
                parts.append("%d of them came before any ENOBUFS: a loss the kernel did not tell" % self._untold)
            return {"since": self._since, "last": self._last, "events": dict(self._events), "given": self._given,
                    "missed": dict(self._missed), "unread": dict(self._unread), "threads": self._threads,
                    "older": self._older_n, "reused": self._reused,
                    "lost": {"count": self._lost, "events": self._lost_events, "why": "; ".join(parts) or None},
                    "beyond": self._beyond, "live": len(self._live), "refused": self.refused, "ended": self.ended,
                    "said": list(self._said)}

    def stop(self):
        """Ends the thread, asks the kernel to stop sending, closes the socket. Raises nothing; the second call
        does nothing."""
        if self._state != "running":
            return []
        self._state = "stopping"
        with self._lock:
            self._stopping = True
        problems = []
        if self._thread is not None:
            try:
                self._thread.join(JOIN_SECONDS)
                if self._thread.is_alive():
                    problems.append("the reader's thread did not end within %g s of the stop" % JOIN_SECONDS)
            except Exception as exc:
                problems.append("the reader's thread could not be waited for (%s)" % _flat(exc))
        sock, self._sock = self._sock, None
        try:
            sock.send(ask(self.pid, PROC_CN_MCAST_IGNORE, self._mark))
        except Exception as exc:
            problems.append("the ask to stop listening failed (%s)" % _why(exc))
        try:
            sock.close()
        except Exception as exc:
            problems.append("the socket could not be closed (%s)" % _flat(exc))
        if self._atexit_registered:
            self._atexit.unregister(self._stop_at_exit)
            self._atexit_registered = False
        self._state = "stopped"
        self.stop_problems = problems
        return problems


# --- the helper (ADR-0007 Amendments BU and BW): the reader in a process of its own -------------------------------
VERSION = 1                # every line the helper writes carries "v": VERSION (BW-8)
SERVE_MAX = 2000           # entries one answer holds at most, processes, ends and older together (BU-2); the rest next
LINE_MAX = 1 << 20         # bytes one line of the helper holds at most, its newline included (BW-1)
HELD_LINES = 4             # lines of the helper the client holds unread at most (BW-1)
ASK_SECONDS = 2.0          # the longest the watch waits for an answer; a watch's own is at most its interval / 4
STARTING_SECONDS = 5.0     # until the ready line comes: `starting` for this long after the start, then `late` (BW-4)
STOP_SECONDS = 2.0         # stop(): how long the helper is waited for once its input is closed, before it is ended
KILL_SECONDS = 1.0         # and after it is ended, before it is killed
LATE, ENDED, NOT_A_LINE, REFUSED, STARTING = "late", "ended", "not a line", "refused", "starting"   # not an answer
TOO_LONG = object()        # the client's mark of a line longer than LINE_MAX
FULL = "its input was full: the ask could not be written without waiting"   # BY-6: said as the helper's end
NOT_A_COMMAND = "not a command: the helper answers `read`, `read N` and `stop`"
ANSWER_KEYS = ("v", "ask", "processes", "ends", "older", "more", "counts")
TOO_LONG_EXE = "its program's path is not given: the record alone would pass the line's bound (LINE_MAX)"
# the helper's program (BW-5): a constant; its one argument is the watch's own import path as JSON
PATH_PROGRAM = "import json, sys; sys.path[:] = json.loads(sys.argv[1])"
SERVE_PROGRAM = PATH_PROGRAM + "; from raqib import procevents; sys.exit(procevents.main(['--serve']))"
# CG-1 (M17.2a): where Raqib is packed with its own runtime (sys.frozen), the helper is the packed program and this
# word, its only argument; Raqib's entry (raqib/cli.py main, so every `raqib`) takes it before anything else (word())
WORD = "__raqib_procevents_helper__"
WORD_USAGE = "the helper of the process events takes no argument (ADR-0007 CG-1)"   # never names the word (CG-2)


def _line(value):
    return json.dumps(dict(value, v=VERSION), sort_keys=True, ensure_ascii=True) + "\n"


def _size(value):
    return len(json.dumps(value, sort_keys=True, ensure_ascii=True))


def _shrunk(entry):
    """An entry whose program paths are not given, each said unread (an entry alone past LINE_MAX)."""
    out = dict(entry)
    unread = dict(out.get("unread") or {})
    if "exe" in out:
        out["exe"] = None
        unread["exe"] = TOO_LONG_EXE
    if out.get("earlier"):
        out["earlier"] = [{"exe": None, "name": e.get("name") if isinstance(e, dict) else None,
                           "unread": {"exe": TOO_LONG_EXE}} for e in out["earlier"]]
    out["unread"] = unread
    return out


def pack(held, counts, ask, bound=SERVE_MAX, line_max=LINE_MAX):
    """One answer from `held` ({processes, ends, older}, taken from in place): its entries in order until the line
    would pass `line_max` bytes or hold `bound` entries; "more" where any is left. An entry that alone would pass
    the line's bound is given with its programs unread (TOO_LONG_EXE)."""
    out = {"ask": ask, "processes": [], "ends": [], "older": [], "more": False, "counts": counts}
    size, room = len(_line(out)), bound
    for key in ("processes", "ends", "older"):
        while held[key] and room > 0:
            entry, cost = held[key][0], _size(held[key][0]) + 2   # the entry and its ", "
            if size + cost > line_max:
                if out["processes"] or out["ends"] or out["older"]:
                    break            # it comes with the next answer
                entry = _shrunk(entry)
                cost = _size(entry) + 2
                if size + cost > line_max:
                    break            # never: a record with no path is small
            out[key].append(entry)
            del held[key][0]
            size, room = size + cost, room - 1
        if held[key]:
            break
    out["more"] = any(held.values())
    return out


def serve(stdin=None, stdout=None, reader=None, bound=SERVE_MAX, line_max=LINE_MAX):
    """BU-1, BW-1, BW-8: the helper's loop. Starts the reader, says `{"ready": null, "v": 1}` (or the refusal in
    "ready", and returns 0), then answers each line of stdin: `read` or `read N` -> one JSON line {"v", "ask",
    "processes", "ends", "older", "more", "counts"} of at most `line_max` bytes and `bound` entries (pack(); what
    does not fit comes with the next `read`, and "more" says so; "ask" is N, or None); `stop` or the end of stdin
    -> the reader stopped, 0; any other line, `read` with anything int() refuses -> {"error": NOT_A_COMMAND, "v"}
    (the line is not echoed) and the helper lives. A new read() of the reader is taken only when what it holds
    from the reads before was given whole, so what it holds is bounded by the reader's own bounds. serve itself
    reads only its input and writes only its output; its Reader reads the kernel's socket and, at each exec,
    /proc/PID/exe and /proc/PID/stat. 1 where the output cannot be written."""
    stdin = sys.stdin if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    reader = Reader() if reader is None else reader
    held = {"processes": [], "ends": [], "older": []}
    try:
        why = reader.start()
        if why == RUNNING:
            why = None
        try:
            stdout.write(_line({"ready": why}))
            stdout.flush()
        except (OSError, ValueError):
            return 1
        if why:
            return 0
        for raw in stdin:
            words = raw.split()
            if words == ["stop"]:
                return 0
            number = None
            ok = bool(words) and words[0] == "read" and len(words) <= 2
            if ok and len(words) == 2:
                try:
                    number = int(words[1])
                except ValueError:
                    ok = False
            if not ok:
                out = {"error": NOT_A_COMMAND}
            else:
                if not any(held.values()):
                    got = reader.read()
                    for key in held:
                        held[key] = list(got.get(key) or ())
                out = pack(held, reader.counts(), number, bound, line_max)
            try:
                stdout.write(_line(out))
                stdout.flush()
            except (OSError, ValueError):
                return 1
        return 0
    finally:
        reader.stop()


def main(argv=None):
    """`python -m raqib.procevents --serve`, the helper's own program (SERVE_PROGRAM) and a packed Raqib given WORD
    (word(), CG-1): the helper (BU-1). A
    Ctrl-C at the terminal does not end it: the end of its input does, so a watch that dies leaves none behind."""
    argv = sys.argv[1:] if argv is None else argv
    if argv != ["--serve"]:
        sys.stderr.write("usage: python -m raqib.procevents --serve\n")
        return 2
    if hasattr(signal, "SIGINT"):
        signal.signal(signal.SIGINT, signal.SIG_IGN)
    return serve()


def word(argv, stderr=None):
    """CG-1, CG-2 (M17.2a): the entry's first look at its arguments (raqib/cli.py main, before anything else).
    None where the first argument is not WORD: the entry goes on as it always did. Exactly [WORD]: the helper, as
    `python -m raqib.procevents --serve` is (main(['--serve']): SIGINT ignored, it ends with its input), and nothing
    else of the arguments is read. WORD with anything after it: a usage error, 2, said in words that do not name
    the word. Packed or not, one entry, one behaviour; a watch that is not packed never starts it this way."""
    argv = list(argv or ())
    if argv[:1] != [WORD]:
        return None
    if len(argv) != 1:
        (sys.stderr if stderr is None else stderr).write("raqib: %s\n" % WORD_USAGE)
        return 2
    return main(["--serve"])


def command(executable=None, path=None, frozen=None):
    """BW-5, BY-6: the helper's command: this interpreter, always -I (isolated: no user site folder, no PYTHON*
    variable of the environment, no directory of its own before the path), -c SERVE_PROGRAM, a constant; its one
    argument this process's import path, its absolute entries in order, as JSON. The helper loads Raqib from where
    this process did, and from nowhere else: it needs nothing of the user's environment or site folder.
    CG-1 (M17.2a): where this process is a packed program (`frozen`: sys.frozen, which a packer such as PyInstaller
    sets), its sys.executable is that program and no interpreter: the helper is the same program with WORD as its
    only argument, and the import path is not given (a packed program loads Raqib from what it carries)."""
    executable = sys.executable if executable is None else executable
    if bool(getattr(sys, "frozen", False)) if frozen is None else frozen:
        return [executable, WORD]
    path = [p for p in (sys.path if path is None else path) if isinstance(p, str) and os.path.isabs(p)]
    return [executable, "-I", "-c", SERVE_PROGRAM, json.dumps(path)]


def _pump(out, lines, stop, line_max=LINE_MAX):
    """The client's thread: each line of the helper's output into `lines` (a queue of HELD_LINES), a line longer
    than `line_max` as TOO_LONG (the rest of it read and let go), then None at its end. It holds the pipe and the
    queue, never the client; a full queue waits, and a stop lets it go."""
    def put(item):
        while True:
            try:
                lines.put(item, timeout=0.2)
                return True
            except queue.Full:
                if stop.is_set():
                    return False
    try:
        while True:
            raw = out.readline(line_max + 1)
            if not raw:
                break
            if len(raw) > line_max or not raw.endswith(b"\n"):
                while raw and not raw.endswith(b"\n"):
                    raw = out.readline(line_max + 1)
                if not put(TOO_LONG):
                    return
                if not raw:
                    break
                continue
            if not put(raw):
                return
    except Exception:
        pass
    put(None)


class Helper:
    """The watch's client of the helper (BU-1, BU-2, BW-1, BW-4, BW-5). start() returns None or why the helper
    could not be started (and raises nothing), and does not wait for it: the process is started by `popen` (in
    the directory /, command()) and handed at once to `started` (raqib/own.py: the watch's record). ask(timeout)
    -> (the answer, None) or (None, LATE | ENDED | NOT_A_LINE | REFUSED | STARTING). At most one ask is
    unanswered: while one is, ask writes nothing and waits for that answer, and an answer that comes after its
    round is taken by the ask that reads it. Before the ready line it says STARTING for STARTING_SECONDS after the
    start, then LATE. It waits at most its timeout: a thread reads the helper's output, lines of at most LINE_MAX
    bytes (a longer one is NOT_A_LINE), at most HELD_LINES of them held unread. stop() closes the helper's input,
    waits STOP_SECONDS, then ends it, and returns its problems ([] when clean); a second stop() does nothing."""

    def __init__(self, started=None, popen=None, argv=None, thread=None, clock=None):
        self._started = started or (lambda proc: proc)
        self._popen = popen
        self.argv = list(argv) if argv is not None else command()
        self._thread_class = thread or threading.Thread
        self._clock = clock or time.monotonic
        self.proc = None
        self.ready = False
        self.refused = None
        self.ended = False           # its output ended: the helper is gone
        self.ended_why = None        # BY-6: why, where it is not that its output ended (its input full)
        self.asks = 0                # asks written
        self.outstanding = None      # the number of the ask written and not answered yet
        self.began = None            # when it was started (the clock's)
        self.stop_problems = None
        self._lines = queue.Queue(HELD_LINES)
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        if self.proc is not None:
            return None
        try:
            popen = self._popen
            if popen is None:
                import subprocess
                popen = subprocess.Popen
                kw = {"stdin": subprocess.PIPE, "stdout": subprocess.PIPE, "stderr": subprocess.DEVNULL,
                      "close_fds": True, "cwd": "/"}
            else:
                kw = {"cwd": "/"}
            self.began = self._clock()
            self.proc = self._started(popen(self.argv, **kw))
        except Exception as exc:
            self.proc = None
            return "the helper could not be started (%s)" % _flat(exc)
        self._fd = None   # BY-6: the ask is written to a pipe that does not block; a full one is the helper's end
        fileno = getattr(self.proc.stdin, "fileno", None)
        if fileno is not None:   # an input with no descriptor (a test's stand-in) is written as it is
            try:
                fd = fileno()
                os.set_blocking(fd, False)
                self._fd = fd
            except Exception as exc:   # BZ-12: an input that cannot be made unblocking is the helper not started
                self.stop(0)
                return "the helper's input could not be made unblocking (%s)" % _flat(exc)
        try:   # the thread holds the pipe and the queue, not the client: a client let go ends its helper
            self._thread = self._thread_class(target=_pump, args=(self.proc.stdout, self._lines, self._stop),
                                              name="raqib-procevents-helper", daemon=True)
            self._thread.start()
        except Exception as exc:
            self._thread = None
            self.stop()
            return "the helper's output could not be read (%s)" % _flat(exc)
        return None

    def _next(self, deadline):
        """The next line of the helper's output, None at its end, TOO_LONG, or LATE where none came in time. One
        line at most: it never loops."""
        left = deadline - self._clock()
        try:
            return self._lines.get(timeout=left) if left > 0 else self._lines.get_nowait()
        except queue.Empty:
            return LATE

    @staticmethod
    def _parse(raw):
        """The line as a dict of this protocol's version, or None."""
        if raw is TOO_LONG or not isinstance(raw, (bytes, str)):
            return None
        try:
            value = json.loads(raw.decode("ascii") if isinstance(raw, bytes) else raw)
        except (ValueError, UnicodeDecodeError, RecursionError):
            return None
        if not isinstance(value, dict) or value.get("v") != VERSION or isinstance(value.get("v"), bool):
            return None
        return value

    @staticmethod
    def _answer(got, number):
        """Whether `got` is the answer to ask `number`, in its shape."""
        return (got is not None and set(got) == set(ANSWER_KEYS) and got["ask"] == number
                and isinstance(got["ask"], int) and not isinstance(got["ask"], bool)
                and all(isinstance(got[k], list) for k in ("processes", "ends", "older"))
                and isinstance(got["more"], bool) and isinstance(got["counts"], dict))

    def _end(self):
        self.ended = True
        return None, ENDED

    def ask(self, timeout=ASK_SECONDS):
        if self.refused is not None:
            return None, REFUSED
        if self.proc is None or self.ended:
            return None, ENDED
        deadline = self._clock() + timeout
        if not self.ready:
            raw = self._next(deadline)
            if raw is LATE:
                starting = self.began is not None and self._clock() - self.began < STARTING_SECONDS
                return None, STARTING if starting else LATE
            if raw is None:
                return self._end()
            first = self._parse(raw)
            if first is None or set(first) != {"v", "ready"} or not (first["ready"] is None or isinstance(
                    first["ready"], str)):
                return None, NOT_A_LINE
            if first["ready"] is not None:
                self.refused = first["ready"]
                return None, REFUSED
            self.ready = True
        if self.outstanding is None:   # BW-1: a new ask only where the last was answered
            self.asks += 1
            line = b"read %d\n" % self.asks
            try:
                if getattr(self, "_fd", None) is None:
                    self.proc.stdin.write(line)
                    self.proc.stdin.flush()
                elif getattr(self.proc.stdin, "raw", self.proc.stdin).write(line) != len(line):
                    raise BlockingIOError("a part of the ask was written")   # BY-6: never blocks; None or a part: full
            except BlockingIOError:
                self.ended_why = FULL
                self._stop.set()
                return self._end()
            except (OSError, ValueError):
                return self._end()
            self.outstanding = self.asks
        raw = self._next(deadline)
        if raw is LATE:
            return None, LATE
        if raw is None:
            return self._end()
        got = self._parse(raw)
        if not self._answer(got, self.outstanding):
            return None, NOT_A_LINE
        self.outstanding = None
        return got, None

    def __del__(self):
        """A client let go without stop(): its helper's input is closed, so the helper ends (BU-1). subprocess
        keeps a Popen whose child runs alive to reap it later, so the pipe would not close by itself."""
        proc = getattr(self, "proc", None)
        if proc is not None and getattr(self, "stop_problems", None) is None:
            try:
                self._stop.set()
                proc.stdin.close()
            except Exception:
                pass

    def stop(self, within=None):
        """Ends the helper. Without `within`: its input is closed and it is given STOP_SECONDS to end by itself
        (the watch's own Stop). With `within` (seconds; ADR-0007 BX-1, the second review's M1: a helper the watch
        ends inside a round - late, ended or refused): its input is closed and it is ended at once, and each wait
        is at most `within`, so the round that ends it is not held for the helper's sake."""
        if self.stop_problems is not None:
            return []
        self.stop_problems = problems = []
        self._stop.set()
        proc = self.proc
        if proc is None:
            return problems
        try:
            proc.stdin.close()
        except Exception as exc:
            problems.append("the helper's input could not be closed (%s)" % _flat(exc))
        wait = KILL_SECONDS if within is None else max(0.0, min(KILL_SECONDS, within))
        try:
            if within is not None:
                raise TimeoutError("ended at once")
            proc.wait(STOP_SECONDS)
        except Exception:
            if within is None:
                problems.append("the helper did not end within %g s of its input's end: it was ended" % STOP_SECONDS)
            try:
                if within is not None:   # a stopped process takes no SIGTERM until it is continued: the kill ends it
                    raise TimeoutError("ended at once")
                proc.terminate()
                proc.wait(wait)
            except Exception:
                try:
                    proc.kill()
                    proc.wait(wait)
                except Exception as exc:
                    problems.append("the helper could not be ended (%s)" % _flat(exc))
        if self._thread is not None:   # its output ends with it: the thread that read it ends too (bounded)
            try:
                self._thread.join(wait)
            except Exception:
                pass
        return problems


if __name__ == "__main__":
    sys.exit(main())
