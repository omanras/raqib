"""Linux: the processes that began, read from the kernel's own process events
(the netlink connector: fork, exec, exit) by a listener of the reader's own
(ADR-0007 Amendment BQ, BQ-1 and BQ-2). This is the reader alone: no watch
reads it yet. docs/specs/PROC-EVENTS.md says all of it in prose.

The messages, as measured (the probe branch, kernels 6.8 and 7.0): a socket
of AF_NETLINK, SOCK_DGRAM, protocol 11 (the connector), bound to (the
reader's pid, group 1). One message asks to listen: a netlink header of 16
bytes (=IHHII: length, type 3, flags 0, seq 0, the reader's pid), a
connector header of 20 bytes (=IIIIHH: idx 1, val 1, seq 0, ack, len 4,
flags 0) and the u32 1. The kernel answers the ask (an event of `what` 0
whose u32 at 16 is an errno, 0 when the ask was taken, its connector ack the
ask's plus 1; its seq is the kernel's own count, measured on 6.18); the ask's
ack is the reader's pid, so its answer is told from another listener's.
start() waits for that answer, so a kernel that takes the ask and says
nothing is a refusal, not a silence. An event is a netlink header, a connector header, then
`what` u32, cpu u32, the kernel's time u64 (=IIQ, nanoseconds of the
monotonic clock), then: fork (0x1) parent pid, parent tgid, child pid, child
tgid (=IIII at 16); exec (0x2) pid, tgid (=II at 16); exit (0x80000000) pid,
tgid, code, signal (=IIII at 16: the code at 24). Several messages may come
in one datagram, each padded to 4 bytes. A thread (tgid not equal to pid)
is not a process: it is counted in `threads` and nothing else. A message
shorter than its shape, of another `what` (uid, gid, sid, ptrace, comm,
coredump, ...), of another connector or another netlink type is counted as
unread by its kind, never guessed.

What is read at an exec, at once, and nothing else of the process: the link
/proc/PID/exe (the program) and /proc/PID/stat (the parent and the start in
clock ticks). No argument, no environment, no working directory, no file of
the process is read, and nothing at a fork or an exit. A read that fails (the
process gone before it, or not this user's) is counted in `missed` and named
in the process's `unread`. The parent is the fork's where the fork was heard
(the kernel's word at the moment the process began), else the stat's. The
exit's code is the kernel's wait status: `code` is the exit status where the
process exited, `signal` the signal that ended it where one did; the event's
own exit_signal (the signal the parent is sent, SIGCHLD) is not kept.

read() gives the processes that began (or changed their program) since the
read before, and the ends of processes given before (`ends`), and the ends of
processes it never heard begin (`older`: older than the reader, or their
beginning lost). Every way it loses an event is counted: the kernel's ENOBUFS
(its queue for this socket overflowed: what it held is gone), a read missed,
a message unread, PROCESSES_MAX passed (`beyond`: what is past the bound is
counted, not kept), a thread that ended before the stop (`ended`).

No rights, no asking: a start the system refuses (not Linux; the socket, the
bind or the ask refused, with the system's errno name; no answer) returns
its reason in this module's words and raises nothing. Ended on every way
out: stop() ends the thread, asks the kernel to stop sending (op 2) and
closes the socket, and a second stop() does nothing; the Reader is a context
manager; a reader started and never stopped is stopped at the interpreter's
exit (atexit, which stop() unregisters).

Everything of the system goes through arguments a test replaces: the
socket's maker, the reads of /proc, the clocks, the thread class, the exit
registry, the platform. The standard library only. It imports `socket` for
AF_NETLINK alone (a test replaces socket.socket and fails on any other
family); it starts no program and writes no file. It imports on every
system: nothing of Linux is touched until start().
"""
from __future__ import annotations

import atexit
import datetime
import errno
import os
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
PROCESSES_MAX = 32768      # the most processes (and ends) it keeps; what is past it is counted `beyond`
RECV_BYTES = 65536
RCVBUF_BYTES = 1 << 20     # asked of the socket's receive queue; the system may keep less
POLL_SECONDS = 0.25        # the socket's timeout: how soon the thread sees a stop
ANSWER_SECONDS = 2.0       # how long start() waits for the kernel's answer to the ask
JOIN_SECONDS = 5.0
PREFIX = "the process events are not read: "
NO_EXEC_EXE = "no exec heard: its program is its parent's, not read"
NO_EXEC_STAT = "no exec heard: its stat is not read"
NO_FORK = "no fork heard: it began before the reader, or its fork was lost"
NO_END = "its end was not heard before its pid began again"
GLOSS = {errno.ENOENT: "gone before the read", errno.ESRCH: "gone before the read",
         errno.EACCES: "not this user's to read", errno.EPERM: "not this user's to read"}


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


def ask(pid, op=PROC_CN_MCAST_LISTEN, nonce=0):
    """The message that asks the kernel to listen (op 1) or to stop (op 2): 40 bytes. `nonce` is its connector
    ack: the kernel answers with it plus 1."""
    body = CN.pack(CN_IDX_PROC, CN_VAL_PROC, 0, nonce & 0xFFFFFFFF, 4, 0) + struct.pack("=I", op)
    return NLMSG.pack(NLMSG.size + len(body), NLMSG_DONE, 0, 0, pid & 0xFFFFFFFF) + body


def refusal(step, exc):
    """The reason, in this module's words, a step of the start was refused."""
    what = {"socket": "the socket (AF_NETLINK, the connector) was refused",
            "bind": "the bind to the connector's group of process events was refused",
            "ask": "the ask to listen was refused",
            "answer": "the kernel's answer to the ask could not be read"}[step]
    name = _why(exc)
    more = ""
    if isinstance(exc, OSError) and exc.errno in (errno.EPERM, errno.EACCES):
        more = ("; this kernel keeps its process events from this user (a kernel older than 6.8 may keep them for"
                " root), and no right is asked")
    return PREFIX + "%s (%s)%s" % (what, name, more)


def parse(data):
    """Every message of one datagram, in order: (kind, time_ns, fields) - a fork (parent pid, parent tgid, child
    pid, child tgid), an exec (pid, tgid), an exit (pid, tgid, code, signal as the kernel gives them), an answer
    (seq, ack, errno) - or ("unread", why, None) for what is not read. Never guesses, never raises on bytes."""
    out, at, n = [], 0, len(data)
    if not n:
        return [("unread", "an empty datagram", None)]
    while at < n:
        if n - at < NLMSG.size:
            out.append(("unread", "a datagram's tail shorter than a netlink header", None))
            break
        length, kind = NLMSG.unpack_from(data, at)[:2]
        if length < NLMSG.size or at + length > n:
            out.append(("unread", "a netlink message whose length is not in its datagram", None))
            break
        body = data[at + NLMSG.size:at + length]
        at += (length + 3) & ~3
        if kind != NLMSG_DONE:
            out.append(("unread", "a netlink message of type %d" % kind, None))
            continue
        if len(body) < CN.size:
            out.append(("unread", "a connector message shorter than its header", None))
            continue
        idx, val, seq, ack_, size, _ = CN.unpack_from(body, 0)
        if (idx, val) != (CN_IDX_PROC, CN_VAL_PROC):
            out.append(("unread", "a message of another connector (%d, %d)" % (idx, val), None))
            continue
        ev = body[CN.size:CN.size + size]
        if len(ev) < size or size < EVENT.size:
            out.append(("unread", "an event shorter than its header", None))
            continue
        what, _, when = EVENT.unpack_from(ev, 0)
        name = KINDS.get(what)
        if name is None:
            out.append(("unread", OTHER_WHAT.get(what, "what 0x%x" % what), None))
        elif len(ev) < SHAPE[name]:
            out.append(("unread", "%s shorter than its shape" % name, None))
        elif name == "fork":
            out.append((name, when, FORK.unpack_from(ev, 16)))
        elif name == "exec":
            out.append((name, when, EXEC.unpack_from(ev, 16)))
        elif name == "exit":
            out.append((name, when, EXIT.unpack_from(ev, 16)))
        else:
            out.append((name, when, (seq, ack_, ANSWER.unpack_from(ev, 16)[0])))
    return out


def wait_status(raw):
    """(code, signal) of the kernel's exit code, as wait(2) reads it: the exit status where the process exited,
    the signal that ended it where one did."""
    if raw & 0x7F == 0:
        return (raw >> 8) & 0xFF, None
    return None, raw & 0x7F


def stat_fields(raw):
    """(ppid, starttime in clock ticks) of /proc/PID/stat's bytes; raises ValueError where they are not there."""
    rest = raw.rsplit(b")", 1)[1].split() if b")" in raw else []
    if len(rest) < 20:
        raise ValueError("a stat of %d fields after its name" % len(rest))
    return int(rest[1]), int(rest[19])


def _read_bytes(path):
    with open(path, "rb") as f:
        return f.read()


class _Proc:
    __slots__ = ("pid", "ppid", "exe", "started_ticks", "began", "ended", "code", "signal", "unread", "given",
                 "queued")

    def __init__(self, pid, ppid, began, unread):
        self.pid, self.ppid, self.began, self.unread = pid, ppid, began, unread
        self.exe = self.started_ticks = self.ended = self.code = self.signal = None
        self.given = self.queued = False

    def public(self):
        return {"pid": self.pid, "ppid": self.ppid, "exe": self.exe, "started_ticks": self.started_ticks,
                "began": self.began, "ended": self.ended, "code": self.code, "signal": self.signal,
                "unread": dict(self.unread)}

    def end(self):
        out = {"pid": self.pid, "started_ticks": self.started_ticks, "ended": self.ended, "code": self.code,
               "signal": self.signal, "unread": {}}
        if self.ended is None:
            out["unread"] = {"ended": self.unread.get("ended", NO_END)}
        return out


class Reader:
    """A listener of the kernel's process events and its thread. start() returns None or the reason it was
    refused (also kept in `refused`) and raises nothing; read() and counts() are copies, from any thread; stop()
    returns the problems of the stop ([] when clean) and does nothing the second time. sockets: the socket's
    maker (socket.socket); readlink and read_bytes: the reads of /proc; clock: wall seconds; mono: the monotonic
    clock in ns (the kernel's events are stamped by it); thread: the thread class; at_exit: the exit registry."""

    def __init__(self, pid=None, sockets=None, readlink=None, read_bytes=None, clock=None, mono=None, thread=None,
                 at_exit=None, platform=None):
        self.pid = os.getpid() if pid is None else int(pid)
        self.refused = None
        self.ended = None            # why the thread ended before the stop (a hole), or None
        self.stop_problems = []
        self._sockets, self._readlink = sockets, readlink or os.readlink
        self._read_bytes = read_bytes or _read_bytes
        self._clock, self._mono = clock or time.time, mono or time.monotonic_ns
        self._thread_class = thread or threading.Thread
        self._atexit = atexit if at_exit is None else at_exit
        self._platform = sys.platform if platform is None else platform
        self._atexit_registered = False
        self._lock = threading.Lock()
        self._nonce = self.pid & 0xFFFFFFFF   # the connector ack of the ask: its answer carries it plus 1
        self._sock, self._thread, self._since, self._asked, self._answer = None, None, None, False, None
        self._live, self._pending, self._ends, self._older = {}, [], [], []
        self._events = {"fork": 0, "exec": 0, "exit": 0}
        self._missed = {"exe": 0, "stat": 0}
        self._unread, self._said = {}, []
        self._given = self._threads = self._lost = self._beyond = self._older_n = 0
        self._state, self._stopping = "new", False

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.stop()
        return False

    # start -------------------------------------------------------------------------------
    def start(self):
        if self._state != "new":
            return "this reader was started once already (%s)" % self._state
        try:
            why = self._start()
        except Exception as exc:
            why = PREFIX + "the reader failed while starting: %s" % _flat(exc)
        except BaseException:
            self._undo()                 # an interrupt after the socket was made: closed, then let go up
            self._state = "refused"
            raise
        if why:
            self._undo()
            self.refused, self._state = why, "refused"
            return why
        self._state = "running"
        self._atexit.register(self._stop_at_exit)   # stop() unregisters it
        self._atexit_registered = True
        return None

    def _start(self):
        if not str(self._platform).startswith("linux"):
            return PREFIX + "this is not Linux (%s): the process events are the Linux kernel's" % self._platform
        maker = self._sockets or socket.socket
        try:
            sock = maker(AF_NETLINK, socket.SOCK_DGRAM, NETLINK_CONNECTOR)
        except OSError as exc:
            return refusal("socket", exc)
        self._sock = sock
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, RCVBUF_BYTES)
        except OSError as exc:
            self._said.append("the socket's receive queue is left at the system's size (%s)" % _why(exc))
        try:
            sock.bind((self.pid, CN_IDX_PROC))
        except OSError as exc:
            return refusal("bind", exc)
        sock.settimeout(POLL_SECONDS)
        self._since = stamp(self._clock())
        try:
            sock.send(ask(self.pid, PROC_CN_MCAST_LISTEN, self._nonce))
        except OSError as exc:
            return refusal("ask", exc)
        self._asked = True
        deadline = self._mono() + int(ANSWER_SECONDS * 1e9)
        while self._answer is None:      # what comes before the answer is taken as it comes
            if self._mono() >= deadline:
                return PREFIX + ("the kernel did not answer the ask to listen within %g s (by the kernel's source, a"
                                 " process outside the system's first namespaces, as in a container, is not"
                                 " answered; not measured)" % ANSWER_SECONDS)
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
                sock.send(ask(self.pid, PROC_CN_MCAST_IGNORE, self._nonce))
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
        while self._once():
            pass

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
            with self._lock:
                if not self._stopping:
                    self.ended = ("the reader's thread ended before the stop (its receive failed: %s): from then on"
                                  " nothing is heard" % _why(exc))
            return False
        self._take(data)
        return True

    def _count_unread(self, why):
        self._unread[why] = self._unread.get(why, 0) + 1

    def _take(self, data):
        """Every message of a datagram, under the lock. Raises nothing: what it cannot take is counted."""
        wall, mono = self._clock(), self._mono()
        with self._lock:
            try:
                items = parse(bytes(data))
            except Exception as exc:
                self._count_unread("not read: %s" % type(exc).__name__)
                return
            for kind, when, fields in items:
                try:
                    if kind == "unread":
                        self._count_unread(when)
                    elif kind == "answer":
                        self._on_answer(*fields)
                    else:
                        at = stamp(wall - (mono - when) / 1e9)
                        getattr(self, "_on_" + kind)(at, *fields)
                except Exception as exc:
                    self._count_unread("not read: %s" % type(exc).__name__)

    def _on_answer(self, seq, ack_, err):
        if ack_ == (self._nonce + 1) & 0xFFFFFFFF and self._answer is None:
            self._answer = err
        else:
            self._count_unread("an answer to another listener's ask")

    def _keep(self, rec):
        if len(self._live) >= PROCESSES_MAX or len(self._pending) >= PROCESSES_MAX:
            self._beyond += 1
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

    def _on_fork(self, at, parent_pid, parent_tgid, pid, tgid):
        self._events["fork"] += 1
        if pid != tgid:
            self._threads += 1
            return
        old = self._live.pop(pid, None)
        if old is not None:          # its end was lost: the pid begins again
            old.unread["ended"] = NO_END
            if old.given and not old.queued:
                self._hold(self._ends, old.end())
        self._keep(_Proc(pid, parent_tgid, at, {"exe": NO_EXEC_EXE, "started_ticks": NO_EXEC_STAT}))

    def _on_exec(self, at, pid, tgid):
        self._events["exec"] += 1
        if pid != tgid:
            self._threads += 1
            return
        rec = self._live.get(pid)
        if rec is None:
            rec = _Proc(pid, None, None, {"began": NO_FORK})
            if not self._keep(rec):
                return
        else:
            self._queue(rec)         # given before: given again, with the program it became
        rec.unread.pop("exe", None)
        rec.unread.pop("started_ticks", None)
        try:
            rec.exe = self._readlink("/proc/%d/exe" % pid)
        except Exception as exc:
            rec.exe = None
            self._missed["exe"] += 1
            rec.unread["exe"] = self._missed_words(exc)
        try:
            ppid, ticks = stat_fields(self._read_bytes("/proc/%d/stat" % pid))
        except Exception as exc:
            rec.started_ticks = None
            self._missed["stat"] += 1
            rec.unread["started_ticks"] = self._missed_words(exc)
            if rec.ppid is None:
                rec.unread["ppid"] = rec.unread["started_ticks"]
        else:
            rec.started_ticks = ticks
            if rec.ppid is None:
                rec.ppid = ppid
                rec.unread.pop("ppid", None)

    @staticmethod
    def _missed_words(exc):
        name = _why(exc)
        gloss = GLOSS.get(exc.errno) if isinstance(exc, OSError) else None
        return "not read at its exec (%s%s)" % (name, ": %s" % gloss if gloss else "")

    def _on_exit(self, at, pid, tgid, raw_code, raw_signal):
        self._events["exit"] += 1
        if pid != tgid:
            self._threads += 1
            return
        code, sig = wait_status(raw_code)
        rec = self._live.pop(pid, None)
        if rec is None:
            self._older_n += 1
            self._hold(self._older, {"pid": pid, "started_ticks": None, "ended": at, "code": code, "signal": sig,
                                     "unread": {"began": NO_FORK}})
            return
        rec.ended, rec.code, rec.signal = at, code, sig
        if rec.given and not rec.queued:
            self._hold(self._ends, rec.end())

    # the reader's face -----------------------------------------------------------------------
    def read(self):
        """A copy: {"processes": every process that began, or changed its program, since the read before, each
        {pid, ppid, exe, started_ticks, began, ended, code, signal, unread}; "ends": the ends of processes given
        before, each {pid, started_ticks, ended, code, signal, unread}; "older": the ends of processes never heard
        to begin, in the same shape}."""
        with self._lock:
            out = []
            for rec in self._pending:
                out.append(rec.public())
                rec.given, rec.queued = True, False
            self._given += len(out)
            ends, older = self._ends, self._older
            self._pending, self._ends, self._older = [], [], []
            return {"processes": out, "ends": ends, "older": older}

    def counts(self):
        """A copy: "since" (the ask's time, None before it), "events" ({fork, exec, exit} heard, threads too),
        "given" (processes given by read()), "missed" ({exe, stat}: reads at an exec that failed), "unread"
        ({kind: n} of messages not read), "threads", "older" (ends of processes never heard to begin), "lost"
        ({"count", "why"}: the kernel's ENOBUFS), "beyond" (past PROCESSES_MAX, not kept), "live" (processes
        kept whose end is not heard yet), "refused", "ended", "said"."""
        with self._lock:
            why = None
            if self._lost:
                why = ("the kernel's queue for this socket overflowed %d time(s) (ENOBUFS): the events it held then"
                       " are gone, and how many is not known" % self._lost)
            return {"since": self._since, "events": dict(self._events), "given": self._given,
                    "missed": dict(self._missed), "unread": dict(self._unread), "threads": self._threads,
                    "older": self._older_n, "lost": {"count": self._lost, "why": why}, "beyond": self._beyond,
                    "live": len(self._live), "refused": self.refused, "ended": self.ended, "said": list(self._said)}

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
            sock.send(ask(self.pid, PROC_CN_MCAST_IGNORE, self._nonce))
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
