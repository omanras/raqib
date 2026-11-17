"""The rig's forwarder run (ADR-0011 J-14, L-10): `raqib forward` against the stand-in collector
(tools/rig/collector.py, loopback only, the hec shape, a made-up token), over the events file the rig's watch
wrote. It writes what it saw as JSON for tools/rig/check.py, which states X19 to X22; it judges nothing itself.

    python tools/rig/forward_run.py --events FILE --out FACTS.json [--home DIR]

X19 the whole file, --once. X20 the collector down from the start (its port bound by it, nothing listening),
then up: the state says failing, and nothing is lost. X21 a forwarder killed while the collector holds its
second request (by the collector's count of requests, not a window of time), then started again (--once): the
lines taken before the kill must not come again. X22 every output, state and error of every run here, every
argument list, and the argument list of a running forwarder as the system's own process list says it, for both
made-up tokens (the right one and the refused one). The forwarders run with HOME (and USERPROFILE) set to
--home (default: a new directory), so their states are the rig's own.

Over syslog (ADR-0011 J-6, J-14), against the stand-in syslog collector (tools/rig/syslog_collector.py,
loopback only, udp and tcp): X23 the whole file over tcp, octet counting, --once; X24 the whole file over udp,
--once (on loopback every datagram sent arrives); X25 the whole file over tcp with --framing newline, --once.
For each, what arrived, the collector's problems with the messages' RFC 5424 shape, how it framed them, and
the forwarder's state.

To the journal (ADR-0011 W-2, W-8), on Linux with the journal's socket there: X26 the whole file, --once,
`--to journal:`, then read back with journalctl - this run's entries alone, by the journal's trusted _PID of
the forwarder's own process and SYSLOG_IDENTIFIER raqib (W-7: who wrote an entry is asked of the journal's
trusted fields) - polled for at most READ_S, since the journal may need a moment after the send; what was
read is recorded. Elsewhere (Windows, or no socket) it is not run, and the reason is the fact. A test points
JOURNAL at a stand-in of its own: the forwarder then runs through JOURNAL_RUN, which hands it that path (the
CLI has no option for it), and journal_read is the test's.

To the Windows event log (ADR-0011 Y-7), on Windows: X27 the whole file, --once, `--to eventlog:`, and a made-up
file of three lines whose second is LONG_EVENTLOG characters (handed in parts, Y-3), each then read back with
wevtutil - the Application log, the provider Raqib, the record's own Execution ProcessID the forwarder's (as its
state says it), oldest first, as XML - polled for at most READ_S; the XML read is recorded whole, and
tools/rig/check.py puts the lines together. Elsewhere it is not run, and the reason is the fact. A test sets
EVENTLOG_FAKE (a file): the forwarder then runs through EVENTLOG_RUN with a made-up advapi32 (FakeAdvapi) that
writes each event to that file as wevtutil prints it, and eventlog_read is the test's - never the system's.

It never raises (L-10): each case is its own, an error in one is a fact of that case, and a missing events file
is a fact; it writes its facts and exits 0 whatever happened (2 only for its own usage). Stdlib only.
"""
import argparse
import binascii
import json
import os
import stat
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import collector  # noqa: E402  (the stand-in beside this file)
import syslog_collector  # noqa: E402  (the syslog stand-in beside this file)

PATH = "/services/collector/event"
FORWARD = [sys.executable, "-m", "raqib", "forward"]   # the forwarder (a test names one that cannot start)
CASES = ("x19", "x20", "x21", "x22")
SYSLOG_CASES = ("x23", "x24", "x25")   # J-6: over tcp, over udp, over tcp with --framing newline
JOURNAL_CASES = ("x26",)               # W-8: to the journal, Linux only
JOURNAL = "/run/systemd/journal/socket"   # the journal's socket, as raqib/forward.py's JOURNAL (a test: a stand-in)
REAL_JOURNAL = JOURNAL
PLATFORM = sys.platform
JOURNALCTL = ["journalctl", "--no-pager", "--all", "-b", "-o", "json", "-t", "raqib"]   # X-5: --all: long fields whole
READ_S = 30.0                          # journalctl is asked again for at most this long after the send
EVENTLOG_CASES = ("x27",)              # Y-7: to the Windows event log, Windows only
LONG_EVENTLOG = 100000                 # Y-7: a made-up line of this many characters (four parts of 30000 at most)
EVENTLOG_FAKE = None                   # a test's file for the made-up system (None: the system's own, on Windows)
EVENTLOG_RUN = ("import sys\nsys.path.insert(0, sys.argv[1])\nimport forward_run\n"
                "sys.exit(forward_run.run_fake_eventlog(sys.argv[2], sys.argv[3:]))")
EVENTS_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
JOURNAL_RUN = ("import sys\nfrom raqib import cli, forward\nforward.JOURNAL = sys.argv[1]\n"
               "sys.exit(cli.main(['forward'] + sys.argv[2:]))")


class Run:
    def __init__(self, events, home):
        self.events, self.home = events, home
        self.forward = os.path.join(home, ".raqib", "forward")
        self.env = dict(os.environ, HOME=home, USERPROFILE=home,
                        PYTHONPATH=os.pathsep.join([ROOT] + [p for p in [os.environ.get("PYTHONPATH")] if p]))
        for key in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
            self.env.pop(key, None)
        self.token_file = self.secret("token", "rig-made-up-token-" + binascii.hexlify(os.urandom(8)).decode())
        self.wrong_file = self.secret("wrong", "rig-made-up-wrong-" + binascii.hexlify(os.urandom(8)).decode())
        self.texts, self.argvs, self.listed = [], [], []

    def secret(self, name, value):
        path = os.path.join(self.home, name + ".txt")
        fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(value + "\n")
        return path

    def argv(self, name, port, *more, token=None):
        return FORWARD + [self.events, "--to", "http://127.0.0.1:%d%s" % (port, PATH), "--name", name, "--shape",
                          "hec", "--token-file", token or self.token_file, "--beat", "1"] + list(more)

    def say(self, where, text):
        self.texts.append({"where": where, "text": text})

    def run(self, where, argv, timeout=120):
        self.argvs.append(argv)
        try:
            p = subprocess.run(argv, env=self.env, cwd=self.home, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               timeout=timeout)
            out, err, code = p.stdout, p.stderr, p.returncode
        except subprocess.TimeoutExpired as exc:
            out, err, code = exc.stdout or b"", exc.stderr or b"", None
        except OSError as exc:   # the forwarder cannot start: a fact
            self.say(where + " start", "cannot start: %s" % type(exc).__name__)
            return None
        self.say(where + " stdout", out.decode("utf-8", "replace"))
        self.say(where + " stderr", err.decode("utf-8", "replace"))
        return code

    def start(self, where, argv):
        self.argvs.append(argv)
        out = open(os.path.join(self.home, where + ".out"), "wb")
        try:
            return subprocess.Popen(argv, env=self.env, cwd=self.home, stdout=out, stderr=subprocess.STDOUT), out
        except OSError:
            out.close()
            raise

    def end(self, where, proc, out, kill=False):
        if proc.poll() is None:
            if kill:
                proc.kill()
            else:
                proc.terminate()
        try:
            proc.wait(15)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(15)
        out.close()
        with open(out.name, "rb") as f:
            self.say(where + " output", f.read().decode("utf-8", "replace"))
        return proc.returncode

    def list_process(self, where, pid):
        """L-10: the argument list of a running process as the system lists it (not as the rig built it)."""
        how, text = None, ""
        try:
            if sys.platform.startswith("linux") and os.path.exists("/proc/%d/cmdline" % pid):
                how = "/proc/%d/cmdline" % pid
                with open(how, "rb") as f:
                    text = f.read().replace(b"\0", b" ").decode("utf-8", "replace")
            elif sys.platform == "win32":
                how = "Win32_Process CommandLine"
                text = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                                       "(Get-CimInstance Win32_Process -Filter 'ProcessId=%d').CommandLine" % pid],
                                      stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                      timeout=60).stdout.decode("utf-8", "replace")
            else:
                how = "ps"
                text = subprocess.run(["ps", "-ww", "-o", "args=", "-p", str(pid)], stdout=subprocess.PIPE,
                                      stderr=subprocess.DEVNULL, timeout=60).stdout.decode("utf-8", "replace")
        except (OSError, subprocess.SubprocessError) as exc:
            text = ""
            how = "%s (%s)" % (how, type(exc).__name__)
        self.listed.append({"where": where, "pid": pid, "how": how, "text": text.strip()})

    def state(self, name):
        try:
            with open(os.path.join(self.forward, name + ".json"), "rb") as f:
                return json.loads(f.read().decode("ascii"))
        except (OSError, ValueError):
            return None

    def until(self, test, seconds, proc=None):
        """Polls `test` (the collector's or the state's own facts) until it holds, the process ended, or
        `seconds` passed."""
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            got = test()
            if got:
                return got
            if proc is not None and proc.poll() is not None:
                return test()
            time.sleep(0.05)
        return None

    def states(self):
        out = []
        for name in sorted(os.listdir(self.forward)) if os.path.isdir(self.forward) else []:
            try:
                with open(os.path.join(self.forward, name), "rb") as f:
                    out.append({"where": "state " + name, "text": f.read().decode("utf-8", "replace")})
            except OSError:
                pass
        return out


def count_lines(path):
    with open(path, "rb") as f:
        return f.read().count(b"\n")


def x19(r):
    c = collector.Collector(r.token_file)
    port = c.start()
    try:
        code = r.run("x19", r.argv("rig-x19", port, "--once"))
    finally:
        c.stop()
    r.run("x19 status", FORWARD + ["--status", "rig-x19"])
    return {"exit": code, "events": list(c.events), "requests": len(c.requests)}


def x20(r):
    c = collector.Collector(r.token_file, down=True)
    port = c.start()   # bound by the collector, nothing listening: down, and no one else's port
    proc = out = None
    try:
        proc, out = r.start("x20", r.argv("rig-x20", port))
        failing = r.until(lambda: (r.state("rig-x20") or {}).get("failing"), 30, proc)
        if proc.poll() is None:
            r.list_process("x20 running", proc.pid)
        c.up()
        final = r.until(lambda: (lambda s: s if s and not s.get("failing") and s.get("behind") == 0 and
                                 s.get("last_ok") else None)(r.state("rig-x20")), 60, proc)
    finally:
        if proc is not None:
            r.end("x20", proc, out)
        c.stop()
    return {"failing": failing, "final": final, "events": list(c.events)}


def x21(r):
    lines = count_lines(r.events)
    batch = max(1, min(5, lines // 4))
    c = collector.Collector(r.token_file, hold=1)   # the second request is held: the kill comes then
    port = c.start()
    proc = out = None
    try:
        proc, out = r.start("x21", r.argv("rig-x21", port, "--batch", str(batch)))
        held = bool(r.until(c.held.is_set, 60, proc))
        killed = r.state("rig-x21")
        before, at_kill = len(c.events), c.arrived
        r.end("x21", proc, out, kill=True)
        proc = None
        c.release.set()   # the held request is dropped, never taken
        code = r.run("x21 again", r.argv("rig-x21", port, "--once"))
    finally:
        if proc is not None:
            r.end("x21", proc, out, kill=True)
        c.stop()
    return {"batch": batch, "held": held, "killed": (killed or {}).get("cursor"), "before": before,
            "requests_at_kill": at_kill, "size": os.path.getsize(r.events), "exit": code, "events": list(c.events)}


def x22(r):
    c = collector.Collector(r.token_file)
    port = c.start()
    try:
        r.run("x22 wrong token", r.argv("rig-x22-wrong", port, "--once", token=r.wrong_file))
        c.fail = 1000
        r.run("x22 failing", r.argv("rig-x22-fail", port, "--once"))
    finally:
        c.stop()
    r.run("x22 status", FORWARD + ["--status"])
    return {}


def over_syslog(r, name, transport, more=()):
    """One forwarder over syslog, --once, against a stand-in of its own: what arrived and what the stand-in
    found of each message's shape (J-6)."""
    c = syslog_collector.SyslogCollector()
    tcp, udp = c.start()
    try:
        url = "syslog+%s://127.0.0.1:%d" % (transport, tcp if transport == "tcp" else udp)
        code = r.run(name, FORWARD + [r.events, "--to", url, "--name", "rig-" + name, "--beat", "1", "--once"] +
                     list(more))
        s = r.state("rig-" + name) or {}
    finally:
        c.stop()
    r.run(name + " status", FORWARD + ["--status", "rig-" + name])
    return {"exit": code, "events": list(c.events[transport]), "messages": c.messages,
            "connections": c.connections, "sessions": [len(m) for m in c.sessions],   # P-2: each one's messages
            "problems": c.problems[:20], "framings": sorted(c.framings),
            "delivery": s.get("delivery"), "sent": s.get("sent"), "refused": (s.get("refused") or {}).get("count"),
            "behind": s.get("behind"), "failing": s.get("failing")}


def x23(r):
    return over_syslog(r, "x23", "tcp")


def x24(r):
    return over_syslog(r, "x24", "udp", ("--batch", "10"))


def x25(r):
    return over_syslog(r, "x25", "tcp", ("--framing", "newline"))


def journal_read(pid):
    """One read of the journal: this run's entries (SYSLOG_IDENTIFIER raqib, _PID the forwarder's process), as
    `journalctl -o json` gives them: (entries, journalctl's exit, its first words on stderr)."""
    p = subprocess.run(JOURNALCTL + ["_PID=%d" % pid], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    entries = []
    for row in p.stdout.decode("utf-8", "replace").splitlines():
        if row.strip():
            try:
                entries.append(json.loads(row))
            except ValueError:
                entries.append({"unreadable": row[:200]})
    return entries, p.returncode, p.stderr.decode("utf-8", "replace")[:500]


def _text(value):
    """A field as journalctl's JSON says it: text, or an array of bytes where it is not printable UTF-8."""
    if isinstance(value, list):
        try:
            return bytes(value).decode("utf-8", "replace")
        except (TypeError, ValueError):
            return None
    return value if isinstance(value, str) else None


LONG = 300 * 1024   # X-5: a made-up line longer than the journal's socket takes as a datagram (measured: 212000)


def journal_long(r):
    """X-5: three made-up events, the second LONG bytes, to the journal by the forwarder: the long one goes as a
    sealed memory file (W-3). What journalctl read back of them: each MESSAGE's length and whether it is the
    line as written."""
    from raqib import event
    facts = {"run": "rig-long", "mode": "host", "platform": "linux", "version": "0.0.0", "host": "rig.example",
             "beat": 20.0}
    rows = []
    for n, pad in ((1, 0), (2, LONG), (3, 0)):
        e = event.note({"text": "rig long %d%s" % (n, "x" * pad)}, facts, "2026-11-17T07:50:0%d.250Z" % n, n,
                       "note:%d" % n)
        rows.append(event.line(e))
    path = os.path.join(r.home, "long.jsonl")
    with open(path, "wb") as f:
        f.write(("\n".join(rows) + "\n").encode("ascii"))
    more = [path, "--to", "journal:", "--name", "rig-x26-long", "--beat", "1", "--once"]
    argv = FORWARD + more if JOURNAL == REAL_JOURNAL else [sys.executable, "-c", JOURNAL_RUN, JOURNAL] + more
    proc, out = r.start("x26 long", argv)
    try:
        proc.wait(120)
    except subprocess.TimeoutExpired:
        pass
    code = r.end("x26 long", proc, out)
    got, end = ([], None, None), time.monotonic() + READ_S
    while True:
        got = journal_read(proc.pid)
        if len(got[0]) >= len(rows) or time.monotonic() >= end:
            break
        time.sleep(0.25)
    messages = [_text(e.get("MESSAGE")) for e in got[0]]
    return {"exit": code, "lines": [len(x) for x in rows], "read": [len(m) if isinstance(m, str) else None
                                                                    for m in messages],
            "as_written": messages == rows, "journalctl": {"exit": got[1], "stderr": got[2]},
            "state": {k: (r.state("rig-x26-long") or {}).get(k) for k in ("sent", "refused", "failing", "behind")}}


def x26(r):
    """W-8: the whole file to the journal, --once, read back by journalctl; not run where there is no journal."""
    if not PLATFORM.startswith("linux"):
        return {"not_run": "not Linux (%s): the journal is Linux's (W-1)" % PLATFORM}
    try:   # X-6: on Linux a journal that is not there is a finding of the rig, not a case that does not apply
        mode = os.stat(JOURNAL).st_mode
    except OSError as exc:
        return {"error": "no journal's socket at %s (%s) on a Linux machine" % (JOURNAL, type(exc).__name__)}
    if not stat.S_ISSOCK(mode):
        return {"error": "%s is no socket: no journal on a Linux machine" % JOURNAL}
    with open(r.events, "rb") as f:
        want = f.read().count(b"\n")
    name = "rig-x26"
    more = [r.events, "--to", "journal:", "--name", name, "--beat", "1", "--once"]
    argv = FORWARD + more if JOURNAL == REAL_JOURNAL else [sys.executable, "-c", JOURNAL_RUN, JOURNAL] + more
    proc, out = r.start("x26", argv)
    try:
        proc.wait(300)
    except subprocess.TimeoutExpired:
        pass
    code = r.end("x26", proc, out)
    s = r.state(name) or {}
    got, asked, end = ([], None, None), 0, time.monotonic() + READ_S
    while True:   # the journal may take a moment to show what it was handed
        asked += 1
        try:
            got = journal_read(proc.pid)
        except (OSError, subprocess.SubprocessError) as exc:
            got = ([], None, "journalctl cannot be run: %s" % type(exc).__name__)
            break
        if len(got[0]) >= want or time.monotonic() >= end:
            break
        time.sleep(0.25)
    entries = got[0]
    r.run("x26 status", FORWARD + ["--status", name])
    try:
        long = journal_long(r)
    except Exception as exc:   # the rig's own failure is said, never raised
        long = {"error": "%s: %s" % (type(exc).__name__, exc)}
    return {"exit": code, "pid": proc.pid, "socket": JOURNAL, "lines": want, "asked": asked, "long": long,
            "journalctl": {"exit": got[1], "stderr": got[2]}, "read": len(entries),
            "messages": [_text(e.get("MESSAGE")) for e in entries],
            "identifiers": sorted(set(str(_text(e.get("SYSLOG_IDENTIFIER"))) for e in entries)),
            "priorities": [_text(e.get("PRIORITY")) for e in entries[:50]],
            "delivery": s.get("delivery"), "sent": s.get("sent"), "refused": (s.get("refused") or {}).get("count"),
            "behind": s.get("behind"), "failing": s.get("failing"), "destination": s.get("destination")}


class FakeAdvapi:
    """A test's made-up advapi32 (EVENTLOG_FAKE): each event the forwarder reports is appended to `path` as one
    <Event> element on a line of its own, as wevtutil prints it (no root element; System's Provider, EventID,
    Level, Execution ProcessID this process's; EventData's Data, one a string, XML-escaped)."""

    LEVEL = {1: 2, 2: 3, 4: 4}   # ReportEventW's type as the record's Level: Error 2, Warning 3, Information 4

    def __init__(self, path):
        self.path = path

        def fn(f):   # a plain function, so that ctypes' restype and argtypes can be set on it
            return lambda *a: f(*a)
        self.RegisterEventSourceW = fn(lambda server, source: 1 if source == "Raqib" else 0)
        self.ReportEventW = fn(self.report)
        self.DeregisterEventSource = fn(lambda handle: 1)

    def load(self, name):
        return self

    def report(self, handle, kind, category, ident, user, count, size, strings, raw):
        from xml.sax.saxutils import escape
        datas = "".join("<Data>%s</Data>" % escape(strings[i]) for i in range(count))
        with open(self.path, "a", encoding="utf-8") as f:
            f.write("<Event xmlns='%s'><System><Provider Name='Raqib'/><EventID Qualifiers='0'>%d</EventID>"
                    "<Level>%d</Level><Execution ProcessID='%d' ThreadID='1'/><Channel>Application</Channel>"
                    "</System><EventData>%s</EventData></Event>\n" % (EVENTS_NS, ident, self.LEVEL.get(kind, 0),
                                                                    os.getpid(), datas))
        return 1


def run_fake_eventlog(path, args):
    """EVENTLOG_RUN's body: `raqib forward ARGS` as on Windows, its calls taken by FakeAdvapi(path)."""
    sys.path.insert(0, ROOT)
    from raqib import cli, forward
    real = forward.Forwarder
    forward.Forwarder = lambda *a, **k: real(*a, platform="win32", loader=FakeAdvapi(path).load, **k)
    return cli.main(["forward"] + list(args))


def eventlog_read(pid):
    """One read of the Application log: this run's events (provider Raqib, the record's Execution ProcessID
    `pid`), oldest first, as XML: (wevtutil's output, its exit, its first words on stderr). The command line is
    given whole, as measured (its query quoted for wevtutil)."""
    cmd = ('wevtutil qe Application "/q:*[System[Provider[@Name=\'Raqib\'] and Execution[@ProcessID=%d]]]" /f:xml'
           ' /rd:false' % int(pid))
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    return p.stdout.decode("utf-8", "replace"), p.returncode, p.stderr.decode("utf-8", "replace")[:500]


def eventlog_count(text):
    """How many <Event> elements the XML holds (the wait's measure only; check.py reads them)."""
    return text.count("<Event ") + text.count("<Event>")


def to_eventlog(r, name, path, want, where):
    """One forwarder to the event log, --once, then its events read back for at most READ_S (`want`: how many
    events are awaited). The record's ProcessID is the forwarder's own, as its state says (a launcher's pid,
    proc.pid, may be another's)."""
    more = [path, "--to", "eventlog:", "--name", name, "--beat", "1", "--once"]
    argv = FORWARD + more if EVENTLOG_FAKE is None else [sys.executable, "-c", EVENTLOG_RUN, HERE,
                                                         EVENTLOG_FAKE] + more
    proc, out = r.start(where, argv)
    try:
        proc.wait(300)
    except subprocess.TimeoutExpired:
        pass
    code = r.end(where, proc, out)
    s = r.state(name) or {}
    pid = s.get("pid") if isinstance(s.get("pid"), int) else proc.pid
    got, asked, end = ("", None, None), 0, time.monotonic() + READ_S
    while True:   # the log may take a moment to show what it was handed
        asked += 1
        try:
            got = eventlog_read(pid)
        except (OSError, subprocess.SubprocessError, ValueError) as exc:
            got = ("", None, "wevtutil cannot be run: %s" % type(exc).__name__)
            break
        if eventlog_count(got[0]) >= want or time.monotonic() >= end:
            break
        time.sleep(0.25)
    return {"exit": code, "pid": pid, "process": proc.pid, "asked": asked, "xml": got[0],
            "wevtutil": {"exit": got[1], "stderr": got[2]}, "read": eventlog_count(got[0]),
            "delivery": s.get("delivery"), "sent": s.get("sent"), "refused": (s.get("refused") or {}).get("count"),
            "behind": s.get("behind"), "failing": s.get("failing"), "destination": s.get("destination")}


def parts_of(chars):
    return max(1, -(-chars // 30000))


def x27(r):
    """Y-7: the whole file to the Windows event log, --once, and a made-up long line, read back by wevtutil; not
    run where there is no Windows event log (a test's made-up system is run anywhere)."""
    if PLATFORM != "win32" and EVENTLOG_FAKE is None:
        return {"not_run": "not Windows (%s): the event log is Windows' (Y-5)" % PLATFORM}
    with open(r.events, "rb") as f:
        rows = f.read().split(b"\n")[:-1]
    facts = to_eventlog(r, "rig-x27", r.events, sum(parts_of(len(x)) for x in rows), "x27")
    facts["lines"] = len(rows)
    r.run("x27 status", FORWARD + ["--status", "rig-x27"])
    try:   # Y-3: a made-up line of LONG_EVENTLOG characters, in parts
        from raqib import event
        made = {"run": "rig-long", "mode": "host", "platform": "win32", "version": "0.0.0", "host": "rig.example",
                "beat": 20.0}
        lines = []
        for n in (1, 2, 3):
            e = event.note({"text": "rig long %d" % n}, made, "2026-11-17T07:50:0%d.250Z" % n, n, "note:%d" % n)
            if n == 2:   # padded to exactly LONG_EVENTLOG characters
                e = event.note({"text": "rig long 2" + "x" * (LONG_EVENTLOG - len(event.line(e)))}, made,
                               "2026-11-17T07:50:02.250Z", 2, "note:2")
            lines.append(event.line(e))
        path = os.path.join(r.home, "long-eventlog.jsonl")
        with open(path, "wb") as f:
            f.write(("\n".join(lines) + "\n").encode("ascii"))
        import hashlib
        long = to_eventlog(r, "rig-x27-long", path, sum(parts_of(len(x)) for x in lines), "x27 long")
        long.update(lines=[len(x) for x in lines], sha256=[hashlib.sha256(x.encode("ascii")).hexdigest()
                                                            for x in lines])
    except Exception as exc:   # the rig's own failure is said, never raised
        long = {"error": "%s: %s" % (type(exc).__name__, exc)}
    facts["long"] = long
    return facts


def main(argv=None):
    p = argparse.ArgumentParser(prog="tools/rig/forward_run.py")
    p.add_argument("--events", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--home")
    a = p.parse_args(argv)
    facts = {}
    try:
        home = os.path.abspath(a.home or tempfile.mkdtemp(prefix="raqib-forward-rig-"))
        os.makedirs(home, exist_ok=True)
        r = Run(os.path.abspath(a.events), home)
        facts.update(events=r.events, token_file=r.token_file, wrong_file=r.wrong_file)
        if not os.path.isfile(r.events):
            facts["events_missing"] = True   # the watch wrote none: X16 says it; nothing is forwarded
        else:
            for name, case in zip(CASES + SYSLOG_CASES + JOURNAL_CASES + EVENTLOG_CASES,
                                  (x19, x20, x21, x22, x23, x24, x25, x26, x27)):
                try:
                    facts[name] = case(r)
                except Exception as exc:   # one case's error is that case's fact
                    facts[name] = {"error": "%s: %s" % (type(exc).__name__, exc)}
        facts.setdefault("x22", {}).update(texts=r.texts + r.states(), argv=r.argvs, listed=r.listed)
    except Exception as exc:
        facts["error"] = "%s: %s" % (type(exc).__name__, exc)
    try:
        with open(a.out, "w", encoding="ascii") as f:
            json.dump(facts, f, indent=1, ensure_ascii=True)
        print("forward_run: facts in %s" % a.out)
    except OSError as exc:
        print("forward_run: the facts cannot be written to %s (%s)" % (a.out, type(exc).__name__))
    return 0


if __name__ == "__main__":
    sys.exit(main())
