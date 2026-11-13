"""raqib forward: the events leave the host (ADR-0011 Amendment J; docs/specs/FORWARD.md).

A process of its own (J-1). It reads one events file - the watch's ~/.raqib/host/events.jsonl, as
docs/specs/EVENT.md "For a reader of the file" says a reader may - and sends every whole line to one HTTP
collector, at least once and in the file's order (J-3). The file is the buffer: it is opened for reading only,
never written, moved or locked; the forwarder keeps nothing of it but the batch in flight. Its cursor is a byte
offset at the end of the last whole line it passed, kept with the sha256 of that line (J-5); it moves only past
lines the collector took: a 2xx answer, and in the hec shape also the answer's code 0 (`acknowledged`).

What it is not (J-1, J-2, A-1): the watch does not know it runs. raqib/host.py, raqib/eventlog.py,
raqib/event.py and raqib/hooks/ import nothing of this module (a test reads the imports). It sends; of the
collector it reads only the answer to its own send (its status, and in the hec shape the code of its body),
follows no redirect (http.client follows none: a 3xx is a failed send) and uses no proxy of the environment
(http.client reads none; urllib is never used). The standard library only.

The secret (J-7): the token is read from --token-file at every connection; never an argument, the environment,
the state, an output line or an error's text. An error is the forwarder's own word and a status number, never
the collector's body. The wire (J-8): https is verified against the system's authorities or --ca; nothing turns
verification off. Plain http only to a loopback address unless --plain.

Its own silence is said (J-9): after every batch, every failure and at least once a beat the state is written
whole (beside, then renamed) to ~/.raqib/forward/<name>.json; `raqib forward --status` reads it.
"""
from __future__ import annotations

import calendar
import datetime
import hashlib
import http.client
import ipaddress
import json
import os
import re
import signal
import socket
import ssl
import sys
import threading
import time
from urllib.parse import urlsplit

from raqib import event
from raqib import eventlog
from raqib import host as host_watch
from raqib import ui

SCHEMA = "raqib-forward/1"
DIR_NAME = "forward"
NAME = re.compile(r"[a-z0-9-]{1,32}\Z")   # J-13
SHAPES = ("raqib", "hec")                  # J-6
SYSLOG = ("syslog+udp", "syslog+tcp", "syslog+tls")
DELIVERY = "acknowledged"                  # J-3: HTTP's word
BEAT_DEFAULT = 60.0                        # J-9
MAX_LINES = 100                            # J-11
MAX_BYTES = 512 * 1024                     # J-11
CONNECT_S = 10.0                           # J-8
ANSWER_S = 30.0                            # J-8
WAITS = (1, 2, 4, 8, 16, 32, 60)           # J-10: seconds, the last one again for as long as it runs
IDS_KEPT = 50                              # J-4
POLL_S = 1.0                               # how often a forwarder with nothing to send looks at the file again
READ_CHUNK = 1 << 20
ANSWER_READ = 64 * 1024                    # of an answer's body, only the hec code is read
TOKEN_READ = 64 * 1024
TOKEN = re.compile(rb"[\x21-\x7e]+\Z")     # one token: printable ASCII, no space (never a header's CR or LF)
# J-9 failing.error: the forwarder's own words, never the collector's.
ERRORS = {
    "connect": "no connection to the collector",
    "tls": "the TLS handshake or the certificate failed",
    "no-answer": "the connection ended with no answer",
    "late": "no answer in time",
    "redirect": "the collector answered a redirect (never followed)",
    "busy": "the collector said it is busy (408 or 429)",
    "server": "the collector failed (5xx)",
    "answer": "an answer that does not say the batch was taken",
    "token": "the collector refused the token (401 or 403)",
    "token-file": "the token file cannot be read",
    "file": "the events file cannot be read",
}
KEYS = ("schema", "name", "pid", "written", "destination", "shape", "delivery", "plain", "file", "cursor", "from",
        "beat", "sent", "skipped", "refused", "restarts", "last_id", "last_ok", "behind", "failing")


class UsageError(Exception):
    """Exit 2 with the reason (J-10: a usage error ends the forwarder)."""


def forward_dir(home=None):
    """~/.raqib/forward, the home resolved as the watch resolves its own (raqib/host.py host_dir)."""
    return os.path.join(os.path.dirname(host_watch.host_dir(home)), DIR_NAME)


def events_default(home=None):
    return os.path.join(host_watch.host_dir(home), eventlog.NAME)


def state_path(name, home=None):
    return os.path.join(forward_dir(home), name + ".json")


def iso(seconds):
    d = datetime.datetime.fromtimestamp(seconds, datetime.timezone.utc)
    return d.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (d.microsecond // 1000)


def seconds_of(text):
    """An instant of raqib-event/1 (or of the state) as seconds since the epoch."""
    d = datetime.datetime.strptime(text[:-1], "%Y-%m-%dT%H:%M:%S.%f")
    return calendar.timegm(d.timetuple()) + d.microsecond / 1e6


def hec_time(text):
    """J-6: the event's time as seconds, with its milliseconds, written as the instant holds them."""
    d = datetime.datetime.strptime(text[:-1], "%Y-%m-%dT%H:%M:%S.%f")
    return "%d.%03d" % (calendar.timegm(d.timetuple()), d.microsecond // 1000)


def check_name(name):
    if not isinstance(name, str) or not NAME.match(name):
        raise UsageError("--name: a name is [a-z0-9-]{1,32} (J-13), not %r" % (name,))
    return name


def loopback(host):
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def destination(url, plain=False):
    """J-8, J-9: --to as {scheme, host, port, path} (no query, no user info) and the request's target. A
    syslog destination is a usage error that says so (the next task builds it)."""
    try:
        parts = urlsplit(url or "")
        port = parts.port
    except ValueError:
        raise UsageError("--to: not a URL with a valid port")
    scheme = parts.scheme.lower()
    if scheme in SYSLOG:
        raise UsageError("--to %s://: a syslog destination is not built yet (ADR-0011 J-6, the next task);"
                         " http:// and https:// are" % scheme)
    if scheme not in ("http", "https"):
        raise UsageError("--to: an http:// or https:// collector (syslog+udp, syslog+tcp and syslog+tls are not"
                         " built yet)")
    if "@" in parts.netloc:
        raise UsageError("--to: no user information in the URL (the token is read from --token-file only, J-7)")
    host = parts.hostname
    if not host:
        raise UsageError("--to: the URL names no host")
    if scheme == "http" and not loopback(host) and not plain:
        raise UsageError("--to http://%s: plain http is taken only to a loopback address (127.0.0.0/8, ::1) unless"
                         " --plain is given (J-8)" % host)
    path = parts.path or "/"
    target = path + ("?" + parts.query if parts.query else "")
    return {"scheme": scheme, "host": host, "port": port or (443 if scheme == "https" else 80), "path": path}, target


def where(dest):
    host = "[%s]" % dest["host"] if ":" in dest["host"] else dest["host"]
    return "%s://%s:%d%s" % (dest["scheme"], host, dest["port"], dest["path"])


def read_token(path, platform=None):
    """J-7: the token, read afresh. Off Windows a file others can read (mode & 0o077) is a usage error; on
    Windows that is not checked. A file that cannot be read raises OSError (a failed try, said as token-file)."""
    if (platform or sys.platform) != "win32":
        mode = os.stat(path).st_mode
        if mode & 0o077:
            raise UsageError("--token-file: others can read it (mode %03o); make it the owner's only (chmod 600)"
                             % (mode & 0o777))
    with open(path, "rb") as f:
        raw = f.read(TOKEN_READ + 1)
    token = raw.strip()
    if len(raw) > TOKEN_READ or not TOKEN.match(token):
        raise UsageError("--token-file: it does not hold one token (printable ASCII, no space)")
    return token.decode("ascii")


def classify(raw):
    """J-5 (EVENT.md): the event a whole line holds, or None where it is not JSON or not an event."""
    try:
        obj = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(obj, dict):
        return None
    try:
        return None if event.check(obj) else obj
    except Exception:   # a line the contract cannot read is not an event
        return None


def piece(shape, raw, obj):
    """J-6: what one line puts in a request's body. raqib: the line as the file holds it, its newline with it.
    hec: the envelope, the event's bytes inside it unchanged."""
    if shape == "raqib":
        return raw
    head = '{"time":%s,"host":%s,"source":"raqib","sourcetype":"raqib:event","event":' % (
        hec_time(obj["time"]), json.dumps(obj["watch"]["host"], ensure_ascii=True))
    return head.encode("ascii") + raw.rstrip(b"\r\n") + b"}\n"


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


class Line:
    __slots__ = ("start", "end", "raw", "obj")

    def __init__(self, start, raw, obj):
        self.start, self.end, self.raw, self.obj = start, start + len(raw), raw, obj


def whole_lines(f, offset):
    """The whole lines from offset, about READ_CHUNK of them (more where one line is longer): [Line]."""
    f.seek(offset)
    data = f.read(READ_CHUNK)
    while data and b"\n" not in data:
        more = f.read(READ_CHUNK)
        if not more:
            break
        data += more
    cut = data.rfind(b"\n")
    out, at = [], offset
    for body in (data[:cut + 1].split(b"\n")[:-1] if cut >= 0 else ()):   # only a newline ends a line
        raw = body + b"\n"
        out.append(Line(at, raw, classify(raw)))
        at += len(raw)
    return out


def _rfind_newline(f, before, floor=0):
    """The offset just past the last newline before `before` and at or after `floor` (floor where none)."""
    pos = before
    while pos > floor:
        size = min(65536, pos - floor)
        f.seek(pos - size)
        block = f.read(size)
        i = block.rfind(b"\n")
        if i >= 0:
            return pos - size + i + 1
        pos -= size
    return floor


def line_before(f, offset):
    """The bytes of the line that ends at offset (its newline included), or None where offset is not a line's
    end."""
    if offset <= 0:
        return b""
    f.seek(offset - 1)
    if f.read(1) != b"\n":
        return None
    start = _rfind_newline(f, offset - 1)
    f.seek(start)
    return f.read(offset - start)


class Result:
    """The answer to one send: taken, refused (a 4xx of J-4), token (401, 403) or failed (error word)."""
    __slots__ = ("kind", "error", "status")

    def __init__(self, kind, error=None, status=None):
        self.kind, self.error, self.status = kind, error, status


class Forwarder:
    """One name, one file, one destination (J-13). Every clock, wait and timeout can be given (tests)."""

    def __init__(self, name, path, url, shape="raqib", token_file=None, ca=None, plain=False, beat=None,
                 start="start", batch=MAX_LINES, home=None, out=None, clock=time.time, wait=None,
                 connect_s=CONNECT_S, answer_s=ANSWER_S, poll_s=POLL_S, alive=ui.pid_alive, platform=None,
                 pid=None):
        self.name = check_name(name)
        if shape not in SHAPES:
            raise UsageError("--shape: raqib or hec, not %r" % (shape,))
        self.dest, self.target = destination(url, plain)
        self.shape, self.token_file, self.platform = shape, token_file, platform or sys.platform
        if shape == "hec" and not token_file:
            raise UsageError("--shape hec needs --token-file (Authorization: Splunk <token>)")
        self.beat = BEAT_DEFAULT if beat is None else float(beat)
        if not self.beat > 0:
            raise UsageError("--beat: a number of seconds above 0")
        if not (isinstance(batch, int) and 1 <= batch <= MAX_LINES):
            raise UsageError("--batch: 1 to %d lines (J-11)" % MAX_LINES)
        if start not in ("start", "end"):
            raise UsageError("--from: start or end")
        self.batch, self.home = batch, home
        self.path = os.path.abspath(path or events_default(home))
        self.plain = self.dest["scheme"] == "http"
        self.out = out if out is not None else sys.stdout
        self.clock, self.connect_s, self.answer_s, self.poll_s = clock, connect_s, answer_s, poll_s
        self._stop = threading.Event()
        self.wait = wait or self._stop.wait
        self.alive, self.pid = alive, os.getpid() if pid is None else pid
        self.ca = ca
        if ca is not None and not os.path.isfile(ca):
            raise UsageError("--ca: no such file: %s" % ca)
        if self.dest["scheme"] == "https":
            try:   # J-8: verified, by the system's authorities or by --ca; nothing turns it off
                self.context = ssl.create_default_context(cafile=ca) if ca else ssl.create_default_context()
            except (OSError, ssl.SSLError):
                raise UsageError("--ca: the file holds no certificate that can be read")
            self.context.check_hostname, self.context.verify_mode = True, ssl.CERT_REQUIRED
        else:
            self.context = None
        if token_file:
            try:   # J-7: a token file others can read is exit 2 before anything is sent
                self.token()
            except OSError as exc:
                raise UsageError("--token-file: cannot read %s: %s" % (token_file, exc.strerror or exc))
        self.state_file = state_path(self.name, home)
        self.lock_file = os.path.join(forward_dir(home), self.name + ".pid")
        self.offset, self.line_sha, self.sent, self.skipped, self.restarts = 0, None, 0, 0, 0
        self.refused, self.refused_ids, self.last_id, self.last_ok, self.failing = 0, [], None, None, None
        self.refused_now = 0
        self.start_from = {"start": start, "offset": 0}
        self.written_at, self.locked, self.state_error = None, False, None

    # --- the state (J-9) -------------------------------------------------------------------------------------
    def behind(self):
        try:
            with open(self.path, "rb") as f:
                size = os.fstat(f.fileno()).st_size
                return max(0, _rfind_newline(f, size, self.offset) - self.offset) if size > self.offset else 0
        except OSError:
            return 0

    def state(self):
        return {"schema": SCHEMA, "name": self.name, "pid": self.pid, "written": iso(self.clock()),
                "destination": dict(self.dest), "shape": self.shape, "delivery": DELIVERY, "plain": self.plain,
                "file": self.path, "cursor": {"offset": self.offset, "line_sha256": self.line_sha},
                "from": dict(self.start_from), "beat": self.beat, "sent": self.sent, "skipped": self.skipped,
                "refused": {"count": self.refused, "ids": list(self.refused_ids)}, "restarts": self.restarts,
                "last_id": self.last_id, "last_ok": self.last_ok, "behind": self.behind(),
                "failing": dict(self.failing) if self.failing else None}

    def write_state(self):
        """Whole: written beside, then renamed over (J-9). A state that cannot be written is said once."""
        text = json.dumps(self.state(), indent=2, sort_keys=True, ensure_ascii=True) + "\n"
        temp = "%s.%d.tmp" % (self.state_file, self.pid)
        self.written_at = self.clock()
        try:
            os.makedirs(os.path.dirname(self.state_file), exist_ok=True)
            with open(temp, "w", encoding="ascii", newline="\n") as f:
                f.write(text)
            for attempt in range(5):   # Windows: a reader holding the old state for a moment
                try:
                    os.replace(temp, self.state_file)
                    break
                except PermissionError:
                    if attempt == 4:
                        raise
                    time.sleep(0.05)
            self.state_error = None
        except OSError as exc:
            if self.state_error is None:
                self.say("the state cannot be written: %s (%s)" % (self.state_file, exc.strerror or exc))
            self.state_error = exc

    def say(self, text):
        try:
            self.out.write("raqib forward %s: %s\n" % (self.name, text))
            self.out.flush()
        except (OSError, ValueError):
            pass

    # --- the name (J-13) -------------------------------------------------------------------------------------
    def lock(self):
        os.makedirs(forward_dir(self.home), exist_ok=True)
        for _ in range(3):
            try:
                fd = os.open(self.lock_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                try:
                    with open(self.lock_file, "rb") as f:
                        other = int(f.read(32).strip() or b"0")
                except (OSError, ValueError):
                    other = 0
                if other and other != self.pid and self.alive(other) is not False:
                    raise UsageError("a forwarder named %s runs (pid %d): a second one of one name is refused (J-13)"
                                     % (self.name, other))
                try:
                    os.remove(self.lock_file)
                except FileNotFoundError:
                    pass
                continue
            with os.fdopen(fd, "w") as f:
                f.write("%d\n" % self.pid)
            self.locked = True
            return
        raise UsageError("the name %s cannot be taken: %s" % (self.name, self.lock_file))

    def unlock(self):
        if self.locked:
            try:
                os.remove(self.lock_file)
            except OSError:
                pass
            self.locked = False

    def resume(self):
        """The cursor of an earlier run of this name, where its state holds one for this file and this
        destination; a first run starts at the file's start or, with --from end, at its end (J-12)."""
        try:
            with open(self.state_file, "rb") as f:
                old = json.loads(f.read().decode("ascii"))
        except FileNotFoundError:
            old = None
        except (OSError, ValueError, UnicodeDecodeError):
            raise UsageError("the state %s cannot be read: move it away to start this name again" % self.state_file)
        if isinstance(old, dict) and old.get("schema") == SCHEMA:
            if old.get("file") != self.path or old.get("destination") != self.dest or old.get("shape") != self.shape:
                raise UsageError("the name %s forwards %s to %s (shape %s): another file, destination or shape is"
                                 " another name (J-13)" % (self.name, old.get("file"), where(old.get("destination") or
                                                           {"scheme": "?", "host": "?", "port": 0, "path": ""}),
                                                           old.get("shape")))
            cur = old.get("cursor") or {}
            self.offset, self.line_sha = int(cur.get("offset") or 0), cur.get("line_sha256")
            for key in ("sent", "skipped", "restarts"):
                setattr(self, key, int(old.get(key) or 0))
            refused = old.get("refused") or {}
            self.refused, self.refused_ids = int(refused.get("count") or 0), list(refused.get("ids") or [])[-IDS_KEPT:]
            self.last_id, self.last_ok = old.get("last_id"), old.get("last_ok")
            self.start_from = dict(old.get("from") or self.start_from)
            return "resumed at offset %d" % self.offset
        if self.start_from["start"] == "end":
            try:
                with open(self.path, "rb") as f:
                    size = os.fstat(f.fileno()).st_size
                    self.offset = _rfind_newline(f, size)
                    self.line_sha = _sha(line_before(f, self.offset)) if self.offset else None
            except OSError:
                self.offset = 0
            self.start_from["offset"] = self.offset
            return "a first run, from the file's end (offset %d)" % self.offset
        return "a first run, from the file's start"

    # --- one send --------------------------------------------------------------------------------------------
    def token(self):
        return read_token(self.token_file, self.platform) if self.token_file else None

    def post(self, body, token):
        d = self.dest
        if d["scheme"] == "https":
            conn = http.client.HTTPSConnection(d["host"], d["port"], timeout=self.connect_s, context=self.context)
        else:
            conn = http.client.HTTPConnection(d["host"], d["port"], timeout=self.connect_s)
        try:
            try:
                conn.connect()
            except ssl.SSLError:
                return Result("failed", "tls")
            except OSError:
                return Result("failed", "connect")
            conn.sock.settimeout(self.answer_s)
            headers = {"Content-Type": "application/x-ndjson" if self.shape == "raqib" else "application/json",
                       "Content-Length": str(len(body)), "User-Agent": SCHEMA}
            if token is not None:
                headers["Authorization"] = ("Splunk " if self.shape == "hec" else "Bearer ") + token
            try:
                conn.request("POST", self.target, body=body, headers=headers)
                resp = conn.getresponse()
                status = resp.status
                data = resp.read(ANSWER_READ)
            except socket.timeout:
                return Result("failed", "late")
            except ssl.SSLError:
                return Result("failed", "tls")
            except (http.client.HTTPException, OSError):
                return Result("failed", "no-answer")
        finally:
            conn.close()
        if 200 <= status < 300:
            if self.shape == "hec":
                try:
                    code = json.loads(data.decode("utf-8")).get("code")
                except (UnicodeDecodeError, ValueError, AttributeError):
                    code = None
                if code != 0 or isinstance(code, bool):
                    return Result("failed", "answer", status)
            return Result("taken", status=status)
        if 300 <= status < 400:
            return Result("failed", "redirect", status)
        if status in (401, 403):
            return Result("token", "token", status)
        if status in (408, 429):
            return Result("failed", "busy", status)
        if 400 <= status < 500:
            return Result("refused", status=status)
        if status >= 500:
            return Result("failed", "server", status)
        return Result("failed", "answer", status)

    def send(self, lines):
        try:
            token = self.token()
        except OSError:
            return Result("failed", "token-file")
        return self.post(b"".join(piece(self.shape, ln.raw, ln.obj) for ln in lines), token)

    # --- the cursor (J-3, J-4, J-5) --------------------------------------------------------------------------
    def passed(self, ln):
        self.offset, self.line_sha = ln.end, _sha(ln.raw)

    def took(self, lines):
        self.passed(lines[-1])
        self.sent += len(lines)
        self.last_id, self.last_ok = lines[-1].obj.get("id"), iso(self.clock())
        if self.failing:
            self.say("taken again after %d failed tr%s" % (self.failing["tries"], "y" if self.failing["tries"] == 1
                                                           else "ies"))
        self.failing = None

    def refuse(self, ln, why):
        self.passed(ln)
        self.refused += 1
        self.refused_now += 1
        self.refused_ids = (self.refused_ids + [ln.obj.get("id")])[-IDS_KEPT:]
        self.say("line at offset %d (id %s) refused %s: counted and passed (J-4)" % (ln.start, ln.obj.get("id"), why))

    def fail(self, r):
        now = iso(self.clock())
        if self.failing is None:
            self.failing = {"since": now, "tries": 0, "error": r.error, "status": r.status}
        self.failing.update(tries=self.failing["tries"] + 1, error=r.error, status=r.status)
        if self.failing["tries"] == 1 or self.failing["tries"] % 10 == 0:
            self.say("failing: %s (%s%s); %d tr%s; nothing moves" % (
                r.error, ERRORS.get(r.error, r.error), "" if r.status is None else ", status %d" % r.status,
                self.failing["tries"], "y" if self.failing["tries"] == 1 else "ies"))

    def same_file(self, f):
        """J-5: the file is the one read where it is not shorter than the cursor and the line that ends at the
        cursor is the line that was passed."""
        size = os.fstat(f.fileno()).st_size
        if size < self.offset:
            return "shorter than the cursor"
        if self.offset and self.line_sha is not None:
            raw = line_before(f, self.offset)
            if raw is None or _sha(raw) != self.line_sha:
                return "the last line passed changed"
        return None

    def step(self):
        """One read of the file and one send: "idle" (nothing whole to send), "moved", "failed"."""
        try:
            with open(self.path, "rb") as f:
                other = self.same_file(f)
                if other:
                    self.restarts += 1
                    self.offset, self.line_sha = 0, None
                    self.say("the file is another (%s): read again from its start, restart %d (the collector"
                             " gets lines twice: watch.host and id tell)" % (other, self.restarts))
                lines = whole_lines(f, self.offset)
        except OSError:
            self.fail(Result("failed", "file"))
            self.write_state()
            return "failed"
        if not lines:
            if self.failing and self.failing.get("error") == "file":
                self.failing = None
            return "idle"
        first = lines[0]
        if first.obj is None:   # J-5: not JSON or not an event: skipped, counted, never sent
            self.passed(first)
            self.skipped += 1
            self.write_state()
            return "moved"
        if len(piece(self.shape, first.raw, first.obj)) > MAX_BYTES:
            self.refuse(first, "locally: longer than one request may be (J-11)")
            self.write_state()
            return "moved"
        batch, size = [], 0
        for ln in lines:
            if ln.obj is None or len(batch) >= self.batch:
                break
            size += len(piece(self.shape, ln.raw, ln.obj))
            if size > MAX_BYTES:
                break
            batch.append(ln)
        r = self.send(batch)
        if r.kind == "taken":
            self.took(batch)
        elif r.kind == "refused":   # J-4: the batch's lines one by one; one bad line does not stop the rest
            for ln in batch:
                one = self.send([ln]) if len(batch) > 1 else r
                if one.kind == "taken":
                    self.took([ln])
                elif one.kind == "refused":
                    self.refuse(ln, "alone (status %d)" % one.status)
                else:
                    self.fail(one)
                    self.write_state()
                    return "failed"
        else:
            self.fail(r)
            self.write_state()
            return "failed"
        self.write_state()
        return "moved"

    # --- the run (J-10) --------------------------------------------------------------------------------------
    def stop(self):
        self._stop.set()

    def stopped(self):
        return self._stop.is_set()

    def pause(self, seconds):
        """Wait `seconds`, writing the state at least once a beat; True where Stop came."""
        end = self.clock() + seconds
        while not self.stopped():
            now = self.clock()
            if self.written_at is None or now - self.written_at >= self.beat:
                self.write_state()
            left = end - now
            if left <= 0:
                return False
            if self.wait(max(0.001, min(left, self.written_at + self.beat - now))):
                return True
        return True

    def run(self, once=False):
        """J-10: for as long as it runs; --once: what the file holds, then 0 all taken, 1 not all."""
        self.lock()
        try:
            how = self.resume()
            self.say("%s -> %s (shape %s, delivery %s%s); %s; state %s" % (
                self.path, where(self.dest), self.shape, DELIVERY, ", plain: not encrypted" if self.plain else "",
                how, self.state_file))
            self.write_state()
            tries = 0
            while not self.stopped():
                r = self.step()
                if r == "failed":
                    if once:
                        break
                    wait = WAITS[min(tries, len(WAITS) - 1)]
                    tries += 1
                    if self.pause(wait):
                        break
                    continue
                tries = 0
                if r == "idle":
                    if once:
                        break
                    if self.pause(self.poll_s):
                        break
                elif self.written_at is None or self.clock() - self.written_at >= self.beat:
                    self.write_state()
            self.write_state()   # J-10: at Stop, at the end of --once
        finally:
            self.unlock()
        ok = self.failing is None and self.refused_now == 0 and self.behind() == 0
        self.say("%s: sent %d, skipped %d, refused %d, restarts %d, behind %d byte(s)%s" % (
            "stopped" if self.stopped() else "done", self.sent, self.skipped, self.refused, self.restarts,
            self.behind(), "" if self.failing is None else "; failing: %s" % self.failing["error"]))
        return 0 if ok else 1


# --- --status (J-9) ------------------------------------------------------------------------------------------
def judge(state, now):
    """(exit, word, lines) of one state: 0 taken and nothing waits longer than a beat, 1 failing or behind, 3
    unreadable or written more than two beats ago (the forwarder is silent)."""
    if not isinstance(state, dict) or state.get("schema") != SCHEMA:
        return 3, "UNREADABLE", ["not a %s state" % SCHEMA]
    try:
        written = seconds_of(state["written"])
        beat = float(state.get("beat") or BEAT_DEFAULT)
        dest, cursor, refused = state["destination"], state["cursor"], state["refused"]
        lines = ["to %s (shape %s, delivery %s%s)" % (where(dest), state["shape"], state["delivery"],
                                                     ", plain: not encrypted" if state.get("plain") else ""),
                 "file %s, cursor %d (from the %s, offset %d)" % (state["file"], cursor["offset"],
                                                                   state["from"]["start"], state["from"]["offset"]),
                 "sent %d, skipped %d, refused %d%s, restarts %d" % (
                     state["sent"], state["skipped"], refused["count"],
                     " (latest: %s)" % ", ".join(str(i) for i in refused["ids"][-3:]) if refused["ids"] else "",
                     state["restarts"]),
                 "last taken: %s at %s; behind %d byte(s)" % (state.get("last_id") or "none",
                                                               state.get("last_ok") or "never", state["behind"]),
                 "written %s by pid %s (a beat of %g s)" % (state["written"], state["pid"], beat)]
        failing, behind = state.get("failing"), int(state["behind"])
        last_ok = seconds_of(state["last_ok"]) if state.get("last_ok") else None
    except (KeyError, TypeError, ValueError, AttributeError):
        return 3, "UNREADABLE", ["a %s state with a key missing or of the wrong type" % SCHEMA]
    if now - written > 2 * beat:
        return 3, "SILENT", lines + ["the state was written %.0f s ago, more than two beats: the forwarder is silent"
                                     " (stopped, killed or stuck)" % (now - written)]
    if failing:
        return 1, "FAILING", lines + ["failing since %s: %s (%s), %s tr%s%s" % (
            failing.get("since"), failing.get("error"), ERRORS.get(failing.get("error"), "?"), failing.get("tries"),
            "y" if failing.get("tries") == 1 else "ies",
            "" if failing.get("status") is None else ", status %s" % failing.get("status"))]
    if behind and (last_ok is None or written - last_ok > beat):
        return 1, "BEHIND", lines + ["%d byte(s) of whole lines wait longer than a beat" % behind]
    return 0, "OK", lines


def status(name=None, home=None, out=None, clock=time.time):
    out = out if out is not None else sys.stdout
    folder = forward_dir(home)
    if name:
        check_name(name)
        names = [name]
    else:
        try:
            names = sorted(n[:-5] for n in os.listdir(folder) if n.endswith(".json") and NAME.match(n[:-5]))
        except OSError:
            names = []
    if not names:
        out.write("raqib forward --status: no forwarder has written a state in %s: silent (exit 3)\n" % folder)
        return 3
    worst, now = 0, clock()
    for n in names:
        try:
            with open(state_path(n, home), "rb") as f:
                state = json.loads(f.read().decode("ascii"))
        except FileNotFoundError:
            code, word, lines = 3, "SILENT", ["no state: %s (it never ran, or not here)" % state_path(n, home)]
        except (OSError, ValueError, UnicodeDecodeError):
            code, word, lines = 3, "UNREADABLE", ["the state %s cannot be read" % state_path(n, home)]
        else:
            code, word, lines = judge(state, now)
        out.write("raqib forward %s: %s (exit %d)\n" % (n, word, code))
        for line in lines:
            out.write("  %s\n" % line)
        worst = code if (code == 3 or worst != 3 and code > worst) else worst
    return worst


def cli_run(args, out):
    """`raqib forward` (raqib/cli.py): --status, or a forwarder until Stop (--once: until the file is sent)."""
    if args.status is not None:
        return status(args.status or None, out=out)
    if not args.to:
        raise UsageError("--to URL: the collector (or --status [NAME])")
    if not args.name:
        raise UsageError("--name NAME: the forwarder's name, [a-z0-9-]{1,32}; its state is ~/.raqib/forward/NAME.json")
    fwd = Forwarder(args.name, args.file, args.to, shape=args.shape, token_file=args.token_file, ca=args.ca,
                    plain=args.plain, beat=args.beat, start=args.start, batch=args.batch, out=out)
    if not os.path.isfile(fwd.path) and args.once:
        raise UsageError("no events file: %s" % fwd.path)
    stops, old = [signal.SIGINT, signal.SIGTERM] + ([signal.SIGBREAK] if hasattr(signal, "SIGBREAK") else []), {}
    if threading.current_thread() is threading.main_thread():
        for sig in stops:
            old[sig] = signal.signal(sig, lambda *_: fwd.stop())
    try:
        return fwd.run(once=args.once)
    finally:
        for sig, handler in old.items():
            signal.signal(sig, handler)
