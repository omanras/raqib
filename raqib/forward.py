"""raqib forward: the events leave the host (ADR-0011 Amendments J, K, L and M; docs/specs/FORWARD.md).

A process of its own (J-1). It reads one events file - the watch's ~/.raqib/host/events.jsonl, as
docs/specs/EVENT.md "For a reader of the file" says a reader may - and sends every whole line to one HTTP
collector, at least once (J-3). The file is the buffer: it is opened for reading only, never written, moved or
locked; the forwarder keeps nothing of it but the lines in flight. Its cursor is a byte offset at the end of
the last whole line it passed, kept with the sha256 of that line (J-5).

The cursor and the lines in question (L-1, M-1, M-2). What a run holds, and what a try does with it:

- the cursor (`offset`, with `line_sha`): on the disk, in the state, and the only thing a restart has (a
  restart asks again from the cursor). Every line before it is passed: taken (a 2xx answer, in the hec shape
  with the code 0: `acknowledged`), not sent (not an event: skipped; longer than one request may be: refused
  locally), or refused alone twice with a take of a later line between the two refusals (M-2).
- the reach (`reach`, in memory only): how far this run has asked lines alone. Between the cursor and the reach
  lie only lines in question and lines that are not sent; the line at the cursor is then the first in question.
  With nothing in question, the reach is the cursor.
- the count in question (`question`, in memory only): the event lines between the cursor and the reach that
  were refused alone in this run and wait. They are not kept one by one: a reach and a count.
- the proof (`proof`, in memory only): where a send taken after the lines in question lies (its first byte, its
  end, the sha256 of its last line), until the lines in question before it are settled.

A try (one `step`) sends at most ALONE_MAX lines alone:
- a proof: each line in question before it is asked alone once more (M-2). Refused again, it is counted and
  passed; taken now, it is taken (and arrived after the proof). The lines not sent are passed on the way. Where
  the cursor reaches the proof, it passes the proof. A try that has sent ALONE_MAX lines alone while settling
  ends where the cursor is, and the next try goes on settling.
- lines in question and no proof (`refusing`): the first line in question is asked again alone, once a try (and
  the line after it, while each is taken: taken, it is passed); then the try goes on from the reach, a batch
  first, a refused batch line by line, the lines not sent reached past. A line refused alone there is in
  question too; a send taken there is the proof, and the try settles. Where the file has no more whole lines,
  or the try has sent ALONE_MAX lines alone, and nothing after the lines in question was taken, the forwarder
  is failing `refusing`, the cursor where it was.
- nothing in question: the lines not sent at the cursor are passed, then one batch. Taken, the cursor passes
  it. Refused, its lines are asked alone in order: a line taken while nothing is in question is passed; a line
  refused is in question (the reach passes it, the cursor stays), and the try goes on as above.
- a failed send, Stop, the token's answer, the file replaced (M-8): the try ends where it is.
The cursor never passes a line that was neither taken, nor not sent, nor refused twice with a take between.
A kill at any point leaves on the disk only a state written whole, whose cursor is before every line it had
not passed: a restart sends again (the collector may get a line twice), it never skips.

What it is not (J-1, J-2, A-1): the watch does not know it runs. raqib/host.py, raqib/eventlog.py,
raqib/event.py and raqib/hooks/ import nothing of this module (a test reads the imports). It sends; of the
collector it reads only the answer to its own send (its status, and in the hec shape the code of its body),
follows no redirect (http.client follows none: a 3xx is a failed send) and uses no proxy of the environment
(http.client reads none; urllib is never used). The standard library only.

The secret (J-7): the token is read from --token-file at every try; never an argument, the environment, the
state, an output line or an error's text. The wire (J-8, L-4, L-5, M-4, M-5): https is verified against the
system's authorities or --ca; nothing turns verification off and SSLKEYLOGFILE is not honoured. One send is
bounded whole: connecting (name resolution and the handshake included) 10 s from its start, sending the request
30 s, the answer 30 s from the request's last byte. A request late while being sent halves the next batch,
down to one line. A send abandoned (Stop, a bound) has its sockets shut down and is left to its own thread,
which alone closes them; while four abandoned sends have not ended, no send starts (`stuck`). Plain http only
to a loopback address unless --plain.

Its own silence is said (J-9, L-3, M-4): after every batch, every failure, at least once a beat whatever it is
doing (a send, a try of many lines, a walk over lines that are not events) and before whatever ends the run,
the state is written whole (beside, flushed, then renamed) to ~/.raqib/forward/<name>.json; `raqib forward
--status` reads it. Stop is looked at within SLICE_S everywhere it waits or walks.
"""
from __future__ import annotations

import binascii
import calendar
import datetime
import hashlib
import http.client
import ipaddress
import json
import math
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
DELIVERIES = ("acknowledged", "written", "sent")
BEAT_DEFAULT = 60.0                        # J-9
BEAT_MIN = 1.0                             # L-6
MAX_LINES = 100                            # J-11
MAX_BYTES = 512 * 1024                     # J-11, L-8, M-3
ALONE_MAX = 100                            # M-1: at most this many sends of a line alone in one try
STUCK_MAX = 4                              # M-5: at most this many abandoned sends not yet ended
CONNECT_S = 10.0                           # J-8, L-4: connecting, name resolution and the handshake included
ANSWER_S = 30.0                            # J-8, L-4: sending the request; the whole answer from its last byte
WAITS = (1, 2, 4, 8, 16, 32, 60)           # J-10: seconds, the last one again for as long as it runs
IDS_KEPT = 50                              # J-4
POLL_S = 1.0                               # how often a forwarder with nothing to send looks at the file again
SLICE_S = 0.25                             # L-4, M-4: no wait is longer than this without looking for Stop
JOIN_S = 0.5                               # an abandoned send's thread is given this long to end (M-5: never closed)
SCAN_READ = 64 * 1024                      # L-8, M-3: a line too long is looked through in pieces this long
ANSWER_READ = 64 * 1024                    # of an answer's body, only the hec code is read
TOKEN_READ = 64 * 1024
TOKEN = re.compile(rb"[\x21-\x7e]+\Z")     # one token: printable ASCII, no space (never a header's CR or LF)
TARGET = re.compile(r"[\x21-\x7e]*\Z")     # L-6: a path and query of printable ASCII, no space
CONTROL = re.compile(r"[\x00-\x1f\x7f]")   # M-8: a control character anywhere in the URL
LABEL = re.compile(r"[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")
SHA = re.compile(r"[0-9a-f]{64}\Z")
TAIL = "tail"                              # read_lines: more than 512 KiB after the last newline (L-8)
OTHER = "other"                            # read_at: the file is not the one the try began with (M-8)
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
    "refusing": "the collector refused each line sent alone and took no line after them (a 4xx): they wait in"
                " question",
    "token": "the collector refused the token (401 or 403)",
    "token-file": "the token file cannot be read or fails its checks",
    "file": "the events file cannot be read, or more than 512 KiB follow its last newline",
    "stuck": "four sends abandoned have not ended (a name that never resolves, a connect that never returns): no"
             " send starts until one ends",
    "unforeseen": "an error the forwarder did not foresee ended the run",
}
KEYS = ("schema", "name", "pid", "written", "destination", "shape", "delivery", "plain", "file", "cursor", "from",
        "beat", "sent", "skipped", "refused", "restarts", "last_id", "last_ok", "behind", "failing")
# L-2: the status's rule, said by FORWARD.md and the guide in these words (a test holds the three together)
STATUS_RULE = ("exit 0 only where nothing is failing and no whole line has waited longer than a beat; 1 where it"
               " is failing (`refusing` too) or behind; 3 where there is no state, it cannot be read, or it was"
               " written more than two beats ago or in the future (the forwarder is silent)")


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


def valid_host(host):
    """L-6: an IP address, or a name of ASCII labels (letters, digits, inner hyphens; 1 to 63 each, 253 in all)."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    if not host.isascii() or len(host) > 253:
        return False
    return all(LABEL.match(label) for label in host.split("."))


def destination(url, plain=False):
    """J-8, J-9, L-6, M-8: --to as {scheme, host, port, path} (no query, no user info) and the request's target.
    A syslog destination is a usage error that says so (the next task builds it)."""
    if not isinstance(url, str) or CONTROL.search(url):   # urlsplit would drop a tab or a newline unsaid
        raise UsageError("--to: the URL holds a control character (a tab, a newline, ...): it is refused, never"
                         " taken without it")
    try:
        parts = urlsplit(url)
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
    if port == 0:
        raise UsageError("--to: port 0 is no port a collector listens on (write the port, or none for the"
                         " scheme's own)")
    if not valid_host(host):
        raise UsageError("--to: the host is no valid name or address (a name of ASCII letters, digits and inner"
                         " hyphens; a name in another script is written in its xn-- form)")
    path = parts.path or "/"
    target = path + ("?" + parts.query if parts.query else "")
    if not TARGET.match(target):
        raise UsageError("--to: the path and the query are printable ASCII with no space (write a space as %20)")
    if scheme == "http" and not loopback(host) and not plain:
        raise UsageError("--to http://%s: plain http is taken only to a loopback address (127.0.0.0/8, ::1) unless"
                         " --plain is given (J-8)" % host)
    return {"scheme": scheme, "host": host, "port": port or (443 if scheme == "https" else 80), "path": path}, target


def where(dest):
    host = "[%s]" % dest["host"] if ":" in dest["host"] else dest["host"]
    return "%s://%s:%d%s" % (dest["scheme"], host, dest["port"], dest["path"])


def tls_context(ca=None):
    """J-8, L-5: what ssl.create_default_context builds for a client - certificate and host name verified, the
    flags of this Python's default - by the system's authorities or by --ca alone, and never a key log: the
    environment's SSLKEYLOGFILE is not read (create_default_context would open that file and write to it)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.verify_mode, ctx.check_hostname = ssl.CERT_REQUIRED, True
    if sys.version_info >= (3, 13):   # the flags create_default_context gained in 3.13
        ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN | ssl.VERIFY_X509_STRICT
    if ca:
        ctx.load_verify_locations(cafile=ca)
    else:
        ctx.load_default_certs(ssl.Purpose.SERVER_AUTH)
    return ctx


def read_token(path, platform=None):
    """J-7: the token, read afresh. Off Windows a file others can read (mode & 0o077) is a UsageError; on
    Windows that is not checked. A file that cannot be read raises OSError. At the start each is a usage error;
    while the forwarder runs each is a failed try, said as token-file (L-3)."""
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
    """J-5 (EVENT.md): the event a whole line holds, or None where it is not JSON or not an event. Only a line of
    at most MAX_BYTES is ever given (M-3: a longer one is never read whole)."""
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


def _hec_head(obj):
    return ('{"time":%s,"host":%s,"source":"raqib","sourcetype":"raqib:event","event":' % (
        hec_time(obj["time"]), json.dumps(obj["watch"]["host"], ensure_ascii=True))).encode("ascii")


def _bare(raw):
    """The length of raw without its line end (no copy of the line is made)."""
    n = len(raw)
    while n and raw[n - 1] in (10, 13):
        n -= 1
    return n


def piece(shape, raw, obj):
    """J-6: what one line puts in a request's body. raqib: the line as the file holds it, its newline with it.
    hec: the envelope, the event's bytes inside it unchanged."""
    if shape == "raqib":
        return raw
    return _hec_head(obj) + raw[:_bare(raw)] + b"}\n"


def piece_len(shape, raw, obj):
    """M-3: the length of piece(), computed without building it."""
    if shape == "raqib":
        return len(raw)
    return len(_hec_head(obj)) + _bare(raw) + 2


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


class Line:
    """One whole line of the file: its bytes and its event where it is at most MAX_BYTES long; where it is longer
    (M-3) only its place and its sha256, found piece by piece - its bytes are never held."""
    __slots__ = ("start", "end", "raw", "obj", "digest")

    def __init__(self, start, end, raw, obj, digest=None):
        self.start, self.end, self.raw, self.obj, self.digest = start, end, raw, obj, digest

    @property
    def long(self):
        return self.raw is None

    def sha(self):
        if self.digest is None:
            self.digest = _sha(self.raw)
        return self.digest

    def id(self):
        return self.obj.get("id") if isinstance(self.obj, dict) else None

    def named(self):
        """Its id, or - where the id was not read (a line too long, M-3) - its offset."""
        ident = self.id()
        return ident if isinstance(ident, str) else "offset %d" % self.start


def _rfind_newline(f, before, floor=0):
    """The offset just past the last newline before `before` and at or after `floor` (floor where none)."""
    pos = before
    while pos > floor:
        size = min(SCAN_READ, pos - floor)
        f.seek(pos - size)
        block = f.read(size)
        i = block.rfind(b"\n")
        if i >= 0:
            return pos - size + i + 1
        pos -= size
    return floor


def sha_range(f, start, end):
    """The sha256 of the bytes [start, end), read in pieces of SCAN_READ (M-3); None where the file is shorter."""
    h, pos = hashlib.sha256(), start
    f.seek(start)
    while pos < end:
        block = f.read(min(SCAN_READ, end - pos))
        if not block:
            return None
        h.update(block)
        pos += len(block)
    return h.hexdigest()


def sha_before(f, offset):
    """The sha256 of the line that ends at offset (its newline included), read in pieces; None where offset is
    not a line's end."""
    if offset <= 0:
        return None
    f.seek(offset - 1)
    if f.read(1) != b"\n":
        return None
    return sha_range(f, _rfind_newline(f, offset - 1), offset)


def _count(v):
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def _instant(v):
    if not isinstance(v, str) or not v.endswith("Z"):
        return False
    try:
        seconds_of(v)
    except ValueError:
        return False
    return True


def state_problem(old):
    """L-6, M-6: why a JSON state is not what the forwarder writes (None where it is). The run refuses to go on
    from such a state, and --status reads it as unreadable (3)."""
    if not isinstance(old, dict) or old.get("schema") != SCHEMA:
        return "not a %s state" % SCHEMA
    missing = [k for k in KEYS if k not in old]
    if missing:
        return "no %s" % ", ".join(missing)
    if not isinstance(old["name"], str) or not NAME.match(old["name"]) or not _count(old["pid"]):
        return "name or pid is not one a forwarder has"
    if not _instant(old["written"]):
        return "written is not an instant"
    d = old["destination"]
    if not (isinstance(d, dict) and d.get("scheme") in ("http", "https") and isinstance(d.get("host"), str) and
            d["host"] and _count(d.get("port")) and 0 < d["port"] < 65536 and isinstance(d.get("path"), str)):
        return "destination is not {scheme, host, port, path}"
    if old["shape"] not in SHAPES or old["delivery"] not in DELIVERIES or not isinstance(old["plain"], bool):
        return "shape, delivery or plain is not one the forwarder writes"
    if not isinstance(old["file"], str):
        return "file is not a text"
    cur = old["cursor"]
    if not isinstance(cur, dict) or not _count(cur.get("offset")):
        return "no cursor offset of whole bytes"
    sha = cur.get("line_sha256")
    if not (sha is None or isinstance(sha, str) and SHA.match(sha)):
        return "a cursor whose line_sha256 is not a sha256"
    if cur["offset"] > 0 and sha is None:
        return "a cursor above 0 with no line_sha256 (every line passed has its hash)"
    start = old["from"]
    if not isinstance(start, dict) or start.get("start") not in ("start", "end") or not _count(start.get("offset")):
        return "from is not {start, offset}"
    beat = old["beat"]
    if isinstance(beat, bool) or not isinstance(beat, (int, float)) or not math.isfinite(beat) or beat <= 0:
        return "beat is not a number of seconds above 0"
    if not all(_count(old[k]) for k in ("sent", "skipped", "restarts", "behind")):
        return "sent, skipped, restarts and behind are not counts"
    refused = old["refused"]
    if not isinstance(refused, dict) or not _count(refused.get("count")) or not isinstance(refused.get("ids"), list):
        return "refused is not {count, ids}"
    if old["last_id"] is not None and not isinstance(old["last_id"], str):
        return "last_id is not a text"
    if old["last_ok"] is not None and not _instant(old["last_ok"]):
        return "last_ok is not an instant"
    failing = old["failing"]
    if failing is not None:
        if not isinstance(failing, dict) or not _instant(failing.get("since")) or not _count(failing.get("tries")):
            return "failing is not {since, tries, error, status}"
        if failing.get("error") not in ERRORS:
            return "failing.error is not one of the forwarder's words"
        st = failing.get("status")
        if st is not None and not _count(st):
            return "failing.status is not a status"
    return None


class Result:
    """The answer to one send: taken, refused (a 4xx of J-4), token (401, 403), failed (error word; `phase` says
    where a send that was late was: connect, handshake, send or answer) or stopped (Stop came during the send: it
    was abandoned, L-4)."""
    __slots__ = ("kind", "error", "status", "phase")

    def __init__(self, kind, error=None, status=None, phase=None):
        self.kind, self.error, self.status, self.phase = kind, error, status, phase


def answer(shape, status, data):
    """J-3, J-4: what one answer says of the batch."""
    if 200 <= status < 300:
        if shape == "hec":
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


class Send:
    """L-4, M-5: one request on a thread of its own, so that the forwarder bounds it whole - connecting with name
    resolution and its handshake, sending, and the answer from the request's last byte - and honours Stop
    during it. The thread opens every socket of the send and is the only one that closes them (its own code, at
    its end). To abandon the send, the forwarder shuts its sockets down - which ends a blocked connect, send or
    read - and leaves them to the thread: no descriptor is closed under a thread that may still use it. Each
    socket call also has its own timeout, so a thread whose shutdown did not wake it ends within its bound."""

    def __init__(self, fwd, body, headers):
        self.dest, self.target, self.context = fwd.dest, fwd.target, fwd.context
        self.connect_s, self.answer_s, self.shape = fwd.connect_s, fwd.answer_s, fwd.shape
        self.lookup = fwd.lookup
        self.body, self.headers = body, headers
        self.wake, self.lock = threading.Event(), threading.Lock()
        self.socks, self.abandoned, self.done = [], False, False
        self.phase, self.since = "connect", time.monotonic()
        self.result = self.error = None
        self.thread = threading.Thread(target=self.run, name="raqib-forward-send", daemon=True)

    def mark(self, phase):
        self.phase = phase
        if phase in ("send", "answer"):   # the handshake is within the connect bound
            self.since = time.monotonic()

    def hold(self, sock):
        """Called by the send's own thread for every socket it opens."""
        with self.lock:
            if self.abandoned:
                sock.close()   # this thread's own socket, not yet used
                raise OSError("abandoned")
            self.socks.append(sock)
        return sock

    def deadline(self):
        return self.since + (self.connect_s if self.phase in ("connect", "handshake") else self.answer_s)

    def word(self):
        return "connect" if self.phase == "connect" else "late"

    def left(self):
        return max(0.001, self.deadline() - time.monotonic())

    def run(self):
        try:
            self.result = self.exchange()
        except BaseException as exc:   # handed to the forwarder, which says it as its own word (L-3)
            self.error = exc
        finally:
            with self.lock:
                socks, self.socks = self.socks, []
            for s in socks:   # M-5: closed here, by the thread that used them, and nowhere else
                try:
                    s.close()
                except OSError:
                    pass
            self.done = True
            self.wake.set()

    def exchange(self):
        d = self.dest
        try:
            raw = None
            for family, kind, proto, _, addr in self.lookup(d["host"], d["port"], 0, socket.SOCK_STREAM):
                s = self.hold(socket.socket(family, kind, proto))
                try:
                    s.settimeout(self.left())
                    s.connect(addr)
                    raw = s
                    break
                except OSError:
                    continue
            if raw is None:
                return Result("failed", "connect", phase="connect")
        except OSError:
            return Result("failed", "connect", phase="connect")
        sock = raw
        if self.context is not None:
            self.mark("handshake")
            try:
                sock = self.hold(self.context.wrap_socket(raw, server_hostname=d["host"],
                                                          do_handshake_on_connect=False))
                sock.settimeout(self.left())
                sock.do_handshake()
            except socket.timeout:
                return Result("failed", "late", phase="handshake")
            except (ssl.SSLError, ssl.CertificateError, OSError, ValueError):
                return Result("failed", "tls", phase="handshake")
        conn = (http.client.HTTPSConnection(d["host"], d["port"], context=self.context) if self.context else
                http.client.HTTPConnection(d["host"], d["port"]))
        conn.sock = sock   # connected and verified above: http.client sends on it and never connects
        self.mark("send")
        try:
            sock.settimeout(self.answer_s)
            conn.request("POST", self.target, body=self.body, headers=self.headers)
            self.mark("answer")
            resp = conn.getresponse()
            status = resp.status
            data = resp.read(ANSWER_READ)
            resp.close()
        except socket.timeout:
            return Result("failed", "late", phase=self.phase)
        except ssl.SSLError:
            return Result("failed", "tls", phase=self.phase)
        except (http.client.HTTPException, OSError, ValueError):
            return Result("failed", "no-answer", phase=self.phase)
        finally:
            conn.close()
        return answer(self.shape, status, data)

    def abandon(self):
        """Stop or the bound came: end the send where it is. Its sockets are shut down (a blocked call returns)
        and left to its thread, which closes them (M-5); the thread is given JOIN_S to end."""
        with self.lock:
            self.abandoned = True
            socks = list(self.socks)
        for s in socks:
            try:
                socket.socket.shutdown(s, socket.SHUT_RDWR)
            except (OSError, ValueError):
                pass
        if self.thread.ident is not None:
            self.thread.join(JOIN_S)

    def ended(self):
        return self.thread.ident is None or not self.thread.is_alive()


class Forwarder:
    """One name, one file, one destination (J-13). Every clock, wait and timeout can be given (tests): `clock`
    is the wall's and gives only the state's times; `mono` does not step and gives every wait and the beat;
    `nap(event, seconds)` is how the forwarder waits for a send in slices; `lookup` is getaddrinfo."""

    def __init__(self, name, path, url, shape="raqib", token_file=None, ca=None, plain=False, beat=None,
                 start="start", batch=MAX_LINES, home=None, out=None, clock=time.time, mono=time.monotonic,
                 wait=None, connect_s=CONNECT_S, answer_s=ANSWER_S, poll_s=POLL_S, alive=ui.pid_alive,
                 platform=None, pid=None, opener=None, nap=None, lookup=None):
        self.name = check_name(name)
        if shape not in SHAPES:
            raise UsageError("--shape: raqib or hec, not %r" % (shape,))
        self.dest, self.target = destination(url, plain)
        self.shape, self.token_file, self.platform = shape, token_file, platform or sys.platform
        if shape == "hec" and not token_file:
            raise UsageError("--shape hec needs --token-file (Authorization: Splunk <token>)")
        try:
            self.beat = BEAT_DEFAULT if beat is None else float(beat)
        except (TypeError, ValueError):
            self.beat = float("nan")
        if not (math.isfinite(self.beat) and self.beat >= BEAT_MIN):
            raise UsageError("--beat: a finite number of seconds, at least %g (L-6), not %r" % (BEAT_MIN, beat))
        if not (isinstance(batch, int) and 1 <= batch <= MAX_LINES):
            raise UsageError("--batch: 1 to %d lines (J-11)" % MAX_LINES)
        if start not in ("start", "end"):
            raise UsageError("--from: start or end")
        self.batch, self.size, self.home, self.alone_max = batch, batch, home, ALONE_MAX
        self.path = os.path.abspath(path or events_default(home))
        self.plain = self.dest["scheme"] == "http"
        self.out = out if out is not None else sys.stdout
        self.clock, self.mono = clock, mono
        self.connect_s, self.answer_s, self.poll_s = connect_s, answer_s, poll_s
        self.opener = opener or (lambda p: open(p, "rb"))
        self.nap = nap or (lambda ev, seconds: ev.wait(seconds))
        self.lookup = lookup or socket.getaddrinfo
        self._stop, self._signalled, self._send = threading.Event(), False, None
        self.wait = wait or self.sliced_wait
        self.alive, self.pid = alive, os.getpid() if pid is None else pid
        self.ca = ca
        if ca is not None and not os.path.isfile(ca):
            raise UsageError("--ca: no such file: %s" % ca)
        if self.dest["scheme"] == "https":
            try:   # J-8, L-5: verified, by the system's authorities or by --ca; nothing turns it off; no key log
                self.context = tls_context(ca)
            except (OSError, ssl.SSLError):
                raise UsageError("--ca: the file holds no certificate that can be read")
        else:
            self.context = None
        if token_file:
            try:   # J-7: a token file others can read is exit 2 before anything is sent
                self.token()
            except OSError as exc:
                raise UsageError("--token-file: cannot read %s: %s" % (token_file, exc.strerror or exc))
        self.state_file = state_path(self.name, home)
        self.lock_file = os.path.join(forward_dir(home), self.name + ".pid")
        self.between = lambda: None   # L-7: called between the pid file's two steps (a test injects a start)
        self.offset, self.line_sha, self.sent, self.skipped, self.restarts = 0, None, 0, 0, 0
        self.refused, self.refused_ids, self.last_id, self.last_ok, self.failing = 0, [], None, None, None
        self.refused_now = 0
        self.reach, self.question, self.proof, self.refusal, self.alone = 0, 0, None, None, 0   # M-1, M-2
        self.adrift = []   # M-5: the sends abandoned that have not ended
        self.carried, self.lost = False, None   # M-6: a failing carried from the state; M-7: the name lost
        self.start_from = {"start": start, "offset": 0}
        self.written_at, self.locked, self.state_error, self.scanned = None, False, None, None

    # --- the state (J-9) -------------------------------------------------------------------------------------
    def behind(self):
        try:
            with self.opener(self.path) as f:
                size = os.fstat(f.fileno()).st_size
                if size <= self.offset:
                    return 0
                floor = self.scanned[1] if self.scanned and self.scanned[0] == self.offset else self.offset
                last = _rfind_newline(f, size, min(floor, size))
                return last - self.offset if last > floor or (floor == self.offset and last > self.offset) else 0
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
        """Whole: written beside, flushed to the disk, then renamed over (J-9, L-6). A state that cannot be
        written is said once. M-7: where the pid file of the name no longer holds this forwarder's pid, another
        took the name: nothing is written over its state, and the run stops with the reason."""
        if self.lost:
            return
        if self.locked:
            other = self.holder()
            if other != self.pid:
                self.lost = ("the pid file %s no longer holds this forwarder's pid %d (it holds %s): another"
                             " forwarder took the name %s, so this one stops and leaves the name's state to it"
                             % (self.lock_file, self.pid, "nothing" if other is None else "no pid that can be"
                                " read" if other is False else "pid %d" % other, self.name))
                self.say(self.lost)
                raise UsageError(self.lost)
        text = json.dumps(self.state(), indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n"
        temp = "%s.%d.tmp" % (self.state_file, self.pid)
        self.written_at = self.mono()
        try:
            os.makedirs(os.path.dirname(self.state_file), exist_ok=True)
            with open(temp, "w", encoding="ascii", newline="\n") as f:
                f.write(text)
                f.flush()
                os.fsync(f.fileno())
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

    def tick(self):
        """M-4: the state at least once a beat, whatever the forwarder is doing (a send, a try, a walk)."""
        if self.written_at is None or self.mono() - self.written_at >= self.beat:
            self.write_state()

    def say(self, text):
        try:
            self.out.write("raqib forward %s: %s\n" % (self.name, text))
            self.out.flush()
        except (OSError, ValueError):
            pass

    # --- the name (J-13, L-7, M-6, M-7) ----------------------------------------------------------------------
    def holder(self):
        """The pid in the pid file: an int, None where the file is gone, False where it is empty or cannot be
        read (a life that cannot be told)."""
        try:
            with open(self.lock_file, "rb") as f:
                text = f.read(32).strip()
        except FileNotFoundError:
            return None
        except OSError:
            return False
        return int(text) if text.isdigit() and int(text) > 0 else False

    def publish(self, temp):
        """The pid file appears whole or not at all, and never over another's: a hard link off Windows, a rename
        on Windows (which never replaces a file that is there)."""
        if os.name == "nt":
            os.rename(temp, self.lock_file)
        else:
            os.link(temp, self.lock_file)

    def lock(self):
        """J-13, L-7; M-6: an error of the system here (the directory, the pid file) is a usage error with its
        reason, never a traceback."""
        try:
            self._lock()
        except OSError as exc:
            raise UsageError("the name %s cannot be taken: %s: %s" % (
                self.name, exc.filename or self.lock_file, exc.strerror or type(exc).__name__))

    def _lock(self):
        os.makedirs(forward_dir(self.home), exist_ok=True)
        temp = "%s.%d.%s.tmp" % (self.lock_file, self.pid, binascii.hexlify(os.urandom(4)).decode("ascii"))
        fd = os.open(temp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("%d\n" % self.pid)
            f.flush()
        try:
            for _ in range(3):
                self.between()
                try:
                    self.publish(temp)
                    self.locked = True
                    return
                except FileExistsError:
                    pass
                other = self.holder()
                if other is False:
                    raise UsageError("the pid file %s is empty or cannot be read: whether a forwarder named %s runs"
                                     " cannot be told, so the name is refused (remove the file where none runs)"
                                     % (self.lock_file, self.name))
                if other is not None and other != self.pid and self.alive(other) is not False:
                    raise UsageError("a forwarder named %s runs (pid %d): a second one of one name is refused (J-13)"
                                     % (self.name, other))
                if other is not None:   # its forwarder is gone: the name is free again
                    try:
                        os.remove(self.lock_file)
                    except FileNotFoundError:
                        pass
            raise UsageError("the name %s cannot be taken: %s" % (self.name, self.lock_file))
        finally:
            try:
                os.remove(temp)
            except OSError:
                pass

    def unlock(self):
        if self.locked:
            if self.holder() == self.pid:
                try:
                    os.remove(self.lock_file)
                except OSError:
                    pass
            self.locked = False

    def resume(self):
        """The cursor of an earlier run of this name, where its state holds one for this file and this
        destination, with the `failing` it held (M-6: said until the first try has an answer); a first run
        starts at the file's start or, with --from end, at its end (J-12). A state that is there and is not
        what the forwarder writes is a usage error, never a first run (L-6)."""
        try:
            with open(self.state_file, "rb") as f:
                text = f.read()
        except FileNotFoundError:
            text = None
        except OSError:
            raise UsageError("the state %s cannot be read: move it away to start this name again" % self.state_file)
        if text is not None:
            try:
                old = json.loads(text.decode("ascii"))
            except (ValueError, UnicodeDecodeError):
                old = None
            why = state_problem(old) if old is not None else "not JSON"
            if why:
                raise UsageError("the state %s is damaged (%s): it is never taken for a first run; move it away to"
                                 " start this name again" % (self.state_file, why))
            if old.get("file") != self.path or old.get("destination") != self.dest or old.get("shape") != self.shape:
                raise UsageError("the name %s forwards %s to %s (shape %s): another file, destination or shape is"
                                 " another name (J-13)" % (self.name, old.get("file"), where(old["destination"]),
                                                           old.get("shape")))
            cur = old["cursor"]
            self.offset, self.line_sha = cur["offset"], cur.get("line_sha256")
            self.reach = self.offset
            self.sent, self.skipped, self.restarts = old["sent"], old["skipped"], old["restarts"]
            self.refused, self.refused_ids = old["refused"]["count"], list(old["refused"]["ids"])[-IDS_KEPT:]
            self.last_id, self.last_ok = old.get("last_id"), old.get("last_ok")
            self.start_from = dict(old["from"])
            if old["failing"]:
                self.failing, self.carried = dict(old["failing"]), True
            return "resumed at offset %d%s" % (self.offset, "; failing %s, as the state said, until a try has an"
                                               " answer" % self.failing["error"] if self.carried else "")
        if self.start_from["start"] == "end":
            try:
                with self.opener(self.path) as f:
                    size = os.fstat(f.fileno()).st_size
                    self.offset = _rfind_newline(f, size)
                    self.line_sha = sha_before(f, self.offset) if self.offset else None
            except OSError:
                self.offset = 0
            self.reach = self.offset
            self.start_from["offset"] = self.offset
            return "a first run, from the file's end (offset %d)" % self.offset
        return "a first run, from the file's start"

    # --- one send (J-8, L-4, M-4, M-5) -----------------------------------------------------------------------
    def token(self):
        return read_token(self.token_file, self.platform) if self.token_file else None

    def post(self, body, token):
        """One request, bounded whole, waited for in slices: Stop abandons it within SLICE_S, and the state is
        written once a beat while it lasts (M-4). While STUCK_MAX abandoned sends have not ended, none starts."""
        headers = {"Content-Type": "application/x-ndjson" if self.shape == "raqib" else "application/json",
                   "Content-Length": str(len(body)), "User-Agent": SCHEMA}
        if token is not None:
            headers["Authorization"] = ("Splunk " if self.shape == "hec" else "Bearer ") + token
        if self.stopped():   # Stop came before the send: nothing is sent
            return Result("stopped")
        self.adrift = [job for job in self.adrift if not job.ended()]
        if len(self.adrift) >= STUCK_MAX:
            return Result("failed", "stuck")
        job = Send(self, body, headers)
        self._send = job
        outcome = None
        try:
            job.thread.start()
            while not job.done:
                if self.stopped():
                    outcome = Result("stopped")
                    break
                left = job.deadline() - time.monotonic()
                if left <= 0:
                    outcome = Result("failed", job.word(), phase=job.phase)
                    break
                self.nap(job.wake, min(left, SLICE_S))
                self.tick()
        except BaseException:
            if not job.done:
                self.leave(job)
            raise
        finally:
            self._send = None
        if not job.done:
            self.leave(job)
            return outcome
        job.thread.join()
        if job.error is not None:
            raise job.error
        return job.result

    def leave(self, job):
        job.abandon()
        if not job.ended():
            self.adrift.append(job)

    def send(self, lines):
        try:
            token = self.token()
        except (OSError, UsageError):   # L-3: while it runs, a failed try; read again at the next
            return Result("failed", "token-file")
        r = self.post(b"".join(piece(self.shape, ln.raw, ln.obj) for ln in lines), token)
        if r.kind == "taken" and self.size != self.batch:
            self.say("a batch was taken: batches are %d lines again" % self.batch)
            self.size = self.batch
        elif r.kind == "failed" and r.error == "late" and r.phase == "send" and len(lines) > 1:
            self.size = max(1, len(lines) // 2)   # M-4: a link too slow for the batch within the bound
            self.say("a request of %d lines was not sent within %g s: the next batch is %d" % (
                len(lines), self.answer_s, self.size))
        return r

    # --- the cursor (J-3, J-4, J-5, L-1, M-1, M-2, M-3) ------------------------------------------------------
    def unsent(self, ln):
        """J-5, K-2, M-3: a line that is not sent - not an event, or longer than one request may be."""
        return ln.long or ln.obj is None or piece_len(self.shape, ln.raw, ln.obj) > MAX_BYTES

    def pass_line(self, ln):
        self.offset, self.line_sha = ln.end, ln.sha()
        if self.reach < self.offset:
            self.reach = self.offset

    def pass_unsent(self, ln):
        if ln.obj is None and not ln.long:
            self.skipped += 1
        else:
            self.count_refused(ln, "locally: longer than one request may be (J-11)")
        self.pass_line(ln)

    def taken(self, lines):
        """J-3: the collector took them (counted now; the cursor passes them where nothing waits before them)."""
        self.sent += len(lines)
        self.last_id, self.last_ok = lines[-1].id(), iso(self.clock())
        if self.failing:
            self.say("taken again after %d failed tr%s" % (self.failing["tries"], "y" if self.failing["tries"] == 1
                                                           else "ies"))
        self.failing = None

    def count_refused(self, ln, why):
        self.refused += 1
        self.refused_now += 1
        self.refused_ids = (self.refused_ids + [ln.named()])[-IDS_KEPT:]
        self.say("line at offset %d (%s) refused %s: counted and passed" % (
            ln.start, "id %s" % ln.id() if ln.id() is not None else "its id not read", why))

    def fail(self, r):
        now = iso(self.clock())
        if self.failing is None:
            self.failing = {"since": now, "tries": 0, "error": r.error, "status": r.status}
        self.failing.update(tries=self.failing["tries"] + 1, error=r.error, status=r.status)
        if self.failing["tries"] == 1 or self.failing["tries"] % 10 == 0:
            more = ""
            if r.error == "refusing":
                more = ("; %d line(s) in question from offset %d (asked alone as far as offset %d) wait for a later"
                        " line taken" % (self.question, self.offset, self.reach))
            self.say("failing: %s (%s%s); %d tr%s; nothing moves%s" % (
                r.error, ERRORS.get(r.error, r.error), "" if r.status is None else ", status %d" % r.status,
                self.failing["tries"], "y" if self.failing["tries"] == 1 else "ies", more))

    def failed(self, r):
        self.fail(r)
        self.write_state()
        return "failed"

    def same_file(self, f):
        """J-5: the file is the one read where it is not shorter than the cursor and the line that ends at the
        cursor is the line that was passed."""
        size = os.fstat(f.fileno()).st_size
        if size < self.offset:
            return "shorter than the cursor"
        if self.offset and self.line_sha is not None:
            if sha_before(f, self.offset) != self.line_sha:
                return "the last line passed changed"
        return None

    def scan_newline(self, f, offset, start):
        """L-8: the end of the first line at offset, looked for from `start` in pieces never kept; None where no
        newline is there yet (what was looked through is remembered for the next look)."""
        if self.scanned and self.scanned[0] == offset:
            start = max(start, self.scanned[1])
        f.seek(start)
        pos = start
        while True:
            block = f.read(SCAN_READ)
            if not block:
                self.scanned = (offset, pos)
                return None
            i = block.find(b"\n")
            if i >= 0:
                self.scanned = None
                return pos + i + 1
            pos += len(block)

    def read_lines(self, f, offset):
        """The whole lines from offset, at most about one request's bytes of them ([Line]); TAIL where more than
        512 KiB follow with no newline (L-8). A line longer than 512 KiB is never read whole (M-3): its end is
        found and its sha256 made piece by piece, and it is given alone, its bytes not held."""
        if self.scanned and self.scanned[0] == offset:   # no newline up to where the last look reached
            data, cut = b"", -1
        else:
            f.seek(offset)
            data = f.read(MAX_BYTES + 1)
            cut = data.rfind(b"\n")
        if cut < 0:
            if len(data) <= MAX_BYTES and not self.scanned:
                return []
            end = self.scan_newline(f, offset, offset + len(data))
            if end is None:
                return TAIL
            del data
            return [Line(offset, end, None, None, sha_range(f, offset, end))]
        out, at = [], offset
        for body in data[:cut + 1].split(b"\n")[:-1]:   # only a newline ends a line
            raw = body + b"\n"
            out.append(Line(at, at + len(raw), raw, classify(raw)))
            at += len(raw)
        return out

    def read_at(self, at):
        """M-8: the whole lines from `at` in the file the try began with - the same check as at each pass: where
        the file is another, OTHER (the try ends; the next pass counts the restart). None where it cannot be
        read."""
        try:
            with self.opener(self.path) as f:
                if self.same_file(f):
                    return OTHER
                return self.read_lines(f, at)
        except OSError:
            return None

    def batch_of(self, lines):
        batch, size = [], 0
        for ln in lines:
            if self.unsent(ln) or len(batch) >= self.size:
                break
            size += piece_len(self.shape, ln.raw, ln.obj)
            if size > MAX_BYTES:
                break
            batch.append(ln)
        return batch

    def check_file(self):
        """The same file as the cursor's, or another (J-5: read again from its start, a restart counted)."""
        try:
            with self.opener(self.path) as f:
                other = self.same_file(f)
        except OSError:
            return self.failed(Result("failed", "file"))
        if other:
            self.restarts += 1
            self.offset, self.line_sha, self.scanned = 0, None, None
            self.reach, self.question, self.proof = 0, 0, None
            self.say("the file is another (%s): read again from its start, restart %d (the collector gets lines"
                     " twice: watch.host and id tell)" % (other, self.restarts))
        return None

    def step(self):
        """One try: "idle" (nothing whole to send), "moved", "failed", "stopped", or "again" (the file was replaced
        during the try: the next pass counts the restart)."""
        r = self.attempt()
        if r == "idle" and self.carried:   # M-6: the file read and nothing waits: the failing carried is over
            self.failing = None
        if r != "stopped":
            self.carried = False
        return r

    def attempt(self):
        self.alone = 0
        r = self.check_file()
        if r:
            return r
        if self.proof is not None:
            r = self.settle()
            if r != "settled":
                return r
            self.write_state()
            return "moved"
        offset = self.offset
        if self.question:
            r = self.ask_first()
            if r != "on":
                return r
        r = self.go_on()
        return "moved" if r == "idle" and self.offset != offset else r

    def ask_first(self):
        """M-1: each try asks the first line in question again, alone - a collector put right is seen at once,
        and the line is then taken, not refused - and, while each is taken, the line in question after it."""
        while self.question:
            if self.stopped():
                return "stopped"
            if self.alone >= self.alone_max:
                return "moved"
            chunk = self.read_at(self.offset)
            if chunk == OTHER:
                return "again"
            if not isinstance(chunk, list) or not chunk:
                return self.failed(Result("failed", "file"))
            ln = chunk[0]
            if self.unsent(ln):   # not reached while the cursor is at the first line in question
                self.pass_unsent(ln)
                continue
            self.tick()
            r = self.send([ln])
            self.alone += 1
            if r.kind == "stopped":
                return "stopped"
            if r.kind == "refused":   # no take between its two refusals: it stays in question
                self.refusal = r.status
                return "on"
            if r.kind != "taken":
                return self.failed(r)
            self.taken([ln])
            self.pass_line(ln)
            self.question -= 1
            r = self.walk_to_question()
            if r:
                return r
            self.write_state()
        return "on"

    def walk_to_question(self):
        """The cursor passes the lines not sent after it, up to the next line in question or the reach."""
        while self.offset < self.reach:
            chunk = self.read_at(self.offset)
            if chunk == OTHER:
                return "again"
            if not isinstance(chunk, list) or not chunk:
                return self.failed(Result("failed", "file"))
            for ln in chunk:
                if ln.start >= self.reach or not self.unsent(ln):
                    return None
                if self.stopped():
                    return "stopped"
                self.pass_unsent(ln)
                self.tick()
        return None

    def go_on(self):
        """From the reach (the cursor, where nothing is in question): the lines not sent (passed at the cursor,
        reached past behind a line in question, M-4: a walk looks at Stop and the beat at each line), a batch, a
        refused batch line by line (J-4, M-1). Past one batch, a try goes on only while lines are in question."""
        begun = self.offset
        while True:
            if self.stopped():
                return "stopped"
            self.tick()
            at = self.reach if self.question else self.offset
            chunk = self.read_at(at)
            if chunk == OTHER:
                return "again"
            if chunk is None or chunk == TAIL and not self.question:
                return self.failed(Result("failed", "file"))
            if self.failing and self.failing.get("error") == "file":   # it is read again, and has its newline
                self.failing = None
            if chunk == TAIL or not chunk:
                break
            walked = 0
            for ln in chunk:
                if not self.unsent(ln):
                    break
                if walked and self.stopped():
                    return "stopped"
                if self.question:
                    self.reach = ln.end   # behind a line in question: passed when the cursor gets there
                else:
                    self.pass_unsent(ln)
                walked += 1
                self.tick()
            if walked:
                continue
            if self.alone >= self.alone_max:   # M-1: a batch refused now could not be asked line by line
                break
            batch = self.batch_of(chunk)
            alone = len(batch) == 1
            r = self.send(batch)
            if alone:
                self.alone += 1
            if r.kind == "stopped":
                return "stopped"
            if r.kind == "taken":
                w = self.after_take(batch)
                if w:
                    return w
                self.write_state()
                return "moved"
            if r.kind != "refused":
                return self.failed(r)
            self.refusal = r.status
            if alone:
                self.question += 1
                self.reach = batch[0].end
                continue
            w = self.split(batch)
            if w == "plain":
                self.write_state()
                return "moved"
            if w == "cap":
                break
            if w != "on":
                return w
        if self.question:
            return self.failed(Result("failed", "refusing", self.refusal))
        if self.offset != begun:
            self.write_state()
            return "moved"
        return "idle"

    def after_take(self, lines):
        """A send taken: passed at once where nothing is in question before it; otherwise it is the proof, and
        the lines in question before it are settled (M-2). None where the try goes on."""
        self.taken(lines)
        if not self.question:
            self.pass_line(lines[-1])
            return None
        self.proof = (lines[0].start, lines[-1].end, lines[-1].sha())
        self.reach = lines[-1].end
        self.write_state()
        r = self.settle()
        return None if r == "settled" else r

    def split(self, batch):
        """J-4: a refused batch, line by line, in order. "plain" where nothing is left in question, "on" where
        lines are, "cap" at ALONE_MAX sends alone, or the word that ends the try."""
        for ln in batch:
            if self.alone >= self.alone_max:
                return "cap"
            if self.stopped():
                return "stopped"
            self.tick()
            r = self.send([ln])
            self.alone += 1
            if r.kind == "stopped":
                return "stopped"
            if r.kind == "taken":
                w = self.after_take([ln])
                if w:
                    return w
                self.write_state()
                continue
            if r.kind != "refused":
                return self.failed(r)
            self.refusal = r.status
            self.question += 1
            self.reach = ln.end
        return "on" if self.question else "plain"

    def settle(self):
        """M-2: a send was taken after the lines in question: each line in question before it is asked alone once
        more. Refused again, it is counted and passed; taken now, it is taken. The lines not sent are passed on
        the way, and the cursor then passes the proof. "settled", or the word that ends the try ("moved" at
        ALONE_MAX sends alone: the next try goes on settling)."""
        start, end, sha = self.proof
        while self.offset < start:
            if self.stopped():
                return "stopped"
            chunk = self.read_at(self.offset)
            if chunk == OTHER:
                return "again"
            if not isinstance(chunk, list) or not chunk:
                return self.failed(Result("failed", "file"))
            for ln in chunk:
                if ln.start >= start:
                    break
                if self.stopped():
                    return "stopped"
                self.tick()
                if self.unsent(ln):
                    self.pass_unsent(ln)
                    continue
                if self.alone >= self.alone_max:
                    self.write_state()
                    return "moved"
                r = self.send([ln])
                self.alone += 1
                if r.kind == "stopped":
                    return "stopped"
                if r.kind == "taken":
                    self.taken([ln])
                elif r.kind == "refused":
                    self.count_refused(ln, "alone twice (status %d), a later line taken between (M-2)" % r.status)
                else:
                    return self.failed(r)
                self.pass_line(ln)
                self.question = max(0, self.question - 1)
                self.write_state()
        self.offset, self.line_sha = end, sha
        self.reach, self.question, self.proof = max(self.reach, end), 0, None
        return "settled"

    # --- the run (J-10, L-3, L-4) ----------------------------------------------------------------------------
    def stop(self):
        self._stop.set()
        job = self._send
        if job is not None:
            job.wake.set()

    def stop_by_signal(self, *_):
        """A signal's handler: a flag only (no lock is taken in a handler); every wait looks at it within
        SLICE_S."""
        self._signalled = True

    def stopped(self):
        return self._signalled or self._stop.is_set()

    def sliced_wait(self, seconds):
        """The default wait: on the clock that does not step, in slices, so that Stop - by stop() or by a
        signal - is seen within SLICE_S on every platform. True where Stop came."""
        end = time.monotonic() + seconds
        while not self.stopped():
            left = end - time.monotonic()
            if left <= 0:
                return False
            self._stop.wait(min(left, SLICE_S))
        return True

    def pause(self, seconds):
        """Wait `seconds` on the monotonic clock, writing the state at least once a beat; True where Stop came."""
        end = self.mono() + seconds
        while not self.stopped():
            now = self.mono()
            if self.written_at is None or now - self.written_at >= self.beat:
                self.write_state()
            left = end - now
            if left <= 0:
                return False
            if self.wait(max(0.001, min(left, self.written_at + self.beat - now))):
                return True
        return True

    def loop(self, once):
        tries = 0
        while not self.stopped():
            r = self.step()
            if r == "stopped":
                break
            if r == "failed":
                if once:
                    break
                wait = WAITS[min(tries, len(WAITS) - 1)]
                tries += 1
                if self.pause(wait):
                    break
                continue
            tries = 0
            if r in ("idle", "again"):
                if once:
                    break
                if self.pause(self.poll_s):
                    break
            else:
                self.tick()

    def run(self, once=False):
        """J-10: for as long as it runs; --once: what the file holds, then 0 all taken, 1 not all. Whatever ends
        the run after its start - Stop, a usage error, an error it did not foresee - the state is written first
        (L-3; M-7: unless another forwarder took the name); an unforeseen error is said by the word
        `unforeseen`, never by its text."""
        self.lock()
        try:
            how = self.resume()
        except BaseException:
            self.unlock()
            raise
        ended = None
        try:
            self.say("%s -> %s (shape %s, delivery %s%s); %s; state %s" % (
                self.path, where(self.dest), self.shape, DELIVERY, ", plain: not encrypted" if self.plain else "",
                how, self.state_file))
            self.write_state()
            self.loop(once)
        except UsageError:
            raise
        except Exception as exc:
            ended = type(exc).__name__
            self.fail(Result("failed", "unforeseen"))
        finally:
            try:
                self.write_state()   # J-10, L-3: at Stop, at the end of --once, and whatever else ends it
            finally:
                self.unlock()
        behind = self.behind()
        ok = ended is None and self.failing is None and self.refused_now == 0 and behind == 0
        if ended:
            self.say("ended by an error it did not foresee (%s): the state is written, failing: unforeseen" % ended)
        self.say("%s: sent %d, skipped %d, refused %d, restarts %d, behind %d byte(s)%s" % (
            "stopped" if self.stopped() else "ended" if ended else "done", self.sent, self.skipped, self.refused,
            self.restarts, behind, "" if self.failing is None else "; failing: %s" % self.failing["error"]))
        return 0 if ok else 1


# --- --status (J-9, L-2, M-6) --------------------------------------------------------------------------------
def judge(state, now):
    """(exit, word, lines) of one state, by STATUS_RULE. M-6: a state that is not what the forwarder writes is
    unreadable (3), never read as calm."""
    why = state_problem(state)
    if why:
        return 3, "UNREADABLE", ["not what a forwarder writes: %s" % why]
    try:
        written, beat = seconds_of(state["written"]), float(state["beat"])
        dest, cursor, refused, failing = state["destination"], state["cursor"], state["refused"], state["failing"]
        lines = ["to %s (shape %s, delivery %s%s)" % (where(dest), state["shape"], state["delivery"],
                                                     ", plain: not encrypted" if state["plain"] else ""),
                 "file %s, cursor %d (from the %s, offset %d)" % (state["file"], cursor["offset"],
                                                                   state["from"]["start"], state["from"]["offset"]),
                 "sent %d, skipped %d, refused %d%s, restarts %d" % (
                     state["sent"], state["skipped"], refused["count"],
                     " (latest: %s)" % ", ".join(str(i) for i in refused["ids"][-3:]) if refused["ids"] else "",
                     state["restarts"]),
                 "last taken: %s at %s; behind %d byte(s)" % (state["last_id"] or "none", state["last_ok"] or "never",
                                                               state["behind"]),
                 "written %s by pid %d (a beat of %g s)" % (state["written"], state["pid"], beat)]
        last_ok = seconds_of(state["last_ok"]) if state["last_ok"] else None
    except Exception:   # state_problem read every key; this is the last guard against a traceback
        return 3, "UNREADABLE", ["a %s state that cannot be read" % SCHEMA]
    age = now - written
    if age < 0:
        return 3, "SILENT", lines + ["the state was written %.0f s in the future of this clock: its age cannot be"
                                     " told, so it is not fresh" % -age]
    if age > 2 * beat:
        return 3, "SILENT", lines + ["the state was written %.0f s ago, more than two beats: the forwarder is silent"
                                     " (stopped, killed or stuck)" % age]
    if failing:
        return 1, "FAILING", lines + ["failing since %s: %s (%s), %d tr%s%s" % (
            failing["since"], failing["error"], ERRORS[failing["error"]], failing["tries"],
            "y" if failing["tries"] == 1 else "ies",
            "" if failing.get("status") is None else ", status %d" % failing["status"])]
    if state["behind"] and (last_ok is None or written - last_ok > beat):
        return 1, "BEHIND", lines + ["%d byte(s) of whole lines wait longer than a beat%s" % (
            state["behind"], " (no send of this name was ever taken)" if last_ok is None else "")]
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
        refused = "unknown"
        try:
            with open(state_path(n, home), "rb") as f:
                state = json.loads(f.read().decode("ascii"))
        except FileNotFoundError:
            code, word, lines = 3, "SILENT", ["no state: %s (it never ran, or not here)" % state_path(n, home)]
        except (OSError, ValueError, UnicodeDecodeError):
            code, word, lines = 3, "UNREADABLE", ["the state %s cannot be read" % state_path(n, home)]
        else:
            code, word, lines = judge(state, now)
            try:
                refused = "%d" % state["refused"]["count"]
            except (KeyError, TypeError, ValueError):
                pass
        out.write("raqib forward %s: %s (exit %d); refused %s\n" % (n, word, code, refused))
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
    # L-11: Stop by the system's signal: SIGINT and SIGTERM, and on Windows SIGBREAK (CTRL_BREAK_EVENT)
    stops, old = [signal.SIGINT, signal.SIGTERM] + ([signal.SIGBREAK] if hasattr(signal, "SIGBREAK") else []), {}
    if threading.current_thread() is threading.main_thread():
        for sig in stops:
            old[sig] = signal.signal(sig, fwd.stop_by_signal)
    try:
        return fwd.run(once=args.once)
    finally:
        for sig, handler in old.items():
            signal.signal(sig, handler)
