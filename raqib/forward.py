"""raqib forward: the events leave the host (ADR-0011 Amendments J to N; docs/specs/FORWARD.md).

A process of its own (J-1). It reads one events file - the watch's ~/.raqib/host/events.jsonl, as
docs/specs/EVENT.md "For a reader of the file" says a reader may - and sends every whole line to one collector,
over HTTP or over syslog, at least once (J-3). The file is the buffer: it is opened for reading only, never
written, moved or locked; the forwarder keeps nothing of it but the lines in flight. Its cursor is a byte offset
at the end of the last whole line it passed, kept with the sha256 of that line (J-5).

Two transports, one machine (J-6). A send is one batch of whole lines, whatever carries it; the cursor, the
lines in question, the state and --status below are the same for both. HTTP: one request, taken on a 2xx
(`acknowledged`). Syslog (syslog+udp://, syslog+tcp://, syslog+tls://): one RFC 5424 message per line -
<PRI>1 TIMESTAMP HOSTNAME raqib - MSGID - MSG, PRI the facility (13, log audit, unless --facility N) times 8
plus the event's severity (high 2, medium 4, low 5, a hole 4, none and info 6), TIMESTAMP the event's time,
HOSTNAME its watch.host, MSGID its kind (each "-" where the event's value is not what RFC 5424 takes there),
MSG the line as written, without its newline. Over tcp and tls the messages of a batch are written on one
connection, framed by octet count (RFC 6587: "<length> <message>"), or with --framing newline each followed by
a newline; over udp each message is one datagram. Syslog has no answer: over tcp and tls a batch is taken when
its bytes were handed to the system with no error (`written`: not that they were received), over udp when its
datagrams were sent (`sent`: nothing is known). So a syslog collector never refuses a line, and the paths of
the lines in question never arise there. A line whose message is longer than a datagram may be (over 65000
bytes, over udp) is refused locally as a line longer than one request is: counted, named, passed, never cut.
Syslog carries no token (no --token-file) and only the raqib shape (the MSG is the line).

The cursor and the lines in question (L-1, M-1, M-2, N-3, N-5). What a run holds, and what a try does with it:

- the head (`head`, in the state): the sha256 of the file's first bytes, at most HEAD_MAX, and how many (N-3).
- the cursor (`offset`, with `line_sha`): on the disk, in the state, and the only thing a restart has (a
  restart asks again from the cursor). Every line before it is passed: taken (a 2xx answer, in the hec shape
  with the code 0: `acknowledged`), not sent (not an event: skipped; longer than one request may be: refused
  locally), or refused alone twice with a take of a later line between the two refusals (M-2). `sent` counts
  a taken line when the cursor passes it (N-5).
- the reach (`reach`, in memory only, kept with `reach_sha`, the sha256 of the line that ends at it): how far
  this run has asked lines alone. Between the cursor and the reach lie only lines in question and lines that
  are not sent; the line at the cursor is then the first in question. With nothing in question, the reach is
  the cursor.
- the count in question (`question`, in memory only; the state says it, with since when, as `in_question`):
  the event lines between the cursor and the reach that were refused alone in this run and wait. They are not
  kept one by one: a reach and a count.
- the proof (`proof`, in memory only): where a send taken after the lines in question lies (its first byte, its
  end, the sha256 of its last line, how many lines), until the lines in question before it are settled.
- the tail's mark (`scanned`, in memory only): how far a line with no newline yet was looked through (L-8).

The same file (J-5, M-8, N-3), looked at before each try and at each read inside it: the file is the one read
where its first bytes are the head (a head hashed while the file was shorter than HEAD_MAX is hashed again,
longer, once its bytes are found the same), it is not shorter than the cursor, and the line that ends at the
cursor is the line passed. Otherwise it is another: read again from its start, a restart counted, the head
hashed anew. The run's memory after the cursor - the reach, the count, the proof, the tail's mark - is held to
the file too: where the file is shorter than any of them, or the line that ends at the reach is not what it
was, it is given up back to the cursor (said, no restart counted), and the lines after the cursor are asked
as new ones. At a read inside a try either ends the try ("again"); the next try's look does it.

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
A try moved (N-2) where it took a line, passed a line or carried the reach further: the next try follows with
no wait, and --once goes on, until a try moves nothing; a try that moved nothing and failed waits 1, 2, 4 ...
60 s (J-10). While lines are in question, a take does not end the `refusing` the state says: it ends when no
line is in question (N-2).
Batches (J-11, N-1): a send `late` in its request or in its answer halves the next batch, down to one line; a
taken send doubles it, up to --batch.

What it is not (J-1, J-2, A-1): the watch does not know it runs. raqib/host.py, raqib/eventlog.py,
raqib/event.py and raqib/hooks/ import nothing of this module (a test reads the imports). It sends; of the
collector it reads only the answer to its own send (its status, and in the hec shape the code of its body),
follows no redirect (http.client follows none: a 3xx is a failed send) and uses no proxy of the environment
(http.client reads none; urllib is never used). The standard library only.

The secret (J-7): the token is read from --token-file at every try; never an argument, the environment, the
state, an output line or an error's text. The wire (J-8, L-4, L-5, M-4, M-5): https is verified against the
system's authorities or --ca; nothing turns verification off and SSLKEYLOGFILE is not honoured. One send is
bounded whole: connecting (name resolution and the handshake included) 10 s from its start, sending the request
30 s, the answer 30 s from the request's last byte. A send abandoned (Stop, a bound) has its sockets shut down
and is left to its own thread, which alone closes them; while four abandoned sends have not ended, no send
starts (`stuck`). Plain http only to a loopback address unless --plain. Syslog over tls is verified by the same
context; syslog over udp or tcp is plain, taken only to a loopback address unless --plain. A syslog send is
bounded as an HTTP one: connecting and the handshake 10 s, writing the batch 30 s (there is no answer).

Its own silence is said (J-9, L-3, M-4, N-8): after every batch, every failure, at least once a beat whatever it
is doing (a send, a try of many lines, a walk over lines that are not events, a walk through one long line or
tail - looking for its end, hashing it, looking back for its start) and before whatever ends the run, the state
is written whole (beside, flushed, then renamed) to ~/.raqib/forward/<name>.json; `raqib forward --status` reads
it. Stop is looked at within SLICE_S everywhere it waits, and at every line and every piece where it walks.
`behind` looks back at most BEHIND_LOOK bytes from the file's end (beyond that, the furthest line end the run
knows), so a state write never walks a long tail.

The name (J-13, L-7, M-7, N-4): at each state write the pid file is read. Gone, or holding a pid no process
has: written again, and said. Unreadable at this write: read again at the next. The pid of another process that
lives (or whose life cannot be told): the run ends with 1 and the reason said once, and nothing is written over
the state, which is the other's now.
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
SCHEMES = ("http", "https") + SYSLOG
DELIVERY = "acknowledged"                  # J-3: HTTP's word
DELIVERIES = ("acknowledged", "written", "sent")
DELIVERY_OF = {"http": DELIVERY, "https": DELIVERY, "syslog+udp": "sent", "syslog+tcp": "written",
               "syslog+tls": "written"}    # J-3: what taken means, per transport
PLAIN = ("http", "syslog+udp", "syslog+tcp")   # J-8: the wires that are not encrypted
PORT_OF = {"http": 80, "https": 443, "syslog+udp": 514, "syslog+tls": 6514}   # P-3: syslog+tcp has none
SYSLOG_KEYS = ("facility", "framing")      # P-3: written in a syslog destination's state only
FACILITY = 13                              # J-6: log audit, unless --facility N
FACILITIES = range(0, 24)                  # RFC 5424 6.2.1: the facilities are 0 to 23
FRAMINGS = ("octet", "newline")            # J-6: RFC 6587 octet counting (the default) or a newline after each
DATAGRAM_MAX = 65000                       # J-6: a message longer than this is never sent over udp
# J-6: the event's severity as RFC 5424's (2 critical, 4 warning, 5 notice, 6 informational)
SEVERITY = {"high": 2, "medium": 4, "low": 5, "hole": 4, "none": 6, "info": 6}
SEVERITY_ELSE = 4                          # a severity the event contract does not have: a warning, never calm
PRINTUS = re.compile(r"[\x21-\x7e]+\Z")    # RFC 5424 PRINTUSASCII: a HOSTNAME (255 at most), a MSGID (32)
# P-1: an RFC 5424 TIMESTAMP in UTC, of ASCII digits only (re.ASCII: a str pattern's \d is every script's digit)
STAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?Z\Z", re.ASCII)
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
HEAD_MAX = 4096                            # N-3: the file's first bytes hashed, at most this many
BEHIND_LOOK = 16 * SCAN_READ               # N-8: `behind` looks back from the file's end at most this far
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
    "write": "the system did not take the batch's bytes or datagrams, or the connection did not end in order after"
             " them (syslog: a reset, the collector's end before the forwarder's, no route)",
    "file": "the events file cannot be read, or more than 512 KiB follow its last newline",
    "stuck": "four sends abandoned have not ended (a name that never resolves, a connect that never returns): no"
             " send starts until one ends",
    "unforeseen": "an error the forwarder did not foresee ended the run",
}
# P-5: the words said of a syslog send, which has no answer (an orderly end is what is waited for)
SYSLOG_ERRORS = dict(ERRORS, late="the batch was not written, or the connection not ended in order, within the"
                                  " bound")
KEYS = ("schema", "name", "pid", "written", "destination", "shape", "delivery", "plain", "file", "cursor", "from",
        "beat", "sent", "skipped", "refused", "restarts", "last_id", "last_ok", "behind", "failing", "head",
        "in_question")
LATER = ("head", "in_question")            # N-3, N-5: a state written before them is read without them
# L-2: the status's rule, said by FORWARD.md and the guide in these words (a test holds the three together)
STATUS_RULE = ("exit 0 only where nothing is failing and no whole line has waited longer than a beat; 1 where it"
               " is failing (`refusing` too) or behind; 3 where there is no state, it cannot be read, or it was"
               " written more than two beats ago or in the future (the forwarder is silent)")


class UsageError(Exception):
    """Exit 2 with the reason (J-10: a usage error ends the forwarder)."""


class Stopped(Exception):
    """N-8: Stop seen in a walk through a line or a tail; the try ends where it is (nothing moved since the last
    pass)."""


class NameLost(Exception):
    """N-4: the pid file holds another live process's pid; the run ends with 1, the reason said once."""


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
    J-6: a syslog destination - syslog+udp://, syslog+tcp://, syslog+tls://host[:port] - has no path, query or
    fragment (its path is "" and its target None); its port is 514 (udp) or 6514 (tls) unless written. P-3:
    syslog+tcp:// needs its port written (514 over tcp is another service's: no default)."""
    if not isinstance(url, str) or CONTROL.search(url):   # urlsplit would drop a tab or a newline unsaid
        raise UsageError("--to: the URL holds a control character (a tab, a newline, ...): it is refused, never"
                         " taken without it")
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        raise UsageError("--to: not a URL with a valid port")
    scheme = parts.scheme.lower()
    if scheme not in SCHEMES:
        raise UsageError("--to: an http:// or https:// collector, or syslog over syslog+udp://, syslog+tcp:// or"
                         " syslog+tls://")
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
    if scheme in SYSLOG:
        if parts.path not in ("", "/") or "?" in url or "#" in url:
            raise UsageError("--to %s://: a syslog destination is host[:port] only (no path, query or fragment)"
                             % scheme)
        if scheme == "syslog+tcp" and port is None:
            raise UsageError("--to syslog+tcp://%s: write the collector's port (syslog+tcp://host:port): syslog over"
                             " tcp has no port of its own - 514 over tcp is another service's (rsh), so there is no"
                             " default; syslog+udp:// is 514 and syslog+tls:// 6514 unless written (P-3)" % ("[%s]" % host if ":" in host else host))
        if scheme != "syslog+tls" and not loopback(host) and not plain:
            raise UsageError("--to %s://%s: plain syslog (udp, tcp) is taken only to a loopback address (127.0.0.0/8,"
                             " ::1) unless --plain is given; syslog+tls:// is verified (J-8)" % (scheme, host))
        return {"scheme": scheme, "host": host, "port": port or PORT_OF[scheme], "path": ""}, None
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


def severity_of(obj):
    """J-6: the event's severity as RFC 5424's: high 2, medium 4, low 5, a hole 4, none and info 6 (a value the
    event contract does not have: 4)."""
    sev = obj.get("severity")
    return SEVERITY.get(sev, SEVERITY_ELSE) if isinstance(sev, str) else SEVERITY_ELSE


def _field(value, most):
    """An RFC 5424 header field: the value where it is 1 to `most` printable US-ASCII characters, else "-"."""
    return value if isinstance(value, str) and len(value) <= most and PRINTUS.match(value) else "-"


def syslog_head(obj, facility=FACILITY):
    """J-6: the RFC 5424 header and its empty STRUCTURED-DATA, up to the MSG: <PRI>1 TIMESTAMP HOSTNAME raqib -
    MSGID - (and the space before the MSG). Each field is "-" where the event's value is not what RFC 5424
    takes there (P-1: a time of other digits than ASCII, a host or kind too long or with a space); the event
    itself is in the MSG, unchanged. P-1: it never raises, whatever the line holds - every field is printable
    ASCII by its own check, and a value no check foresaw is "-" in every field the event gives."""
    try:
        obj = obj if isinstance(obj, dict) else {}
        watch = obj.get("watch") if isinstance(obj.get("watch"), dict) else {}
        stamp = obj.get("time") if isinstance(obj.get("time"), str) and STAMP.match(obj.get("time")) else "-"
        return ("<%d>1 %s %s raqib - %s - " % (facility * 8 + severity_of(obj), stamp,
                                              _field(watch.get("host"), 255),
                                              _field(obj.get("kind"), 32))).encode("ascii")
    except Exception:   # P-1: no event ends the forwarder; the MSG still carries the line as written
        return b"<%d>1 - - raqib - - - " % (facility * 8 + SEVERITY_ELSE)


def syslog_message(raw, obj, facility=FACILITY):
    """J-6: one line as one RFC 5424 message: the header, then the line as written without its line end."""
    return syslog_head(obj, facility) + raw[:_bare(raw)]


def syslog_frame(message, scheme, framing="octet"):
    """J-6, RFC 6587: over tcp and tls "<length> <message>" (octet counting), or the message and a newline
    (--framing newline); over udp the message is the datagram, unframed."""
    if scheme == "syslog+udp":
        return message
    if framing == "newline":
        return message + b"\n"
    return b"%d " % len(message) + message


def syslog_len(raw, obj, scheme, facility=FACILITY, framing="octet"):
    """M-3: the length of syslog_frame(syslog_message(...)), computed without building it."""
    n = len(syslog_head(obj, facility)) + _bare(raw)
    if scheme == "syslog+udp":
        return n
    return n + 1 if framing == "newline" else n + len(b"%d " % n)


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


def _rfind_newline(f, before, floor=0, look=None):
    """The offset just past the last newline before `before` and at or after `floor` (floor where none). N-8:
    `look` is called at each piece (Stop and the beat)."""
    pos = before
    while pos > floor:
        if look is not None:
            look()
        size = min(SCAN_READ, pos - floor)
        f.seek(pos - size)
        block = f.read(size)
        i = block.rfind(b"\n")
        if i >= 0:
            return pos - size + i + 1
        pos -= size
    return floor


def sha_range(f, start, end, look=None):
    """The sha256 of the bytes [start, end), read in pieces of SCAN_READ (M-3); None where the file is shorter.
    N-8: `look` is called at each piece."""
    h, pos = hashlib.sha256(), start
    f.seek(start)
    while pos < end:
        if look is not None:
            look()
        f.seek(pos)   # `look` may have written the state; the file's place is its own again
        block = f.read(min(SCAN_READ, end - pos))
        if not block:
            return None
        h.update(block)
        pos += len(block)
    return h.hexdigest()


def sha_before(f, offset, look=None):
    """The sha256 of the line that ends at offset (its newline included), read in pieces; None where offset is
    not a line's end."""
    if offset <= 0:
        return None
    f.seek(offset - 1)
    if f.read(1) != b"\n":
        return None
    return sha_range(f, _rfind_newline(f, offset - 1, 0, look), offset, look)


def head_of(f, length):
    """N-3: {length, sha256} of the file's first `length` bytes (at most HEAD_MAX: one read, never more)."""
    f.seek(0)
    data = f.read(min(length, HEAD_MAX))
    return {"length": len(data), "sha256": _sha(data)}


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
    """L-6, M-6, N-6: why a JSON state is not what the forwarder writes (None where it is). The run refuses to go
    on from such a state, and --status reads it as unreadable (3). It never raises, whatever the JSON holds."""
    try:
        return _state_problem(old)
    except Exception:   # N-6: a value of a type no check foresaw is no state of the forwarder's
        return "a value the forwarder never writes"


def _state_problem(old):
    if not isinstance(old, dict) or old.get("schema") != SCHEMA:
        return "not a %s state" % SCHEMA
    missing = [k for k in KEYS if k not in old and k not in LATER]
    if missing:
        return "no %s" % ", ".join(missing)
    if not isinstance(old["name"], str) or not NAME.match(old["name"]) or not _count(old["pid"]):
        return "name or pid is not one a forwarder has"
    if not _instant(old["written"]):
        return "written is not an instant"
    d = old["destination"]
    if not (isinstance(d, dict) and d.get("scheme") in SCHEMES and isinstance(d.get("host"), str) and
            d["host"] and _count(d.get("port")) and 0 < d["port"] < 65536 and isinstance(d.get("path"), str)):
        return "destination is not {scheme, host, port, path}"
    if old["shape"] not in SHAPES or old["delivery"] not in DELIVERIES or not isinstance(old["plain"], bool):
        return "shape, delivery or plain is not one the forwarder writes"
    if d["scheme"] in SYSLOG and (old["shape"] != "raqib" or old["delivery"] != DELIVERY_OF[d["scheme"]] or
                                  d["path"] != ""):
        return "a syslog destination with a shape, delivery or path the forwarder never writes for it"
    if d["scheme"] in SYSLOG:   # P-3: a state written before the two were kept has neither, and is read
        if "facility" in old and (not _count(old["facility"]) or old["facility"] not in FACILITIES):
            return "facility is not a syslog facility (0 to 23)"
        if "framing" in old and not (old["framing"] is None if d["scheme"] == "syslog+udp" else
                                     isinstance(old["framing"], str) and old["framing"] in FRAMINGS):
            return "framing is not one the forwarder writes for the destination (none over udp)"
        if ("facility" in old) != ("framing" in old):
            return "a syslog state holds both facility and framing, or neither"
    elif any(k in old for k in SYSLOG_KEYS):
        return "facility or framing in the state of an HTTP destination"
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
    if not all(isinstance(i, str) for i in refused["ids"]):
        return "refused.ids are not texts"
    if old["last_id"] is not None and not isinstance(old["last_id"], str):
        return "last_id is not a text"
    if old["last_ok"] is not None and not _instant(old["last_ok"]):
        return "last_ok is not an instant"
    failing = old["failing"]
    if failing is not None:
        if not isinstance(failing, dict) or not _instant(failing.get("since")) or not _count(failing.get("tries")):
            return "failing is not {since, tries, error, status}"
        error = failing.get("error")
        if not isinstance(error, str) or error not in ERRORS:   # N-6: a list is no word (and no key of a dict)
            return "failing.error is not one of the forwarder's words"
        st = failing.get("status")
        if st is not None and not _count(st):
            return "failing.status is not a status"
    head = old.get("head")
    if head is not None and not (isinstance(head, dict) and _count(head.get("length")) and
                                 head["length"] <= HEAD_MAX and isinstance(head.get("sha256"), str) and
                                 SHA.match(head["sha256"])):
        return "head is not {length, sha256}"
    inq = old.get("in_question", {"count": 0, "since": None})
    if not (isinstance(inq, dict) and _count(inq.get("count")) and
            (inq.get("since") is None or _instant(inq.get("since")))):
        return "in_question is not {count, since}"
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

    def stream(self):
        """Connected - each address name resolution gives, in turn - and, with a TLS context, the handshake done:
        (the socket, None), or (None, the Result of the failure). HTTP's and syslog's over tcp and tls alike."""
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
                return None, Result("failed", "connect", phase="connect")
        except OSError:
            return None, Result("failed", "connect", phase="connect")
        sock = raw
        if self.context is not None:
            self.mark("handshake")
            try:
                sock = self.hold(self.context.wrap_socket(raw, server_hostname=d["host"],
                                                          do_handshake_on_connect=False))
                sock.settimeout(self.left())
                sock.do_handshake()
            except socket.timeout:
                return None, Result("failed", "late", phase="handshake")
            except (ssl.SSLError, ssl.CertificateError, OSError, ValueError):
                return None, Result("failed", "tls", phase="handshake")
        return sock, None

    def exchange(self):
        d = self.dest
        sock, failed = self.stream()
        if failed is not None:
            return failed
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


class SyslogSend(Send):
    """J-3, J-6: one batch to a syslog collector, on a thread of its own and bounded as an HTTP send is (L-4, M-4,
    M-5: connecting and the handshake within connect_s, writing within answer_s; abandoned by shutting its
    sockets down; closed by its own thread alone). There is no answer. Over tcp and tls the batch's framed
    messages are written on one connection, and the batch is taken only when that connection ended in order
    (P-2, `written`): see end(). Over udp each message is one datagram: taken when every sendto returned with no
    error (`sent`: nothing is known)."""

    def __init__(self, fwd, messages):
        Send.__init__(self, fwd, messages, None)
        self.scheme = fwd.dest["scheme"]

    def exchange(self):
        if self.scheme == "syslog+udp":
            return self.datagrams()
        sock, failed = self.stream()
        if failed is not None:
            return failed
        self.mark("send")
        try:
            sock.settimeout(self.answer_s)
            sock.sendall(b"".join(self.body))
        except socket.timeout:
            return Result("failed", "late", phase="send")
        except ssl.SSLError:
            return Result("failed", "tls", phase="send")
        except (OSError, ValueError):
            return Result("failed", "write", phase="send")
        self.mark("answer")   # P-2: the orderly end, within the answer's bound from the batch's last byte
        return self.end(sock)

    def end(self, sock):
        """P-2: `written` is a connection ended in order. Over tcp: an end of the collector's that came before the
        forwarder's own is no end in answer to it (a collector that accepts and closes); the forwarder half-closes
        (shutdown SHUT_WR) and reads to the collector's end, what it sends thrown away. Over tls: the close is sent
        and the collector's read (unwrap: what the collector sent before it - session tickets, data - is read and
        thrown away; an alert is an error), then the same half-close and read to the end below it. Each read
        within what is left of the bound. A reset, an alert, an error, a socket error left after the end, or no
        end within the bound is a failed send: nothing passes, and the batch is sent again."""
        try:
            if self.context is not None:
                sock.settimeout(self.left())
                sock.unwrap()   # the close sent and the collector's read; the socket is plain from here
            elif self.ended_first(sock):
                return Result("failed", "write", phase="answer")
            socket.socket.shutdown(sock, socket.SHUT_WR)
            while True:
                sock.settimeout(self.left())
                if not socket.socket.recv(sock, ANSWER_READ):
                    break
            if sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR):
                return Result("failed", "write", phase="answer")
        except socket.timeout:
            return Result("failed", "late", phase="answer")
        except ssl.SSLError:
            return Result("failed", "tls", phase="answer")
        except (OSError, ValueError):
            return Result("failed", "write", phase="answer")
        return Result("taken")

    @staticmethod
    def ended_first(sock):
        """P-2: whether the collector's end is already there before the forwarder's own (a look, no wait: a peek
        that takes nothing)."""
        sock.settimeout(0.0)
        try:
            return socket.socket.recv(sock, 1, socket.MSG_PEEK) == b""
        except (BlockingIOError, InterruptedError):
            return False

    def datagrams(self):
        d = self.dest
        try:
            family, kind, proto, _, addr = self.lookup(d["host"], d["port"], 0, socket.SOCK_DGRAM)[0]
            sock = self.hold(socket.socket(family, kind, proto))
        except (OSError, IndexError, ValueError):
            return Result("failed", "connect", phase="connect")
        self.mark("send")
        try:
            sock.settimeout(self.answer_s)
            for message in self.body:
                sock.sendto(message, addr)
        except socket.timeout:
            return Result("failed", "late", phase="send")
        except (OSError, ValueError):
            return Result("failed", "write", phase="send")
        return Result("taken")


class Forwarder:
    """One name, one file, one destination (J-13). Every clock, wait and timeout can be given (tests): `clock`
    is the wall's and gives only the state's times; `mono` does not step and gives every wait and the beat;
    `nap(event, seconds)` is how the forwarder waits for a send in slices; `lookup` is getaddrinfo."""

    def __init__(self, name, path, url, shape="raqib", token_file=None, ca=None, plain=False, beat=None,
                 start="start", batch=MAX_LINES, home=None, out=None, clock=time.time, mono=time.monotonic,
                 wait=None, connect_s=CONNECT_S, answer_s=ANSWER_S, poll_s=POLL_S, alive=ui.pid_alive,
                 platform=None, pid=None, opener=None, nap=None, lookup=None, facility=None, framing=None):
        self.name = check_name(name)
        if shape not in SHAPES:
            raise UsageError("--shape: raqib or hec, not %r" % (shape,))
        self.dest, self.target = destination(url, plain)
        self.shape, self.token_file, self.platform = shape, token_file, platform or sys.platform
        scheme = self.dest["scheme"]
        self.syslog, self.delivery = scheme in SYSLOG, DELIVERY_OF[scheme]
        self.facility, self.framing = self.syslog_options(scheme, shape, token_file, facility, framing)
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
        self.plain = scheme in PLAIN   # K-2 (Q10): said for every plain wire, loopback too
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
        if scheme in ("https", "syslog+tls"):
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
        self.reach_sha, self.since, self.known_end, self.head = None, None, 0, None   # N-3, N-5, N-8
        self.takes, self.moved, self.pid_doubt = 0, False, False   # N-2; N-4: the pid file unreadable, said
        self.adrift = []   # M-5: the sends abandoned that have not ended
        self.carried, self.lost = False, None   # M-6: a failing carried from the state; M-7: the name lost
        self.start_from = {"start": start, "offset": 0}
        self.written_at, self.locked, self.state_error, self.scanned = None, False, None, None

    @staticmethod
    def syslog_options(scheme, shape, token_file, facility, framing):
        """J-6, J-7: what a syslog destination takes - the raqib shape, no token, --facility 0 to 23 (13 unless
        given), --framing octet or newline over tcp and tls - and what an HTTP one does not (--facility,
        --framing): each a usage error that says so. The token file is never read here."""
        if scheme not in SYSLOG:
            if facility is not None or framing is not None:
                raise UsageError("--facility and --framing are syslog's: an http:// or https:// destination takes"
                                 " neither")
            return None, None
        if token_file:
            raise UsageError("--token-file: syslog carries no token (no Authorization header, J-7): a syslog"
                             " destination takes no token file")
        if shape != "raqib":
            raise UsageError("--shape %s is HTTP's: over syslog the message is the line as written (the raqib"
                             " shape)" % shape)
        if facility is None:
            facility = FACILITY
        else:
            text = "" if isinstance(facility, bool) else str(facility)
            facility = int(text) if text.isascii() and text.isdigit() and len(text) <= 2 else -1
            if facility not in FACILITIES:
                raise UsageError("--facility: a syslog facility, a whole number from 0 to 23 (13, log audit, unless"
                                 " given)")
        if framing is not None and scheme == "syslog+udp":
            raise UsageError("--framing: a datagram is one message, never framed: --framing is syslog over tcp's"
                             " and tls's")
        if framing is None:
            framing = "octet"
        elif framing not in FRAMINGS:
            raise UsageError("--framing: octet (RFC 6587 octet counting, the default) or newline")
        return facility, framing

    # --- the state (J-9) -------------------------------------------------------------------------------------
    def behind(self):
        """J-9: bytes of whole lines after the cursor not yet passed. N-8: it looks back from the file's end at
        most BEHIND_LOOK bytes (and never below what the run already knows: the reach, the furthest line end it
        read, the tail's mark), so a state write never walks a long line or tail; where no newline is in that
        window, it reads once forward from what the run knows (at most MAX_BYTES + 1), and the last newline it
        saw - or what the run knows - is the last line end: a lower bound, never more than what waits."""
        try:
            with self.opener(self.path) as f:
                size = os.fstat(f.fileno()).st_size
                if size <= self.offset:
                    return 0
                known = min(size, max(self.offset, self.reach, self.known_end,
                                      self.scanned[0] if self.scanned else 0))
                floor = known
                if self.scanned and self.scanned[0] == known:   # no newline there up to the mark
                    floor = min(size, max(floor, self.scanned[1]))
                pos, last = size, None
                low = max(floor, size - BEHIND_LOOK)
                while pos > low and last is None:
                    n = min(SCAN_READ, pos - low)
                    f.seek(pos - n)
                    i = f.read(n).rfind(b"\n")
                    if i >= 0:
                        last = pos - n + i + 1
                    pos -= n
                if last is None and low > floor:   # a long tail: one read forward from what the run knows
                    f.seek(known)
                    i = f.read(min(MAX_BYTES + 1, low - known)).rfind(b"\n")
                    last = known + i + 1 if i >= 0 else None
                return max(0, (known if last is None else last) - self.offset)
        except OSError:
            return 0

    def state(self):
        s = {"schema": SCHEMA, "name": self.name, "pid": self.pid, "written": iso(self.clock()),
                "destination": dict(self.dest), "shape": self.shape, "delivery": self.delivery, "plain": self.plain,
                "file": self.path, "cursor": {"offset": self.offset, "line_sha256": self.line_sha},
                "from": dict(self.start_from), "beat": self.beat, "sent": self.sent, "skipped": self.skipped,
                "refused": {"count": self.refused, "ids": list(self.refused_ids)}, "restarts": self.restarts,
                "last_id": self.last_id, "last_ok": self.last_ok, "behind": self.behind(),
                "failing": dict(self.failing) if self.failing else None,
                "head": dict(self.head) if self.head else None,
                "in_question": {"count": self.question, "since": self.since if self.question else None}}
        if self.syslog:   # P-3: the facility and the framing are the destination's, kept as the shape is
            s.update(facility=self.facility, framing=self.state_framing())
        return s

    def state_framing(self):
        """P-3: the framing the state says: octet or newline over tcp and tls; none (null) over udp."""
        return None if self.dest["scheme"] == "syslog+udp" else self.framing

    def own_name(self):
        """M-7, N-4: the pid file, read at each state write. Gone, or holding a pid no process has: written again
        and said. Unreadable now: read again at the next write. Another live pid (or one whose life cannot be
        told): NameLost - nothing is written over the state, which is the other forwarder's now."""
        other = self.holder()
        if other == self.pid:
            self.pid_doubt = False
            return
        if other is False:
            if not self.pid_doubt:
                self.say("the pid file %s cannot be read at this state write: it is read again at the next"
                         % self.lock_file)
            self.pid_doubt = True
            return
        self.pid_doubt = False
        if other is not None and self.alive(other) is not False:
            self.lost = ("the pid file %s holds pid %d, a process that lives, not this forwarder's pid %d: another"
                         " forwarder took the name %s, so this one ends (exit 1) and leaves the name's state to it"
                         % (self.lock_file, other, self.pid, self.name))
            self.say(self.lost)
            raise NameLost(self.lost)
        self.say("the pid file %s %s: it is written again with pid %d" % (
            self.lock_file, "was gone" if other is None else "held pid %d, a process that is gone" % other, self.pid))
        try:
            if other is not None:
                os.remove(self.lock_file)
            temp = self._pid_temp()
            try:
                self.publish(temp)
            except FileExistsError:   # another made it between: it is read at the next write
                pass
            finally:
                try:
                    os.remove(temp)   # off Windows the link's other name; on Windows already renamed
                except OSError:
                    pass
        except OSError as exc:
            self.say("the pid file %s cannot be written again now (%s): tried at the next write"
                     % (self.lock_file, exc.strerror or type(exc).__name__))

    def write_state(self):
        """Whole: written beside, flushed to the disk, then renamed over (J-9, L-6). A state that cannot be
        written is said once. M-7, N-4: the pid file is read first (own_name)."""
        if self.lost:
            return
        if self.locked:
            self.own_name()
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

    def look(self):
        """N-8: at each piece of a walk through one line or a tail (looking for its end, hashing it, looking back
        for its start): Stop ends the try (Stopped), and the state is written once a beat."""
        if self.stopped():
            raise Stopped()
        self.tick()

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

    def _pid_temp(self):
        """The pid file's content, whole, beside it (published by a link or a rename)."""
        os.makedirs(forward_dir(self.home), exist_ok=True)
        temp = "%s.%d.%s.tmp" % (self.lock_file, self.pid, binascii.hexlify(os.urandom(4)).decode("ascii"))
        fd = os.open(temp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("%d\n" % self.pid)
            f.flush()
        return temp

    def _lock(self):
        temp = self._pid_temp()
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
            except Exception:   # N-6: not JSON, not ASCII, nested past what the reader takes (RecursionError)
                old = None
            why = state_problem(old) if old is not None else "not JSON that can be read"
            if why:
                raise UsageError("the state %s is damaged (%s): it is never taken for a first run; move it away to"
                                 " start this name again" % (self.state_file, why))
            if old.get("file") != self.path or old.get("destination") != self.dest or old.get("shape") != self.shape:
                raise UsageError("the name %s forwards %s to %s (shape %s): another file, destination or shape is"
                                 " another name (J-13)" % (self.name, old.get("file"), where(old["destination"]),
                                                           old.get("shape")))
            kept = ""
            if self.syslog and "facility" in old:   # P-3: another facility or framing is another name
                if old["facility"] != self.facility or old["framing"] != self.state_framing():
                    raise UsageError("the name %s forwards with facility %d, framing %s: another facility or"
                                     " framing is another name, as another shape is (P-3)" % (
                                         self.name, old["facility"], old["framing"] or "none"))
            elif self.syslog:   # P-3: a state written before the two were kept: this start's are kept from now
                kept = ("; the state held no facility or framing (written before they were kept): this start's,"
                        " facility %d, framing %s, are kept from now" % (self.facility,
                                                                        self.state_framing() or "none"))
            cur = old["cursor"]
            self.offset, self.line_sha = cur["offset"], cur.get("line_sha256")
            self.reach, self.reach_sha, self.known_end = self.offset, self.line_sha, self.offset
            self.head = dict(old["head"]) if old.get("head") else None   # N-3: an older state has none
            self.sent, self.skipped, self.restarts = old["sent"], old["skipped"], old["restarts"]
            self.refused, self.refused_ids = old["refused"]["count"], list(old["refused"]["ids"])[-IDS_KEPT:]
            self.last_id, self.last_ok = old.get("last_id"), old.get("last_ok")
            self.start_from = dict(old["from"])
            if old["failing"]:
                self.failing, self.carried = dict(old["failing"]), True
            return "resumed at offset %d%s%s" % (self.offset, "; failing %s, as the state said, until a try has an"
                                                 " answer" % self.failing["error"] if self.carried else "", kept)
        if self.start_from["start"] == "end":
            try:
                with self.opener(self.path) as f:
                    size = os.fstat(f.fileno()).st_size
                    self.offset = _rfind_newline(f, size)
                    self.line_sha = sha_before(f, self.offset) if self.offset else None
            except OSError:
                self.offset = 0
            self.reach, self.reach_sha, self.known_end = self.offset, self.line_sha, self.offset
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
        return self.carry(lambda: Send(self, body, headers))

    def carry(self, make):
        """One send of either transport (Send, SyslogSend: `make` builds it), bounded whole and waited for in
        slices: Stop abandons it within SLICE_S, and the state is written once a beat while it lasts (M-4). While
        STUCK_MAX abandoned sends have not ended, none starts (M-5)."""
        if self.stopped():   # Stop came before the send: nothing is sent
            return Result("stopped")
        self.adrift = [job for job in self.adrift if not job.ended()]
        if len(self.adrift) >= STUCK_MAX:
            return Result("failed", "stuck")
        job = make()
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
        if self.syslog:   # J-6: one message per line; J-7: no token
            r = self.carry(lambda: SyslogSend(self, [self.wire(ln) for ln in lines]))
        else:
            try:
                token = self.token()
            except (OSError, UsageError):   # L-3: while it runs, a failed try; read again at the next
                return Result("failed", "token-file")
            r = self.post(b"".join(piece(self.shape, ln.raw, ln.obj) for ln in lines), token)
        if r.kind == "taken" and self.size < self.batch:   # N-1: a taken send doubles it, up to --batch
            self.size = min(self.batch, self.size * 2)
            self.say("a send was taken: the next batch is %d line(s)" % self.size)
        elif r.kind == "failed" and r.error == "late" and r.phase in ("send", "answer"):
            size = max(1, len(lines) // 2)   # M-4, N-1: late in its request or its answer, halved down to one
            if size < self.size:
                self.size = size
                self.say("a send of %d line(s) was late (%s): the next batch is %d" % (
                    len(lines), ("its bytes not written" if r.phase == "send" else "no orderly end of the connection")
                    if self.syslog else "its request not sent" if r.phase == "send" else "no whole answer",
                    self.size))
        return r

    def wire(self, ln):
        """J-6: what one line puts on the wire: HTTP's piece of a body, or syslog's framed message (a datagram)."""
        if self.syslog:
            return syslog_frame(syslog_message(ln.raw, ln.obj, self.facility), self.dest["scheme"], self.framing)
        return piece(self.shape, ln.raw, ln.obj)

    def wire_len(self, ln):
        """M-3: the length of self.wire(ln), computed without building it."""
        if self.syslog:
            return syslog_len(ln.raw, ln.obj, self.dest["scheme"], self.facility, self.framing)
        return piece_len(self.shape, ln.raw, ln.obj)

    def too_long(self, ln):
        """K-2, M-3, J-6: longer than one request may be (512 KiB), or over udp than one datagram (65000)."""
        n = self.wire_len(ln)
        return n > MAX_BYTES or self.dest["scheme"] == "syslog+udp" and n > DATAGRAM_MAX

    # --- the cursor (J-3, J-4, J-5, L-1, M-1, M-2, M-3) ------------------------------------------------------
    def unsent(self, ln):
        """J-5, K-2, M-3, J-6: a line that is not sent - not an event, or longer than one request (or one
        datagram) may be."""
        return ln.long or ln.obj is None or self.too_long(ln)

    def pass_line(self, ln, sent=0):
        """The cursor passes the line (N-5: `sent` counts the taken lines it passes, here and nowhere else)."""
        self.offset, self.line_sha = ln.end, ln.sha()
        self.sent += sent
        if self.reach <= self.offset:
            self.reach, self.reach_sha = self.offset, self.line_sha

    def reach_to(self, ln):
        """The reach is carried past the line (N-3: with the sha256 of the line that ends at it)."""
        self.reach, self.reach_sha = ln.end, ln.sha()

    def question_up(self, status):
        """A line refused alone is in question (N-5: since when the first now in question was)."""
        if not self.question:
            self.since = iso(self.clock())
        self.question += 1
        self.refusal = status

    def question_down(self):
        self.question = max(0, self.question - 1)
        if not self.question:
            self.none_in_question()

    def none_in_question(self):
        """N-2: `refusing` is said while lines are in question, and ends when none is."""
        self.question, self.since = 0, None
        if self.failing and self.failing.get("error") == "refusing":
            self.say("no line is in question now: refusing is over")
            self.failing = None

    def pass_unsent(self, ln):
        if ln.obj is None and not ln.long:
            self.skipped += 1
        elif not ln.long and self.dest["scheme"] == "syslog+udp" and self.wire_len(ln) <= MAX_BYTES:
            self.count_refused(ln, "locally: longer than one datagram may be (over %d bytes, J-6)" % DATAGRAM_MAX)
        else:
            self.count_refused(ln, "locally: longer than one request may be (J-11)")
        self.pass_line(ln)

    def taken(self, lines):
        """J-3: the collector took them (`sent` counts them when the cursor passes them, N-5). N-2: while lines
        are in question the failing is `refusing` still, and ends when none is."""
        self.takes += 1
        self.last_id, self.last_ok = lines[-1].id(), iso(self.clock())
        if self.question:
            if self.failing and self.failing.get("error") != "refusing":
                self.failing.update(error="refusing", status=self.refusal)
            return
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
            more = "nothing moves"
            if r.error == "refusing":
                more = ("the cursor stays before them; %d line(s) in question from offset %d (asked alone as far as"
                        " offset %d) wait for a later line taken" % (self.question, self.offset, self.reach))
            self.say("failing: %s (%s%s); %d tr%s; %s" % (
                r.error, (SYSLOG_ERRORS if self.syslog else ERRORS).get(r.error, r.error), "" if r.status is None else ", status %d" % r.status,
                self.failing["tries"], "y" if self.failing["tries"] == 1 else "ies", more))

    def failed(self, r):
        self.fail(r)
        self.write_state()
        return "failed"

    def same_file(self, f):
        """J-5, N-3: the file is the one read where its first bytes are the head, it is not shorter than the
        cursor, and the line that ends at the cursor is the line that was passed - the cursor at 0 included.
        The head covers the first HEAD_MAX bytes at most, and of them only what the cursor has passed once it
        has passed any (at 0: what the file holds): a change after the cursor is not the file's identity but
        the run's memory (memory_problem). A head hashed shorter is hashed again, longer, as the cursor passes
        more (at 0: as the file grows), once its bytes are found the same; a head that still reaches past the
        cursor (hashed at 0, the cursor moved since) is no proof either way: the cursor's line decides, and the
        head is hashed again. A head never hashed (a first run, an older state) is hashed at the first look."""
        size = os.fstat(f.fileno()).st_size
        want = min(HEAD_MAX, self.offset if self.offset else size)
        if self.head is not None and self.head["length"]:
            n = self.head["length"]
            short = size < n
            if not short:
                f.seek(0)
                changed = _sha(f.read(n)) != self.head["sha256"]
            if (short or changed) and (self.offset == 0 or n <= self.offset):
                return ("shorter than its first %d bytes hashed" if short else "its first %d bytes changed") % n
        if size < self.offset:
            return "shorter than the cursor"
        if self.offset and self.line_sha is not None:
            if sha_before(f, self.offset, self.look) != self.line_sha:
                return "the last line passed changed"
        if self.head is None or self.head["length"] != want:
            self.head = head_of(f, want)
        return None

    def memory_problem(self, f):
        """N-3: why what the run holds after the cursor - the reach, the proof, the tail's mark - is not held by
        the file (None where it is): the file is shorter than it, or the line that ends at the reach is not what
        it was."""
        size = os.fstat(f.fileno()).st_size
        if self.reach > self.offset:
            if size < self.reach:
                return "shorter than this run asked (offset %d)" % self.reach
            if sha_before(f, self.reach, self.look) != self.reach_sha:
                return "the line at offset %d, as far as this run asked, changed" % self.reach
        if self.proof is not None and size < self.proof[1]:
            return "shorter than the line taken after those in question"
        if self.scanned and size < self.scanned[1]:
            return "shorter than its tail was looked through (offset %d)" % self.scanned[1]
        return None

    def give_up(self, why):
        """N-3: what the run held after the cursor is given up, back to the cursor; the lines after it are asked
        again as new ones. No restart: the cursor's own line is the one passed."""
        held = (self.question, self.reach)
        self.reach, self.reach_sha, self.proof, self.scanned, self.known_end = (
            self.offset, self.line_sha, None, None, self.offset)
        self.none_in_question()
        self.say("the file after the cursor is not what this run read (%s): what it asked after offset %d (%d"
                 " line(s) in question, as far as offset %d) is asked again from the cursor" % (
                     why, self.offset, held[0], held[1]))

    def scan_newline(self, f, offset, start):
        """L-8: the end of the first line at offset, looked for from `start` in pieces never kept; None where no
        newline is there yet (what was looked through is remembered for the next look). N-8: Stop and the beat
        at each piece."""
        if self.scanned and self.scanned[0] == offset:
            start = max(start, self.scanned[1])
        pos = start
        while True:
            self.look()
            f.seek(pos)
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
            self.known_end = max(self.known_end, end)
            return [Line(offset, end, None, None, sha_range(f, offset, end, self.look))]
        out, at = [], offset
        for body in data[:cut + 1].split(b"\n")[:-1]:   # only a newline ends a line
            raw = body + b"\n"
            out.append(Line(at, at + len(raw), raw, classify(raw)))
            at += len(raw)
        self.known_end = max(self.known_end, at)
        return out

    def read_at(self, at):
        """M-8, N-3: the whole lines from `at` in the file the try began with - the same checks as at each pass:
        where the file is another, or no longer holds what the run read after the cursor, OTHER (the try ends;
        the next pass counts the restart or gives that up). None where it cannot be read."""
        try:
            with self.opener(self.path) as f:
                if self.same_file(f) or self.memory_problem(f):
                    return OTHER
                return self.read_lines(f, at)
        except OSError:
            return None

    def batch_of(self, lines):
        batch, size = [], 0
        for ln in lines:
            if self.unsent(ln) or len(batch) >= self.size:
                break
            size += self.wire_len(ln)
            if size > MAX_BYTES:
                break
            batch.append(ln)
        return batch

    def check_file(self):
        """The same file as the cursor's, or another (J-5: read again from its start, a restart counted)."""
        try:
            with self.opener(self.path) as f:
                other = self.same_file(f)
                lost = None if other else self.memory_problem(f)
        except OSError:
            return self.failed(Result("failed", "file"))
        if other:
            self.restarts += 1
            self.offset, self.line_sha, self.scanned, self.head = 0, None, None, None
            self.reach, self.reach_sha, self.proof, self.known_end = 0, None, None, 0
            self.none_in_question()
            self.say("the file is another (%s): read again from its start, restart %d (the collector gets lines"
                     " twice: watch.host and id tell)" % (other, self.restarts))
        elif lost:
            self.give_up(lost)
        return None

    def step(self):
        """One try: "idle" (nothing whole to send), "moved", "failed", "stopped", or "again" (the file was replaced
        during the try: the next pass counts the restart). N-2: `moved` says whether the try took a line, passed
        a line or carried the reach further, whatever its word."""
        self.moved = False
        try:
            r = self.attempt()
        except Stopped:   # N-8: Stop in a walk through one line or a tail
            r = "stopped"
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
        mark = (self.offset, self.reach, self.takes)
        try:
            return self._attempt()
        finally:
            self.moved = (self.offset, self.reach, self.takes) != mark

    def _attempt(self):
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
            self.taken([ln])   # an earlier line's take: never the proof of a line after it (N-7)
            self.pass_line(ln, sent=1)
            self.question_down()
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
                    self.reach_to(ln)   # behind a line in question: passed when the cursor gets there
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
                self.question_up(r.status)
                self.reach_to(batch[0])
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
            self.pass_line(lines[-1], sent=len(lines))
            return None
        self.proof = (lines[0].start, lines[-1].end, lines[-1].sha(), len(lines))
        self.reach_to(lines[-1])
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
            self.question_up(r.status)
            self.reach_to(ln)
        return "on" if self.question else "plain"

    def settle(self):
        """M-2: a send was taken after the lines in question: each line in question before it is asked alone once
        more. Refused again, it is counted and passed; taken now, it is taken. The lines not sent are passed on
        the way, and the cursor then passes the proof. "settled", or the word that ends the try ("moved" at
        ALONE_MAX sends alone: the next try goes on settling)."""
        start, end, sha, count = self.proof
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
                self.pass_line(ln, sent=1 if r.kind == "taken" else 0)
                self.question_down()
                self.write_state()
        self.offset, self.line_sha, self.sent = end, sha, self.sent + count   # N-5: the proof counted as passed
        if end >= self.reach:
            self.reach, self.reach_sha = end, sha
        self.proof = None
        self.none_in_question()
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
            if self.moved:   # N-2: a try that moved is followed by the next with no wait; --once goes on
                tries = 0
                self.tick()
                continue
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
        (L-3; M-7, N-4: unless another live forwarder took the name: then 1, the reason said once); an unforeseen
        error is said by the word `unforeseen`, never by its text."""
        self.lock()
        try:
            how = self.resume()
        except BaseException:
            self.unlock()
            raise
        ended = None
        try:
            self.say("%s -> %s (shape %s, delivery %s%s%s); %s; state %s" % (
                self.path, where(self.dest), self.shape, self.delivery,
                ", facility %d, framing %s" % (self.facility, self.framing if self.dest["scheme"] != "syslog+udp"
                                               else "none: one datagram a message") if self.syslog else "",
                ", plain: not encrypted" if self.plain else "", how, self.state_file))
            self.write_state()
            self.loop(once)
        except UsageError:
            raise
        except NameLost:   # N-4: said once by own_name; nothing is written over the other's state
            ended = "lost"
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
        if ended and ended != "lost":
            self.say("ended by an error it did not foresee (%s): the state is written, failing: unforeseen" % ended)
        self.say("%s: sent %d, skipped %d, refused %d, restarts %d, behind %d byte(s)%s" % (
            "stopped" if self.stopped() else "ended" if ended else "done", self.sent, self.skipped, self.refused,
            self.restarts, behind, "" if self.failing is None else "; failing: %s" % self.failing["error"]))
        return 0 if ok else 1


# --- --status (J-9, L-2, M-6) --------------------------------------------------------------------------------
def judge(state, now):
    """(exit, word, lines) of one state, by STATUS_RULE. M-6, N-6: a state that is not what the forwarder writes
    is unreadable (3), never read as calm, and never a traceback. N-5: a line in question longer than a beat is a
    whole line that waited (1), settling included."""
    try:
        why = state_problem(state)
        if why:
            return 3, "UNREADABLE", ["not what a forwarder writes: %s" % why]
        written, beat = seconds_of(state["written"]), float(state["beat"])
        dest, cursor, refused, failing = state["destination"], state["cursor"], state["refused"], state["failing"]
        inq = state.get("in_question") or {"count": 0, "since": None}
        lines = ["to %s (shape %s, delivery %s%s%s)" % (
                     where(dest), state["shape"], state["delivery"],
                     "" if "facility" not in state else ", facility %d, framing %s" % (
                         state["facility"], state.get("framing") or "none: one datagram a message"),
                     ", plain: not encrypted" if state["plain"] else ""),
                 "file %s, cursor %d (from the %s, offset %d)" % (state["file"], cursor["offset"],
                                                                   state["from"]["start"], state["from"]["offset"]),
                 "sent %d, skipped %d, refused %d%s, restarts %d" % (
                     state["sent"], state["skipped"], refused["count"],
                     " (latest: %s)" % ", ".join(str(i) for i in refused["ids"][-3:]) if refused["ids"] else "",
                     state["restarts"]),
                 "last taken: %s at %s; behind %d byte(s); in question %d%s" % (
                     state["last_id"] or "none", state["last_ok"] or "never", state["behind"], inq["count"],
                     " since %s" % inq["since"] if inq["count"] and inq.get("since") else ""),
                 "written %s by pid %d (a beat of %g s)" % (state["written"], state["pid"], beat)]
        last_ok = seconds_of(state["last_ok"]) if state["last_ok"] else None
        asked = seconds_of(inq["since"]) if inq["count"] and inq.get("since") else None
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
            failing["since"], failing["error"], (SYSLOG_ERRORS if dest["scheme"] in SYSLOG else
                                                 ERRORS)[failing["error"]], failing["tries"],
            "y" if failing["tries"] == 1 else "ies",
            "" if failing.get("status") is None else ", status %d" % failing["status"])]
    if inq["count"] and (asked is None or written - asked > beat):
        return 1, "BEHIND", lines + ["%d line(s) in question since %s, longer than a beat: they wait (settling"
                                     " included)" % (inq["count"], inq.get("since") or "a time not said")]
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
        except Exception:   # N-6: OSError, not JSON, not ASCII, nested past what the reader takes, anything else
            code, word, lines = 3, "UNREADABLE", ["the state %s cannot be read" % state_path(n, home)]
        else:
            code, word, lines = judge(state, now)
            try:
                refused = "%d" % state["refused"]["count"] if code != 3 or word != "UNREADABLE" else "unknown"
            except Exception:
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
                    plain=args.plain, beat=args.beat, start=args.start, batch=args.batch, out=out,
                    facility=getattr(args, "facility", None), framing=getattr(args, "framing", None))
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
