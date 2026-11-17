"""raqib link: a forwarder's state read and judged, with no network (ADR-0011 Amendment R-1, R-4; J-9, L-2).

What reads and judges a state - the schema's name and keys, the state's problems, the judgement of STATUS_RULE,
where the states are - is here, once: `raqib forward --status` (raqib/forward.py, which takes every one of these
names from this module) and the window read the state by it. This module imports nothing of the network and
nothing of the forwarder: of raqib only raqib.host, for the folder (its host_dir). It never writes a state; it
reads `~/.raqib/forward/<name>.json` (docs/specs/FORWARD.md "The state").

`read` reads every state, bounded (R-4): at most LINKS_MAX names, in order of name (the rest counted, never
read); each state at most STATE_MAX bytes, never read whole (more is UNREADABLE, said); only a regular file (a
directory, a pipe, a device is UNREADABLE: never waited on). A state that cannot be listed or read is a row or
no row, never an exception: one forwarder's failure is its own UNREADABLE (or SILENT), never the reader's.
"""
from __future__ import annotations

import calendar
import datetime
import heapq
import json
import math
import os
import re
import stat
import time

from raqib import host as host_watch

SCHEMA = "raqib-forward/1"
DIR_NAME = "forward"
NAME = re.compile(r"[a-z0-9-]{1,32}\Z")   # J-13
SHAPES = ("raqib", "hec")                  # J-6
SYSLOG = ("syslog+udp", "syslog+tcp", "syslog+tls")
JOURNAL = "journal"                        # W-1, W-2: the system's journal, by its native protocol (Linux)
EVENTLOG = "eventlog"                      # Y-1: the Windows event log, the Application log (Windows)
SCHEMES = ("http", "https") + SYSLOG + (JOURNAL, EVENTLOG)
DELIVERY = "acknowledged"                  # J-3: HTTP's word
DELIVERIES = ("acknowledged", "written", "sent")
DELIVERY_OF = {"http": DELIVERY, "https": DELIVERY, "syslog+udp": "sent", "syslog+tcp": "written",
               "syslog+tls": "written", JOURNAL: "sent", EVENTLOG: "written"}   # J-3, W-4, Y-4: what taken means
SYSLOG_KEYS = ("facility", "framing")      # P-3: written in a syslog destination's state only
FACILITIES = range(0, 24)                  # RFC 5424 6.2.1: the facilities are 0 to 23
FRAMINGS = ("octet", "newline")            # J-6: RFC 6587 octet counting (the default) or a newline after each
HEAD_MAX = 4096                            # N-3: the file's first bytes hashed, at most this many
SHA = re.compile(r"[0-9a-f]{64}\Z")
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
                                  " bound",
                     tls="the TLS handshake or the certificate failed, or the collector ended the session with an"
                         " alert or with no close")
KEYS = ("schema", "name", "pid", "written", "destination", "shape", "delivery", "plain", "file", "cursor", "from",
        "beat", "sent", "skipped", "refused", "restarts", "last_id", "last_ok", "behind", "failing", "head",
        "in_question")
LATER = ("head", "in_question")            # N-3, N-5: a state written before them is read without them
# L-2: the status's rule, said by FORWARD.md and the guide in these words (a test holds the three together)
STATUS_RULE = ("exit 0 only where nothing is failing and no whole line has waited longer than a beat; 1 where it"
               " is failing (`refusing` too) or behind; 3 where there is no state, it cannot be read, or it was"
               " written more than two beats ago or in the future (the forwarder is silent)")



def forward_dir(home=None):
    """~/.raqib/forward, the home resolved as the watch resolves its own (raqib/host.py host_dir)."""
    return os.path.join(os.path.dirname(host_watch.host_dir(home)), DIR_NAME)


def state_path(name, home=None):
    return os.path.join(forward_dir(home), name + ".json")


def seconds_of(text):
    """An instant of raqib-event/1 (or of the state) as seconds since the epoch."""
    d = datetime.datetime.strptime(text[:-1], "%Y-%m-%dT%H:%M:%S.%f")
    return calendar.timegm(d.timetuple()) + d.microsecond / 1e6


def where(dest):
    if dest.get("scheme") == JOURNAL:   # W-6: the journal has no host, port or path
        return "the journal"
    if dest.get("scheme") == EVENTLOG:   # Y-1: the Windows event log has no host, port or path
        return "the Windows event log"
    host = "[%s]" % dest["host"] if ":" in dest["host"] else dest["host"]
    return "%s://%s:%d%s" % (dest["scheme"], host, dest["port"], dest["path"])


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
    if isinstance(d, dict) and d.get("scheme") == JOURNAL:   # W-6: the scheme, and nothing of a host or a port
        if d != {"scheme": JOURNAL}:
            return "a journal destination holds its scheme only (no host, port or path)"
    elif isinstance(d, dict) and d.get("scheme") == EVENTLOG:   # Y-1: the scheme, and nothing of a host or a port
        if d != {"scheme": EVENTLOG}:
            return "an eventlog destination holds its scheme only (no host, port or path)"
    elif not (isinstance(d, dict) and d.get("scheme") in SCHEMES and isinstance(d.get("host"), str) and
              d["host"] and _count(d.get("port")) and 0 < d["port"] < 65536 and isinstance(d.get("path"), str)):
        return "destination is not {scheme, host, port, path}"
    if old["shape"] not in SHAPES or old["delivery"] not in DELIVERIES or not isinstance(old["plain"], bool):
        return "shape, delivery or plain is not one the forwarder writes"
    if d["scheme"] in SYSLOG and (old["shape"] != "raqib" or old["delivery"] != DELIVERY_OF[d["scheme"]] or
                                  d["path"] != ""):
        return "a syslog destination with a shape, delivery or path the forwarder never writes for it"
    if d["scheme"] == JOURNAL and (old["shape"] != "raqib" or old["delivery"] != DELIVERY_OF[JOURNAL] or
                                   old["plain"]):
        return "a journal destination with a shape, delivery or plain the forwarder never writes for it"
    if d["scheme"] == EVENTLOG and (old["shape"] != "raqib" or old["delivery"] != DELIVERY_OF[EVENTLOG] or
                                    old["plain"]):
        return "an eventlog destination with a shape, delivery or plain the forwarder never writes for it"
    if d["scheme"] in SYSLOG:   # P-3: a state written before the two were kept has neither, and is read
        if "facility" in old and (not _count(old["facility"]) or old["facility"] not in FACILITIES):
            return "facility is not a syslog facility (0 to 23)"
        if "framing" in old and not (old["framing"] is None if d["scheme"] == "syslog+udp" else
                                     isinstance(old["framing"], str) and old["framing"] in FRAMINGS):
            return "framing is not one the forwarder writes for the destination (none over udp)"
        if ("facility" in old) != ("framing" in old):
            return "a syslog state holds both facility and framing, or neither"
    elif d["scheme"] == JOURNAL:   # W-2: the facility is kept, as syslog's is; a framing is never the journal's
        if "facility" not in old or not _count(old["facility"]) or old["facility"] not in FACILITIES:
            return "a journal state holds no facility, or one that is not a syslog facility (0 to 23)"
        if "framing" in old:
            return "framing in the state of the journal (it has none)"
    elif d["scheme"] == EVENTLOG:   # Y-5: the Windows event log has no facility and no framing
        if any(k in old for k in SYSLOG_KEYS):
            return "facility or framing in the state of the Windows event log (it has neither)"
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


# X-3: a journal has no collector, no connection and no answer: its failing words say what it is
JOURNAL_ERRORS = dict(ERRORS, connect="the journal's socket is not there, or takes no entry",
                      late="the entries were not handed to the journal within the bound",
                      write="an entry could not be handed to the journal")


# Y-5: the Windows event log has no collector, no connection and no answer: its failing words say what it is
EVENTLOG_ERRORS = dict(ERRORS, connect="the source Raqib of the Windows event log cannot be opened",
                       late="the events were not taken by the Windows event log within the bound",
                       write="an event was refused by the Windows event log")


def errors_of(scheme):
    """The words of failing.error for a destination's scheme (J-9, P-5, X-3, Y-5)."""
    return (SYSLOG_ERRORS if scheme in SYSLOG else JOURNAL_ERRORS if scheme == JOURNAL else
            EVENTLOG_ERRORS if scheme == EVENTLOG else ERRORS)


FACTS = 5   # T-2: judge's first lines describe a state it could read; what follows them says why it is judged so


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
                     "" if "facility" not in state else ", facility %d" % state["facility"]   # X-3: no framing
                     if dest["scheme"] == JOURNAL else ", facility %d, framing %s" % (
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
            failing["since"], failing["error"], errors_of(dest["scheme"])[failing["error"]], failing["tries"],
            "y" if failing["tries"] == 1 else "ies",
            "" if failing.get("status") is None else ", status %d" % failing["status"])]
    if inq["count"] and (asked is None or written - asked > beat):
        return 1, "BEHIND", lines + ["%d line(s) in question since %s, longer than a beat: they wait (settling"
                                     " included)" % (inq["count"], inq.get("since") or "a time not said")]
    if state["behind"] and (last_ok is None or written - last_ok > beat):
        return 1, "BEHIND", lines + ["%d byte(s) of whole lines wait longer than a beat%s" % (
            state["behind"], " (no send of this name was ever taken)" if last_ok is None else "")]
    return 0, "OK", lines


# --- the reader (R-1, R-4) -------------------------------------------------------------------------------------
LINKS_MAX = 64                             # R-4: at most this many names are read; the rest are counted, said
STATE_MAX = 1024 * 1024                    # R-4: a state longer than this (1 MiB) is unreadable, never read whole


class Rows(list):
    """`read`'s rows, in order of name; `rest` is how many states past LINKS_MAX were counted and not read, and
    `problem` why the states could not all be looked for (None where they were). S-1: either makes `worst` 3 -
    what was not read is not calm. A copy that is not a Rows (a slice, sorted()) has lost both: judge the Rows."""
    rest = 0
    problem = None


class _TooLong(Exception):
    """A state longer than STATE_MAX."""


def _names(folder):
    """The first LINKS_MAX names of a forwarder's state files in the folder, in order, and how many more there are:
    the listing is walked once and never held whole."""
    count = [0]

    def each():
        with os.scandir(folder) as entries:
            for entry in entries:
                n = entry.name
                if n.endswith(".json") and NAME.match(n[:-5]):
                    count[0] += 1
                    yield n[:-5]
    first = heapq.nsmallest(LINKS_MAX, each())
    return first, count[0] - len(first)


def _load(path):
    """The state at path, parsed: a regular file only (opened without waiting: a pipe is never waited on), at most
    STATE_MAX bytes read (more is _TooLong), ASCII, JSON. Raises what it meets; `read` makes it a row."""
    if not stat.S_ISREG(os.stat(path).st_mode):   # S-4: asked before it is opened (a device is never opened)
        raise OSError("not a regular file")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("not a regular file")
        f = os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise
    with f:
        data = f.read(STATE_MAX + 1)
    if len(data) > STATE_MAX:
        raise _TooLong()
    return json.loads(data.decode("ascii"))


def _row(name, path, now):
    row = _parts({"name": name, "path": path, "code": 3, "word": "UNREADABLE",
                  "lines": ["the state %s cannot be read" % path], "refused": None, "state": None}, now)
    try:
        state = _load(path)
    except FileNotFoundError:
        if not os.path.islink(path):   # S-4: a link to nothing is an unreadable file, not an absent one
            row.update(word="SILENT", lines=["no state: %s (it never ran, or not here)" % path])
        return _parts(row, now)
    except _TooLong:
        row["lines"] = ["the state %s cannot be read: it is longer than 1 MiB and is not read" % path]
        return _parts(row, now)
    except Exception:   # N-6: OSError, not JSON, not ASCII, nested past what the reader takes, anything else
        return row
    try:
        code, word, lines = judge(state, now)
    except Exception:   # judge says UNREADABLE of what it cannot read; this is the reader's own last guard
        return row
    refused = None
    if code != 3 or word != "UNREADABLE":
        try:
            refused = state["refused"]["count"] if _count(state["refused"]["count"]) else None
        except Exception:
            pass
    row.update(code=code, word=word, lines=lines, refused=refused,
               state=state if code != 3 or word != "UNREADABLE" else None)
    return _parts(row, now)


def _parts(row, now):
    """T-2: what a panel shows of a row, so that it restates nothing of `judge`: "age" (seconds from the state's
    `written` to `now`), "to" (the destination as `where` says it), "facts" (the lines that describe the state)
    and "why" (the lines that say why it is judged so). Of a state that is missing or unreadable nothing is
    known but its lines: age and to are None, facts are none, and all its lines are the why. lines is always
    facts + why."""
    row.update(age=None, to=None, facts=[], why=list(row["lines"]))
    state = row["state"]
    if state is not None:
        try:
            row.update(age=now - seconds_of(state["written"]), to=where(state["destination"]),
                       facts=list(row["lines"][:FACTS]), why=list(row["lines"][FACTS:]))
        except Exception:
            row.update(age=None, to=None, facts=[], why=list(row["lines"]))
    return row


def read(home=None, now=None, name=None):
    """R-1, R-4: one row for each state file whose name is a forwarder's name, in order of name, each judged by
    `judge` at `now` (this clock where None): {"name", "path", "code", "word", "lines", "refused" (the count, or
    None where it is not known), "state" (the state parsed, or None where it is unreadable)} and what a panel
    shows of it, {"age", "to", "facts", "why"} (_parts). With `name`, that one
    (no file: SILENT; a name that is not a forwarder's: no row). At most LINKS_MAX rows; `rows.rest` counts the
    states past them. No folder is no row (no forwarder ever wrote here); a folder that is there and cannot be
    listed is no row and `rows.problem` says why (S-2). Nothing raises."""
    rows = Rows()
    try:
        if name is not None:
            if not isinstance(name, str) or not NAME.match(name):
                return rows
            names = [name]
        else:
            folder = forward_dir(home)
            try:
                names, rows.rest = _names(folder)
            except FileNotFoundError:
                return rows
            except OSError as exc:
                rows.problem = "the folder %s cannot be listed (%s)" % (folder, type(exc).__name__)
                return rows
        now = time.time() if now is None else now
        for n in names:
            rows.append(_row(n, state_path(n, home), now))
    except Exception as exc:   # a home or a clock no check foresaw: the rows read so far, never a traceback
        rows.problem = "the states were not all read (%s)" % type(exc).__name__
    return rows


def worst(rows):
    """The code of several rows, as `raqib forward --status` returns it (STATUS_RULE): 3 over 1 over 0; no row is
    3 (no state: silent); and 3 where states were counted and not read, or could not be looked for (S-1, S-2)."""
    if not rows or getattr(rows, "rest", 0) or getattr(rows, "problem", None):
        return 3
    code = 0
    for row in rows:
        c = row["code"]
        code = c if (c == 3 or code != 3 and c > code) else code
    return code
