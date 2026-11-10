"""Raqib os capture source on Windows: Sysmon (M5.3, ADR-0003 and its
Amendments C and D, rulings C-5 to C-7 of docs/review/2026-11-03-M5.3-ruling.md
and D-3 to D-6, D-12 of docs/review/2026-11-03-M5.3-redo-ruling.md).

`python -m raqib os-sysmon --root PID[:GUID] --log PATH [--from FILE.xml] [--cwd DIR]`
reads Sysmon events 1 (process create), 11 (file create) and 3 (network
connect) of the process tree under PID and appends them to the trace PATH.
The os record is the only one the watched agent does not write: Sysmon
writes it, from the kernel's view of the tree.

Reading, read-only and offline:
- live (Windows only): `C:\\Windows\\System32\\wevtutil.exe qe
  Microsoft-Windows-Sysmon/Operational /f:xml`, by that absolute path, never
  through PATH, with an environment of SystemRoot only and a timeout. Never
  run on POSIX: there, without --from, os-sysmon is a usage error (exit 2).
- --from FILE.xml: an export in the same shape (wevtutil ... /f:xml, any
  order; UTF-8 or UTF-16 with a BOM), on every platform.
The XML is read by discover.sysmon_events, the one Sysmon reader (C-6).
One run reads once and exits; it does not follow the channel.

API (M7.2b, ADR-0007 decision 3 as narrowed by Amendment H): follow(root,
log, stop) is run() again and again, live, every `every` seconds, until
`stop` (a threading.Event, or anything with wait(seconds) -> bool) is set;
it is how `raqib watch --host` attaches the os source to a discovered
tree, in a thread of its own. Each pass appends only the events of the tree
whose EventRecordID is above the highest one an earlier pass of the same
follow appended (build's after_record), so a pass does not append the
channel's history again; each silence detail is written once per follow,
not once per pass. It reads, and writes nothing but the trace (A4).
ADR-0007 Amendment I-5: a follow's live pass runs wevtutil with a timeout
of its own, FOLLOW_TIMEOUT (10 s, the notifier's), through
read_live_bounded; a wevtutil that has not returned by then is Raqib's own
helper and is terminated (then killed), and its end is recorded on the
follow's Helpers; the pass writes that reason as a RAQIB-SILENCE line.
Helpers.end() terminates the helper still running when the watch stops,
so nothing of Raqib's outlives the watch unrecorded. The agent's processes
are never signalled: only the wevtutil this module started.

The tree (D-5): the root is the process --root PID:GUID names, or, with no
GUID, the LATEST process that held pid PID in the export (the one whose
event 1 is latest; a holder with no event 1 started before the export).
Earlier holders are named in one silence line, and their trees are not
read. A process joins the tree when its event 1 names a tree process as its
parent (ParentProcessId, with ParentProcessGuid deciding which process
holding that pid is meant, so a reused pid does not join an unrelated
process). Events 3 and 11 are kept when their ProcessGuid (or, with none,
their pid) is in the tree. Events are taken in UtcTime order,
EventRecordID breaking ties, so a newest-first export (/rd:true) reads the
same as an oldest-first one.

What is written (C-5), one session per run, `os-<PID>`:
- session_start at the first kept event's time; when the export holds no
  event of some read id, the line carries `missing_events` (the ids);
- per event a `pre` and a `post` with one seq, at the event's UtcTime (the
  time of the act, not of the read), tool `process`, `file` or `net`, and
  `source: "os"`; the post carries `ok: true` and `output_meta: {}` (an os
  event has no output);
- input_sha256 is the sha256 of the canonical JSON of the command line
  ({"command_line": CommandLine}), the path ({"path": TargetFilename}) or
  the destination ({"destination": {hostname, ip, port, protocol}}); the
  text itself is never written;
- input_meta: for a process {"command_head": NAME, "command_programs":
  [NAME], "image": IMAGE, "depth": D, "parent_seq": S}, NAME the basename of
  Image as Sysmon logged it if common's name rules accept it (HEAD_NAME, not
  key-like; else `command_unread: true` and IMAGE null), IMAGE (M7.8,
  ADR-0007 P-1) the same Image in discover's one normalised form
  (discover.image_name: lower case, no .exe/.com/.bat/.cmd: `curl.exe` ->
  `curl`), the field NET-TOOL and DESTRUCT-CMD read on os lines; a line
  written before M7.8 has no "image" key (the host watch says so once per
  source; no rule guesses the name from NAME); "parent_image" (M7.8 REDO
  R-7) the ParentImage the same way, null when its basename is not a plain
  name (NET-TOOL leaves out ssh started by git), D 0 for the root, 1 for its direct
  children, 2 and more below, S the seq of the parent's process line in
  this run (absent for the root, and for a direct child when the root's
  own event 1 is not in the export); never an argument. For a file
  {"path": the path, as a hook Write or Edit line keeps it (D-3),
  redacted by common.redact}. For a connection {"dest_port": N,
  "dest_private": true|false} (null when unreadable), private meaning
  10/8, 172.16/12, 192.168/16, 127/8, 169.254/16, 100.64/10, ::1, fc00::/7
  or fe80::/10; a documentation address is not private. UDP connections
  are written like TCP ones (the protocol is in the hash only);
- session_end at the last kept event's time;
- cwd on every line: --cwd DIR (an absolute directory, Windows or POSIX:
  the export may be read on another host), else the CurrentDirectory of
  the root's own event 1 in the export, else NO cwd key at all (D-4):
  nothing was observed, and os-sysmon's own directory is never written, so
  the SCOPE-CWD rules give their partial note.
The seq goes on from the highest seq of `os-<PID>` already in the trace,
which is read once at the start. A second run over the same events appends
them again: reruns are not deduplicated (C-5), the duplicates are visible.

Silence is an alarm (A3, C-7). Each of these writes one line starting with
RAQIB-SILENCE: to stderr and then to the trace (D-6: stderr first, so a
trace that cannot be written does not lose them), and the run exits 1:
- wevtutil could not be run, did not finish, or exited non-zero (no
  Sysmon, no channel, no rights);
- an event the reader cannot read, or one with no ProcessId or UtcTime;
- the export holds no event 1, or no event 11, at all;
- the root is in no event 1, 3 or 11 of the export, as ProcessId or as
  ParentProcessId, or no event carries the GUID given (then nothing else is
  written);
- the root pid had earlier holders in the export (D-5): one line names how
  many, and the root's ProcessGuid.
An export with no event 3 is not an alarm: the session's `missing_events`
holds 3, and the rules report the source as incomplete (exit 3; Sysmon
logs network connections only with -n).
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import subprocess
import sys

from raqib import discover
from raqib.hooks import capture, common
from raqib.rules import engine

SOURCE = "os"
MARKER = capture.SILENCE
WEVTUTIL = "C:\\Windows\\System32\\wevtutil.exe"
CHANNEL = "Microsoft-Windows-Sysmon/Operational"
LIVE_ARGS = ("qe", CHANNEL, "/f:xml")
LIVE_TIMEOUT = 600.0
READ = (1, 11, 3)                 # the event ids read, in the HANDOFF's order
TOOLS = {1: "process", 11: "file", 3: "net"}
SESSION_TOOL = "-"
SILENT_IF_MISSING = {
    1: "the export holds no event 1 (process create): no process of the tree is seen",
    11: "the export holds no event 11 (file create): no file write of the tree is seen; the Sysmon"
        " configuration may not log them",
}
PRIVATE_NETS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
    "::1/128", "fc00::/7", "fe80::/10"))
TEXT_MAX = 300
# --root PID[:GUID] (ruling D-5): a Sysmon ProcessGuid, braces optional.
ROOT_SPEC = re.compile(r"([0-9]+)(?::(\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?))?\Z")


class UsageError(Exception):
    """A bad option, an unreadable --from file, or a trace that cannot be read or written (exit 2)."""


def session_id(root):
    return "os-%d" % root


def safe(text, limit=TEXT_MAX):
    """One printable ASCII line, bounded."""
    text = "".join(c if " " <= c <= "~" else "?" for c in str(text))
    return text if len(text) <= limit else text[:limit - 3] + "..."


def silence_line(root, what):
    return "%s os-sysmon root=%s %s" % (MARKER, root, safe(what))


def program_name(image):
    """The basename of an Image path as Sysmon logged it, when common's name
    rules accept it (HEAD_NAME, not key-like), else None."""
    if not isinstance(image, str) or not image.strip():
        return None
    base = image.strip().replace("/", "\\").rstrip("\\").rsplit("\\", 1)[-1]
    if base and common.HEAD_NAME.match(base) and not common.looks_like_key(base):
        return base
    return None


def dest_private(text):
    """True when the address is on a private, loopback or link-local network,
    False for any other address, None when it is not an address."""
    try:
        ip = ipaddress.ip_address((text or "").strip().split("%")[0])
    except ValueError:
        return None
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return any(ip.version == net.version and ip in net for net in PRIVATE_NETS)


def _int(value):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _guid(value):
    value = (value or "").strip()
    return value or None


def parse_root(value):
    """(pid, ProcessGuid or None) of --root PID[:GUID] (ruling D-5)."""
    if isinstance(value, int) and not isinstance(value, bool):
        pid, guid = value, None
    else:
        m = ROOT_SPEC.match(str(value))
        if not m:
            raise UsageError("--root must be PID or PID:GUID (a process id, and optionally its Sysmon ProcessGuid,"
                             " {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}), not %r" % (value,))
        pid, guid = int(m.group(1)), m.group(2)
    if pid < 0:
        raise UsageError("--root must be a process id (a whole number >= 0), not %r" % (value,))
    return pid, guid


def check_cwd(cwd):
    """--cwd as the proxy checks it (ruling D-12): an absolute directory. The
    trace may describe another host than the one reading the export, so a
    path absolute on either system (a Windows drive or UNC path, or a POSIX
    path) is accepted, as the rules place it (engine.norm_path)."""
    placed = engine.norm_path(cwd)
    if placed is None or not (placed[0] == "windows" or placed[1].startswith("/")):
        raise UsageError("--cwd must be an absolute directory, not %r" % (cwd,))
    return cwd


def _same_guid(a, b):
    return a is not None and b is not None and a.strip("{}").lower() == b.strip("{}").lower()


def build(text, root, guid=None, cwd=None, start_seq=0, after_record=None, info=None):
    """(trace lines, silence details) for an export's text. Pure.
    API (M7.2b): after_record, when given, keeps only the tree's events
    whose EventRecordID is above it (an event with none was written by the
    pass that had after_record None); info, a dict, receives "top_record",
    the highest EventRecordID of the tree's events in the export (None when
    none has one). Without them build is what it was."""
    silences = []
    problems = []
    events = []
    present = set()
    for ev in discover.sysmon_events(text, "sysmon", problems, READ):
        present.add(ev["event"])
        d = ev["data"]
        pid, ts = _int(d.get("ProcessId")), discover._ts(d.get("UtcTime"))
        if pid is None or ts is None:
            silences.append("the event at line %d (Sysmon %d) has no ProcessId or UtcTime: it is not recorded"
                            % (ev["line"], ev["event"]))
            continue
        events.append(dict(ev, pid=pid, ts=ts, guid=_guid(d.get("ProcessGuid"))))
    for p in problems:
        silences.append("the export's line %d cannot be read (%s): that event is not recorded"
                        % (p["line"], p["reason"]))
    missing = sorted(set(READ) - present)
    silences += [SILENT_IF_MISSING[i] for i in sorted(SILENT_IF_MISSING) if i in missing]
    events.sort(key=lambda e: (e["ts"], e["record_id"] if e["record_id"] is not None else float("inf"), e["line"]))
    found, root_guid, said = _root(events, root, guid)
    silences += said
    if not found:
        return [], silences
    kept = _tree(events, root, root_guid)
    if info is not None:
        ids = [e["record_id"] for e, _, _ in kept if e["record_id"] is not None]
        info["top_record"] = max(ids) if ids else None
    if after_record is not None:
        kept = [k for k in kept if k[0]["record_id"] is not None and k[0]["record_id"] > after_record]
    if not kept:
        return [], silences
    if cwd is None:   # D-4: else no cwd at all, never os-sysmon's own
        starts = [e["data"].get("CurrentDirectory") for e, depth, _ in kept if e["event"] == 1 and depth == 0]
        cwd = next((c for c in starts if c), None)
    return _lines(kept, root, cwd, start_seq, missing), silences


def _root(events, root, guid):
    """(found, the root's ProcessGuid or None, silence details) (ruling D-5).
    The holders of the root pid are the ProcessGuids of its events and of
    the parents named by its children's event 1. Without a GUID the root is
    the latest of them: the one whose event 1 is latest, else (no event 1:
    it started before the export) the last first seen; the earlier ones are
    named in one silence line."""
    first, start = {}, {}
    for e in events:
        d = e["data"]
        if e["pid"] == root and e["guid"]:
            first.setdefault(e["guid"], e["ts"])
            if e["event"] == 1:
                start[e["guid"]] = (e["ts"], e["record_id"] if e["record_id"] is not None else -1)
        pguid = _guid(d.get("ParentProcessGuid"))
        if e["event"] == 1 and _int(d.get("ParentProcessId")) == root and pguid:
            first.setdefault(pguid, e["ts"])
    named = any(e["pid"] == root or (e["event"] == 1 and _int(e["data"].get("ParentProcessId")) == root)
                for e in events)
    if guid is not None:
        match = [g for g in first if _same_guid(g, guid)]
        if not match:
            return False, None, ["root pid %d with ProcessGuid %s is in no event 1, 3 or 11 of the export: nothing"
                                 " of its tree is recorded" % (root, guid)]
        return True, match[0], []
    if not named:
        return False, None, ["root pid %d is in no event 1, 3 or 11 of the export (as ProcessId or"
                             " ParentProcessId): nothing of its tree is recorded" % root]
    if not first:
        return True, None, []   # no ProcessGuid in the export: the pid alone decides
    rank = {g: ((1,) + start[g]) if g in start else (0, first[g], -1) for g in first}
    latest = max(first, key=lambda g: rank[g])
    earlier = len(first) - 1
    said = ["pid %d had %d earlier holder(s) in the export; the latest is the root (ProcessGuid %s); give --root"
            " %d:GUID for another" % (root, earlier, latest, root)] if earlier else []
    return True, latest, said


def _tree(events, root, root_guid):
    """[(event, depth, parent)] of the events of the tree under root, in
    order; parent is the identity (ProcessGuid, else ("pid", pid)) of an
    event 1's parent, None otherwise."""
    by_guid = {root_guid: 0} if root_guid else {}
    by_pid = {root: 0}   # for events that carry no ProcessGuid
    kept = []
    for e in events:
        d = e["data"]
        parent = None
        if e["event"] == 1:
            pguid, ppid = _guid(d.get("ParentProcessGuid")), _int(d.get("ParentProcessId"))
            if e["pid"] == root and (e["guid"] is None or e["guid"] == root_guid):
                depth = 0
            elif pguid is not None:
                depth = by_guid[pguid] + 1 if pguid in by_guid else None
                parent = pguid
            else:
                depth = by_pid[ppid] + 1 if ppid in by_pid else None
                parent = ("pid", ppid)
            if depth is None:
                if e["pid"] in by_pid and e["pid"] != root:
                    del by_pid[e["pid"]]   # the pid now names a process outside the tree
                continue
            if depth == 0:
                parent = None
            if e["guid"] is not None:
                by_guid[e["guid"]] = depth
            by_pid[e["pid"]] = depth
        else:
            depth = by_guid.get(e["guid"]) if e["guid"] is not None else by_pid.get(e["pid"])
            if depth is None:
                continue
        kept.append((e, depth, parent))
    return kept


def _image(image):
    """M7.8 (ADR-0007 P-1): an Image in discover's one normalised form
    (discover.image_name, as discover names a tree's image), or None."""
    return discover.image_name(image) or None


def _event_fields(e, depth):
    d = e["data"]
    if e["event"] == 1:
        name = program_name(d.get("Image"))
        meta = ({"command_head": name, "command_programs": [name]} if name else {"command_unread": True})
        # M7.8 (ADR-0007 P-1): the image name in discover's one normalised form (discover.image_name, as discover
        # names a tree's image), the field NET-TOOL and DESTRUCT-CMD read; null when the name is not read. A line
        # written before M7.8 has no "image" key at all (said once per source by the host watch, never guessed).
        meta["image"] = _image(d.get("Image")) if name else None
        # M7.8 REDO R-7: the parent's image name, the same way (a name through the same gate, never an argument)
        meta["parent_image"] = _image(d.get("ParentImage")) if program_name(d.get("ParentImage")) else None
        meta["depth"] = depth
        return common.canonical_sha256({"command_line": d.get("CommandLine")}), meta
    if e["event"] == 11:
        path = d.get("TargetFilename") or None
        return common.canonical_sha256({"path": path}), ({"path": common.redact(path)} if path else {})
    destination = {"hostname": d.get("DestinationHostname"), "ip": d.get("DestinationIp"),
                   "port": d.get("DestinationPort"), "protocol": d.get("Protocol")}
    return (common.canonical_sha256({"destination": destination}),
            {"dest_port": _int(d.get("DestinationPort")), "dest_private": dest_private(d.get("DestinationIp"))})


def _lines(kept, root, cwd, start_seq, missing):
    sid = session_id(root)
    seq = start_seq
    out = []
    line_of = {}   # a process's identity -> the seq of its line (D-9: parent_seq)

    def emit(rec):
        if cwd is not None:
            rec["cwd"] = cwd
        rec["source"] = SOURCE
        out.append(json.dumps(rec, separators=(",", ":"), ensure_ascii=True))

    seq += 1
    start = {"ts": discover.iso(kept[0][0]["ts"]), "seq": seq, "session_id": sid, "phase": "session_start",
             "tool": SESSION_TOOL}
    if missing:
        start["missing_events"] = missing
    emit(start)
    for e, depth, parent in kept:
        seq += 1
        digest, meta = _event_fields(e, depth)
        if e["event"] == 1:
            if parent is not None and parent in line_of:
                meta["parent_seq"] = line_of[parent]
            line_of[e["guid"] if e["guid"] is not None else ("pid", e["pid"])] = seq
        base = {"ts": discover.iso(e["ts"]), "seq": seq, "session_id": sid}
        tool = TOOLS[e["event"]]
        emit(dict(base, phase="pre", tool=tool, input_sha256=digest, input_meta=dict(meta)))
        emit(dict(base, phase="post", tool=tool, input_sha256=digest, input_meta=dict(meta), output_meta={},
                  ok=True))
    seq += 1
    emit({"ts": discover.iso(kept[-1][0]["ts"]), "seq": seq, "session_id": sid, "phase": "session_end",
          "tool": SESSION_TOOL})
    return out


def read_live(runner=subprocess.run, environ=None):
    """(text, None) of the live channel, or (None, why it was not read)."""
    environ = os.environ if environ is None else environ
    env = {"SystemRoot": environ.get("SystemRoot") or "C:\\Windows"}
    try:
        proc = runner([WEVTUTIL] + list(LIVE_ARGS), capture_output=True, env=env, timeout=LIVE_TIMEOUT)
    except subprocess.TimeoutExpired:
        return None, "wevtutil did not finish in %g s: the Sysmon channel was not read" % LIVE_TIMEOUT
    except OSError as exc:
        return None, ("wevtutil could not be run (%s): the Sysmon channel was not read"
                      % (exc.strerror or type(exc).__name__))
    if proc.returncode != 0:
        said = (proc.stderr or b"").decode("utf-8", "replace").strip().splitlines()
        return None, ("wevtutil exited %d (%s): the Sysmon channel was not read (no Sysmon, no channel, or no"
                      " rights to read it)" % (proc.returncode, said[0] if said else "no message"))
    return decode(proc.stdout), None


def decode(data):
    """discover.decode, and UTF-16 LE without a BOM (a NUL in every other byte)."""
    if data[:2] not in (b"\xff\xfe", b"\xfe\xff") and len(data) > 1 and data[1:2] == b"\x00":
        return data.decode("utf-16-le", "replace")
    return discover.decode(data)


def last_seq(log, sid):
    """The highest seq of session sid already in the trace (0: none or no trace)."""
    try:
        with open(log, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        return 0
    except OSError as exc:
        raise UsageError("cannot read the trace %s: %s" % (log, exc.strerror or exc))
    top = 0
    needle = json.dumps(sid).encode("ascii")
    for raw in data.split(b"\n"):
        if needle not in raw:
            continue
        try:
            rec = json.loads(raw.decode("utf-8", "replace"))
        except ValueError:
            continue
        if isinstance(rec, dict) and rec.get("session_id") == sid and type(rec.get("seq")) is int:
            top = max(top, rec["seq"])
    return top


def append(log, lines):
    """Append lines under capture's file lock (as the proxy does)."""
    try:
        with open(log, "ab+") as f:
            capture.lock(f)
            try:
                end = f.seek(0, os.SEEK_END)
                torn = end > 0 and f.seek(end - 1) >= 0 and f.read(1) != b"\n"
                f.write((b"\n" if torn else b"") + "".join(line + "\n" for line in lines).encode("ascii"))
                f.flush()
            finally:
                capture.unlock(f)
    except Exception as exc:
        raise UsageError("cannot write the trace %s: %s" % (log, getattr(exc, "strerror", None) or exc))


def run(root, log, from_path=None, cwd=None, out=None, err=None, live=None, nt=None):
    """The os-sysmon command: 0 written with no silence, 1 a RAQIB-SILENCE
    line was written, UsageError (exit 2) otherwise. root is PID, or the
    text PID[:GUID] (ruling D-5)."""
    out = sys.stdout if out is None else out
    err = sys.stderr if err is None else err
    nt = (os.name == "nt") if nt is None else nt
    pid, guid = parse_root(root)
    if cwd is not None:
        check_cwd(cwd)
    if from_path is None and not nt:
        raise UsageError("os-sysmon reads the live Sysmon channel on Windows only; here, give an export with"
                         " --from FILE.xml (wevtutil qe %s /f:xml > FILE.xml)" % CHANNEL)
    start = last_seq(log, session_id(pid))
    if from_path is not None:
        try:
            with open(from_path, "rb") as f:
                text, failed = decode(f.read()), None
        except OSError as exc:
            raise UsageError("cannot read --from %s: %s" % (from_path, exc.strerror or exc))
    else:
        text, failed = (live or read_live)()
    if failed is not None:
        lines, silences = [], [failed]
    else:
        lines, silences = build(text, pid, guid=guid, cwd=cwd, start_seq=start)
    marked = [silence_line(pid, s) for s in silences]
    for line in marked:   # D-6: on stderr first, so a failed append cannot lose them
        err.write(line + "\n")
    err.flush()
    append(log, marked + lines)
    events = max(0, (len(lines) - 2) // 2)
    where = "from %s" % from_path if from_path is not None else "from the live channel"
    out.write("raqib os-sysmon: %d events of the tree under pid %d %s -> %s (session %s); %d RAQIB-SILENCE"
              " line(s)\n" % (events, pid, where, log, session_id(pid) if lines else "none", len(marked)))
    return 1 if marked else 0


FOLLOW_EVERY = 10.0
FOLLOW_TIMEOUT = 10.0     # I-5: one live pass of a follow, as the notifier's timeout (notify.TIMEOUT_SECONDS)
HELPER_GRACE = 2.0        # after terminate(), how long a helper is given before kill()


class Helpers:
    """I-5: the wevtutil children one follow started (Raqib's own, never
    the agent's). running: pid -> the process still out; record: one text
    per helper that had to be ended (by its timeout, or by end() at Stop)."""

    def __init__(self):
        self.running = {}
        self.record = []

    @staticmethod
    def _stop(proc):
        try:
            proc.terminate()
            try:
                proc.wait(HELPER_GRACE)
                return "terminated"
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(HELPER_GRACE)
                return "killed"
        except Exception as exc:   # already gone, or no rights: said, never silent
            return "not ended (%s)" % (type(exc).__name__,)

    def ended(self, proc, why):
        how = self._stop(proc)
        self.running.pop(proc.pid, None)
        text = "wevtutil pid %s (Raqib's own helper) %s: %s" % (proc.pid, how, why)
        self.record.append(text)
        return text

    def end(self, why="the watch stopped"):
        """Every helper still running is ended and recorded; their texts."""
        return [self.ended(proc, why) for proc in list(self.running.values())]


def read_live_bounded(timeout=FOLLOW_TIMEOUT, helpers=None, popen=subprocess.Popen, environ=None, args=LIVE_ARGS):
    """read_live for a follow's pass (I-5): the same wevtutil, argv and
    environment, started as a child Raqib owns and waited for at most
    timeout seconds; one that has not returned is terminated and recorded on
    helpers; (text, None) or (None, why it was not read). args (M7.9): the
    wevtutil arguments after its path (default LIVE_ARGS: the whole channel;
    a round of raqib watch --host gives round_args, a bounded query)."""
    environ = os.environ if environ is None else environ
    helpers = Helpers() if helpers is None else helpers
    env = {"SystemRoot": environ.get("SystemRoot") or "C:\\Windows"}
    options = {"stdin": subprocess.DEVNULL, "stdout": subprocess.PIPE, "stderr": subprocess.PIPE, "env": env}
    if os.name == "nt":
        options["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        proc = popen([WEVTUTIL] + list(args), **options)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        return None, ("wevtutil could not be run (%s): the Sysmon channel was not read"
                      % (getattr(exc, "strerror", None) or type(exc).__name__))
    helpers.running[proc.pid] = proc
    try:
        data, said = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        text = helpers.ended(proc, "did not return in %g s" % timeout)
        return None, "wevtutil did not return in %g s (%s): the Sysmon channel was not read" % (timeout, text)
    except Exception as exc:   # ended from outside (Stop) while waited for
        if proc.pid in helpers.running:
            helpers.ended(proc, "its pass failed: %s" % type(exc).__name__)
        return None, "wevtutil was ended before it returned: the Sysmon channel was not read"
    helpers.running.pop(proc.pid, None)
    if proc.returncode != 0:
        lines = (said or b"").decode("utf-8", "replace").strip().splitlines()
        return None, ("wevtutil exited %s (%s): the Sysmon channel was not read (no Sysmon, no channel, or no"
                      " rights to read it)" % (proc.returncode, lines[0] if lines else "no message"))
    return decode(data or b""), None


def follow(root, log, stop, every=FOLLOW_EVERY, cwd=None, out=None, err=None, live=None, nt=None, on_pass=None,
           after_record=None, helpers=None, timeout=FOLLOW_TIMEOUT):
    """API (M7.2b): the os source followed live until stop is set (see the
    module docstring). Returns the number of passes. Raises UsageError as
    run() does (a bad root or cwd, off Windows without a `live` reader, a
    trace it cannot read or write); the caller's thread turns that into a
    hole. Every pass that could not read the channel writes its reason once
    as a RAQIB-SILENCE line (A3). on_pass(n, top), when given, is called
    after each pass has appended what it read, with the highest
    EventRecordID appended so far; after_record starts a follow there (a
    follow of the same tree resumed: the events already appended are not
    appended again). Without `live`, each pass reads through
    read_live_bounded(timeout, helpers) (I-5)."""
    out = sys.stdout if out is None else out
    err = sys.stderr if err is None else err
    nt = (os.name == "nt") if nt is None else nt
    pid, guid = parse_root(root)
    if cwd is not None:
        check_cwd(cwd)
    if live is None and not nt:
        raise UsageError("os-sysmon follows the live Sysmon channel on Windows only")
    top, said, passes = after_record, set(), 0
    while True:
        passes += 1
        text, failed = live() if live is not None else read_live_bounded(timeout, helpers)
        if failed is not None:
            lines, silences = [], [failed]
        else:
            info = {}
            lines, silences = build(text, pid, guid=guid, cwd=cwd, start_seq=last_seq(log, session_id(pid)),
                                    after_record=top, info=info)
            if info.get("top_record") is not None:
                top = info["top_record"] if top is None else max(top, info["top_record"])
        fresh = [s for s in silences if s not in said]
        said.update(fresh)
        marked = [silence_line(pid, s) for s in fresh]
        for line in marked:
            err.write(line + "\n")
        err.flush()
        if marked or lines:
            append(log, marked + lines)
        out.write("raqib os-sysmon: follow pass %d: %d events of the tree under pid %d -> %s; %d RAQIB-SILENCE"
                  " line(s)\n" % (passes, max(0, (len(lines) - 2) // 2), pid, log, len(marked)))
        if on_pass is not None:
            on_pass(passes, top)
        if stop.wait(every):
            return passes


# --- M7.9 (ADR-0007 Amendment P, ruling P-4): the round reads the channel ------------------------------------
# One bounded read of the channel per round of raqib watch --host, by the same wevtutil (absolute path, SystemRoot
# only, a timeout, Raqib's own helper ended and recorded: I-5). The query is built here from two values Raqib holds
# itself - the watch's start (its own clock) and the highest EventRecordID an earlier round read (an integer parsed
# by discover.sysmon_events) - and the event ids discover reads; no text of an event or of an agent goes into it.

ROUND_IDS = (1, 3, 11, 22)        # discover.SYSMON_READ: the events the round gives discover
ROUND_CAP = 2000                  # events per round at most (wevtutil /c:); reaching it is a hole of the round
ROUND_TIMEOUT = FOLLOW_TIMEOUT    # I-5: one round's read, as a follow's pass
SILENT_ROUNDS = 3                 # X-3(c): rounds of new sampled processes with no event 1 before the read restarts
OPEN_CHANNELS = []                # X-1: the channels the live readers of this process own (Stop ends their helpers)
RECORD_ID = re.compile(r"<EventRecordID>\s*([0-9]{1,20})\s*</EventRecordID>")
SYSTEM_TIME = re.compile(r"<TimeCreated\s+SystemTime=['\"]([^'\"]{1,40})['\"]")


def query_time(moment):
    """An aware datetime as the XPath SystemTime text, UTC, milliseconds."""
    offset = moment.utcoffset()
    if offset is None:
        raise ValueError("the watch's start must be an aware time")
    moment = moment.replace(tzinfo=None) - offset
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (moment.microsecond // 1000)


def round_query(after_record=None, since=None):
    """The XPath of one round's read: the events of ROUND_IDS whose
    EventRecordID is above after_record (an int), or, before any round read
    a record (and after a restart, X-3c), whose TimeCreated is at or after
    since. Only Raqib's own values are formatted into it (int(), query_time())."""
    ids = " or ".join("EventID=%d" % i for i in ROUND_IDS)
    if after_record is not None:
        bound = "EventRecordID>%d" % int(after_record)
    elif since is not None:
        bound = "TimeCreated[@SystemTime>='%s']" % query_time(since)
    else:
        raise ValueError("a round's query needs a bound: an EventRecordID or the watch's start")
    return "*[System[(%s) and %s]]" % (ids, bound)


def round_args(query, cap=ROUND_CAP):
    """wevtutil's arguments for one round: oldest first (wevtutil's default
    direction), at most cap events, XML."""
    return ("qe", CHANNEL, "/q:%s" % query, "/c:%d" % int(cap), "/f:xml")


def _chunks(text):
    """The text cut at each <Event: (chunk, record id or None, SystemTime text or None)."""
    starts = [m.start() for m in discover.EVENT_START.finditer(text)]
    out = []
    for i, at in enumerate(starts):
        chunk = text[at:starts[i + 1] if i + 1 < len(starts) else len(text)]
        rid, when = RECORD_ID.search(chunk), SYSTEM_TIME.search(chunk)
        out.append((chunk, int(rid.group(1)) if rid else None, discover._ts(when.group(1)) if when else None))
    return text[:starts[0]] if starts else text, out


def _age(later, earlier):
    return round((later - earlier).total_seconds(), 3)


class Channel:
    """The channel as the live reader of raqib watch --host reads it, one
    bounded read per round (M7.9; REDO X-1: owned by the reader, never
    passed by a caller). since: the watch's start as the reader knows it
    (set by the reader before the first record is kept, T-3's adjusted
    start); after: the highest EventRecordID of a round that was kept
    (commit(); X-4: a reader that fails after the read loses nothing).
    reader(args, timeout) -> (text, None) or (None, why): default
    read_live_bounded with this channel's helpers."""

    def __init__(self, since=None, cap=None, timeout=ROUND_TIMEOUT, reader=None, helpers=None):
        self.since = since
        self.cap = int(ROUND_CAP if cap is None else cap)
        self.timeout = float(timeout)
        self.helpers = Helpers() if helpers is None else helpers
        self.reader = reader or (lambda args, timeout: read_live_bounded(timeout, self.helpers, args=args))
        self.after = None
        self.reads = self.failed = self.cut = self.events = self.dropped = 0
        self.kinds = set()            # X-8: the event ids the kept rounds read
        self.event1_seen = False      # X-3(b): the channel has given an event 1
        self.silent_rounds = 0        # X-3(b,c)
        self.restarts = []
        self.prev_at = None           # the time of the last kept read
        self.read_times = []          # Z-2: the times of the kept reads (the rounds a process had to be delivered)
        self.created = {}             # Z-2: pid -> the Sysmon 1 times every kept read so far gave for it
        self.start = since            # Z-2: the channel's own start (what is older was never asked for)
        self.early_rounds = 0         # Z-5 (Y12): reads that returned only records older than since
        self.filtered = set()         # Z-2: images whose event 1 never came while the channel gave others
        self.closed = False           # Z-6: a closed channel starts no helper
        self.said = 0                 # helper records already carried by a round's record
        self.last = None

    def close(self, why="the watch stopped (Stop)"):
        """Z-6: the channel leaves OPEN_CHANNELS; a helper still out is ended (its texts)."""
        self.closed = True
        if self in OPEN_CHANNELS:
            OPEN_CHANNELS.remove(self)
        return self.helpers.end(why)

    def read(self, at):
        """One round's read at `at` (an aware datetime): (kept text or None,
        record). What came back is checked against what was asked (X-3a): a
        record not above the bound, or before since, is dropped and said."""
        if self.start is None:
            self.start = self.since
        query = round_query(self.after, self.since)
        text, failed = (None, "the channel is closed (its watch stopped): not read") if self.closed else \
            self.reader(round_args(query, self.cap), self.timeout)
        record = {"query": query, "cap": self.cap, "events": 0, "after": self.after, "top": self.after,
                  "error": failed, "cut": False, "dropped": 0, "behind_seconds": None, "older_seconds": None,
                  "kinds": [], "holes": [], "restarted": None, "silent": 0, "at": discover.iso(at),
                  "since": discover.iso(self.since), "helpers": list(self.helpers.record[self.said:])}
        self.said = len(self.helpers.record)
        if failed is not None:
            self.failed += 1
            record["holes"].append("the Sysmon channel was not read this round (%s): the round keeps its sample; the"
                                   " next round reads the records after %s" % (
                                       failed, "record %d" % self.after if self.after is not None else "the start"))
            self.last = record
            return None, record
        lead, chunks = _chunks(text)
        kept, low, early = [], None, 0
        for chunk, rid, when in chunks:
            below = self.after is not None and rid is not None and rid <= self.after
            early = self.since is not None and when is not None and when < self.since
            if below or early:
                record["dropped"] += 1
                if below:
                    low = rid if low is None else min(low, rid)
                else:
                    early += 1
                continue
            kept.append((chunk, rid, when))
        kept_text = lead + "".join(c for c, _, _ in kept)
        ids = [rid for _, rid, _ in kept if rid is not None]
        times = [w for _, _, w in kept if w is not None]
        events = list(discover.sysmon_events(kept_text, "sysmon", [], None))
        record.update(events=len(kept), top=max(ids + ([self.after] if self.after is not None else [])) if ids
                      else self.after, kinds=sorted({e["event"] for e in events if e["event"] in ROUND_IDS}),
                      event1=sorted({(_int(e["data"].get("ProcessId", "")), discover.iso(discover._ts(
                          e["data"].get("UtcTime")))) for e in events if e["event"] == 1} - {(None, None)},
                          key=lambda x: (x[0] or 0, x[1] or "")))
        if times:
            record["behind_seconds"] = _age(at, max(times))
            length = _age(at, self.prev_at) if self.prev_at is not None else None
            # Z-8: behind only by more than one round's length (less is the log's ordinary delay)
            if length is not None and min(times) < self.prev_at and _age(self.prev_at, min(times)) > length:
                record["older_seconds"] = _age(self.prev_at, min(times))
        if record["dropped"]:
            record["holes"].append("the Sysmon channel gave %d record(s) %s: dropped, never a tree (the query's bound"
                                   " was not applied)" % (record["dropped"], "at or below record %d" % self.after
                                                          if low is not None else "from before the watch's start"))
            if low is not None:
                self.restart(at, record, "its record numbers restarted (record %d at or below the bound %d: the"
                             " channel was cleared?)" % (low, self.after))
        self.early_rounds = self.early_rounds + 1 if chunks and early == len(chunks) else 0
        if self.early_rounds >= 2 and not record["restarted"]:   # Z-5 (Y12): a clock that stepped back
            self.restart(at, record, "two reads returned only records older than the read's start (%s): the wall"
                         " clock stepped back?" % discover.iso(self.since))
        if len(chunks) >= self.cap:
            record["cut"] = True
            record["holes"].append("the Sysmon channel gave %d events this round, the cap (/c:%d): the newest read is"
                                   " %s s behind the round; the records after %s are read by the next round"
                                   % (len(chunks), self.cap, record["behind_seconds"], "record %s" % record["top"]))
        elif record["older_seconds"] is not None:
            record["holes"].append("the round read the channel %s s behind the previous round (the newest read is %s s"
                                   " behind this round): the rounds lag the channel"
                                   % (record["older_seconds"], record["behind_seconds"]))
        self.last = record
        return kept_text, record

    def restart(self, at, record, why):
        """X-3(c), Z-5: the read starts again from the round's time; what it skips is said."""
        skipped = self.prev_at or self.since
        self.after, self.since, self.silent_rounds, self.early_rounds = None, at, 0, 0
        text = ("the Sysmon channel's read starts again from %s: %s; what the channel logged from %s to %s that no"
                " round returned is not read" % (discover.iso(at), why, discover.iso(skipped), discover.iso(at)))
        self.restarts.append(text)
        record["restarted"] = text
        record["holes"].append(text)

    def silence(self, record, sampled, at):
        """Z-2 (X-3(b) restated): sampled is [(pid, image, start)] of the round's
        sample. A process is due when it was created after the channel's start
        and before the previous kept read (a full round to be delivered), and is
        looked for in every kept read so far. Due and missing while this read
        holds other event 1s: a note, once per image (record["filtered"]).
        Due and missing for three rounds in a row whose reads held no event 1
        at all, after the channel gave event 1 before: the hole "behind,
        stopped or cleared", in the third round, and the read restarts."""
        if record.get("error") or record.get("cut") or self.prev_at is None or self.start is None:
            return
        seen = {pid: list(times) for pid, times in self.created.items()}
        for pid, when in record.get("event1") or ():
            seen.setdefault(pid, []).append(when)
        lo = self.read_times[-2] if len(self.read_times) >= 2 else self.start
        due = [(pid, image, start) for pid, image, start in sampled
               if start is not None and lo <= start <= self.prev_at and image not in self.filtered]
        missing = [(pid, image) for pid, image, start in due if not any(
            discover._start_close(start, discover._ts(w)) for w in seen.get(pid, ()) if w)]
        if not missing:
            self.silent_rounds = 0
            return
        if record.get("event1"):   # the channel gives others: this image is left out of its configuration
            record["filtered"] = sorted({image or "?" for _, image in missing})
            self.filtered.update(record["filtered"])
            self.silent_rounds = 0
            return
        if not self.event1_seen:
            return
        self.silent_rounds += 1
        record["silent"] = len(missing)
        if self.silent_rounds >= SILENT_ROUNDS:
            record["holes"].append("the Sysmon channel is behind, stopped or cleared: for %d rounds the sample showed"
                                   " processes created a round earlier and the channel gave no event 1 at all (pid %s)"
                                   % (SILENT_ROUNDS, ", ".join(str(p) for p, _ in missing[:10])))
            self.restart(at, record, "%d rounds without any event 1" % SILENT_ROUNDS)

    def commit(self, record, at):
        """The round that read is kept: its bound moves (X-4)."""
        if record.get("error"):
            return
        if not record.get("restarted"):
            self.after = record.get("top")
        self.reads += 1
        self.events += record.get("events") or 0
        self.dropped += record.get("dropped") or 0
        self.cut += 1 if record.get("cut") else 0
        self.kinds.update(record.get("kinds") or ())
        self.event1_seen = self.event1_seen or 1 in (record.get("kinds") or ())
        for pid, when in record.get("event1") or ():
            times = self.created.setdefault(pid, [])
            if when not in times:
                times.append(when)
                del times[:-8]
        self.prev_at = at
        self.read_times = (self.read_times + [at])[-3:]
