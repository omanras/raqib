"""Raqib os capture source on Windows: Sysmon (M5.3, ADR-0003 and its
Amendment C, rulings C-5 to C-7 of docs/review/2026-11-03-M5.3-ruling.md).

`python -m raqib os-sysmon --root PID --log PATH [--from FILE.xml] [--cwd DIR]`
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

The tree: the root is every process that held pid PID in the export (its
ProcessGuid); a process joins the tree when its event 1 names a tree
process as its parent (ParentProcessId, with ParentProcessGuid deciding
which process holding that pid is meant, so a reused pid does not join an
unrelated process). Events 3 and 11 are kept when their ProcessGuid (or,
with none, their pid) is in the tree. Events are taken in UtcTime order,
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
  [NAME], "depth": D}, NAME the basename of Image as Sysmon logged it if
  common's name rules accept it (HEAD_NAME, not key-like; else
  `command_unread: true`), D 0 for the root, 1 for its direct children, 2
  and more below; never an argument. For a file {"path": the path,
  redacted by common.redact}. For a connection {"dest_port": N,
  "dest_private": true|false} (null when unreadable), private meaning
  10/8, 172.16/12, 192.168/16, 127/8, 169.254/16, 100.64/10, ::1, fc00::/7
  or fe80::/10; a documentation address is not private. UDP connections
  are written like TCP ones (the protocol is in the hash only);
- session_end at the last kept event's time;
- cwd on every line: --cwd DIR, else the CurrentDirectory of the root's
  own event 1 in the export, else os-sysmon's own working directory (the
  proxy's rule, ADR-0003 Amendment A).
The seq goes on from the highest seq of `os-<PID>` already in the trace,
which is read once at the start. A second run over the same events appends
them again: reruns are not deduplicated (C-5), the duplicates are visible.

Silence is an alarm (A3, C-7). Each of these writes one line starting with
RAQIB-SILENCE: to the trace and to stderr, and the run exits 1:
- wevtutil could not be run, did not finish, or exited non-zero (no
  Sysmon, no channel, no rights);
- an event the reader cannot read, or one with no ProcessId or UtcTime;
- the export holds no event 1, or no event 11, at all;
- the root is in no event 1, 3 or 11 of the export, as ProcessId or as
  ParentProcessId (then nothing else is written).
An export with no event 3 is not an alarm: the session's `missing_events`
holds 3, and the rules report the source as incomplete (exit 3; Sysmon
logs network connections only with -n).
"""
from __future__ import annotations

import ipaddress
import json
import os
import subprocess
import sys

from raqib import discover
from raqib.hooks import capture, common

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


def build(text, root, cwd=None, start_seq=0, own_cwd=None):
    """(trace lines, silence details) for an export's text. Pure but for
    os.getcwd() when neither cwd nor the root's event 1 gives one."""
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
    named = [e for e in events if e["pid"] == root
             or (e["event"] == 1 and _int(e["data"].get("ParentProcessId")) == root)]
    if not named:
        silences.append("root pid %d is in no event 1, 3 or 11 of the export (as ProcessId or ParentProcessId):"
                        " nothing of its tree is recorded" % root)
        return [], silences
    kept = _tree(events, root)
    if cwd is None:
        starts = [e["data"].get("CurrentDirectory") for e, depth in kept if e["event"] == 1 and depth == 0]
        cwd = next((c for c in starts if c), None) or own_cwd or os.getcwd()
    return _lines(kept, root, cwd, start_seq, missing), silences


def _tree(events, root):
    """[(event, depth)] of the events of the tree under root, in order."""
    root_guids = {e["guid"] for e in events if e["pid"] == root and e["guid"]}
    root_guids |= {_guid(e["data"].get("ParentProcessGuid")) for e in events
                   if e["event"] == 1 and _int(e["data"].get("ParentProcessId")) == root} - {None}
    by_guid = {g: 0 for g in root_guids}
    by_pid = {root: 0}   # for events that carry no ProcessGuid
    kept = []
    for e in events:
        d = e["data"]
        if e["event"] == 1:
            pguid, ppid = _guid(d.get("ParentProcessGuid")), _int(d.get("ParentProcessId"))
            if e["pid"] == root and (e["guid"] is None or e["guid"] in root_guids):
                depth = 0
            elif pguid is not None:
                depth = by_guid[pguid] + 1 if pguid in by_guid else None
            else:
                depth = by_pid[ppid] + 1 if ppid in by_pid else None
            if depth is None:
                if e["pid"] in by_pid and e["pid"] != root:
                    del by_pid[e["pid"]]   # the pid now names a process outside the tree
                continue
            if e["guid"] is not None:
                by_guid[e["guid"]] = depth
            by_pid[e["pid"]] = depth
        else:
            depth = by_guid.get(e["guid"]) if e["guid"] is not None else by_pid.get(e["pid"])
            if depth is None:
                continue
        kept.append((e, depth))
    return kept


def _event_fields(e, depth):
    d = e["data"]
    if e["event"] == 1:
        name = program_name(d.get("Image"))
        meta = ({"command_head": name, "command_programs": [name]} if name else {"command_unread": True})
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

    def emit(rec):
        rec.update(cwd=cwd, source=SOURCE)
        out.append(json.dumps(rec, separators=(",", ":"), ensure_ascii=True))

    seq += 1
    start = {"ts": discover.iso(kept[0][0]["ts"]), "seq": seq, "session_id": sid, "phase": "session_start",
             "tool": SESSION_TOOL}
    if missing:
        start["missing_events"] = missing
    emit(start)
    for e, depth in kept:
        seq += 1
        digest, meta = _event_fields(e, depth)
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
    line was written, UsageError (exit 2) otherwise."""
    out = sys.stdout if out is None else out
    err = sys.stderr if err is None else err
    nt = (os.name == "nt") if nt is None else nt
    if not isinstance(root, int) or isinstance(root, bool) or root < 0:
        raise UsageError("--root must be a process id (a whole number >= 0), not %r" % (root,))
    if from_path is None and not nt:
        raise UsageError("os-sysmon reads the live Sysmon channel on Windows only; here, give an export with"
                         " --from FILE.xml (wevtutil qe %s /f:xml > FILE.xml)" % CHANNEL)
    start = last_seq(log, session_id(root))
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
        lines, silences = build(text, root, cwd=cwd, start_seq=start)
    marked = [silence_line(root, s) for s in silences]
    append(log, marked + lines)
    for line in marked:
        err.write(line + "\n")
    events = max(0, (len(lines) - 2) // 2)
    where = "from %s" % from_path if from_path is not None else "from the live channel"
    out.write("raqib os-sysmon: %d events of the tree under pid %d %s -> %s (session %s); %d RAQIB-SILENCE"
              " line(s)\n" % (events, root, where, log, session_id(root) if lines else "none", len(marked)))
    return 1 if marked else 0
