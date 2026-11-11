"""Agent discovery (M5.0, ADR-0004 with Amendment B): find the AI agents on
a host by what they do, with no prior knowledge of their names.

    An agent is a process tree that talks to a model and acts on the machine.

Layers (ADR-0004; kinds as in ADR-0002):
1. endpoints (signature, supporting): an outbound connection to a model
   host, network or local model port in raqib/discover/endpoints.yaml. Names
   come only from records the host holds: the Windows DNS client cache and
   Sysmon events 22 and 3. Linux keeps no such record offline, so there the
   catalog matches by IP network and loopback port only (a recorded hole).
2. tree (anchor, primary; B-6): a process with outbound TCP (a "talker")
   that has a child. Every process goes to its nearest talking ancestor;
   a file the talker's tree writes outside config space (Sysmon 11) is an
   act too. The catalog's `acts:` names only label a child (a listed shell,
   interpreter or git); they decide nothing, so a renamed shell is still a
   child.
4. footprint (signature, supporting): agent config paths in the homes, and
   *_API_KEY variable NAMES in a process environment. AGENT-DARK: a path
   footprint on disk that no candidate or act-root in the window links to.
Layer 3 (rhythm) is M5.4.

M5.0b (ADR-0004 Amendment F), after the Kimi field test: an agent between
two requests owns no connection, so its acts go to a talking ancestor.
- act-root (signature, the catalog's act_root block): a process whose image
  is under a user directory, not a listed shell or system image, with a
  listed shell as a child that has a command below it, and no talk of its
  own in any sample. A weaker class than a candidate; exit 1 all the same.
  When a sample shows it talking it is a candidate instead (the merge).
- recent talk, owner unknown: a TIME-WAIT row with no owner (Windows
  OwningProcess 0, Linux inode 0) or a DNS cache row (a name, no pid) for a
  catalog endpoint. Evidence with cites; never a candidate or an act-root
  by itself; with neither in the run it is incomplete (exit 3, G-3).
- the Windows window: the docs/GUIDE.md export is a loop of N samples; each sample
  is one file per kind, win-process-<k>.csv, win-tcp-<k>.csv and
  win-dns-<k>.csv, merged as the Linux window merges its snapshots. The
  loop's run.json declares N; a sample without its process or connection
  file is not read, so the run is incomplete (A3).
- `raqib discover --check` measures candidates and act-roots on the
  fixtures the act_root block names, against act_root's fp_budget (A6).

Every reader is a parser over text, so fixtures are text and the tests need
no live host. A record is a dict with "src" (the source kind), "line" (its
line in that source's text) and "text" (that line, bounded); every claim of
the inventory cites the record lines it rests on (A5). Source texts, and
their names under --from DIR:
  proc.txt         Linux /proc snapshot as JSON lines, written by
                   snapshot_proc(): pid, ppid (status PPid), name (status
                   Name), argv (cmdline), cwd, env_keys (environ NAMES only:
                   values are dropped on reading and never stored), sockets
                   (socket inodes from /proc/PID/fd), exe (the
                   /proc/PID/exe link; M5.0b G-2). A {"snapshot": TIME,
                   "self": PID, ...counts} line opens each snapshot.
  proc-net.txt     /proc/net/tcp and /proc/net/tcp6 as the kernel prints
                   them; "# at TIME (FILE)" opens each block. Owners come
                   from the sockets in proc.txt (B-1).
  ss.txt           `ss -tnp` or `ss -tanp` output (the fallback when
                   /proc/net/tcp cannot be read); "# at TIME" may open a block.
  win-process.csv  Get-CimInstance Win32_Process | ConvertTo-Csv
  win-tcp.csv      Get-NetTCPConnection | ConvertTo-Csv
  win-dns.csv      Get-DnsClientCache | ConvertTo-Csv
                   (or win-process-<k>.csv, win-tcp-<k>.csv, win-dns-<k>.csv:
                   sample k of the docs/GUIDE.md loop; source name win-tcp-<k>)
  run.json         --save's record of a live run, or the docs/GUIDE.md loop's
                   {"raqib": "discover-run", "samples": N}
  sysmon.xml       Sysmon events as XML (wevtutil qe ... /f:xml): 1 process
                   create, 3 network connect, 11 file create, 22 DNS query
  footprints.txt   one path per line: what exists in the homes ("#" lines
                   are comments)
A line "!hole TEXT" in proc-net.txt or footprints.txt is a read failure the
reader met; it becomes a hole of the inventory, with its line cited (B-3).

Offline and read-only (E6, A4): no socket is opened; no process is
signalled, attached to or written to. A live run on Linux reads /proc,
/proc/net/tcp and /proc/net/tcp6; only when /proc/net/tcp cannot be read
does it run ss, by absolute path from SS_PATHS with a minimal environment,
never through PATH (B-1). A live run on Windows (M7.1, ADR-0007) reads the
OS API in-process through raqib/hostwin.py, N samples T seconds apart, and
each sample is the three texts above (win-process-<k>, win-tcp-<k>,
win-dns-<k>) in the cmdlets' columns, parsed by the same parsers; a
"# raqib-snapshot ... self=PID" line in win-process names the reader, so
its tree is never evidence. Elsewhere it lists the homes only and says so.
"""
from __future__ import annotations

import csv
import datetime
import fnmatch
import io
import ipaddress
import json
import os
import re
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

from raqib.rules import yamlite

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CATALOG = os.path.join(ROOT, "raqib", "discover", "endpoints.yaml")
SOURCES = ("proc", "proc-net", "ss", "win-process", "win-tcp", "win-dns", "sysmon", "footprints")
FILE_NAMES = {"proc": "proc.txt", "proc-net": "proc-net.txt", "ss": "ss.txt",
              "win-process": "win-process.csv", "win-tcp": "win-tcp.csv", "win-dns": "win-dns.csv",
              "sysmon": "sysmon.xml", "footprints": "footprints.txt"}
PROCESS_SOURCES = ("proc", "win-process", "sysmon")
CONNECTION_SOURCES = ("proc-net", "ss", "win-tcp", "sysmon")
# E1 (M5.0b): the docs/GUIDE.md loop writes one file per kind and sample k = 1..N.
SAMPLED = ("win-process", "win-tcp", "win-dns")
SAMPLE_NEEDS = ("win-process", "win-tcp")   # a sample without both is not read (A3)
SAMPLE_NAME = re.compile(r"(win-process|win-tcp|win-dns)-([1-9][0-9]{0,4})\Z")
SAMPLES_MAX = 10000
# The record each source must hold for the run to be complete (B-2).
EXPECTED = {"proc": "proc", "win-process": "proc", "proc-net": "conn", "ss": "conn", "win-tcp": "conn"}
# ss is a fallback only, and only from here: never found through PATH (B-1).
SS_PATHS = ("/usr/sbin/ss", "/usr/bin/ss", "/sbin/ss", "/bin/ss")
SS_ARGS = ("-tanp",)
# M7.4 (ADR-0007 decision 4, E1): the per-socket byte counts, read-only, by the same run_ss (absolute path,
# minimal environment): -i adds the TCP info line (bytes_sent / bytes_received where the kernel and ss give
# them), -p the owner, -n numbers. Only raqib watch --host asks for it (read_conn_bytes).
SS_INFO_ARGS = ("-tinp",)
SS_BYTES = re.compile(r"\bbytes_(sent|received):([0-9]+)\b")
# What the anchor cannot see, said on every run (B-4, D8).
ALWAYS_HOLES = (
    "liveness: a child is seen only if it is alive at a snapshot (or has a Sysmon 1 event), and a"
    " connection only while it is open; one that ended between snapshots is not seen. An agent between"
    " two requests owns no connection, so its acts go to a talking ancestor: what is left of its talk"
    " (a TIME-WAIT row with no owner, a DNS cache row with no pid) is shown as recent talk, owner"
    " unknown, never as a candidate, and its tree can be an act-root (talk not seen)",
    "sibling talkers: the talker must be an ancestor of the child; a talker beside it (an Electron"
    " network process, a local daemon or proxy that relays the model) is not joined to it",
    "reparented acts: a child started with setsid, nohup or a double fork, or whose parent exited"
    " (reparented to init; on Windows a dead parent's pid can be reused), is not attributed",
    "TCP only: UDP and QUIC (HTTP/3) and unix-socket relays to a local proxy are not read as talk",
    "one view: sockets of other network namespaces (containers) and processes hidden by hidepid or"
    " by another user's /proc permissions are not seen",
)
TALK_STATES = ("ESTABLISHED", "SYN-SENT", "CLOSE-WAIT", "FIN-WAIT-1", "FIN-WAIT-2", "LAST-ACK",
               "CLOSING", "CONNECT")
STATES = {"ESTAB": "ESTABLISHED", "ESTABLISHED": "ESTABLISHED", "SYNSENT": "SYN-SENT",
          "SYNRECV": "SYN-RECEIVED", "SYNRECEIVED": "SYN-RECEIVED", "FINWAIT1": "FIN-WAIT-1",
          "FINWAIT2": "FIN-WAIT-2", "CLOSEWAIT": "CLOSE-WAIT", "CLOSING": "CLOSING",
          "LASTACK": "LAST-ACK", "TIMEWAIT": "TIME-WAIT", "LISTEN": "LISTEN", "CLOSED": "CLOSED",
          "CLOSE": "CLOSED", "UNCONN": "CLOSED", "BOUND": "BOUND", "DELETETCB": "DELETE-TCB",
          # MSFT_NetTCPConnection.State as a number
          "1": "CLOSED", "2": "LISTEN", "3": "SYN-SENT", "4": "SYN-RECEIVED", "5": "ESTABLISHED",
          "6": "FIN-WAIT-1", "7": "FIN-WAIT-2", "8": "CLOSE-WAIT", "9": "CLOSING", "10": "LAST-ACK",
          "11": "TIME-WAIT", "12": "DELETE-TCB", "100": "BOUND"}
# The `st` column of /proc/net/tcp (include/net/tcp_states.h).
PROC_NET_STATES = {"01": "ESTABLISHED", "02": "SYN-SENT", "03": "SYN-RECEIVED", "04": "FIN-WAIT-1",
                   "05": "FIN-WAIT-2", "06": "TIME-WAIT", "07": "CLOSED", "08": "CLOSE-WAIT",
                   "09": "LAST-ACK", "0A": "LISTEN", "0B": "CLOSING", "0C": "SYN-RECEIVED"}
# Path segments of config, cache and temp space; a write there is not an act.
CONFIG_SEGMENTS = ("appdata", "programdata", "temp", "tmp", "$recycle.bin")
SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"
LINE_TEXT_MAX = 240
CITES_PER_CLAIM = 3
ACTS_SHOWN = 12
ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
EXIT = {"none-seen": 0, "alarm": 1, "incomplete": 3}


class CatalogError(ValueError):
    pass


class LiveRefused(Exception):
    """A live run that cannot start (M7.1 E3: the Windows process snapshot
    failed): the CLI says so in one line and exits 2."""


# --- text helpers -------------------------------------------------------------

def decode(data):
    """Text of a source file: UTF-8, or UTF-16 with a BOM (PowerShell 5's `>`)."""
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8", "replace")
    if data.startswith(b"\xff\xfe"):
        return data[2:].decode("utf-16-le", "replace")
    if data.startswith(b"\xfe\xff"):
        return data[2:].decode("utf-16-be", "replace")
    return data.decode("utf-8", "replace")


def _safe(text):
    return "".join(c if c.isprintable() else "?" for c in str(text))


def bounded(text, limit=LINE_TEXT_MAX):
    """One printable line; a long one keeps its start and end."""
    text = _safe(text)
    if len(text) > limit:
        keep = limit - 3
        text = text[:keep // 2] + "..." + text[-(keep - keep // 2):]
    return text


def _numbered(text):
    for number, raw in enumerate(text.split("\n"), start=1):
        yield number, raw[:-1] if raw.endswith("\r") else raw


def _rec(kind, src, line, text, **fields):
    rec = {"kind": kind, "src": src, "line": line, "text": bounded(text)}
    rec.update(fields)
    return rec


def _problem(src, line, reason):
    return {"src": src, "line": line, "reason": reason}


def _int(value):
    try:
        return int(str(value).strip())
    except ValueError:
        return None


def _ts(value):
    """An observation time as an aware UTC datetime, or None."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        dt = datetime.datetime.fromisoformat(text)
    except ValueError:
        return None
    return dt.replace(tzinfo=datetime.timezone.utc) if dt.tzinfo is None else dt.astimezone(datetime.timezone.utc)


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z" if dt else None


def image_name(path):
    """Program name of a path: basename, lower case, no .exe/.com/.bat/.cmd,
    no leading "-" of a login shell."""
    if not path:
        return None
    base = re.split(r"[\\/]", path.strip().strip('"'))[-1].lower().lstrip("-")
    for ext in (".exe", ".com", ".bat", ".cmd"):
        if base.endswith(ext):
            base = base[:-len(ext)]
    return base or None


def win_argv(cmdline):
    """argv of a Windows command line: whitespace splits outside double quotes."""
    out, word, quoted, started = [], [], False, False
    for c in cmdline or "":
        if c == '"':
            quoted, started = not quoted, True
        elif c in " \t" and not quoted:
            if started:
                out.append("".join(word))
            word, started = [], False
        else:
            word.append(c)
            started = True
    if started:
        out.append("".join(word))
    return out


def _ip(text):
    """Normalised IP text (an IPv4-mapped IPv6 address becomes IPv4), "*" for
    a wildcard, or None."""
    text = (text or "").strip()
    if text in ("*", ""):
        return "*" if text == "*" else None
    text = text.split("%")[0]
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return None
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return str(ip)


def _hostport(text):
    """(ip, port) of an ss address like 1.2.3.4:443, [::1]:80, *:22."""
    if text.startswith("["):
        host, sep, port = text[1:].partition("]:")
        if not sep:
            return None
    else:
        host, sep, port = text.rpartition(":")
        if not sep:
            return None
    ip = _ip(host)
    if ip is None:
        return None
    if port == "*":
        return ip, None
    port = _int(port)
    return (ip, port) if port is not None and 0 <= port <= 65535 else None


def _wildcard(ip):
    return ip in (None, "*") or ipaddress.ip_address(ip).is_unspecified


def _state(text):
    return STATES.get(re.sub(r"[^A-Z0-9]", "", str(text).upper()))


# --- the catalog (endpoints.yaml) ---------------------------------------------------

def load_catalog(path=CATALOG):
    """The signature catalog. kind must be signature and evasion a non-empty
    list (ADR-0002); anything malformed is a CatalogError, never a silent
    misread."""
    try:
        with open(path, encoding="utf-8") as f:
            doc = yamlite.loads(f.read())
    except (OSError, UnicodeDecodeError, yamlite.YamlError) as exc:
        raise CatalogError("%s: %s" % (path, exc))

    def bad(field, msg):
        raise CatalogError("%s: %s: %s" % (path, field, msg))

    keys = ("id", "kind", "evasion", "hosts", "networks", "ports", "footprints", "env", "acts", "handoff",
            "act_root", "benign_images")
    optional = ("benign_images",)   # M7.2 REDO C-1d: read by raqib watch --host only
    if not isinstance(doc, dict):
        raise CatalogError("%s: the catalog must hold a mapping" % path)
    for key in keys:
        if key not in doc and key not in optional:
            bad(key, "missing")
    for key in doc:
        if key not in keys:
            bad(key, "unknown field")
    if doc["kind"] != "signature":
        bad("kind", "must be signature (the anchor reads no catalog)")
    if not (isinstance(doc["evasion"], list) and doc["evasion"]
            and all(isinstance(e, str) and e.strip() for e in doc["evasion"])):
        bad("evasion", "a signature must list its known evasions (ADR-0002)")

    def items(field, required, optional=("note",)):
        value = doc[field]
        if not isinstance(value, list):
            bad(field, "must be a list")
        for i, item in enumerate(value):
            if not (isinstance(item, dict) and set(required) <= set(item)
                    and set(item) <= set(required) | set(optional)):
                bad("%s[%d]" % (field, i), "must have %s (and optionally %s)"
                    % (", ".join(required), ", ".join(optional)))
        return value

    hosts = items("hosts", ("match", "vendor"))
    for i, h in enumerate(hosts):
        if not (isinstance(h["match"], str) and h["match"] and h["match"] == h["match"].lower()):
            bad("hosts[%d].match" % i, "must be a lower-case host name or glob")
    networks = []
    for i, n in enumerate(items("networks", ("cidr", "vendor"))):
        try:
            networks.append(dict(n, net=ipaddress.ip_network(str(n["cidr"]))))
        except ValueError as exc:
            bad("networks[%d].cidr" % i, str(exc))
    ports = items("ports", ("port", "name"))
    for i, p in enumerate(ports):
        if not (isinstance(p["port"], int) and not isinstance(p["port"], bool) and 0 < p["port"] < 65536):
            bad("ports[%d].port" % i, "must be a port number")
    footprints = items("footprints", ("match", "agent"))
    for i, fp in enumerate(footprints):
        m = fp["match"]
        if not (isinstance(m, str) and m and not m.startswith("/") and "\\" not in m
                and ".." not in m.split("/") and not any(c in "*?[" for c in m.rpartition("/")[0])):
            bad("footprints[%d].match" % i, "must be a path relative to a home, '/'-separated,"
                " with a glob in its last part only")
        if not (isinstance(fp["agent"], str) and fp["agent"] == fp["agent"].lower() and fp["agent"]):
            bad("footprints[%d].agent" % i, "must be a lower-case program name")
    if not (isinstance(doc["env"], list) and all(isinstance(e, str) and e for e in doc["env"])):
        bad("env", "must be a list of variable-name globs")
    acts = doc["acts"]
    if not (isinstance(acts, dict) and set(acts) <= {"names", "evasion", "note"} and "names" in acts):
        bad("acts", "must be a mapping with names and evasion")
    if not (isinstance(acts.get("evasion"), list) and acts["evasion"]
            and all(isinstance(e, str) and e.strip() for e in acts["evasion"])):
        bad("acts.evasion", "the act names are a signature: list their known evasions (ADR-0002, B-6)")
    if not (isinstance(acts["names"], list) and acts["names"]
            and all(isinstance(n, str) and n and n == n.lower() for n in acts["names"])):
        bad("acts.names", "must be a non-empty list of lower-case program names or globs")
    handoff = doc["handoff"]
    if not (isinstance(handoff, dict) and set(handoff) == {"hook", "proxy"}):
        bad("handoff", "must hold hook and proxy")
    for name, fields in (("hook", {"images", "not_paths"}), ("proxy", {"proxy_capable"})):
        part = handoff[name]
        if not (isinstance(part, dict) and set(part) == fields | {"evasion"}):
            bad("handoff.%s" % name, "must hold %s and evasion" % ", ".join(sorted(fields)))
        if not (isinstance(part["evasion"], list) and part["evasion"]
                and all(isinstance(e, str) and e.strip() for e in part["evasion"])):
            bad("handoff.%s.evasion" % name, "a hand-off criterion is a signature: list its evasions (D-5)")
        for field in fields:
            if not (isinstance(part[field], list) and all(isinstance(n, str) and n for n in part[field])):
                bad("handoff.%s.%s" % (name, field), "must be a list of names")
    images = handoff["hook"]["images"] + handoff["proxy"]["proxy_capable"]
    if any(n != n.lower() for n in images):
        bad("handoff", "images and proxy_capable must be lower-case program names")
    proxy = handoff["proxy"]["proxy_capable"]
    return {"id": doc["id"], "kind": doc["kind"], "evasion": doc["evasion"], "hosts": hosts,
            "networks": networks, "ports": ports, "footprints": footprints, "env": doc["env"],
            "acts": acts["names"], "acts_evasion": acts["evasion"], "proxy_capable": proxy,
            "hook_images": handoff["hook"]["images"], "hook_not_paths": handoff["hook"]["not_paths"],
            "hook_evasion": handoff["hook"]["evasion"], "proxy_evasion": handoff["proxy"]["evasion"],
            "act_root": _act_root_spec(doc["act_root"], bad),
            "benign_images": _benign_spec(doc.get("benign_images"), bad), "path": str(path)}


def _benign_spec(spec, bad):
    """M7.2 REDO (ADR-0007 Amendment C, C-1d): the catalog's benign_images
    block, a signature (kind signature, evasion listed), or None when the
    catalog has none (then no tree is benign). REDO-2 D-3: a Windows glob is
    rooted at the system drive (`%systemdrive%/...`, never `?:`), and
    `exclude` names the user-writable places under it."""
    if spec is None:
        return None
    if not (isinstance(spec, dict) and {"kind", "names", "dirs", "exclude", "evasion"} <= set(spec)
            <= {"kind", "names", "dirs", "exclude", "evasion", "pinned"}):
        bad("benign_images", "must hold kind, names, dirs, exclude and evasion (and optionally pinned)")
    if spec["kind"] != "signature":
        bad("benign_images.kind", "must be signature (a name and a path the process's record gives)")
    if not (isinstance(spec["evasion"], list) and spec["evasion"]
            and all(isinstance(e, str) and e.strip() for e in spec["evasion"])):
        bad("benign_images.evasion", "a signature must list its known evasions (ADR-0002)")
    if not (isinstance(spec["names"], list) and spec["names"]
            and all(isinstance(n, str) and n and n == n.lower() for n in spec["names"])):
        bad("benign_images.names", "must be a non-empty list of lower-case image names")
    for key in ("dirs", "exclude"):
        if not (isinstance(spec[key], list) and spec[key]
                and all(isinstance(d, str) and d.endswith("/*") and "?" not in d
                        and (d.startswith("/") or d.startswith(SYSTEM_DRIVE + "/"))
                        and d == (d.lower() if d.startswith(SYSTEM_DRIVE) else d) for d in spec[key])):
            bad("benign_images.%s" % key, "must be a non-empty list of '/...' or lower-case '%s/...' globs ending"
                " in /* (D-3: the system drive only, no '?')" % SYSTEM_DRIVE)
    # M7.8 (ADR-0007 P-3): pinned names are benign under their own directories only, never under `dirs`
    pinned = spec.get("pinned", [])
    if not isinstance(pinned, list):
        bad("benign_images.pinned", "must be a list of {name, dirs}")
    pins = {}
    for i, pin in enumerate(pinned):
        if not (isinstance(pin, dict) and set(pin) == {"name", "dirs"} and isinstance(pin["name"], str)
                and pin["name"] and pin["name"] == pin["name"].lower() and pin["name"] not in spec["names"]
                and pin["name"] not in pins):
            bad("benign_images.pinned[%d]" % i, "must be {name, dirs}: a lower-case image name, once, not in names")
        if not (isinstance(pin["dirs"], list) and pin["dirs"]
                and all(isinstance(d, str) and d.endswith("/*") and "?" not in d and d.startswith(SYSTEM_DRIVE + "/")
                        and d == d.lower() for d in pin["dirs"])):
            bad("benign_images.pinned[%d].dirs" % i, "must be a non-empty list of lower-case '%s/...' globs ending in"
                " /* (D-3: the system drive only)" % SYSTEM_DRIVE)
        pins[pin["name"]] = list(pin["dirs"])
    return {"names": list(spec["names"]), "dirs": list(spec["dirs"]), "exclude": list(spec["exclude"]),
            "evasion": list(spec["evasion"]), "pinned": pins}


SYSTEM_DRIVE = "%systemdrive%"     # D-3: the root of a Windows benign glob, the drive SystemRoot is on
NO_DRIVE = ("the run record gives no system drive (hostwin records SystemRoot's drive in run.json): no Windows image"
            " is benign (D-3)")


def benign_check(image, exe, exe_from, catalog, system_drive=None):
    """M7.2 REDO-2 D-3 (API for raqib/host.py): (glob, None) when the
    tree's root image is a listed benign program, else (None, why), where
    why is NO_DRIVE when the image would be judged on a Windows path and
    the run record gives no system drive, and None otherwise. The image name
    and the basename of the image path must both be a listed name, the path
    must come from the process's record (exe_from "record": never argv[0],
    which the process writes), must not be blank or denied, must hold no
    '.' or '..' part, must fall under a listed directory and under no
    excluded one. A Windows path (a drive letter or a backslash) is
    compared lower case with '/', and its globs are rooted at the system
    drive (system_drive, one lower-case letter, from run.json): another
    drive's Windows or Program Files is not benign; a POSIX path is
    compared as it is. M7.8 (ADR-0007 P-3): a pinned name (Windows
    Defender's engine, msmpeng) is benign only under its own directories
    on the system drive, never under the block's other directories."""
    spec = catalog.get("benign_images")
    if not spec or not exe or exe_from != "record" or not isinstance(exe, str):
        return None, None
    name = image_name(exe)
    pinned = (spec.get("pinned") or {}).get(name)   # M7.8 (P-3): benign by image AND its own directory
    if (name not in spec["names"] and pinned is None) or (image and image != name):
        return None, None
    path = exe.strip().strip('"')
    windows = "\\" in path or re.match(r"[A-Za-z]:", path) is not None
    if windows:
        path = re.sub(r"\A/(?:/\?|\?\?)/", "", path.replace("\\", "/")).lower()
    if any(part in (".", "..") for part in path.split("/")):
        return None, None
    if windows:
        if not (isinstance(system_drive, str) and re.match(r"[a-z]\Z", system_drive)):
            return None, NO_DRIVE
        root = system_drive + ":"
        dirs = [d.replace(SYSTEM_DRIVE, root, 1) for d in (pinned or spec["dirs"]) if d.startswith(SYSTEM_DRIVE)]
        exclude = [d.replace(SYSTEM_DRIVE, root, 1) for d in spec["exclude"] if d.startswith(SYSTEM_DRIVE)]
    else:
        dirs = [d for d in spec["dirs"] if d.startswith("/")] if pinned is None else []
        exclude = [d for d in spec["exclude"] if d.startswith("/")]
    if any(fnmatch.fnmatchcase(path, d) for d in exclude):
        return None, None
    return next((d for d in dirs if fnmatch.fnmatchcase(path, d)), None), None


def benign_image(image, exe, exe_from, catalog, system_drive=None):
    """The glob of benign_check, or None (M7.2 REDO C-1d, REDO-2 D-3)."""
    return benign_check(image, exe, exe_from, catalog, system_drive)[0]


def system_drive_of(run):
    """D-3: the system drive a run record (run.json, or collect_live's
    run_info) gives: one lower-case letter, or None."""
    drive = (run or {}).get("system_drive") if isinstance(run, dict) else None
    return drive if isinstance(drive, str) and re.match(r"[a-z]\Z", drive) else None


ACT_ROOT_KEYS = ("kind", "status", "fp_budget", "user_dirs", "shells", "launchers", "not_images", "evasion",
                 "fixtures")
ACT_ROOT_STATUSES = ("ok", "disabled")   # G-8: disabling is the Table's act
CITE = re.compile(r"([a-z-]+(?:-[1-9][0-9]*)?):([1-9][0-9]*)\Z")


def _act_root_spec(spec, bad):
    """The catalog's act_root block (M5.0b E3): a signature (ADR-0002: kind
    signature and a non-empty evasion list), an fp_budget as the rules have
    one (A6), its globs and names, and the fixtures --check measures it on."""
    if not (isinstance(spec, dict) and set(spec) == set(ACT_ROOT_KEYS)):
        bad("act_root", "must hold %s" % ", ".join(ACT_ROOT_KEYS))
    if spec["kind"] != "signature":
        bad("act_root.kind", "must be signature (the image path is the process's own record)")
    if spec["status"] not in ACT_ROOT_STATUSES:
        bad("act_root.status", "must be one of %s (G-8)" % "|".join(ACT_ROOT_STATUSES))
    if not (isinstance(spec["evasion"], list) and spec["evasion"]
            and all(isinstance(e, str) and e.strip() for e in spec["evasion"])):
        bad("act_root.evasion", "a signature must list its known evasions (ADR-0002)")
    budget = spec["fp_budget"]
    if not (isinstance(budget, (int, float)) and not isinstance(budget, bool) and 0 <= budget < 1):
        bad("act_root.fp_budget", "must be a number with 0 <= fp_budget < 1")
    for field in ("user_dirs", "shells", "launchers", "not_images"):
        value = spec[field]
        if not (isinstance(value, list) and value
                and all(isinstance(n, str) and n and n == n.lower() and "\\" not in n for n in value)):
            bad("act_root.%s" % field, "must be a non-empty list of lower-case names or '/' globs")
    fixtures = spec["fixtures"]
    if not (isinstance(fixtures, dict) and set(fixtures) == {"positive", "negative"}
            and all(isinstance(fixtures[k], list) for k in fixtures)):
        bad("act_root.fixtures", "must hold positive and negative lists")

    def relative(p):
        return (isinstance(p, str) and p and not p.startswith("/") and "\\" not in p and ":" not in p
                and ".." not in p.split("/"))
    positive = []
    for i, item in enumerate(fixtures["positive"]):
        expect = next((k for k in ("act_root", "promoted") if isinstance(item, dict) and k in item), None)
        name = item.get(expect) if expect else None
        line = item.get("cite") if expect else None
        if not (expect and set(item) == {"dir", expect, "cite"} and relative(item["dir"])
                and isinstance(name, str) and name and name == name.lower()
                and isinstance(line, str) and CITE.match(line) and split_name(CITE.match(line).group(1))):
            bad("act_root.fixtures.positive[%d]" % i, "must be {dir: PATH, act_root: NAME, cite: SRC:LINE} or {dir:"
                " PATH, promoted: NAME, cite: SRC:LINE}, PATH relative to a checkout, NAME a lower-case program"
                " name, SRC:LINE a line the entry must cite (G-8)")
        positive.append({"dir": item["dir"], "expect": expect, "name": name, "cite": line})
    for i, p in enumerate(fixtures["negative"]):
        if not relative(p):
            bad("act_root.fixtures.negative[%d]" % i, "must be a directory relative to a checkout")
    if not positive or not fixtures["negative"]:
        bad("act_root.fixtures", "a budget is measured: at least one positive and one negative")
    return {"kind": spec["kind"], "status": spec["status"], "fp_budget": budget, "user_dirs": list(spec["user_dirs"]),
            "shells": list(spec["shells"]), "launchers": list(spec["launchers"]), "not_images": list(spec["not_images"]),
            "evasion": list(spec["evasion"]), "positive": positive, "negative": list(fixtures["negative"])}


# --- parsers: text in, records out (E1) ---------------------------------------------

def cmdline_args(raw):
    """argv from the bytes of /proc/PID/cmdline (NUL-separated)."""
    parts = raw.split(b"\0")
    if parts and parts[-1] == b"":
        parts.pop()
    return [p.decode("utf-8", "replace") for p in parts]


def status_fields(text):
    """The `Key:<tab>value` fields of /proc/PID/status."""
    out = {}
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if sep:
            out[key.strip()] = value.strip()
    return out


def environ_keys(raw):
    """The variable NAMES of /proc/PID/environ. Values are dropped here and
    never reach a record (E4)."""
    names = set()
    for item in raw.split(b"\0"):
        name = item.split(b"=", 1)[0].decode("ascii", "replace")
        if ENV_NAME.match(name):
            names.add(name)
    return sorted(names)


def _linux_image(argv, name):
    """argv[0]'s program name; status Name when argv[0] was rewritten (has a
    space, e.g. "sshd: user") or is empty."""
    first = argv[0] if argv else ""
    if first and " " not in first:
        return image_name(first)
    return image_name(name) if name else None


def parse_proc(text, src="proc"):
    """Records of a proc.txt snapshot (JSON lines from snapshot_proc)."""
    records, problems = [], []
    at = None
    for number, raw in _numbered(text):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        try:
            obj = json.loads(raw)
        except ValueError:
            problems.append(_problem(src, number, "not a JSON line"))
            continue
        if not isinstance(obj, dict):
            problems.append(_problem(src, number, "not a JSON object"))
            continue
        if "snapshot" in obj:
            at = _ts(obj["snapshot"])
            counts = {k: obj[k] for k in ("gone_while_read", "unreadable", "kernel_threads", "start_unread")
                      if isinstance(obj.get(k), int) and not isinstance(obj.get(k), bool)}
            self_pid = obj.get("self") if isinstance(obj.get("self"), int) else None
            records.append(_rec("snapshot", src, number, raw, ts=at, self=self_pid, counts=counts,
                                kernel_parent=obj.get("kernel_parent")))
            continue
        pid, ppid, argv, env = obj.get("pid"), obj.get("ppid"), obj.get("argv"), obj.get("env_keys")
        sockets = obj.get("sockets")
        if not (isinstance(pid, int) and (ppid is None or isinstance(ppid, int))
                and (argv is None or (isinstance(argv, list) and all(isinstance(a, str) for a in argv)))
                and (env is None or (isinstance(env, list) and all(isinstance(e, str) for e in env)))
                and (sockets is None or (isinstance(sockets, list) and all(isinstance(i, int) for i in sockets)))):
            problems.append(_problem(src, number, "a process line needs int pid and ppid, argv and"
                                                  " env_keys as lists of strings, sockets as ints"))
            continue
        cwd = obj.get("cwd") if isinstance(obj.get("cwd"), str) else None
        unread = obj.get("unread") if isinstance(obj.get("unread"), list) else []
        # M7.8 REDO R-5, REDO 2 T-4: the start where the snapshot carries it (a tree's key on Linux): the kernel's
        # ticks since boot ("boot+N"), else a start time a snapshot of the first REDO wrote, else none
        ticks = obj.get("start_ticks")
        shown = obj.get("started") if isinstance(obj.get("started"), str) and obj.get("started") else None
        started_at = None
        if isinstance(ticks, int) and not isinstance(ticks, bool) and ticks >= 0:
            started, started_at = "boot+%d" % ticks, shown   # V-4: the key, and beside it the time to show
        else:
            started = shown
        # G-2: the exe link places a process; argv[0], its own text, is the fallback.
        linked = isinstance(obj.get("exe"), str) and bool(obj.get("exe"))
        exe = obj.get("exe") if linked else (argv or [None])[0]
        records.append(_rec("proc", src, number, raw, pid=pid, ppid=ppid, argv=argv or [],
                            image=_linux_image(argv, obj.get("name")), exe=exe,
                            exe_from="record" if linked else "argv",   # M7.2 REDO C-1d
                            cwd=cwd, env_keys=env, sockets=sockets, ts=_ts(obj.get("at")) or at,
                            unread=[str(u) for u in unread], **dict({"started": started} if started else {},
                                                                    **({"started_at": started_at} if started_at else {}))))
    return records, problems


def _proc_net_addr(text):
    """(ip, port) of a /proc/net/tcp address: hex words in host byte order
    (little-endian, as on x86 and arm64) and a hex port."""
    addr, sep, port = text.partition(":")
    if not sep or len(addr) not in (8, 32):
        return None
    try:
        raw = bytes.fromhex(addr)
        port = int(port, 16)
    except ValueError:
        return None
    packed = b"".join(raw[i:i + 4][::-1] for i in range(0, len(raw), 4))
    ip = ipaddress.ip_address(packed)
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return str(ip), port


def parse_proc_net(text, src="proc-net"):
    """Records of /proc/net/tcp and /proc/net/tcp6 text. The owner is left
    open (pid None): build() joins each socket inode to the processes whose
    /proc/PID/fd hold it (B-1). Inode 0 has no owner (TIME-WAIT)."""
    records, problems = [], []
    at = None
    for number, raw in _numbered(text):
        line = raw.strip()
        if not line:
            continue
        if line.startswith("!hole "):
            records.append(_rec("hole", src, number, raw, note=line[len("!hole "):]))
            continue
        if line.startswith("#"):
            m = re.match(r"#\s*at\s+(\S+)", line)
            if m:
                at = _ts(m.group(1))
            continue
        fields = line.split()
        if fields[0] == "sl":
            continue
        if len(fields) < 10 or not fields[0].endswith(":"):
            problems.append(_problem(src, number, "not a /proc/net/tcp row"))
            continue
        local, peer = _proc_net_addr(fields[1]), _proc_net_addr(fields[2])
        state, inode = PROC_NET_STATES.get(fields[3].upper()), _int(fields[9])
        if local is None or peer is None or state is None or inode is None:
            problems.append(_problem(src, number, "cannot read addresses, state or inode"))
            continue
        records.append(_rec("conn", src, number, raw, pid=None, comm=None, state=state, laddr=local[0],
                            lport=local[1], raddr=peer[0], rport=peer[1], inode=inode, ts=at))
    _set_direction(records)
    return records, problems


USERS = re.compile(r'\("((?:[^"\\]|\\.)*)",pid=([0-9]+),fd=[0-9]+\)')


def parse_ss(text, src="ss"):
    """Records of `ss -tnp` / `ss -tanp` output."""
    records, problems = [], []
    at = None
    netid = False
    for number, raw in _numbered(text):
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#"):
            m = re.match(r"#\s*at\s+(\S+)", line)
            if m:
                at = _ts(m.group(1))
            continue
        fields = line.split()
        if fields[0] in ("State", "Netid"):
            netid = fields[0] == "Netid"
            continue
        if netid:
            if fields[0] != "tcp":
                continue
            fields = fields[1:]
        if len(fields) < 5:
            problems.append(_problem(src, number, "fewer than 5 columns"))
            continue
        state, local, peer = _state(fields[0]), _hostport(fields[3]), _hostport(fields[4])
        if state is None or local is None or peer is None:
            problems.append(_problem(src, number, "cannot read state or addresses (run ss with -n)"))
            continue
        base = dict(state=state, laddr=local[0], lport=local[1], raddr=peer[0], rport=peer[1], ts=at)
        users = USERS.findall(" ".join(fields[5:]))
        for comm, pid in users or [(None, None)]:
            records.append(_rec("conn", src, number, raw, pid=_int(pid) if pid else None, comm=comm, **base))
    _set_direction(records)
    return records, problems


def _set_direction(conns):
    """Outbound or inbound, for a snapshot of sockets. With listening sockets
    in the same text: inbound when the local port is listened on. Without:
    outbound when the local port is above the remote one (an ephemeral port
    calling a service port). The basis is recorded on each connection."""
    conns = [r for r in conns if r["kind"] == "conn"]
    listening = {r["lport"] for r in conns if r["state"] == "LISTEN"}
    for r in conns:
        if r["state"] not in TALK_STATES or r["lport"] is None or r["rport"] is None:
            r["direction"], r["basis"] = None, None
        elif listening:
            r["direction"], r["basis"] = ("in" if r["lport"] in listening else "out"), "listen"
        else:
            r["direction"], r["basis"] = ("out" if r["lport"] > r["rport"] else "in"), "ports"


def _csv_rows(text, src, what, required, problems):
    """(line, raw line, row dict) per data row of a PowerShell CSV. A first
    `#TYPE` line and `#` comment lines before the header are skipped."""
    lines = text.split("\n")
    reader = csv.reader(io.StringIO(text, newline=""))
    header, prev = None, 0
    try:
        for row in reader:
            start, prev = prev + 1, reader.line_num
            if not row or not "".join(row).strip():
                continue
            if header is None:
                if row[0].lstrip().startswith("#"):
                    continue
                header = [h.strip() for h in row]
                missing = [k for k in required if not any(k == h or (isinstance(k, tuple) and h in k)
                                                          for h in header)]
                if missing:
                    problems.append(_problem(src, start, "not a %s CSV: no column %s" % (
                        what, ", ".join("|".join(k) if isinstance(k, tuple) else k for k in missing))))
                    return
                continue
            if len(row) != len(header):
                problems.append(_problem(src, start, "%d fields, the header has %d" % (len(row), len(header))))
                continue
            yield start, lines[start - 1].rstrip("\r"), dict(zip(header, row))
    except csv.Error as exc:
        problems.append(_problem(src, prev + 1, "CSV: %s" % exc))
    if header is None:
        problems.append(_problem(src, 1, "no CSV header: not a %s CSV" % what))


def _col(row, *names):
    for n in names:
        if row.get(n, "").strip():
            return row[n].strip()
    return None


# M7.1: the first line of a win-process text the live reader wrote names the
# reader's own pid, as proc.txt's snapshot line does, so its tree is never
# evidence (E3); --save keeps it, so a replay knows it too.
WIN_SNAPSHOT_LINE = "# raqib-snapshot at=%s self=%s sample=%d"
# ADR-0007 A-7: self= is the reader's pid, then its launchers (raqib*.exe,
# python*.exe) nearest first, comma-separated: all of them are the reader.
WIN_SNAPSHOT = re.compile(r"# raqib-snapshot at=(\S+) self=([0-9]+(?:,[0-9]+)*) sample=([0-9]+)\Z")


def parse_win_process(text, src="win-process"):
    """Records of `Get-CimInstance Win32_Process | ConvertTo-Csv`, or of the
    same columns written by the live reader (raqib/hostwin.py), whose
    "# raqib-snapshot" line before the header becomes a snapshot record."""
    records, problems = [], []
    for number, raw in _numbered(text):
        if not raw.lstrip().startswith("#"):
            break
        m = WIN_SNAPSHOT.match(raw.strip())
        if m:
            pids = [int(x) for x in m.group(2).split(",")]
            records.append(_rec("snapshot", src, number, raw, ts=_ts(m.group(1)), self=pids[0], counts={},
                                kernel_parent=None, launchers=pids[1:]))
    for number, raw, row in _csv_rows(text, src, "Win32_Process",
                                      ("ProcessId", "ParentProcessId", "Name"), problems):
        pid, ppid = _int(row["ProcessId"]), _int(row["ParentProcessId"])
        if pid is None or ppid is None:
            problems.append(_problem(src, number, "ProcessId and ParentProcessId must be numbers"))
            continue
        exe, cmdline = _col(row, "ExecutablePath"), _col(row, "CommandLine")
        records.append(_rec("proc", src, number, raw, pid=pid, ppid=ppid, image=image_name(row["Name"]),
                            exe=exe, argv=win_argv(cmdline), cwd=None, env_keys=None, ts=None,
                            started=_col(row, "CreationDate")))
    return records, problems


def parse_win_tcp(text, src="win-tcp"):
    """Records of `Get-NetTCPConnection | ConvertTo-Csv`."""
    records, problems = [], []
    for number, raw, row in _csv_rows(text, src, "Get-NetTCPConnection",
                                      ("LocalAddress", "LocalPort", "RemoteAddress", "RemotePort",
                                       "State", "OwningProcess"), problems):
        state, pid = _state(row["State"]), _int(row["OwningProcess"])
        laddr, raddr = _ip(row["LocalAddress"]), _ip(row["RemoteAddress"])
        lport, rport = _int(row["LocalPort"]), _int(row["RemotePort"])
        if None in (state, pid, laddr, raddr, lport, rport):
            problems.append(_problem(src, number, "cannot read state, addresses, ports or OwningProcess"))
            continue
        records.append(_rec("conn", src, number, raw, pid=pid, comm=None, state=state, laddr=laddr,
                            lport=lport, raddr=raddr, rport=rport, ts=None, started=_col(row, "CreationTime")))
    _set_direction(records)
    return records, problems


def parse_win_dns(text, src="win-dns"):
    """Name records (A and AAAA) of `Get-DnsClientCache | ConvertTo-Csv`."""
    records, problems = [], []
    for number, raw, row in _csv_rows(text, src, "Get-DnsClientCache",
                                      ("Entry", "Data", ("Type", "RecordType")), problems):
        rtype = (_col(row, "Type", "RecordType") or "").upper()
        if rtype not in ("A", "AAAA", "1", "28"):
            continue
        ip = _ip(row["Data"])
        if ip in (None, "*"):
            problems.append(_problem(src, number, "an A/AAAA record whose Data is not an IP"))
            continue
        names = sorted({n.lower().rstrip(".") for n in (_col(row, "Entry"), _col(row, "Name", "RecordName")) if n})
        records.append(_rec("dns", src, number, raw, pid=None, names=names, ips=[ip], ts=None))
    return records, problems


def _sysmon_ips(results):
    """IPs in a Sysmon 22 QueryResults value ("type:  5 x.net;::ffff:1.2.3.4;")."""
    ips = []
    for part in (results or "").split(";"):
        ip = _ip(part)
        if ip not in (None, "*"):
            ips.append(ip)
    return ips


EVENT_START = re.compile(r"<Event(?=[\s>])")


def parse_sysmon(text, src="sysmon", keyed=False):
    """Records of Sysmon events 1, 3, 11 and 22 in XML. Events may stand one
    per line (wevtutil /f:xml) or span lines; each is cited at its first line.
    Other providers and event ids are counted, not read. The XML is read by
    sysmon_events(), the one Sysmon reader (M5.3, ruling C-6). keyed (M7.9,
    a round's channel): each record also carries the ProcessGuid of its
    process (guid; pguid, created on an event 1's own record); off by
    default, so the records of every export read as they always did."""
    records, problems = [], []
    for ev in sysmon_events(text, src, problems, SYSMON_READ):
        records += [dict(r, event=ev["event"]) for r in _sysmon_records(src, ev["line"], ev["event"], ev["data"],
                                                                         problems, keyed)]
    return records, problems


SYSMON_READ = (1, 3, 11, 22)   # the event ids parse_sysmon reads


def sysmon_events(text, src="sysmon", problems=None, ids=None):
    """The one reader of Sysmon XML (M5.3, ruling C-6), shared by
    parse_sysmon and the os capture source (raqib/hooks/os_sysmon.py).

    Yields one dict per event of provider Microsoft-Windows-Sysmon whose
    EventID is in ids (every id when ids is None), in the order of the text:
    line (the line of its <Event>), event (the EventID), record_id (the
    EventRecordID, or None) and data (every named Data field as text,
    stripped: the whole CommandLine, ProcessGuid and ParentProcessGuid, and
    Protocol, so a UDP event 3 is there too). Events of other providers are
    skipped. An event that cannot be read (no </Event>, a DOCTYPE or ENTITY,
    malformed XML) is appended to problems as it is met, so a caller that
    adds problems of its own keeps them in text order."""
    problems = [] if problems is None else problems
    starts = [m.start() for m in EVENT_START.finditer(text)]
    line, pos = 1, 0
    for i, start in enumerate(starts):
        line += text.count("\n", pos, start)
        pos = start
        chunk = text[start:starts[i + 1] if i + 1 < len(starts) else len(text)]
        end = chunk.rfind("</Event>")
        if end < 0:
            problems.append(_problem(src, line, "an <Event> without </Event>"))
            continue
        chunk = chunk[:end + len("</Event>")]
        if "<!DOCTYPE" in chunk or "<!ENTITY" in chunk:
            problems.append(_problem(src, line, "DOCTYPE or ENTITY in an event: not read"))
            continue
        try:
            event = ET.fromstring(chunk)
        except ET.ParseError as exc:
            problems.append(_problem(src, line, "XML: %s" % exc))
            continue
        provider = event_id = record_id = None
        data = {}
        for el in event.iter():
            tag = el.tag.rsplit("}", 1)[-1]
            if tag == "Provider":
                provider = el.get("Name")
            elif tag == "EventID":
                event_id = _int(el.text or "")
            elif tag == "EventRecordID":
                record_id = _int(el.text or "")
            elif tag == "Data" and el.get("Name"):
                data[el.get("Name")] = (el.text or "").strip()
        if provider != SYSMON_PROVIDER or (ids is not None and event_id not in ids):
            continue
        yield {"line": line, "event": event_id, "record_id": record_id, "data": data}


def _sysmon_records(src, line, event_id, d, problems, keyed=False):
    """The records of one Sysmon event, all with one rendering of its line:
    the event itself, and a process record derived from its Image (and, for
    event 1, from its Parent fields) so a talker has a name."""
    pid, ts = _int(d.get("ProcessId", "")), _ts(d.get("UtcTime"))
    image = d.get("Image") or None
    guid = _guid_text(d.get("ProcessGuid"))   # M7.9: the process's own key (None where the event has none)
    if pid is None:
        problems.append(_problem(src, line, "Sysmon event %d without a ProcessId" % event_id))
        return []
    head = "Sysmon %d %s pid %d %s" % (event_id, d.get("UtcTime", "-"), pid, image or "-")
    if event_id == 1:
        ppid, parent = _int(d.get("ParentProcessId", "")), d.get("ParentImage") or None
        text = "%s parent %s %s: %s" % (head, d.get("ParentProcessId", "-"), parent or "-", d.get("CommandLine", ""))
        out = [_rec("proc", src, line, text, pid=pid, ppid=ppid, image=image_name(image), exe=image,
                    argv=win_argv(d.get("CommandLine")), cwd=d.get("CurrentDirectory") or None,
                    env_keys=None, ts=ts)]
        if keyed:
            out[0].update(guid=guid, pguid=_guid_text(d.get("ParentProcessGuid")), created=True)
        if ppid is not None:
            out.append(_rec("proc", src, line, text, pid=ppid, ppid=None, image=image_name(parent),
                            exe=parent, argv=win_argv(d.get("ParentCommandLine")), cwd=None,
                            env_keys=None, ts=ts, derived=True))
            if keyed:
                out[-1]["guid"] = _guid_text(d.get("ParentProcessGuid"))
        return out
    event = None
    if event_id == 3 and (d.get("Protocol") or "tcp").lower() == "tcp":
        # Source is the side that initiated: for an inbound connection the
        # local end is the destination.
        out = d.get("Initiated", "").lower() == "true"
        local, remote = ("Source", "Destination") if out else ("Destination", "Source")
        laddr, raddr = _ip(d.get(local + "Ip")), _ip(d.get(remote + "Ip"))
        lport, rport = _int(d.get(local + "Port", "")), _int(d.get(remote + "Port", ""))
        if None in (raddr, laddr, rport, lport):
            problems.append(_problem(src, line, "Sysmon 3 without addresses and ports"))
            text = head
        else:
            host = (d.get("DestinationHostname") or "").lower().rstrip(".") if out else ""
            host = "" if host == "-" else host
            text = "%s %s:%s %s %s:%s host=%s" % (head, laddr, lport, "->" if out else "<-", raddr, rport,
                                                  host or "-")
            event = _rec("conn", src, line, text, pid=pid, comm=None, state="CONNECT", laddr=laddr,
                         lport=lport, raddr=raddr, rport=rport, ts=ts, host=host or None,
                         direction="out" if out else "in", basis="initiated")
    elif event_id == 3:
        text = "%s %s" % (head, d.get("Protocol"))
    elif event_id == 22:
        name = (d.get("QueryName") or "").lower().rstrip(".")
        text = "%s query %s -> %s" % (head, name, d.get("QueryResults", ""))
        event = _rec("dns", src, line, text, pid=pid, names=[name] if name else [],
                     ips=_sysmon_ips(d.get("QueryResults")), ts=ts)
    else:
        path = d.get("TargetFilename") or None
        text = "%s wrote %s" % (head, path)
        event = _rec("file", src, line, text, pid=pid, path=path, ts=ts) if path else None
    own = _rec("proc", src, line, text, pid=pid, ppid=None, image=image_name(image), exe=image,
               argv=[], cwd=None, env_keys=None, ts=ts, derived=True)
    out = [own] + ([event] if event else [])
    return out if not keyed else [dict(r, guid=guid) for r in out]


GUID_TEXT = re.compile(r"\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?\Z")


def _guid_text(value):
    """A ProcessGuid as one text ({...}, lower case), or None (absent, or not a GUID)."""
    value = (value or "").strip()
    if not GUID_TEXT.match(value):
        return None
    return "{%s}" % value.strip("{}").lower()


def parse_footprints(text, src="footprints"):
    """One path per line; "#" lines are comments; "!hole TEXT" lines are
    read failures of the scan (B-3)."""
    records = []
    for number, raw in _numbered(text):
        path = raw.strip()
        if path.startswith("!hole "):
            records.append(_rec("hole", src, number, raw, note=path[len("!hole "):]))
        elif path and not path.startswith("#"):
            records.append(_rec("path", src, number, raw, path=path))
    return records, []


PARSERS = {"proc": parse_proc, "proc-net": parse_proc_net, "ss": parse_ss,
           "win-process": parse_win_process, "win-tcp": parse_win_tcp, "win-dns": parse_win_dns,
           "sysmon": parse_sysmon, "footprints": parse_footprints}


# --- live readers (read-only; Linux /proc and /proc/net; homes anywhere) ---------------------

def _read_bytes(path):
    with open(path, "rb") as f:
        return f.read()


def _try(fn):
    try:
        return fn()
    except (OSError, ValueError):
        return None


def _sockets(fd_dir, own=False):
    """Socket inodes among a process's open files (/proc/PID/fd links). Any
    failure - the fd directory or one link - makes the set unknown (an
    OSError), never a partial list (D-3). The one exception is the reader's
    own fd directory (own=True): the descriptor its listing used is closed
    before it is read back, so that ENOENT is expected and skipped."""
    inodes = set()
    for fd in os.listdir(fd_dir):
        try:
            target = os.readlink(os.path.join(fd_dir, fd))
        except FileNotFoundError:
            if own:
                continue
            raise
        m = re.match(r"socket:\[([0-9]+)\]\Z", target)
        if m:
            inodes.add(int(m.group(1)))
    return sorted(inodes)


def snapshot_proc(proc_root="/proc", at=None, self_pid=None, note=None):
    """A proc.txt snapshot of every process: JSON lines, ASCII. Reads status,
    cmdline, environ (names kept, values dropped at once), the cwd link, the
    socket inodes among the fd links and the exe link (G-2: `exe`, null and
    listed in `unread` when it cannot be read); writes nothing to /proc and
    touches no process (A4). Kernel threads are left out only when pid 2's
    status Name is kthreadd (B-3); a process that ended while read and one
    whose status could not be read are counted apart."""
    at = at or iso(datetime.datetime.now(datetime.timezone.utc))
    try:
        names = [n for n in os.listdir(proc_root) if n.isdigit()]
    except OSError as exc:
        raise OSError("cannot list %s: %s" % (proc_root, exc.strerror or exc))
    status = {}
    gone = unreadable = 0
    for name in names:
        try:
            status[int(name)] = status_fields(_read_bytes(os.path.join(proc_root, name, "status"))
                                              .decode("utf-8", "replace"))
        except FileNotFoundError:
            gone += 1
        except (OSError, ValueError):
            unreadable += 1
    kernel_parent = 2 if status.get(2, {}).get("Name") == "kthreadd" else None
    # M7.8 REDO R-5, REDO 2 T-4: each process's start as the kernel gives it, /proc/PID/stat starttime (clock
    # ticks since boot: the key, which a step of the wall clock does not move), and for display only the time
    # computed from it with /proc/stat btime where the clock tick rate is known (proc_start_times: no os.sysconf
    # where the platform has none). A pid whose stat cannot be read gets neither key and is counted (start_unread).
    ticks = {}
    for pid in status:
        try:
            got = parse_stat_starttime(_read_bytes(os.path.join(proc_root, str(pid), "stat")).decode("utf-8", "replace"))
        except OSError:
            got = None
        if got is not None:
            ticks[pid] = got
    starts, _ = proc_start_times(list(ticks), proc_root)
    procs, kernel = [], 0
    for pid in sorted(status):
        fields = status[pid]
        ppid = _int(fields.get("PPid", ""))
        if ppid is None:
            unreadable += 1
            continue
        if kernel_parent is not None and kernel_parent in (pid, ppid):
            kernel += 1
            continue
        base = os.path.join(proc_root, str(pid))
        unread = []

        def get(field, fn):
            try:
                return fn()
            except (OSError, ValueError):
                unread.append(field)
                return None
        procs.append({"pid": pid, "ppid": ppid, "name": fields.get("Name"),
                      "argv": get("cmdline", lambda: cmdline_args(_read_bytes(os.path.join(base, "cmdline")))),
                      "cwd": get("cwd", lambda: os.readlink(os.path.join(base, "cwd"))),
                      "env_keys": get("environ", lambda: environ_keys(_read_bytes(os.path.join(base, "environ")))),
                      "sockets": get("fd", lambda: _sockets(os.path.join(base, "fd"), own=pid == self_pid)),
                      "exe": get("exe", lambda: os.readlink(os.path.join(base, "exe"))),
                      "unread": unread, "at": at})
        if pid in ticks:
            procs[-1]["start_ticks"] = ticks[pid]
        if pid in starts:
            procs[-1]["started"] = starts[pid]
    meta = {"snapshot": at, "self": self_pid, "processes": len(procs), "kernel_threads": kernel,
            "kernel_parent": kernel_parent, "gone_while_read": gone, "unreadable": unreadable,
            "start_unread": sum(1 for p in procs if p["pid"] not in ticks)}   # T-8: counted, said by build()
    if note:
        meta["note"] = note
    return "".join(json.dumps(x, sort_keys=True, ensure_ascii=True) + "\n" for x in [meta] + procs)


def read_proc_net(proc_root="/proc", at=None):
    """(proc-net.txt text or None, error or None): /proc/net/tcp and
    /proc/net/tcp6 as the kernel prints them, each opened by "# at TIME
    (FILE)". Only a missing tcp6 file (ENOENT) is a "!hole" line (no IPv6
    table); any other failure on tcp or tcp6 is an error of the source
    (D-2). Text None: tcp could not be read (then ss is the fallback)."""
    out, errors, tcp_ok = [], [], False
    for name in ("tcp", "tcp6"):
        path = os.path.join(proc_root, "net", name)
        try:
            text = _read_bytes(path).decode("ascii", "replace")
        except FileNotFoundError as exc:
            if name == "tcp6":
                out.append("!hole %s not present (%s): no IPv6 table\n" % (path, exc.strerror or exc))
            else:
                errors.append("cannot read %s: %s" % (path, exc.strerror or exc))
            continue
        except OSError as exc:
            errors.append("cannot read %s: %s" % (path, exc.strerror or exc))
            continue
        tcp_ok = tcp_ok or name == "tcp"
        out.append("# at %s (%s)\n%s" % (at, path, text if text.endswith("\n") or not text else text + "\n"))
    return ("".join(out) if tcp_ok else None), ("; ".join(errors) or None)


def run_ss(path, args=SS_ARGS, at=None):
    """(text, error) of one ss run, opened by a "# at" line. The program is
    given by absolute path and runs with a minimal environment: no PATH
    lookup, nothing an agent's shell exported (B-1)."""
    if not os.path.isabs(path):
        return None, "%s is not an absolute path: ss is never looked up through PATH" % path
    env = {"LC_ALL": "C"}
    if os.name == "nt" and os.environ.get("SYSTEMROOT"):
        env["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    try:
        proc = subprocess.run([path] + list(args), capture_output=True, text=True, timeout=30,
                              stdin=subprocess.DEVNULL, env=env)
    except FileNotFoundError:
        return None, "%s not found" % path
    except (OSError, subprocess.SubprocessError) as exc:
        return None, "%s failed: %s" % (path, exc)
    if proc.returncode != 0:
        return None, "%s exited %d: %s" % (path, proc.returncode, bounded(proc.stderr.strip(), 160))
    return "# at %s (%s)\n%s" % (at, " ".join([path] + list(args)), proc.stdout), None


def parse_ss_bytes(text, src="ss-info"):
    """M7.4 E1 (API for raqib/host.py): the byte counts of `ss -tinp`
    output: ({"PID REMOTE": {"bytes_sent", "bytes_received", "sockets"}},
    problems, counts). REMOTE is "ip:port" as the inventory's talks name it;
    the counts of the sockets one pid holds to one remote are summed; a
    count ss does not print is None (an older ss or kernel). ss prints a
    socket's TCP info on the indented line after it. A socket with no owner
    (ss -p shows another user's sockets without one) is counted in
    counts["no_owner"], never attributed. Pure."""
    socks, problems = [], []
    for number, raw in _numbered(text or ""):
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if raw[:1] in (" ", "\t"):
            if socks and socks[-1] is not None:
                socks[-1]["info"] += " " + line.strip()
            continue
        fields = line.split()
        if fields[0] in ("State", "Netid", "Recv-Q"):
            continue
        if len(fields) < 5:
            problems.append(_problem(src, number, "fewer than 5 columns"))
            socks.append(None)
            continue
        state, local, peer = _state(fields[0]), _hostport(fields[3]), _hostport(fields[4])
        if state is None or local is None or peer is None or peer[1] is None:
            problems.append(_problem(src, number, "cannot read state or addresses (run ss with -n)"))
            socks.append(None)
            continue
        socks.append({"remote": "%s:%s" % peer, "pids": sorted({int(pid) for _, pid in USERS.findall(
            " ".join(fields[5:]))}), "info": " ".join(fields[5:])})
    out = {}
    counts = {"sockets": 0, "with_bytes": 0, "no_owner": 0}
    for s in socks:
        if s is None:
            continue
        counts["sockets"] += 1
        found = dict(SS_BYTES.findall(s["info"]))
        if found:
            counts["with_bytes"] += 1
        if not s["pids"]:
            counts["no_owner"] += 1
            continue
        for pid in s["pids"]:
            e = out.setdefault("%d %s" % (pid, s["remote"]), {"bytes_sent": None, "bytes_received": None,
                                                              "sockets": 0})
            e["sockets"] += 1
            for name in ("sent", "received"):
                if name in found:
                    e["bytes_" + name] = (e["bytes_" + name] or 0) + int(found[name])
    return out, problems, counts


def read_conn_bytes(ss_paths=SS_PATHS, at=None):
    """M7.4 E1 (API for raqib/host.py): (byte counts or None, label, hole or
    None) of this host's TCP sockets, from `ss -tinp` run by run_ss (an
    absolute path of ss_paths, a minimal environment, read-only: ss reads
    the kernel's socket table and changes nothing). A missing ss, a failed
    run, or an ss that prints no bytes_sent / bytes_received for any socket
    is a named hole (A3), never zero bytes."""
    path = find_ss(ss_paths)
    if path is None:
        return None, "ss (none found)", "no ss at %s: the bytes of the connections are not read" % ", ".join(ss_paths)
    label = " ".join([path] + list(SS_INFO_ARGS))
    text, error = run_ss(path, SS_INFO_ARGS, at)
    if text is None:
        return None, label, "%s: the bytes of the connections are not read" % error
    got, problems, counts = parse_ss_bytes(text)
    holes = []
    if counts["sockets"] and not counts["with_bytes"]:
        holes.append("%s printed no bytes_sent or bytes_received for any of %d socket(s) (no -i byte counts in this"
                     " ss or kernel): the bytes of the connections are not read" % (label, counts["sockets"]))
        got = None
    if problems:
        holes.append("%s: %d line(s) could not be read" % (label, len(problems)))
    if counts["no_owner"]:
        holes.append("%s: %d socket(s) with no owner shown (another user's): their bytes are not attributed" % (
            label, counts["no_owner"]))
    return got, label, "; ".join(holes) or None


def parse_btime(text):
    """M7.4 REDO K-5 (API for raqib/host.py): the boot time (seconds since
    the epoch) of /proc/stat's `btime` line, or None. Pure."""
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] == "btime" and parts[1].isdigit():
            return int(parts[1])
    return None


def parse_stat_starttime(text):
    """M7.4 REDO K-5 (API): field 22 of /proc/PID/stat (starttime, in clock
    ticks since boot), or None. The comm field (2) is in parentheses and may
    hold spaces and parentheses itself, so the fields are read after the
    LAST ')'. Pure."""
    text = text or ""
    close = text.rfind(")")
    if close < 0:
        return None
    rest = text[close + 1:].split()
    # rest[0] is field 3 (state); starttime is field 22, so rest[19]
    if len(rest) < 20 or not rest[19].isdigit():
        return None
    return int(rest[19])


def proc_start_times(pids, proc_root="/proc", clk_tck=None):
    """M7.4 REDO K-5 (API for raqib/host.py): ({pid: ISO UTC start time},
    hole or None) of each pid, from /proc/PID/stat's starttime and
    /proc/stat's btime: start = btime + starttime / CLK_TCK. Read-only
    (A4): two files are opened for reading, nothing is written, no process
    is touched. A pid whose stat cannot be read (it ended, or is another
    user's and hidden) is left out and counted in the hole text; no btime
    or no clock tick rate is a hole for every pid. Never a guessed time."""
    pids = sorted({p for p in pids if isinstance(p, int) and not isinstance(p, bool) and p > 0})
    if not pids:
        return {}, None
    try:
        btime = parse_btime(_read_bytes(os.path.join(proc_root, "stat")).decode("ascii", "replace"))
    except OSError as exc:
        return {}, "cannot read %s: %s: no child start time is read" % (
            os.path.join(proc_root, "stat"), exc.strerror or exc)
    if btime is None:
        return {}, "%s has no btime line: no child start time is read" % os.path.join(proc_root, "stat")
    if clk_tck is None:
        try:
            clk_tck = os.sysconf("SC_CLK_TCK")
        except (AttributeError, ValueError, OSError):
            clk_tck = None
    if not (isinstance(clk_tck, int) and clk_tck > 0):
        return {}, "no clock tick rate (SC_CLK_TCK): no child start time is read"
    out, missed = {}, 0
    for pid in pids:
        try:
            ticks = parse_stat_starttime(_read_bytes(os.path.join(proc_root, str(pid), "stat"))
                                         .decode("utf-8", "replace"))
        except OSError:
            ticks = None
        if ticks is None:
            missed += 1
            continue
        out[pid] = iso(datetime.datetime.fromtimestamp(btime + ticks / float(clk_tck), datetime.timezone.utc))
    hole = None
    if missed:
        hole = ("%d of %d child pid(s) had no readable %s/PID/stat starttime (ended before it was read, or"
                " hidden): their act time is the round's" % (missed, len(pids), proc_root))
    return out, hole


def find_ss(paths=SS_PATHS):
    """The first of a fixed list of absolute paths that is a file, or None."""
    return next((p for p in paths if os.path.isabs(p) and os.path.isfile(p)), None)


def default_homes(platform=None):
    platform = platform or sys.platform
    if platform == "win32":
        base = os.path.join(os.environ.get("SystemDrive", "C:") + os.sep, "Users")
        found = [os.environ.get("USERPROFILE", "")]
    else:
        base = "/home"
        found = [os.path.expanduser("~"), "/root"]
    try:
        found += [os.path.join(base, n) for n in sorted(os.listdir(base))]
    except OSError:
        pass
    homes = []
    for h in found:
        if h and os.path.isdir(h) and os.path.abspath(h) not in homes:
            homes.append(os.path.abspath(h))
    return homes


def scan_footprints(homes, catalog):
    """footprints.txt for some homes: the paths that match a catalog footprint.
    Only names are listed; no file is opened. A home that cannot be listed,
    and a matching path with a control character (it could forge a line),
    are "!hole" lines (B-3)."""
    lines = ["# raqib discover: footprint listing (paths only; nothing opened)"]
    for home in homes:
        try:
            names = sorted(os.listdir(home))
        except OSError as exc:
            lines.append("!hole home %s not readable: %s" % (_safe(home), exc.strerror or exc))
            continue
        lines.append("# home %s: %d entries" % (_safe(home), len(names)))
        found = []
        for fp in catalog["footprints"]:
            parts = fp["match"].split("/")
            if len(parts) == 1:
                found += [os.path.join(home, n) for n in names if fnmatch.fnmatchcase(n.lower(), parts[0].lower())]
            elif os.path.lexists(os.path.join(home, *parts)):
                found.append(os.path.join(home, *parts))
        odd = [p for p in found if any(not c.isprintable() for c in p)]
        lines += sorted(set(found) - set(odd))
        if odd:
            lines.append("!hole home %s: %d matching names with control characters not listed"
                         % (_safe(home), len(set(odd))))
    return "\n".join(lines) + "\n"


WIN_SAMPLES, WIN_EVERY = 6, 10.0   # M7.1: the docs/GUIDE.md loop's defaults, live


def collect_live(catalog, window=0.0, homes=None, platform=None, proc_root="/proc", ss_paths=SS_PATHS,
                 ss_args=SS_ARGS, interval=1.0, clock=time.time, sleep=time.sleep, win_samples=WIN_SAMPLES,
                 win_every=WIN_EVERY, api=None, run_info=None):
    """({kind: (label, text or None, error or None)} read from this host, the
    holes of the live run, the number of samples taken). On Linux: a /proc
    snapshot and /proc/net/tcp
    (+tcp6) every `interval` seconds for `window` seconds (0: one snapshot);
    ss from `ss_paths` only for a sample whose /proc/net/tcp could not be
    read. A source that failed in any sample keeps its text and an error,
    so the run is incomplete, not clean (B-2, D-2) - also when ss stood in.
    On Windows (M7.1): `win_samples` samples `win_every` seconds apart read
    by raqib/hostwin.py through `api` (default: the real Win32 API) as
    win-process-<k>, win-tcp-<k> and win-dns-<k>, the shapes of the docs/GUIDE.md
    loop; run_info (a dict) receives the APIs read and the sample times for
    run.json; a failed process snapshot raises LiveRefused.
    Elsewhere: the homes only. Read-only (A4)."""
    platform = platform or sys.platform
    texts, holes = {}, []
    samples = 0
    if platform.startswith("linux"):
        fallbacks = 0
        parts = {"proc": [], "proc-net": [], "ss": []}
        errors = {"proc": [], "proc-net": [], "ss": []}
        ss_path = None
        start = clock()
        while True:
            samples += 1
            at = iso(datetime.datetime.fromtimestamp(clock(), datetime.timezone.utc))
            try:
                parts["proc"].append(snapshot_proc(proc_root, at, os.getpid()))
            except OSError as exc:
                errors["proc"].append(str(exc))
            text, error = read_proc_net(proc_root, at)
            if error:
                errors["proc-net"].append(error)
            if text is not None:
                parts["proc-net"].append(text)
            else:
                fallbacks += 1
                ss_path = ss_path or find_ss(ss_paths)
                text, error = run_ss(ss_path, ss_args, at) if ss_path else (
                    None, "no ss at %s" % ", ".join(ss_paths))
                if text is None:
                    errors["ss"].append(error)
                else:
                    parts["ss"].append(text)
            if clock() - start >= window:
                break
            sleep(interval)
        labels = {"proc": "live %s" % proc_root,
                  "proc-net": "live %s" % ", ".join(os.path.join(proc_root, "net", n) for n in ("tcp", "tcp6")),
                  "ss": "live fallback: %s" % " ".join([ss_path or "ss (none found)"] + list(ss_args))}

        def entry(kind, out_of):
            failed = sorted(set(errors[kind]))
            error = ("%d of %d sample(s) failed: %s" % (len(errors[kind]), out_of, "; ".join(failed))
                     if failed else None)
            return labels[kind], "".join(parts[kind]) if parts[kind] else None, error

        texts["proc"] = entry("proc", samples)
        texts["proc-net"] = entry("proc-net", samples)
        if fallbacks:
            holes.append("ss fallback used for %d of %d sample(s): %s" % (fallbacks, samples, ss_path or "none found"))
            texts["ss"] = entry("ss", fallbacks)
    elif platform == "win32":
        # M7.1 (ADR-0007): the host's own records through the OS API, in-process.
        from raqib import hostwin
        try:     # ADR-0007 A-6: only the API load is "cannot be loaded"
            api = hostwin.Api() if api is None else api
        except (OSError, AttributeError) as exc:     # a DLL or symbol of kernel32/iphlpapi missing
            raise LiveRefused("Windows live discovery: the API cannot be loaded: %s" % exc)
        from raqib import notify
        system_root, _ = notify.windows_root(os.environ)   # D-3: run.json records its drive
        try:
            got, more, info = hostwin.collect(api, win_samples, win_every, os.getpid(), sleep, system_root=system_root)
        except hostwin.HostError as exc:
            raise LiveRefused("Windows live discovery: %s" % exc)
        except hostwin.ReaderFailed as exc:
            raise LiveRefused(str(exc))
        texts.update(got)
        holes += more
        samples = win_samples
        if run_info is not None:
            run_info.update(info)
    else:
        holes.append("no live process or connection reader on %s: export the Win32_Process,"
                     " Get-NetTCPConnection and Get-DnsClientCache CSVs (the docs/GUIDE.md loop,"
                     ' "Find the agents on a host (discover)") or Sysmon XML and give them with --read or --from'
                     " (docs/GUIDE.md)" % platform)
    homes = default_homes(platform) if homes is None else list(homes)
    texts["footprints"] = ("live: homes %s" % (", ".join(homes) or "(none)"), scan_footprints(homes, catalog), None)
    return texts, holes, samples


def read_inputs(paths):
    """{kind: (path, text or None, error or None)} for {kind: path}."""
    texts = {}
    for kind, path in paths.items():
        try:
            texts[kind] = (path, decode(_read_bytes(path)), None)
        except OSError as exc:
            texts[kind] = (path, None, "cannot read: %s" % (exc.strerror or exc))
    return texts


def split_name(name):
    """(kind, sample) of a source name: "win-tcp-3" is ("win-tcp", 3), "proc"
    is ("proc", None); None for a name that is no source (E1)."""
    if name in SOURCES:
        return name, None
    m = SAMPLE_NAME.match(name or "")
    return (m.group(1), int(m.group(2))) if m else None


def file_name(name):
    """The file of a source name: win-tcp.csv for win-tcp, win-tcp-3.csv for win-tcp-3."""
    kind, sample = split_name(name)
    return FILE_NAMES[kind] if sample is None else "%s-%d.csv" % (kind, sample)


def _order(name):
    kind, sample = split_name(name)
    return SOURCES.index(kind), sample or 0


def inputs_in(directory):
    """{name: path} for the known source files present in a directory: the
    files of FILE_NAMES, and the numbered samples of the docs/GUIDE.md loop
    (win-process-<k>.csv, win-tcp-<k>.csv, win-dns-<k>.csv; E1)."""
    found = {kind: os.path.join(directory, FILE_NAMES[kind]) for kind in SOURCES
             if os.path.isfile(os.path.join(directory, FILE_NAMES[kind]))}
    try:
        names = os.listdir(directory)
    except OSError:
        names = []
    for n in names:
        if n.endswith(".csv") and split_name(n[:-4]) and split_name(n[:-4])[1] is not None \
                and os.path.isfile(os.path.join(directory, n)):
            found[n[:-4]] = os.path.join(directory, n)
    return {k: found[k] for k in sorted(found, key=_order)}


def window_gaps(texts, directory, declared=None):
    """The holes of a Windows window (E1, A3), and an unread entry in texts
    for every sample 1..N that has no process or no connection file, so the
    run is incomplete: N is run.json's declared count, else the highest
    sample found (a loop cut short after it is then not seen)."""
    have = {}
    for name in texts:
        kind, sample = split_name(name)
        if sample is not None:
            have.setdefault(kind, set()).add(sample)
    found = set().union(*have.values()) if have else set()
    if not found and declared is None:
        return []
    holes = []
    top = declared if declared is not None else max(found)
    why = ("run.json declares %d sample(s)" % declared if declared is not None
           else "no run.json: the highest sample found is %d" % top)
    for k in range(1, top + 1):
        for kind in SAMPLE_NEEDS:
            if k not in have.get(kind, ()):
                name = "%s-%d" % (kind, k)
                texts[name] = (os.path.join(directory, file_name(name)), None,
                               "sample %d of %d: %s missing (%s)" % (k, top, file_name(name), why))
        if have.get("win-dns") and k not in have["win-dns"]:
            holes.append("sample %d of %d: win-dns-%d.csv missing, beside the DNS cache of other samples: names"
                         " recorded in that sample are not read" % (k, top, k))
    beyond = sorted(k for k in found if k > top)
    if beyond:
        holes.append("sample(s) %s read beyond the %d that run.json declares" % (", ".join(map(str, beyond)), top))
    if declared is None:
        holes.append("no run.json beside the numbered samples: the sample count is taken as the highest found"
                      " (%d); a loop that stopped after it is not seen (the docs/GUIDE.md loop,"
                      ' "Find the agents on a host (discover)", writes run.json first)' % top)
    return holes


RUN_FILE = "run.json"


def _samples_field(run):
    samples = run.get("samples")
    if samples is not None and not (isinstance(samples, int) and not isinstance(samples, bool)
                                    and 1 <= samples <= SAMPLES_MAX):
        raise ValueError("samples must be a whole number from 1 to %d" % SAMPLES_MAX)
    return samples


def save(texts, directory, holes=(), samples=None, extra=None):
    """Write the texts of a live run and a run.json - each source's label
    and error, the connections it was read from, the live holes and the
    number of samples taken (E1) - so the run can be repeated with --from
    (A5) and a replay of an incomplete run is incomplete too (D-4). extra:
    more run.json fields (M7.1: the Windows live run's export, APIs read,
    sample times and seconds apart); it never replaces a field above."""
    os.makedirs(directory, exist_ok=True)
    written, sources = [], {}
    for kind, (label, text, error) in texts.items():
        sources[kind] = {"label": label, "file": file_name(kind) if text is not None else None, "error": error}
        if text is not None:
            path = os.path.join(directory, file_name(kind))
            with open(path, "w", encoding="utf-8", newline="\n") as f:
                f.write(text)
            written.append(path)
    run = dict(extra or {})
    run.update({"raqib": "discover-run", "version": 1, "sources": sources, "holes": list(holes),
                "connections_from": [texts[k][0] for k in sorted(texts, key=_order)
                                     if split_name(k)[0] in CONNECTION_SOURCES and texts[k][1] is not None]})
    if samples:
        run["samples"] = samples
    path = os.path.join(directory, RUN_FILE)
    with open(path, "w", encoding="ascii", newline="\n") as f:
        f.write(json.dumps(run, indent=2, sort_keys=True, ensure_ascii=True) + "\n")
    return written + [path]


def read_dir(directory):
    """(texts, holes) of a directory of source texts. With a run.json from
    --save, every source keeps its recorded label and error and the live
    holes come back, so a replay of an incomplete run is incomplete and the
    ss path survives (D-4). A run.json without sources is the docs/GUIDE.md loop's
    (E1): {"raqib": "discover-run", "samples": N}; the directory's files are
    read and every sample 1..N must be there (window_gaps). A ValueError if
    run.json cannot be read. Without run.json, proc-net.txt is read and an
    ss.txt beside it is ignored (B-1, D-8), and numbered samples are checked
    up to the highest found."""
    run_path = os.path.join(directory, RUN_FILE)
    if not os.path.isfile(run_path):
        paths = inputs_in(directory)
        holes = []
        if "proc-net" in paths and "ss" in paths:
            holes.append("%s ignored: %s is read first and ss is only its fallback (B-1)"
                         % (paths.pop("ss"), paths["proc-net"]))
        texts = read_inputs(paths)
        return texts, holes + window_gaps(texts, directory)
    try:
        run = json.loads(decode(_read_bytes(run_path)))
        if not isinstance(run, dict):
            raise ValueError("not a JSON object")
        samples = _samples_field(run)
        if "sources" not in run:
            if run.get("raqib") != "discover-run" or samples is None:
                raise ValueError("a run.json without sources must be the docs/GUIDE.md loop's"
                                 ' ("Find the agents on a host (discover)"): raqib discover-run and its samples count')
            texts = read_inputs(inputs_in(directory))
            return texts, window_gaps(texts, directory, samples)
        sources, saved_holes = run["sources"], run["holes"]
        if not (isinstance(sources, dict) and all(split_name(k) for k in sources) and isinstance(saved_holes, list)
                and all(isinstance(v, dict) and isinstance(v.get("label"), str) for v in sources.values())):
            raise ValueError("unknown source or field")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise ValueError("%s cannot be read: %s" % (run_path, exc))
    texts = {}
    for kind, src in sources.items():
        path = os.path.join(directory, file_name(kind))
        error = src.get("error") if isinstance(src.get("error"), str) else None
        text = None
        if src.get("file"):
            try:
                text = decode(_read_bytes(path))
            except OSError as exc:
                error = "; ".join(x for x in (error, "saved text %s missing: %s" % (path, exc.strerror or exc)) if x)
        texts[kind] = ("%s (saved from %s)" % (path, src["label"]), text, error)
    return texts, ["saved run: %s" % h for h in saved_holes if isinstance(h, str)]


# --- the inventory ---------------------------------------------------------------------

def cite(rec):
    return {"src": rec["src"], "line": rec["line"], "text": rec["text"]}


def _cites(recs, limit=CITES_PER_CLAIM, skip=()):
    """Up to `limit` distinct cited lines of some records, none of `skip`."""
    seen, out = {(c["src"], c["line"]) for c in skip}, []
    for r in recs:
        key = (r["src"], r["line"])
        if key not in seen:
            seen.add(key)
            out.append(cite(r))
    return out[:limit]


def _merge_procs(records):
    """pid -> process. Records read from a process list or Sysmon 1 come
    first; records derived from another event's Image field only fill gaps.
    The first value of a field wins; every image the pid had is kept (an
    exec keeps the pid)."""
    procs = {}
    own = [r for r in records if r["kind"] == "proc" and not r.get("derived")]
    derived = [r for r in records if r["kind"] == "proc" and r.get("derived")]
    for r in own + derived:
        p = procs.setdefault(r["pid"], {"pid": r["pid"], "ppid": None, "image": None, "images": [],
                                        "exe": None, "argv": [], "cwd": None, "env_keys": None,
                                        "sockets": None, "recs": [], "derived": True})
        p["recs"].append(r)
        if not r.get("derived"):
            p["derived"] = False
        for key in ("ppid", "exe", "cwd", "env_keys"):
            if p[key] is None and r.get(key) is not None:
                p[key] = r[key]
        if r.get("sockets") is not None:
            p["sockets"] = sorted(set(p["sockets"] or []) | set(r["sockets"]))
        if not p["argv"] and r.get("argv"):
            p["argv"] = r["argv"]
        if r.get("image") and r["image"] not in p["images"]:
            p["images"].append(r["image"])
        p["image"] = p["images"][0] if p["images"] else None
    return procs


def ancestors(procs, pid):
    """Parent pids from the nearest up; stops at a missing parent or a loop."""
    seen = {pid}
    p = procs.get(pid)
    while p is not None and p["ppid"] is not None and p["ppid"] not in seen:
        seen.add(p["ppid"])
        yield p["ppid"]
        p = procs.get(p["ppid"])


def _descendants(procs, pid):
    children = {}
    for q in procs.values():
        if q["ppid"] is not None:
            children.setdefault(q["ppid"], []).append(q["pid"])
    out, todo = set(), [pid]
    while todo:
        for c in children.get(todo.pop(), []):
            if c not in out and c != pid:
                out.add(c)
                todo.append(c)
    return out


def talks(conn):
    return (conn["direction"] == "out" and conn["state"] in TALK_STATES and conn["pid"] is not None
            and not _wildcard(conn["raddr"]))


def _config_write(path, exe):
    """A write into config, cache or temp space: a dot-directory, AppData,
    ProgramData, a temp directory, or the writer's own program directory."""
    norm = path.replace("\\", "/").lower()
    segments = [s for s in norm.split("/")[:-1] if s]
    if any(s.startswith(".") and s not in (".", "..") or s in CONFIG_SEGMENTS for s in segments):
        return True
    if exe:
        own = exe.replace("\\", "/").lower().rpartition("/")[0]
        if own and norm.startswith(own + "/"):
            return True
    return False


def names_of(p):
    """Names a process goes by, lower case: its images; the last part of its
    executable path, argv[0] and argv[1] (a script run by an interpreter),
    with and without extension; and an npm package name in those paths (the
    part after node_modules/ or node_modules/@scope/). Directory names are
    not names: /home/claude/x.py does not run as claude."""
    out = set(p["images"])
    for text in [p["exe"]] + p["argv"][:2]:
        parts = [x for x in re.split(r"[\\/]", text or "") if x]
        picks = parts[-1:]
        for i, part in enumerate(parts[:-1]):
            if part == "node_modules":
                nxt = parts[i + 1]
                picks.append(parts[i + 2] if nxt.startswith("@") and i + 2 < len(parts) - 1 else nxt)
        for part in picks:
            name = image_name(part)
            if name:
                out.add(name)
                out.add(name.rsplit(".", 1)[0])
    return out


def _named(p, agent):
    return any(n == agent or n.startswith(agent + "-") for n in names_of(p))


def _endpoint(conn, names, catalog):
    """Catalog matches (signature) of one outbound connection."""
    matches = []
    ip = ipaddress.ip_address(conn["raddr"])
    for n in catalog["networks"]:
        if ip.version == n["net"].version and ip in n["net"]:
            matches.append({"layer": "network", "match": n["cidr"], "vendor": n["vendor"]})
    if ip.is_loopback:
        for p in catalog["ports"]:
            if conn["rport"] == p["port"]:
                matches.append({"layer": "local-port", "match": p["port"], "vendor": p["name"]})
    for name in sorted(names):
        for h in catalog["hosts"]:
            if fnmatch.fnmatchcase(name, h["match"]):
                matches.append({"layer": "host", "match": h["match"], "name": name, "vendor": h["vendor"]})
    return matches


def _join_sockets(records, procs):
    """Connection records from /proc/net/tcp get their owners: one record
    per process whose fd links hold the socket inode (B-1). A socket no
    process is seen to hold keeps pid None."""
    owners = {}
    for p in procs.values():
        for inode in p["sockets"] or []:
            owners.setdefault(inode, []).append(p["pid"])
    out = []
    for r in records:
        if r["kind"] == "conn" and r.get("inode") and r["pid"] is None and r["inode"] in owners:
            out += [dict(r, pid=pid) for pid in sorted(owners[r["inode"]])]
        else:
            out.append(r)
    return out


def _listed(image, catalog):
    return bool(image) and any(fnmatch.fnmatchcase(image, g) for g in catalog["acts"])


# G-6: a pid whose CreationDate differs between Windows samples is two
# processes. The later instance gets an internal key pid + REUSE * n (n >= 1)
# while the tree is built; the inventory shows the OS pid again (_os_pids),
# and the cites tell the instances apart.
REUSE = 10 ** 10
PID_FIELDS = ("pid", "root")
PID_LISTS = ("via", "tree", "self")


def _process_sample(src):
    """The win-process source name of the sample a Windows record is from."""
    kind, sample = split_name(src) or (None, None)
    return ("win-process" if sample is None else "win-process-%d" % sample) if kind in SAMPLED else None


def _instances(records):
    """(records, holes): Windows records keyed by pid and CreationDate (G-6).
    A process record without CreationDate is a hole: reuse cannot be told for
    it, and it is merged by pid as before."""
    dates, seen, missing = {}, {}, set()
    for r in records:
        if r["kind"] == "proc" and split_name(r["src"]) and split_name(r["src"])[0] == "win-process":
            if r.get("started"):
                if r["started"] not in dates.setdefault(r["pid"], []):
                    dates[r["pid"]].append(r["started"])
                seen[(r["src"], r["pid"])] = r["started"]
            else:
                missing.add(r["pid"])
    holes = []
    if missing:
        shown = sorted(missing)
        holes.append("%d process(es) without CreationDate: a pid reused between samples cannot be told for them,"
                     " so they are merged by pid (G-6): pid %s%s" % (len(shown), ", ".join(map(str, shown[:20])),
                                                                      " and %d more" % (len(shown) - 20)
                                                                      if len(shown) > 20 else ""))
    reused = {pid: ds for pid, ds in dates.items() if len(ds) > 1}
    if not reused:
        return records, holes
    order = sorted({src for src, _ in seen}, key=_order)

    def key(pid, src):
        if pid not in reused or src is None:
            return pid
        started = seen.get((src, pid))
        if started is None:      # no record of the pid in this sample: the nearest earlier sample's instance
            earlier = [s for s in order if _order(s) <= _order(src) and (s, pid) in seen]
            started = seen[(earlier[-1], pid)] if earlier else reused[pid][0]
        n = reused[pid].index(started)
        return pid + REUSE * n if n else pid
    out = []
    for r in records:
        sample = _process_sample(r["src"])
        if sample is None or r.get("pid") is None:
            out.append(r)
            continue
        changed = {"pid": key(r["pid"], sample)}
        if r["kind"] == "proc" and r.get("ppid") is not None:
            changed["ppid"] = key(r["ppid"], sample)
        out.append(dict(r, **changed))
    for pid in sorted(reused):
        where = {}
        for (src, p), started in seen.items():
            if p == pid:
                where.setdefault(started, []).append(src)
        holes.append("pid %d was reused within the window: %s; keyed by pid and CreationDate, %d processes (G-6)" % (
            pid, "; ".join("CreationDate %s in %s" % (d, ", ".join(sorted(where[d], key=_order))) for d in reused[pid]),
            len(reused[pid])))
    return out, holes


def _os_pids(node):
    """The inventory with every internal key shown as its OS pid (G-6)."""
    if isinstance(node, dict):
        out = {}
        for k, v in node.items():
            if k in PID_FIELDS and isinstance(v, int) and not isinstance(v, bool):
                out[k] = v % REUSE
            elif k in PID_LISTS and isinstance(v, list):
                out[k] = [x % REUSE if isinstance(x, int) and not isinstance(x, bool) else x for x in v]
            else:
                out[k] = _os_pids(v)
        return out
    if isinstance(node, list):
        return [_os_pids(v) for v in node]
    return node


PROCESS_LISTS = ("proc", "win-process")   # M7.8: the sources that list the processes alive at a sample


GUID_SAME_SECONDS = 2.0   # M7.9: a sampled CreationDate and a Sysmon 1 UtcTime this close are one process's start


def _start_close(a, b):
    return a is not None and b is not None and abs((a - b).total_seconds()) <= GUID_SAME_SECONDS


def _guid_instances(records):
    """M7.9 (ADR-0007 P-4, E2; REDO X-2): (records, holes). Two records are
    one process only when what was read agrees: the pid, the image, and the
    start within GUID_SAME_SECONDS where it was read on both sides (a
    sampled CreationDate, a Sysmon 1 UtcTime). Each ProcessGuid of the
    round's channel is one process: it is the sampled process of its pid
    when the image and both starts agree; where a start was read on one side
    only, it is that process when it is the only one of that image on either
    side (said, once per round: a reuse by the same image is not told);
    otherwise it is its own process, keyed apart (pid + REUSE * n, as
    _instances keys a reused pid), and a child's ppid follows its
    ParentProcessGuid. Records without a guid are merged by pid as before."""
    guids, sampled = {}, {}
    for r in records:
        kind = (split_name(r["src"]) or (None,))[0]
        if kind == "sysmon" and r.get("guid") and r.get("pid") is not None:
            g = guids.setdefault(r["pid"], {}).setdefault(r["guid"], {"image": None, "start": None, "first": None})
            if r.get("ts") is not None:
                g["first"] = r["ts"] if g["first"] is None else min(g["first"], r["ts"])
            if r["kind"] == "proc" and r.get("image") and (g["image"] is None or r.get("created")):
                g["image"] = r["image"]
            if r["kind"] == "proc" and r.get("created") and r.get("ts") is not None and g["start"] is None:
                g["start"] = r["ts"]
        elif kind == "win-process" and r["kind"] == "proc" and not r.get("derived") and r.get("pid") is not None:
            entry = (r["pid"], r.get("image"), _ts(r["started"]) if r.get("started") else None)
            if entry not in sampled.setdefault(r["pid"] % REUSE, []):
                sampled[r["pid"] % REUSE].append(entry)
    remap, holes, untold = {}, [], []
    for pid in sorted(guids):
        insts, gs = sampled.get(pid, []), guids[pid]
        used, taken, apart = set(), set(k for k, _, _ in insts), []
        for g, info in gs.items():   # both starts read and agreeing, the same image
            match = next((k for k, image, s in insts if k not in used and image == info["image"]
                          and info["start"] is not None and _start_close(s, info["start"])), None)
            if match is not None:
                used.add(match)
                remap[g] = match
        for k, image, s in insts:    # a start read on one side only: the one process of that image, or none
            if k in used:
                continue
            # a process logs nothing before it was created: a guid with an event before the sampled start is not it
            free = [g for g, info in gs.items() if g not in remap and info["image"] == image
                    and (info["start"] is None or s is None)
                    and not (s is not None and info["first"] is not None
                             and (s - info["first"]).total_seconds() > GUID_SAME_SECONDS)]
            others = [x for x in insts if x[0] not in used and x[1] == image]
            # Z-5: unique on BOTH sides (one guid that can be it, one sampled process of the image), and never with
            # the sampled start unread
            if len(free) == 1 and len(others) == 1 and s is not None:
                used.add(k)
                remap[free[0]] = k
                untold.append(pid)
        for g in gs:                 # the rest: each its own process
            if g in remap:
                continue
            if not insts and not used:
                remap[g] = pid
            else:
                n = 1
                while pid + REUSE * n in taken:
                    n += 1
                remap[g] = pid + REUSE * n
                taken.add(remap[g])
                apart.append(g)
            used.add(remap[g])
        if apart or len(gs) > 1:
            holes.append("pid %d held %d process(es) in this round's channel (ProcessGuid %s)%s: keyed by ProcessGuid,"
                         " each its own process (M7.9)" % (
                             pid, len(gs), ", ".join(gs), ", %d beside the sampled one" % len(apart) if insts and apart
                             else ""))
    if untold:
        shown = sorted(set(untold))
        holes.append("%d process(es) whose start was read on one side only (the sample or the channel's event 1) were"
                     " taken for the sampled process of their pid and image: a reuse of the pid by the same image is"
                     " not told for them (M7.9): pid %s" % (len(shown), ", ".join(map(str, shown[:20]))))
    if not remap:
        return records, holes
    out = []
    for r in records:
        if (split_name(r["src"]) or (None,))[0] != "sysmon":
            out.append(r)
            continue
        changed = {}
        if r.get("guid") in remap:
            changed["pid"] = remap[r["guid"]]
        if r["kind"] == "proc" and r.get("pguid") in remap:
            changed["ppid"] = remap[r["pguid"]]
        out.append(dict(r, **changed) if changed else r)
    return out, holes


def _channel_fields(p):
    """M7.9 (API for raqib/host.py): what the round's channel says of a
    tree's root: guid (its ProcessGuid, or None), brief (no record of it
    from the round's process sample: seen in the channel only), and
    channel_started (its Sysmon 1 UtcTime as ISO UTC, where the round read
    its creation)."""
    recs = (p or {}).get("recs") or ()
    guid = next((r["guid"] for r in recs if r.get("guid") and not r.get("derived")), None) or next(
        (r["guid"] for r in recs if r.get("guid")), None)
    started = next((r["ts"] for r in recs if r.get("created") and r.get("ts") is not None), None)
    sampled = any(not r.get("derived") and (split_name(r["src"]) or (None,))[0] in PROCESS_LISTS for r in recs)
    return {"guid": guid, "brief": bool(recs) and not sampled, "channel_started": iso(started)}


def _acts_core(records, catalog, channel=False):
    """The anchor of build() (B-6), apart so that a round can be built
    again without its channel's records (M7.9 REDO 4, ADR-0007 AB-6):
    (records joined to their sockets, procs, conns, talkers, snapshots,
    self_pids, self_tree, self_line, acts). A talker with an act is a candidate."""
    snapshots = [r for r in records if r["kind"] == "snapshot"]
    self_pids = {r["self"] for r in snapshots if r.get("self") is not None}
    self_pids |= {p for r in snapshots for p in r.get("launchers") or ()}     # ADR-0007 A-7
    procs = _merge_procs(records)
    records = _join_sockets(records, procs)
    conns = [r for r in records if r["kind"] == "conn"]
    talkers = {}
    for c in conns:
        if talks(c):
            talkers.setdefault(c["pid"], []).append(c)
    self_tree = set()
    for s in self_pids:
        self_tree |= {s} | _descendants(procs, s)
    self_line = set()
    for s in self_pids:
        self_line |= set(ancestors(procs, s))

    # The anchor (B-6): every process goes to its nearest talking ancestor, so
    # a talker with a child is a candidate; a file write outside config space
    # goes to the nearest talking ancestor-or-self. The catalog's act names
    # only label the child.
    acts = {}
    for pid in sorted(procs):
        p = procs[pid]
        if pid in self_tree:
            continue
        chain = []
        for anc in ancestors(procs, pid):
            if anc in talkers:
                label = next((i for i in p["images"] if _listed(i, catalog)), None)
                acts.setdefault(anc, []).append({
                    "how": "process", "pid": pid, "image": label or p["image"], "listed": label is not None,
                    "path": None, "via": list(reversed(chain)), "reader_ancestor": pid in self_line,
                    "started": started_of(p) or (_channel_fields(p)["channel_started"] if channel else None),   # X-6
                    # M7.4 E1 (API): the child's creation time where the reader gives it (M7.9: or its Sysmon 1 time)
                    "cites": _cites(p["recs"])})
                break
            chain.append(anc)
    for f in (r for r in records if r["kind"] == "file"):
        writer = procs.get(f["pid"])
        if f["pid"] in self_tree or _config_write(f["path"], writer["exe"] if writer else None):
            continue
        owner = f["pid"] if f["pid"] in talkers else next(
            (a for a in ancestors(procs, f["pid"]) if a in talkers), None)
        if owner is not None:
            acts.setdefault(owner, []).append({
                "how": "file-write", "pid": f["pid"], "image": writer["image"] if writer else None,
                "listed": False, "path": f["path"], "via": [], "reader_ancestor": False, "cites": [cite(f)]})
    return records, procs, conns, talkers, snapshots, self_pids, self_tree, self_line, acts


NO_HOLDER = "pid %d (the tree that links it without the channel is no tree of this round: ADR-0007 AD-1)"


def _without_channel(records, parsed, catalog, candidates, act_roots):
    """ADR-0007 AB-6, AD-1: the same round built WITHOUT the channel's
    records (the sampled records keep their keys: _guid_instances moves
    Sysmon records only), so M7.9 does not change how a footprint is
    judged: {"roots": {root pid: "candidate" | "act-root"} of that build,
    "footprints", "dark"} - its footprints and AGENT-DARK, each link
    naming the tree of the channel's round that holds the linking tree's
    root (that root's own tree, else the larger tree it is part of), in
    the field of the class it has without the channel."""
    records = [r for r in records if (split_name(r["src"]) or (None,))[0] != "sysmon"]
    parsed = [s for s in parsed if s["kind"] != "sysmon"]
    records, procs, conns, talkers, snapshots, self_pids, self_tree, self_line, acts = _acts_core(records, catalog)
    ids = {pid: "C%d" % i for i, pid in enumerate(sorted(acts), start=1)}
    cands = [{"pid": pid, "id": ids[pid], "tree": [pid] + [a["pid"] for a in acts[pid] if a["how"] == "process"],
              "talking_ancestors": [{"pid": a} for a in ancestors(procs, pid) if a in talkers]} for pid in sorted(acts)]

    def held(role, kinds):
        return [s["name"] for s in parsed if s["text_read"] and s["kind"] in kinds
                and any(r["kind"] == role for r in s["records"])]
    trees_read = bool(held("proc", PROCESS_SOURCES)) and bool(held("conn", CONNECTION_SOURCES))
    roots = _act_roots(procs, talkers, self_tree, ids, catalog, held("conn", CONNECTION_SOURCES)) if (
        trees_read and catalog["act_root"]["status"] == "ok") else []
    footprints, dark = _footprints(records, procs, cands, talkers, catalog, judged=trees_read, act_roots=roots)
    root_of = dict([(c["id"], c["pid"]) for c in cands] + [(a["id"], a["pid"]) for a in roots])

    def holder(pid):
        for t in list(candidates) + list(act_roots):
            if t["pid"] == pid:
                return t["id"]
        for t in candidates:
            if pid in t["tree"]:
                return t["id"]
        return next((t["id"] for t in act_roots if any(a["pid"] == pid for a in t["acts"])), None)
    for f in footprints:
        for field in ("candidate", "act_root"):
            if f.get(field):
                f[field] = holder(root_of[f[field]]) or NO_HOLDER % (root_of[f[field]] % REUSE)
    return {"roots": dict([(c["pid"], "candidate") for c in cands] + [(a["pid"], "act-root") for a in roots]),
            "footprints": footprints, "dark": dark}


def build(parsed, catalog, window=None, holes=(), live=False, processes=False, channel=False):
    """The inventory (E5) of parsed sources:
    [{"name", "path", "error", "records", "problems", "lines"}].
    processes (M7.8, ADR-0007 P-2; API for raqib watch --host): the
    inventory also carries "processes", every process of the round's
    process sample - read from a process list (a /proc snapshot, a
    Win32_Process sample), never one known only from a Sysmon event - as
    {"pid", "image", "started"}, image and started as a tree's (image_name,
    started_of), so a tree's root can be looked up in it. Off by default:
    `raqib discover` and its --json are unchanged. channel (M7.9, ADR-0007
    P-4; API for raqib watch --host): the source sysmon is a round's read of
    the channel since the previous round: its Sysmon records are keyed by
    ProcessGuid (_guid_instances), each candidate and act-root carries
    _channel_fields, and a kind of event the window does not hold is not a
    gap of the round (the watch says once what the channel holds)."""
    holes = list(ALWAYS_HOLES) + list(holes)
    problems = [p for s in parsed for p in s["problems"]]
    records = [r for s in parsed for r in s["records"]]
    dropped = 0
    if window and not live:
        times = [r["ts"] for r in records if r.get("ts")]
        if times:
            cutoff = max(times) - datetime.timedelta(seconds=window)
            kept = [r for r in records if not r.get("ts") or r["ts"] >= cutoff]
            dropped, records = len(records) - len(kept), kept
    records, reuse_holes = _instances(records)
    if channel:
        records, guid_holes = _guid_instances(records)
        reuse_holes += guid_holes
    unjoined = records   # AB-6: the round's records before the anchor, for the round built without the channel
    records, procs, conns, talkers, snapshots, self_pids, self_tree, self_line, acts = _acts_core(
        records, catalog, channel)
    unowned = [c for c in conns if c["pid"] is None and c["direction"] == "out"
               and c["state"] in TALK_STATES and not _wildcard(c["raddr"])]
    orphans = sorted({c["pid"] for c in conns if talks(c) and c["pid"] not in procs})

    # DNS names per IP (any process) and per (pid, IP), with the lines behind them.
    by_ip, by_pid_ip = {}, {}
    for r in records:
        if r["kind"] == "dns":
            for ip in r["ips"]:
                for n in r["names"]:
                    by_ip.setdefault(ip, {}).setdefault(n, []).append(r)
                    if r["pid"] is not None:
                        by_pid_ip.setdefault((r["pid"], ip), {}).setdefault(n, []).append(r)

    def names_for(c):
        found = {}
        for table in (by_pid_ip.get((c["pid"], c["raddr"]), {}), by_ip.get(c["raddr"], {})):
            for n, recs in table.items():
                found.setdefault(n, []).extend(recs)
        if c.get("host"):
            found.setdefault(c["host"], []).append(c)
        return found


    candidates = []
    ids = {}
    for pid in sorted(acts):
        ids[pid] = "C%d" % (len(ids) + 1)
    endpoint_talkers = []
    for pid in sorted(talkers):
        p = procs.get(pid)
        groups = {}
        for c in talkers[pid]:
            groups.setdefault((c["raddr"], c["rport"]), []).append(c)
        talk = []
        for (raddr, rport), cs in sorted(groups.items(), key=lambda kv: (kv[1][0]["src"], kv[1][0]["line"])):
            names = {}
            for c in cs:
                for n, recs in names_for(c).items():
                    names.setdefault(n, []).extend(recs)
            matches = _endpoint(cs[0], names, catalog)
            name_recs = [r for m in matches if m["layer"] == "host" for r in names[m["name"]]]
            conn_cites = _cites(cs)
            talk.append({"remote": "%s:%s" % (raddr, rport),
                         "state": "/".join(sorted({c["state"] for c in cs})),
                         "basis": cs[0]["basis"], "lines": len(cs), "names": sorted(names),
                         "endpoint": matches, "cites": conn_cites + _cites(name_recs, 2, skip=conn_cites)})
        entry = {"pid": pid, "image": p["image"] if p else None, "exe": p["exe"] if p else None,
                 "talks": talk, "cites": _cites(p["recs"]) if p else []}
        if pid not in acts:
            if any(t["endpoint"] for t in talk):
                above = [ids[a] for a in _descendant_candidates(procs, pid, acts)]
                endpoint_talkers.append(dict(entry, above=above))
            continue
        tree = [pid] + [a["pid"] for a in acts[pid] if a["how"] == "process"]
        talking_up = [{"pid": a, "image": procs[a]["image"] if a in procs else None,
                       "cites": _cites(talkers[a], 1)} for a in ancestors(procs, pid) if a in talkers]
        inside = next((ids[a] for a in ancestors(procs, pid) if a in ids), None)
        env = sorted({k for k in ((p or {}).get("env_keys") or [])
                      if any(fnmatch.fnmatchcase(k, g) for g in catalog["env"])})
        times = [r["ts"] for r in ((p["recs"] if p else []) + talkers[pid]) if r.get("ts")]
        for a in acts[pid]:
            q = procs.get(a["pid"])
            times += [r["ts"] for r in (q["recs"] if q else []) if r.get("ts")]
        candidates.append(dict(
            entry, id=ids[pid], cwd=p["cwd"] if p else None, acts=acts[pid], inside=inside, started=started_of(p),
            exe_from=exe_from(p), **_shown_start(p),
            listed_acts=sum(1 for a in acts[pid] if a["listed"]),
            talking_ancestors=talking_up, tree=tree,
            env_footprints=[{"name": k, "cites": _cites(p["recs"], 1)} for k in env],
            seen={"first": iso(min(times)) if times else None, "last": iso(max(times)) if times else None,
                  "basis": "observed times in the cited records" if times
                  else "no observation time in the records (a snapshot without time)"},
            source=_handoff(pid, p, catalog)))

    read = {s["kind"] for s in parsed if s["text_read"]}

    def holds(s, role):
        """Whether a read source holds the records it must hold for a role
        (D-1: Sysmon is a process source only with an event 1, a connection
        source only with an event 3)."""
        if s["kind"] == "sysmon":
            return any(r.get("event") == (1 if role == "proc" else 3) for r in s["records"])
        return any(r["kind"] == role for r in s["records"])
    proc_held = {s["kind"] for s in parsed if s["text_read"] and s["kind"] in PROCESS_SOURCES and holds(s, "proc")}
    conn_held = {s["kind"] for s in parsed if s["text_read"] and s["kind"] in CONNECTION_SOURCES and holds(s, "conn")}
    trees_read = bool(proc_held) and bool(conn_held)
    recent = _recent_talk(conns, records, talkers, names_for, catalog)
    # "Talk not seen" is an observation only where talk could be seen: with
    # no connection record read, it is a gap (A3), and act-roots are unjudged.
    # A disabled act_root (G-8, the Table's act) judges nothing here.
    judge = trees_read and catalog["act_root"]["status"] == "ok"
    act_roots = _act_roots(procs, talkers, self_tree, ids, catalog,
                           [s["name"] for s in parsed if s["kind"] in CONNECTION_SOURCES and s["text_read"]
                            and holds(s, "conn")]) if judge else []
    bare = None
    if channel:   # ADR-0007 AD-1: the footprints are those of the same round built WITHOUT the channel's records
        bare = _without_channel(unjoined, parsed, catalog, candidates, act_roots)
        footprints, dark = bare["footprints"], bare["dark"]
    else:
        footprints, dark = _footprints(records, procs, candidates, talkers, catalog, judged=trees_read,
                                       act_roots=act_roots)
    env_fp = []
    owner_of = {}
    for c in candidates:
        for q in c["tree"]:
            owner_of.setdefault(q, c["id"])
    for pid in sorted(procs):
        p = procs[pid]
        keys = sorted({k for k in (p["env_keys"] or []) if any(fnmatch.fnmatchcase(k, g) for g in catalog["env"])})
        if keys:
            env_fp.append({"pid": pid, "image": p["image"], "names": keys, "candidate": owner_of.get(pid),
                           "cites": _cites(p["recs"], 1)})

    # Every read failure is a hole (B-3), and every gap in a process or
    # connection source makes the run incomplete (B-2).
    incomplete = []
    holes += _holes(records, procs, conns, read)
    holes += reuse_holes
    if catalog["act_root"]["status"] != "ok":
        holes.append("act-root not judged: act_root has status %s in %s (G-8, A6)"
                     % (catalog["act_root"]["status"], catalog["path"]))
    elif not trees_read:
        holes.append("act-root not judged: no process source and connection source both hold records, so a"
                     " tree's talk cannot be told from a gap")
    # G-4: an image path the export left blank places nothing.
    blank = sorted({p["pid"] % REUSE for p in procs.values() if p["pid"] % REUSE not in (0, 4) and not p["exe"]
                    and any(split_name(r["src"])[0] == "win-process" for r in p["recs"] if split_name(r["src"]))})
    if blank:
        holes.append("%d process(es) without image path (export not elevated?): act-root cannot place them: pid %s%s"
                     % (len(blank), ", ".join(map(str, blank[:20])), " and %d more" % (len(blank) - 20)
                        if len(blank) > 20 else ""))
    # G-2: an exe link that could not be read places by argv[0] only.
    unplaced = [p for p in sorted(procs.values(), key=lambda q: q["pid"])
                if any("exe" in (r.get("unread") or []) for r in p["recs"])]
    if unplaced:
        holes.append("act-root could not place %d process(es) (exe unreadable): their argv[0], which a process writes"
                     " itself, is used instead: %s%s" % (
                         len(unplaced), ", ".join("pid %d (%s)" % (p["pid"] % REUSE, _cite_text(_cites(p["recs"], 1)))
                                                  for p in unplaced[:20]),
                         " and %d more" % (len(unplaced) - 20) if len(unplaced) > 20 else ""))
    # G-10: an unnumbered file beside numbered samples of its kind, from --from or --read.
    mixed = [k for k in SAMPLED if any(s["kind"] == k and s["sample"] is None for s in parsed)
             and any(s["kind"] == k and s["sample"] is not None for s in parsed)]
    if mixed:
        holes.append("%s read beside numbered samples of the same kind: merged as one more sample"
                     % ", ".join(file_name(next(s["name"] for s in parsed if s["kind"] == k and s["sample"] is None))
                                 for k in mixed))
    for r in records:
        if r["kind"] == "hole":
            holes.append("%s:%d %s" % (r["src"], r["line"], r["note"]))
    for snap in snapshots:
        counts = snap.get("counts") or {}
        where = "%s:%d snapshot %s" % (snap["src"], snap["line"], iso(snap["ts"]) or "-")
        if counts.get("gone_while_read"):
            holes.append("%s: %d process(es) ended while read" % (where, counts["gone_while_read"]))
        if counts.get("kernel_threads"):
            holes.append("%s: %d kernel thread(s) under kthreadd (pid %s) not listed"
                         % (where, counts["kernel_threads"], snap.get("kernel_parent")))
        if counts.get("unreadable"):
            holes.append("%s: %d process(es) whose status could not be read" % (where, counts["unreadable"]))
            incomplete.append("%s: %d process(es) could not be read" % (where, counts["unreadable"]))
    unread_starts = sum((snap.get("counts") or {}).get("start_unread", 0) for snap in snapshots)
    if unread_starts:   # T-8 (S14): said once per round, with the count
        holes.append("%d process(es) whose start could not be read from /proc/PID/stat in %d snapshot(s): they are"
                     " keyed by pid and image only (a pid reused by a process of the same image is taken for the same"
                     " tree)" % (unread_starts, len(snapshots)))
    for s in parsed:
        if not s["text_read"]:
            if s["sample"] is not None:
                holes.append("sample %d: source %s not read (%s): what it would hold in that sample is not seen;"
                             " the run is incomplete (exit 3 unless an alarm)" % (s["sample"], s["name"],
                                                                                 s["error"] or "no text"))
            continue
        if s["kind"] == "sysmon" and channel:
            pass   # M7.9: a window of the channel; what the channel holds is said once per watch (E4)
        elif s["kind"] == "sysmon":
            if not holds(s, "proc"):
                holes.append("source sysmon holds no event 1 (process create): it is not a complete process source")
                incomplete.append("source sysmon holds no event 1")
            if not holds(s, "conn"):
                holes.append("source sysmon holds no event 3 (network connect): it is not a complete connection"
                             " source; Sysmon without -n logs no event 3")
                incomplete.append("source sysmon holds no event 3")
        elif s["kind"] in EXPECTED and not holds(s, EXPECTED[s["kind"]]):
            holes.append("source %s was read and holds no %s record" % (s["name"], EXPECTED[s["kind"]]))
            incomplete.append("source %s holds no %s record" % (s["name"], EXPECTED[s["kind"]]))
        elif not s["records"]:
            holes.append("source %s was read and holds no record" % s["name"])
    # Per-process read failures (D-3): one hole per field, citing each pid's line.
    for field, what in (("fd", "open sockets (/proc/PID/fd links) unknown, recorded as null"),
                        ("cwd", "working directory (cwd link) not read"),
                        ("cmdline", "command line not read")):
        failed = [p for p in sorted(procs.values(), key=lambda q: q["pid"])
                  if any(field in (r.get("unread") or []) for r in p["recs"])]
        if failed:
            shown = ", ".join("pid %d (%s)" % (p["pid"] % REUSE, _cite_text(_cites(p["recs"], 1))) for p in failed[:20])
            holes.append("%d process(es) with %s: %s%s" % (len(failed), what, shown,
                                                            " and %d more" % (len(failed) - 20) if len(failed) > 20 else ""))
    if unowned:
        zero = sorted({c["state"] for c in unowned if c.get("inode") == 0})
        holes.append("%d talking connection line(s) without an owning process (%s). Reasons: not root or another"
                     " user's /proc/PID/fd; the owner ended; the socket was opened between the fd snapshot and the"
                     " tcp read%s" % (len(unowned), _cite_text(_cites(unowned, 5)),
                                      "; %d with inode 0, which the kernel keeps after the owner closed it (%s)"
                                      % (sum(1 for c in unowned if c.get("inode") == 0), ", ".join(zero)) if zero else ""))
        incomplete.append("%d talking line(s) without an owner" % len(unowned))
    if orphans:
        incomplete.append("%d talking pid(s) with no process record" % len(orphans))
    if dropped:
        holes.append("--window %g: %d timed records older than the window were left out" % (window, dropped))
    samples = sorted({s["sample"] for s in parsed if s["sample"] is not None})
    samples_read = sorted({s["sample"] for s in parsed if s["sample"] is not None and s["text_read"]})
    merged = len(samples_read) + any(s["kind"] in SAMPLED and s["sample"] is None and s["text_read"] for s in parsed)
    if merged > 1 or len(snapshots) > 1:
        holes.append("window merge: the records of %d %s are merged by pid, as one tree; a pid that ended and was"
                     " reused between them joins two processes (on Windows pids are reused soon after exit)"
                     % ((merged, "sample(s)") if merged > 1 else (len(snapshots), "snapshot(s)")))
    alarms = []
    if not records:
        alarms.append("nothing read: no record from any source (A3)")
    if candidates:
        alarms.append("%d candidate tree(s) that talk and have a child or write" % len(candidates))
    if act_roots:
        alarms.append("%d act-root(s): a program in a user directory runs a shell that runs a command, and no talk"
                      " of its own was seen" % len(act_roots))
    if dark:
        alarms.append("%d AGENT-DARK footprint(s)" % len(dark))
    if problems:
        alarms.append("%d line(s) could not be read (A3)" % len(problems))
    if recent and not candidates and not act_roots:
        # G-3 (B-2): talk to a model endpoint whose talker is not seen is a gap, never none-seen.
        incomplete.append("%d recent-talk line(s) to a model endpoint, owner unknown, and no candidate or act-root:"
                          " the talker is not seen" % len(recent))
    if not read & set(PROCESS_SOURCES):
        incomplete.append("no process source read (%s): no tree can be built" % ", ".join(PROCESS_SOURCES))
    if not read & set(CONNECTION_SOURCES):
        incomplete.append("no connection source read (%s): no process can be seen to talk"
                          % ", ".join(CONNECTION_SOURCES))
    for s in parsed:
        if s["error"]:
            incomplete.append("source %s %s: %s" % (s["name"], "partly read" if s["text_read"] else "not read",
                                                    s["error"]))
    result = "alarm" if alarms else "incomplete" if incomplete else "none-seen"
    times = sorted(r["ts"] for r in records if r.get("ts"))
    connections_from = [s["path"] for s in parsed if s["kind"] in CONNECTION_SOURCES and s["text_read"]]
    extra = {}
    if channel:   # M7.9: a tree's root as the round's channel saw it (guid, brief, its creation)
        for t in candidates + act_roots:
            t.update(_channel_fields(procs.get(t["pid"])))
            # AD-1: the class its root has in the round built without the channel's records (None: a tree of this
            # round only by the channel), so the watch keeps a footprint's quiet and kept trees as that build does
            t["bare_class"] = bare["roots"].get(t["pid"])
        # AB-6 (AA-1): "sample" exactly when the tree is a candidate of the same round built WITHOUT the channel's
        # records (the sampled records keep their keys: _guid_instances moves Sysmon records only), else "channel"
        for t in candidates:
            t["candidate_by"] = "sample" if bare["roots"].get(t["pid"]) == "candidate" else "channel"
    if processes:   # M7.8 (P-2): the round's process sample, for "quiet" (root alive, no talk) against "gone"
        extra["processes"] = _last_sample(records, procs)
    return _os_pids(dict(extra, **{
        "tool": "raqib discover (ADR-0004)",
        "live": live,
        "catalog": catalog["path"],
        "window": {"start": iso(times[0]) if times else None, "end": iso(times[-1]) if times else None,
                   "seconds": round((times[-1] - times[0]).total_seconds(), 3) if times else None,
                   "snapshots": len(snapshots), "filter_seconds": window if window and not live else None,
                   "samples": samples, "samples_read": samples_read,
                   "basis": "observed times in %d of %d records" % (len(times), len(records)) if times
                   else "no observation time in the records read"},
        "sources": [{"name": s["name"], "path": s["path"], "lines": s["lines"], "records": len(s["records"]),
                     "problems": len(s["problems"]), "error": s["error"], "text_read": s["text_read"]}
                    for s in parsed],
        "connections_from": connections_from,
        "records": len(records),
        "self": sorted(self_pids),
        "holes": holes,
        "problems": problems,
        "candidates": candidates,
        "act_roots": act_roots,
        "recent_talk": recent,
        "endpoint_talkers": endpoint_talkers,
        "footprints": footprints,
        "env_footprints": env_fp,
        "agent_dark": dark,
        "alarms": alarms,
        "incomplete": incomplete,
        "complete": not incomplete,
        "result": result,
        "exit": EXIT[result],
    }))


def _last_sample(records, procs):
    """M7.8 (P-2), REDO R-5: the processes of the LAST sample of the round
    (the last /proc snapshot of a --window, the last Win32_Process sample),
    read from a process list (never a Sysmon event), each as {pid, image,
    started} as that sample's own record gives them (image_name; the start
    time, None where unread), so a pid that a process of another image or
    start time holds now does not match a tree's key; a pid in an earlier
    snapshot only is not in it."""
    lists = [r for r in records if r["kind"] == "proc" and not r.get("derived")
             and (split_name(r["src"]) or (None,))[0] in PROCESS_LISTS]
    if not lists:
        return []
    last_src = max({r["src"] for r in lists}, key=_order)
    snaps = [r["line"] for r in records if r["kind"] == "snapshot" and r["src"] == last_src]
    after = max(snaps) if snaps else 0
    out = {}
    for r in lists:
        if r["src"] == last_src and r["line"] > after and r["pid"] not in out:
            out[r["pid"]] = {"pid": r["pid"], "image": r["image"], "started": r.get("started") or None}
    return [out[pid] for pid in sorted(out)]


def exe_from(p):
    """M7.2 REDO C-1d (API for raqib/host.py): where a process's image path
    came from: "record" (Windows ExecutablePath, a Sysmon image, the Linux
    exe link), "argv" (Linux argv[0], the process's own text), or None (no
    path: blank or denied)."""
    for r in (p or {}).get("recs") or ():
        if r.get("kind") == "proc" and r.get("exe") and r.get("exe") == p.get("exe"):
            return r.get("exe_from") or "record"
    return None


def started_of(p):
    """M7.2 (API for raqib/host.py): the creation time the reader gave for a
    process, as the record holds it (Windows: CreationDate, an export's text
    or the live reader's ISO UTC; Linux since M7.8 REDO R-5: the snapshot's
    "started", from /proc/PID/stat), or None where none was read (an older
    snapshot). raqib watch --host keys a tree by (pid, image, started)."""
    for r in (p or {}).get("recs") or ():
        if r.get("kind") == "proc" and r.get("started"):
            return r["started"]
    return None


def started_at_of(p):
    """M7.8 REDO 3 V-4: the time a Linux snapshot computed for display from
    the start ticks (where the clock tick rate was known), or None. Never the
    key: started_of is."""
    for r in (p or {}).get("recs") or ():
        if r.get("kind") == "proc" and r.get("started_at"):
            return r["started_at"]
    return None


def _shown_start(p):
    """V-4: {"started_at": time} where a snapshot gave one, else {} (so the inventories of every shipped
    export read byte-identical)."""
    at = started_at_of(p)
    return {"started_at": at} if at else {}


def _descendant_candidates(procs, pid, acts):
    """Candidates below a talker that is not one itself."""
    return [q for q in sorted(_descendants(procs, pid)) if q in acts]


def _recent_talk(conns, records, talkers, names_for, catalog):
    """E2: what is left of talk whose owner is not in the records. A TIME-WAIT
    row with no owner (Windows OwningProcess 0; Linux inode 0, so no pid) to a
    catalog endpoint - by IP network, loopback port, or a name the host's own
    DNS record gives that IP - and a DNS cache row (no pid) for a catalog host
    whose IPs no process is seen to talk to. One line per remote, or per host
    name for a DNS row alone; cited (A5); never a candidate or an act-root by
    itself, and no alarm (with neither in the run, build() makes it incomplete,
    G-3)."""
    live = {c["raddr"] for cs in talkers.values() for c in cs}
    groups = {}
    for c in conns:
        if c["state"] == "TIME-WAIT" and c["pid"] in (None, 0) and c["rport"] is not None \
                and not _wildcard(c["raddr"]):
            groups.setdefault((c["raddr"], c["rport"]), []).append(c)
    out, covered = [], set()
    for (raddr, rport), cs in sorted(groups.items(), key=lambda kv: (_order(kv[1][0]["src"]), kv[1][0]["line"])):
        names = {}
        for c in cs:
            for n, recs in names_for(c).items():
                names.setdefault(n, []).extend(recs)
        matches = _endpoint(cs[0], names, catalog)
        if not matches:
            continue
        covered.add(raddr)
        name_recs = [r for m in matches if m["layer"] == "host" for r in names[m["name"]]]
        conn_cites = _cites(cs)
        out.append({"how": "time-wait", "remote": "%s:%s" % (raddr, rport), "state": "TIME-WAIT", "lines": len(cs),
                    "names": sorted(names), "endpoint": matches, "owner": None,
                    "cites": conn_cites + _cites(name_recs, 2, skip=conn_cites)})
    by_name = {}
    for r in records:
        if r["kind"] != "dns" or r["pid"] is not None or set(r["ips"]) & (live | covered):
            continue
        for name in r["names"]:
            for h in catalog["hosts"]:
                if fnmatch.fnmatchcase(name, h["match"]):
                    entry = by_name.setdefault(name, {"match": h, "recs": []})
                    if r not in entry["recs"]:
                        entry["recs"].append(r)
    for name in sorted(by_name, key=lambda n: (_order(by_name[n]["recs"][0]["src"]), by_name[n]["recs"][0]["line"])):
        recs, h = by_name[name]["recs"], by_name[name]["match"]
        out.append({"how": "dns", "remote": None, "state": None, "lines": len(recs), "names": [name],
                    "endpoint": [{"layer": "host", "match": h["match"], "name": name, "vendor": h["vendor"]}],
                    "ips": sorted({ip for r in recs for ip in r["ips"]}), "owner": None, "cites": _cites(recs)})
    for i, entry in enumerate(out, start=1):
        ep = "; ".join("%s %s%s" % (m["vendor"], m["match"], " (%s)" % m["name"] if m.get("name") else "")
                       for m in entry["endpoint"])
        entry["id"] = "R%d" % i
        entry["summary"] = ("recent talk, owner unknown: %s [%s]" % (
            "TIME-WAIT to %s x%d" % (entry["remote"], entry["lines"]) if entry["how"] == "time-wait"
            else "the DNS cache names %s (%s)" % (entry["names"][0], ", ".join(entry["ips"])), ep))
    return out


def _user_dir(path, globs):
    """The user_dirs glob an image path matches, or None (E3): lower case,
    '\\' read as '/', a \\\\?\\ or \\??\\ prefix dropped."""
    if not path:
        return None
    norm = re.sub(r"\A/(?:/\?|\?\?)/", "", path.strip().strip('"').replace("\\", "/").lower())
    return next((g for g in globs if fnmatch.fnmatchcase(norm, g)), None)


def _helper(p):
    """An Electron/Chromium helper: `--type=` in its argv (G-1b)."""
    return any(a.startswith("--type=") for a in p["argv"])


def _norm_path(path):
    return re.sub(r"\A/(?:/\?|\?\?)/", "", (path or "").strip().strip('"').replace("\\", "/").lower())


def _act_roots(procs, talkers, self_tree, ids, catalog, conn_names):
    """E3, the act-root class (signature; the catalog's act_root block), as
    narrowed by G-1: a process P whose image path is under a user directory,
    none of whose names is a listed shell or system image, whose own parent
    is a listed shell or launcher (a terminal host or multiplexer), that
    carries no `--type=`, whose child S is a listed shell with a command
    below it - a process that is no listed shell, reached through no
    `--type=` hop, whose image is not under P's own directory - and that
    owns no talking connection in any sample read. The reader's own tree is
    never evidence. Talk in a later sample makes P a talker, so it is a
    candidate instead (the window merge); recent talk never promotes it."""
    spec = catalog["act_root"]
    shells, never = set(spec["shells"]), set(spec["not_images"])
    parents = shells | set(spec["launchers"])
    children = {}
    for q in procs.values():
        if q["ppid"] is not None and q["ppid"] != q["pid"]:
            children.setdefault(q["ppid"], []).append(q["pid"])

    def below(pid):
        """Descendants reached through no --type= helper, not the reader's tree."""
        out, todo, seen = [], [pid], {pid}
        while todo:
            for c in sorted(children.get(todo.pop(0), [])):
                if c not in seen and c not in self_tree and not _helper(procs[c]):
                    seen.add(c)
                    out.append(c)
                    todo.append(c)
        return out

    def shell(p):
        return any(i in shells for i in p["images"])

    def outside(d, root):
        own = _norm_path(root["exe"]).rpartition("/")[0]
        return not (own and _norm_path(procs[d]["exe"]).startswith(own + "/"))
    chains = {}
    for pid in sorted(procs):
        s = procs[pid]
        if pid in self_tree or not shell(s) or _helper(s) or s["ppid"] not in procs or s["ppid"] == pid:
            continue
        parent = procs[s["ppid"]]
        if parent["pid"] in self_tree or shell(parent):
            continue
        under = below(pid)
        if any(not shell(procs[d]) and outside(d, parent) for d in under):
            chains.setdefault(parent["pid"], []).append((pid, under))
    roots = []
    for pid in sorted(chains):
        p = procs[pid]
        place = _user_dir(p["exe"], spec["user_dirs"])
        up = procs.get(p["ppid"]) if p["ppid"] is not None else None
        if pid in talkers or any(i in never for i in p["images"]) or place is None or _helper(p) \
                or up is None or not any(i in parents for i in up["images"]):
            continue
        acts, heads = [], []
        for s, under in chains[pid]:
            commands = sorted({procs[d]["image"] or "?" for d in under if not shell(procs[d]) and outside(d, p)})
            heads.append({"pid": s, "image": procs[s]["image"], "below": len(under), "commands": commands,
                          "cites": _cites(procs[s]["recs"], 1)})
            for q in [s] + under:
                qp, via = procs[q], []
                for anc in ancestors(procs, q):
                    if anc == pid:
                        break
                    via.append(anc)
                label = next((i for i in qp["images"] if _listed(i, catalog)), None)
                acts.append({"how": "process", "pid": q, "image": label or qp["image"], "listed": label is not None,
                             "path": None, "via": list(reversed(via)), "reader_ancestor": False,
                             "started": started_of(qp),   # M7.4 E1 (API)
                             "cites": _cites(qp["recs"])})
        owner = next((a for a in ancestors(procs, pid) if a in talkers), None)
        times = [r["ts"] for q in [pid] + [a["pid"] for a in acts] for r in procs[q]["recs"] if r.get("ts")]
        first = heads[0]
        roots.append({
            "pid": pid, "image": p["image"], "exe": p["exe"], "cwd": p["cwd"], "user_dir": place, "started": started_of(p),
            "exe_from": exe_from(p), **_shown_start(p),
            "chains": heads, "acts": acts, "cites": _cites(p["recs"]),
            "attributed_to": ids.get(owner) if owner is not None else None,
            "talking_ancestor": ({"pid": owner, "image": procs[owner]["image"] if owner in procs else None,
                                  "cites": _cites(talkers[owner], 1)} if owner is not None else None),
            "launched_by": {"pid": up["pid"], "image": up["image"], "cites": _cites(up["recs"], 1)},
            "talk": "not seen: pid %d owns no talking connection in %s" % (pid % REUSE, ", ".join(conn_names)
                                                                           or "no source"),
            "seen": {"first": iso(min(times)) if times else None, "last": iso(max(times)) if times else None,
                     "basis": "observed times in the cited records" if times
                     else "no observation time in the records (a snapshot without time)"},
            "summary": "act-root, talk not seen: pid %d %s (%s) runs %s -> ... -> %s" % (
                pid % REUSE, p["image"] or "?", p["exe"] or "-", first["image"] or "?", ", ".join(first["commands"]))})
    index = {r["pid"]: "A%d" % i for i, r in enumerate(roots, start=1)}
    for r in roots:
        r["id"] = index[r["pid"]]
        r["inside"] = next((index[a] for a in ancestors(procs, r["pid"]) if a in index), None)
    return roots


def _handoff(pid, p, catalog):
    """Suggested capture source (ADR-0003; D-5, criteria in the catalog's
    handoff:): hook for a root image named claude unless its path matches a
    Claude Desktop pattern; proxy for a root marked proxy_capable; else os.
    A hook suggested for an image that offers none is a signature miss, and
    os still watches the tree: the error is on the safe side."""
    cites = _cites(p["recs"], 1) if p else []
    desktop = []
    if p is not None and p["image"] in catalog["hook_images"]:
        paths = [x.replace("\\", "/").lower() for x in [p["exe"]] + p["argv"][:2] if x]
        desktop = [d for d in catalog["hook_not_paths"] if any(d.lower() in x for x in paths)]
        if not desktop:
            return {"suggested": "hook", "root": pid, "cites": cites,
                    "why": "the root image is %s (Claude Code), which offers hooks" % p["image"]}
    marked = sorted(n for n in catalog["proxy_capable"] if p is not None and _named(p, n))
    if marked:
        return {"suggested": "proxy", "root": pid, "cites": cites,
                "why": "the catalog marks %s proxy_capable (a documented base-URL setting)" % ", ".join(marked)}
    return {"suggested": "os", "root": pid, "cites": cites,
            "why": "%s: an os source rooted at pid %d (M5.3)" % (
                "the path matches Claude Desktop (%s), which offers no hooks" % ", ".join(desktop) if desktop
                else "neither a hook image nor marked proxy_capable", pid % REUSE)}


def _footprints(records, procs, candidates, talkers, catalog, judged, act_roots=()):
    """Path footprints with the candidate each links to, and AGENT-DARK:
    a footprint no candidate tree links to, by name or by its path in argv
    or cwd, nor an act-root (M5.0b: an act-root is a tree acting in the
    window, so its footprint is linked to it, not dark). Unjudged when no
    tree could be built (no process or connection records): then silence
    would be a false clearance."""
    footprints, dark = [], []
    for r in records:
        if r["kind"] != "path":
            continue
        norm = r["path"].replace("\\", "/").rstrip("/")
        last = norm.rpartition("/")[2].lower()
        fp = next((f for f in catalog["footprints"]
                   if (fnmatch.fnmatchcase(last, f["match"].lower()) if "/" not in f["match"]
                       else norm.lower().endswith("/" + f["match"].lower()))), None)
        if fp is None:
            continue
        agent = fp["agent"]
        link = None
        # A candidate whose root goes by the agent's name first, then an
        # act-root whose root does (M5.0b), then any process of a candidate's
        # tree, then any process of an act-root's tree.
        passes = ((candidates, "candidate", lambda c: [c["pid"]]),
                  (act_roots, "act_root", lambda a: [a["pid"]]),
                  (candidates, "candidate", lambda c: c["tree"] + [a["pid"] for a in c["talking_ancestors"]]),
                  (act_roots, "act_root", lambda a: [a["pid"]] + [x["pid"] for x in a["acts"]]))
        for group, field, tree_of in passes:
            for c in group:
                for pid in tree_of(c):
                    q = procs.get(pid)
                    texts = ([q["cwd"] or ""] + q["argv"]) if q else []
                    if q and (_named(q, agent) or any(norm.lower() in t.replace("\\", "/").lower() for t in texts)):
                        link = (field, c["id"], q)
                        break
                if link:
                    break
            if link:
                break
        entry = {"path": r["path"], "match": fp["match"], "agent": agent,
                 "candidate": link[1] if link and link[0] == "candidate" else None,
                 "act_root": link[1] if link and link[0] == "act_root" else None,
                 "cites": [cite(r)] + (_cites(link[2]["recs"], 1) if link else [])}
        footprints.append(entry)
        if link:
            continue
        if not judged:
            entry["unjudged"] = "no process or connection records: AGENT-DARK cannot be judged"
            continue
        quiet = [{"pid": q["pid"], "image": q["image"], "talks": q["pid"] in talkers,
                  "cites": _cites(q["recs"], 1)} for q in procs.values() if _named(q, agent)]
        dark.append({"rule": "AGENT-DARK", "path": r["path"], "agent": agent, "quiet": quiet,
                     "cites": [cite(r)] + [c for q in quiet for c in q["cites"]],
                     "summary": "%s footprint %s on disk; no tree in the window talks and acts as %s%s" % (
                         agent, r["path"], agent,
                         " (%d %s process(es) seen, none acting)" % (len(quiet), agent) if quiet else "")})
    return footprints, dark


def _holes(records, procs, conns, kinds):
    """What this run could not see (A3), one line each. kinds: the sources read."""
    holes = []
    if kinds & {"proc", "proc-net", "ss"}:
        holes.append("Linux: no offline name record in M5.0, so endpoints match by IP network and"
                     " loopback port only (ADR-0004)")
        holes.append("Linux: argv[0] and status Name are written by the process itself, and a copied"
                     " shell takes any name; the /proc/PID/exe link places a process for act-root (G-2), the"
                     " names still come from argv[0]")
    if kinds & {"win-process", "win-tcp", "win-dns", "sysmon"} and "proc" not in kinds:
        holes.append("Windows: no process environment is read, so *_API_KEY names are not seen")
    if not any(r["kind"] == "file" for r in records):
        holes.append("no file-write record (Sysmon 11): a talker that acts only by writing files,"
                     " with no child, is not seen")
    else:
        holes.append("config space: writes into a dot-directory (also .ssh, .git/hooks, .github/workflows),"
                     " AppData (also the Startup folder), ProgramData, a temp directory or the writer's own"
                     " program directory are not counted as acts")
    if "footprints" not in kinds:
        holes.append("no footprint listing read: AGENT-DARK cannot be judged")
    orphans = sorted({c["pid"] for c in conns if talks(c) and c["pid"] not in procs})
    if orphans:
        holes.append("%d talking pid(s) with no process record (started after the snapshot, or"
                     " gone): %s" % (len(orphans), ", ".join(str(p % REUSE) for p in orphans[:10])))
    if any(c.get("basis") == "ports" for c in conns):
        holes.append("no listening sockets in the connection text: direction guessed from port order"
                     " (ephemeral local port above the remote one = outbound)")
    proc_read = [p for p in procs.values() if not p["derived"] and any(r["src"] == "proc" for r in p["recs"])]
    hidden = sum(1 for p in proc_read if p["env_keys"] is None)
    if hidden:
        holes.append("%d process(es) whose environment could not be read (not root?)" % hidden)
    return holes


def run(texts, catalog, window=None, holes=(), live=False, run=None, processes=False, channel=False):
    """Parse {kind: (path, text, error)} and build the inventory. A text with
    an error was partly read: it is parsed, and the run is incomplete. run:
    the run record (run.json, or collect_live's run_info); its system drive
    (D-3) is the inventory's `system_drive`, None without one. processes
    (M7.8): the inventory carries the round's process sample (build())."""
    parsed = []
    unknown = [n for n in texts if not split_name(n)]
    if unknown:
        raise ValueError("no such source: %s" % ", ".join(sorted(unknown)))
    for name in sorted(texts, key=_order):
        kind, sample = split_name(name)
        path, text, error = texts[name]
        parser = PARSERS[kind] if not (channel and kind == "sysmon") else (
            lambda t, n: parse_sysmon(t, n, keyed=True))   # M7.9: a round's channel, keyed by ProcessGuid
        records, problems = parser(text, name) if text is not None else ([], [])
        parsed.append({"name": name, "kind": kind, "sample": sample, "path": path, "error": error,
                       "records": records, "problems": problems, "text_read": text is not None,
                       "lines": text.count("\n") + (not text.endswith("\n")) if text else 0})
    inv = build(parsed, catalog, window, holes, live, processes=processes, channel=channel)
    inv["system_drive"] = system_drive_of(run)
    return inv


def run_record(directory):
    """D-3: the run.json of a directory as a dict, or None when there is
    none or it cannot be read (read_dir says why)."""
    try:
        got = json.loads(decode(_read_bytes(os.path.join(directory, RUN_FILE))))
    except (OSError, ValueError):
        return None
    return got if isinstance(got, dict) else None


# --- --check: the first fp numbers (M5.0b E4, A6) -----------------------------------------

def check(catalog, root):
    """Measure act-roots and candidates on the fixture directories the
    catalog's act_root block names (relative to the checkout `root`), as
    check-rules measures a rule (A6). A positive must show what it names:
    `act_root: NAME` an act-root of that image; `promoted: NAME` a candidate
    of that image and no act-root of it. A negative is a benign export: an
    act-root on it is a false positive of act_root's fp_budget; a candidate
    on it is counted for the anchor, which declares no budget (ADR-0004
    B-8). A negative is measured when its inventory is complete or when the
    class fired on it; otherwise it is unmeasured, never clean (A3). A
    ValueError for a fixture that cannot be read."""
    spec = catalog["act_root"]
    measuring = dict(catalog, act_root=dict(spec, status="ok"))    # measured whatever its status (G-8, as rules)
    negatives = [{"dir": d, "expect": None, "name": None, "cite": None} for d in spec["negative"]]
    rows = []
    for role, items in (("positive", spec["positive"]), ("negative", negatives)):
        for item in items:
            path = os.path.join(root, *item["dir"].split("/"))
            if not os.path.isdir(path):
                raise ValueError("act_root fixture %s: no such directory in %s" % (item["dir"], root))
            texts, holes = read_dir(path)
            if not texts:
                raise ValueError("act_root fixture %s holds no source text" % item["dir"])
            inv = run(texts, measuring, holes=holes)
            w = inv["window"]
            row = {"dir": item["dir"], "role": role, "expect": item["expect"], "name": item["name"], "cite": item["cite"],
                   "samples": len(w["samples_read"]) or w["snapshots"] or None, "result": inv["result"],
                   "exit": inv["exit"], "complete": inv["complete"],
                   "candidates": [{"id": c["id"], "pid": c["pid"], "image": c["image"]} for c in inv["candidates"]],
                   "act_roots": [{"id": r["id"], "pid": r["pid"], "image": r["image"]} for r in inv["act_roots"]]}
            if item["expect"] == "act_root":
                entries = [r for r in inv["act_roots"] if r["image"] == item["name"]]
                row["found"] = any(item["cite"] in _cite_keys(r) for r in entries)
                row["verdict"] = "%s: an act-root %s citing %s" % ("found" if row["found"] else "MISSED", item["name"],
                                                                  item["cite"])
            elif item["expect"] == "promoted":
                entries = [c for c in inv["candidates"] if c["image"] == item["name"]]
                row["found"] = (any(item["cite"] in _cite_keys(c) for c in entries)
                                and not any(r["image"] == item["name"] for r in inv["act_roots"]))
                row["verdict"] = "%s: %s a candidate citing %s, not an act-root" % (
                    "found" if row["found"] else "MISSED", item["name"], item["cite"])
            else:
                row["measured"] = {k: inv["complete"] or bool(row[k]) for k in ("candidates", "act_roots")}
                row["verdict"] = "%s%s" % ("measured" if inv["complete"] else "UNMEASURED (incomplete)",
                                           "; act-root FALSE POSITIVE" if row["act_roots"] else "")
            rows.append(row)
    negs = [r for r in rows if r["role"] == "negative"]

    def rate(key):
        measured = [r for r in negs if r["measured"][key]]
        fired = sum(1 for r in measured if r[key])
        return (fired / len(measured) if measured else None), len(measured), len(negs) - len(measured), fired
    positives = [r for r in rows if r["role"] == "positive"]
    fp, measured, unmeasured, fired = rate("act_roots")
    if not all(r["found"] for r in positives):
        verdict = "positive-missed"
    elif not measured:
        verdict = "unmeasured"
    elif spec["status"] == "disabled":
        verdict = "disabled"
    elif fp > spec["fp_budget"]:
        verdict = "over-budget"
    else:
        verdict = "ok"
    act = {"class": "act-root", "kind": "signature", "status": spec["status"], "fp_budget": spec["fp_budget"], "fp_rate": fp,
           "fired": fired, "measured": measured, "unmeasured": unmeasured,
           "positives": len(positives), "found": sum(1 for r in positives if r["found"]), "verdict": verdict}
    fp, measured, unmeasured, fired = rate("candidates")
    anchor = {"class": "candidate", "kind": "anchor", "status": None, "fp_budget": None, "fp_rate": fp, "fired": fired,
              "measured": measured, "unmeasured": unmeasured, "verdict": "no-budget"}
    return {"tool": "raqib discover --check", "catalog": catalog["path"], "root": root, "fixtures": rows,
            "classes": [act, anchor], "exit": 0 if verdict in ("ok", "disabled") else 1}


def _cite_keys(node):
    """Every SRC:LINE an inventory entry cites, at any depth."""
    out = set()
    if isinstance(node, dict):
        for c in node.get("cites") or []:
            out.add("%s:%s" % (c["src"], c["line"]))
        for v in node.values():
            if isinstance(v, (dict, list)):
                out |= _cite_keys(v)
    elif isinstance(node, list):
        for v in node:
            out |= _cite_keys(v)
    return out


def render_check(report):
    def names(items):
        return "%d%s" % (len(items), " (%s)" % ",".join(sorted({i["image"] or "?" for i in items})) if items else "")
    width = max([len(r["dir"]) for r in report["fixtures"]] + [len("fixture")])
    out = ["raqib discover --check (A6): candidates and act-roots per fixture; catalog %s" % report["catalog"],
           "%-*s  %-8s  %-7s  %-10s  %-36s  %-14s  %s" % (width, "fixture", "role", "samples", "result",
                                                         "candidates", "act-roots", "verdict")]
    for r in report["fixtures"]:
        out.append("%-*s  %-8s  %-7s  %-10s  %-36s  %-14s  %s" % (
            width, r["dir"], r["role"], r["samples"] or "-", "%s(%d)" % (r["result"], r["exit"]),
            names(r["candidates"]), names(r["act_roots"]), r["verdict"]))
    out += ["", "%-10s  %-9s  %-8s  %-15s  %-7s  %-9s  %s" % ("class", "kind", "status", "verdict", "fp_rate",
                                                                "fp_budget", "fixtures")]
    for c in report["classes"]:
        rate = "-" if c["fp_rate"] is None else "%.3f" % c["fp_rate"]
        budget = "none" if c["fp_budget"] is None else "%g" % c["fp_budget"]
        tail = "negatives: %d of %d measured fired, %d unmeasured" % (c["fired"], c["measured"], c["unmeasured"])
        if "positives" in c:
            tail = "positives: %d of %d found; %s" % (c["found"], c["positives"], tail)
        else:
            tail += "; the anchor declares no budget (ADR-0004 B-8)"
        out.append("%-10s  %-9s  %-8s  %-15s  %-7s  %-9s  %s" % (c["class"], c["kind"], c["status"] or "-",
                                                                 c["verdict"], rate, budget, tail))
    verdict = report["classes"][0]["verdict"]
    out.append("RESULT: %s (exit %d)" % ("OK" if verdict == "ok" else verdict.upper(), report["exit"]))
    return "\n".join(_safe(line) for line in out) + "\n"


# --- text output ------------------------------------------------------------------------

def _cite_text(cites):
    return " ".join("%s:%d" % (c["src"], c["line"]) for c in cites)


def render_text(inv):
    w = inv["window"]
    samples = w.get("samples") or []
    out = ["Raqib discover (ADR-0004): an agent is a tree that talks to a model and acts",
           "window: %s .. %s (%s; %d snapshot(s)%s%s)" % (
               w["start"] or "-", w["end"] or "-", w["basis"], w["snapshots"],
               "; filter: last %g s" % w["filter_seconds"] if w["filter_seconds"] else "",
               "; Windows samples: %d of %d read, merged" % (len(w.get("samples_read") or []), len(samples))
               if samples else ""),
           "records read: %d from %d source(s)%s" % (
               inv["records"], len(inv["sources"]),
               "; raqib discover itself: pid %s" % ", ".join(str(s) for s in inv["self"]) if inv["self"] else "")]
    for s in inv["sources"]:
        out.append("  %-12s %5d lines %5d records %3d problems  %s%s" % (
            s["name"], s["lines"], s["records"], s["problems"], s["path"],
            "  %s: %s" % ("PARTLY READ" if s["text_read"] else "NOT READ", s["error"]) if s["error"] else ""))
    out.append("connections read from: %s" % ("; ".join(inv["connections_from"]) or "nothing"))
    out.append("catalog (signature, supporting only): %s" % inv["catalog"])
    out += ["", "HOLES (A3): %d" % len(inv["holes"])] + ["  - %s" % h for h in inv["holes"]]
    out += ["", "PROBLEMS (unread lines): %d" % len(inv["problems"])]
    out += ["  - %s:%d %s" % (p["src"], p["line"], p["reason"]) for p in inv["problems"]]
    out += ["", "CANDIDATES (anchor: talks + has a child or writes): %d" % len(inv["candidates"])]
    cited = []
    for c in inv["candidates"]:
        out.append("  [%s] pid %d %s  %s%s" % (c["id"], c["pid"], c["image"] or "?", c["exe"] or "-",
                                             "  (inside %s)" % c["inside"] if c["inside"] else ""))
        out.append("      cwd %s; seen %s .. %s (%s)  %s" % (c["cwd"] or "-", c["seen"]["first"] or "-",
                                                            c["seen"]["last"] or "-", c["seen"]["basis"],
                                                            _cite_text(c["cites"])))
        out.append("      suggested source: %s - %s  %s" % (c["source"]["suggested"], c["source"]["why"],
                                                           _cite_text(c["source"]["cites"])))
        out.append("      talks: %d remote(s)" % len(c["talks"]))
        for t in c["talks"]:
            ep = "; ".join("%s %s%s" % (m["vendor"], m["match"], " (%s)" % m["name"] if m.get("name") else "")
                           for m in t["endpoint"]) or "no catalog match"
            out.append("        %s %s x%d [%s]%s  %s" % (t["remote"], t["state"], t["lines"], ep,
                                                      " names %s" % ",".join(t["names"]) if t["names"] else "",
                                                      _cite_text(t["cites"])))
        out.append("      acts: %d (%d with a listed act name)" % (len(c["acts"]), c["listed_acts"]))
        for a in c["acts"][:ACTS_SHOWN]:
            what = "wrote %s" % a["path"] if a["how"] == "file-write" else "%s%s%s" % (
                a["image"] or "?", " via pid %s" % ",".join(str(v) for v in a["via"]) if a["via"] else " (child)",
                " [listed]" if a["listed"] else " [unlisted]")
            out.append("        pid %d %s%s  %s" % (a["pid"], what, "  [an ancestor of the reader itself]"
                                                    if a["reader_ancestor"] else "", _cite_text(a["cites"])))
        if len(c["acts"]) > ACTS_SHOWN:
            out.append("        ... %d more (all in --json)" % (len(c["acts"]) - ACTS_SHOWN))
        for t in c["talking_ancestors"]:
            out.append("      talking ancestor: pid %d %s  %s" % (t["pid"], t["image"] or "?", _cite_text(t["cites"])))
        for e in c["env_footprints"]:
            out.append("      env footprint: %s  %s" % (e["name"], _cite_text(e["cites"])))
        cited.append(c)
    act_roots, recent = inv.get("act_roots") or [], inv.get("recent_talk") or []
    if not inv["candidates"] and act_roots:
        out.append("  none; %d act-root(s) below: a tree that acts with no talk of its own seen" % len(act_roots))
    elif not inv["candidates"]:
        out.append("  NO AGENT SEEN in window %s .. %s; %d records read (%s); the read was %s.%s Not a clearance."
                   % (w["start"] or "-", w["end"] or "-", inv["records"],
                      ", ".join("%s %d" % (s["name"], s["records"]) for s in inv["sources"]) or "no source",
                      "complete" if inv["complete"] else "INCOMPLETE (see below)",
                      " %d recent-talk line(s), owner unknown (below)." % len(recent) if recent else ""))
    out += ["", "ACT-ROOTS (signature: a program in a user directory runs a shell that runs a command; talk"
                " not seen): %d" % len(act_roots)]
    for r in act_roots:
        out.append("  [%s] pid %d %s  %s  (user directory %s)%s" % (
            r["id"], r["pid"], r["image"] or "?", r["exe"] or "-", r["user_dir"],
            "  (inside %s)" % r["inside"] if r["inside"] else ""))
        out.append("      cwd %s; seen %s .. %s (%s)  %s" % (r["cwd"] or "-", r["seen"]["first"] or "-",
                                                            r["seen"]["last"] or "-", r["seen"]["basis"],
                                                            _cite_text(r["cites"])))
        out.append("      launched by pid %d %s (a listed shell or launcher)  %s" % (
            r["launched_by"]["pid"], r["launched_by"]["image"] or "?", _cite_text(r["launched_by"]["cites"])))
        out.append("      talk %s" % r["talk"])
        t = r["talking_ancestor"]
        if t:
            out.append("      its acts go to %s, the nearest talking ancestor: pid %d %s  %s" % (
                r["attributed_to"] or "?", t["pid"], t["image"] or "?", _cite_text(t["cites"])))
        for h in r["chains"]:
            out.append("      chain: pid %d %s -> %d below (%s)  %s" % (h["pid"], h["image"] or "?", h["below"],
                                                                     ", ".join(h["commands"]), _cite_text(h["cites"])))
        for a in r["acts"][:ACTS_SHOWN]:
            out.append("        pid %d %s%s%s  %s" % (
                a["pid"], a["image"] or "?", " via pid %s" % ",".join(str(v) for v in a["via"]) if a["via"]
                else " (child)", " [listed]" if a["listed"] else " [unlisted]", _cite_text(a["cites"])))
        if len(r["acts"]) > ACTS_SHOWN:
            out.append("        ... %d more (all in --json)" % (len(r["acts"]) - ACTS_SHOWN))
    out += ["", "RECENT TALK (owner unknown; never a candidate by itself): %d" % len(recent)]
    for t in recent:
        out.append("  [%s] %s  %s" % (t["id"], t["summary"], _cite_text(t["cites"])))
    out += ["", "MODEL ENDPOINT TALKERS WITHOUT AN ACT (signature only): %d" % len(inv["endpoint_talkers"])]
    for t in inv["endpoint_talkers"]:
        eps = sorted({"%s %s" % (m["vendor"], m["match"]) for x in t["talks"] for m in x["endpoint"]})
        out.append("  pid %d %s -> %s%s  %s" % (t["pid"], t["image"] or "?", "; ".join(eps),
                                              " (above %s)" % ",".join(t["above"]) if t["above"] else "",
                                              _cite_text([c for x in t["talks"] for c in x["cites"]][:3])))
    out += ["", "FOOTPRINTS (signature, supporting): %d on disk, %d env" % (
        len(inv["footprints"]), len(inv["env_footprints"]))]
    for f in inv["footprints"]:
        out.append("  %s (%s) -> %s  %s" % (f["path"], f["agent"], f["candidate"] or f.get("act_root")
                                            or f.get("unjudged") or "no candidate", _cite_text(f["cites"])))
    for e in inv["env_footprints"]:
        out.append("  env %s in pid %d %s -> %s  %s" % (",".join(e["names"]), e["pid"], e["image"] or "?",
                                                       e["candidate"] or "no candidate", _cite_text(e["cites"])))
    out += ["", "AGENT-DARK (footprint, no active tree; A3): %d" % len(inv["agent_dark"])]
    for d in inv["agent_dark"]:
        out.append("  %s  %s" % (d["summary"], _cite_text(d["cites"])))
    lines = {}
    for c in cited:
        for group in [c["cites"], c["source"]["cites"]] + [t["cites"] for t in c["talks"]] + \
                [a["cites"] for a in c["acts"][:ACTS_SHOWN]] + [t["cites"] for t in c["talking_ancestors"]]:
            for x in group:
                lines[(x["src"], x["line"])] = x["text"]
    for r in act_roots:
        groups = [r["cites"], r["launched_by"]["cites"]] + [h["cites"] for h in r["chains"]] + \
            [a["cites"] for a in r["acts"][:ACTS_SHOWN]]
        groups += [r["talking_ancestor"]["cites"]] if r["talking_ancestor"] else []
        for x in (x for g in groups for x in g):
            lines[(x["src"], x["line"])] = x["text"]
    for d in inv["agent_dark"] + recent:
        for x in d["cites"]:
            lines[(x["src"], x["line"])] = x["text"]
    if lines:
        out += ["", "CITED LINES (A5): %d" % len(lines)]
        out += ["  %s:%d  %s" % (src, n, text) for (src, n), text in sorted(lines.items())]
    out += ["", "ALARMS: %s" % ("; ".join(inv["alarms"]) or "none"),
            "INCOMPLETE: %s" % ("; ".join(inv["incomplete"]) or "none - every process and connection source"
                                                                 " was read, held records, and every talking line"
                                                                 " had an owner"),
            "RESULT: %s (exit %d)" % (inv["result"].upper(), inv["exit"])]
    # Every value can come from a file or process the agent controls: no
    # control character reaches the terminal.
    return "\n".join(_safe(line) for line in out) + "\n"
