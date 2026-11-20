"""The autostart places of Windows, read by Raqib itself (ADR-0014 Amendment G, AG-1 to AG-3; M15.3a).

read() reads, with the standard library alone and in this process, every place AG-1 names: the values under Run
and RunOnce of every loaded user's hive (HKU by its SID; a `_Classes` hive and `.DEFAULT` left out; HKCU is not
read a second time) and of the machine's, the 32-bit view only where it holds an entry the other view does not
hold as the same name and content; the files directly in the user's and all users' Startup folders
(`desktop.ini` left out); each service's ImagePath, Start and Type; each scheduled task of the scheduler's tree
in the registry (its Actions and Triggers); Winlogon's Shell and Userinit. changes() compares two reads.

An entry: `place` (run, runonce, startup, service, task, winlogon), `scope` (user or machine), `view32`, `name`
(as raqib.hooks.os_sysmon.value_name gives a value's name: redacted, bounded), `program` (as PERSIST-RUN-KEY's
line names the program a value would run, os_sysmon.registry_program; None where the content is not a command
or was not read), `sha256` (of its content; None where the content was not read) and `key` (a sha256 of where
it is, so that two reads can be compared). A value's text, a file's content, a SID and a user's name stay in
this process's memory, and leave it only as a hash.

What the rights do not give is said per place, never read as empty (AG-2): `refused` (the whole place),
`partly` (how many of its keys were refused) or `failed` (another error, with its reason); a place that is not
there is empty. read() never raises and imports winreg only inside the call. Off Windows it reads nothing and
says so (Linux's places are ADR-0014 S4).

    python -m raqib.autostart [--rounds N] [--every S]

prints one line of the first read, then at each later read one line per change. It writes no file and opens
no socket. Exit 0; 2 for arguments it does not take. Spec: docs/specs/AUTOSTART.md.
"""
from __future__ import annotations

import argparse
import hashlib
import math
import os
import re
import sys
import time

from raqib.hooks import os_sysmon

PLACES = ("run", "runonce", "startup", "service", "task", "winlogon")
CURRENT_VERSION = "Microsoft\\Windows\\CurrentVersion"
RUN_KEYS = (("run", "Run"), ("runonce", "RunOnce"))
SERVICES = "SYSTEM\\CurrentControlSet\\Services"
TASK_CACHE = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache"
TASK_TREE = TASK_CACHE + "\\Tree"
TASK_BODIES = TASK_CACHE + "\\Tasks"
TASK_DEPTH = 32                       # the scheduler's folders, at most this deep; a deeper one is said (AH-2)
# ADR-0014 AH-1: a SID wherever it stands in a name an entry's maker chose (a per-user task of an updater holds one)
SID_IN_NAME = re.compile(r"S-1-[0-9]+(?:-[0-9]+)+", re.I)
GONE_WHILE_OPEN = 1018                # ERROR_KEY_DELETED: a key deleted while it is read is not there (AH-5)
WINLOGON = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
WINLOGON_VALUES = ("Shell", "Userinit")
STARTUP = ("Microsoft", "Windows", "Start Menu", "Programs", "Startup")
STARTUP_ROOTS = (("user", "APPDATA"), ("machine", "ProgramData"))
LEFT_OUT = ("desktop.ini",)           # AG-1, as A-3
SID = re.compile(r"S-1-[0-9]+(?:-[0-9]+)+\Z")   # a hive by its SID; `S-1-...-1001_Classes` does not match
NO_MORE_ITEMS = 259                   # ERROR_NO_MORE_ITEMS: an enumeration's end
CHUNK = 1 << 16
NOT_WINDOWS = ("autostart: not Windows (%s): nothing is read; the autostart places read here are Windows',"
               " and Linux's are ADR-0014 S4.")


class WinRegistry:
    """The registry as read() asks it, over the standard library's winreg (handed in: imported by read() alone).
    subkeys() and values() open a key read-only, in the 64-bit view or the 32-bit one, and raise what winreg
    raises (FileNotFoundError: not there; PermissionError: refused; another OSError)."""

    def __init__(self, winreg):
        self.w = winreg
        self.roots = {"HKU": winreg.HKEY_USERS, "HKLM": winreg.HKEY_LOCAL_MACHINE}

    def _open(self, root, path, view32):
        w = self.w
        return w.OpenKey(self.roots[root], path, 0, w.KEY_READ | (w.KEY_WOW64_32KEY if view32 else w.KEY_WOW64_64KEY))

    def _each(self, root, path, view32, count_at, enum):
        out = []
        with self._open(root, path, view32) as key:
            for i in range(self.w.QueryInfoKey(key)[count_at]):
                try:
                    out.append(enum(key, i))
                except OSError as exc:
                    if getattr(exc, "winerror", None) == NO_MORE_ITEMS:   # fewer than counted: one went meanwhile
                        break
                    raise
        return out

    def subkeys(self, root, path, view32=False):
        return self._each(root, path, view32, 0, self.w.EnumKey)

    def values(self, root, path, view32=False):
        """[(name, data, type)] of the key's values."""
        return [tuple(v) for v in self._each(root, path, view32, 1, self.w.EnumValue)]


class Disk:
    """The Startup folders as read() asks them: the names of the files directly in a folder, and a file's sha256
    (its content is read in chunks and kept nowhere). A test hands in its own."""

    def files(self, folder):
        with os.scandir(folder) as it:
            return [e.name for e in it if e.is_file()]

    def sha256(self, folder, name):
        h = hashlib.sha256()
        with open(os.path.join(folder, name), "rb") as f:
            for chunk in iter(lambda: f.read(CHUNK), b""):
                h.update(chunk)
        return h.hexdigest()


def _why(exc):
    """An error's reason without its text (a path in it could hold a user's name): its kind and its number."""
    code = getattr(exc, "winerror", None)
    code = getattr(exc, "errno", None) if code is None else code
    return "%s%s" % (type(exc).__name__, "" if code is None else " (%s)" % code)


def _hash(text):
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


def _bytes(typ, data):
    """A value's content as bytes, its registry type first, so that "1" and the number 1 differ."""
    if isinstance(data, (bytes, bytearray)):
        body = bytes(data)
    elif isinstance(data, str):
        body = data.encode("utf-8", "surrogatepass")
    elif isinstance(data, (list, tuple)):
        body = "\0".join(str(x) for x in data).encode("utf-8", "surrogatepass")
    elif data is None:
        body = b""
    else:
        body = str(data).encode("utf-8", "surrogatepass")
    return ("%s:" % typ).encode("ascii") + body


def _digest(*parts):
    """The sha256 of a value's content, or of several (a service's three, a task's two), each (type, data);
    None for a part not there."""
    h = hashlib.sha256()
    for part in parts:
        h.update(b"\0-" if part is None else b"\0+" + _bytes(*part))
    return h.hexdigest()


def _program(data):
    """The program a content would run, as PERSIST-RUN-KEY's line names it; None where it is not text."""
    return os_sysmon.registry_program(data) if isinstance(data, str) else None


class _Place:
    def __init__(self, name):
        self.name, self.entries, self.opened, self.refused, self.failed = name, [], 0, [], None

    def ask(self, ident, call):
        """call()'s answer; None where the key is not there (empty), refused (counted) or failed (the place
        failed, with its reason)."""
        try:
            got = call()
        except FileNotFoundError:
            return None
        except PermissionError:
            self.refused.append(ident)
            return None
        except OSError as exc:
            if getattr(exc, "winerror", None) == GONE_WHILE_OPEN:   # AH-5: deleted while it was read: not there
                return None
            if self.failed is None:
                self.failed = _why(exc)
            return None
        except Exception as exc:   # AG-2: another error is said with its reason
            if self.failed is None:
                self.failed = _why(exc)
            return None
        self.opened += 1
        return got

    def add(self, scope, view32, raw_name, program, digest, where):
        shown = os_sysmon.value_name(SID_IN_NAME.sub("[sid]", raw_name))   # AH-1: a SID in a name is not shown
        self.entries.append({"place": self.name, "scope": scope, "view32": view32,
                             "name": shown, "program": program, "sha256": digest,
                             "key": _hash("\0".join((self.name, where, "32" if view32 else "64", raw_name.lower())))})

    def said(self):
        if self.failed is not None:
            state = "failed"
        elif self.refused and not self.opened:
            state = "refused"
        elif self.refused:
            state = "partly"
        else:
            state = "read"
        return {"state": state, "entries": len(self.entries), "keys_refused": len(self.refused),
                "reason": self.failed, "refused_sha256": _hash("\n".join(sorted(self.refused)))}


def _run_keys(reg, places):
    """Run and RunOnce of every loaded user's hive (by its SID) and of the machine's, both views."""
    users = places["run"].ask("HKU", lambda: reg.subkeys("HKU", "", False))
    if users is None:   # the users' hives not listed: said for RunOnce as for Run
        places["runonce"].refused += places["run"].refused
        places["runonce"].failed = places["run"].failed
    hives = [("HKU", sid + "\\Software", "user", "HKU\\" + sid) for sid in sorted(users or ()) if SID.match(sid)]
    hives.append(("HKLM", "SOFTWARE", "machine", "HKLM"))
    for kind, leaf in RUN_KEYS:
        place = places[kind]
        for root, soft, scope, hive in hives:
            path = "%s\\%s\\%s" % (soft, CURRENT_VERSION, leaf)
            seen = set()
            for view32 in (False, True):
                got = place.ask("%s\\%s %d" % (hive, leaf, view32),
                                lambda: reg.values(root, path, view32))
                for name, data, typ in got or ():
                    name = "" if name is None else str(name)
                    digest = _digest((typ, data))
                    if (name.lower(), digest) in seen:   # the same entry seen in the other view: counted once
                        continue
                    seen.add((name.lower(), digest))
                    place.add(scope, view32, name, _program(data), digest, hive)


def _startup(disk, folders, place):
    for scope, _ in STARTUP_ROOTS:
        folder = folders.get(scope)
        if not folder:
            if place.failed is None:
                place.failed = "the %s Startup folder is not known (its environment variable is not set)" % scope
            continue
        names = place.ask("startup %s" % scope, lambda: disk.files(folder))
        for name in sorted(names or ()):
            if name.lower() in LEFT_OUT:
                continue
            try:
                digest = disk.sha256(folder, name)
            except FileNotFoundError:   # gone between the listing and the read
                continue
            except PermissionError:
                place.refused.append("startup %s %s" % (scope, name))
                digest = None
            except Exception as exc:
                if place.failed is None:
                    place.failed = _why(exc)
                continue
            place.add(scope, False, name, None, digest, "startup " + scope)


def _services(reg, place):
    for name in sorted(place.ask("services", lambda: reg.subkeys("HKLM", SERVICES, False)) or ()):
        got = place.ask("service " + name, lambda: reg.values("HKLM", SERVICES + "\\" + name, False))
        if got is None:
            continue
        held = {str(n).lower(): (t, d) for n, d, t in got}
        if "imagepath" not in held:   # a key of the services with no ImagePath runs nothing: not an entry
            continue
        image = held["imagepath"][1]
        place.add("machine", False, name, _program(image),
                  _digest(held["imagepath"], held.get("start"), held.get("type")), "services")


def _tasks(reg, place, path, rel, depth):
    subs = place.ask("tree " + rel, lambda: reg.subkeys("HKLM", path, False)) if depth == 0 else \
        place.ask("folder " + rel, lambda: reg.subkeys("HKLM", path, False))
    if subs is None:
        return
    for name in sorted(subs):
        sub, sub_rel = path + "\\" + name, rel + "\\" + name
        got = place.ask("tree " + sub_rel, lambda: reg.values("HKLM", sub, False))
        if got is None:   # refused, failed or gone: its folder is not walked (a refused key is counted once)
            continue
        held = {str(n).lower(): (t, d) for n, d, t in got}
        ident = held.get("id", (None, None))[1]
        if isinstance(ident, str) and ident:
            body = place.ask("task " + ident, lambda: reg.values("HKLM", TASK_BODIES + "\\" + ident, False))
            if body is None and ("task " + ident) in place.refused:
                digest = None
            else:
                parts = {str(n).lower(): (t, d) for n, d, t in body or ()}
                digest = _digest(parts.get("actions"), parts.get("triggers"))
            place.add("machine", False, sub_rel, None, digest, "tree")
        if depth < TASK_DEPTH:
            _tasks(reg, place, sub, sub_rel, depth + 1)
        else:   # AH-2: a folder below the bound is not walked, and is counted as a key not read (the place: partly)
            deeper = place.ask("folder " + sub_rel, lambda: reg.subkeys("HKLM", sub, False))
            if deeper:
                place.refused.append("deeper " + sub_rel)


def _winlogon(reg, place):
    got = place.ask("winlogon", lambda: reg.values("HKLM", WINLOGON, False))
    held = {str(n).lower(): (str(n), t, d) for n, d, t in got or ()}
    for want in WINLOGON_VALUES:
        if want.lower() in held:
            name, typ, data = held[want.lower()]
            place.add("machine", False, name, _program(data), _digest((typ, data)), "winlogon")


def default_folders(environ=None):
    """The user's and all users' Startup folders, from APPDATA and ProgramData (None where one is not set)."""
    environ = os.environ if environ is None else environ
    return {scope: os.path.join(environ[var], *STARTUP) if environ.get(var) else None for scope, var in STARTUP_ROOTS}


def read(registry=None, folders=None, platform=None, clock=None, disk=None):
    """One read of every place (AG-1): {"read", "said", "platform", "seconds", "entries", "places"}. On Windows,
    with no registry handed in, winreg is imported here; off Windows with none handed in nothing is read and
    `said` is the sentence that says so. It never raises: a place whose read fails is `failed`, with its reason."""
    platform = sys.platform if platform is None else platform
    clock = clock or time.monotonic
    t0 = _now(clock)
    result = {"read": False, "said": None, "platform": platform, "seconds": 0.0, "entries": [], "places": {}}
    places = {p: _Place(p) for p in PLACES}
    try:
        if registry is None:
            if not str(platform).startswith("win"):
                result["said"] = NOT_WINDOWS % platform
                return result
            try:
                import winreg   # Windows' alone: imported inside the call, never at the module's import
                registry = WinRegistry(winreg)
            except Exception as exc:
                for p in PLACES:
                    places[p].failed = "winreg cannot be used (%s)" % _why(exc)
        result["read"] = True
        folders = default_folders() if folders is None else folders
        disk = disk or Disk()
        steps = (("run", lambda: _run_keys(registry, places)),
                 ("startup", lambda: _startup(disk, folders, places["startup"])),
                 ("service", lambda: _services(registry, places["service"])),
                 ("task", lambda: _tasks(registry, places["task"], TASK_TREE, "", 0)),
                 ("winlogon", lambda: _winlogon(registry, places["winlogon"])))
        for name, step in steps:
            if places[name].failed is not None:   # winreg could not be used
                continue
            try:
                step()
            except Exception as exc:   # never raises: the place failed
                places[name].failed = places[name].failed or _why(exc)
                if name == "run":
                    places["runonce"].failed = places["runonce"].failed or _why(exc)
        entries = []
        for p in PLACES:
            entries += places[p].entries
        result["entries"] = sorted(entries, key=lambda e: (PLACES.index(e["place"]), e["scope"], e["name"], e["key"]))
        result["places"] = {p: places[p].said() for p in PLACES}
    except Exception as exc:   # never raises
        result["read"] = True
        result["entries"] = []
        result["places"] = {p: dict(_Place(p).said(), state="failed", reason=_why(exc)) for p in PLACES}
    t1 = _now(clock)
    result["seconds"] = None if t0 is None or t1 is None else round(max(0.0, t1 - t0), 3)
    return result


def _now(clock):
    """The clock's time, or None where it fails (a read never raises: its time is then not known)."""
    try:
        return float(clock())
    except Exception:
        return None


def unread(result, place):
    """Why a read gives no change for a place (AG-2), or None where it was read (whole or in part)."""
    if not isinstance(result, dict) or not result.get("read"):
        return "not read"
    said = (result.get("places") or {}).get(place)
    if not isinstance(said, dict):
        return "not read"
    if said.get("state") == "refused":
        return "refused"
    if said.get("state") == "failed":
        return "failed (%s)" % said.get("reason")
    return None


FIELDS = ("place", "scope", "view32", "name", "program", "sha256", "key")


def changes(before, after):
    """AG-3: {"changes": [...], "unread": {place: why}}. Every entry added, changed (its hash) or removed, with
    the entry's fields and `change` (a changed one carries the hash it had, `was`). A place refused or failed in
    either read, or whose refused keys are not the same in both, gives no change and is named in `unread`. An
    entry is known by its `key`: the same entry seen twice in one read is one entry."""
    gone = {}
    for p in PLACES:
        why = [w for w in (unread(before, p), unread(after, p)) if w]
        if why:
            gone[p] = "; ".join(sorted(set(why)))
            continue
        b, a = before["places"][p], after["places"][p]
        if b.get("refused_sha256") != a.get("refused_sha256"):
            gone[p] = "the keys refused are not the same in the two reads (%s, then %s)" % (
                b.get("keys_refused"), a.get("keys_refused"))

    def keyed(result):
        return {e["key"]: e for e in result.get("entries") or () if e.get("place") not in gone}
    old, new = keyed(before), keyed(after)
    out = []
    for key in set(old) | set(new):
        if key not in old:
            out.append(dict({f: new[key].get(f) for f in FIELDS}, change="added"))
        elif key not in new:
            out.append(dict({f: old[key].get(f) for f in FIELDS}, change="removed"))
        elif old[key].get("sha256") != new[key].get("sha256"):
            out.append(dict({f: new[key].get(f) for f in FIELDS}, change="changed", was=old[key].get("sha256")))
    out.sort(key=lambda c: (PLACES.index(c["place"]) if c["place"] in PLACES else len(PLACES), c["scope"] or "",
                            c["name"] or "", c["change"], c["key"]))
    return {"changes": out, "unread": gone}


def first_line(result):
    """The first read in one ASCII line: entries per place, what is refused, the seconds it took."""
    if not result.get("read"):
        return os_sysmon.safe(result.get("said") or "autostart: nothing is read")
    parts, refused, failed = [], [], []
    for p in PLACES:
        s = result["places"][p]
        if s["state"] == "refused":
            refused.append(p)
            parts.append("%s refused" % p)
        elif s["state"] == "failed":
            failed.append("%s (%s)" % (p, s["reason"]))
            parts.append("%s failed" % p)
        elif s["state"] == "partly":
            parts.append("%s %d (%d key(s) refused)" % (p, s["entries"], s["keys_refused"]))
        else:
            parts.append("%s %d" % (p, s["entries"]))
    took = result.get("seconds")
    took = "in %.2f s" % took if isinstance(took, (int, float)) else "in an unknown time"
    return os_sysmon.safe("autostart round 1: %d entries %s: %s; refused: %s; failed: %s" % (
        len(result["entries"]), took, ", ".join(parts), ", ".join(refused) or "none",
        "; ".join(failed) or "none"), 1000)


def change_line(round_no, c):
    """`CHANGE round 3: added service "name" (would run cmd.exe)`, ASCII."""
    words = '%s %s "%s"' % (c["change"], c["place"], c["name"])
    if c["place"] in ("run", "runonce", "startup"):
        words += " of the %s" % c["scope"]
    if c.get("view32"):
        words += ", 32-bit view"
    if c.get("program"):
        words += " (would run %s)" % c["program"]
    return os_sysmon.safe("CHANGE round %d: %s" % (round_no, words), 1000)


def unread_line(round_no, gone):
    return os_sysmon.safe("UNREAD round %d: %s" % (round_no, "; ".join("%s (%s)" % (p, gone[p]) for p in PLACES
                                                                       if p in gone)), 1000)


def main(argv=None, out=None, reader=None, sleep=None):
    out = out or sys.stdout
    reader, sleep = reader or read, sleep or time.sleep
    p = argparse.ArgumentParser(prog="python -m raqib.autostart",
                                description="Read Windows' autostart places, and say what changed between reads.")
    p.add_argument("--rounds", type=int, default=1, help="how many reads (1 or more; default 1)")
    p.add_argument("--every", type=float, default=5.0, help="seconds between two reads (default 5)")
    try:
        a = p.parse_args(argv)
    except SystemExit as exc:
        return 0 if exc.code == 0 else 2
    if a.rounds < 1 or not math.isfinite(a.every) or a.every < 0:
        print("python -m raqib.autostart: --rounds is 1 or more and --every 0 or more", file=sys.stderr)
        return 2
    before = reader()
    print(first_line(before), file=out, flush=True)
    if not before.get("read"):
        return 0
    for round_no in range(2, a.rounds + 1):
        sleep(a.every)
        now = reader()
        got = changes(before, now)
        for c in got["changes"]:
            print(change_line(round_no, c), file=out, flush=True)
        if got["unread"]:
            print(unread_line(round_no, got["unread"]), file=out, flush=True)
        before = now
    return 0


if __name__ == "__main__":
    sys.exit(main())
