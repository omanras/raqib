"""The rig's run of the autostart places' read (ADR-0014 Amendments G and I, AG-4, AI-10; M15.3a, M15.3b): on
Windows it reads the places with a raqib.autostart.Watcher, which compares each read with what every place and key
last held when it was read. First a file held open: it makes a file in the user's Startup folder (it holds a
`rem`), holds it open with no sharing across one read, lets it go, reads again, removes it and reads again, and
writes what each of those reads said of it. Then it starts the stand-in agent (tools/rig/workload.py) as its own
child, reads every EVERY_S seconds while the stand-in works and once after it ended, and writes every change,
with its read's number, as JSON for tools/rig/check.py, which states X37. It judges nothing itself.

    python tools/rig/autostart_run.py --out FACTS.json

The facts: the first read's places (state, entries, keys not read, reason), how many reads were made and the
longest one's seconds, every change (round, change, place, scope, view32, name, program, sure, and a hive's count
of entries: never a hash, a value's text or a SID), every read that left a place unread or read in part, the held
file's reads, and the stand-in's WORKLOAD lines and exit code (its lines are printed as they come, so the job's
log holds them). Off Windows nothing is run, and the reason is the fact. It never raises: an error is a fact,
said by its kind alone; it writes its facts and exits 0 whatever happened (2 only for its own usage). The
standard library and raqib.autostart only. A test hands in its own watcher, holder, stand-in and clock.
"""
import argparse
import json
import os
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
from raqib import autostart  # noqa: E402

EVERY_S = 1.0         # between two reads while the stand-in works
LIMIT_S = 240.0       # the stand-in is given this long; then it is ended, and that is said
CHANGE_FIELDS = ("change", "place", "scope", "view32", "name", "program", "sure", "entries")
HELD_NAME = "raqib-rig-held.cmd"
HELD_TEXT = b"rem raqib rig held\r\n"
GENERIC_READ, GENERIC_WRITE, CREATE_NEW, FILE_ATTRIBUTE_NORMAL = 0x80000000, 0x40000000, 1, 0x80


def start_stand_in():
    """The stand-in agent as this run's child, its output a pipe of text."""
    return subprocess.Popen([sys.executable, os.path.join(HERE, "workload.py")], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                            errors="replace")


def hold_open(path):
    """Windows: makes the file (CREATE_NEW), writes a `rem` into it and keeps it open with no sharing (share mode
    0), so that no other open of it is given while it is held; returns the function that lets it go. Raises an
    OSError where it cannot be made so."""
    import ctypes
    from ctypes import wintypes
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                              wintypes.DWORD, wintypes.HANDLE]
    k.CreateFileW.restype = wintypes.HANDLE
    k.WriteFile.argtypes = [wintypes.HANDLE, ctypes.c_char_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                            ctypes.c_void_p]
    k.WriteFile.restype = wintypes.BOOL
    k.CloseHandle.argtypes = [wintypes.HANDLE]
    k.CloseHandle.restype = wintypes.BOOL
    handle = k.CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, None, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, None)
    if handle is None or handle == ctypes.c_void_p(-1).value:
        raise OSError(None, "the held file was not made", None, ctypes.get_last_error())
    wrote = wintypes.DWORD(0)
    if not k.WriteFile(handle, HELD_TEXT, len(HELD_TEXT), ctypes.byref(wrote), None):
        error = ctypes.get_last_error()
        k.CloseHandle(handle)
        raise OSError(None, "the held file was not written", None, error)
    return lambda: k.CloseHandle(handle)


def _drain(child, lines):
    for line in child.stdout:
        line = line.rstrip("\r\n")
        print(line, flush=True)
        if line.startswith("WORKLOAD "):
            lines.append(line)


def _places(result):
    return {p: {k: s.get(k) for k in ("state", "entries", "keys_refused", "keys_why", "reason")}
            for p, s in (result.get("places") or {}).items()}


class _Reads:
    """Every read of the run, each taken by the watcher; its changes and its unread places kept as facts."""

    def __init__(self, watcher, facts):
        self.watcher, self.facts, self.round = watcher, facts, 0

    def next(self):
        result = self.watcher.read()
        got = self.watcher.take(result)
        self.round += 1
        f = self.facts
        f["reads"] = self.round
        f["seconds_max"] = max(f["seconds_max"] or 0.0, result.get("seconds") or 0.0)
        if self.round == 1:
            f["first"] = {"read": result.get("read"), "said": result.get("said"),
                          "entries": len(result.get("entries") or ()), "places": _places(result)}
        f["changes"] += [dict({k: c.get(k) for k in CHANGE_FIELDS if k in c}, round=self.round)
                         for c in got["changes"]]
        if got["unread"]:
            f["unread"].append({"round": self.round, "places": got["unread"]})
        return result, got


def _of_held(rnd, result, got, held_now):
    """What one read said of the held file: listed, its content read or not, its changes."""
    mine = [e for e in result.get("entries") or () if e.get("place") == "startup" and e.get("scope") == "user"
            and e.get("name") == HELD_NAME]
    return {"round": rnd, "held": held_now, "listed": bool(mine),
            "content": None if not mine else "read" if mine[0].get("sha256") else "not read",
            "changes": [c["change"] for c in got["changes"] if c.get("place") == "startup"
                        and c.get("name") == HELD_NAME]}


def collect(watcher=None, start=None, hold=None, folder=None, platform=None, sleep=None, clock=None, every=EVERY_S,
            limit=LIMIT_S):
    platform = sys.platform if platform is None else platform
    start, hold, sleep, clock = start or start_stand_in, hold or hold_open, sleep or time.sleep, clock or time.monotonic
    facts = {"platform": platform, "first": None, "reads": 0, "seconds_max": None, "changes": [], "unread": [],
             "held": {"made": False, "error": None, "reads": [], "removed": False},
             "workload": [], "workload_rc": None, "ended_by_run": False, "error": None}
    if not str(platform).startswith("win"):
        facts["not_run"] = "not Windows (%s): the autostart places read here are Windows'" % platform
        return facts
    child = None
    try:
        reads = _Reads(watcher or autostart.Watcher(), facts)
        reads.next()
        held = facts["held"]
        folder = folder or (autostart.default_folders().get("user") or "")
        path = os.path.join(folder, HELD_NAME)
        release = None
        try:
            release = hold(path)
            held["made"] = True
        except Exception as exc:
            held["error"] = autostart._why(exc)
        if held["made"]:
            try:
                for now_held in (True, False, None):   # held across one read; let go; removed
                    if now_held is False:
                        release()
                    elif now_held is None:
                        os.remove(path)
                        held["removed"] = True
                    sleep(every)
                    result, got = reads.next()
                    held["reads"].append(_of_held(reads.round, result, got, bool(now_held)))
            except Exception as exc:
                held["error"] = autostart._why(exc)
            finally:
                if not held["removed"]:
                    try:
                        if release is not None:
                            release()
                        os.remove(path)
                        held["removed"] = True
                    except Exception:
                        pass
        child = start()
        drain = threading.Thread(target=_drain, args=(child, facts["workload"]), daemon=True)
        drain.start()
        end = clock() + limit
        while True:
            done = child.poll() is not None
            sleep(every)
            reads.next()
            if done or clock() >= end:
                break
        if child.poll() is None:
            facts["ended_by_run"] = True
            child.kill()
        facts["workload_rc"] = child.wait(30)
        drain.join(10)
    except Exception as exc:
        facts["error"] = autostart._why(exc)   # its kind and number alone: an error's text can hold a path
        facts["ended_by_run"] = child is not None and child.poll() is None
        if child is not None and child.poll() is None:
            try:
                child.kill()
            except Exception:
                pass
    return facts


def main(argv=None, **hand):
    p = argparse.ArgumentParser(prog="tools/rig/autostart_run.py")
    p.add_argument("--out", required=True)
    a = p.parse_args(argv)
    facts = collect(**hand)
    try:
        with open(a.out, "w", encoding="utf-8") as f:
            json.dump(facts, f, indent=1, sort_keys=True)
    except OSError as exc:
        print("autostart_run: the facts could not be written (%s)" % type(exc).__name__)
        return 0
    print("autostart_run: %s; %d read(s), %d change(s), the longest read %s s; held file: %s; not run: %s;"
          " error: %s" % (facts["platform"], facts["reads"], len(facts["changes"]), facts["seconds_max"],
                          "made" if facts["held"]["made"] else facts["held"]["error"] or "not made",
                          facts.get("not_run") or "no", facts["error"] or "none"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
