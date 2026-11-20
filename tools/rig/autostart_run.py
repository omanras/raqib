"""The rig's run of the autostart places' read (ADR-0014 Amendment G, AG-4; M15.3a): on Windows it reads the places
with raqib.autostart.read, starts the stand-in agent (tools/rig/workload.py) as its own child, reads them again
every EVERY_S seconds while the stand-in works and once after it ended, compares each read with the one before it
(raqib.autostart.changes) and writes every change, with its read's number, as JSON for tools/rig/check.py, which
states X37. It judges nothing itself.

    python tools/rig/autostart_run.py --out FACTS.json

The facts: the first read's places (state, entries, keys refused, reason), how many reads were made and the
longest one's seconds, every change (round, change, place, scope, view32, name, program: never a hash, a value's
text or a SID), every read whose comparison left a place unread, and the stand-in's WORKLOAD lines and exit code
(its lines are printed as they come, so the job's log holds them). Off Windows nothing is run, and the reason is
the fact. It never raises: an error is a fact; it writes its facts and exits 0 whatever happened (2 only for its
own usage). The standard library and raqib.autostart only. A test hands in its own reader, stand-in and clock.
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
CHANGE_FIELDS = ("change", "place", "scope", "view32", "name", "program")


def start_stand_in():
    """The stand-in agent as this run's child, its output a pipe of text."""
    return subprocess.Popen([sys.executable, os.path.join(HERE, "workload.py")], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                            errors="replace")


def _drain(child, lines):
    for line in child.stdout:
        line = line.rstrip("\r\n")
        print(line, flush=True)
        if line.startswith("WORKLOAD "):
            lines.append(line)


def _places(result):
    return {p: {k: s.get(k) for k in ("state", "entries", "keys_refused", "reason")}
            for p, s in (result.get("places") or {}).items()}


def collect(reader=None, compare=None, start=None, platform=None, sleep=None, clock=None, every=EVERY_S,
            limit=LIMIT_S):
    platform = sys.platform if platform is None else platform
    reader, compare = reader or autostart.read, compare or autostart.changes
    start, sleep, clock = start or start_stand_in, sleep or time.sleep, clock or time.monotonic
    facts = {"platform": platform, "first": None, "reads": 0, "seconds_max": None, "changes": [], "unread": [],
             "workload": [], "workload_rc": None, "ended_by_run": False, "error": None}
    if not str(platform).startswith("win"):
        facts["not_run"] = "not Windows (%s): the autostart places read here are Windows'" % platform
        return facts
    child = None
    try:
        before = reader()
        facts["reads"], facts["seconds_max"] = 1, before.get("seconds")
        facts["first"] = {"read": before.get("read"), "said": before.get("said"),
                          "entries": len(before.get("entries") or ()), "places": _places(before)}
        child = start()
        drain = threading.Thread(target=_drain, args=(child, facts["workload"]), daemon=True)
        drain.start()
        end, round_no = clock() + limit, 1
        while True:
            done = child.poll() is not None
            sleep(every)
            now = reader()
            round_no += 1
            facts["reads"] = round_no
            facts["seconds_max"] = max(facts["seconds_max"] or 0.0, now.get("seconds") or 0.0)
            got = compare(before, now)
            facts["changes"] += [dict({f: c.get(f) for f in CHANGE_FIELDS}, round=round_no) for c in got["changes"]]
            if got["unread"]:
                facts["unread"].append({"round": round_no, "places": got["unread"]})
            before = now
            if done or clock() >= end:
                break
        if child.poll() is None:
            facts["ended_by_run"] = True
            child.kill()
        facts["workload_rc"] = child.wait(30)
        drain.join(10)
    except Exception as exc:
        facts["error"] = "%s: %s" % (type(exc).__name__, " ".join(str(exc).split())[:200])
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
    print("autostart_run: %s; %d read(s), %d change(s), the longest read %s s; not run: %s; error: %s" % (
        facts["platform"], facts["reads"], len(facts["changes"]), facts["seconds_max"],
        facts.get("not_run") or "no", facts["error"] or "none"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
