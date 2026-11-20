"""Probe only: what the stand-in's tree left in its source (the lines' tools and what each carries), and the
watch's findings, from ~/.raqib; the stand-in's pid is read from its own output (argv 1)."""
import glob
import json
import os
import re
import sys

text = open(sys.argv[1], encoding="utf-8", errors="replace").read() if len(sys.argv) > 1 else ""
text = text.replace("\x00", "")
found = re.search(r"WORKLOAD \S+ pid (\d+)", text)
pid = found.group(1) if found else None
print("the stand-in's pid:", pid)
home = os.path.join(os.path.expanduser("~"), ".raqib", "host")
KEYS = ("image", "parent_image", "depth", "path", "dest_port", "dest_private", "command_programs", "under_root",
        "autostart", "hive", "view32", "value_name", "program")
for path in sorted(glob.glob(os.path.join(home, "sources", "*.jsonl"))):
    name = os.path.basename(path)
    mine = pid is not None and ("-%s-" % pid) in name
    kinds = {}
    rows = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            try:
                d = json.loads(line)
            except ValueError:
                continue
            if d.get("phase") not in ("pre", "session_start"):
                continue
            kinds[d.get("tool")] = kinds.get(d.get("tool"), 0) + 1
            meta = d.get("input_meta") or {}
            rows.append("  seq %s %s %s %s" % (d.get("seq"), d.get("ts"), d.get("tool"), json.dumps(
                {k: meta[k] for k in KEYS if k in meta}, sort_keys=True)))
    print("source %s%s: %s" % (name, " (the stand-in's)" if mine else "", json.dumps(kinds, sort_keys=True)))
    if mine:
        for row in rows[:160]:
            print(row[:300])
events = os.path.join(home, "events.jsonl")
try:
    with open(events, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            try:
                d = json.loads(line)
            except ValueError:
                continue
            if d.get("kind") in ("finding", "source-finding"):
                rule = d.get("rule") if isinstance(d.get("rule"), dict) else {}
                subject = d.get("subject") if isinstance(d.get("subject"), dict) else {}
                print("event %s %s %s tree %s: %s" % (d.get("kind"), rule.get("id"), d.get("severity"),
                                                    subject.get("tree"), str(d.get("summary"))[:200]))
except OSError as exc:
    print("events:", type(exc).__name__)

many = set()
for path in sorted(glob.glob(os.path.join(home, "sources", "*.jsonl"))):
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            many.update(re.findall(r"RaqibRigMany\d\d", line))
print("of the 40 values set one by one, each by a fresh reg.exe: %d are a registry line (missing: %s)" % (
    len(many), sorted(set("RaqibRigMany%02d" % i for i in range(40)) - many)))
