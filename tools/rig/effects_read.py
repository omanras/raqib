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
        for row in rows[:60]:
            print(row[:300])
        print("  ... the last 12 of %d:" % len(rows))
        for row in rows[-12:]:
            print(row[:300])
        with open(path, encoding="utf-8", errors="replace") as fh:
            marks = [line.strip()[:260] for line in fh if "RAQIB-SILENCE" in line or '"session_start"' in line
                     or '"session_end"' in line]
        print("  its passes (session marks and silences), %d:" % len(marks))
        for m in marks:
            print("   ", m)
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

regs = 0
for path in sorted(glob.glob(os.path.join(home, "sources", "*.jsonl"))):
    if pid is None or ("-%s-" % pid) not in os.path.basename(path) or path.endswith("-host.jsonl"):
        continue
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if '"phase":"pre"' in line and '"tool":"process"' in line and '"image":"reg"' in line:
                regs += 1
print("process lines of reg in the stand-in's source: %d (the stand-in started reg 46 times before its undo)" % regs)

debug = os.path.join(home, "follow-debug.log")
try:
    with open(debug, encoding="utf-8", errors="replace") as fh:
        rows = [line.strip() for line in fh if pid is not None and ('"pid": %s,' % pid) in line]
    print("the follow's passes of the stand-in's tree (probe only), %d; the last 14:" % len(rows))
    for row in rows[-14:]:
        print("   ", row[:420])
except OSError as exc:
    print("follow-debug:", type(exc).__name__)

try:
    import collections
    seen = collections.Counter()
    with open(os.path.join(home, "round-debug.log"), encoding="utf-8", errors="replace") as fh:
        for line in fh:
            d = json.loads(line)
            if not 10 <= d.get("round", 0) <= 20:
                continue
            mine = [t for t in d.get("trees") or [] if pid is not None and str(pid) in json.dumps(t)]
            new = [h for h in d.get("holes") or [] if not seen[h]]
            for h in d.get("holes") or []:
                seen[h] += 1
            print("round %s at %s: holes %d; the stand-in's tree in the inventory: %s; its source: %s; quiet: %s; "
                  "holes not seen before: %s" % (
                      d.get("round"), d.get("at"), len(d.get("holes") or []), mine,
                      (d.get("sources") or {}).get(str(pid)), [q for q in d.get("quiet") or [] if str(pid) in q],
                      [h[:200] for h in new][:3]))
            if d.get("round") == 10:
                print("   the inventory's keys:", d.get("inv_keys"))
except (OSError, ValueError) as exc:
    print("round-debug:", type(exc).__name__)
