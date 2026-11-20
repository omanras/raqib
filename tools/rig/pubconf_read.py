"""Probe only: what a public Sysmon configuration logged during the stand-in's three acts. Reads the channel's
export (argv 1, wevtutil's XML) and says: events per id; the registry's value events (13) per 10 seconds; the
families of their keys; those directly under Run or RunOnce; file events in a Startup folder; connections to
port 22. Nothing is written."""
import collections
import datetime
import re
import sys

raw = open(sys.argv[1], "rb").read()
text = raw.decode("utf-16", "replace") if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else raw.decode("utf-8", "replace")
events = re.findall(r"<Event[ >].*?</Event>", text, re.S)
print("events in the export:", len(events))


def field(ev, name):
    m = re.search(r"<Data Name=['\"]%s['\"]>(.*?)</Data>" % re.escape(name), ev, re.S)
    return m.group(1) if m else None


def when(ev):
    m = re.search(r"SystemTime=['\"]([0-9T:\-]{19})", ev)
    return datetime.datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S") if m else None


ids = collections.Counter()
per = collections.Counter()
fam = collections.Counter()
run, startup, port22, times = [], [], [], []
RUN = re.compile(r"\\CurrentVersion\\(Run|RunOnce)\\[^\\]+$", re.I)
for ev in events:
    m = re.search(r"<EventID[^>]*>(\d+)</EventID>", ev)
    if not m:
        continue
    i = int(m.group(1))
    ids[i] += 1
    t = when(ev)
    if t:
        times.append(t)
    if i == 13:
        target = field(ev, "TargetObject") or ""
        if t:
            per[int(t.timestamp()) // 10] += 1
        parts = target.split("\\")
        if len(parts) > 1 and parts[0] == "HKU":
            parts[1] = "<SID>"
        fam["\\".join(parts[:6])] += 1
        if "Slash" in target:
            print("event 13 of the value whose name holds a backslash: TargetObject %r" % re.sub(
                r"^HKU\\[^\\]+", r"HKU\\<SID>", target))
        if RUN.search(target):
            run.append((field(ev, "Image"), re.sub(r"^HKU\\[^\\]+", r"HKU\\<SID>", target)))
    elif i == 11:
        target = field(ev, "TargetFilename") or ""
        if re.search(r"\\Start Menu\\Programs\\Startup\\", target, re.I):
            startup.append((field(ev, "Image"), target.rsplit("\\", 1)[-1]))
    elif i == 3:
        if field(ev, "DestinationPort") == "22":
            port22.append((field(ev, "Image"), field(ev, "Initiated")))
if times:
    print("span: %s to %s (%d s)" % (min(times), max(times), (max(times) - min(times)).total_seconds()))
print("events per id:", dict(sorted(ids.items())))
counts = sorted(per.values())
if counts:
    print("event 13 per 10 s: windows with any %d, max %d, median %d, sum %d" % (
        len(counts), counts[-1], counts[len(counts) // 2], sum(counts)))
else:
    print("event 13: none")
print("event 13, the key families (the 25 most):")
for name, n in fam.most_common(25):
    print("  %5d  %s" % (n, name))
print("event 13 directly under Run or RunOnce: %d" % len(run))
for image, target in run[:20]:
    print("  %s -> %s" % ((image or "?").rsplit("\\", 1)[-1], target))
print("event 11 in a Startup folder: %d" % len(startup))
for image, name in startup[:10]:
    print("  %s -> %s" % ((image or "?").rsplit("\\", 1)[-1], name))
print("event 3 to port 22: %d" % len(port22))
for image, init in port22[:10]:
    print("  %s initiated %s" % ((image or "?").rsplit("\\", 1)[-1], init))
