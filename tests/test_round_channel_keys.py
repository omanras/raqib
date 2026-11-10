"""M7.9 REDO (ADR-0007 Amendment X, X-2): two records are one process only
when everything read agrees - the pid, the image, and the start within
discover.GUID_SAME_SECONDS where it was read on both sides. Enumerated, as
V-1 was: a pid held by one process, or by two in turn (another image; the
same image again), each with its event 1 read or not, sampled or not, its
talk in the channel or not, in every order of the channel's records. Every
record here is text (SYNTHETIC: host `host`, user `user`, RFC 5737)."""
import itertools
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from raqib import discover  # noqa: E402

NS = "http://schemas.microsoft.com/win/2004/08/events/event"
CONHOST = "C:\\Windows\\System32\\conhost.exe"
WHOAMI = "C:\\Windows\\System32\\whoami.exe"
# three processes that hold pid 5890 in turn: A (conhost), B (whoami: another image), C (conhost again)
PROCS = {"A": (CONHOST, "2026-11-10 07:50:00.100", "{4f1a2b3c-0000-6730-0001-000000005890}"),
         "B": (WHOAMI, "2026-11-10 07:50:05.500", "{4f1a2b3c-0000-6730-0002-000000005890}"),
         "C": (CONHOST, "2026-11-10 07:55:00.000", "{4f1a2b3c-0000-6730-0003-000000005890}")}
HEAD = ('"ProcessId","ParentProcessId","Name","ExecutablePath","CommandLine","CreationDate"\n'
        '"5888","5100","powershell.exe","C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",'
        '"powershell.exe","2026-11-10T07:49:00.000Z"\n')


def ev(eid, rec, name, utc):
    image, _, guid = PROCS[name]
    data = dict(UtcTime=utc, ProcessGuid=guid, ProcessId="5890", Image=image)
    if eid == 1:
        data.update(CommandLine=image.rsplit("\\", 1)[1], CurrentDirectory="C:\\Users\\user\\",
                    ParentProcessGuid="{4f1a2b3c-0000-6730-0000-000000005888}", ParentProcessId="5888",
                    ParentImage="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")
    else:
        data.update(Protocol="tcp", Initiated="true", SourceIp="192.0.2.10", SourcePort=str(50500 + rec),
                    DestinationIp="203.0.113.90", DestinationHostname="-", DestinationPort="443")
    body = "".join("<Data Name='%s'>%s</Data>" % kv for kv in data.items())
    return ("<Event xmlns='%s'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>%d</EventID>"
            "<TimeCreated SystemTime='%sZ'/><EventRecordID>%d</EventRecordID></System><EventData>%s</EventData>"
            "</Event>\n" % (NS, eid, utc.replace(" ", "T"), rec, body))


def sample_row(name):
    image, start, _ = PROCS[name]
    return '"5890","5888","%s","%s","%s","%s"\n' % (image.rsplit("\\", 1)[1], image, image.rsplit("\\", 1)[1],
                                                     start.replace(" ", "T") + "Z")


def procs_of(sampled, events):
    texts = {"win-process-1": ("fixture", HEAD + (sample_row(sampled) if sampled else ""), None),
             "sysmon": ("fixture channel", "".join(events), None)}
    records, holes = [], []
    for name in sorted(texts, key=discover._order):
        kind, _ = discover.split_name(name)
        parse = discover.PARSERS[kind] if kind != "sysmon" else (lambda t, n: discover.parse_sysmon(t, n, keyed=True))
        records += parse(texts[name][1], name)[0]
    records, holes = discover._instances(records)
    records, more = discover._guid_instances(records)
    procs = discover._merge_procs(records)
    return {pid: p for pid, p in procs.items() if pid % discover.REUSE == 5890}, holes + more


FORMS = [(s, e1, e3) for s in (False, True) for e1 in (False, True) for e3 in (False, True) if s or e1 or e3]


def cases():
    for names in (("A",), ("A", "B"), ("A", "C")):
        for forms in itertools.product(FORMS, repeat=len(names)):
            if sum(1 for f in forms if f[0]) > 1:
                continue   # one sample, one instant: at most one of two processes in turn is in it
            yield names, forms


def told(names, forms):
    """Whether the records can tell the processes apart: another image, or both starts read."""
    if len(names) == 1:
        return True
    a, b = PROCS[names[0]], PROCS[names[1]]
    if a[0] != b[0]:
        return True
    if all(f[1] or f[2] for f in forms):
        return True   # both in the channel: two ProcessGuids
    starts = [(f[0] or f[1]) for f in forms]   # a start is read from the sample or from an event 1
    return all(starts)


@pytest.mark.parametrize("names, forms", list(cases()))
def test_x2_one_process_one_key_in_every_order(names, forms):
    events, rec = [], 100
    sampled = None
    for name, (s, e1, e3) in zip(names, forms):
        image, start, guid = PROCS[name]
        if s:
            sampled = name
        if e1:
            events.append(ev(1, rec, name, start))
            rec += 1
        if e3:
            events.append(ev(3, rec, name, start[:-7] + "%02d.000" % (int(start[-6:-4]) + 2)))
            rec += 1
    expect = {name for name, f in zip(names, forms)}
    for order in itertools.permutations(events):
        procs, holes = procs_of(sampled, order)
        keys = sorted(procs)
        guids = [{r.get("guid") for r in procs[k]["recs"] if r.get("guid")} for k in keys]
        assert all(len(g) <= 1 for g in guids), (names, forms, guids)   # a root carries its own guid or none
        images = [set(procs[k]["images"]) for k in keys]
        assert all(len(i) == 1 for i in images), (names, forms, images)   # never one key for two images
        if told(names, forms):
            assert len(keys) == len(expect), (names, forms, keys, guids, holes)
            for name, f in zip(names, forms):
                if f[1] or f[2]:
                    assert {PROCS[name][2]} in guids, (name, forms, guids)
        else:   # same pid and image, a start unread on one side: not told apart, and said
            assert any("start" in h and "5890" in h for h in holes), (names, forms, holes)


def test_x2_p2b_the_guid_whose_start_agrees_takes_the_sampled_process_in_either_order():
    a_talk = ev(3, 101, "A", "2026-11-10 07:50:02.000")
    c_talk = ev(3, 102, "C", "2026-11-10 07:55:02.000")
    a_made = ev(1, 100, "A", PROCS["A"][1])
    for order in itertools.permutations([c_talk, a_made, a_talk]):
        procs, holes = procs_of("A", order)
        by_guid = {next(iter({r.get("guid") for r in p["recs"] if r.get("guid")} or {None})): p for p in procs.values()}
        sampled = [p for p in procs.values() if any(r["src"].startswith("win-process") for r in p["recs"])]
        assert len(sampled) == 1 and PROCS["A"][2] in {r.get("guid") for r in sampled[0]["recs"]}, order
        assert PROCS["C"][2] in by_guid and by_guid[PROCS["C"][2]] is not sampled[0], order
