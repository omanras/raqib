"""M7.9 (ADR-0007 Amendment P, ruling P-4): the round reads the channel.

Where Sysmon is readable each round of raqib watch --host also reads the
channel's events 1, 3, 11, 22 since the previous round (one bounded wevtutil)
and gives them to the same discover run as its `sysmon` source, so a tree that
starts, talks, acts and ends between two rounds is a tree of that round
(`brief`). Every round here is a text fixture: the samples are
tests/fixtures/host/quiet and tests/fixtures/discover/benign/windows-desktop,
the channel is Sysmon XML written by channel_xml() below (SYNTHETIC: host
`host`, user `user`, RFC 5737 addresses). No live host, no Windows, no wait on
a time in any fake."""
import io
import itertools
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from raqib import discover, host, notify  # noqa: E402
from raqib.hooks import os_sysmon  # noqa: E402
from raqib.rules import engine  # noqa: E402
from hostthreads import raqib_threads_end  # noqa: E402,F401  (every HostWatch ended, no thread leaked)

FIX = ROOT / "tests" / "fixtures"
HOSTFIX = FIX / "host"
CATALOG = discover.load_catalog(discover.CATALOG)
RULES = engine.load_catalog(ROOT / "raqib" / "rules" / "catalog")
NS = "http://schemas.microsoft.com/win/2004/08/events/event"
WALL0 = 1794296700.0          # 2026-11-10T07:45:00Z: the fixture watch's start, before the shell's (07:50)


def guid_of(n):
    """A ProcessGuid of the fixtures (SYNTHETIC), one per number."""
    return "{4f1a2b3c-0000-6730-%04x-%012x}" % (n & 0xFFFF, n)


G_SHELL = guid_of(5888)
G_KIMI = guid_of(9176)
G_KIMI2 = guid_of(19176)
G_AGENTX = guid_of(9216)


def event(eid, rec, utc, pid, image, guid, **data):
    fields = dict(UtcTime=utc, ProcessGuid=guid, ProcessId=str(pid), Image=image, **data)
    body = "".join("<Data Name='%s'>%s</Data>" % (k, v) for k, v in fields.items())
    return ("<Event xmlns='%s'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>%d</EventID>"
            "<TimeCreated SystemTime='%sZ'/><EventRecordID>%d</EventRecordID>"
            "<Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>host</Computer></System>"
            "<EventData>%s</EventData></Event>\n" % (NS, eid, utc.replace(" ", "T"), rec, body))


def created(rec, utc, pid, image, guid, ppid, pimage, pguid, cmd):
    return event(1, rec, utc, pid, image, guid, CommandLine=cmd, CurrentDirectory="C:\\Users\\user\\",
                 ParentProcessGuid=pguid, ParentProcessId=str(ppid), ParentImage=pimage, ParentCommandLine="-")


def talked(rec, utc, pid, image, guid, port=50200, dest="203.0.113.40"):
    return event(3, rec, utc, pid, image, guid, Protocol="tcp", Initiated="true", SourceIp="192.0.2.10",
                 SourcePort=str(port), DestinationIp=dest, DestinationHostname="-", DestinationPort="443")


PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
KIMI = "C:\\Users\\user\\AppData\\Local\\Programs\\kimi\\kimi.exe"
AGENTX = "C:\\Users\\user\\AppData\\Local\\agentx\\agentx.exe"
EXPLORER = "C:\\Windows\\explorer.exe"


def shell_events(rec=500, start="2026-11-10 07:50:00.412", create=True, child=True, guid=G_SHELL, pid=5888,
                 at="2026-11-10 07:50:05"):
    """The field run's shell (pid 5888) as the channel logs it: its creation (event 1, 412 ms after the sample's
    CreationDate), its talk (event 3) and a child (event 1)."""
    out = []
    if create:
        out.append(created(rec, start, pid, PS, guid, 5100, EXPLORER, guid_of(5100),
                           "powershell.exe"))
    out.append(talked(rec + 1, at + ".000", pid, PS, guid))
    if child:
        out.append(created(rec + 2, at + ".500", pid + 2, "C:\\Windows\\System32\\whoami.exe",
                           guid_of(rec + 2 + 100000), pid, PS, guid, "whoami"))
    return "".join(out)


def kimi_events(rec=600, pid=9176, guid=G_KIMI, at="2026-11-10 07:51:"):
    """A brief named tree: kimi starts, talks, runs curl and ends between two rounds."""
    return "".join([
        created(rec, at + "00.000", pid, KIMI, guid, 3000, EXPLORER, guid_of(3000), "kimi"),
        talked(rec + 1, at + "01.000", pid, KIMI, guid, port=50300, dest="203.0.113.50"),
        created(rec + 2, at + "02.000", pid + 124, "C:\\Windows\\System32\\curl.exe",
                guid_of(rec + 2 + 100000), pid, KIMI, guid, "curl -s https://198.51.100.20/x"),
        event(11, rec + 3, at + "03.000", pid, KIMI, guid,   # a write into its own AppData: config space, no act
              TargetFilename="C:\\Users\\user\\AppData\\Local\\Programs\\kimi\\state.json"),
    ])


def agentx_events(rec=700):
    """A brief unknown tree: a program under the user's AppData talks to an unknown host and starts cmd."""
    return "".join([
        created(rec, "2026-11-10 07:52:00.000", 9216, AGENTX, G_AGENTX, 3000, EXPLORER,
                guid_of(3000), "agentx"),
        talked(rec + 1, "2026-11-10 07:52:01.000", 9216, AGENTX, G_AGENTX, port=50400, dest="203.0.113.70"),
        created(rec + 2, "2026-11-10 07:52:02.000", 9330, "C:\\Windows\\System32\\cmd.exe",
                guid_of(9330), 9216, AGENTX, G_AGENTX, "cmd /c dir"),
    ])


def channel_xml(*parts):
    return "<!-- SYNTHETIC Sysmon channel read (tests/test_round_channel.py): host `host`, user `user` -->\n" + \
        "".join(parts)


class FakeChannelReader:
    """The channel's wevtutil, faked: answers the start's probes (held: the event ids the channel holds) and gives
    each round's read the next text of `rounds` (None: the read did not return). It records every argv."""

    def __init__(self, rounds, held=(1, 3, 22)):
        self.rounds = list(rounds)
        self.held = held
        self.args = []

    def __call__(self, args, timeout):
        self.args.append(tuple(args))
        if "/rd:true" in args:   # a probe
            eid = int(args[2].split("EventID=")[1].split(")")[0])
            return (channel_xml(event(eid, 1, "2026-11-10 07:00:00.000", 4, "System", "{0-0-0-0-0}"))
                    if eid in self.held else "", None)
        text = self.rounds.pop(0) if self.rounds else ""
        if text is None:
            return None, "wevtutil did not return in %g s (fake): the Sysmon channel was not read" % timeout
        return text, None


class SampleSeq:
    """discover.collect_live, faked: each call is the next sample directory (its texts and run.json)."""

    def __init__(self, names):
        self.names = list(names)

    def __call__(self, catalog, window=0.0, homes=None, platform=None, win_samples=1, win_every=0.0, run_info=None,
                 **kw):
        d = HOSTFIX / self.names.pop(0) if not str(self.names[0]).startswith("/") else Path(self.names.pop(0))
        texts, holes = discover.read_dir(str(d))
        texts = {k: v for k, v in texts.items() if not k.startswith("sysmon")}
        if run_info is not None:
            run_info.update(discover.run_record(str(d)) or {})
        return texts, holes, 1


def channel_follow(text_of):
    """The real os_sysmon.follow over the channel as it stands (text_of()), never a live wevtutil: its Stop is
    the only thing it waits on (source_every is an hour)."""
    def follow(root, log, stop, **kw):
        return os_sysmon.follow(root, log, stop, live=lambda: (text_of(), None), nt=True, **kw)
    return follow


def channel_watch(tmp_path, monkeypatch, samples, rounds, held=(1, 3, 22), cap=os_sysmon.ROUND_CAP, sysmon=True,
                  platform="win32", follow=None):
    seen = []
    reader = FakeChannelReader(rounds, held)
    chan = os_sysmon.Channel(since=None, cap=cap, reader=reader)
    monkeypatch.setattr(discover, "collect_live", SampleSeq(samples))
    clock = host.FixtureClock()
    notifier = notify.Notifier(host.HOST, enabled=False, reason="fixture", host=True)
    whole = "".join(t for t in reader.rounds if t)
    w = host.HostWatch(host.live_reader(CATALOG, platform=platform, channel=chan), CATALOG, RULES, notifier, every=10,
                       out=None, err=io.StringIO(), clock=clock, wall=lambda: WALL0 + clock.t, home=str(tmp_path),
                       platform=platform, run="fixture-run", source_every=3600,
                       sysmon=(lambda: (True, "fixture: Sysmon")) if sysmon else (lambda: (False, "fixture: no Sysmon")),
                       os_follow=follow or channel_follow(lambda: channel_xml(whole)), channel=chan)
    for _ in samples:
        w.tick(wait=30)
        for src in list(w.sources.values()):
            if src.thread is not None:
                src.first_pass.wait(5)
        w.tick()
        seen.append(w.round_lines[-1])
        clock.t += 10
    w.finish()
    return w, reader, seen


def new_findings(w, rule_id=None):
    return [f for f in w.findings if f["rule_id"] in host.NEW_RULES and (rule_id is None or f["rule_id"] == rule_id)]


# --- E1: one bounded read per round, by Raqib's own wevtutil -------------------------------------------------

def test_e1_the_query_is_bounded_and_made_of_raqibs_own_values():
    import datetime
    since = datetime.datetime(2026, 11, 10, 11, 45, 0, 250000, tzinfo=datetime.timezone(datetime.timedelta(hours=4)))
    first = os_sysmon.round_query(None, since)
    assert first == ("*[System[(EventID=1 or EventID=3 or EventID=11 or EventID=22) and"
                     " TimeCreated[@SystemTime>='2026-11-10T07:45:00.250Z']]]")
    assert os_sysmon.round_query(123456, since) == (
        "*[System[(EventID=1 or EventID=3 or EventID=11 or EventID=22) and EventRecordID>123456]]")
    assert os_sysmon.round_args(first, 50) == ("qe", os_sysmon.CHANNEL, "/q:" + first, "/c:50", "/f:xml")
    with pytest.raises(ValueError):
        os_sysmon.round_query(None, None)        # never the whole channel
    with pytest.raises(ValueError):
        os_sysmon.round_query("1]] or *[System[EventID=1", since)   # only an int goes in
    assert os_sysmon.ROUND_IDS == discover.SYSMON_READ


def test_e1_each_round_reads_on_from_the_last_record_and_round_1_reads_nothing_older_than_the_start(
        tmp_path, monkeypatch):
    w, reader, rounds = channel_watch(tmp_path, monkeypatch, ["quiet/quiet"] * 4,
                                      ["", shell_events(rec=500), None, kimi_events(rec=600)])
    reads = [a for a in reader.args if "/rd:true" not in a]
    assert len(reads) == 4                                        # one read per round
    assert all(a[0] == "qe" and a[1] == os_sysmon.CHANNEL and a[-1] == "/f:xml" and a[3] == "/c:%d" %
               os_sysmon.ROUND_CAP for a in reads)
    assert "TimeCreated[@SystemTime>='2026-11-10T07:45:00.000Z']" in reads[0][2]   # the watch's start
    assert "TimeCreated[@SystemTime>='2026-11-10T07:45:00.000Z']" in reads[1][2]   # round 1 read no record
    assert reads[2][2].endswith("EventRecordID>502]]") and reads[3][2].endswith("EventRecordID>502]]")   # a failed read
    assert w.channel.after == 603
    assert [r["channel"]["query"] for r in rounds] == [a[2][3:] for a in reads]


def test_e1_the_real_wevtutil_path_a_timeout_ends_the_helper_and_records_it(tmp_path, monkeypatch):
    calls = []

    class Stuck:
        pid = 4242
        returncode = None

        def __init__(self, argv, **kw):
            calls.append((argv, kw))

        def communicate(self, timeout=None):
            raise subprocess.TimeoutExpired("wevtutil", timeout)

        def terminate(self):
            calls.append("terminate")

        def wait(self, timeout=None):
            return 0

    chan = os_sysmon.Channel(since=None)
    chan.reader = lambda args, timeout: os_sysmon.read_live_bounded(timeout, chan.helpers, popen=Stuck,
                                                                    environ={"SystemRoot": "C:\\Windows"}, args=args)
    import datetime
    chan.since = datetime.datetime(2026, 11, 10, 7, 45, tzinfo=datetime.timezone.utc)
    text, holes, record = chan.read()
    assert text is None and record["error"] and "did not return in 10 s" in holes[0]
    argv, kw = calls[0]
    assert argv[0] == os_sysmon.WEVTUTIL == "C:\\Windows\\System32\\wevtutil.exe" and kw["env"] == {
        "SystemRoot": "C:\\Windows"}
    assert argv[1:] == list(os_sysmon.round_args(record["query"]))
    assert "terminate" in calls and chan.helpers.record and chan.helpers.running == {}
    assert "(Raqib's own helper) terminated: did not return in 10 s" in chan.helpers.record[0]


def test_e1_a_read_that_times_out_is_a_hole_of_its_round_and_the_round_keeps_its_sample(tmp_path, monkeypatch):
    w, _, rounds = channel_watch(tmp_path, monkeypatch, ["quiet/quiet", "quiet/talking"], ["", None])
    assert rounds[1]["trees"] == ["5888:powershell:2026-11-10T07:50:00.000Z"]   # the sample is kept
    (hole,) = [h for h in w.holes if h["kind"] == "channel-unread"]
    assert hole["round"] == 2 and "did not return" in hole["detail"] and "keeps its sample" in hole["detail"]
    assert w.result()[0] == "alarm" and any("hole(s) of the watch" in x for x in w.result()[1])


def test_e1_the_cap_is_a_hole_and_the_next_round_reads_on(tmp_path, monkeypatch):
    w, reader, rounds = channel_watch(tmp_path, monkeypatch, ["quiet/quiet"] * 3,
                                      ["", shell_events(rec=500), ""], cap=3)
    (hole,) = [h for h in w.holes if h["kind"] == "channel-cut"]
    assert hole["round"] == 2 and "the cap" in hole["detail"] and rounds[1]["channel"]["cut"] is True
    reads = [a for a in reader.args if "/rd:true" not in a]
    assert reads[2][2].endswith("EventRecordID>502]]") and reads[0][3] == "/c:3"


# --- E2 / E3: a brief tree is a tree of its round --------------------------------------------------------------

KIMI_WORD = "9176:kimi:2026-11-10T07:51:00.000Z"


def test_e2_e3_a_brief_named_tree_gives_new_agent_in_its_round_and_its_source_lines_are_judged(
        tmp_path, monkeypatch):
    w, _, rounds = channel_watch(tmp_path, monkeypatch, ["quiet/quiet"] * 3, ["", kimi_events(), ""])
    assert rounds[1][host.BRIEF] == [KIMI_WORD] and rounds[1]["new"] == [KIMI_WORD]
    (f,) = new_findings(w)
    assert f["rule_id"] == host.NEW_AGENT and f["round"] == 2 and f["tree"] == KIMI_WORD
    assert all(c["src"] == "sysmon" for c in f["cites"]) and f["cites"]           # A5: the channel's lines
    (line,) = [x for x in rounds[1]["lines"] if x["tool"] == host.TREE_TOOL]
    assert line["input_meta"]["brief"] is True and line["input_meta"]["seen"] == host.BRIEF_TEXT
    key = tuple(f["tree_key"])
    src = w.sources[key]
    assert src.kind == "os" and G_KIMI in src.text and "rooted at pid 9176 and ProcessGuid" in src.text
    assert src.error is None and src.ended and "gone" in src.ended               # ended, without a hole
    assert not [h for h in w.holes if h["kind"].startswith("source")]
    acts = [s for s in w.source_findings if tuple(s.get("tree_key") or ()) == key or s.get("tree") == KIMI_WORD]
    assert any(s["rule_id"] == "NET-TOOL" for s in acts), w.source_findings       # curl under kimi, judged
    assert rounds[2]["gone"] == [KIMI_WORD]
    report = w.summary()[0]
    assert "[candidate] [brief] pid 9176 kimi" in report and "CHANNEL (the rounds read" in report


def test_e2_a_brief_unknown_tree_gives_new_agent_unknown(tmp_path, monkeypatch):
    w, _, rounds = channel_watch(tmp_path, monkeypatch, ["quiet/quiet"] * 2, ["", agentx_events()])
    (f,) = new_findings(w)
    assert f["rule_id"] == host.NEW_UNKNOWN and f["round"] == 2 and rounds[1][host.BRIEF] == [f["tree"]]


FORMS = {   # one round's view of the shell: (sample directory, channel text)
    "sampled": ("quiet/talking", ""),
    "sampled+channel": ("quiet/talking", shell_events(rec=500)),
    "alive+channel": ("quiet/quiet", shell_events(rec=500)),
    "brief": ("quiet/ended", shell_events(rec=500)),
    "brief-no-create": ("quiet/ended", shell_events(rec=500, create=False)),
}


@pytest.mark.parametrize("first, second", list(itertools.product(sorted(FORMS), repeat=2)))
def test_e2_a_tree_seen_both_ways_is_one_tree_in_every_order(tmp_path, monkeypatch, first, second):
    samples = ["quiet/quiet", FORMS[first][0], FORMS[second][0]]
    w, _, rounds = channel_watch(tmp_path, monkeypatch, samples, ["", FORMS[first][1], FORMS[second][1]])
    keys = {k for k in w.trees if k[0] == 5888}
    assert len(keys) == 1, (first, second, keys)
    assert len(new_findings(w)) == 1 and new_findings(w)[0]["round"] in (2, 3)
    assert len([k for k in w.sources if k[0] == 5888]) == 1


@pytest.mark.parametrize("together", [False, True])
def test_e2_a_reused_pid_is_another_tree(tmp_path, monkeypatch, together):
    again = kimi_events(rec=700, guid=G_KIMI2, at="2026-11-10 07:53:")
    rounds = ["", kimi_events() + again, ""] if together else ["", kimi_events(), "", again]
    w, _, seen = channel_watch(tmp_path, monkeypatch, ["quiet/quiet"] * len(rounds), rounds)
    keys = sorted(k for k in w.trees if k[0] == 9176)
    assert len(keys) == 2 and len(new_findings(w, host.NEW_AGENT)) == 2, keys
    assert {w.trees[k]["guid"] for k in keys} == {G_KIMI, G_KIMI2}


def test_e2_round_1_a_tree_created_after_the_start_is_not_history_one_there_before_is(tmp_path, monkeypatch):
    w, _, rounds = channel_watch(tmp_path, monkeypatch, ["quiet/ended", "quiet/ended"], [kimi_events(), ""])
    assert rounds[0]["new"] == [KIMI_WORD] and len(new_findings(w)) == 1
    w2, _, rounds2 = channel_watch(tmp_path / "b", monkeypatch, ["quiet/talking"], [""])
    assert rounds2[0]["history"] and new_findings(w2) == []


# --- E4: what the channel does not hold, and the hole where there is none ---------------------------------------

def test_e4_what_the_channel_does_not_hold_is_said_once(tmp_path, monkeypatch):
    w, reader, _ = channel_watch(tmp_path, monkeypatch, ["quiet/quiet"] * 3, ["", "", ""], held=(1,))
    probes = [a for a in reader.args if "/rd:true" in a]
    assert [a[2] for a in probes] == ["/q:*[System[(EventID=%d)]]" % i for i in (1, 3, 22)]
    said = [n for n in w.notes if n.startswith("the Sysmon channel holds no event")]
    assert len(said) == 2 and "no event 3" in said[0] and "talk between two rounds is not seen" in said[0]
    assert "no event 22" in said[1]
    report = w.summary()[0]
    assert report.count("holds no event 3") == 2   # NOTES and the CHANNEL line, once each
    assert not any("source sysmon holds no event" in h for h in w.last_inventory["holes"])   # never per round


@pytest.mark.parametrize("platform, sysmon", [("linux", False), ("win32", False)])
def test_e4_without_the_channel_the_between_rounds_hole_stays(tmp_path, monkeypatch, platform, sysmon):
    clock = host.FixtureClock()
    notifier = notify.Notifier(host.HOST, enabled=False, reason="fixture", host=True)
    chan = os_sysmon.Channel(since=None, reader=FakeChannelReader([])) if platform == "win32" else None
    w = host.HostWatch(lambda: None, CATALOG, RULES, notifier, out=None, err=io.StringIO(), clock=clock,
                       wall=lambda: WALL0, home=str(tmp_path), platform=platform, run="fixture-run",
                       sysmon=lambda: (sysmon, "no Sysmon here"), channel=chan)
    (note,) = [n for n in w.notes if n.startswith("a tree that lives between two rounds is not seen")]
    assert ("Linux" in note) == (platform == "linux") and ("no Sysmon channel is read" in note) == (platform == "win32")
    assert chan is None or (chan.on is False and chan.reader.args == [])   # no probe, no read
    w.finish()
    threat = (ROOT / "docs" / "THREAT_MODEL.md").read_text(encoding="utf-8")
    threat = " ".join(threat.split())
    assert "closed where Sysmon is (ADR-0007 P-4)" in threat and "`brief`" in threat and "between two rounds" in threat
    assert "does not close" in threat and "keep the whole hole" in threat


def test_e6_linux_is_unchanged_no_channel_no_sysmon_source(tmp_path, monkeypatch):
    monkeypatch.setattr(discover, "collect_live", SampleSeq(["quiet/talking"]))
    # the Linux reader's two other reads, faked: this test runs on the windows jobs too (no /proc, no sysconf)
    monkeypatch.setattr(discover, "read_conn_bytes", lambda paths: ({}, "fake ss", "no ss here (fake)"))
    monkeypatch.setattr(discover, "proc_start_times", lambda pids: ({}, "no /proc here (fake)"))
    inv = host.live_reader(CATALOG, platform="linux", ss_paths=("/nonexistent/ss",))()
    assert "channel" not in inv and not any(s["name"].startswith("sysmon") for s in inv["sources"])
    texts, holes = discover.read_dir(str(HOSTFIX / "quiet" / "talking"))
    plain = discover.run(texts, CATALOG, holes=holes, processes=True)
    assert plain["candidates"] and "guid" not in plain["candidates"][0] and "brief" not in plain["candidates"][0]


# --- E5: budgets: the benign Windows desktop with its channel -----------------------------------------------------

def desktop_counts(channel):
    d = FIX / "discover" / "benign" / "windows-desktop"
    texts, holes = discover.read_dir(str(d))
    out = {"trees": 0, "act_roots": 0, "unknown_new": 0}
    xml = (FIX / "os" / "benign-windows-desktop.sysmon.xml").read_text(encoding="ascii")
    for k in (1, 2):
        one = {n: v for n, v in texts.items() if n.endswith("-%d" % k) or n == "footprints"}
        if channel:
            one["sysmon"] = ("fixture channel", xml if k == 1 else "", None)
        inv = discover.run(one, CATALOG, holes=holes, run=discover.run_record(str(d)), processes=True,
                           channel=channel)
        trees = host.trees_of(inv, CATALOG)
        out["trees"] += len(trees)
        out["act_roots"] += len(inv["act_roots"])
        out["unknown_new"] += sum(1 for t in trees.values() if t["class"] == "candidate" and not t["named"]
                                  and not t["benign"])
    return out


def test_e5_the_benign_desktop_with_its_channel_fires_nothing_new_and_the_budgets_are_said():
    without, with_channel = desktop_counts(False), desktop_counts(True)
    # measured (A6): over its two samples the desktop lists 4 unknown candidate trees (history in a watch's round 1)
    # and no act-root, with the channel and without it: the channel adds no tree, no act-root, no unknown
    assert with_channel == without == {"trees": 4, "act_roots": 0, "unknown_new": 4}, (without, with_channel)


def test_e5_the_budgets_with_the_channel_in_as_the_watch_reads_them(tmp_path, monkeypatch):
    d = str(FIX / "discover" / "benign" / "windows-desktop")
    xml = (FIX / "os" / "benign-windows-desktop.sysmon.xml").read_text(encoding="ascii")

    class Desktop(SampleSeq):
        def __call__(self, catalog, run_info=None, **kw):
            k = self.names.pop(0)
            texts, holes = discover.read_dir(d)
            if run_info is not None:
                run_info.update(discover.run_record(d) or {})
            return {n: v for n, v in texts.items() if n.endswith("-%d" % k) or n == "footprints"}, holes, 1

    reader = FakeChannelReader([xml, ""])
    chan = os_sysmon.Channel(since=None, reader=reader)
    monkeypatch.setattr(discover, "collect_live", Desktop([1, 2]))
    clock = host.FixtureClock()
    w = host.HostWatch(host.live_reader(CATALOG, platform="win32", channel=chan), CATALOG, RULES,
                       notify.Notifier(host.HOST, enabled=False, reason="fixture", host=True), every=10, out=None,
                       err=io.StringIO(), clock=clock, wall=lambda: WALL0 + clock.t, home=str(tmp_path),
                       platform="win32", run="fixture-run", sysmon=lambda: (True, "fixture"), channel=chan,
                       os_follow=channel_follow(lambda: xml), source_every=3600)
    for _ in range(2):
        w.tick(wait=30)
        w.tick()
        clock.t += 10
    w.finish()
    # the export's events are dated before the watch's start: what they make is history, never a new tree (E5)
    assert new_findings(w) == [] and w.trees and all(t["history"] for t in w.trees.values())
    assert w.channel.events == xml.count("<Event ")


# --- the help text and the README say it ----------------------------------------------------------------------------

def test_e6_the_readme_and_the_help_say_it():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "M7.9" in readme and "`brief`" in readme and "between two rounds is not seen" in readme
    cli_text = (ROOT / "raqib" / "cli.py").read_text(encoding="ascii")
    assert "listed as brief" in cli_text and cli_text.count("M7.9") >= 2
