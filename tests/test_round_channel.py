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
import re
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
WALL0 = 1794296970.0          # 2026-11-10T07:49:30Z: the fixture watch's start, before the shell's (07:50)
EVERY = 120   # Z-2: the rounds read at 07:49:30, 07:51:30, ...: every event is dated before the read that returns it


def at_text(seconds):
    """A Sysmon UtcTime `seconds` after the fixture watch's start."""
    import datetime
    t = datetime.datetime.fromtimestamp(WALL0 + seconds, datetime.timezone.utc)
    return t.strftime("%Y-%m-%d %H:%M:%S.") + "%03d" % (t.microsecond // 1000)


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


def agentx_events(rec=700, image=None, pid=9216):
    """A brief unknown tree: a program under the user's AppData talks to an unknown host and starts cmd."""
    image = image or AGENTX
    g = G_AGENTX if pid == 9216 else guid_of(pid)
    return "".join([
        created(rec, "2026-11-10 07:51:00.000", pid, image, g, 3000, EXPLORER,
                guid_of(3000), "agentx"),
        talked(rec + 1, "2026-11-10 07:51:01.000", pid, image, g, port=50400, dest="203.0.113.70"),
        created(rec + 2, "2026-11-10 07:51:02.000", pid + 114, "C:\\Windows\\System32\\cmd.exe",
                guid_of(pid + 114), pid, image, g, "cmd /c dir"),   # AB-10: each run's child its own guid
    ])


def channel_xml(*parts):
    return "<!-- SYNTHETIC Sysmon channel read (tests/test_round_channel.py): host `host`, user `user` -->\n" + \
        "".join(parts)


class FakeWevtutil:
    """os_sysmon.read_live_bounded, faked: a channel that HONOURS the query (EventRecordID>N, or TimeCreated at or
    after the start; oldest first; /c:cap), whose records are appended round by round. None in `fail` rounds: the
    read did not return. Every argv is recorded."""

    def __init__(self, rounds, fail=(), now=None):
        self.rounds = list(rounds)
        self.fail = set(fail)
        self.log = []
        self.args = []
        self.now = now   # Z-2: the read's time: an event dated after it is not returned yet

    def __call__(self, timeout, helpers=None, popen=None, environ=None, args=()):
        self.args.append(tuple(args))
        n = len(self.args)
        if n <= len(self.rounds) and self.rounds[n - 1]:
            self.log += os_sysmon._chunks(self.rounds[n - 1])[1]
        if n in self.fail:
            return None, "wevtutil did not return in %g s (fake): the Sysmon channel was not read" % timeout
        query, cap = args[2][3:], int(args[3][3:])
        rid = re.search(r"EventRecordID>([0-9]+)", query)
        since = re.search(r"SystemTime>='([^']+)'", query)
        now = self.now() if self.now else None
        keep = [c for c, r, t in self.log if ((rid and r > int(rid.group(1))) or
                (since and t >= discover._ts(since.group(1)))) and (now is None or t <= now)]
        return channel_xml(*keep[:cap]), None


class SampleSeq:
    """discover.collect_live, faked: each call is the next sample directory (its texts and run.json)."""

    def __init__(self, names):
        self.names = list(names)

    def __call__(self, catalog, window=0.0, homes=None, platform=None, win_samples=1, win_every=0.0, run_info=None,
                 **kw):
        d = HOSTFIX / self.names.pop(0)   # a name, or a directory a test wrote (an absolute path)
        texts, holes = discover.read_dir(str(d))
        if run_info is not None:
            run_info.update(discover.run_record(str(d)) or {})
        return {k: v for k, v in texts.items() if not k.startswith("sysmon")}, holes, 1


def channel_follow(fake):
    """The real os_sysmon.follow over the fake channel's records as they stand, never a live wevtutil: its Stop is
    the only thing it waits on (source_every is an hour)."""
    def follow(root, log, stop, **kw):
        return os_sysmon.follow(root, log, stop, live=lambda: (channel_xml(*[c for c, _, _ in fake.log]), None),
                                nt=True, **kw)
    return follow


def window_reader(catalog):
    """The reader as raqib-app's window builds it (app.py: Options.reader is host.live_reader(catalog, 0.0), wrapped
    by HostSession.reader in a plain function that takes no argument)."""
    real = host.live_reader(catalog, 0.0)

    def read():
        return real()
    return read


PROPERTY = []   # AB-6: every channel round of this file, checked (sample-labelled trees == the round without it)


def candidates_by_sample(texts, inv, catalog, kw):
    """AB-6: the trees labelled "sample" in a channel round are exactly the candidates of the same round built
    without the channel's records, no more and no fewer."""
    bare = REAL_RUN({k: v for k, v in texts.items() if not k.startswith("sysmon")}, catalog,
                    **dict(kw, channel=False))
    labelled = {(c["pid"], c["image"]) for c in inv["candidates"] if c.get("candidate_by") == "sample"}
    assert labelled == {(c["pid"], c["image"]) for c in bare["candidates"]}, (labelled, bare["candidates"])
    assert all(c.get("candidate_by") in ("sample", "channel") for c in inv["candidates"])
    PROPERTY.append(len(inv["candidates"]))


REAL_RUN = discover.run


def checked_run(texts, catalog, **kw):
    inv = REAL_RUN(texts, catalog, **kw)
    if kw.get("channel"):
        candidates_by_sample(texts, inv, catalog, kw)
    return inv


def channel_watch(tmp_path, monkeypatch, samples, rounds, fail=(), sysmon=True, wall0=WALL0, follow=None,
                  reader=None, wevtutil=None, own=None, out=None):
    seen = []
    monkeypatch.setattr(discover, "run", checked_run)   # AB-6: the property, over every channel round
    clock = host.FixtureClock()
    import datetime
    fake = wevtutil or FakeWevtutil(rounds, fail, now=lambda: datetime.datetime.fromtimestamp(
        wall0 + clock.t, datetime.timezone.utc))
    monkeypatch.setattr(os_sysmon, "read_live_bounded", fake)
    monkeypatch.setattr(os_sysmon, "OPEN_CHANNELS", [])
    monkeypatch.setattr(host, "sysmon_present", lambda platform=None, registry=None: (sysmon, "fixture: Sysmon"))
    monkeypatch.setattr(host, "reader_wall", lambda: wall0 + clock.t)
    monkeypatch.setattr(discover, "collect_live", SampleSeq(samples))
    monkeypatch.setattr(sys, "platform", "win32")   # the window's reader takes the platform from sys (faked here)
    notifier = notify.Notifier(host.HOST, enabled=False, reason="fixture", host=True)
    own = sysmon if own is None else own   # the watch's own check (AB-3); `sysmon` is the live reader's
    w = host.HostWatch((reader or window_reader)(CATALOG), CATALOG, RULES, notifier, every=EVERY, out=out,
                       err=io.StringIO(), clock=clock, wall=lambda: wall0 + clock.t, home=str(tmp_path),
                       platform="win32", run="fixture-run", source_every=3600,
                       sysmon=lambda: (own, "fixture: the watch's own check"), os_follow=follow or channel_follow(fake))
    for _ in samples:
        w.tick(wait=30)
        for src in list(w.sources.values()):
            if src.thread is not None:
                src.first_pass.wait(5)
        w.tick()
        seen.append(w.round_lines[-1])
        clock.t += EVERY
    w.finish()
    return w, fake, seen


def new_findings(w, rule_id=None):
    return [f for f in w.findings if f["rule_id"] in host.NEW_RULES and (rule_id is None or f["rule_id"] == rule_id)]


def new_knocks(w):
    return [k for k in w.knocks if str(k.get("event") or k.get("rule_id") or k.get("title") or "").startswith("NEW-")
            or "NEW-AGENT" in json.dumps(k)]


# --- E1 / X-1: one bounded read per round, by the live reader's own channel ---------------------------------

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


def test_x1_the_windows_round_reads_the_channel_and_no_caller_passes_one(tmp_path, monkeypatch):
    import inspect
    w, fake, rounds = channel_watch(tmp_path, monkeypatch, ["quiet/quiet"] * 2, ["", kimi_events()])
    assert len(fake.args) == 2 and rounds[1][host.BRIEF] == [KIMI_WORD]   # the window's wrapped reader read it
    for fn in (host.live_reader, host.HostWatch.__init__, host.start, host.command):
        assert "channel" not in inspect.signature(fn).parameters, fn
    assert "channel" not in (ROOT / "raqib" / "app.py").read_text(encoding="utf-8").lower().replace(
        "sysmon channel", "")   # the window is unchanged and passes nothing


def test_e1_each_round_reads_on_from_the_last_record_and_round_1_reads_nothing_older_than_the_start(
        tmp_path, monkeypatch):
    w, fake, rounds = channel_watch(tmp_path, monkeypatch, ["quiet/quiet"] * 4,
                                    ["", shell_events(rec=500), "", kimi_events(rec=600)], fail={3})
    assert len(fake.args) == 4 and all(a[0] == "qe" and a[1] == os_sysmon.CHANNEL and a[-1] == "/f:xml"
                                       and a[3] == "/c:%d" % os_sysmon.ROUND_CAP for a in fake.args)
    starts = [re.search(r"SystemTime>='([^']+)'", a[2]).group(1) for a in fake.args[:2]]
    assert all("2026-11-10T07:49:29.9" <= x <= "2026-11-10T07:49:30.000Z" for x in starts), starts   # T-3
    assert fake.args[2][2].endswith("EventRecordID>502]]") and fake.args[3][2].endswith("EventRecordID>502]]")
    assert rounds[3]["channel"]["top"] == 603 and rounds[3]["channel"]["events"] == 4   # nothing lost by round 3
    assert [r["channel"]["query"] for r in rounds] == [a[2][3:] for a in fake.args]


def test_e1_the_real_wevtutil_path_a_timeout_ends_the_helper_and_records_it():
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

    import datetime
    chan = os_sysmon.Channel(since=datetime.datetime(2026, 11, 10, 7, 45, tzinfo=datetime.timezone.utc))
    chan.reader = lambda args, timeout: os_sysmon.read_live_bounded(timeout, chan.helpers, popen=Stuck,
                                                                    environ={"SystemRoot": "C:\\Windows"}, args=args)
    text, record = chan.read(chan.since)
    assert text is None and record["error"] and "did not return in 10 s" in record["holes"][0]
    argv, kw = calls[0]
    assert argv[0] == os_sysmon.WEVTUTIL == "C:\\Windows\\System32\\wevtutil.exe" and kw["env"] == {
        "SystemRoot": "C:\\Windows"}
    assert argv[1:] == list(os_sysmon.round_args(record["query"]))
    assert "terminate" in calls and chan.helpers.record and chan.helpers.running == {}
    assert "(Raqib's own helper) terminated: did not return in 10 s" in chan.helpers.record[0]


def test_e1_a_read_that_times_out_is_a_hole_of_its_round_and_the_round_keeps_its_sample(tmp_path, monkeypatch):
    w, _, rounds = channel_watch(tmp_path, monkeypatch, ["quiet/quiet", "quiet/talking"], ["", ""], fail={2})
    assert rounds[1]["trees"] == ["5888:powershell:2026-11-10T07:50:00.000Z"]   # the sample is kept
    (hole,) = [h for h in w.holes if h["kind"] == "channel-unread"]
    assert hole["round"] == 2 and "did not return" in hole["detail"] and "keeps its sample" in hole["detail"]


def test_e1_x4_the_cap_is_a_hole_with_its_size_and_the_backlog_is_said_at_stop(tmp_path, monkeypatch):
    monkeypatch.setattr(os_sysmon, "ROUND_CAP", 3)
    w, fake, rounds = channel_watch(tmp_path, monkeypatch, ["quiet/quiet"] * 3,
                                    ["", shell_events(rec=500) + kimi_events(rec=600), ""])
    cuts = [h for h in w.holes if h["kind"] == "channel-cut"]
    assert [h["round"] for h in cuts] == [2, 3] and "s behind the round" in cuts[0]["detail"]
    assert fake.args[2][2].endswith("EventRecordID>502]]") and fake.args[0][3] == "/c:3"
    assert "BACKLOG at Stop" in w.summary()[0]


def test_x3_a_cleared_channel_is_said_and_the_read_starts_again(tmp_path, monkeypatch):
    cleared = created(5, "2026-11-10 07:52:00.000", 9500, "C:\\Windows\\System32\\cmd.exe", guid_of(9500), 3000,
                      EXPLORER, guid_of(3000), "cmd")   # record 5: the numbers restarted (wevtutil cl)

    def unbounded(timeout, helpers=None, popen=None, environ=None, args=()):   # a bound wevtutil did not apply
        unbounded.args.append(tuple(args))
        n = len(unbounded.args)
        return channel_xml(shell_events(rec=500) if n == 2 else cleared if n == 3 else ""), None
    unbounded.args = []
    w2, _, rounds2 = channel_watch(tmp_path, monkeypatch, ["quiet/quiet"] * 4, [], wevtutil=unbounded,
                                   follow=host.FixtureFollow())
    kinds = [h["kind"] for h in w2.holes]
    assert "channel-unbounded" in kinds and "channel-restart" in kinds, kinds
    assert "TimeCreated" in rounds2[3]["channel"]["query"]   # the read started again from the round's time


def sample_dir(tmp_path, name, rows):
    """quiet/quiet with these processes added (SYNTHETIC rows, ISO UTC CreationDate as the live reader writes it)."""
    import shutil
    d = tmp_path / name
    shutil.copytree(str(HOSTFIX / "quiet" / "quiet"), str(d))
    with open(d / "win-process-1.csv", "a", encoding="ascii", newline="\n") as f:
        for pid, exe, start in rows:
            f.write('"%d","3000","%s","%s","%s","%s"\n' % (pid, exe.rsplit("\\", 1)[1], exe, exe.rsplit("\\", 1)[1],
                                                         start.replace(" ", "T") + "Z"))
    return d


CONHOST = "C:\\Windows\\System32\\conhost.exe"
HEALTHY = channel_xml(created(500, "2026-11-10 07:50:00.412", 5888, PS, G_SHELL, 5100, EXPLORER, guid_of(5100), "ps"),
                      created(501, "2026-11-10 07:50:00.150", 5890, CONHOST, guid_of(5890), 5888, PS, G_SHELL, "c"))


def test_z2_a_healthy_channel_over_ten_rounds_says_nothing_and_ends_exit_0(tmp_path, monkeypatch):
    w, _, rounds = channel_watch(tmp_path, monkeypatch, ["quiet/quiet"] * 10, ["", HEALTHY] + [""] * 8)
    assert not [h for h in w.holes if h["kind"].startswith("channel")], w.holes
    assert not [n for n in w.notes if "no event 1 from the channel" in n]
    assert all(r["channel"]["behind_seconds"] is None or r["channel"]["behind_seconds"] >= 0 for r in rounds)
    assert w.result()[0] == "none-seen" and w.summary()[1] == 0


def test_z2_a_filtered_image_is_one_note_never_a_hole(tmp_path, monkeypatch):
    other = created(600, "2026-11-10 07:52:00.000", 9500, "C:\\Windows\\System32\\cmd.exe", guid_of(9500), 3000,
                    EXPLORER, guid_of(3000), "cmd")   # the channel gives other processes' event 1
    only_ps = channel_xml(created(500, "2026-11-10 07:50:00.412", 5888, PS, G_SHELL, 5100, EXPLORER, guid_of(5100),
                                  "ps"))
    w, _, _ = channel_watch(tmp_path, monkeypatch, ["quiet/quiet"] * 5, ["", only_ps, other, "", ""])
    notes = [n for n in w.notes if "no event 1 from the channel for conhost" in n]
    assert len(notes) == 1 and not [h for h in w.holes if h["kind"].startswith("channel")], w.holes
    assert "left out by its configuration, or late" in notes[0] and w.summary()[1] == 0
    # AA-5, the other side: its event 1 comes late: the note is withdrawn in the report
    came = channel_xml(created(610, "2026-11-10 07:56:00.000", 5990, CONHOST, guid_of(5990), 5888, PS, G_SHELL, "c"))
    w2, _, _ = channel_watch(tmp_path / "b", monkeypatch, ["quiet/quiet"] * 6, ["", only_ps, other, "", came, ""])
    assert any("is withdrawn: an event 1 of conhost came" in n for n in w2.notes), w2.notes   # AB-8


def test_z2_a_stopped_channel_is_the_hole_in_its_third_round(tmp_path, monkeypatch):
    samples = [sample_dir(tmp_path, "s%d" % k, [(7000 + j, "C:\\Windows\\System32\\cmd.exe", at_text(EVERY * j - 90))
                                                 for j in range(1, k)]) for k in range(1, 7)]
    w, _, rounds = channel_watch(tmp_path / "w", monkeypatch, samples, ["", HEALTHY] + [""] * 4)
    silent = [h for h in w.holes if "behind, stopped or cleared" in h["detail"]]
    assert [h["round"] for h in silent] == [5], [(h["round"], h["kind"]) for h in w.holes]   # rounds 3, 4, 5 gave none
    assert [h["kind"] for h in w.holes if h["kind"] == "channel-restart"] == ["channel-restart"]
    restart = next(h for h in w.holes if h["kind"] == "channel-restart")["detail"]
    assert "that no round returned is not read" in restart and "TimeCreated" in rounds[5]["channel"]["query"]
    assert w.summary()[1] == 3


def test_z1_a_shell_older_than_the_watch_that_becomes_a_tree_in_round_2_is_new(tmp_path, monkeypatch):
    w, _, rounds = channel_watch(tmp_path, monkeypatch, ["quiet/quiet", "quiet/talking"], ["", ""], wall0=WALL0 + 600)
    (f,) = new_findings(w)
    assert f["round"] == 2 and not rounds[1]["history"]   # C-4: a tree new in a later round knocks, whatever its start
    w2, _, rounds2 = channel_watch(tmp_path / "b", monkeypatch, ["quiet/talking"], [""], wall0=WALL0 + 600)
    assert rounds2[0]["history"] and new_findings(w2) == []   # must not touch: round 1, older than the watch


def test_x4_a_tree_read_late_says_by_how_much_and_the_lag_beyond_a_round_is_a_hole(tmp_path, monkeypatch):
    monkeypatch.setattr(os_sysmon, "ROUND_CAP", 3)
    w, _, rounds = channel_watch(tmp_path, monkeypatch, ["quiet/quiet"] * 5,
                                 ["", shell_events(rec=500) + kimi_events(rec=600) + agentx_events(rec=700), "", "", ""])
    late = [x for r in rounds for x in r["lines"] if x["input_meta"].get("read_late_seconds")]
    assert late and all(x["input_meta"]["read_late_seconds"] > EVERY for x in late)
    assert "channel-behind" in [h["kind"] for h in w.holes]


def test_x6_a_brief_childs_act_is_at_its_event_time():
    texts, holes = discover.read_dir(str(HOSTFIX / "quiet" / "quiet"))
    texts = {k: v for k, v in texts.items() if not k.startswith("sysmon")}
    texts["sysmon"] = ("fixture channel", channel_xml(kimi_events()), None)
    inv = discover.run(texts, CATALOG, holes=holes, processes=True, channel=True)
    (kimi,) = [c for c in inv["candidates"] if c["image"] == "kimi"]
    assert [a["started"] for a in kimi["acts"] if a["how"] == "process"] == ["2026-11-10T07:51:02.000Z"]


# --- E2 / E3 / X-2: a brief tree is a tree of its round ----------------------------------------------------------

KIMI_WORD = "9176:kimi:2026-11-10T07:51:00.000Z"


def test_e2_e3_a_brief_named_tree_gives_new_agent_in_its_round_and_its_source_lines_are_judged(
        tmp_path, monkeypatch):
    w, _, rounds = channel_watch(tmp_path, monkeypatch, ["quiet/quiet"] * 3, ["", kimi_events(), ""])
    assert rounds[1][host.BRIEF] == [KIMI_WORD] and rounds[1]["new"] == [KIMI_WORD]
    (f,) = new_findings(w)
    assert f["rule_id"] == host.NEW_AGENT and f["round"] == 2 and f["tree"] == KIMI_WORD
    assert all(c["src"] == "sysmon" for c in f["cites"]) and f["cites"]           # A5: the channel's lines
    assert len([k for k in w.knocks if "kimi" in json.dumps(k) and "NEW-AGENT" in json.dumps(k)]) == 1   # one knock
    (line,) = [x for x in rounds[1]["lines"] if x["tool"] == host.TREE_TOOL]
    assert line["input_meta"]["brief"] is True and line["input_meta"]["seen"] == host.BRIEF_TEXT
    key = tuple(f["tree_key"])
    src = w.sources[key]
    assert src.kind == "os" and G_KIMI in src.text and "rooted at pid 9176 and ProcessGuid" in src.text
    assert src.error is None and src.ended and "gone" in src.ended               # ended, without a hole
    assert not [h for h in w.holes if h["kind"].startswith("source")]
    assert any(s["rule_id"] == "NET-TOOL" and s.get("tree") == KIMI_WORD for s in w.source_findings), \
        w.source_findings   # curl under kimi, on kimi's tree
    assert rounds[2]["gone"] == [KIMI_WORD]
    report = w.summary()[0]
    assert "[candidate] [brief] pid 9176 kimi" in report and "CHANNEL (the rounds read" in report


def not_by_itself(w):
    """AA-1: no NEW-AGENT-UNKNOWN finding, no knock of it, no alarm of it (its acts are judged as any tree's)."""
    return (not [k for k in w.knocks if "NEW-AGENT" in json.dumps(k)]
            and not [a for a in w.result()[1] if "NEW-AGENT" in a])


def test_aa1_case1_a_brief_unknown_tree_is_listed_by_the_channel_not_knocked(tmp_path, monkeypatch):
    w, _, rounds = channel_watch(tmp_path, monkeypatch, ["quiet/quiet"] * 2, ["", agentx_events()])
    (word,) = rounds[1][host.BRIEF]
    assert new_findings(w) == [] and rounds[1]["by_channel"] == [word] and rounds[1]["new"] == []
    tree = next(t for k, t in w.trees.items() if k[0] == 9216)
    assert tree["by_channel"] and w.sources.get(next(k for k in w.trees if k[0] == 9216)) is not None   # sourced
    assert not_by_itself(w) and "unknown, by the channel: 1 tree(s) of " + AGENTX in w.summary()[0]
    assert w.state(w.clock())["host"]["by_channel"][0]["count"] == 1


def without(tmp_path, name, pids, base="quiet/quiet"):
    """A copy of a sample with these processes' rows left out (SYNTHETIC)."""
    import shutil
    d = tmp_path / name
    shutil.copytree(str(HOSTFIX / base), str(d))
    rows = (d / "win-process-1.csv").read_text(encoding="ascii").splitlines(True)
    (d / "win-process-1.csv").write_text("".join(r for r in rows if not any(r.startswith('"%d",' % p) for p in pids)),
                                         encoding="ascii")
    return d


def test_aa1_case2_a_long_lived_unknown_tree_a_candidate_only_in_the_channel_is_not_knocked(tmp_path, monkeypatch):
    # AB-10: the shell alive in every sample with no sampled child (conhost left out), never talking at one; its talk
    # and its child are in the channel only
    alone = without(tmp_path, "alone", [5890])
    w, _, rounds = channel_watch(tmp_path / "w", monkeypatch, [alone] * 3, ["", shell_events(rec=500), ""])
    assert rounds[1]["by_channel"] and new_findings(w) == [] and not_by_itself(w)
    assert [g["count"] for g in w.by_channel.values()] == [1]


def test_aa1_case3_a_named_tree_knocks_each_time_brief_or_not(tmp_path, monkeypatch):
    again = kimi_events(rec=700, guid=G_KIMI2, at="2026-11-10 07:53:")
    w, _, _ = channel_watch(tmp_path, monkeypatch, ["quiet/quiet"] * 4, ["", kimi_events(), "", again])
    assert len(new_findings(w, host.NEW_AGENT)) == 2 and not w.by_channel


def test_aa1_case4_a_candidate_at_a_sample_knocks_as_before_and_once_after_the_channel(tmp_path, monkeypatch):
    w, _, rounds = channel_watch(tmp_path, monkeypatch, ["quiet/talking"], [""])
    assert [f["rule_id"] for f in new_findings(w)] == [host.NEW_UNKNOWN]   # exactly as before M7.9
    w2, _, rounds2 = channel_watch(tmp_path / "b", monkeypatch, ["quiet/quiet", "quiet/quiet", "quiet/talking",
                                                                 "quiet/talking"], ["", shell_events(rec=500), "", ""])
    news = new_findings(w2)
    assert rounds2[1]["by_channel"] and [f["round"] for f in news] == [3]   # first by the channel, then at the sample


FORMS = {   # one round's view of the shell: (sample directory, what the channel logged since the last round)
    "alive-unread+talk": ("quiet/quiet-unread", "T"),   # AB-7: alive, its sampled start unread, its guid's talk
    "sampled": ("quiet/talking", ""),
    "sampled+channel": ("quiet/talking", "S"),
    "alive+channel": ("quiet/quiet", "S"),
    "alive+talk": ("quiet/quiet", "T"),
    "brief": ("quiet/ended", "S"),
    "brief-no-create": ("quiet/ended", "T"),
}


@pytest.mark.parametrize("first, second", list(itertools.product(sorted(FORMS), repeat=2)))
def test_e2_a_tree_seen_both_ways_is_one_tree_in_every_order(tmp_path, monkeypatch, first, second):
    made = {"S": shell_events(rec=500), "T": shell_events(rec=510, create=False, at="2026-11-10 07:50:20")}
    texts = [made.get(FORMS[first][1], ""), made.get(FORMS[second][1], "")]
    if texts[1] == texts[0]:
        texts[1] = shell_events(rec=520, create=False, at="2026-11-10 07:51:20") if texts[0] else texts[1]
    w, _, rounds = channel_watch(tmp_path, monkeypatch, ["quiet/quiet", FORMS[first][0], FORMS[second][0]],
                                 [""] + texts)
    keys = {k for k in w.trees if k[0] == 5888}
    news = new_findings(w)
    assert len(keys) == 1, (first, second, keys)   # AA-4: one tree in every order (its events within its life)
    at_sample = {"sampled", "sampled+channel"} & {first, second}   # AA-1: knocked only where a sample shows it
    assert len(news) == (1 if at_sample else 0) and all(f["round"] in (2, 3) for f in news), news
    # AB-1: one tree, so a count of 1 where it was listed by the channel and never knocked, else 0 (never tagged)
    assert w.by_channel_count() == (0 if at_sample else 1), (first, second, w.by_channel)
    assert all(not w.trees[k].get("by_channel") for k in keys) if at_sample else True
    assert len([k for k in w.knocks if "5888" in json.dumps(k) and "NEW-AGENT" in json.dumps(k)]) == len(news)
    srcs = [w.sources[k] for k in w.sources if k[0] == 5888]
    assert len(srcs) == 1 and (G_SHELL in srcs[0].text or "ProcessGuid" not in srcs[0].text)


@pytest.mark.parametrize("together", [False, True])
def test_e2_a_reused_pid_is_another_tree(tmp_path, monkeypatch, together):
    again = kimi_events(rec=700, guid=G_KIMI2, at="2026-11-10 07:53:")
    rounds = ["", kimi_events() + again, ""] if together else ["", kimi_events(), "", again]
    w, _, seen = channel_watch(tmp_path, monkeypatch, ["quiet/quiet"] * len(rounds), rounds)
    keys = sorted(k for k in w.trees if k[0] == 9176)
    assert len(keys) == 2 and len(new_findings(w, host.NEW_AGENT)) == 2, keys   # a named agent: news each time
    assert {w.trees[k]["guid"] for k in keys} == {G_KIMI, G_KIMI2}


def test_x9_history_is_one_rule_for_both_readers(tmp_path, monkeypatch):
    # the shell's start (07:50:00) read after the watch's start (07:49:30): not history in round 1, sampled or brief
    w, _, rounds = channel_watch(tmp_path, monkeypatch, ["quiet/talking"], [""])
    assert not w.trees[next(iter(w.trees))]["history"] and len(new_findings(w)) == 1
    w2, _, _ = channel_watch(tmp_path / "b", monkeypatch, ["quiet/ended", "quiet/ended"], [kimi_events(), ""])
    assert len(new_findings(w2)) == 1
    # a watch that started after the shell: its start was read and is before the start: history
    w3, _, rounds3 = channel_watch(tmp_path / "c", monkeypatch, ["quiet/talking"], [""], wall0=WALL0 + 600)
    assert rounds3[0]["history"] and new_findings(w3) == []


def test_x9_brief_then_alive_and_one_nested_under_a_living_tree(tmp_path, monkeypatch):
    # brief in round 2, alive (sampled, talking) in round 3: one tree, quiet or present, never new twice
    w, _, rounds = channel_watch(tmp_path, monkeypatch, ["quiet/quiet", "quiet/ended", "quiet/talking"],
                                 ["", shell_events(rec=500), ""])
    assert len({k for k in w.trees if k[0] == 5888}) == 1 and len(new_findings(w)) == 1
    # a brief tree under a living one: the shell sampled and talking; its child kimi starts, talks, acts, ends
    nested = kimi_events(rec=600).replace("<Data Name='ParentProcessId'>3000</Data>",
                                          "<Data Name='ParentProcessId'>5888</Data>").replace(
        guid_of(3000), G_SHELL)
    w2, _, rounds2 = channel_watch(tmp_path / "b", monkeypatch, ["quiet/talking"] * 2, ["", nested])
    assert any(k[0] == 9176 for k in w2.trees) and len({k for k in w2.trees if k[0] == 5888}) == 1


def test_x1_the_channel_helper_is_ended_at_stop(tmp_path, monkeypatch):
    class Out:
        pid = 777

        def terminate(self):
            pass

        def wait(self, timeout=None):
            return 0

    w2, _, _ = channel_watch(tmp_path / "b", monkeypatch, ["quiet/quiet"], [""])
    chan, other = os_sysmon.Channel(), os_sysmon.Channel()
    chan.helpers.running[777] = Out()
    other.helpers.running[778] = Out()
    os_sysmon.OPEN_CHANNELS.extend([chan, other])
    w2.channel_owner = os_sysmon.ChannelOwner()   # AB-9: the watch's own reader's channel, and another's
    w2.channel_owner.add(chan)
    w2.finished = None
    w2.stop_sources(w2.clock())
    assert chan.helpers.running == {} and any(h["kind"] == "channel-helper" and "777" in h["detail"]
                                              for h in w2.holes)
    assert 778 in other.helpers.running and other in os_sysmon.OPEN_CHANNELS and not other.closed   # no other


# --- AA-1 (X-5 withdrawn): brief unknown runs are listed by the channel and counted by path, not knocked --------

def updater_run(i):
    """An updater that starts, talks, starts the new version and ends between two rounds (SYNTHETIC)."""
    pid, rec, at = 9400 + 10 * i, 1000 + 10 * i, at_text(EVERY * (1 + i // 2) - 60 + 20 * (i % 2))[:-4]
    up = "C:\\Users\\user\\AppData\\Local\\notes\\Update.exe"
    return "".join([
        created(rec, at + ".000", pid, up, guid_of(pid), 3000, EXPLORER, guid_of(3000), "Update.exe --update"),
        talked(rec + 1, at + ".200", pid, up, guid_of(pid), port=51000 + i, dest="203.0.113.80"),
        created(rec + 2, at + ".400", pid + 1, "C:\\Users\\user\\AppData\\Local\\notes\\app-2.1\\notes.exe",
                guid_of(pid + 1), pid, up, guid_of(pid), "notes.exe --updated"),
        event(11, rec + 3, at + ".500", pid, up, guid_of(pid),
              TargetFilename="C:\\Users\\user\\AppData\\Local\\notes\\packages\\RELEASES")])


def git_run(i):
    """git over https: git-remote-https talks and starts its credential helper (SYNTHETIC)."""
    pid, rec, at = 9800 + 10 * i, 2000 + 10 * i, at_text(EVERY * (1 + i) - 50)[:-4]
    git = "C:\\Program Files\\Git\\mingw64\\bin\\git.exe"
    remote = "C:\\Program Files\\Git\\mingw64\\libexec\\git-core\\git-remote-https.exe"
    return "".join([
        created(rec, at + ".000", pid, remote, guid_of(pid), 9799, git, guid_of(9799), "git-remote-https origin"),
        talked(rec + 1, at + ".100", pid, remote, guid_of(pid), port=52000 + i, dest="203.0.113.81"),
        created(rec + 2, at + ".300", pid + 1, "C:\\Program Files\\Git\\mingw64\\bin\\git-credential-manager.exe",
                guid_of(pid + 1), pid, remote, guid_of(pid), "git-credential-manager get")])


def test_x5_brief_unknown_runs_are_counted_by_path_one_per_tree_and_never_knocked(tmp_path, monkeypatch):
    rounds = [""] + ["".join(updater_run(2 * k + j) for j in (0, 1)) for k in range(7)]
    w, _, seen = channel_watch(tmp_path, monkeypatch, ["quiet/quiet"] * len(rounds), rounds)
    ups = [k for k in w.trees if k[1] == "update"]
    (group,) = w.by_channel.values()
    assert len(ups) == 14 and new_findings(w) == [] and group["count"] == 14 and len(group["trees"]) == 5   # W6
    assert [t["round"] for t in group["trees"]] == sorted(w.trees[k]["by_channel_round"] for k in ups)[-5:]   # AB-1
    assert all(w.sources.get(k) is not None for k in ups)   # each listed and sourced like any tree
    assert "14 tree(s) of C:\\Users\\user\\AppData\\Local\\notes\\Update.exe" in w.summary()[0]


def test_x5_measured_git_over_https_and_a_living_agents_short_lived_child(tmp_path, monkeypatch):
    rounds = [""] + [git_run(k) for k in range(5)]
    w, _, _ = channel_watch(tmp_path, monkeypatch, ["quiet/quiet"] * len(rounds), rounds)
    gits = [k for k in w.trees if k[1] == "git-remote-https"]
    knocks = new_findings(w)
    # measured: 5 brief trees, none knocked (AA-1: listed by the channel, counted by path: 5 trees)
    assert len(gits) == 5 and knocks == [] and [g["count"] for g in w.by_channel.values()] == [5], (gits, knocks)
    child = created(3000, "2026-11-10 07:50:40.000", 5990, "C:\\Windows\\System32\\curl.exe", guid_of(5990), 5888,
                    PS, G_SHELL, "curl -s https://198.51.100.20/y")
    w2, _, _ = channel_watch(tmp_path / "b", monkeypatch, ["quiet/talking"] * 3, ["", child, ""])
    assert len(w2.trees) == 1 and len(new_findings(w2)) == 1   # the child is an act of the living tree, no tree


# --- E4 / X-8: what the channel does not hold, and the hole where there is none ---------------------------------------

def test_x8_no_probe_at_the_start_and_a_kind_not_read_in_three_rounds_is_said_once(tmp_path, monkeypatch):
    w, fake, _ = channel_watch(tmp_path, monkeypatch, ["quiet/quiet"] * 4, ["", shell_events(rec=500), "", ""])
    assert len(fake.args) == 4 and not any("/rd:true" in a for a in fake.args)   # no probe: one read per round
    said = [n for n in w.notes if "read so far" in n]
    assert len(said) == 1 and "no event 22 read so far" in said[0]
    report = w.summary()[0]
    assert "kinds read: event 1, event 3" in report and report.count("no event 22 read so far") == 2


@pytest.mark.parametrize("platform", ["linux", "win32"])
def test_e4_without_the_channel_the_between_rounds_hole_stays(tmp_path, monkeypatch, platform):
    clock = host.FixtureClock()
    notifier = notify.Notifier(host.HOST, enabled=False, reason="fixture", host=True)
    off = {"channel": {"off": "no Sysmon here (the reader's check)"}} if platform == "win32" else {}
    rounds = iter([dict(discover.run({}, CATALOG), **off)] * 2)
    w = host.HostWatch(lambda: next(rounds), CATALOG, RULES, notifier, out=None, err=io.StringIO(), clock=clock,
                       wall=lambda: WALL0, home=str(tmp_path), platform=platform, run="fixture-run",
                       sysmon=lambda: (platform == "win32", "the watch's own check (AA-6: not the one that decides)"))
    for _ in range(2):
        w.tick(wait=30)
        clock.t += 10
    (note,) = [n for n in w.notes if n.startswith("a tree that lives between two rounds is not seen")]   # once
    assert ("Linux" in note) == (platform == "linux") and ("no Sysmon channel is read" in note) == (platform == "win32")
    assert platform == "linux" or ("the reader's check" in note and w.sysmon_ok() is False)   # AA-6: the reader decides
    w.finish()
    threat = " ".join((ROOT / "docs" / "THREAT_MODEL.md").read_text(encoding="utf-8").split())
    assert "narrowed where Sysmon is read (ADR-0007 P-4)" in threat and "`brief`" in threat and "`by the channel`" in threat
    assert "does not close" in threat and "keep the whole hole" in threat and "a hole that remains" in threat
    assert "closed where Sysmon is" not in threat and "said as a hole of each round" not in threat


def test_e6_linux_is_unchanged_no_channel_no_sysmon_source(monkeypatch):
    monkeypatch.setattr(discover, "collect_live", SampleSeq(["quiet/talking"]))
    monkeypatch.setattr(discover, "read_conn_bytes", lambda paths: ({}, "fake ss", "no ss here (fake)"))
    monkeypatch.setattr(discover, "proc_start_times", lambda pids: ({}, "no /proc here (fake)"))
    inv = host.live_reader(CATALOG, platform="linux", ss_paths=("/nonexistent/ss",))()
    assert "channel" not in inv and not any(s["name"].startswith("sysmon") for s in inv["sources"])
    texts, holes = discover.read_dir(str(HOSTFIX / "quiet" / "talking"))
    plain = discover.run(texts, CATALOG, holes=holes, processes=True)
    assert plain["candidates"] and "guid" not in plain["candidates"][0] and "brief" not in plain["candidates"][0]


def test_e5_the_benign_desktop_with_its_channel_adds_no_tree():
    d = FIX / "discover" / "benign" / "windows-desktop"
    texts, holes = discover.read_dir(str(d))
    xml = (FIX / "os" / "benign-windows-desktop.sysmon.xml").read_text(encoding="ascii")
    counts = []
    for channel in (False, True):
        out = [0, 0]
        for k in (1, 2):
            one = {n: v for n, v in texts.items() if n.endswith("-%d" % k) or n == "footprints"}
            if channel:
                one["sysmon"] = ("fixture channel", xml if k == 1 else "", None)
            inv = discover.run(one, CATALOG, holes=holes, run=discover.run_record(str(d)), processes=True,
                               channel=channel)
            out[0] += len(host.trees_of(inv, CATALOG))
            out[1] += len(inv["act_roots"])
        counts.append(out)
    assert counts[0] == counts[1] == [4, 0], counts   # measured (A6): trees 4 / 4, act-roots 0 / 0


def test_e6_the_readme_and_the_help_say_it():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "M7.9" in readme and "`brief`" in readme and "between two rounds is not seen" in readme
    cli_text = (ROOT / "raqib" / "cli.py").read_text(encoding="ascii")
    assert "listed as brief" in cli_text and cli_text.count("M7.9") >= 2


# --- REDO 3: AA-2, AA-3, AA-4, AA-6 - each with the case it is for and the case it must not touch -------------------

def _utc(*a):
    import datetime
    return datetime.datetime(*a, tzinfo=datetime.timezone.utc)


def old_records(n, base=800):
    return channel_xml(*[created(base + i, "2026-11-10 07:40:%02d.000" % i, 9600 + i, CONHOST, guid_of(9600 + i),
                                 3000, EXPLORER, guid_of(3000), "c") for i in range(n)])


def test_aa2_two_reads_of_only_records_older_than_their_start_restart_said():
    import datetime
    t0 = _utc(2026, 11, 10, 7, 49, 30)
    chan = os_sysmon.Channel(since=t0, reader=lambda args, timeout: (old_records(4), None))   # N = 4 > 2
    _, r1 = chan.read(t0)
    chan.commit(r1, t0)
    assert r1["dropped"] == 4 and not r1["restarted"] and chan.early_rounds == 1
    _, r2 = chan.read(t0 + datetime.timedelta(seconds=120))
    assert r2["restarted"] and "older than the read's start" in r2["restarted"] and "is not read" in r2["restarted"]
    # must not touch: reads that also return a record at or after the start never restart
    texts = [old_records(4, base=1000 + 10 * k) + created(1005 + 10 * k, "2026-11-10 07:50:00.000", 9700 + k, CONHOST,
                                                          guid_of(9700 + k), 3000, EXPLORER, guid_of(3000), "c")
             for k in range(3)]
    chan2 = os_sysmon.Channel(since=t0, reader=lambda args, timeout: (texts.pop(0), None))
    for k in range(3):
        _, r = chan2.read(t0 + datetime.timedelta(seconds=120 * k))
        chan2.commit(r, t0 + datetime.timedelta(seconds=120 * k))
        assert not r["restarted"] and chan2.early_rounds == 0


def test_aa3_two_programs_of_one_name_in_two_directories_are_two_groups(tmp_path, monkeypatch):
    other = "C:\\Users\\user\\AppData\\Local\\elsewhere\\agentx.exe"
    w, _, _ = channel_watch(tmp_path, monkeypatch, ["quiet/quiet"] * 3,
                            ["", agentx_events(), agentx_events(rec=750, image=other, pid=9260)])
    assert sorted(w.by_channel) == sorted([AGENTX, other]) and [g["count"] for g in w.by_channel.values()] == [1, 1]
    # must not touch: the same path twice is one group of two
    w2, _, _ = channel_watch(tmp_path / "b", monkeypatch, ["quiet/quiet"] * 3,
                             ["", agentx_events(), agentx_events(rec=750, pid=9260)])
    assert [(g["path"], g["count"]) for g in w2.by_channel.values()] == [(AGENTX, 2)]


def test_aa3_a_run_with_no_path_read_is_grouped_by_its_name_and_says_so(tmp_path, monkeypatch):
    # AB-10: through rounds: a run whose path was read nowhere (its sampled row has no ExecutablePath, as an export
    # not elevated gives it; its talk and child are in the channel, with no image path) beside one with its path
    d = sample_dir(tmp_path, "nopath", [])
    with open(d / "win-process-1.csv", "a", encoding="ascii", newline="\n") as f:
        f.write('"9216","3000","agentx.exe",,"agentx","2026-11-10T07:50:30.000Z"\n')
    g = guid_of(9216)
    nopath = (talked(701, "2026-11-10 07:51:01.000", 9216, "", g, port=50400, dest="203.0.113.70")
              + created(702, "2026-11-10 07:51:02.000", 9330, "C:\\Windows\\System32\\cmd.exe", guid_of(9330), 9216,
                        "", g, "cmd /c dir"))
    w, _, _ = channel_watch(tmp_path / "w", monkeypatch, [d] * 3, ["", nopath, agentx_events(rec=750, pid=9260)])
    nameless = [p for p in w.by_channel if p.endswith("(no path read: grouped by name)")]
    assert len(w.by_channel) == 2 and AGENTX in w.by_channel and len(nameless) == 1, w.by_channel
    assert w.by_channel[nameless[0]]["count"] == 1 and w.by_channel[AGENTX]["count"] == 1
    assert any("grouped by name" in x for x in w.by_channel_lines())


def test_aa3_a_read_less_than_a_round_behind_says_nothing():
    import datetime
    t0 = _utc(2026, 11, 10, 7, 49, 30)
    late = created(901, "2026-11-10 07:51:10.000", 9701, CONHOST, guid_of(9701), 3000, EXPLORER, guid_of(3000), "c")
    chan = os_sysmon.Channel(since=t0, reader=lambda args, timeout: ("", None))
    _, r = chan.read(t0 + datetime.timedelta(seconds=120))
    chan.commit(r, t0 + datetime.timedelta(seconds=120))   # prev_at 07:51:30
    chan.reader = lambda args, timeout: (channel_xml(late), None)   # 20 s older than the previous read: < a round
    _, r = chan.read(t0 + datetime.timedelta(seconds=240))
    assert r["older_seconds"] is None and r["holes"] == []
    # must not touch: more than a round behind is said
    chan.commit(r, t0 + datetime.timedelta(seconds=240))
    chan.reader = lambda args, timeout: (channel_xml(created(902, "2026-11-10 07:50:00.000", 9702, CONHOST,
                                                             guid_of(9702), 3000, EXPLORER, guid_of(3000), "c")), None)
    _, r = chan.read(t0 + datetime.timedelta(seconds=360))
    assert r["older_seconds"] > 120 and any("lag the channel" in h for h in r["holes"])


def test_aa4_a_guid_within_a_trees_life_is_that_tree_and_a_reuse_after_it_is_another(tmp_path, monkeypatch):
    talk = shell_events(rec=510, create=False, at="2026-11-10 07:50:20")   # within [07:50:00, the sample at 07:51:30]
    w, _, _ = channel_watch(tmp_path, monkeypatch, ["quiet/quiet", "quiet/talking", "quiet/ended"], ["", "", talk])
    assert len({k for k in w.trees if k[0] == 5888}) == 1 and len(new_findings(w)) == 1
    # must not touch: the same pid and image after the tree's last sample is another process (a reuse)
    after = shell_events(rec=520, create=False, guid=guid_of(15888), at="2026-11-10 07:52:40")
    w2, _, _ = channel_watch(tmp_path / "b", monkeypatch, ["quiet/quiet", "quiet/talking", "quiet/ended"],
                             ["", "", after])
    assert len({k for k in w2.trees if k[0] == 5888}) == 2


def test_aa6_the_channel_leaves_the_open_set_at_stop_and_a_closed_channel_reads_and_starts_nothing(
        tmp_path, monkeypatch):
    w, fake, _ = channel_watch(tmp_path, monkeypatch, ["quiet/quiet"] * 2, ["", ""])
    assert os_sysmon.OPEN_CHANNELS == [] and len(fake.args) == 2   # closed by the watch's Stop
    calls = []
    chan = os_sysmon.Channel(since=_utc(2026, 11, 10, 7, 49, 30), reader=lambda args, timeout: calls.append(args))
    chan.close()
    text, record = chan.read(_utc(2026, 11, 10, 7, 51, 30))
    assert text is None and "closed" in record["error"] and calls == []


def test_aa6_a_helper_started_as_its_channel_closes_is_ended_and_recorded():
    events = []

    class Starting:
        pid = 4343
        returncode = None

        def __init__(self, argv, **kw):
            helpers.end("the watch stopped (Stop)")   # Stop lands between the closed check and the registration

        def communicate(self, timeout=None):
            events.append("communicate")
            return b"", b""

        def terminate(self):
            events.append("terminate")

        def wait(self, timeout=None):
            return 0

    helpers = os_sysmon.Helpers()
    text, why = os_sysmon.read_live_bounded(10, helpers, popen=Starting, environ={"SystemRoot": "C:\\Windows"},
                                            args=os_sysmon.round_args("*"))
    assert text is None and "closed" in why and events == ["terminate"] and helpers.running == {}
    assert "its channel was closed as it started" in helpers.record[-1]


# --- REDO 4 (ADR-0007 Amendment AB): each ruling, the case it is FOR and what it MUST NOT TOUCH ---------------------

def test_ab1_a_long_lived_tree_by_the_channel_in_every_round_is_one_tree_not_one_per_round(tmp_path, monkeypatch):
    alone = without(tmp_path, "alone", [5890])
    talks = [shell_events(rec=500 + 10 * k, create=False, at=at_text(EVERY * (k - 1) + 30)[:-4]) for k in range(1, 5)]
    w, _, rounds = channel_watch(tmp_path / "w", monkeypatch, [alone] * 5, [""] + talks)
    (key,) = [k for k in w.trees if k[0] == 5888]
    assert all(r["by_channel"] == [] for r in rounds[2:]) and rounds[1]["by_channel"] == [host.tree_word(key)]
    assert w.by_channel_count() == 1 and [g["count"] for g in w.by_channel.values()] == [1]   # FOR: 1, not 4
    assert w.trees[key]["by_channel_round"] == 2 and new_findings(w) == []
    assert w.state(w.clock())["host"]["by_channel_count"] == 1
    assert "[candidate] [%s] pid 5888" % host.BY_CHANNEL in w.summary()[0]   # AB-11: the TREES SEEN line says it
    from raqib import ui
    assert "by the channel</span>" in ui.host_page(w.state(w.clock()))   # the page's tag


def test_ab11_threat_model_records_what_is_not_built():
    threat = " ".join((ROOT / "docs" / "THREAT_MODEL.md").read_text(encoding="utf-8").split())
    assert "Recorded, not closed (ADR-0007 AB-11)" in threat and "1440 entries" in threat and "M7.12" in threat
    assert "joins the earlier tree" in threat and "HOST-RHYTHM and HOST-UNWATCHED never see the repetition" in threat
    assert "with the sampled start unread, never" not in threat and "two reads of only such records" not in threat
    cli_text = " ".join((ROOT / "raqib" / "cli.py").read_text(encoding="ascii").split())
    assert "listed `by the channel` and counted, not knocked" in cli_text


def test_ab1_a_knocked_tree_is_never_tagged_by_the_channel(tmp_path, monkeypatch):
    # V12: knocked at a sample in round 2, then a candidate only by the channel in round 3
    w, _, rounds = channel_watch(tmp_path, monkeypatch, ["quiet/quiet", "quiet/talking", "quiet/quiet"],
                                 ["", "", shell_events(rec=520, create=False, at="2026-11-10 07:52:00")])
    (key,) = [k for k in w.trees if k[0] == 5888]
    assert len(new_findings(w)) == 1 and not w.trees[key].get("by_channel") and w.by_channel_count() == 0
    assert rounds[2]["by_channel"] == [] and "[%s]" % host.BY_CHANNEL not in w.summary()[0]
    assert not any(x["input_meta"].get("by_channel") for r in rounds for x in r["lines"])
    from raqib import ui
    assert "by the channel</span>" not in ui.host_page(w.state(w.clock()))   # never tagged on the page
    # must not touch (AA-1 case 4): first listed by the channel, then a candidate at a sample: knocked then, once,
    # and untagged from then on
    w2, _, rounds2 = channel_watch(tmp_path / "b", monkeypatch, ["quiet/quiet", "quiet/quiet", "quiet/talking"],
                                   ["", shell_events(rec=500), ""])
    (key2,) = [k for k in w2.trees if k[0] == 5888]
    assert rounds2[1]["by_channel"] and [f["round"] for f in new_findings(w2)] == [3]
    assert not w2.trees[key2].get("by_channel") and "by_channel_round" not in w2.trees[key2]
    assert w2.by_channel_count() == 0 and not w2.by_channel


def test_ab2_the_clean_words_say_the_trees_listed_by_the_channel(tmp_path, monkeypatch):
    in_project = "<Data Name='CurrentDirectory'>C:\\Users\\user\\AppData\\Local\\notes\\</Data>"
    rounds = ["", (updater_run(0) + updater_run(1)).replace(
        "<Data Name='CurrentDirectory'>C:\\Users\\user\\</Data>", in_project)]
    w, _, _ = channel_watch(tmp_path, monkeypatch, ["quiet/quiet"] * 2, rounds)
    text, code = w.summary()
    up = "C:\\Users\\user\\AppData\\Local\\notes\\Update.exe"
    assert code == 0 and w.result()[0] == "clean", w.result()
    assert ("CLEAN: %d tree(s) listed, none knocked; 2 unknown tree(s) seen a candidate only by the channel, listed"
            " and not knocked (AA-1): %s (2)" % (len(w.trees), up)) in text
    assert "RESULT: CLEAN (exit 0: trees listed, none knocked; 2 unknown tree(s) by the channel, listed and not" \
           " knocked (AA-1))" in text
    st = w.state(w.clock())["host"]
    assert st["by_channel_count"] == 2 and st["by_channel_sentence"].startswith("2 unknown tree(s) seen a candidate")
    # must not touch: with M = 0 both lines read exactly as before M7.9
    w2, _, _ = channel_watch(tmp_path / "b", monkeypatch, ["quiet/talking"], [""], wall0=WALL0 + 600,
                             follow=host.FixtureFollow())   # a history tree, its source quiet: a clean watch, M = 0
    text2, code2 = w2.summary()
    assert code2 == 0 and "CLEAN: 1 tree(s) listed, none new: powershell pid 5888\n" in text2
    assert "RESULT: CLEAN (exit 0: trees listed, nothing new)" in text2
    assert w2.state(w2.clock())["host"]["by_channel_sentence"] is None


def first_lines(tmp_path, platform, own):
    running = host.start(CATALOG, RULES, every=10, no_open=True, no_notify=True, port=0, out=io.StringIO(),
                         err=io.StringIO(), environ={}, home=str(tmp_path), platform=platform,
                         reader=lambda: dict(discover.run({}, CATALOG)), sysmon=lambda: (own, "fixture: own check"))
    try:
        return running.out.getvalue().splitlines(), running.watcher
    finally:
        host.close(running)


@pytest.mark.parametrize("platform, own", [("linux", False), ("win32", False), ("win32", True)])
def test_ab3_the_first_lines_say_the_between_rounds_hole_from_the_watchs_own_check(tmp_path, platform, own):
    lines, w = first_lines(tmp_path, platform, own)
    holes = [x for x in lines if x.startswith("raqib watch --host: hole: a tree that lives between two rounds")]
    (src,) = [x for x in lines if x.startswith("raqib watch --host: sources:")]
    assert "(%s" % host.OWN_CHECK in src   # said to be that check
    if platform == "linux" or not own:   # FOR: a `hole:` line of the first lines, as before M7.9
        assert len(holes) == 1 and ("Linux" in holes[0]) == (platform == "linux")
        assert platform == "linux" or host.OWN_CHECK in holes[0]
    else:   # must not touch: Windows with Sysmon prints no between-rounds hole
        assert holes == []


@pytest.mark.parametrize("own, reader", [(True, False), (False, True), (True, True), (False, False)])
def test_ab3_where_the_readers_check_differs_round_1_says_so_once(tmp_path, monkeypatch, own, reader):
    out = io.StringIO()
    w, _, _ = channel_watch(tmp_path, monkeypatch, ["quiet/quiet"] * 2, ["", ""], sysmon=reader, own=own, out=out)
    printed = out.getvalue()
    between = [n for n in w.notes if n.startswith("a tree that lives between two rounds is not seen")]
    differs = printed.count("the live reader's own check at round 1 finds")
    assert differs == (1 if own != reader else 0), printed
    assert len(between) == (0 if own and reader else 1)   # said once in all: first lines or round 1, never both
    if own and not reader:
        assert "hole: a tree that lives between two rounds is not seen" in printed and "host's own record" in printed
    if reader and not own:
        assert "now os (Sysmon) for every tree" in printed and w.sysmon_ok() is True


def footprint_dir(tmp_path, name, base="quiet/quiet"):
    import shutil
    d = tmp_path / name
    shutil.copytree(str(HOSTFIX / base), str(d))
    (d / "footprints.txt").write_text("# SYNTHETIC footprint listing (tests/test_round_channel.py): user `user`\n"
                                      "C:\\Users\\user\\.kimi\n", encoding="ascii")
    return d


def dark_rounds(w):
    return [f["round"] for f in w.findings if f["rule_id"] == "AGENT-DARK-LIVE"]


def test_ab4_a_tree_listed_by_the_channel_does_not_make_a_footprint_live(tmp_path, monkeypatch):
    fp = footprint_dir(tmp_path, "fp")
    reads = agentx_events().replace("cmd /c dir", "cmd /c type C:\\Users\\user\\.kimi\\config.toml")
    w, _, rounds = channel_watch(tmp_path / "a", monkeypatch, [fp] * 4, ["", reads, "", ""])
    w0, _, _ = channel_watch(tmp_path / "b", monkeypatch, [fp] * 4, ["", "", "", ""])   # as before M7.9: unseen
    (line,) = [x for x in rounds[1]["lines"] if x["tool"] == host.FOOTPRINT_TOOL]
    assert w.by_channel_count() == 1 and host.BY_CHANNEL in str(line["input_meta"]["linked"])   # the link is shown
    assert not line["input_meta"]["was_live"] and w.footprints["C:\\Users\\user\\.kimi"].get("live_key") is None
    assert dark_rounds(w) == dark_rounds(w0) == [3]   # FOR: AGENT-DARK-LIVE at the round it did before M7.9
    # must not touch: a footprint linked by a knocked (named) tree is live as before
    w2, _, _ = channel_watch(tmp_path / "c", monkeypatch, [fp] * 5, ["", kimi_events(), "", "", ""])
    assert w2.footprints["C:\\Users\\user\\.kimi"].get("live_key") is not None and dark_rounds(w2) == []


def test_ab5_the_rule_says_it_a_by_the_channel_line_does_not_fire_a_line_without_the_key_does():
    from raqib.rules import fixtures
    rule = next(r for r in RULES if r.id == host.NEW_UNKNOWN)
    neg = ROOT / "tests" / "fixtures" / "rules" / "NEW-AGENT-UNKNOWN" / "negative-by-the-channel.json"
    pos = ROOT / "tests" / "fixtures" / "rules" / "NEW-AGENT-UNKNOWN" / "positive-new-unknown.json"
    assert "tests/fixtures/rules/NEW-AGENT-UNKNOWN/negative-by-the-channel.json" in rule.fixtures["negative"]
    lines = fixtures.load_fixture(str(neg))[0]
    assert [x["input_meta"]["by_channel"] for x in lines] == [True] and not fixtures.fires(rule, str(neg))
    plain = [dict(x, input_meta={k: v for k, v in x["input_meta"].items() if k not in ("by_channel", "candidate_by")})
             for x in lines]
    assert engine.judge(rule, plain, {})[0]   # MUST NOT TOUCH: the same line without the key fires as before
    assert fixtures.fires(rule, str(pos)) and "by_channel" not in pos.read_text(encoding="ascii")
    assert "continue   # AA-1" not in (ROOT / "raqib" / "host.py").read_text(encoding="ascii")   # no host code


def test_ab5_a_rule_switched_off_counts_no_by_the_channel_line(tmp_path, monkeypatch):
    from raqib import overlay
    w, _, rounds = channel_watch(tmp_path, monkeypatch, ["quiet/quiet"] * 2, ["", agentx_events()])
    off = [r for r in RULES if r.id == host.NEW_UNKNOWN]
    import copy
    off = [copy.copy(off[0])]
    off[0].status = "disabled"
    got = overlay.count_not_judged(off, rounds[1]["lines"], {}, {})
    assert got[host.NEW_UNKNOWN]["fired"] == 0   # FOR: no finding it would have made
    lines = [dict(x, input_meta={k: v for k, v in x["input_meta"].items() if k != "by_channel"})
             for x in rounds[1]["lines"]]
    assert overlay.count_not_judged(off, lines, {}, {})[host.NEW_UNKNOWN]["fired"] == 1   # without the key: counted


def channel_texts(sample, xml):
    texts, holes = discover.read_dir(str(sample))
    texts = {k: v for k, v in texts.items() if not k.startswith("sysmon")}
    texts["sysmon"] = ("fixture channel", xml, None)
    return texts, holes


def test_ab6_a_talker_whose_sampled_descendant_hangs_under_a_channel_process_is_by_the_channel(tmp_path):
    # V9: T (the shell) talks at the sample; its only sampled descendant G (pid 6100) has as parent X (pid 6000),
    # known only from its Sysmon 1 (it started and ended between rounds)
    d = without(tmp_path, "v9", [5890], base="quiet/talking")
    with open(d / "win-process-1.csv", "a", encoding="ascii", newline="\n") as f:
        f.write('"6100","6000","whoami.exe","C:\\Windows\\System32\\whoami.exe","whoami","2026-11-10T07:50:30.000Z"\n')
    x = created(800, "2026-11-10 07:50:29.000", 6000, "C:\\Windows\\System32\\cmd.exe", guid_of(6000), 5888, PS,
                G_SHELL, "cmd /c whoami")
    texts, holes = channel_texts(d, channel_xml(x))
    inv = checked_run(texts, CATALOG, holes=holes, processes=True, channel=True)
    (shell,) = [c for c in inv["candidates"] if c["pid"] == 5888]
    assert shell["candidate_by"] == "channel"   # FOR: its candidacy rests on the channel
    bare = REAL_RUN({k: v for k, v in texts.items() if k != "sysmon"}, CATALOG, holes=holes, processes=True)
    assert bare["candidates"] == []   # before M7.9 it was no candidate


def test_ab6_q15_talk_at_the_sample_child_only_in_the_channel_is_by_the_channel(tmp_path):
    d = without(tmp_path, "q15", [5890], base="quiet/talking")
    child = created(810, "2026-11-10 07:50:40.000", 5990, "C:\\Windows\\System32\\whoami.exe", guid_of(5990), 5888,
                    PS, G_SHELL, "whoami")
    texts, holes = channel_texts(d, channel_xml(child))
    (shell,) = [c for c in checked_run(texts, CATALOG, holes=holes, processes=True, channel=True)["candidates"]]
    assert shell["candidate_by"] == "channel"


def test_ab6_the_property_over_every_fixture_round_with_a_channel(tmp_path):
    before = len(PROPERTY)
    reads = [shell_events(), shell_events(create=False), kimi_events(), agentx_events(), updater_run(0), git_run(0),
             HEALTHY, old_records(3), ""]
    for name in ("quiet/quiet", "quiet/talking", "quiet/ended", "quiet/quiet-unread"):
        for xml in reads:
            texts, holes = channel_texts(HOSTFIX / name, xml if xml.startswith("<!--") else channel_xml(xml))
            checked_run(texts, CATALOG, holes=holes, processes=True, channel=True)
    d = FIX / "discover" / "benign" / "windows-desktop"
    texts, holes = discover.read_dir(str(d))
    texts["sysmon"] = ("fixture channel", (FIX / "os" / "benign-windows-desktop.sysmon.xml").read_text(
        encoding="ascii"), None)
    checked_run(texts, CATALOG, holes=holes, run=discover.run_record(str(d)), processes=True, channel=True)
    assert len(PROPERTY) - before == 4 * len(reads) + 1 and sum(PROPERTY[before:]) > 0


def test_ab7_a_live_process_whose_sampled_start_was_unread_is_one_tree_with_its_guid(tmp_path, monkeypatch):
    talking = tmp_path / "talking-unread"
    import shutil
    shutil.copytree(str(HOSTFIX / "quiet" / "talking"), str(talking))
    rows = (talking / "win-process-1.csv").read_text(encoding="ascii").replace(
        '.exe"","2026-11-10T07:50:00.000Z"', '.exe"",""', 1)
    (talking / "win-process-1.csv").write_text(rows, encoding="ascii")
    quiet = HOSTFIX / "quiet" / "quiet-unread"
    t3 = shell_events(rec=530, create=False, at="2026-11-10 07:52:10")   # after round 2's sample, before round 3's
    t4 = shell_events(rec=540, create=False, at="2026-11-10 07:54:10")
    w, _, rounds = channel_watch(tmp_path / "w", monkeypatch, [quiet, talking, quiet, quiet], ["", "", t3, t4])
    keys = [k for k in w.trees if k[0] == 5888]
    assert len(keys) == 1 and keys[0][2] is None and len(new_findings(w)) == 1, keys   # FOR (and AA-4's unread side)
    assert w.trees[keys[0]]["guid"] == G_SHELL and not w.trees[keys[0]].get("by_channel")
    # must not touch: a guid whose events begin after the root left the sample is another tree
    ended = without(tmp_path, "ended-unread", [5888, 5890], base="quiet/quiet")
    w2, _, _ = channel_watch(tmp_path / "w2", monkeypatch, [quiet, talking, ended], ["", "", t3])
    assert len([k for k in w2.trees if k[0] == 5888]) == 2


def filtered_round_samples(tmp_path):
    later = sample_dir(tmp_path, "later", [(7200, CONHOST, "2026-11-10 07:58:00.000")])
    return ["quiet/quiet"] * 5 + [later] * 4


def other_event1(rec, at):
    return created(rec, at, 9500 + rec % 50, "C:\\Windows\\System32\\cmd.exe", guid_of(9500 + rec), 3000, EXPLORER,
                   guid_of(3000), "cmd")


def test_ab8_the_note_for_an_image_without_its_event_1_is_said_per_episode(tmp_path, monkeypatch):
    only_ps = created(500, "2026-11-10 07:50:00.412", 5888, PS, G_SHELL, 5100, EXPLORER, guid_of(5100), "ps")
    came = created(610, "2026-11-10 07:56:00.000", 5990, CONHOST, guid_of(5990), 5888, PS, G_SHELL, "c")
    reads = ["", only_ps, other_event1(600, "2026-11-10 07:52:00.000"), "", came,
             other_event1(620, "2026-11-10 07:58:30.000"), other_event1(630, "2026-11-10 08:00:30.000"),
             other_event1(640, "2026-11-10 08:02:30.000"), ""]
    w, _, _ = channel_watch(tmp_path / "w", monkeypatch, filtered_round_samples(tmp_path), reads)
    said = [n for n in w.notes if "for conhost" in n]
    assert len(said) == 3 and "withdrawn: an event 1 of conhost came" in said[1], said   # note, withdrawn, again
    assert "left out by its configuration, or late" in said[-1]   # the last word is its present state
    assert not [h for h in w.holes if h["kind"].startswith("channel")]


def test_ab9_a_channel_is_closed_by_its_owner_and_no_other(monkeypatch):
    monkeypatch.setattr(os_sysmon, "OPEN_CHANNELS", [])
    monkeypatch.setattr(host, "sysmon_present", lambda platform=None, registry=None: (True, "fixture"))
    monkeypatch.setattr(discover, "collect_live", SampleSeq(["quiet/quiet", "quiet/quiet"]))
    monkeypatch.setattr(os_sysmon, "read_live_bounded", lambda timeout, helpers=None, popen=None, environ=None,
                        args=(): (channel_xml(), None))
    a = os_sysmon.ChannelOwner()
    os_sysmon.OWNER.owner = a
    try:
        host.live_reader(CATALOG, 0.0, "win32")()   # a watch's reader: its channel is the watch's
    finally:
        os_sysmon.OWNER.owner = None
    look = host.live_reader(CATALOG, 0.0, "win32")   # a single look, outside any watch
    look()
    (mine,) = a.channels
    (theirs,) = [c for c in os_sysmon.OPEN_CHANNELS if c is not mine]
    a.close("the watch stopped (Stop)")
    assert mine.closed and mine not in os_sysmon.OPEN_CHANNELS and not theirs.closed   # two open channels: one closed
    assert look.close() == [] and theirs.closed and os_sysmon.OPEN_CHANNELS == []   # the reader's own close
    late = os_sysmon.Channel()
    os_sysmon.OPEN_CHANNELS.append(late)
    a.add(late)   # opened after its owner's Stop: closed at once
    assert late.closed and os_sysmon.OPEN_CHANNELS == []


def test_ab9_a_helper_ended_by_two_callers_is_recorded_once():
    helpers = os_sysmon.Helpers()

    class Racing:
        pid = 4545

        def terminate(self):   # the reader's closed check lands while Stop ends it
            helpers.ended(self, "its channel was closed as it started")

        def wait(self, timeout=None):
            return 0
    helpers.running[4545] = Racing()
    assert len(helpers.end("the watch stopped (Stop)")) == 1 and len(helpers.record) == 1 and helpers.running == {}


def test_ab10_a_benign_brief_tree_is_listed_benign_sourced_its_findings_notes(tmp_path, monkeypatch):
    edge = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"
    reads = "".join([created(900, "2026-11-10 07:51:00.000", 9900, edge, guid_of(9900), 5100, EXPLORER, guid_of(5100),
                             "msedge"),
                     talked(901, "2026-11-10 07:51:01.000", 9900, edge, guid_of(9900), port=50500),
                     created(902, "2026-11-10 07:51:02.000", 9910, "C:\\Windows\\System32\\curl.exe", guid_of(9910),
                             9900, edge, guid_of(9900), "curl -s https://198.51.100.20/z")])
    w, _, rounds = channel_watch(tmp_path, monkeypatch, ["quiet/quiet"] * 2, ["", reads])
    (key,) = [k for k in w.trees if k[0] == 9900]
    t = w.trees[key]
    assert t["benign"] and not t.get("sampled", True) and not t.get("by_channel") and w.sources.get(key) is not None
    assert new_findings(w) == [] and rounds[1]["benign"] == [host.tree_word(key)]
    assert not [f for f in w.source_alarms() if f.get("tree") == host.tree_word(key)]   # its findings are notes


def test_ab10_a_named_long_lived_tree_a_candidate_only_by_the_channel_knocks(tmp_path, monkeypatch):
    alive = sample_dir(tmp_path, "kimi", [(9176, KIMI, "2026-11-10 07:50:30.000")])
    reads = "".join(kimi_events().split("\n", 1)[1:])   # its talk and child, its creation not in the reads
    w, _, _ = channel_watch(tmp_path / "w", monkeypatch, [alive] * 3, ["", reads, ""])
    assert [f["rule_id"] for f in new_findings(w)] == [host.NEW_AGENT] and w.by_channel_count() == 0


def test_ab10_the_sysmon_line_and_the_sources_say_the_readers_check(tmp_path, monkeypatch):
    w, _, _ = channel_watch(tmp_path, monkeypatch, ["quiet/quiet"] * 2, ["", ""], sysmon=False, own=True)
    sysmon_line = next(x for x in w.summary()[0].splitlines() if x.startswith("SYSMON:"))
    assert w.sysmon_ok() is False and "fixture: the watch's own check" not in sysmon_line
    assert all(s.kind != "os" for s in w.sources.values())
