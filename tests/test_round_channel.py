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
EVERY = 60


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


class FakeWevtutil:
    """os_sysmon.read_live_bounded, faked: a channel that HONOURS the query (EventRecordID>N, or TimeCreated at or
    after the start; oldest first; /c:cap), whose records are appended round by round. None in `fail` rounds: the
    read did not return. Every argv is recorded."""

    def __init__(self, rounds, fail=()):
        self.rounds = list(rounds)
        self.fail = set(fail)
        self.log = []
        self.args = []

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
        keep = [c for c, r, t in self.log if (rid and r > int(rid.group(1))) or
                (since and t >= discover._ts(since.group(1)))]
        return channel_xml(*keep[:cap]), None


class SampleSeq:
    """discover.collect_live, faked: each call is the next sample directory (its texts and run.json)."""

    def __init__(self, names):
        self.names = list(names)

    def __call__(self, catalog, window=0.0, homes=None, platform=None, win_samples=1, win_every=0.0, run_info=None,
                 **kw):
        d = HOSTFIX / self.names.pop(0)
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


def channel_watch(tmp_path, monkeypatch, samples, rounds, fail=(), sysmon=True, wall0=WALL0, follow=None,
                  reader=None, wevtutil=None):
    seen = []
    fake = wevtutil or FakeWevtutil(rounds, fail)
    clock = host.FixtureClock()
    monkeypatch.setattr(os_sysmon, "read_live_bounded", fake)
    monkeypatch.setattr(os_sysmon, "OPEN_CHANNELS", [])
    monkeypatch.setattr(host, "sysmon_present", lambda platform=None, registry=None: (sysmon, "fixture: Sysmon"))
    monkeypatch.setattr(host, "reader_wall", lambda: wall0 + clock.t)
    monkeypatch.setattr(discover, "collect_live", SampleSeq(samples))
    monkeypatch.setattr(sys, "platform", "win32")   # the window's reader takes the platform from sys (faked here)
    notifier = notify.Notifier(host.HOST, enabled=False, reason="fixture", host=True)
    w = host.HostWatch((reader or window_reader)(CATALOG), CATALOG, RULES, notifier, every=EVERY, out=None,
                       err=io.StringIO(), clock=clock, wall=lambda: wall0 + clock.t, home=str(tmp_path),
                       platform="win32", run="fixture-run", source_every=3600,
                       sysmon=lambda: (sysmon, "fixture: Sysmon"), os_follow=follow or channel_follow(fake))
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


def test_x3b_new_processes_without_their_event_1_say_the_channel_is_behind():
    import datetime
    t0 = datetime.datetime(2026, 11, 10, 7, 49, 30, tzinfo=datetime.timezone.utc)
    chan = os_sysmon.Channel(since=t0, reader=lambda args, timeout: (channel_xml(shell_events(rec=500)), None))
    text, record = chan.read(t0)
    chan.commit(record, t0)
    later = t0 + datetime.timedelta(minutes=2)
    for k in range(3):
        chan.reader = lambda args, timeout: ("", None)
        text, record = chan.read(later)
        chan.silence(record, [(7000 + k, later - datetime.timedelta(seconds=30))], later)
        chan.commit(record, later)
        later += datetime.timedelta(minutes=1)
        assert record["silent"] == 1 and "behind, stopped or cleared" in record["holes"][0]
    assert record["restarted"] and chan.after is None and chan.since is not None


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
    assert any(s["rule_id"] == "NET-TOOL" for s in w.source_findings), w.source_findings   # curl under kimi
    assert rounds[2]["gone"] == [KIMI_WORD]
    report = w.summary()[0]
    assert "[candidate] [brief] pid 9176 kimi" in report and "CHANNEL (the rounds read" in report


def test_e2_a_brief_unknown_tree_gives_new_agent_unknown(tmp_path, monkeypatch):
    w, _, rounds = channel_watch(tmp_path, monkeypatch, ["quiet/quiet"] * 2, ["", agentx_events()])
    (f,) = new_findings(w)
    assert f["rule_id"] == host.NEW_UNKNOWN and f["round"] == 2 and rounds[1][host.BRIEF] == [f["tree"]]


FORMS = {   # one round's view of the shell: (sample directory, what the channel logged since the last round)
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
    if not keys:
        assert news == []
        return
    assert len(keys) == 1, (first, second, keys)
    assert len(news) == 1 and news[0]["round"] in (2, 3), news
    assert len([k for k in w.knocks if "5888" in json.dumps(k) and "NEW-AGENT" in json.dumps(k)]) == 1
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

    w, _, _ = channel_watch(tmp_path, monkeypatch, ["quiet/quiet"], [""])
    chan = os_sysmon.Channel()
    chan.helpers.running[777] = Out()
    os_sysmon.OPEN_CHANNELS.append(chan)
    w2, _, _ = channel_watch(tmp_path / "b", monkeypatch, ["quiet/quiet"], [""])
    os_sysmon.OPEN_CHANNELS.append(chan)
    w2.finished = None
    w2.stop_sources(w2.clock())
    assert chan.helpers.running == {} and any(h["kind"] == "channel-helper" and "777" in h["detail"]
                                              for h in w2.holes)


# --- X-5: a brief unknown image knocks once per watch; its later trees grow the finding --------------------------

def updater_run(i):
    """An updater that starts, talks, starts the new version and ends between two rounds (SYNTHETIC)."""
    pid, rec, at = 9400 + 10 * i, 1000 + 10 * i, "2026-11-10 07:5%d:%02d" % (1 + i // 6, (i * 9) % 60)
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
    pid, rec, at = 9800 + 10 * i, 2000 + 10 * i, "2026-11-10 07:5%d:%02d" % (1 + i // 6, (i * 7 + 3) % 60)
    git = "C:\\Program Files\\Git\\mingw64\\bin\\git.exe"
    remote = "C:\\Program Files\\Git\\mingw64\\libexec\\git-core\\git-remote-https.exe"
    return "".join([
        created(rec, at + ".000", pid, remote, guid_of(pid), 9799, git, guid_of(9799), "git-remote-https origin"),
        talked(rec + 1, at + ".100", pid, remote, guid_of(pid), port=52000 + i, dest="203.0.113.81"),
        created(rec + 2, at + ".300", pid + 1, "C:\\Program Files\\Git\\mingw64\\bin\\git-credential-manager.exe",
                guid_of(pid + 1), pid, remote, guid_of(pid), "git-credential-manager get")])


def test_x5_a_brief_unknown_image_knocks_once_per_watch_and_its_later_runs_grow_it(tmp_path, monkeypatch):
    rounds = [""] + ["".join(updater_run(2 * k + j) for j in (0, 1)) for k in range(7)]
    w, _, seen = channel_watch(tmp_path, monkeypatch, ["quiet/quiet"] * len(rounds), rounds)
    ups = [k for k in w.trees if k[1] == "update"]
    news = new_findings(w, host.NEW_UNKNOWN)
    assert len(ups) == 14 and len(news) == 1 and news[0]["seen"] == 14 and news[0]["grown"].startswith("seen 14 times")
    assert all(w.sources.get(k) is not None for k in ups)   # each listed and sourced like any tree


def test_x5_measured_git_over_https_and_a_living_agents_short_lived_child(tmp_path, monkeypatch):
    rounds = [""] + [git_run(k) for k in range(5)]
    w, _, _ = channel_watch(tmp_path, monkeypatch, ["quiet/quiet"] * len(rounds), rounds)
    gits = [k for k in w.trees if k[1] == "git-remote-https"]
    knocks = new_findings(w)
    # measured: 5 brief trees, at most one NEW-AGENT-UNKNOWN (once for the image), or none where the catalog's
    # benign list holds the image under the system drive's Program Files
    assert len(gits) == 5 and len(knocks) <= 1, (gits, knocks)
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
    w = host.HostWatch(lambda: None, CATALOG, RULES, notifier, out=None, err=io.StringIO(), clock=clock,
                       wall=lambda: WALL0, home=str(tmp_path), platform=platform, run="fixture-run",
                       sysmon=lambda: (False, "no Sysmon here"))
    (note,) = [n for n in w.notes if n.startswith("a tree that lives between two rounds is not seen")]
    assert ("Linux" in note) == (platform == "linux") and ("no Sysmon channel is read" in note) == (platform == "win32")
    w.finish()
    threat = " ".join((ROOT / "docs" / "THREAT_MODEL.md").read_text(encoding="utf-8").split())
    assert "closed where Sysmon is (ADR-0007 P-4)" in threat and "`brief`" in threat and "between two rounds" in threat
    assert "does not close" in threat and "keep the whole hole" in threat and "cleared" in threat


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
