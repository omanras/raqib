"""M15.2b (ADR-0014 Amendment E, AE-1 to AE-3): what was not read is said.

E1 (AE-1): an os net line whose Initiated was not read has no `initiated` key, so NET-ADMIN-PORT cannot judge it and
says so in its partial note. E2 (AE-2): the watch says, once, that its rounds have read no event 11, as it says it of
events 1, 3 and 22. E3 (AE-3): the live reader asks the channel once for its newest event 13; where it holds none, or
the question fails, that is a blind spot of the run, kind `registry`. Every export and channel here is SYNTHETIC
(user `user`, private example or documentation addresses); no live host, no Windows, no real wevtutil."""
import datetime
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from raqib import discover, host  # noqa: E402
from raqib.hooks import os_sysmon  # noqa: E402
from raqib.rules import engine, fixtures  # noqa: E402
from hostthreads import raqib_threads_end  # noqa: E402,F401  (every HostWatch ended, no thread leaked)
from test_round_channel import (CATALOG, EXPLORER, PS, RULES, FakeWevtutil, SampleSeq, channel_watch,  # noqa: E402
                                channel_xml, event, guid_of, shell_events)

FX = ROOT / "tests" / "fixtures" / "rules" / "NET-ADMIN-PORT"
_spec = importlib.util.spec_from_file_location("os_synthetic_m152b", ROOT / "tests" / "fixtures" / "os" / "synthetic.py")
SYN = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(SYN)
PWSH = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
READ_KEYS = ["dest_port", "dest_private", "initiated", "dest_scope", "image", "parent_image"]


def rule(rule_id):
    return next(r for r in RULES if r.id == rule_id)


def export(said):
    """The agent (4950) starts PowerShell (4970), which connects to port 22 of a private address once per word in
    `said`: the word its event 3 gives as Initiated ("-": no Initiated at all)."""
    x = SYN.Export(first_record=79501)
    x.proc("00.100", 4950, SYN.AGENT, '"%s"' % SYN.AGENT, 900, SYN.EXPLORER, "C:\\Windows\\Explorer.EXE")
    x.proc("01.000", 4970, PWSH, '"%s"' % PWSH, 4950, SYN.AGENT, '"%s"' % SYN.AGENT)
    for i, word in enumerate(said):
        x.net("02.%03d" % (100 * (i + 1)), 4970, PWSH, "192.168.1.20", 22)
        x.lines[-1] = x.lines[-1].replace("<Data Name='Initiated'>true</Data>",
                                          "" if word == "-" else "<Data Name='Initiated'>%s</Data>" % word)
    return x.text()


def built(said):
    lines, _ = os_sysmon.build(export(said), 4950, cwd="C:\\work\\proj")
    return lines, [json.loads(line) for line in lines]


def pre_nets(recs):
    return [r for r in recs if r["tool"] == "net" and r["phase"] == "pre"]


# --- E1 (AE-1): an unread Initiated is no key, and the rule says it could not judge the line ----------------------------

def test_e1_absent_empty_or_another_word_is_no_key_and_a_read_one_is_what_it_was():
    lines, recs = built(["true", "-", "", "maybe", "FALSE", "yes"])
    metas = [r["input_meta"] for r in pre_nets(recs)]
    assert [m.get("initiated", "no key") for m in metas] == [True, "no key", "no key", "no key", False, "no key"]
    for m in metas:   # the other three keys of A-5 are there on every line, read or not
        assert {"dest_scope", "image", "parent_image"} <= set(m) and m["dest_scope"] == "private"
    # a line whose Initiated was read keeps its keys in their order, so its bytes are what they were
    read = [json.loads(x)["input_meta"] for x in lines if json.loads(x)["tool"] == "net" and
            "initiated" in json.loads(x)["input_meta"]]
    assert read and all(list(m) == READ_KEYS for m in read)
    assert all('"dest_private":true,"initiated":' in x for x in lines if '"initiated"' in x)
    # post lines carry what the pre lines carry
    posts = [r["input_meta"].get("initiated", "no key") for r in recs if r["tool"] == "net" and r["phase"] == "post"]
    assert sorted(map(str, posts)) == sorted(map(str, [m.get("initiated", "no key") for m in metas]))


def test_e1_every_existing_os_fixture_gives_its_bytes_to_the_byte():
    import test_event_logged_time as logged
    assert logged.every_fixture_build() == logged.FIXTURES_BUILT


def test_e1_net_admin_port_judges_none_of_the_three_and_says_its_partial_note():
    _, recs = built(["-", "", "maybe"])
    found, notes = engine.evaluate([rule("NET-ADMIN-PORT")], recs, {})
    seqs = [r["seq"] for r in pre_nets(recs)]
    assert found == [] and len(seqs) == 3
    (note,) = notes
    assert note["rule_id"] == "NET-ADMIN-PORT" and note["status"] == "partial"
    assert note["detail"].startswith("could not judge 3 line(s) (session:seq %s)" % ", ".join(
        "os-4950:%d" % s for s in seqs))
    # through the watch's own road (host.judge_source): no finding of the rule, the same note
    found, notes = host.judge_source(host.source_rules(RULES), recs)
    assert not [f for f in found if f["rule_id"] == "NET-ADMIN-PORT"]
    assert [n["status"] for n in notes if n["rule_id"] == "NET-ADMIN-PORT"] == ["partial"]
    # the rule is not dead here: the same line with Initiated true is its finding, and no note
    _, recs = built(["true"])
    found, notes = host.judge_source(host.source_rules(RULES), recs)
    assert [f["cited_seq"] for f in found if f["rule_id"] == "NET-ADMIN-PORT"] == [[pre_nets(recs)[0]["seq"]]]
    assert not [n for n in notes if n["rule_id"] == "NET-ADMIN-PORT"]


def test_e1_the_fixture_of_an_unread_initiated_and_the_rules_words():
    lines, _, _ = fixtures.load_fixture(FX / "negative-initiated-unread.json")
    found, notes = engine.evaluate([rule("NET-ADMIN-PORT")], lines, {})
    nets = pre_nets(lines)
    assert len(nets) == 4 and not [r for r in nets if "initiated" in r["input_meta"]]
    assert found == [] and [n["status"] for n in notes] == ["partial"]
    assert "could not judge 3 line(s)" in notes[0]["detail"]   # the public 22 is false whatever it was: judged
    public = [r["seq"] for r in nets if r["input_meta"]["dest_scope"] == "public"]
    assert public and "os-4953:%d)" % public[0] not in notes[0]["detail"]
    assert "negative-initiated-unread.json" in " ".join(rule("NET-ADMIN-PORT").fixtures["negative"])
    # negative-not-admin.json holds no unread Initiated any more, and stays measured
    lines, _, _ = fixtures.load_fixture(FX / "negative-not-admin.json")
    assert all("initiated" in r["input_meta"] for r in pre_nets(lines))
    assert fixtures.outcome(rule("NET-ADMIN-PORT"), FX / "negative-not-admin.json") == (False, set(), True)
    r = rule("NET-ADMIN-PORT")
    text = " ".join(r.evasion)
    assert "initiated null" not in text and "is not judged as initiated" not in text
    assert ("nor a line whose Initiated was not read (absent, empty or another word: no initiated key since M15.2b,"
            " ADR-0014 AE-1), which is said as partial too") in text
    assert ("no initiated key where Sysmon's Initiated was not read: such a line is not judged, the partial note says"
            " it, ADR-0014 AE-1") in r.doc["description"]


# --- E2 (AE-2): no event 11 read is said under the same rule as events 1, 3 and 22 ------------------------------------

OLD_HELD = {1: "no event 1 read so far: a tree that starts and ends between two rounds may be unseen",
            3: "no event 3 read so far: talk between rounds may be unseen (Sysmon without -n logs none)",
            22: "no event 22 read so far: a name asked between two rounds may be unseen"}
SENTENCE_11 = ("no event 11 read so far: a file a tree makes may be unseen, and PERSIST-AUTOSTART's os lines may have"
               " nothing to read (this Sysmon's configuration may not log file creation)")


def wrote(rec, utc, pid=5888, guid=None):
    """A Sysmon event 11 (a file created) of the shell (SYNTHETIC)."""
    return event(11, rec, utc, pid, PS, guid or guid_of(pid), RuleName="-",
                 TargetFilename="C:\\Users\\user\\notes.txt", CreationUtcTime=utc)


def test_e2_the_three_older_sentences_are_unchanged_and_event_11_has_its_own():
    assert sorted(host.CHANNEL_HELD) == [1, 3, 11, 22]
    assert {k: v for k, v in host.CHANNEL_HELD.items() if k != 11} == OLD_HELD
    assert host.CHANNEL_HELD[11] == SENTENCE_11


def test_e2_said_once_when_no_event_11_was_read(tmp_path, monkeypatch):
    w, fake, _ = channel_watch(tmp_path, monkeypatch, ["quiet/quiet"] * 5, ["", shell_events(rec=500), "", "", ""])
    said = [n for n in w.notes if "no event 11 read so far" in n]
    assert said == ["round 3: the Sysmon channel: " + SENTENCE_11]
    assert SENTENCE_11 in w.channel_said and w.channel_said.count(SENTENCE_11) == 1
    assert len(fake.args) == 5   # one read per round, as before


def test_e2_not_said_when_an_event_11_was_read(tmp_path, monkeypatch):
    rounds = ["", shell_events(rec=500) + wrote(503, "2026-11-10 07:50:06.000"), "", ""]
    w, _, _ = channel_watch(tmp_path, monkeypatch, ["quiet/quiet"] * 4, rounds)
    assert 11 in w.channel_last["kinds_read"]
    assert not [n for n in w.notes if "no event 11" in n] and SENTENCE_11 not in w.channel_said
    assert [n for n in w.notes if "no event 22 read so far" in n]   # the others are said as they were


# --- E3 (AE-3): the channel's one question for event 13 ---------------------------------------------------------------

NEWEST = "2026-11-10 07:40:00.000"
REG13 = event(13, 401, NEWEST, 4400, "C:\\Windows\\System32\\reg.exe", guid_of(4400), RuleName="-",
              EventType="SetValue", TargetObject="HKLM\\SOFTWARE\\Example\\Value", Details="DWORD (0x00000001)")
FAILED = "wevtutil did not return in 10 s (SYNTHETIC): the Sysmon channel was not read"


class Asked(FakeWevtutil):
    """The rounds' channel (FakeWevtutil: it honours each round's query) with a question for event 13 of its own,
    `newest`, as os_sysmon.read_live_bounded has one: `answer` is "held" (an event 13), "none" or "error". Each
    question is recorded with the number of round reads before it."""

    def __init__(self, rounds, answer, fail=()):
        super().__init__(rounds, fail)
        self.answer, self.asked = answer, []

    def newest(self, timeout, helpers=None, popen=None, environ=None, args=()):
        self.asked.append((len(self.args), tuple(args), timeout))
        if self.answer == "error":
            return None, FAILED
        return channel_xml(*([REG13] if self.answer == "held" else [])), None


def keeping(invs):
    """The window's reader (host.live_reader) whose inventories are kept, in order."""
    def make(catalog):
        real = host.live_reader(catalog, 0.0)

        def read():
            inv = real()
            invs.append(inv)
            return inv
        return read
    return make


def registry_blind(w):
    return [b for b in w.blind if b["kind"] == "registry"]


def test_e3_the_question_is_bounded_and_of_raqibs_own_values():
    assert os_sysmon.newest_args() == ("qe", "Microsoft-Windows-Sysmon/Operational", "/q:*[System[(EventID=13)]]",
                                       "/rd:true", "/c:1", "/f:xml")
    assert os_sysmon.newest_args(13) == os_sysmon.newest_args("13")
    assert os_sysmon.read_live_bounded.newest is os_sysmon.read_live_bounded


def test_e3_held_is_carried_and_nothing_is_said(tmp_path, monkeypatch):
    invs = []
    fake = Asked(["", "", ""], "held")
    w, _, _ = channel_watch(tmp_path, monkeypatch, ["quiet/quiet"] * 3, [], wevtutil=fake, reader=keeping(invs))
    assert fake.asked == [(1, os_sysmon.newest_args(), os_sysmon.ROUND_TIMEOUT)]   # once, after round 1's read
    assert invs[0]["channel"]["registry"] == {"held": True, "newest": "2026-11-10T07:40:00.000Z"}
    assert ["registry" in i["channel"] for i in invs] == [True, False, False]
    assert registry_blind(w) == [] and "  - registry:" not in w.summary()[0]


def test_e3_none_held_is_a_blind_spot_said_once(tmp_path, monkeypatch):
    invs = []
    fake = Asked(["", "", "", ""], "none")
    w, _, _ = channel_watch(tmp_path, monkeypatch, ["quiet/quiet"] * 4, [], wevtutil=fake, reader=keeping(invs))
    assert len(fake.asked) == 1 and invs[0]["channel"]["registry"] == {"held": False}
    (b,) = registry_blind(w)
    assert b["detail"] == host.REGISTRY_UNHELD + host.BLIND_TAIL and b["class"] == host.BLIND
    assert (b["round"], b["rounds"]) == (1, [1])
    assert host.REGISTRY_UNHELD == (
        "the Sysmon channel held no event 13 (a registry value set) at this watch's first read of it: this Sysmon's"
        " configuration may log no registry value, or none was set under a key it logs in what the channel then held;"
        " PERSIST-RUN-KEY may have nothing to read here (asked once a run: a value logged after it does not take this"
        " back)")
    report = w.summary()[0]
    assert report.count("  - registry: " + host.REGISTRY_UNHELD + host.BLIND_TAIL + "; 1 round(s)") == 1


def test_e3_an_error_is_the_same_kind_said_as_not_known_with_its_reason(tmp_path, monkeypatch):
    fake = Asked(["", "", ""], "error")
    w, _, _ = channel_watch(tmp_path, monkeypatch, ["quiet/quiet"] * 3, [], wevtutil=fake)
    (b,) = registry_blind(w)
    assert b["detail"] == host.REGISTRY_UNKNOWN % FAILED + host.BLIND_TAIL and b["round"] == 1
    assert b["detail"].startswith("whether the Sysmon channel holds any event 13 (a registry value set) is not known"
                                  " (wevtutil did not return in 10 s")
    assert len(fake.asked) == 1


def test_e3_the_rounds_question_is_byte_for_byte_and_the_result_is_unchanged(tmp_path, monkeypatch):
    rounds = ["", shell_events(rec=500), "", ""]
    asked = Asked(rounds, "none")
    w, _, _ = channel_watch(tmp_path / "a", monkeypatch, ["quiet/quiet"] * 4, [], wevtutil=asked)
    plain = FakeWevtutil(rounds)
    w0, _, _ = channel_watch(tmp_path / "b", monkeypatch, ["quiet/quiet"] * 4, [], wevtutil=plain)
    # the round's own question, to the byte: round_args of its query; the two watches differ only by the start's
    # milliseconds (each reader adjusts its start by its own monotonic clock, X-9)
    assert len(asked.args) == len(plain.args) == 4
    assert all(a == os_sysmon.round_args(a[2][3:]) for a in asked.args)
    start = re.compile(r"SystemTime>='[^']+'")
    assert [start.sub("", a[2]) for a in asked.args] == [start.sub("", a[2]) for a in plain.args]
    assert [a[:2] + a[3:] for a in asked.args] == [a[:2] + a[3:] for a in plain.args]
    assert not any("/rd:true" in a or "/c:1" in a for a in asked.args)
    assert registry_blind(w) and not registry_blind(w0)
    assert w.result() == w0.result() and host.EXIT[w.result()[0]] == host.EXIT[w0.result()[0]]
    assert [h["kind"] for h in w.holes] == [h["kind"] for h in w0.holes]
    assert len(w.findings) == len(w0.findings)


def test_e3_a_failed_first_read_asks_nothing_and_the_next_read_asks(tmp_path, monkeypatch):
    invs = []
    fake = Asked(["", "", "", ""], "none", fail={1})
    w, _, _ = channel_watch(tmp_path, monkeypatch, ["quiet/quiet"] * 4, [], wevtutil=fake, reader=keeping(invs))
    assert [a[0] for a in fake.asked] == [2]   # after round 2's read, the first that read the channel
    assert invs[0]["channel"].get("error") and "registry" not in invs[0]["channel"]
    assert invs[1]["channel"]["registry"] == {"held": False}
    (b,) = registry_blind(w)
    assert b["round"] == 2


def test_e3_a_stand_in_without_the_question_is_never_asked_and_nothing_is_said(tmp_path, monkeypatch):
    invs = []
    w, fake, _ = channel_watch(tmp_path, monkeypatch, ["quiet/quiet"] * 3, ["", "", ""], reader=keeping(invs))
    assert not hasattr(fake, "newest") and len(fake.args) == 3
    assert not [i for i in invs if "registry" in i["channel"]] and registry_blind(w) == []
    # a channel given a reader of its own is asked only through that reader's own question
    calls = []
    chan = os_sysmon.Channel(reader=lambda args, timeout: calls.append(args) or ("", None))
    assert chan.registry_held() is None and calls == []

    def reader(args, timeout):
        calls.append(args)
        return "", None
    reader.newest = lambda args, timeout: (calls.append(("newest",) + tuple(args)) or (channel_xml(), None))
    chan = os_sysmon.Channel(reader=reader)
    assert chan.registry_held() == {"held": False} and calls == [("newest",) + os_sysmon.newest_args()]
    # ADR-0014 AF-5: an answer that holds no event and is not empty is not "none": it is not known, with the reason
    reader.newest = lambda args, timeout: ("The system cannot find the file specified.\r\n", None)
    assert os_sysmon.Channel(reader=reader).registry_held() == {
        "error": "wevtutil's answer holds no event and is not empty (44 characters): not read"}
    reader.newest = lambda args, timeout: (" \r\n", None)
    assert os_sysmon.Channel(reader=reader).registry_held() == {"held": False}


def test_e3_never_asked_without_sysmon_or_off_windows(tmp_path, monkeypatch):
    fake = Asked(["", ""], "none")
    w, _, _ = channel_watch(tmp_path, monkeypatch, ["quiet/quiet"] * 2, [], wevtutil=fake, sysmon=False)
    assert fake.asked == [] and fake.args == [] and registry_blind(w) == []
    off = Asked([""], "none")
    monkeypatch.setattr(os_sysmon, "read_live_bounded", off)
    monkeypatch.setattr(discover, "collect_live", SampleSeq(["quiet/quiet"]))
    inv = host.live_reader(CATALOG, 0.0, platform="darwin", sysmon=lambda: (True, "a stand-in that says yes"))()
    assert off.asked == [] and off.args == [] and "channel" not in inv


class Proc:
    """A stand-in wevtutil process (SYNTHETIC): it answers `out`, or does not return in time (out None)."""
    pid = 4343
    returncode = 0
    started = []
    out = ""

    def __init__(self, argv, **kw):
        Proc.started.append((argv, kw))

    def communicate(self, timeout=None):
        if Proc.out is None:
            raise subprocess.TimeoutExpired("wevtutil", timeout)
        return Proc.out.encode("utf-8"), b""

    def terminate(self):
        pass

    def wait(self, timeout=None):
        return 0


def test_e3_the_real_read_its_wevtutil_timeout_helpers_and_owner(monkeypatch):
    real = os_sysmon.read_live_bounded

    def bounded(timeout, helpers=None, popen=None, environ=None, args=()):
        return real(timeout, helpers, popen=Proc, environ={"SystemRoot": "C:\\Windows"}, args=args)
    bounded.newest = bounded
    monkeypatch.setattr(os_sysmon, "read_live_bounded", bounded)
    Proc.started, Proc.out = [], channel_xml(REG13)
    chan = os_sysmon.Channel()
    assert chan.registry_held() == {"held": True, "newest": "2026-11-10T07:40:00.000Z"}
    (argv, kw), = Proc.started
    assert argv == [os_sysmon.WEVTUTIL] + list(os_sysmon.newest_args()) and kw["env"] == {"SystemRoot": "C:\\Windows"}
    Proc.out = None   # not back in time: the channel's own helpers end it and record it
    got = chan.registry_held()
    assert got["error"].startswith("wevtutil did not return in 10 s (") and chan.helpers.running == {}
    assert "(Raqib's own helper) terminated: did not return in 10 s" in chan.helpers.record[0]
    owner = os_sysmon.ChannelOwner()
    owner.add(chan)
    owner.close()
    Proc.started = []
    assert chan.registry_held() == {"error": "the channel is closed (its watch stopped): not asked"}
    assert Proc.started == []   # a closed channel starts no helper


# --- E4: the documents ------------------------------------------------------------------------------------------------

def flat(path):
    return " ".join((ROOT / path).read_text(encoding="utf-8").split())


def test_e4_the_guide_and_the_threat_model_say_it():
    guide = flat("docs/GUIDE.md")
    for sentence in ("a net line whose `initiated` was not read (no key) is not judged, and the rule's partial note"
                     " says so",
                     "Its os lines need Windows with Sysmon logging file creation (event 11): under `raqib watch"
                     " --host` the watch says once when its rounds have read no event 11 of the channel",
                     "It needs Windows with Sysmon logging connections (event 3; Sysmon without -n logs none)",
                     "the watch asks the channel once, at its first read, for its newest event 13; where it holds"
                     " none then, the blind spot `registry` says that PERSIST-RUN-KEY may have nothing to read here"):
        assert sentence in guide, sentence
    threat = flat("docs/THREAT_MODEL.md")
    for sentence in ("A net line whose Initiated was not read has no `initiated` key (ADR-0014 AE-1):",
                     "the watch says once, after three rounds that read the channel, that no event 11 was read",
                     "a channel that holds some event 13 may still not log the Run keys",
                     "it is said as not known, with the reason"):
        assert sentence in threat, sentence
    assert "Still waiting, and said here until they are closed" not in threat
    assert "Both wait for the stage after the registry's values" not in threat


# --- E5: ASCII ----------------------------------------------------------------------------------------------------------

def test_e5_the_changed_files_are_ascii():
    for rel in ("raqib/hooks/os_sysmon.py", "raqib/host.py", "raqib/rules/catalog/NET-ADMIN-PORT.yaml",
                "tests/fixtures/rules/generate.py", "tests/fixtures/rules/NET-ADMIN-PORT/negative-initiated-unread.json",
                "tests/fixtures/rules/NET-ADMIN-PORT/negative-not-admin.json", "tests/test_said_unread.py"):
        (ROOT / rel).read_bytes().decode("ascii")
