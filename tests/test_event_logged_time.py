"""M7.16 (ADR-0007 Amendment AM): an event's time is when it was logged.
On a machine whose Sysmon stamps its network events weeks behind the time they
were logged, Raqib took the stamp (UtcTime): every connection was before the
watch's start, history, never knocked. AM-1: where System/TimeCreated is read
and UtcTime is more than 60 s from it, the logged time is the event's time and
the line says so (input_meta.time_from, time_skew_s); else UtcTime, to the byte.
AM-2: said once per event kind per watch, a note (not a hole, not a knock).
AM-3: a rule's "could not judge N line(s)" note for one tree's file is one note,
the latest count. AM-4: what RHYTHM BEATS reports for the made-up export, before
AM-1's times and after. The export here is made up in the field's shape (events
1 and 11 at the watch's minute, events 3 logged then and stamped 26 days 7 hours
earlier). SYNTHETIC: host `host`, user `user`, RFC 5737 addresses only. No test
here reads the Table's review folder or the real clock.
"""
import datetime
import json
import re
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from raqib import discover, host  # noqa: E402
from raqib.hooks import os_sysmon  # noqa: E402
from hostthreads import raqib_threads_end  # noqa: E402,F401  (every HostWatch ended, no thread leaked)
from test_round_channel import EXPLORER, G_KIMI, G_SHELL, PS, WALL0, channel_xml, created, event, guid_of, \
    talked  # noqa: E402
from test_host_third_field_run import KIMI, CURL, report, watch  # noqa: E402
from test_host_follow_returns import START, FollowChannel, Rounds, Script, at, follow_through, rounds, \
    settled_follows  # noqa: E402

UTC = datetime.timezone.utc
LAG = datetime.timedelta(days=26, hours=7, minutes=41, seconds=33, milliseconds=383)   # the field's lag
SKEW_S = 2274093   # LAG in whole seconds
NOTE3 = ("Sysmon's event 3 carries a time 26 days 7 hours behind the time it was logged (2274093 s): the logged time"
         " is used")
BASH = "C:\\Program Files\\Git\\usr\\bin\\bash.exe"
G_BASH, G_PS = guid_of(9600), guid_of(9610)


def behind(logged):
    """The UtcTime text of an event logged at `logged` ("YYYY-MM-DD HH:MM:SS.fffffff") whose stamp lags by LAG."""
    when = datetime.datetime.strptime(logged[:26], "%Y-%m-%d %H:%M:%S.%f") - LAG
    return when.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def logged_at(clock):
    return "2026-11-10 %s" % clock


def shape(mode="field"):
    """kimi's shell (bash) and its powershell at the watch's minute (events 1 and 11), each talking (event 3):
    `field` the talks stamped LAG behind the time they were logged; `agree` both times one; `near` logged 59 s
    after the stamp; `none` no TimeCreated in any event."""
    def talk(rec, clock, pid, image, guid, port, dest):
        logged = logged_at(clock)
        if mode == "field":
            return talked(rec, behind(logged), pid, image, guid, port=port, dest=dest, logged=logged)
        utc = logged[:23]
        if mode == "near":
            return talked(rec, utc, pid, image, guid, port=port, dest=dest,
                          logged=(datetime.datetime.strptime(utc, "%Y-%m-%d %H:%M:%S.%f")
                                  + datetime.timedelta(seconds=59)).strftime("%Y-%m-%d %H:%M:%S.%f"))
        return talked(rec, utc, pid, image, guid, port=port, dest=dest, logged="" if mode == "none" else None)
    same = "" if mode == "none" else None
    return [created(800, at("07:54:00"), 9600, BASH, G_BASH, 9176, KIMI, G_KIMI, "bash -c date", logged=same),
            talk(801, "07:54:01.2970157", 9600, BASH, G_BASH, 50500, "198.51.100.40"),
            created(802, at("07:54:02"), 9610, PS, G_PS, 9600, BASH, G_BASH, "powershell -c x", logged=same),
            event(11, 803, at("07:54:03"), 9610, PS, G_PS, logged=same,
                  TargetFilename="C:\\Users\\user\\AppData\\Local\\Temp\\__PSScriptPolicyTest_a.ps1"),
            talk(804, "07:54:04.5000000", 9610, PS, G_PS, 50510, "203.0.113.80")]


def old_times(monkeypatch):
    """The times before AM-1 (UtcTime, whatever the log says): to state what the fix changed."""
    monkeypatch.setattr(discover, "event_time", lambda utc, logged: (discover._ts(utc), None, None))


def pres(lines):
    return [(x["tool"], x["ts"]) for x in lines if x["phase"] == "pre"]


def stamp_behind(text):
    """An export with each event 3's UtcTime set LAG behind the time it was logged (a TimeCreated added from its
    UtcTime where it has none): the field's shape on any synthetic export."""
    chunks = os_sysmon._chunks(text)[1]
    out = []
    for chunk, _, _ in chunks:
        if not re.search(r"<EventID>3</EventID>", chunk):
            out.append(chunk)
            continue
        utc = re.search(r"(<Data Name=['\"]UtcTime['\"]>)([^<]+)(</Data>)", chunk)
        if "TimeCreated" not in chunk:
            chunk = chunk.replace("</EventID>", "</EventID><TimeCreated SystemTime='%sZ'/>"
                                  % utc.group(2).replace(" ", "T"), 1)
        logged = re.search(r"SystemTime=['\"]([^'\"]+)['\"]", chunk).group(1).rstrip("Z").replace("T", " ")
        out.append(chunk.replace(utc.group(0), utc.group(1) + behind(logged + "0000") + utc.group(3)))
    return os_sysmon._chunks(text)[0] + "".join(out)


# --- AM-1: the helper ------------------------------------------------------------------------------------------------

def test_e1_am1_the_time_is_the_logged_one_beyond_sixty_seconds_else_utctime_to_the_byte():
    logged = datetime.datetime(2026, 11, 12, 20, 43, 11, 297015, tzinfo=UTC)
    assert discover.SKEW == 60
    # the field's one event 3: logged then, stamped 26 days 7 hours earlier
    assert discover.event_time("2026-10-17 13:01:37.914", "2026-11-12T20:43:11.2970157Z") == (logged, "logged", SKEW_S)
    assert discover.event_time("2026-11-12 21:43:11.297", "2026-11-12T20:43:11.297Z")[1:] == ("logged", -3600)
    utc = discover._ts("2026-11-12 20:42:11.297")
    for agree in ("2026-11-12T20:43:11.297Z", "2026-11-12T20:42:11.297Z", "2026-11-12T20:41:11.297Z", None, "",
                  "not a time"):
        assert discover.event_time("2026-11-12 20:42:11.297", agree) == (utc, None, None)   # within 60 s, or unread
    assert discover.event_time("2026-11-12 20:42:11.296", "2026-11-12T20:43:11.297Z")[1:] == ("logged", 60)
    assert discover.event_time(None, "2026-11-12T20:43:11.297Z") == (None, None, None)   # no UtcTime: as before
    assert discover.event_time("x", "2026-11-12T20:43:11.297Z") == (None, None, None)


def test_e2_am2_the_notes_words_name_the_kind_and_the_skew_in_days_and_hours():
    assert discover.logged_note(3, SKEW_S) == NOTE3
    assert discover.logged_note("22", -3700) == ("Sysmon's event 22 carries a time 1 hour ahead of the time it was"
                                                 " logged (-3700 s): the logged time is used")
    assert discover.skew_words(86400 + 61) == "1 day behind" and discover.skew_words(61) == "1 minute behind"


# --- AM-1: through the follow -----------------------------------------------------------------------------------------

FIELD_ORDER = [("process", "2026-11-10T07:54:00.000Z"), ("net", "2026-11-10T07:54:01.297Z"),
               ("process", "2026-11-10T07:54:02.000Z"), ("file", "2026-11-10T07:54:03.000Z"),
               ("net", "2026-11-10T07:54:04.500Z")]


def test_e1_am1_through_the_follow_the_net_lines_are_live_in_order_with_the_process_lines(tmp_path, monkeypatch):
    lines, silences, _, _ = follow_through(FollowChannel([shape()]), 1, log=tmp_path / "os.jsonl", since=START)
    assert pres(lines) == FIELD_ORDER and not silences
    assert all(discover._ts(x["ts"]) >= START for x in lines)   # none before the watch's start: none history
    for x in lines:
        if x.get("tool") == "net":
            assert {k: x["input_meta"][k] for k in ("time_from", "time_skew_s")} == {"time_from": "logged",
                                                                                     "time_skew_s": SKEW_S}
        else:
            assert "time_from" not in json.dumps(x) and "time_skew_s" not in json.dumps(x)
    old_times(monkeypatch)   # before AM-1: the talks were weeks before the watch's start: the follow wrote no line
    before, _, _, _ = follow_through(FollowChannel([shape()]), 1, log=tmp_path / "old.jsonl", since=START)
    assert pres(before) == [x for x in FIELD_ORDER if x[0] != "net"]


def build_lines(text, root=9176):
    return os_sysmon.build(text, root, cwd="C:\\work")[0]


def test_e1_am1_not_touched_two_times_that_agree_or_no_timecreated_give_the_lines_byte_for_byte(monkeypatch):
    agree = build_lines(channel_xml(*shape("agree")))
    assert agree == build_lines(channel_xml(*shape("near"))) == build_lines(channel_xml(*shape("none")))
    assert "time_from" not in "".join(agree) and len(agree) == 12
    xml = [p for p in (ROOT / "tests" / "fixtures").rglob("*.xml") if "Microsoft-Windows-Sysmon" in
           p.read_text(encoding="utf-8", errors="replace")]
    assert len(xml) >= 10
    now = [discover.parse_sysmon(p.read_text(encoding="utf-8", errors="replace"), "sysmon", keyed=True) for p in xml]
    assert not [r for recs, _ in now for r in recs if "time_from" in r]
    old_times(monkeypatch)   # the times before AM-1: the same lines and records, to the byte
    assert build_lines(channel_xml(*shape("agree"))) == agree
    assert [discover.parse_sysmon(p.read_text(encoding="utf-8", errors="replace"), "sysmon", keyed=True)
            for p in xml] == now


def test_e1_am1_not_touched_event_1_matches_a_sampled_creation_date_as_before():
    born = created(500, "2026-11-10 07:50:00.412", 5888, PS, G_SHELL, 5100, EXPLORER, guid_of(5100), "powershell",
                   logged="2026-11-10 07:50:40.000")   # logged 40 s later: within SKEW, UtcTime is its time
    (rec, _parent), _ = discover.parse_sysmon(channel_xml(born), "sysmon", keyed=True)
    assert rec["ts"] == discover._ts("2026-11-10 07:50:00.412") and "time_from" not in rec
    assert discover._start_close(rec["ts"], discover._ts("2026-11-10T07:50:00.000Z"))


# --- AM-1, AM-2: through the rounds and the report ------------------------------------------------------------------

BRIEF_G, BRIEF_CURL_G = guid_of(9500), guid_of(9510)


def brief(lag=True):
    """A brief tree known only from the channel (round 2): kimi starts, talks, runs curl, which talks; its talks
    stamped LAG behind the time they were logged (lag), or not."""
    def talk(rec, clock, pid, image, guid, port, dest):
        logged = logged_at(clock + "0000")
        return talked(rec, behind(logged) if lag else logged[:23], pid, image, guid, port=port, dest=dest,
                      logged=logged)
    return [created(700, at("07:55:00"), 9500, KIMI, BRIEF_G, 5888, EXPLORER, G_SHELL, "kimi"),
            talk(701, "07:55:01.000", 9500, KIMI, BRIEF_G, 50400, "203.0.113.60"),
            created(702, at("07:55:02"), 9510, CURL, BRIEF_CURL_G, 9500, KIMI, BRIEF_G, "curl -s https://198.51.100.30/w"),
            talk(703, "07:55:03.000", 9510, CURL, BRIEF_CURL_G, 50410, "198.51.100.30")]


def brief_watch(tmp_path, monkeypatch, lag=True):
    settled_follows(monkeypatch)
    return watch(tmp_path, monkeypatch, rounds(tmp_path, 3), channel=Rounds(xml={2: brief(lag)}),
                 follow=Script(fail_from=1), wall0=WALL0 + 240)


def test_e1_e2_am1_am2_through_the_rounds_a_trees_talk_is_in_its_round_its_window_and_one_note(tmp_path, monkeypatch):
    w, said, seen = brief_watch(tmp_path / "now", monkeypatch)
    window = "window 2026-11-10T07:55:00.000Z .. 2026-11-10T07:55:03.000Z"
    assert seen[1]["sample"].startswith(window)   # the round's window is the round's: its talks at their logged time
    assert "2026-10-" not in w.final_text and "2026-10-" not in said   # no window or line starts weeks back
    (tree,) = [k for k in w.trees if k[0] == 9500]
    assert w.trees[tree].get("first_round", 2) == 2
    # AM-2: one note, in the notes and the report, naming the kind and the skew; not a hole, not a knock
    assert [x for x in w.notes if "carries a time" in x] == [NOTE3]
    assert [x for x in report(w) if "carries a time" in x] == ["  - " + NOTE3]
    assert "carries a time" not in json.dumps(w.holes) + json.dumps(w.knocks, default=str)
    agree, said_agree, seen_agree = brief_watch(tmp_path / "agree", monkeypatch, lag=False)   # not touched: no note
    assert not [x for x in agree.notes if "carries a time" in x] and seen_agree[1]["sample"].startswith(window)
    assert agree.result() == w.result() and len(agree.knocks) == len(w.knocks) and len(agree.holes) == len(w.holes)
    old_times(monkeypatch)   # before AM-1: the round's window started weeks back
    old, _, seen_old = brief_watch(tmp_path / "old", monkeypatch)
    assert seen_old[1]["sample"].startswith("window 2026-10-15T00:13:27.617Z .. 2026-11-10T07:55:02.000Z")


EXPLORER_G = "{8d1c0a51-0000-6732-0000-0000000013ec}"   # explorer 5100's ProcessGuid in that export


def test_e2_am2_a_watch_whose_only_word_is_the_note_ends_clean_exit_0(tmp_path):
    from test_acts_judged import CountingFollow, after_start, built, person_and_agent_export, watch_rounds
    text = person_and_agent_export()
    ends = {}
    logged = "2026-11-03 09:00:00.9000000"   # explorer's own talk, logged among the export's events
    talk = {"lag": talked(77100, behind(logged), 5100, EXPLORER, EXPLORER_G, port=50600, dest="203.0.113.90",
                          logged=logged),
            "agree": talked(77100, logged[:23], 5100, EXPLORER, EXPLORER_G, port=50600, dest="203.0.113.90")}
    for name, export in (("lag", stamp_behind(text + talk["lag"])), ("agree", text + talk["agree"])):
        follow = CountingFollow(by_root={5100: after_start(built(export, 5100))})
        w = watch_rounds(tmp_path / name, ["benign-person/before", "benign-person/before"], follow=follow)
        final, code = w.finish()
        ends[name] = (code, [x for x in final.splitlines() if x.startswith("RESULT:")], w.knocks,
                      [x for x in w.notes if "carries a time" in x])
    assert ends["lag"][0] == 0 and ends["lag"][1] == ["RESULT: CLEAN (exit 0: trees listed, nothing new)"]
    assert ends["lag"][2] == [] and len(ends["lag"][3]) == 1 and ends["lag"][3][0].startswith(
        "Sysmon's event 3 carries a time 26 days 7 hours behind the time it was logged (")
    assert ends["agree"][:3] == ends["lag"][:3] and ends["agree"][3] == []   # not touched: no skew, no note


# --- AM-3: one note per tree, file and rule ---------------------------------------------------------------------------

CMD = "C:\\Windows\\System32\\cmd.exe"
PASSES = [[created(900 + i, at("07:5%d:10" % (4 + 2 * i)), 9700 + i, CMD, guid_of(9700 + i), 9176, KIMI, G_KIMI,
                   "cmd /c dir")] for i in range(3)]


class Paced:
    """A tree's os follow (the real os_sysmon.follow over a FollowChannel) whose k-th pass is let go by the k-th
    round after its attach, before that round's host lines; the round waits for it (no clock)."""

    def __init__(self, passes):
        self.channel = FollowChannel(passes)
        self.n = len(passes)
        self.allowed, self.done = 0, [threading.Event() for _ in passes]

    def __call__(self, root, log, stop, **kw):
        on_pass = kw.pop("on_pass")

        def passed(n, top):
            on_pass(n, top)
            if n <= self.n:
                self.done[n - 1].set()

        def reader(args, timeout):
            k = len(self.channel.args) + 1
            while k > self.allowed and not stop.is_set():
                stop.wait(0.01)
            return self.channel(args, timeout)
        kw["every"] = 0.0
        return os_sysmon.follow(root, log, stop, on_pass=passed, reader=reader, nt=True, **kw)

    def release(self):
        if self.allowed < self.n:
            self.allowed += 1
            assert self.done[self.allowed - 1].wait(10)


def unjudged(w, rule):
    return [x for x in w.notes if (": rule %s partial: could not judge" % rule) in x]


def test_e3_am3_one_note_per_tree_file_and_rule_the_latest_count_through_a_follow_of_three_passes(tmp_path,
                                                                                               monkeypatch):
    paced, seen = Paced(PASSES), []
    real = host.HostWatch._host_lines

    def _host_lines(self, now, n, *rest):
        seen.append({r: unjudged(self, r) for r in ("SCOPE-CWD-ROOT", "SCOPE-CWD-MOVED")})
        if any(s.thread is not None and s.thread.is_alive() for s in self.sources.values()):
            paced.release()
            for s in self.sources.values():
                while s.thread is not None and s.thread.is_alive() and not s.first_pass.is_set():
                    s.first_pass.wait(0.01)
        return real(self, now, n, *rest)
    monkeypatch.setattr(host.HostWatch, "_host_lines", _host_lines)
    w, _, _ = watch(tmp_path, monkeypatch, rounds(tmp_path, 5), channel=Rounds(), follow=paced, wall0=WALL0 + 240)
    assert paced.allowed == 3 and len(paced.channel.args) >= 3   # three passes, each judged in its round
    counts = {}
    for rule in ("SCOPE-CWD-ROOT", "SCOPE-CWD-MOVED"):
        said = [x[rule] for x in seen if x[rule]] + [unjudged(w, rule)]
        assert all(len(x) == 1 for x in said), said   # one note per pass's judging, never one more
        counts[rule] = [int(re.search(r"could not judge ([0-9]+) line", x[0]).group(1)) for x in said]
        assert counts[rule] == sorted(counts[rule]) and counts[rule][0] < counts[rule][-1], counts
    (key,) = w.trees
    feed = w.sources[key].feeds[0]
    notes = {n["rule_id"]: n for n in feed.judge()[1] if n.get("status") == "partial"}
    for rule in counts:   # the latest count: the engine's own note of the whole file, word for word
        assert unjudged(w, rule) == ["tree %s, %s: rule %s partial: %s" % (host.tree_word(key), feed.path, rule,
                                                                         notes[rule]["detail"])]
    assert unjudged(w, "SCOPE-CWD-ROOT") != unjudged(w, "SCOPE-CWD-MOVED")   # two rules: two notes


class Feed:
    def __init__(self, path, notes):
        self.path, self.notes, self.numbered, self.rules, self.epoch = path, notes, [], [], 0
        self.not_judged = {"lines": len(notes)}

    def judge(self):
        return [], [{"rule_id": r, "status": "partial", "detail": "could not judge %d line(s) (session:seq x:1)" % n}
                    for r, n in self.notes], {}


class Src:
    kind, not_run_said, pre_m78_said = "hooks", False, False


def test_e3_am3_not_touched_two_rules_or_two_files_are_two_notes_and_the_state_keeps_its_count(tmp_path,
                                                                                            monkeypatch):
    w, _, _ = watch(tmp_path, monkeypatch, rounds(tmp_path, 1), channel=Rounds(), wall0=WALL0 + 240)
    key, src, before = (9176, "kimi", "2026-11-10T07:51:00.000Z"), Src(), len(w.notes)
    for path, notes in (("a.jsonl", [("R-1", 3)]), ("a.jsonl", [("R-1", 5), ("R-2", 1)]), ("b.jsonl", [("R-1", 2)]),
                        ("a.jsonl", [("R-1", 7)])):
        w._judge_feed(0.0, key, src, Feed(path, notes), False)
    word = host.tree_word(key)
    assert w.notes[before:] == ["tree %s, a.jsonl: rule R-1 partial: could not judge 7 line(s) (session:seq x:1)"
                                % word,
                                "tree %s, a.jsonl: rule R-2 partial: could not judge 1 line(s) (session:seq x:1)"
                                % word,
                                "tree %s, b.jsonl: rule R-1 partial: could not judge 2 line(s) (session:seq x:1)"
                                % word]
    assert w.source_not_judged["a.jsonl"] == {"lines": 1} and w.source_not_judged["b.jsonl"] == {"lines": 1}


# --- AM-4: RHYTHM BEATS, before AM-1's times and after ----------------------------------------------------------------

def beats(tmp_path, monkeypatch, n):
    """kimi (round 1), its curl talking in round 2 (its tree attached, os); the follow's first pass reads the field's
    shape (two shells' starts and a file at the watch's minute, their talks stamped LAG behind); n rounds."""
    settled_follows(monkeypatch)
    w, _, _ = watch(tmp_path, monkeypatch, rounds(tmp_path, n), channel=Rounds(), follow=Script(passes=[shape()]),
                    wall0=WALL0 + 240)
    (line,) = [x for x in report(w) if x.startswith("RHYTHM BEATS:")]
    return re.search(r"beats after the last round: ([0-9]+)", line).group(1), line


def test_e4_am4_rhythm_beats_of_the_made_up_export_before_and_after(tmp_path, monkeypatch):
    """What RHYTHM BEATS says, stated (AM-4). A follow whose lines are read in the last round: "beats after the
    last round" is 2 before AM-1 (the two shells' starts; their talks were before the watch's start, history, no
    line) and 4 after (the starts and the two talks, live). The same export read with two rounds after it: 0 before
    and after. The times decide only whether the talks are beats; that the beats are after the last round is decided
    by the round that read them (a source's beats are counted one round late): not by the times, so nothing there
    is changed and it is returned as a question."""
    after = beats(tmp_path / "after-last", monkeypatch, 2), beats(tmp_path / "after-more", monkeypatch, 4)
    old_times(monkeypatch)
    before = beats(tmp_path / "before-last", monkeypatch, 2), beats(tmp_path / "before-more", monkeypatch, 4)
    assert [b[0] for b in before] == ["2", "0"] and [a[0] for a in after] == ["4", "0"]
    assert after[0][1].startswith("RHYTHM BEATS: beats after the last round: 4 (source beats read by the final poll,"
                                  " in no round: not judged by HOST-RHYTHM); 9176:kimi:2026-11-10T07:51:00.000Z: 4;")


# --- E5: the threat model says it; ASCII; no test here reads the review folder ----------------------------------

def test_e5_the_threat_model_says_which_time_raqib_uses_and_that_the_lag_is_a_note():
    text = " ".join((ROOT / "docs" / "THREAT_MODEL.md").read_text(encoding="utf-8").split())
    for words in ("stamps its events behind the time they were logged", "System/TimeCreated",
                  "more than 60 s", "input_meta.time_from", "lag itself is a note",
                  "not a hole and not a knock"):
        assert words in text, words
    assert "M7.16" not in text


def test_e5_the_code_and_tests_are_ascii_and_no_test_here_reads_docs_review():
    for rel in ("raqib/discover.py", "raqib/host.py", "raqib/hooks/os_sysmon.py", "tests/test_event_logged_time.py",
                "tests/test_round_channel.py"):
        (ROOT / rel).read_bytes().decode("ascii")
    code = (ROOT / "tests" / "test_event_logged_time.py").read_text(encoding="ascii")
    assert ("docs" + "/review") not in code and ("docs" + '" / "review') not in code
    addresses = set(re.findall(r"\b[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b", code))
    assert addresses and all(a.startswith(("192.0.2.", "198.51.100.", "203.0.113.")) for a in addresses)
