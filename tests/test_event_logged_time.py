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
import hashlib
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
from test_host_follow_returns import CURL_BORN, CURL_TALK, KIMI_WORD, Follow, against_without  # noqa: E402

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
    # AN-1: no UtcTime read and a logged time read: timed from the log, no skew (before AN-1: dropped)
    assert discover.event_time(None, "2026-11-12T20:43:11.297Z") == (logged.replace(microsecond=297000), "logged",
                                                                      None)
    assert discover.event_time("x", "2026-11-12T20:43:11.297Z")[1:] == ("logged", None)
    assert discover.event_time("x", "not a time") == discover.event_time(None, None) == (None, None, None)


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
    old_times(monkeypatch)   # UtcTime alone (before AM-1): the talks weeks before the watch's start
    before, _, _, _ = follow_through(FollowChannel([shape()]), 1, log=tmp_path / "old.jsonl", since=START)
    assert [x for x in pres(before) if x[0] != "net"] == [x for x in FIELD_ORDER if x[0] != "net"]
    # AN-2: sorted before their process's event 1 they are still the tree's: at their UtcTime, weeks back (history)
    olds = [x for x in pres(before) if x[0] == "net"]
    assert len(olds) == 2 and all(discover._ts(t) < START for _, t in olds)


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
    assert w.trees[tree]["first_round"] == 2   # W-6: the key itself, never a default
    # AM-2: one note, in the notes and the report, naming the kind and the skew; not a hole, not a knock; AN-6: and
    # the record its skew was measured on (the round's first event 3 timed from the log)
    assert [x for x in w.notes if "carries a time" in x] == [NOTE3 + " (measured on record 701)"]
    assert [x for x in report(w) if "carries a time" in x] == ["  - " + NOTE3 + " (measured on record 701)"]
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


# --- M7.16 REDO (ADR-0007 Amendment AN) ----------------------------------------------------------------------------

UNREAD3 = ("Sysmon's event 3 carries a TimeCreated that is not read: the time it was logged is not read, and its"
           " UtcTime is used unchecked")


def unread_logged(part, eid=3):
    """One event of the export with its TimeCreated there and in a form that does not parse (a converter's)."""
    if "<EventID>%d</EventID>" % eid not in part:
        return part
    return re.sub(r"SystemTime='[^']*'", "SystemTime='11/10/2026 7:54:01 AM'", part)


def test_e1_an1_through_the_follow_an_unread_timecreated_is_one_silence_line_per_kind_utctime_unchecked(tmp_path):
    parts = [unread_logged(p) for p in shape("agree")]
    assert sum("7:54:01 AM" in p for p in parts) == 2   # both talks, one in each pass
    lines, silences, _, _ = follow_through(FollowChannel([parts[:2], parts[2:]]), 2, log=tmp_path / "os.jsonl")
    said = [x for x in silences if "TimeCreated" in x or "UtcTime that" in x]
    assert len(said) == 1 and UNREAD3 in said[0]   # once for the kind, across the passes
    assert pres(lines) == FIELD_ORDER   # the talks at their UtcTime (unchecked), the other lines as they were
    assert "time_from" not in "".join(json.dumps(x) for x in lines)
    assert discover.UTC_UNREAD % 3 not in "".join(silences)


def test_e1_an1_through_discover_a_time_there_and_unread_is_a_problem_once_per_kind_a_utctime_unread_is_logged():
    parts = [unread_logged(p) for p in shape("agree")]
    records, problems = discover.parse_sysmon(channel_xml(*parts), "sysmon", keyed=True)
    assert [x["reason"] for x in problems] == [UNREAD3]
    assert not [r for r in records if "time_from" in r]
    talk = talked(990, "", 9600, BASH, G_BASH, logged="2026-11-10 07:54:09.250")   # no UtcTime read, logged read
    records, problems = discover.parse_sysmon(channel_xml(talk, talk.replace("990", "991")), "sysmon", keyed=True)
    assert [x["reason"] for x in problems] == [discover.UTC_UNREAD % 3]
    nets = [r for r in records if r["kind"] == "conn"]
    assert nets and all(r["ts"] == discover._ts("2026-11-10 07:54:09.250") and r["time_from"] == "logged"
                        and "time_skew_s" not in r and "time_record" not in r for r in nets)


def test_e1_an1_not_touched_no_timecreated_at_all_is_no_word_and_the_same_lines():
    none = channel_xml(*shape("none"))
    assert "TimeCreated" not in none
    lines, silences = os_sysmon.build(none, 9176, cwd="C:\\work")
    assert silences == [] and lines == build_lines(channel_xml(*shape("agree")))
    assert discover.parse_sysmon(none, "sysmon", keyed=True)[1] == []
    assert not discover.logged_unread(None) and discover.logged_unread("") and discover.logged_unread("11/10/2026")


def test_e1_an1_through_a_round_an_unread_timecreated_is_a_problem_of_the_rounds_record_in_the_report(tmp_path,
                                                                                                    monkeypatch):
    settled_follows(monkeypatch)
    ends = {}
    for name, xml in (("unread", [unread_logged(p) for p in brief(lag=False)]), ("read", brief(lag=False))):
        w, _, _ = watch(tmp_path / name, monkeypatch, rounds(tmp_path / name, 3), channel=Rounds(xml={2: xml}),
                        follow=Script(fail_from=1), wall0=WALL0 + 240)
        ends[name] = w
    assert UNREAD3 in ends["unread"].final_text and UNREAD3 in json.dumps(ends["unread"].holes)
    assert UNREAD3 not in ends["read"].final_text and "TimeCreated" not in json.dumps(ends["read"].holes)


G_C, G_GC, G_GGC = guid_of(9630), guid_of(9631), guid_of(9632)


def test_e2_an2_r2_an_act_sorted_before_its_process_start_is_the_trees_through_the_follow(tmp_path):
    # the packet's case: the child's event 1 logged 61.1 s late (the logged time), its event 3 59 s late (UtcTime)
    born = created(810, at("07:54:02"), 9620, PS, G_PS, 9176, KIMI, G_KIMI, "powershell -c x",
                   logged="2026-11-10 07:55:03.100")
    talk = talked(811, at("07:54:05"), 9620, PS, G_PS, port=50410, dest="203.0.113.41", logged="2026-11-10 07:55:04.000")
    lines, silences, _, _ = follow_through(FollowChannel([[born, talk]]), 1, log=tmp_path / "os.jsonl", since=START)
    assert pres(lines) == [("net", "2026-11-10T07:54:05.000Z"), ("process", "2026-11-10T07:55:03.100Z")]
    assert not silences
    net, proc = [x for x in lines if x.get("phase") == "pre"]
    assert "time_from" not in net["input_meta"]
    assert {k: proc["input_meta"].get(k) for k in ("time_from", "time_skew_s", "time_record", "depth")} == {
        "time_from": "logged", "time_skew_s": 61, "time_record": 810, "depth": 1}


def test_e2_an2_a_grandchilds_subtree_sorted_before_its_parents_start_is_the_trees_through_the_follow(tmp_path):
    parts = [created(820, at("07:54:02"), 9630, CMD, G_C, 9176, KIMI, G_KIMI, "cmd /c x",
                     logged="2026-11-10 07:55:03.100"),   # 61.1 s: its logged time, after its subtree's
             created(821, at("07:54:08"), 9631, PS, G_GC, 9630, CMD, G_C, "powershell", logged="2026-11-10 07:55:03.200"),
             talked(822, at("07:54:09"), 9631, PS, G_GC, port=50420, logged="2026-11-10 07:55:03.300"),
             created(823, at("07:54:10"), 9632, CURL, G_GGC, 9631, PS, G_GC, "curl", logged="2026-11-10 07:55:03.400"),
             event(11, 824, at("07:54:11"), 9632, CURL, G_GGC, logged="2026-11-10 07:55:03.500",
                   TargetFilename="C:\\Users\\user\\out.txt")]
    lines, silences, _, _ = follow_through(FollowChannel([parts]), 1, log=tmp_path / "os.jsonl", since=START)
    pre = [x for x in lines if x.get("phase") == "pre"]
    assert [(x["tool"], x["ts"][11:23], x["input_meta"].get("depth")) for x in pre] == [
        ("process", "07:54:08.000", 2), ("net", "07:54:09.000", None), ("process", "07:54:10.000", 3),
        ("file", "07:54:11.000", None), ("process", "07:55:03.100", 1)]   # lines in time order
    assert "parent_seq" not in pre[0]["input_meta"] and pre[2]["input_meta"]["parent_seq"] == pre[0]["seq"]
    assert "parent_seq" not in pre[4]["input_meta"] and not silences   # its parent (kimi) has no line in the window


def no_guids(text):
    return re.sub(r"<Data Name='(Parent)?ProcessGuid'>[^<]*</Data>", "", text)


def test_e2_an2_membership_is_a_fixed_point_whatever_order_the_times_give_and_pid_only_events_are_as_before():
    # a chain whose times run against it (no TimeCreated: UtcTime alone): two rounds of trying again
    text = channel_xml(created(830, at("07:54:20"), 9630, CMD, G_C, 9176, KIMI, G_KIMI, "cmd", logged=""),
                       created(831, at("07:54:15"), 9631, PS, G_GC, 9630, CMD, G_C, "powershell", logged=""),
                       created(832, at("07:54:10"), 9632, CURL, G_GGC, 9631, PS, G_GC, "curl", logged=""),
                       talked(833, at("07:54:11"), 9632, CURL, G_GGC, port=50430, logged=""))
    lines, _ = os_sysmon.build(text, 9176)
    assert [(x["tool"], x["ts"][11:19], x["input_meta"].get("depth")) for x in pres_of(lines)] == [
        ("process", "07:54:10", 3), ("net", "07:54:11", None), ("process", "07:54:15", 2), ("process", "07:54:20", 1)]
    # MUST NOT TOUCH: an event known by its pid alone is placed in the one walk: before its process joined, not
    pids = channel_xml(talked(840, at("07:54:05"), 9640, CURL, "x", port=50440, logged=""),
                       created(841, at("07:54:06"), 9640, CURL, "x", 9176, KIMI, "x", "curl", logged=""),
                       talked(842, at("07:54:07"), 9640, CURL, "x", port=50441, logged=""))
    lines, _ = os_sysmon.build(no_guids(pids), 9176)
    assert [(x["tool"], x["ts"][11:19]) for x in pres_of(lines)] == [("process", "07:54:06"), ("net", "07:54:07")]


def pres_of(lines):
    return [x for x in map(json.loads, lines) if x.get("phase") == "pre"]


def every_fixture_build():
    """os_sysmon.build of every Sysmon fixture for every pid it names, whole and as a follow's pass (tree)."""
    out = []
    for p in sorted((ROOT / "tests" / "fixtures").rglob("*.xml"), key=lambda p: p.relative_to(ROOT).as_posix()):
        text = p.read_text(encoding="utf-8", errors="replace")
        for pid in sorted({int(x) for x in re.findall(r"Name=['\"](?:Parent)?ProcessId['\"]>\s*(\d+)", text)}):
            for tree in (None, {}):
                lines, silences = os_sysmon.build(text, pid, tree=tree, info={} if tree is not None else None)
                out += ["== %s %d %s" % (p.relative_to(ROOT).as_posix(), pid, tree is not None)] + lines + silences
    return hashlib.sha256("\n".join(out).encode("utf-8")).hexdigest(), len(out)


FIXTURES_BUILT = ("c3d84456c2d1d899b64eb9bc20fa72e300f5b5bafcd274acc27b12468a94dca2", 2179)   # the parent commit's code (b713bd2) gave these, to the byte


def test_e2_an2_not_touched_every_fixture_gives_the_lines_it_gave_to_the_byte():
    assert every_fixture_build() == FIXTURES_BUILT


def test_e5_an3_an_event_1_logged_more_than_60_s_late_is_two_processes_said_never_one_unsaid():
    sampled = {"src": "win-process", "kind": "proc", "pid": 5888, "image": discover.image_name(PS),
               "started": "2026-11-10T07:50:00.000Z", "cites": []}
    holes = {}
    for name, logged in (("late", "2026-11-10 07:51:01.000"), ("near", "2026-11-10 07:50:40.000")):
        born = created(500, "2026-11-10 07:50:00.412", 5888, PS, G_SHELL, 5100, EXPLORER, guid_of(5100), "powershell",
                       logged=logged)
        records, _ = discover.parse_sysmon(channel_xml(born), "sysmon", keyed=True)
        holes[name] = discover._guid_instances(records + [dict(sampled)])[1]
    # 60.588 s late: its start is the logged time, it does not match the sampled CreationDate: two processes, said
    assert len(holes["late"]) == 1 and "pid 5888 held 1 process(es)" in holes["late"][0]
    assert "1 beside the sampled one" in holes["late"][0]
    assert holes["near"] == []   # within 60 s: UtcTime, one process, as before


def test_e4_an5_the_alarms_line_counts_what_the_listing_lists_and_says_the_findings_behind_a_joined_pair(
        tmp_path, monkeypatch):
    follow = Follow(unread=0, then=[CURL_BORN, CURL_TALK], go=True)
    w, _, without, _ = against_without(tmp_path, monkeypatch, "both", rounds(tmp_path, 3), follow,
                                       rounds(tmp_path / "w", 3))
    live = w.source_alarms()
    assert sorted(f["source"] for f in live if f["tree"] == KIMI_WORD) == ["host", "host", "os"]
    lines = report(w)
    alarms = next(x for x in lines if x.startswith("ALARMS: "))
    head = next(x for x in lines if x.startswith("SOURCE FINDINGS: "))
    listed = int(re.search(r"\(([0-9]+) live", head).group(1))
    assert ("%d source finding(s) listed (%d findings: a pair taken for the same act is listed once): NET-TOOL on pid"
            " 9176" % (listed, len(live))) in alarms and listed == len(live) - 1
    result = [x for x in lines if x.startswith("RESULT: ")]
    monkeypatch.setattr(host, "told_twice", lambda findings, sources: {})   # the same watch, no pair joined
    text, code = w.summary()
    assert [x for x in text.splitlines() if x.startswith("RESULT: ")] == result and code == w.final_exit == 1
    assert "%d source finding(s): NET-TOOL on pid 9176" % len(live) in text and " listed (" not in text
    # MUST NOT TOUCH: a watch whose sources joined no pair says its count as before
    before = next(x for x in report(without) if x.startswith("ALARMS: "))
    assert "source finding(s): NET-TOOL on pid 9176" in before and " listed (" not in before
