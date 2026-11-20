"""M14.1c (ADR-0007 Amendment BY, BY-1 to BY-7): the round takes the reader's processes. On Linux a child that
begins and ends between two samples becomes its tree's child, so the rules that read a child's name judge it.

Every test here is offline: discover reads the fixture tests/fixtures/procevents-round/linux (a talking agent at the
sample; the reader's curl, bash and shred, a pid the sample holds as another process, a program not read), and the
watch gets a stand-in sample and a stand-in helper (tests/test_host_procevents.py's)."""
import datetime
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from raqib import discover, host, own, procevents  # noqa: E402

sys.path.insert(0, str(ROOT / "tests"))
from test_host_procevents import (CATALOG, StandIn, answer, factory, files, pe, run,  # noqa: E402
                                  watch as make_watch)
from test_procevents_helper import READY  # noqa: E402

FIXTURE = ROOT / "tests" / "fixtures" / "procevents-round" / "linux"
BEFORE = ROOT / "tests" / "fixtures" / "procevents-round" / "before"
LINUX_FIXTURES = {"linux": ROOT / "tests" / "fixtures" / "discover" / "linux",
                  "linux-agent": ROOT / "tests" / "fixtures" / "discover" / "linux-agent",
                  "linux-desktop": ROOT / "tests" / "fixtures" / "discover" / "benign" / "linux-desktop"}


@pytest.fixture(autouse=True)
def _own_record():
    """CA-6: a test that empties or adds to this process's own record (raqib/own.py) puts it back."""
    kept = dict(own.RECORD._kept)
    yield
    with own.RECORD._lock:
        own.RECORD._kept.clear()
        own.RECORD._kept.update(kept)


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    path = tmp_path / "home"
    path.mkdir(exist_ok=True)
    monkeypatch.setenv("HOME", str(path))
    monkeypatch.setenv("USERPROFILE", str(path))
    return path


def line(pid, ppid=1600, exe="/usr/bin/curl", ticks=2200, began="2026-11-20T10:00:01.100000Z",
         ended="2026-11-20T10:00:01.400000Z", code=0):
    return json.dumps({"pid": pid, "ppid": ppid, "exe": exe, "ticks": ticks, "began": began, "ended": ended,
                       "code": code}, sort_keys=True) + "\n"


def texts_of(directory=FIXTURE, reader=True):
    texts, holes = discover.read_dir(str(directory))
    if not reader:
        texts.pop(discover.READER, None)
    return texts, holes


def build(texts, holes=(), live=True):
    return discover.run(texts, CATALOG, holes=list(holes), live=live, processes=live)


def tree(inv, pid):
    return next(t for t in inv["candidates"] + inv["act_roots"] if t["pid"] == pid)


def acts(inv, pid):
    return {(a["pid"], a["image"]): a for a in tree(inv, pid)["acts"] if a["how"] == "process"}


# --- E1 (BY-1): the reader's text, and discover's parser of it ----------------------------------------------------
def test_e1_each_field_of_a_line_is_a_process_record_as_parse_proc_makes_one():
    (r,), problems = discover.parse_procevents(line(1801))
    assert problems == [] and r["kind"] == "proc" and r["src"] == "procevents" and r["line"] == 1
    assert (r["pid"], r["ppid"], r["image"], r["exe"], r["exe_from"], r["argv"]) == (
        1801, 1600, "curl", "/usr/bin/curl", "record", [])
    assert r["started"] == "boot+2200" and r["created"] is True and r["unread"] == []
    assert r["ts"] == datetime.datetime(2026, 11, 20, 10, 0, 1, 100000, tzinfo=datetime.timezone.utc)
    assert (r["began"], r["ended"], r["code"]) == ("2026-11-20T10:00:01.100000Z", "2026-11-20T10:00:01.400000Z", 0)
    assert discover.PARSERS[discover.READER] is discover.parse_procevents and discover.READER in discover.SOURCES
    assert discover.READER not in discover.PROCESS_SOURCES   # a source beside the sample, never the list of it


def test_e1_an_unread_exe_has_no_image_and_no_ticks_has_no_start_key():
    (r,), problems = discover.parse_procevents(line(1804, exe=None, ticks=None, ended=None, code=None))
    assert problems == [] and r["image"] is None and r["exe"] is None and r["exe_from"] is None
    assert "started" not in r and r["unread"] == [] and r["ended"] is None   # no "exe" hole: counted in the section
    (d,), _ = discover.parse_procevents(line(9, exe="/usr/bin/python3.12 (deleted)"))
    assert d["image"] == "python3.12 (deleted)"   # what plain_program refuses is the existing hole


@pytest.mark.parametrize("bad", [
    "not json", "[1, 2]", "7", json.dumps({"pid": 5}), line(5).replace('"code"', '"argv": [], "code"'),
    line("5"), line(0), line(True), line(5, ppid="1"), line(5, ppid=-1), line(5, exe=7), line(5, ticks=-1),
    line(5, ticks=True), line(5, ticks=1 << 63), line(5, began=None), line(5, began="yesterday"),
    line(5, ended="later"), line(5, code="0"), line(5, code=1 << 40)])
def test_e1_a_line_that_is_not_such_a_line_is_a_problem_of_the_round_never_an_exception(bad):
    records, problems = discover.parse_procevents(bad + "\n" + line(6))
    assert [r["pid"] for r in records] == [6] and len(problems) == 1 and problems[0]["line"] == 1
    inv = build({"procevents": ("x", bad + "\n", None)})
    assert inv["problems"] and inv["result"] == "alarm"   # a line not read is a problem of the round (A3), as any


def test_e1_five_thousand_lines_are_read_whole_and_fast():
    text = "".join(line(10000 + n, ticks=5000 + n) for n in range(5000))
    t0 = time.monotonic()
    records, problems = discover.parse_procevents(text)
    assert len(records) == 5000 and not problems and time.monotonic() - t0 < 5


def given_of(pid, ppid, exe, ticks, began, ended, code, name=None):
    """A process as the watch keeps it of an answer (M14.1d, CC-1: its programs, each with the kernel's name)."""
    return {"pid": pid, "ppid": ppid, "programs": [{"exe": exe, "name": name}], "dropped": 0, "ticks": ticks,
            "began": began, "ended": ended, "code": code}


def test_e1_the_watch_writes_one_line_per_process_with_those_keys_alone_and_leaves_its_own_out():
    given = [given_of(41, 1600, "/usr/bin/curl", 3, "2026-11-20T10:00:01.000000Z", None, None),
             given_of(42, 77, "/usr/sbin/ss", 4, "2026-11-20T10:00:01.000000Z", "2026-11-20T10:00:01.010000Z", 0)]
    at = datetime.datetime(2026, 11, 20, 10, 0, 1, tzinfo=datetime.timezone.utc).timestamp()
    text = host.reader_text(given, {42: (at, "ss")}, self_pid=77)
    assert [json.loads(x)["pid"] for x in text.splitlines()] == [41]   # BY-6: the watch's own ss is not given
    assert set(json.loads(text.splitlines()[0])) == set(discover.READER_KEYS)
    for mine, self_pid in (({42: (at, "curl")}, 77), ({42: (at, "ss")}, 78), ({42: (at - 3600, "ss")}, 77), ({}, 77)):
        assert '"pid": 42' in host.reader_text(given, mine, self_pid=self_pid)   # another image, parent or time
    assert host.reader_text([], {}) == ""


def test_e1_procevents_keeps_the_records_of_an_answer_for_its_round_and_drops_them_after():
    rec = dict(pid=5, ppid=1600, exe="/usr/bin/curl", earlier=[], started_ticks=9, began="2026-11-20T10:00:01.000000Z",
               ended="2026-11-20T10:00:01.100000Z", code=0, signal=None, unread={})
    events = host.ProcEvents(factory(StandIn([answer([rec, dict(rec, pid=6, began=None)]), answer([])])))
    events.begin()
    assert events.round()["began"] == 1
    assert events.take() == [given_of(5, 1600, "/usr/bin/curl", 9, "2026-11-20T10:00:01.000000Z",
                                      "2026-11-20T10:00:01.100000Z", 0)]   # no fork heard: no process of the round
    assert events.take() == [] and events.round()["began"] == 0 and events.take() == []
    for bad in (dict(rec, ppid="1"), dict(rec, exe=3), dict(rec, started_ticks=-1), dict(rec, code="0")):
        events = host.ProcEvents(factory(StandIn([answer([bad])])))
        events.begin()
        assert events.round()["hole"] == host.PE_NOT_A_LINE and events.take() == []
    many = host.ProcEvents(factory(StandIn([answer([dict(rec, pid=n + 1) for n in range(procevents.SERVE_MAX + 1)])])))
    many.begin()
    assert many.round()["hole"] == host.PE_NOT_A_LINE and many.take() == []   # bounded as the helper's answers are


# --- E2 (BY-2): what the round does with them --------------------------------------------------------------------
def test_e2_a_child_and_a_grandchild_of_a_talking_sampled_process_are_its_trees_acts_with_their_start():
    inv = build(*texts_of())
    got = acts(inv, 1600)
    assert got[(1801, "curl")]["started"] == "boot+2200" and got[(1801, "curl")]["via"] == []
    assert got[(1803, "shred")]["via"] == [1802] and (1802, "bash") in got   # through a parent the reader gave too
    assert [c["src"] for c in got[(1801, "curl")]["cites"]] == ["procevents"]
    assert inv["from_reader"] == {"given": 6, "joined": 6, "unread": 1, "by_fork": 1, "apart": 1}


def test_e2_the_same_pid_and_start_is_one_process_and_another_start_is_another():
    inv = build(*texts_of())
    pids = [a["pid"] for a in tree(inv, 1600)["acts"]]
    assert pids.count(1700) == 2 - 1 and [c["src"] for c in acts(inv, 1600)[(1700, "bash")]["cites"]] == [
        "proc", "procevents"]                                   # the sampled bash and the reader's word of it: one
    assert (1750, "wget") in acts(inv, 1600)                    # the reader's 1750 began at another tick: another
    assert {"pid": 1750, "image": "sleep", "started": "boot+2300"} in inv["processes"]   # the sampled one stays


def test_e2_without_ticks_a_record_joins_a_sampled_process_by_pid_only_where_the_sample_read_no_start_for_it():
    """BZ-5: the sample read 1700's ticks, the reader did not: kept apart, near in time or far; where the sample read
    no start for 1700, the two are one by the pid."""
    texts, holes = texts_of(reader=False)
    near = line(1700, exe=None, ticks=None, began="2026-11-20T09:59:59.900000Z", ended=None, code=None)
    far = line(1700, exe="/usr/bin/nc", ticks=None, began="2026-11-20T10:00:09.000000Z", ended=None, code=None)
    for text in (near, far):
        inv = build(dict(texts, procevents=("x", text, None)), holes)
        assert inv["from_reader"]["by_fork"] == 1 and inv["from_reader"]["apart"] == 1
        assert len([a for a in tree(inv, 1600)["acts"] if a["pid"] == 1700]) == 2
        assert acts(inv, 1600)[(1700, "bash")]["cites"][0]["src"] == "proc"   # no program named on the sampled one
    unread = texts["proc"][1].replace('"start_ticks": 2100, ', "")
    assert unread != texts["proc"][1]
    inv = build(dict(texts, proc=("p", unread, None), procevents=("x", near, None)), holes)
    assert inv["from_reader"]["apart"] == 0 and [a["pid"] for a in tree(inv, 1600)["acts"]].count(1700) == 1


def test_e2_a_child_is_linked_to_the_parent_alive_at_its_fork_where_the_reader_gave_two_of_one_pid():
    texts, holes = texts_of(reader=False)
    text = (line(1900, ticks=2400, exe="/usr/bin/bash", began="2026-11-20T10:00:01.000000Z",
                 ended="2026-11-20T10:00:01.500000Z")
            + line(1900, ppid=1, ticks=2500, exe="/usr/bin/bash", began="2026-11-20T10:00:02.000000Z", ended=None)
            + line(1901, ppid=1900, ticks=2510, exe="/usr/bin/wget", began="2026-11-20T10:00:02.100000Z"))
    inv = build(dict(texts, procevents=("x", text, None)), holes)
    assert (1901, "wget") not in acts(inv, 1600)   # its parent is the second 1900, under pid 1: no tree of the agent
    assert inv["from_reader"]["apart"] == 1


def test_e2_an_end_heard_from_the_reader_never_removes_a_process_the_sample_holds():
    texts, holes = texts_of(reader=False)
    inv = build(dict(texts, procevents=("x", line(1700, exe="/usr/bin/bash", ticks=2100), None)), holes)
    assert {"pid": 1700, "image": "bash", "started": "boot+2100"} in inv["processes"]
    assert (1700, "bash") in acts(inv, 1600)


def test_e2_a_tree_a_candidate_only_by_the_reader_is_as_one_only_by_the_channel_on_windows():
    texts, holes = texts_of(reader=False)
    sample = "".join(x + "\n" for x in texts["proc"][1].splitlines() if '"pid": 1700' not in x)
    inv = build(dict(texts, proc=("p", sample, None), procevents=("x", line(1801), None)), holes)
    t = tree(inv, 1600)
    assert t["candidate_by"] == "channel" and t["bare_class"] is None and "guid" not in t and "brief" not in t
    inv = build(*texts_of())
    assert tree(inv, 1600)["candidate_by"] == "sample" and tree(inv, 1600)["bare_class"] == "candidate"


def _flat_json(inv):
    """The inventory's bytes, its catalog's path and the checkout's own place taken out (the files were made from
    the checkout's root, with relative paths)."""
    text = json.dumps(inv, sort_keys=True, ensure_ascii=True).replace(json.dumps(CATALOG["path"])[1:-1], "CATALOG")
    for folder in LINUX_FIXTURES.values():   # the Table: on Windows a fixture's files are named with its separator
        text = text.replace(json.dumps(str(folder) + os.sep)[1:-1], folder.relative_to(ROOT).as_posix() + "/")
    return text.replace(json.dumps(str(ROOT) + os.sep)[1:-1], "")


@pytest.mark.parametrize("name", sorted(LINUX_FIXTURES))
@pytest.mark.parametrize("live", [False, True])
def test_e2_a_round_with_no_procevents_text_is_byte_for_byte_the_round_it_was(name, live):
    """The inventories of every Linux fixture of tests/, built by the code before this task (44770c1) and kept in
    tests/fixtures/procevents-round/before/, are what this code builds with no reader's text."""
    texts, holes = discover.read_dir(str(LINUX_FIXTURES[name]))
    assert discover.READER not in texts
    got = _flat_json(build(texts, holes, live=live)) + "\n"
    assert got == (BEFORE / ("%s%s.json" % (name, "-live" if live else ""))).read_text(encoding="ascii")


def test_e2_the_reader_fixture_without_its_text_is_the_sample_alone():
    inv = build(*texts_of(reader=False))
    assert "from_reader" not in inv and "candidate_by" not in tree(inv, 1600)
    assert [a["pid"] for a in tree(inv, 1600)["acts"]] == [1700]


# --- E3 (BY-2, BY-4): through the watch, with a stand-in sample and a stand-in helper ------------------------------
def stand_in_sample(monkeypatch, alive=()):
    """discover's live collection: the fixture's sample each round, with the processes of `alive` (pid ->
    (ppid, argv0, ticks)) added from the round given."""
    rounds = []

    def collect_live(catalog, **kw):
        rounds.append(1)
        texts, holes = texts_of(reader=False)
        extra = "".join(json.dumps({"argv": [argv0], "at": "2026-11-20T10:00:00.000Z", "cwd": None, "env_keys": [],
                                    "exe": "/usr/bin/" + argv0, "name": argv0, "pid": pid, "ppid": ppid, "sockets": [],
                                    "unread": [], "start_ticks": ticks}, sort_keys=True) + "\n"
                        for since, (pid, ppid, argv0, ticks) in alive if len(rounds) >= since)
        texts["proc"] = (texts["proc"][0], texts["proc"][1] + extra, None)
        return texts, holes, 1
    monkeypatch.setattr(discover, "collect_live", collect_live)
    monkeypatch.setattr(discover, "read_conn_bytes", lambda paths: ({}, "fake ss", None))
    monkeypatch.setattr(discover, "proc_start_times", lambda pids: ({}, None))


def reader_rec(pid, exe, ticks, ppid=1600, began="2026-11-20T10:00:05.000000Z", ended="2026-11-20T10:00:05.200000Z"):
    return {"pid": pid, "ppid": ppid, "exe": exe, "earlier": [], "started_ticks": ticks, "began": began,
            "ended": ended, "code": 0 if ended else None, "signal": None, "unread": {}}


def host_children(home):
    out = []
    for name, text in files(home).items():
        if "/sources/" not in "/" + name:
            continue
        for x in text.splitlines():
            d = json.loads(x) if x.strip() else {}
            if d.get("tool") == "HostChild":
                out.append((d["input_meta"]["round"], d["input_meta"]["command_programs"],
                            [c["pid"] for c in d["input_meta"]["children"]]))
    return sorted(out)


def test_e3_a_curl_and_a_shred_between_two_samples_are_the_trees_children_once_and_judged(tmp_path, monkeypatch):
    stand_in_sample(monkeypatch, alive=[(3, (1801, 1600, "curl", 2200))])   # the curl still alive at round 3
    make = factory(StandIn([answer([]), answer([reader_rec(1801, "/usr/bin/curl", 2200, ended=None),
                                                reader_rec(1802, "/usr/bin/bash", 2210),
                                                reader_rec(1803, "/usr/bin/shred", 2211, ppid=1802),
                                                reader_rec(1804, None, None)]), answer([])]))
    w, clock = make_watch(tmp_path, host.live_reader(CATALOG, 0.0, "linux", helper=make))
    text, code = run(w, clock, 3)
    got = host_children(tmp_path / "home")
    assert (2, ["curl", "bash", "shred"], [1801, 1802, 1803]) in got
    assert not [g for g in got if 1801 in g[2] and g[0] != 2]    # alive at the next sample: not written twice
    rules = {f["rule_id"] for f in w.source_findings}
    assert {"NET-TOOL", "DESTRUCT-CMD"} <= rules
    assert not [h for h in w.holes if h["kind"] == "host-source-unfit"]   # 1804: no program read, no line, no hole
    assert ("  given to the rounds: 4; joined to a tree as its child: 4; of them with no program read (no line): 1"
            in text)
    assert host.PE_BY_FORK % 1 in text   # BY-1: the one given with no start ticks read is said


def test_e3_a_name_plain_program_refuses_is_the_existing_hole(tmp_path, monkeypatch):
    stand_in_sample(monkeypatch)
    make = factory(StandIn([answer([reader_rec(1805, "/tmp/two words", 2220)])]))
    w, clock = make_watch(tmp_path, host.live_reader(CATALOG, 0.0, "linux", helper=make))
    run(w, clock, 1)
    assert [h for h in w.holes if h["kind"] == "host-source-unfit"]
    assert "two words" not in json.dumps(host_children(tmp_path / "home"))


def test_e3_a_helper_that_gave_nothing_leaves_the_round_as_it_was(monkeypatch):
    stand_in_sample(monkeypatch)
    with_helper = host.live_reader(CATALOG, 0.0, "linux", helper=factory(StandIn([answer([])])))()
    with_helper.pop("procevents")
    monkeypatch.setattr(host.sys, "platform", "win32")   # no helper is made
    plain = host.live_reader(CATALOG, 0.0, "linux")()
    assert json.dumps(with_helper, sort_keys=True) == json.dumps(plain, sort_keys=True)


# --- E4 (BY-5): when the reader is not whole ----------------------------------------------------------------------
def feed_inv(events):
    """A reader of the stand-in fixture's round (no reader's text), carrying one inv["procevents"] per round."""
    queue = list(events)

    def read():
        return dict(build(*texts_of(reader=False)), procevents=queue.pop(0))
    return read


def test_e4_a_refusal_at_the_first_start_is_the_blind_spot_as_before_and_the_round_the_samples_alone(tmp_path,
                                                                                                      monkeypatch):
    stand_in_sample(monkeypatch)
    words = procevents.PREFIX + "the bind was refused (EPERM)"
    make = factory(StandIn([procevents.REFUSED], refused=words))
    reader = host.live_reader(CATALOG, 0.0, "linux", helper=make)
    inv = reader()
    assert "from_reader" not in inv and inv["procevents"]["refused"] == words
    w, clock = make_watch(tmp_path, feed_inv([pe(hole="refused: " + words, refused=words)] * 2))
    run(w, clock, 2)
    assert not [h for h in w.holes if h["kind"] == host.PE_HOLE_KIND]
    assert [b["kind"] for b in w.blind if b["kind"].startswith("process events")] == ["process events refused"]


@pytest.mark.parametrize("bad,said", [
    (pe(hole=host.PE_LATE % 2.0), "late: the helper's answer did not come within 2 s"),
    (pe(hole=host.PE_ENDED % "its output ended", restarts=1), "ended: the helper of the process events ended"),
    (pe(hole=host.PE_NOT_A_LINE), "not a line: the helper's answer was not its line"),
    (pe(1, lost=2), "lost: the reader lost events: ENOBUFS 2 time(s)"),
    (pe(1, beyond=5), "beyond: the reader passed its bounds: 5 event(s) or record(s) beyond them")])
def test_e4_after_an_answered_ask_each_gap_is_a_hole_of_the_result_said_once_per_episode_with_its_round(
        tmp_path, bad, said):
    w, clock = make_watch(tmp_path, feed_inv([pe(2), bad, bad if not bad["answered"] else dict(
        bad, lost=dict(bad["lost"], count=bad["lost"]["count"] * 2, events=bad["lost"]["events"] * 2),
        beyond=bad["beyond"] * 2)]))
    text, code = run(w, clock, 3)
    holes = [h for h in w.holes if h["kind"] == host.PE_HOLE_KIND]
    assert len(holes) == 1 and holes[0]["round"] == 2 and said in holes[0]["detail"], holes
    assert code == 3 and w.result()[0] == "incomplete"
    assert len([x for x in w.out.getvalue().splitlines() if "HOLE round 2: the process events: " + said[:20] in x]) == 1
    assert not [b for b in w.blind if b["kind"].startswith("process events")]
    assert "  hole, round 2: " + said in text and host.PE_OF_RESULT in text


def test_e4_a_late_answer_before_the_first_answer_is_a_blind_spot_and_the_result_unchanged(tmp_path):
    w, clock = make_watch(tmp_path, feed_inv([pe(hole=host.PE_LATE % 2.0), pe(1)]))
    run(w, clock, 2)
    assert not [h for h in w.holes if h["kind"] == host.PE_HOLE_KIND]
    assert [b["kind"] for b in w.blind if b["kind"].startswith("process events")] == ["process events late"]


# --- E5 (BY-6): the watch's own, and the helper's start -------------------------------------------------------------
def stand_in_ss(tmp_path):
    """The real ss where it is installed; else a stand-in program that prints a header and nothing else."""
    real = discover.find_ss(discover.SS_PATHS)
    if real:
        return real
    path = tmp_path / "ss"
    path.write_text("#!/bin/sh\necho 'State Recv-Q Send-Q Local Address:Port Peer Address:Port Process'\n",
                    encoding="ascii")
    path.chmod(0o755)
    return str(path)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux: the socket tool and the process events")
def test_e5_the_socket_tool_the_round_starts_is_in_the_watchs_record_and_is_no_stranger(tmp_path):
    path = stand_in_ss(tmp_path)
    before = set(own.RECORD.kept())
    t0 = time.time()
    text, error = discover.run_ss(path, discover.SS_INFO_ARGS, at="2026-11-20T10:00:00.000Z")
    assert error is None and text.startswith("# at ")
    (pid,) = set(own.RECORD.kept()) - before
    assert own.RECORD.kept()[pid][1] == "ss"
    began = datetime.datetime.fromtimestamp(t0, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    given = [given_of(pid, os.getpid(), os.path.realpath(path), 10 ** 6, began, began, 0)]
    assert host.reader_text(given, own.RECORD.kept()) == ""          # the watch's own: not given to the round
    sample = json.dumps({"snapshot": "2026-11-20T10:00:00.000Z", "self": os.getpid(), "helpers": []}) + "\n" + \
        json.dumps({"pid": os.getpid(), "ppid": 1, "argv": ["python3"], "exe": sys.executable, "start_ticks": 5,
                    "sockets": [], "unread": []}) + "\n"
    stranger = "process(es) under the reader's pid or a launcher's that the watch did not start"
    texts = {"proc": ("p", sample, None), "procevents": ("x", host.reader_text(given, own.RECORD.kept()) or None,
                                                         None)}
    assert not [h for h in build(texts)["holes"] if stranger in h]
    texts["procevents"] = ("x", host.reader_text(given, {}), None)   # what it would be without the record
    assert [h for h in build(texts)["holes"] if stranger in h]


def test_e5_own_takes_an_image_that_ends_with_deleted_as_the_image_it_was():
    record = own.Record(clock=lambda: 100.0)
    record.add(7, image="/usr/bin/python3.12")
    assert own._base("/usr/bin/python3.12 (deleted)") == "python3.12" and own._base(" (deleted)") is None
    assert record.alive({7: 99.0}, {7: "/usr/bin/python3.12 (deleted)"}) == [7]
    assert record.alive({7: 99.0}, {7: "/usr/bin/python3.11"}) == []


def test_e5_the_helper_always_runs_isolated():
    got = procevents.command("/x/py", path=["/a"])
    assert got[1] == "-I" and "-P" not in got and procevents.Helper(popen=lambda a, **k: None).argv[1] == "-I"


class FullInput:
    """A helper whose input is a real pipe nobody reads, filled to the brim, its writing end then made to block
    again (BZ-9: only the client's own unblocking keeps the ask from waiting); its output says the ready line."""

    def __init__(self, argv, **kw):
        self.args, self.pid, self.returncode = argv, 4343, None
        r, w = os.pipe()
        os.set_blocking(w, False)
        try:
            while True:
                os.write(w, b"x" * 4096)
        except BlockingIOError:
            pass
        os.set_blocking(w, True)
        self._r, self.stdin = r, os.fdopen(w, "wb")
        out_r, self._out_w = os.pipe()
        self.stdout = os.fdopen(out_r, "rb")
        os.write(self._out_w, (json.dumps(READY) + "\n").encode())

    def wait(self, timeout=None):
        self.returncode = 0
        return 0

    def kill(self):
        pass

    terminate = kill


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="os.set_blocking on a pipe: Linux (the helper's own)")
def test_e5_the_ask_never_blocks_a_full_input_is_an_end_and_said_so():
    procs, got = [], []

    def popen(argv, **kw):
        procs.append(FullInput(argv, **kw))
        return procs[-1]
    events = host.ProcEvents(lambda: procevents.Helper(popen=popen), timeout=0.5)
    events.begin()
    asking = threading.Thread(target=lambda: got.append(events.round()), daemon=True)
    asking.start()
    asking.join(3.0)   # a write that blocks would hold the round here: the test fails, never hangs
    assert not asking.is_alive(), "the ask's write blocked on a full input"
    assert got[0]["hole"] == host.PE_ENDED % procevents.FULL and got[0]["restarts"] == 1
    events.close()


class NoUnblock(FullInput):
    """An input whose descriptor cannot be made unblocking."""

    def __init__(self, argv, **kw):
        super().__init__(argv, **kw)
        self.stdin = self

    def fileno(self):
        raise OSError(22, "Invalid argument")

    def close(self):
        pass


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="os.set_blocking on a pipe: Linux (the helper's own)")
def test_e11_an_input_that_cannot_be_made_unblocking_is_the_helper_not_started_and_said():
    events = host.ProcEvents(lambda: procevents.Helper(popen=NoUnblock), timeout=0.5)
    events.begin()
    got = events.round()
    assert got["hole"].startswith("not started: the helper of the process events could not be started (the"
                                  " helper's input could not be made unblocking (")
    assert not got["asked"]


# --- E6 (the words) -------------------------------------------------------------------------------------------------
def flat(path):
    return " ".join((ROOT / path).read_text(encoding="utf-8").split())


def test_e6_the_section_and_the_note_say_what_is_judged_and_what_is_not(tmp_path):
    w, clock = make_watch(tmp_path, feed_inv([pe(2), pe(1)]))
    text, _ = run(w, clock, 2)
    flat_ = " ".join(text.split())
    for words in (host.PE_JUDGED,   # M14.1d (CC-1 to CC-4): what is judged now, and what still is not
                  "with every program it ran while heard (up to 8 a process), each by its file's name and by the name"
                  " it was called by where they differ, and so is a child of a child the watch wrote whose parent"
                  " has gone",
                  "a process can be called by a tool's name it is not",
                  "not judged: a tree that lives whole between two samples, a child's own connections, a program past"
                  " the bound of 8 a process (the oldest of those run between two asks), a child whose parent the"
                  " watch never wrote, a process the reader did not hear made that a sample holds under pid 1, an"
                  " act-root the reader's word alone would make; a program not read is counted, with no line",
                  "a process is its maker's child where the reader heard it made, though a sample holds it under pid"
                  " 1 (CD-1)",   # M14.1d REDO (CD-2)
                  "given to the rounds: 0; joined to a tree as its child: 0; of them with no program read (no line): 0",
                  "not judged: a tree that lives whole between two snapshots, what a child talks to, a program past the"
                  " bound of 8 a process, a child whose parent the watch never wrote, and an act-root the reader's"
                  " word alone would make; a program not read is counted, with no line"):
        assert " ".join(words.split()) in flat_, words
    assert "heard and counted, not judged" not in flat_ and "not judged yet" not in flat_
    assert "a program not read are in no round" not in flat_


def test_e6_the_documents_follow():
    spec = flat("docs/specs/PROC-EVENTS.md")
    for sentence in ("one JSON line per process whose fork was heard, `{pid, ppid, exe, ticks, began, ended, code}`",
                     "A round whose helper gave nothing has no such text, and is the round it was, byte for byte.",
                     "a tree that lives whole between two samples is in no round, and a child's own connections are"
                     " not read",
                     "The helper's lines are its word: what is judged from them comes from the reader, and the watch"
                     " does not check them.",
                     "always with `-I`", "an input that is full (a part of the ask written, or none) is `ended`",
                     # M14.1c REDO (BZ-1, BZ-3, BZ-5, BZ-6, BZ-8)
                     "An act-root is made only by what the samples alone make: its root, the shell under it and a command under"
                     " that shell are each a process a sample held (BZ-1, CA-1, CB-1)",
                     # M14.1d (CC-1 to CC-4): the three silences, now judged; what still is not
                     "A process the watch wrote a line for that runs a program not yet said, in a later round, gets a"
                     " line for that program; a program said of it is not said again.",
                     "is that tree's child though its parent is in neither the sample nor the round's text",
                     "by the name the kernel gave it (a file `nc.openbsd` called `nc`: both); the file's name always"
                     " stays.",
                     "A program past the bound of 8 a process (the oldest of those run between two asks) is not kept"
                     " and not judged",
                     "A child whose parent the watch never wrote (its parent in neither the sample, the text nor the"
                     " kept children) is in no tree, and so is a process whose maker the reader did not hear",
                     "A process is its maker's child (CD-1)",   # M14.1d REDO (CD-2)
                     "where the sample read one, the two are kept apart",
                     "or an answer that holds back a rest for a next one",
                     "The round reads no /proc start of a child the reader alone gave and said ended"):
        assert sentence in spec, sentence
    guide = flat("docs/GUIDE.md")
    for sentence in ("so NET-TOOL and DESTRUCT-CMD judge a short curl, wget, nc or shred by either name (M14.1d)",
                     "Not judged: a tree that lives whole between two samples",
                     "a program past the bound of 8 a process (the oldest of those run between two asks), a child whose"
                     " parent the watch never wrote, a process whose maker the reader did not hear that a sample holds"
                     " under pid 1, and an act-root the reader's word alone would make; a process can be called by a"
                     " tool's name it is not (a link of its own), and its tree then alarms by its own doing.",
                     "A process is its maker's child where the reader heard it made, though a sample holds it under"
                     " pid 1",   # M14.1d REDO (CD-2)
                     "A program not read is in the round and counted; it gets no line.",
                     "the root of a tree, and of an act-root, is always a process a sample held",
                     "where the reader answered and was not whole, the note says what was heard and judged and why it"
                     " was not whole",
                     "the result is INCOMPLETE unless a finding makes it an alarm",
                     "What is judged from the helper is the helper's word: the watch does not check its lines.",
                     "a hole of the result of its own kind (`procevents`)"):
        assert sentence in guide, sentence
    threat = flat("docs/THREAT_MODEL.md")
    for sentence in ("the helper's lines are its word, not a fact the watch checked",
                     "A process of the same user that writes in the helper's place could make the watch write"
                     " HostChild lines for children that never ran under a tree that talks",
                     "it could leave out what did run, so a short child is not judged",
                     "always `-I`", "the watch's record takes that image as the image it was",
                     # M14.1c REDO (BZ-3, BZ-8, BZ-11)
                     "not the name it was called by, so a rule's list of names can miss it",
                     "a child whose parent was given in an earlier round and ended before the sample",
                     "The watch reads no /proc start of a process the reader said ended (BZ-8)",
                     "a tree's line holds the reader's record itself, its path included, made printable and cut as a"
                     " sampled child's record is"):
        assert sentence in threat, sentence
    assert "and judges nothing from it yet" not in threat and "`-P` otherwise" not in threat
    assert "It cannot make the watch run anything or read a file" not in threat


def test_e8_ascii_outside_docs():
    for path in ("raqib/discover.py", "raqib/host.py", "raqib/procevents.py", "raqib/own.py", "tools/rig/check.py",
                 "tools/rig/workload.py", "tests/test_procevents_round.py"):
        assert (ROOT / path).read_text(encoding="utf-8").isascii(), path
    for path in sorted((ROOT / "tests" / "fixtures" / "procevents-round").rglob("*")):
        assert path.is_dir() or path.read_bytes().isascii(), path


# --- M14.1c REDO (ADR-0007 Amendment BZ) ----------------------------------------------------------------------------
def proc_line(pid, ppid, argv0, exe, ticks, **kw):
    return json.dumps(dict({"argv": [argv0], "at": "2026-11-20T10:00:00.000Z", "cwd": "/home/user", "env_keys": [],
                            "exe": exe, "name": argv0, "pid": pid, "ppid": ppid, "sockets": [], "unread": [],
                            "start_ticks": ticks}, **kw), sort_keys=True) + "\n"


TERMINAL = proc_line(2000, 1, "gnome-terminal-server", "/usr/libexec/gnome-terminal-server", 2400) + \
    proc_line(2010, 2000, "bash", "/usr/bin/bash", 2410)
CHAIN = [(2020, 2010, "tool", "/home/user/.local/bin/tool", 2420), (2021, 2020, "sh", "/usr/bin/sh", 2421),
         (2022, 2021, "git", "/usr/bin/git", 2422)]


def test_r1_bz1_a_chain_the_reader_alone_gave_under_a_sampled_terminal_shell_is_no_act_root_and_no_tree():
    texts, holes = texts_of(reader=False)
    sample = texts["proc"][1] + TERMINAL
    reader = "".join(line(pid, ppid=ppid, exe=exe, ticks=ticks, ended=None, code=None)
                     for pid, ppid, _, exe, ticks in CHAIN)
    inv = build(dict(texts, proc=("p", sample, None), procevents=("x", reader, None)), holes)
    assert inv["act_roots"] == [] and not [t for t in inv["candidates"] if t["pid"] in (2010, 2020)]
    assert inv["from_reader"]["given"] == 3 and inv["from_reader"]["joined"] == 0
    # the same chain held by the sample is an act-root, as before: the root's being sampled is what tells them apart
    sampled = sample + "".join(proc_line(pid, ppid, argv0, exe, ticks) for pid, ppid, argv0, exe, ticks in CHAIN)
    assert [r["pid"] for r in build(dict(texts, proc=("p", sampled, None)), holes)["act_roots"]] == [2020]


@pytest.mark.parametrize("field,value", [("began", "9999-12-31T23:59:59-01:00"), ("began", "0000-01-01T00:00:00Z"),
                                         ("ended", "9999-12-31T23:59:59-01:00"), ("ended", "soon"),
                                         ("pid", 10 ** 10), ("ppid", 10 ** 10)])
def test_r4_bz4_a_time_the_round_cannot_read_or_a_pid_past_the_bound_is_no_line_and_never_raises(
        field, value, tmp_path, monkeypatch):
    kw = {"pid": 5, field: value} if field != "pid" else {"pid": value}
    records, problems = discover.parse_procevents(line(**kw) + line(6))
    assert [r["pid"] for r in records] == [6] and len(problems) == 1
    stand_in_sample(monkeypatch)
    rec = reader_rec(1801, "/usr/bin/curl", 2200)
    rec[{"began": "began", "ended": "ended", "pid": "pid", "ppid": "ppid"}[field]] = value
    make = factory(StandIn([answer([rec]), answer([reader_rec(1802, "/usr/bin/curl", 2210)])]))
    reader = host.live_reader(CATALOG, 0.0, "linux", helper=make)
    one, two = reader(), reader()
    assert one["procevents"]["hole"] == host.PE_NOT_A_LINE and "from_reader" not in one
    assert [t["pid"] for t in one["candidates"]] == [1600]   # the round is kept: the sample's alone
    assert two["procevents"]["hole"] is None and two["from_reader"]["given"] == 1


def test_r2_bz2_after_an_answered_ask_a_watch_not_whole_says_what_was_heard_and_judged_and_why(tmp_path):
    w, clock = make_watch(tmp_path, feed_inv([pe(2), pe(1), pe(hole=host.PE_LATE % 2.0)]))
    text, _ = run(w, clock, 3)
    note = next(x for x in w.notes if x.startswith(host.BETWEEN_HEARD))
    assert note == host.BETWEEN_HEARD + host.BETWEEN_NOT_WHOLE % ("1 of 3 ask(s) not answered in their round; round 3:"
                                                                 " late: the helper's answer did not come within 2 s"
                                                                 + host.PE_OF_RESULT)
    assert host.BETWEEN_LINUX not in " ".join(text.split())


def test_r2_bz2_where_no_ask_was_answered_the_rounds_read_proc_only(tmp_path):
    w, clock = make_watch(tmp_path, feed_inv([pe(hole=host.PE_LATE % 2.0)] * 2))
    text, _ = run(w, clock, 2)
    note = next(x for x in w.notes if x.startswith(host.BETWEEN_HOLE % host.BETWEEN_LINUX))
    assert host.BETWEEN_NOT_HEARD.split(":")[0] in note and host.BETWEEN_HEARD not in " ".join(text.split())


def test_r6_bz6_an_answer_that_holds_back_a_rest_is_a_hole_of_the_result_once_an_episode(tmp_path):
    w, clock = make_watch(tmp_path, feed_inv([pe(2), pe(1, more=True), pe(1, more=True), pe(1), pe(1, more=True)]))
    text, code = run(w, clock, 5)
    holes = [h for h in w.holes if h["kind"] == host.PE_HOLE_KIND]
    assert [h["round"] for h in holes] == [2, 5] and all(host.PE_MORE in h["detail"] for h in holes)
    assert code == 3 and "  hole, round 2: " + host.PE_MORE + host.PE_OF_RESULT in text


class Counting(StandIn):
    """A stand-in helper that counts the asks it was written, as procevents.Helper does: `asks` after each round."""

    def __init__(self, script, asks):
        super().__init__(script)
        self.counts, self.asks = list(asks), 0

    def ask(self, timeout):
        self.asks = self.counts.pop(0)
        return super().ask(timeout)


def test_r7_bz7_the_watchs_own_socket_tool_stays_its_own_in_an_answer_taken_a_round_late(monkeypatch):
    me = os.getpid()
    texts, holes = texts_of(reader=False)
    sample = texts["proc"][1].replace('"self": 500,', '"helpers": [], "self": %d,' % me) + proc_line(
        me, 1, "python3", sys.executable, 50)
    assert '"self": %d' % me in sample

    def collect_live(catalog, **kw):
        own.RECORD.alive({}, {}, since=time.time())   # the sample forgets what it does not hold, as snapshot_proc
        return dict(texts, proc=("p", sample, None)), list(holes), 1
    monkeypatch.setattr(discover, "collect_live", collect_live)
    monkeypatch.setattr(discover, "read_conn_bytes", lambda paths: ({}, "fake ss", None))
    monkeypatch.setattr(discover, "proc_start_times", lambda pids: ({}, None))
    began = datetime.datetime.fromtimestamp(time.time(), datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    ss = dict(reader_rec(4194000, "/usr/sbin/ss", 60, ppid=me, began=began), started_ticks=60)
    helper = Counting([answer([], ask=1), procevents.LATE, answer([ss], ask=2)], asks=[1, 2, 2])
    reader = host.live_reader(CATALOG, 0.0, "linux", helper=factory(helper))
    reader()
    own.RECORD.add(4194000, image="ss")   # the round's socket tool, run after round 1's build
    two, three = reader(), reader()
    stranger = "that the watch did not start"
    assert two["procevents"]["hole"] == host.PE_LATE % 2.0 and three["procevents"]["answered"]
    assert three["procevents"]["own"] == 1 and "from_reader" not in three
    assert not [h for h in three["holes"] if stranger in h]
    # without the watch's record it is a stranger under the watch's pid: what the copies kept prevented
    given = given_of(4194000, me, "/usr/sbin/ss", 60, began, ss["ended"], 0)
    inv = build(dict(texts, proc=("p", sample, None), procevents=("x", host.reader_text([given], {}), None)), holes)
    assert [h for h in inv["holes"] if stranger in h]


def test_r8_bz8_no_proc_read_for_the_start_of_a_child_the_reader_said_ended(monkeypatch):
    stand_in_sample(monkeypatch)
    read = []
    monkeypatch.setattr(discover, "proc_start_times", lambda pids: read.append(sorted(pids)) or ({}, None))
    make = factory(StandIn([answer([reader_rec(1801, "/usr/bin/curl", 2200),
                                    reader_rec(1805, "/usr/bin/wget", 2230, ended=None)])]))
    inv = host.live_reader(CATALOG, 0.0, "linux", helper=make)()
    assert read == [[1700, 1805]]   # the sampled bash and the child alive at the ask; never the ended curl
    # its start is the record's, named as the process events' word (CA-4), never among the /proc reads
    assert "1801" not in inv["child_started"]["by"]
    assert inv["child_started"]["events"] == {"from": host.EVENTS_STARTED_FROM,
                                              "by": {"1801": "2026-11-20T10:00:05.000000Z"}}



# --- M14.1c REDO 2 (ADR-0007 Amendment CA) --------------------------------------------------------------------------
def test_s1_ca1_a_shell_no_sample_held_makes_no_chain_of_an_act_root():
    texts, holes = texts_of(reader=False)
    tool, sh, git = CHAIN
    sample = texts["proc"][1] + TERMINAL + proc_line(*tool)
    reader = "".join(line(pid, ppid=ppid, exe=exe, ticks=ticks, ended=None, code=None) for pid, ppid, _, exe, ticks
                     in (sh, git))
    inv = build(dict(texts, proc=("p", sample, None), procevents=("x", reader, None)), holes)
    assert inv["act_roots"] == [] and not [t for t in inv["candidates"] if t["pid"] in (2010, 2020)]
    # CB-1: the shell sampled, its git given by the reader alone: still no act-root (no sample held a command: the
    # samples alone would make none, and the act-root's budget was measured on samples)
    sample += proc_line(*sh)
    reader = line(git[0], ppid=git[1], exe=git[3], ticks=git[4], ended=None, code=None)
    inv = build(dict(texts, proc=("p", sample, None), procevents=("x", reader, None)), holes)
    assert inv["act_roots"] == [] and not [t for t in inv["candidates"] if t["pid"] in (2010, 2020)]
    # the whole chain sampled: the act-root the samples make; a second chain the reader alone gave under the same
    # root adds its processes as acts (CA-1: what only the reader gave adds acts, and never makes an act-root)
    sample += proc_line(*git)
    more = (line(2031, ppid=tool[0], exe="/usr/bin/sh", ticks=5000, ended=None, code=None)
            + line(2032, ppid=2031, exe="/usr/bin/curl", ticks=5001, ended=None, code=None))
    inv = build(dict(texts, proc=("p", sample, None), procevents=("x", more, None)), holes)
    (root,) = inv["act_roots"]
    assert root["pid"] == 2020 and {(a["pid"], a["image"]) for a in root["acts"]} == {
        (2021, "sh"), (2022, "git"), (2031, "sh"), (2032, "curl")}
    assert root["chains"][0]["pid"] == 2021   # the samples' own chain is said first


def child_lines(home):
    out = []
    for name, text in sorted(files(home).items()):
        if "/sources/" in "/" + name:
            out += [json.loads(x) for x in text.splitlines() if x.strip() and '"HostChild"' in x]
    return out


def test_s2_ca2_a_childs_line_says_where_each_child_was_seen_only_in_a_round_that_read_the_readers_text(
        tmp_path, monkeypatch):
    stand_in_sample(monkeypatch, alive=[(2, (1760, 1600, "make", 2600))])
    make = factory(StandIn([answer([reader_rec(1700, "/usr/bin/bash", 2100, ended=None),
                                    reader_rec(1801, "/usr/bin/curl", 2200)]), answer([])]))
    w, clock = make_watch(tmp_path, host.live_reader(CATALOG, 0.0, "linux", helper=make))
    run(w, clock, 2)
    got = [(x["input_meta"]["round"], x["input_meta"]["command_programs"], x["input_meta"].get("command_sources"))
           for x in child_lines(tmp_path / "home")]
    assert got == [(1, ["bash", "curl"], ["both", "events"]), (2, ["make"], None)]   # round 2 read no reader's text
    assert "command_sources" not in json.dumps(child_lines(tmp_path / "home")[1])


def test_s2_ca2_a_round_with_no_readers_text_writes_its_lines_byte_for_byte_as_before(tmp_path, monkeypatch):
    """The same rounds with a helper that gives nothing and with one that never started: the same source lines."""
    def lines(home, helper):
        stand_in_sample(monkeypatch, alive=[(2, (1760, 1600, "make", 2600))])
        w, clock = make_watch(home, host.live_reader(CATALOG, 0.0, "linux", helper=factory(helper)))
        run(w, clock, 2)
        return [{k: v for k, v in x.items() if k not in ("ts",)} for x in child_lines(home / "home")]
    empty = lines(tmp_path / "a", StandIn([answer([]), answer([])]))
    none = lines(tmp_path / "b", StandIn(why="no helper here (a test)"))
    assert empty == none and empty and not [x for x in empty if "command_sources" in x["input_meta"]]


def test_s4_ca4_a_start_from_the_readers_record_is_the_events_word_and_one_from_proc_is_as_before(tmp_path,
                                                                                                   monkeypatch):
    stand_in_sample(monkeypatch)
    monkeypatch.setattr(discover, "proc_start_times", lambda pids: ({p: "2026-11-20T10:00:04.000000Z" for p in pids
                                                                    if p == 1805}, None))
    make = factory(StandIn([answer([reader_rec(1801, "/usr/bin/curl", 2200),
                                    reader_rec(1805, "/usr/bin/wget", 2230, ended=None)])]))
    inv = host.live_reader(CATALOG, 0.0, "linux", helper=make)()
    started = inv["child_started"]
    assert started["from"] == "/proc/PID/stat starttime + /proc/stat btime" and started["by"] == {
        "1805": "2026-11-20T10:00:04.000000Z"}
    assert started["events"] == {"from": host.EVENTS_STARTED_FROM, "by": {"1801": "2026-11-20T10:00:05.000000Z"}}
    assert "the process events" in host.EVENTS_STARTED_FROM and "fork was heard" in host.EVENTS_STARTED_FROM
    w, _ = make_watch(tmp_path, feed_inv([pe(1)]))
    assert w._act_time(0.0, 1, {"pid": 1801}, inv)[1] == host.EVENTS_BASIS == "events"
    assert w._act_time(0.0, 1, {"pid": 1805}, inv)[1] == "stat"


def test_s5_ca5_the_words():
    heard = " ".join(host.BETWEEN_HEARD.split())
    assert "for the whole watch" not in heard and "process events: a process that began under a tree" in heard
    assert "each by its file's name and by the name it was called by where they differ" in heard   # M14.1d (CC-2)
    threat, spec = flat("docs/THREAT_MODEL.md"), flat("docs/specs/PROC-EVENTS.md")
    assert ("a bound passed or an answer that holds back a rest for a next one is a hole of the result (BY-5, BZ-6)"
            in threat)
    assert "It cannot make the watch run anything or write a file of its choosing (CA-5)." in threat
    assert ("a loss, a bound passed or an answer that holds back a rest for a next one is a hole of the result of the"
            " kind `procevents` (BY-5, BZ-6" in spec)
    words = " ".join((ROOT / "raqib" / "ruleform.py").read_text(encoding="utf-8").split())
    assert "talks at a sample, or under an act-root the samples made" in words.replace('" "', "")
    for rule in ("NET-TOOL", "DESTRUCT-CMD"):
        text = (ROOT / "raqib" / "rules" / "catalog" / ("%s.yaml" % rule)).read_text(encoding="utf-8")
        assert "under a tree that talks at a sample, or under an act-root the samples made (M14.1c, CA-1)" in text
    for rule in ("NET-TOOL", "DESTRUCT-CMD"):   # M14.1d (CC-2): the file's name and, where they differ, the name called by
        text = (ROOT / "raqib" / "rules" / "catalog" / ("%s.yaml" % rule)).read_text(encoding="utf-8")
        assert ("named by its program's file and, where they differ, by the name it was called by (CC-2:"
                " `nc.openbsd` called `nc`); a process called by a tool's name it is not (a link of its own) is"
                " judged by that name, so its tree alarms by its own doing") in text


def own_sample(monkeypatch):
    """discover's live collection: the fixture's sample with this process as the reader (a record of what it
    started: "helpers"), forgetting, as snapshot_proc does, every recorded pid the sample does not hold."""
    me = os.getpid()
    texts, holes = texts_of(reader=False)
    sample = texts["proc"][1].replace('"self": 500,', '"helpers": [], "self": %d,' % me) + proc_line(
        me, 1, "python3", sys.executable, 50)

    def collect_live(catalog, **kw):
        own.RECORD.alive({}, {}, since=time.time())
        return dict(texts, proc=("p", sample, None)), list(holes), 1
    monkeypatch.setattr(discover, "collect_live", collect_live)
    monkeypatch.setattr(discover, "read_conn_bytes", lambda paths: ({}, "fake ss", None))
    monkeypatch.setattr(discover, "proc_start_times", lambda pids: ({}, None))
    return texts, holes, sample


def socket_tool(pid, at=None):
    at = time.time() if at is None else at
    began = datetime.datetime.fromtimestamp(at, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return dict(reader_rec(pid, "/usr/sbin/ss", 60, ppid=os.getpid(), began=began), started_ticks=60)


STRANGER = "that the watch did not start"


def late_then_tool():
    """Round 1 answered; ask 2 written in round 2 (R) and late; round 3 takes its answer, empty; round 4's ask 3
    is answered with the socket tool run after round 2's build."""
    ss = socket_tool(4194010)
    return Counting([answer([], ask=1), procevents.LATE, answer([], ask=2), answer([ss], ask=3)],
                    asks=[1, 2, 2, 3])


def test_s6_ca6_an_answer_late_and_empty_then_one_with_the_tool_run_after_the_asks_round_keeps_it_the_watchs(
        monkeypatch):
    own_sample(monkeypatch)
    reader = host.live_reader(CATALOG, 0.0, "linux", helper=factory(late_then_tool()))
    reader()
    two = reader()
    own.RECORD.add(4194010, image="ss")   # the round's socket tool, run after round 2's build (R)
    three, four = reader(), reader()
    assert two["procevents"]["hole"] == host.PE_LATE % 2.0 and three["procevents"]["answered"]
    assert three["procevents"]["own"] == 0 and four["procevents"]["own"] == 1
    assert not [h for h in four["holes"] if STRANGER in h]   # fails where round 3's answer is taken to cover round 3


def test_s6_ca6_the_report_says_how_many_of_the_watchs_own_were_left_out(tmp_path, monkeypatch):
    own_sample(monkeypatch)
    w, clock = make_watch(tmp_path, host.live_reader(CATALOG, 0.0, "linux", helper=factory(late_then_tool())))
    w.tick(wait=30)
    clock.t += w.every
    w.tick(wait=30)
    clock.t += w.every
    own.RECORD.add(4194010, image="ss")
    text, _ = run(w, clock, 2)
    assert host.PE_OWN % 1 in text


def test_s6_ca6_a_copy_written_again_for_the_same_pid_takes_the_new_time_and_image(monkeypatch):
    stand_in_sample(monkeypatch)
    old = time.time() - 300
    own.RECORD.add(4194020, at=old, image="ss")
    ss = socket_tool(4194020)
    reader = host.live_reader(CATALOG, 0.0, "linux", helper=factory(StandIn([answer([], more=True),
                                                                             answer([ss])])))
    reader()                                # the copy (old time) is kept: a rest is held back
    own.RECORD.add(4194020, image="ss")      # the same pid recorded again, now
    two = reader()
    assert two["procevents"]["own"] == 1 and "from_reader" not in two   # by the new copy's time, not the old one


def test_s6_ca6_a_copy_forgotten_at_the_bound_is_counted_and_said(tmp_path, monkeypatch):
    stand_in_sample(monkeypatch)
    monkeypatch.setattr(host, "PE_OWN_MAX", 2)
    for pid in (4194031, 4194032, 4194033):
        own.RECORD.add(pid, image="x")
    w, clock = make_watch(tmp_path, host.live_reader(CATALOG, 0.0, "linux", helper=factory(
        StandIn([answer([], more=True)]))))
    text, _ = run(w, clock, 1)
    said = [x for x in text.splitlines() if x.startswith(host.PE_OWN_FORGOT.split("%d")[0] + "2")]
    assert len(said) == 1 and int(said[0].rsplit(": ", 1)[1]) >= 1, said   # counted and said, never silent


# --- M14.1d (ADR-0007 Amendment CC): every program of a short child, the name it was called by, a parent gone -------
def progs(pid, files, ticks, ppid=1600, names=None, began="2026-11-20T10:00:05.000000Z", ended=None):
    """A process of an answer that ran `files` in order, the kernel's name of each (`names`, else None)."""
    names = list(names) if names is not None else [None] * len(files)
    rec = reader_rec(pid, files[-1], ticks, ppid=ppid, began=began, ended=ended)
    rec["earlier"] = [{"exe": f, "name": x, "unread": {}} for f, x in zip(files[:-1], names[:-1])]
    rec["name"] = names[-1]
    return rec


def lines_of(home):
    return [(x["input_meta"]["round"], x["input_meta"]["command_programs"], [c["pid"] for c in x["input_meta"][
        "children"]]) for x in child_lines(home)]


def watched(tmp_path, monkeypatch, script, rounds, alive=()):
    stand_in_sample(monkeypatch, alive=alive)
    w, clock = make_watch(tmp_path, host.live_reader(CATALOG, 0.0, "linux", helper=factory(StandIn(script))))
    text, code = run(w, clock, rounds)
    return w, text, lines_of(tmp_path / "home")


def test_cc1_e1_a_line_of_the_text_gives_every_program_and_the_old_shape_still_parses():
    new = json.dumps({"pid": 5, "ppid": 1600, "programs": [{"exe": "/usr/bin/bash", "name": "bash"},
                                                           {"exe": "/usr/bin/nc.openbsd", "name": "nc"}],
                      "dropped": 2, "ticks": 3, "began": "2026-11-20T10:00:01Z", "ended": None, "code": None})
    (r, _), problems = discover.parse_procevents(new + "\n" + line(6))
    assert not problems and r["image"] == "nc.openbsd" and r["dropped"] == 2
    assert r["programs"] == [{"exe": "/usr/bin/bash", "name": "bash", "image": "bash"},
                             {"exe": "/usr/bin/nc.openbsd", "name": "nc", "image": "nc.openbsd"}]
    records, _ = discover.parse_procevents(line(6))   # M14.1c's shape: one program, no name
    assert records[0]["programs"] == [{"exe": "/usr/bin/curl", "name": None, "image": "curl"}]


@pytest.mark.parametrize("programs,dropped", [([], 0), ([{"exe": "/x", "name": None}] * 9, 0),
                                              ([{"exe": "/x"}], 0), ([{"exe": "/x", "name": None, "argv": []}], 0),
                                              ([{"exe": 7, "name": None}], 0), ([{"exe": "/x", "name": "a" * 16}], 0),
                                              ([{"exe": "/x", "name": 5}], 0), ("x", 0), ([{"exe": "/x", "name": None}],
                                                                                         -1)])
def test_cc1_e1_a_programs_key_of_another_shape_or_past_its_bounds_is_no_line(programs, dropped):
    bad = json.dumps({"pid": 5, "ppid": 1600, "programs": programs, "dropped": dropped, "ticks": 3,
                      "began": "2026-11-20T10:00:01Z", "ended": None, "code": None})
    records, problems = discover.parse_procevents(bad + "\n" + line(6))
    assert [r["pid"] for r in records] == [6] and len(problems) == 1


def test_cc1_e2_bash_then_curl_in_one_pid_in_one_round_one_line_names_both_and_net_tool_fires(tmp_path, monkeypatch):
    w, _, got = watched(tmp_path, monkeypatch, [answer([progs(1810, ["/usr/bin/bash", "/usr/bin/curl"], 2300)])], 1)
    assert got == [(1, ["bash", "curl"], [1700, 1810])]
    assert "NET-TOOL" in {f["rule_id"] for f in w.source_findings}


def test_cc1_e2_a_program_run_in_a_later_round_gets_its_line_and_one_said_is_not_said_again(tmp_path, monkeypatch):
    script = [answer([]), answer([progs(1820, ["/usr/bin/bash"], 2310)]), answer([]),
              answer([progs(1820, ["/usr/bin/bash", "/usr/bin/wget"], 2310)]),
              answer([progs(1820, ["/usr/bin/bash", "/usr/bin/wget"], 2310)])]
    w, _, got = watched(tmp_path, monkeypatch, script, 5)
    assert [g for g in got if 1820 in g[2]] == [(2, ["bash"], [1820]), (4, ["wget"], [1820])]
    assert [f["rule_id"] for f in w.source_findings].count("NET-TOOL") == 1


def test_cc2_e3_the_name_called_by_beside_the_files_each_through_the_gate(tmp_path, monkeypatch):
    script = [answer([progs(1830, ["/usr/bin/nc.openbsd"], 2320, names=["nc"]),
                      progs(1831, ["/usr/bin/busybox"], 2321, names=["wget"]),
                      progs(1832, ["/usr/bin/true"], 2322, names=["x y"]),           # the gate refuses it
                      progs(1833, ["/usr/bin/abcdefghijklmnopq"], 2323, names=["abcdefghijklmno"]),   # 15: cut
                      progs(1834, ["/usr/bin/shred"], 2324)])]                       # its name not read
    w, _, got = watched(tmp_path, monkeypatch, script, 1)
    ((_, programs, _),) = got
    assert programs == ["bash", "nc.openbsd", "nc", "busybox", "wget", "true", "abcdefghijklmnopq", "shred"]
    tools = [f for f in w.source_findings if f["rule_id"] == "NET-TOOL"]
    assert tools and not [h for h in w.holes if h["kind"] == "host-source-unfit"]


def test_cc3_e4_a_child_whose_parent_was_given_a_round_before_and_ended_is_its_trees_child(tmp_path, monkeypatch):
    parent = progs(1840, ["/usr/bin/bash"], 2330, began="2026-11-20T10:00:04.000000Z")
    child = progs(1841, ["/usr/bin/curl"], 2331, ppid=1840, began="2026-11-20T10:00:06.000000Z",
                  ended="2026-11-20T10:00:06.300000Z")
    ended = dict(answer([child]), ends=[{"pid": 1840, "started_ticks": 2330, "began": parent["began"],
                                         "ended": "2026-11-20T10:00:07.000000Z", "code": 0, "signal": None,
                                         "unread": {}}])
    w, _, got = watched(tmp_path, monkeypatch, [answer([]), answer([parent]), ended, answer([])], 4)
    assert [g for g in got if 1840 in g[2] or 1841 in g[2]] == [(2, ["bash"], [1840]), (3, ["curl"], [1841])]
    assert "NET-TOOL" in {f["rule_id"] for f in w.source_findings}


def test_cc3_e4_a_child_of_a_kept_child_two_rounds_later_and_a_pid_used_again_is_another_child(tmp_path,
                                                                                              monkeypatch):
    p = progs(1850, ["/usr/bin/bash"], 2340, began="2026-11-20T10:00:04.000000Z")
    c = progs(1851, ["/usr/bin/sh"], 2341, ppid=1850, began="2026-11-20T10:00:05.000000Z")
    g = progs(1852, ["/usr/bin/wget"], 2342, ppid=1851, began="2026-11-20T10:00:09.000000Z",
              ended="2026-11-20T10:00:09.500000Z")
    first = progs(1860, ["/usr/bin/curl"], 2350, ended="2026-11-20T10:00:05.500000Z")
    again = progs(1860, ["/usr/bin/curl"], 2360, began="2026-11-20T10:00:09.000000Z",
                  ended="2026-11-20T10:00:09.200000Z")
    w, _, got = watched(tmp_path, monkeypatch, [answer([p, first]), answer([c]), answer([]), answer([g, again])], 4)
    mine = [x for x in got if set(x[2]) & {1850, 1851, 1852, 1860}]
    # the grandchild's parent (1851) is in neither round 4's sample nor its text: it is the tree's by the kept 1851;
    # 1860 begun again (another start) is another child, written again
    assert mine == [(1, ["bash", "curl"], [1700, 1850, 1860]), (2, ["sh"], [1851]), (4, ["curl", "wget"], [1860, 1852])]


def test_cc3_e4_children_kept_past_the_bound_are_said_and_a_hole_of_the_result(tmp_path, monkeypatch):
    monkeypatch.setattr(host, "KEPT_MAX", 2)
    alive = [progs(1870 + i, ["/usr/bin/sleep"], 2370 + i) for i in range(3)]
    w, text, _ = watched(tmp_path, monkeypatch, [answer(alive)], 1)
    holes = [h for h in w.holes if h["kind"] == host.PE_HOLE_KIND and "kept more than 2 children" in h["detail"]]
    assert len(holes) == 1 and host.PE_KEPT_PASSED % (2, 1) in text


def test_cc1_e1_the_reader_reads_each_programs_name_at_its_exec_from_the_stat():
    assert procevents.stat_name(b"5 (nc) S 1 2") == "nc" and procevents.stat_name(b"5 (a) (b) S 1") == "a) (b"
    with pytest.raises(ValueError):
        procevents.stat_name(b"5 nc S")
    assert procevents.PROGRAMS_MAX == 8 and procevents.EARLIER_MAX == 7


# --- M14.1d REDO (ADR-0007 Amendment CD): a process is its maker's child -------------------------------------------
SH = progs(1890, ["/usr/bin/dash"], 2390, names=["sh"], began="2026-11-20T10:00:04.000000Z",
           ended="2026-11-20T10:00:04.010000Z")
BASH = progs(1891, ["/usr/bin/bash"], 2391, ppid=1890, began="2026-11-20T10:00:04.005000Z")
UNDER_INIT = [(1, (1891, 1, "bash", 2391)), (1, (1892, 1891, "sleep", 2392)), (1, (1895, 1, "curl", 2395))]


def test_cd1_a_bash_its_sh_left_is_its_makers_child_though_the_sample_holds_it_under_pid_1(tmp_path, monkeypatch):
    """(a) the round's text gives the sh (begun and ended) and the bash it made; the sample holds the bash under pid
    1: the tree's line names both, the bash is kept; (c) the sleep the sample holds under the bash is the tree's;
    (d) the curl the sample holds under pid 1 that the reader did not give is nobody's; (b) two rounds later the
    bash runs a fetch in its own pid: a line names it and NET-TOOL fires."""
    later = progs(1891, ["/usr/bin/bash", "/usr/bin/wget"], 2391, ppid=1890, began=BASH["began"])
    w, _, got = watched(tmp_path, monkeypatch, [answer([SH, BASH]), answer([]), answer([later])], 3, alive=UNDER_INIT)
    first = next(g for g in got if g[0] == 1)
    assert {1890, 1891, 1892} <= set(first[2]) and 1895 not in first[2]
    assert {"dash", "sh", "bash", "sleep"} <= set(first[1]) and "curl" not in first[1]
    assert [g for g in got if g[0] == 3] == [(3, ["wget"], [1891])]
    assert [f["rule_id"] for f in w.source_findings].count("NET-TOOL") == 1
    kept = next(iter(w.kept_children.values()))
    assert (1891, "boot+2391") in kept


def test_cd1_a_process_the_reader_did_not_give_keeps_the_samples_parent_and_no_text_is_as_before():
    texts, holes = texts_of(reader=False)
    sample = texts["proc"][1] + "".join(proc_line(pid, ppid, argv0, "/usr/bin/" + argv0, ticks)
                                         for _, (pid, ppid, argv0, ticks) in UNDER_INIT)
    plain = build(dict(texts, proc=("p", sample, None)), holes)
    assert [a["pid"] for a in tree(plain, 1600)["acts"]] == [1700]   # under pid 1: nobody's, as before
    assert _flat_json(plain) == _flat_json(build(dict(texts, proc=("p", sample, None)), holes))
    reader = "".join(line(g["pid"], ppid=g["ppid"], exe=g["exe"], ticks=g["started_ticks"], began=g["began"],
                          ended=g["ended"], code=g["code"]) for g in (SH, BASH))
    heard = build(dict(texts, proc=("p", sample, None), procevents=("x", reader, None)), holes)
    assert {a["pid"] for a in tree(heard, 1600)["acts"]} == {1700, 1890, 1891, 1892}   # 1895: the reader gave none
    assert {"pid": 1891, "image": "bash", "started": "boot+2391"} in heard["processes"]   # the sample's list stands
