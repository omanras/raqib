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


def test_e1_the_watch_writes_one_line_per_process_with_those_keys_alone_and_leaves_its_own_out():
    given = [{"pid": 41, "ppid": 1600, "exe": "/usr/bin/curl", "ticks": 3, "began": "2026-11-20T10:00:01.000000Z",
              "ended": None, "code": None},
             {"pid": 42, "ppid": 77, "exe": "/usr/sbin/ss", "ticks": 4, "began": "2026-11-20T10:00:01.000000Z",
              "ended": "2026-11-20T10:00:01.010000Z", "code": 0}]
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
    assert events.take() == [{"pid": 5, "ppid": 1600, "exe": "/usr/bin/curl", "ticks": 9,
                              "began": "2026-11-20T10:00:01.000000Z", "ended": "2026-11-20T10:00:01.100000Z",
                              "code": 0}]   # no fork heard: no process of the round's interval
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


def test_e2_without_ticks_a_record_is_one_with_the_sample_by_the_time_of_its_fork_else_another():
    texts, holes = texts_of(reader=False)
    sample = texts["proc"][1].replace('"start_ticks": 2100,', '"start_ticks": 2100, "started": '
                                      '"2026-11-20T09:59:59.000000Z",')
    assert sample != texts["proc"][1]
    near = line(1700, exe=None, ticks=None, began="2026-11-20T09:59:59.900000Z", ended=None, code=None)
    far = line(1700, exe="/usr/bin/nc", ticks=None, began="2026-11-20T10:00:09.000000Z", ended=None, code=None)
    for text, apart in ((near, 0), (far, 1)):
        inv = build(dict(texts, proc=("p", sample, None), procevents=("x", text, None)), holes)
        assert inv["from_reader"]["by_fork"] == 1 and inv["from_reader"]["apart"] == apart
        assert len([a for a in tree(inv, 1600)["acts"] if a["pid"] == 1700]) == 1 + apart


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
    given = [{"pid": pid, "ppid": os.getpid(), "exe": os.path.realpath(path), "ticks": 10 ** 6, "began": began,
              "ended": began, "code": 0}]
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
    """A helper whose input is a real pipe nobody reads, filled to the brim; its output says the ready line."""

    def __init__(self, argv, **kw):
        self.args, self.pid, self.returncode = argv, 4343, None
        r, w = os.pipe()
        os.set_blocking(w, False)
        try:
            while True:
                os.write(w, b"x" * 4096)
        except BlockingIOError:
            pass
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


def test_e5_the_ask_never_blocks_a_full_input_is_an_end_and_said_so():
    procs = []

    def popen(argv, **kw):
        procs.append(FullInput(argv, **kw))
        return procs[-1]
    events = host.ProcEvents(lambda: procevents.Helper(popen=popen), timeout=0.5)
    events.begin()
    t0 = time.monotonic()
    got = events.round()
    assert time.monotonic() - t0 < 2.0
    assert got["hole"] == host.PE_ENDED % procevents.FULL and got["restarts"] == 1
    events.close()


# --- E6 (the words) -------------------------------------------------------------------------------------------------
def flat(path):
    return " ".join((ROOT / path).read_text(encoding="utf-8").split())


def test_e6_the_section_and_the_note_say_what_is_judged_and_what_is_not(tmp_path):
    w, clock = make_watch(tmp_path, feed_inv([pe(2), pe(1)]))
    text, _ = run(w, clock, 2)
    flat_ = " ".join(text.split())
    for words in ("judged: a process that began between two samples under a tree that talks at a sample is that"
                  " tree's child, by its program's name, from the reader (the helper's lines are its word, not"
                  " checked by the watch)",
                  "not judged: a tree that lives whole between two samples, a child's own connections, a program not"
                  " read",
                  "given to the rounds: 0; joined to a tree as its child: 0; of them with no program read (no line): 0",
                  "a tree that lives whole between two snapshots, what a child talks to and a program not read are in"
                  " no round"):
        assert words in flat_, words
    assert "heard and counted, not judged" not in flat_ and "not judged yet" not in flat_


def test_e6_the_documents_follow():
    spec = flat("docs/specs/PROC-EVENTS.md")
    for sentence in ("one JSON line per process whose fork was heard, `{pid, ppid, exe, ticks, began, ended, code}`",
                     "A round whose helper gave nothing has no such text, and is the round it was, byte for byte.",
                     "a tree that lives whole between two samples is in no round, and a child's own connections are"
                     " not read",
                     "The helper's lines are its word: what is judged from them comes from the reader, and the watch"
                     " does not check them.",
                     "always with `-I`", "an input that is full (a part of the ask written, or none) is `ended`"):
        assert sentence in spec, sentence
    guide = flat("docs/GUIDE.md")
    for sentence in ("so NET-TOOL and DESTRUCT-CMD judge a short curl, wget or shred as they judge a sampled child",
                     "Not judged: a tree that lives whole between two samples",
                     "What is judged from the helper is the helper's word: the watch does not check its lines.",
                     "a hole of the result of its own kind (`procevents`)"):
        assert sentence in guide, sentence
    threat = flat("docs/THREAT_MODEL.md")
    for sentence in ("the helper's lines are its word, not a fact the watch checked",
                     "A process of the same user that writes in the helper's place could make the watch write"
                     " HostChild lines for children that never ran under a tree that talks",
                     "it could leave out what did run, so a short child is not judged",
                     "always `-I`", "the watch's record takes that image as the image it was"):
        assert sentence in threat, sentence
    assert "and judges nothing from it yet" not in threat and "`-P` otherwise" not in threat


def test_e8_ascii_outside_docs():
    for path in ("raqib/discover.py", "raqib/host.py", "raqib/procevents.py", "raqib/own.py", "tools/rig/check.py",
                 "tools/rig/workload.py", "tests/test_procevents_round.py"):
        assert (ROOT / path).read_text(encoding="utf-8").isascii(), path
    for path in sorted((ROOT / "tests" / "fixtures" / "procevents-round").rglob("*")):
        assert path.is_dir() or path.read_bytes().isascii(), path
