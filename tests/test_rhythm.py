"""M7.4 rhythm and suspicion on unknown trees (HANDOFF.md E1-E5; ADR-0007
decision 4; ADR-0004 layer 3; A2).

No live host and no model: every HostWatch gets fake rounds
(tests/fixtures/host/make.py rhythm_inventory, SYNTHETIC) and a fake
suspect backend; the bytes reader gets a fake `ss` through subprocess.run.
"""
import ast
import copy
import io
import json
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from raqib import app, cli, discover, host, ui  # noqa: E402
from raqib.rules import engine, fixtures  # noqa: E402
from raqib.suspect import backends, core  # noqa: E402
from hostthreads import raqib_threads_end  # noqa: E402,F401  (V-5: every HostWatch ended, no thread leaked)

sys.path.insert(0, str(ROOT / "tests"))
from test_watch import FakeRunner, make_notifier  # noqa: E402

sys.path.insert(0, str(ROOT / "tests" / "fixtures" / "host"))
import make as host_fixtures  # noqa: E402

CATALOG = discover.load_catalog(discover.CATALOG)
RULES = engine.load_catalog(ROOT / "raqib" / "rules" / "catalog")
RULE = next(r for r in RULES if r.id == "HOST-RHYTHM")
QUESTIONS = ROOT / "docs" / "review" / "2026-11-04-M7.4-questions.md"
NO_SYSMON = lambda: (False, "test: no Sysmon channel")   # noqa: E731
rin = host_fixtures.rhythm_inventory


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    path = tmp_path / "home"
    path.mkdir()
    monkeypatch.setenv("HOME", str(path))
    monkeypatch.setenv("USERPROFILE", str(path))
    return path


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def make_host(home, invs, runner=None, platform="test", **kw):
    feed = iter(invs)
    clock = Clock()
    notifier = make_notifier(runner or FakeRunner())
    notifier.host = True
    kw.setdefault("sysmon", NO_SYSMON)
    w = host.HostWatch(lambda: next(feed), CATALOG, RULES, notifier, every=10, out=io.StringIO(), err=io.StringIO(),
                       clock=clock, wall=lambda: host_fixtures.WALL0 + clock.t, home=str(home), platform=platform,
                       **kw)
    return w, clock


def rounds(w, clock, n):
    for _ in range(n):
        w.tick(wait=30)
        clock.t += w.every


def scenario(name, n, **kw):
    return [rin(name, k, **kw) for k in range(1, n + 1)]


def settle(w):
    """The suspect call of the last round back and taken (a fake backend may be back within the same tick)."""
    if w.suspect_call is not None:
        w.suspect_call.thread.join(5)
        w.tick(wait=0)


def rhythm_findings(w):
    return [f for f in w.findings if f["rule_id"] == "HOST-RHYTHM"]


def tree_lines(w):
    return [l for r in w.round_lines for l in r.get("lines") or [] if l["tool"] == "HostTree"]


# --- E2: the rule, its thresholds, K, K-1, a changing destination, between rounds ---------------------------

def test_e2_k_cycles_to_one_destination_fire_once_citing_each_beat(home):
    runner = FakeRunner()
    w, clock = make_host(home, scenario("cycle", 4), runner=runner)
    rounds(w, clock, 4)
    (f,) = rhythm_findings(w)
    assert f["round"] == 4 and f["severity"] == "medium" and f["kind"] == "anchor" and f["destination"] == "192.0.2.10:443"
    assert f["cycle_rounds"] == [2, 3, 4] and len(f["beats"]) == 3
    for b in f["beats"]:   # A5: the rounds and the records of each beat
        assert b["run"] == w.run and b["talk_round"] <= b["round"] and b["talk_cites"] and b["acts"]
        assert all(a["basis"] == "started" and a["cites"] for a in b["acts"])
    assert f["notice"] == "sent" and sum(1 for c in runner.calls if "HOST-RHYTHM" in c["text"]) == 1
    assert w.finish()[1] == 1


def test_e2_k_minus_one_cycles_do_not_fire(home):
    w, clock = make_host(home, scenario("cycle", 3))
    rounds(w, clock, 3)
    assert rhythm_findings(w) == [] and tree_lines(w)[-1]["input_meta"]["rhythm"]["cycles"] == 2


def test_e2_a_destination_that_changes_each_turn_does_not_fire(home):
    w, clock = make_host(home, scenario("change", 8))
    rounds(w, clock, 8)
    assert rhythm_findings(w) == []
    assert max(l["input_meta"]["rhythm"]["cycles"] for l in tree_lines(w)) == 1


def test_e2_acts_between_rounds_are_never_seen_a_named_hole(home):
    w, clock = make_host(home, scenario("between", 8))
    rounds(w, clock, 8)
    assert rhythm_findings(w) == [] and all(l["input_meta"]["rhythm"]["acts"] == 0 for l in tree_lines(w))
    assert any(h.startswith("acts between rounds") for h in RULE.holes)
    assert host.RHYTHM_HOLES_NOTE in w.notes and "between two rounds" in host.RHYTHM_HOLES_NOTE


def test_e2_once_per_streak_and_a_new_streak_after_r_rounds_without_a_cycle(home):
    invs = scenario("cycle", 6)                                 # cycles in 2..6: fires at 4 only
    invs += [rin("cycle", 6) for _ in range(10)]                # 10 rounds, no new child: the streak ends
    invs += [rin("cycle", k, children=list(range(1, k - 9))) for k in range(17, 21)]   # cycles again
    for i in invs[16:]:   # the new children have no start time: placed at their round's time (a cycle with its talk)
        for a in i["candidates"][0]["acts"]:
            a["started"] = None
    w, clock = make_host(home, invs)
    rounds(w, clock, len(invs))
    assert [f["round"] for f in rhythm_findings(w)] == [4, 19]
    assert any("streak of tree" in n and "ended" in n for n in w.notes)


def test_e2_one_talk_then_a_burst_of_children_is_one_cycle(home):
    invs = [rin("cycle", 1, children=[1]), rin("cycle", 2, children=[1, 2, 3, 4, 5])]
    w, clock = make_host(home, invs)
    rounds(w, clock, 2)
    assert tree_lines(w)[-1]["input_meta"]["rhythm"]["cycles"] == 1


def test_e2_an_act_more_than_w_after_the_talk_is_not_a_cycle():
    import datetime
    t0 = datetime.datetime(2026, 11, 4, tzinfo=datetime.timezone.utc)
    late = [{"round": k, "at": t0 + datetime.timedelta(seconds=100 * k), "talks": {"192.0.2.10:443": []},
             "acts": [{"pid": k, "image": "bash", "at": t0 + datetime.timedelta(seconds=100 * (k - 1) + 31),
                       "basis": "started", "cites": []}] if k > 1 else [], "seq": k} for k in range(1, 6)]
    assert host.rhythm_of(late, 3, 30, 10, 5)["cycles"] == 0
    near = [dict(e, acts=[dict(a, at=a["at"] - datetime.timedelta(seconds=2)) for a in e["acts"]]) for e in late]
    assert host.rhythm_of(near, 3, 30, 10, 5)["cycles"] == 4
    assert host.rhythm_of(near, 3, 30, 3, 5)["cycles"] == 2   # only the last R rounds count


def test_e2_a_named_tree_is_not_judged_by_rhythm(home):
    w, clock = make_host(home, scenario("cycle", 5, image="claude"))
    rounds(w, clock, 5)
    line = tree_lines(w)[-1]
    assert line["input_meta"]["named"] is True and line["input_meta"]["rhythm"]["cycles"] >= 3
    assert rhythm_findings(w) == []


def test_e2_the_thresholds_are_the_yamls_and_the_code_reads_them():
    assert host.rhythm_params(RULE) == (3, 30, 10) == (host.RHYTHM_K, host.RHYTHM_W, host.RHYTHM_R)
    text = (ROOT / "raqib" / "rules" / "catalog" / "HOST-RHYTHM.yaml").read_text(encoding="ascii")
    for field, value in (("k", 3), ("w", 30), ("r", 10)):
        assert "{field: input_meta.rhythm.%s, eq: %d}" % (field, value) in text
    doc = copy.deepcopy(RULE.doc)
    for node in doc["match"]["all"]:
        if node.get("field") == "input_meta.rhythm.k":
            node["eq"] = 2
    two = engine.compile_rule(doc, "test")
    assert host.rhythm_params(two) == (2, 30, 10)


def test_e2_a_yaml_with_other_thresholds_drives_the_watch(home):
    doc = copy.deepcopy(RULE.doc)
    for node in doc["match"]["all"]:
        if node.get("field") == "input_meta.rhythm.k":
            node["eq"] = 2
    rules = [r for r in RULES if r.id != "HOST-RHYTHM"] + [engine.compile_rule(doc, "test")]
    feed = iter(scenario("cycle", 3))
    clock = Clock()
    w = host.HostWatch(lambda: next(feed), CATALOG, rules, make_notifier(FakeRunner()), every=10, out=io.StringIO(),
                       err=io.StringIO(), clock=clock, wall=lambda: host_fixtures.WALL0 + clock.t, home=str(home),
                       platform="test", sysmon=NO_SYSMON)
    rounds(w, clock, 3)
    assert (w.rhythm_k, w.rhythm_w, w.rhythm_r) == (2, 30, 10) and [f["round"] for f in rhythm_findings(w)] == [3]


def test_e2_the_rule_is_a_catalog_anchor_with_fixtures_from_make_py_and_a_measured_budget():
    assert RULE.kind == "anchor" and RULE.cls == "HOST" and RULE.severity == "medium" and RULE.fp_budget == 0.0
    assert RULE.evasion == () and len(RULE.holes) >= 4
    for word in ("relay or proxy", "acts between rounds", "changes each turn", "reparented"):
        assert any(word in h for h in RULE.holes), word
    reports = {r["rule_id"]: r for r in fixtures.check_catalog(RULES, ROOT, cli.benign_default(str(ROOT)))}
    rep = reports["HOST-RHYTHM"]
    assert rep["verdict"] == "ok" and rep["fp_rate"] == 0.0 and all(p["fired"] for p in rep["positives"])
    measured = [n for n in rep["negatives"] if n["measured"]]
    # K-9: the four synthetic cases only; the arrivals (one round each, no cycle possible) are not listed;
    # M7.5 E2: and the os source's two cycles
    # M7.6c REDO E-2: and the edge negatives of W and R (an act at W+1 s; a first cycle out of the last R rounds)
    assert len(measured) == 7 and not any(n["fired"] for n in measured)
    assert sorted(Path(n["path"]).name for n in measured) == [
        "negative-acts-between-rounds.json", "negative-changing-destination.json", "negative-no-talk.json",
        "negative-os-two-cycles.json", "negative-r-edge.json", "negative-two-cycles.json", "negative-w-edge.json"]
    assert RULE.fixtures["negative"] == ["tests/fixtures/rules/" + n for n in list(host_fixtures.RHYTHM_SCENARIOS)
                                         + list(host_fixtures.OS_SCENARIOS)
                                         + list(host_fixtures.EDGE_SCENARIOS)   # M7.6c REDO E-2
                                         if "/negative-" in n and n.startswith("HOST-RHYTHM/")]
    built = host_fixtures.build()
    for name in list(host_fixtures.RHYTHM_SCENARIOS) + list(host_fixtures.OS_SCENARIOS):
        assert (ROOT / "tests" / "fixtures" / "rules" / name).read_text(encoding="ascii") == built[name], name


def test_e2_rhythm_is_a_tree_rule_and_class_host():
    assert host.RHYTHM in host.TREE_RULES and host.RHYTHM in host.RULES
    assert engine.CLASSES[-1] == "HOST"


# --- E1: the two beats on the host source; bytes; start times -------------------------------------------------

def test_e1_host_connection_lines_are_talk_beats_new_or_bytes_moved(home):
    w, clock = make_host(home, scenario("cycle", 3))
    rounds(w, clock, 3)
    (key,) = list(w.trees)
    got = [json.loads(x) for x in Path(w._source_path(key)).read_text(encoding="ascii").splitlines()]
    conns = [l for l in got if l["tool"] == "HostConnection"]
    assert [(l["input_meta"]["round"], l["input_meta"]["change"]) for l in conns] == [(1, "new"), (2, "bytes"),
                                                                                       (3, "bytes")]
    assert conns[-1]["input_meta"]["bytes"] == {"sent": 3000, "received": 15000, "sockets": 1}
    children = [c for l in got if l["tool"] == "HostChild" for c in l["input_meta"]["children"]]
    assert children and all(c["started"] and c["started"].endswith("Z") for c in children)


def test_e1_windows_bytes_hole_is_a_blind_spot_named_once_per_run(home):
    w, clock = make_host(home, scenario("cycle", 3), platform="win32")
    rounds(w, clock, 3)
    (b,) = [b for b in w.blind if b["kind"] == "bytes"]
    assert b["class"] == "blind spot" and b["detail"].startswith(host.WIN_BYTES_HOLE) and b["rounds"] == [1, 2, 3]
    assert "GetExtendedTcpTable" in host.WIN_BYTES_HOLE and host.WIN_BYTES_HOLE not in w.notes


def test_e1_linux_bytes_are_recorded_on_the_connection_line(home):
    invs = scenario("cycle", 2)
    for i in invs:
        i["conn_bytes"] = {"from": "/usr/sbin/ss -tinp", "hole": None,
                           "by": {"4400 192.0.2.10:443": {"bytes_sent": 1200, "bytes_received": 5400, "sockets": 1}}}
    w, clock = make_host(home, invs, platform="linux")
    rounds(w, clock, 2)
    (key,) = list(w.trees)
    conns = [json.loads(x) for x in Path(w._source_path(key)).read_text(encoding="ascii").splitlines()
             if '"HostConnection"' in x]
    assert conns[-1]["input_meta"]["bytes"] == {"sent": 1200, "received": 5400, "sockets": 1}


def test_e1_a_linux_round_without_child_start_times_uses_the_round_time_a_blind_spot(home):
    invs = scenario("cycle", 4)
    for i in invs:
        for a in i["candidates"][0]["acts"]:
            a["started"] = None
    w, clock = make_host(home, invs, platform="linux")
    rounds(w, clock, 4)
    started = [b for b in w.blind if b["kind"] == "started"]
    assert len(started) == 1 and started[0]["detail"] == host.LINUX_STARTED_HOLE + host.BLIND_TAIL
    assert tree_lines(w)[-1]["input_meta"]["rhythm"]["act_basis"] == ["round"]
    assert [f["round"] for f in rhythm_findings(w)] == [4]   # the round time is within W of the round's talk


def test_e1_a_local_creation_date_is_not_guessed_as_utc():
    assert host.utc_time("11/1/2026 9:14:30 AM") is None and host.utc_time("") is None
    assert host.utc_time("2026-11-04T10:00:00.000000Z") is not None


class FakeSs:
    def __init__(self, stdout, code=0):
        self.stdout, self.code, self.calls = stdout, code, []

    def __call__(self, argv, **kw):
        self.calls.append((argv, kw))
        return subprocess.CompletedProcess(argv, self.code, self.stdout, "")


SS_TEXT = """State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
ESTAB 0 0 192.0.2.20:51000 198.51.100.7:443 users:(("agent",pid=1600,fd=5))
\t cubic wscale:7,7 rto:204 bytes_sent:1200 bytes_acked:1201 bytes_received:5400 segs_out:9
ESTAB 0 0 192.0.2.20:51002 198.51.100.7:443 users:(("agent",pid=1600,fd=6))
\t cubic bytes_sent:100 bytes_received:50
ESTAB 0 0 192.0.2.20:51004 198.51.100.8:443
\t cubic bytes_sent:1
"""


def test_e1_the_bytes_reader_runs_ss_by_absolute_path_with_a_fake_ss(tmp_path, monkeypatch):
    ss = tmp_path / "ss"
    ss.write_text("#!/bin/sh\n", encoding="ascii")
    fake = FakeSs(SS_TEXT)
    monkeypatch.setattr(discover.subprocess, "run", fake)
    got, label, hole = discover.read_conn_bytes((str(ss),))
    (argv, kw), = fake.calls
    assert argv == [str(ss), "-tinp"] and set(kw["env"]) <= {"LC_ALL", "SYSTEMROOT"} and "PATH" not in kw["env"]
    assert got == {"1600 198.51.100.7:443": {"bytes_sent": 1300, "bytes_received": 5450, "sockets": 2}}
    assert "1 socket(s) with no owner" in hole and label.endswith(" -tinp")


def test_e1_a_missing_ss_or_an_ss_without_byte_counts_is_a_named_hole(tmp_path, monkeypatch):
    got, label, hole = discover.read_conn_bytes((str(tmp_path / "no-ss"),))
    assert got is None and "no ss at" in hole and "not read" in hole
    ss = tmp_path / "ss"
    ss.write_text("#!/bin/sh\n", encoding="ascii")
    monkeypatch.setattr(discover.subprocess, "run", FakeSs(SS_TEXT.replace("bytes_", "b_")))
    got, label, hole = discover.read_conn_bytes((str(ss),))
    assert got is None and "printed no bytes_sent or bytes_received" in hole
    monkeypatch.setattr(discover.subprocess, "run", FakeSs("", code=1))
    got, label, hole = discover.read_conn_bytes((str(ss),))
    assert got is None and "exited 1" in hole


def test_e1_the_live_reader_reads_bytes_on_linux_only(monkeypatch):
    calls = []
    monkeypatch.setattr(discover, "collect_live", lambda *a, **k: ({}, [], 1))
    monkeypatch.setattr(discover, "run", lambda *a, **k: {"candidates": []})
    monkeypatch.setattr(discover, "read_conn_bytes", lambda paths: calls.append(paths) or ({}, "ss", None))
    assert host.live_reader(CATALOG, platform="linux")()["conn_bytes"] == {"from": "ss", "hole": None, "by": {}}
    assert "conn_bytes" not in host.live_reader(CATALOG, platform="win32")() and len(calls) == 1


def test_e1_discover_acts_carry_the_childs_started_time():
    inv = host_fixtures.inventory("windows", CATALOG)
    acts = [a for c in inv["candidates"] for a in c["acts"] if a["how"] == "process"]
    assert acts and all("started" in a for a in acts) and any(a["started"] for a in acts)


# --- E3: the suspect layer over unknown trees (A2) ---------------------------------------------------------------

def fake_backend(answer):
    return backends.FakeBackend({"*": answer})


def test_e3_every_r_rounds_an_unknown_trees_source_goes_to_the_suspect_layer_and_suspicion_lands_on_it(home):
    runner = FakeRunner()
    w, clock = make_host(home, scenario("cycle", 10), runner=runner,
                         suspect=fake_backend({"suspicion": 0.9, "reasons": ["a think-act cycle"], "cited_seq": [2]}))
    rounds(w, clock, 9)
    assert w.suspect_call is None and w.suspicions == []          # not before round R
    rounds(w, clock, 1)
    settle(w)
    (s,) = w.suspicions
    assert s["pid"] == 4400 and s["round"] == 10 and s["cited_seq"] == [2] and s["backend"] == "fake"
    assert s["trace"] == w.sources[next(iter(w.trees))].path and s["notice"] == "sent"
    assert sum(1 for c in runner.calls if "SUSPECT" in c["text"]) == 1
    text, code = w.finish()
    assert code == 1 and "suspicion(s) raised by fake" in text and "[suspicion 0.90] SUSPECT on relay-bot" in text


def test_e3_benign_is_no_finding_never_a_clearance(home):
    w, clock = make_host(home, scenario("between", 10),
                         suspect=fake_backend({"suspicion": 0.0, "reasons": [], "cited_seq": []}))
    rounds(w, clock, 10)
    settle(w)
    assert w.suspicions == [] and w.suspect_runs[-1]["below"] == 1
    (t,) = w.trees.values()
    assert t["suspect_below"] == 1 and "suspicion" not in t
    text, code = w.finish()
    assert code == 0 and "below the threshold 0.50 (no finding, not a clearance)" in text
    assert "1 window(s) below the threshold: no finding (A2)" in text
    assert "benign" not in text.split("SUSPICION", 1)[1].split("\n", 1)[0].lower()


def test_e3_named_and_benign_trees_are_never_sent(home):
    invs = scenario("cycle", 10)
    for i in invs:
        named = copy.deepcopy(i["candidates"][0])
        named.update(pid=5500, image="claude")
        i["candidates"].append(named)
    seen = []

    class Spy(backends.FakeBackend):
        def judge(self, system, user, schema):
            seen.append(user)
            return {"suspicion": 0.0, "reasons": [], "cited_seq": []}
    w, clock = make_host(home, invs, suspect=Spy({}))
    rounds(w, clock, 10)
    settle(w)
    # (the Table, 2026-11-11, CI run 42918149551: the prompt carries sha256 hashes, and one of them held "5500"
    # by chance on one windows job; the pids are looked for outside the hashes)
    sent = re.sub(r"[0-9a-f]{64}", "", seen[0])
    assert len(seen) == 1 and '"session_id": "t1"' in seen[0] and "5500" not in sent and "4400" not in sent


def test_e3_what_is_sent_is_hashes_and_names_only(home):
    seen = []

    class Spy(backends.FakeBackend):
        def judge(self, system, user, schema):
            seen.append((system, user, schema))
            return {"suspicion": 0.0, "reasons": [], "cited_seq": []}
    w, clock = make_host(home, scenario("cycle", 10), suspect=Spy({}))
    rounds(w, clock, 10)
    settle(w)
    (system, user, schema), = seen
    assert system == host.SUSPECT_PROMPT and schema == core.SCHEMA
    assert "192.0.2.10" not in user and "remote" not in user and "fake child row" not in user
    assert "input_sha256" in user and '"command_programs"' in user
    for line in re.findall(r"^\{.*\}$", user.split("<trace>", 1)[1], re.M):
        rec = json.loads(line.replace("\\u003c", "<").replace("\\u003e", ">").replace("\\u0026", "&"))
        assert set(rec) <= set(host.SUSPECT_LINE_FIELDS) and set(rec.get("input_meta", {})) <= {"command_programs"}


def test_e3_a_failed_or_late_call_is_a_hole_not_a_clearance(home):
    w, clock = make_host(home, scenario("cycle", 10), suspect=fake_backend({"error": "unreachable"}))
    rounds(w, clock, 10)
    settle(w)
    assert any(h["kind"] == "suspect-error" and "unreachable" in h["detail"] for h in w.holes)

    gate = threading.Event()

    class Slow(backends.FakeBackend):
        def judge(self, system, user, schema):
            gate.wait()   # V-5: the test sets the gate
            return {"suspicion": 0.0, "reasons": [], "cited_seq": []}
    (home / "b").mkdir()
    w2, clock2 = make_host(home / "b", scenario("between", 10), suspect=Slow({}), suspect_timeout=5)
    rounds(w2, clock2, 10)
    call = w2.suspect_call
    assert call is not None
    clock2.t += 10
    w2.tick(wait=0)
    # K-3: late is a hole, said once, and the call is NOT let go while its thread runs (never two in flight)
    assert [h["kind"] for h in w2.holes].count("suspect-late") == 1 and w2.suspect_call is call
    gate.set()
    call.thread.join(5)
    w2.tick(wait=0)
    assert w2.suspect_call is None and w2.suspect_runs[-1]["state"] == "back (late)"
    assert w2.finish()[1] == 3   # no finding: the late call is a hole (incomplete), never a clearance


def test_e3_a_raising_backend_is_a_hole(home):
    class Boom(backends.FakeBackend):
        def judge(self, system, user, schema):
            raise RuntimeError("boom")
    w, clock = make_host(home, scenario("cycle", 10), suspect=Boom({}))
    rounds(w, clock, 10)
    settle(w)
    assert any(h["kind"] == "suspect-error" and "boom" in h["detail"] for h in w.holes) and w.suspicions == []


def test_e3_a_suspicion_citing_outside_its_window_is_an_error_a5(home):
    w, clock = make_host(home, scenario("cycle", 10),
                         suspect=fake_backend({"suspicion": 0.9, "reasons": ["x"], "cited_seq": [999]}))
    rounds(w, clock, 10)
    settle(w)
    assert w.suspicions == [] and any("not in this window (A5)" in h["detail"] for h in w.holes)


def test_e3_suspect_is_off_by_default_and_says_so(home):
    w, clock = make_host(home, scenario("cycle", 10))
    rounds(w, clock, 10)
    assert w.suspect_call is None and "SUSPICION (A2: a model may raise suspicion, never acquit): off" in w.finish()[0]


def test_e3_the_suspect_backend_spec():
    assert host.suspect_backend("ollama").name == "ollama"
    assert host.suspect_backend("anthropic:claude-x").model == "claude-x"
    for bad in ("", "fake", "gpt", "ollama2"):
        with pytest.raises(ValueError):
            host.suspect_backend(bad)


def test_e3_the_backend_call_is_never_on_the_capture_or_discovery_path():
    """AST guard: raqib/suspect is imported by host.py only inside the
    suspect functions, never by the reader; discover.py and hostwin.py and
    the hooks import nothing of it and open no socket."""
    tree = ast.parse((ROOT / "raqib" / "host.py").read_text(encoding="utf-8"))
    top = [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))]
    assert not any("suspect" in (getattr(n, "module", "") or "") or any("suspect" in a.name for a in n.names)
                   for n in top)
    allowed = {"suspect_backend": "backends", "_run": "core", "__init__": "core", "_suspect_start": "core"}
    for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        for n in ast.walk(fn):
            if isinstance(n, ast.ImportFrom) and (n.module or "").startswith("raqib.suspect"):
                assert fn.name in allowed and [a.name for a in n.names] == [allowed[fn.name]], fn.name
    # the backend's judge is called only through core.run, from SuspectCall._run (its thread)
    calls = [fn.name for fn in ast.walk(tree) if isinstance(fn, ast.FunctionDef)
             for n in ast.walk(fn) if isinstance(n, ast.Call) and ast.unparse(n.func) in ("core.run", "self.suspect.judge")]
    assert calls == ["_run"]
    (reader,) = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "live_reader"]
    assert "suspect" not in ast.unparse(reader).replace("suspect call is not in", "")
    for name in ("raqib/discover.py", "raqib/hostwin.py", "raqib/hooks/capture.py", "raqib/hooks/os_sysmon.py"):
        mods = set()
        for n in ast.walk(ast.parse((ROOT / name).read_text(encoding="utf-8"))):
            if isinstance(n, ast.Import):
                mods |= {a.name for a in n.names}
            elif isinstance(n, ast.ImportFrom):
                mods.add(n.module or "")
        assert not any(m.startswith(("raqib.suspect", "urllib", "http", "socket", "anthropic")) for m in mods), name
    # the HostWatch's init (where the reader is set) imports only the pure core: schema and threshold
    (init,) = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "__init__"
               and "suspect_threshold" in ast.unparse(n)]
    assert "from raqib.suspect import core as suspect_core" in ast.unparse(init)


def test_e3_cli_suspect_reaches_the_host_watch(monkeypatch, capsys):
    got = {}
    monkeypatch.setattr(host, "command", lambda *a, **k: got.update(k) or 0)
    assert cli.main(["watch", "--host", "--rounds", "1", "--suspect", "ollama:llama3.1:8b"], out=io.StringIO()) == 0
    assert got["suspect"].name == "ollama" and got["suspect"].model == "llama3.1:8b"
    assert cli.main(["watch", "--host", "--rounds", "1"], out=io.StringIO()) == 0 and got["suspect"] is None
    assert cli.main(["watch", "--host", "--suspect", "gpt"], out=io.StringIO()) == 2
    assert cli.main(["watch", "--suspect", "ollama"], out=io.StringIO()) == 2
    assert "apply to watch --host only" in capsys.readouterr().err


def test_e3_the_window_field_is_empty_by_default_and_reaches_the_host_watch(home):
    o = app.Options(None, RULES, 60)
    assert o.suspect == "" and app.SUSPECT_TEXT == "suspect unknown trees"
    assert app.suspect_spec("") == (None, None) and app.suspect_spec("ollama")[0].name == "ollama"
    assert app.suspect_spec("gpt")[0] is None and "unknown --suspect backend" in app.suspect_spec("gpt")[1]
    got = {}
    o.host_reader = lambda: {"candidates": []}
    o.catalog = CATALOG
    session = app.HostSession(o, log=app.LogBuffer(), starter=lambda *a, **k: got.update(k))
    session._open()
    assert "suspect" not in got
    o.suspect = "ollama"
    session._open()
    assert got["suspect"].name == "ollama"
    src = (ROOT / "raqib" / "app.py").read_text(encoding="utf-8")
    assert "tk.Label(row, text=sentence(SUSPECT_TEXT)" in src   # M8.1: in the watch options, sentence case
    assert "self.c.options.suspect = str(self.suspect_var.get()" in src


# --- E4: report, page, window, exit codes --------------------------------------------------------------------------

def test_e4_report_page_and_window_show_rhythm_and_suspicion(home):
    w, clock = make_host(home, scenario("cycle", 10),
                         suspect=fake_backend({"suspicion": 0.7, "reasons": ["cycle"], "cited_seq": [2]}))
    rounds(w, clock, 10)
    settle(w)
    state = w.state(clock())
    page = ui.host_page(json.loads(json.dumps(state)))
    assert "HOST-RHYTHM round(s) 4" in page and "suspicion 0.70" in page and "<h3>Suspicion (1)</h3>" in page
    assert "rhythm: 1" in page and "suspicion: 1" in page
    view = app.host_watch_view(json.loads(json.dumps(state)))
    assert any(f.startswith("HOST-RHYTHM [medium] round 4") for f in view["findings"])
    assert any(f.startswith("SUSPECT [suspicion 0.70] round 10") for f in view["findings"])
    assert any("HOST-RHYTHM round(s) 4" in " ".join(r) for r in view["rows"])
    text, code = w.finish()
    assert code == 1 and "HOST-RHYTHM in round(s) 4" in text and "SUSPECT 0.70" in text


def test_e4_exit_codes_as_c10(home):
    w, clock = make_host(home, scenario("cycle", 3))
    rounds(w, clock, 3)
    assert w.finish()[1] == 0                                      # history tree, nothing new: CLEAN
    (home / "b").mkdir()
    w2, clock2 = make_host(home / "b", scenario("cycle", 4))
    rounds(w2, clock2, 4)
    assert w2.finish()[1] == 1                                     # HOST-RHYTHM: ALARM


# --- E5: CI, README, questions file, ASCII -----------------------------------------------------------------------

def test_e5_ci_counts_rhythm_zero_on_the_runners():
    gate = (ROOT / ".github" / "workflows" / "gate.yml").read_text(encoding="utf-8")
    assert "M7.4" in gate and 'rhythm = len(re.findall(r"^  \\[medium\\] HOST-RHYTHM ", text, re.M))' in gate
    assert "assert rhythm == 0" in gate


def test_e5_readme_three_lines():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    section = text.split("## Watch the host\n", 1)[1].split("\n## ", 1)[0]
    lines = [l for l in section.split("\n") if l.strip()]
    assert len(lines) == 14   # M7.5: + two lines at the end (test_field_run.py); M7.8: + three at the end
    assert "HOST-RHYTHM" in lines[6] and "--suspect" in lines[7] and "never acquit" in lines[7]
    assert "only network call" in lines[8]


def test_e5_questions_file():
    text = QUESTIONS.read_text(encoding="utf-8")
    for q in ("Q-1", "Q-2", "Q-3", "Q-4", "Q-5"):
        assert q in text
    assert "2657 passed, 19 skipped" in text and "test_rhythm.py" in text
    assert "| HOST-RHYTHM      | anchor    | -" in text and "Ratio after M7.4: 4 : 7 : 11." in text
    assert "Note (2026-11-04, M7.4, ADR-0007 decision 4" in text
    assert "CI: not run; pushes held by the commander's order (Actions minutes exhausted, 2026-11-04)" in text


def test_ascii():
    for name in ("raqib/host.py", "raqib/discover.py", "raqib/ui.py", "raqib/app.py", "raqib/cli.py",
                 "raqib/suspect/core.py", "raqib/rules/catalog/HOST-RHYTHM.yaml", "tests/test_rhythm.py",
                 "tests/fixtures/host/make.py"):
        (ROOT / name).read_bytes().decode("ascii")


# --- M7.4 REDO: ADR-0007 Amendment K (K-1..K-13), each with its test (K-14) ----------------------------------------

class Spy(backends.FakeBackend):
    """Records every window sent (the rendered user text) and answers below the threshold."""

    def __init__(self, answers=None, delay=0.0):
        super().__init__(answers or {})
        self.users = []
        self.delay = delay
        self.inflight = 0
        self.max_inflight = 0
        self.lock = threading.Lock()

    def judge(self, system, user, schema):
        with self.lock:
            self.inflight += 1
            self.max_inflight = max(self.max_inflight, self.inflight)
        try:
            self.users.append(user)
            if self.delay:
                time.sleep(self.delay)
            return {"suspicion": 0.0, "reasons": [], "cited_seq": []}
        finally:
            with self.lock:
                self.inflight -= 1


def sent_seqs(spy):
    out = []
    for user in spy.users:
        head = user.split("\n", 1)[0]
        first, rest = head[len("Window of seq "):].split(" to ", 1)
        body = user.split("<trace>", 1)[1]
        out += [json.loads(l)["seq"] for l in re.findall(r"^\{.*\}$", body, re.M)]
    return out


def five_remotes(n):
    """n rounds of the cycle tree with five remotes, each new every round (six host lines per round)."""
    invs = []
    for k in range(1, n + 1):
        inv = rin("cycle", k, bytes_moved=False)
        talks = inv["candidates"][0]["talks"]
        inv["candidates"][0]["talks"] = [dict(talks[0], remote="192.0.2.%d:%d" % (10 + i, 1000 + k))
                                         for i in range(5)]
        invs.append(inv)
    return invs


def drive(w, clock, n, spy=None):
    for _ in range(n):
        w.tick(wait=30)
        if w.suspect_call is not None:
            w.suspect_call.thread.join(5)
        clock.t += w.every
    w.rounds_max = w.rounds   # no further round: only the continued calls
    for _ in range(50):   # the continued calls (K-1) of the last R-th round
        if w.suspect_call is not None:
            w.suspect_call.thread.join(5)
        w.tick(wait=0)
        if w.suspect_call is None and not w._suspect_pending():
            break


def test_redo_k1_every_host_line_is_sent_exactly_once_in_order_over_calls(home):
    """K-1 (P1): 120 lines over 20 rounds -> all sent, in order, none twice; at most 40 per call."""
    spy = Spy()
    w, clock = make_host(home, five_remotes(20), suspect=spy)
    drive(w, clock, 20, spy)
    (key,) = list(w.trees)
    lines = [json.loads(x) for x in Path(w._source_path(key)).read_text(encoding="ascii").splitlines()]
    assert len(lines) >= 120
    seqs = sent_seqs(spy)
    assert seqs == [l["seq"] for l in lines] and len(seqs) == len(set(seqs))
    assert all(len(re.findall(r"^\{.*\}$", u.split("<trace>", 1)[1], re.M)) <= host.SUSPECT_BATCH for u in spy.users)
    assert w.suspect_upto[w._source_path(key)] == lines[-1]["seq"]
    text, _ = w.finish()
    assert "lines not judged by the suspect layer" not in "".join(h["detail"] for h in w.holes)
    assert "%d line(s) sent, 0 line(s) not judged" % len(lines) in text


def test_redo_k1_upto_advances_only_to_the_last_seq_sent_and_the_rest_is_a_hole(home):
    """K-1: lines after the last R-th round's mark are never sent: a hole per tree, on the tree and in the report."""
    spy = Spy()
    w, clock = make_host(home, five_remotes(13), suspect=spy)
    drive(w, clock, 13, spy)
    (key,) = list(w.trees)
    path = w._source_path(key)
    lines = [json.loads(x) for x in Path(path).read_text(encoding="ascii").splitlines()]
    at10 = [l["seq"] for l in lines if l["input_meta"]["round"] <= 10]
    assert sent_seqs(spy) == at10 and w.suspect_upto[path] == at10[-1]
    text, code = w.finish()
    left = len(lines) - len(at10)
    (hole,) = [h for h in w.holes if h["kind"] == "suspect-unsent"]
    assert "%d lines not judged by the suspect layer" % left in hole["detail"]
    assert w.trees[key]["suspect_unsent"] == left and "%d lines not judged by the suspect layer" % left in text
    assert code == 3


def test_redo_k1_a_watch_shorter_than_r_rounds_with_suspect_says_its_lines_were_not_judged(home):
    w, clock = make_host(home, scenario("cycle", 5), suspect=Spy())
    rounds(w, clock, 5)
    text, code = w.finish()
    assert any(h["kind"] == "suspect-unsent" for h in w.holes) and code in (1, 3)


def os_lines(path, pid, n):
    lines = [{"ts": "2026-11-04T10:00:%02d.000Z" % i, "seq": i, "session_id": "os-%d" % pid, "phase": "pre",
              "tool": "process", "source": "os", "cwd": "/home/user/project", "input_sha256": "ab" * 32,
              "input_meta": {"command_head": "bash", "command_programs": ["bash"], "depth": 1, "parent_seq": 1}}
             for i in range(1, n + 1)]
    with open(path, "a", encoding="ascii") as f:
        f.write("".join(json.dumps(l) + "\n" for l in lines))


class OsFollow:
    def __call__(self, root, log, stop, every=None, out=None, err=None, on_pass=None, after_record=None, helpers=None):
        os_lines(log, root, 3)
        if on_pass:
            on_pass(1, None)
        stop.wait()   # V-5: only the stop it is given ends it
        return 1


def test_redo_k2_an_os_source_tree_is_sent_its_own_os_lines(home):
    spy = Spy()
    invs = scenario("cycle", 10)
    for i in invs[1:]:
        i["candidates"][0]["started"] = invs[0]["candidates"][0]["started"]
    w, clock = make_host(home, invs, suspect=spy, sysmon=lambda: (True, "test"), os_follow=OsFollow())
    for _ in range(10):
        w.tick(wait=30)
        time.sleep(0.05)
        clock.t += w.every
    drive(w, clock, 0, spy)
    (src,) = w.sources.values()
    assert src.kind == "os" and spy.users
    body = "".join(spy.users)
    assert '"tool": "process"' in body and '"command_head": "bash"' in body and "/home/user" not in body
    assert '"session_id": "t1"' in body and "os-4400" not in body and "ab" * 32 not in body
    w.finish()


def test_redo_k2_a_hooks_source_tree_sends_its_trace_and_its_host_lines(home):
    """The jobs of a hooks source: every feed (the agent's trace and the host lines beside it)."""
    w, clock = make_host(home, scenario("cycle", 1), suspect=Spy())
    rounds(w, clock, 1)
    (key,) = list(w.trees)
    trace_path = home / "trace.jsonl"
    trace_path.write_text("".join(json.dumps(l) + "\n" for l in [
        {"ts": "2026-11-04T10:00:01.000Z", "seq": 1, "session_id": "s-hook", "phase": "pre", "tool": "Bash",
         "cwd": "/home/user/p", "input_sha256": "cd" * 32, "input_meta": {"command_head": "curl",
                                                                         "command_programs": ["curl"]}},
        {"ts": "2026-11-04T10:00:02.000Z", "seq": 1, "session_id": "s-hook", "phase": "post", "tool": "Bash",
         "cwd": "/home/user/p", "ok": True, "output_meta": {"scan": "full", "secret_kinds": ["aws"]}}]),
        encoding="ascii")
    old = w.sources[key]
    src = host.TreeSource("hooks", "hooks: test", path=old.path, feeds=[host.Feed(str(trace_path), w.src_rules)]
                          + old.feeds, also_host=True)
    w.sources[key] = src
    w._poll_sources(clock())
    for _, _, feed in w._suspect_feeds():
        w._suspect_cursor(feed)["target"] = len(feed.numbered)
    jobs = w._suspect_jobs(clock(), 1)
    assert sorted(j["source"] for j in jobs) == ["hook", "host"]
    hook = next(j for j in jobs if j["source"] == "hook")
    text = core.render_window(core.windows(hook["records"], hook["findings"], 40)[0], hook["fields"], hook["meta"])
    assert '"command_programs": ["curl"]' in text and '"secret_kinds": ["aws"]' in text
    assert "/home/user" not in text and "s-hook" not in text and "cd" * 32 not in text
    w.finish()


def test_redo_k2_a_record_shape_the_builder_cannot_send_is_a_hole_once_per_tree(home):
    spy = Spy()
    w, clock = make_host(home, scenario("cycle", 10), suspect=spy)
    rounds(w, clock, 1)
    (key,) = list(w.trees)
    with open(w._source_path(key), "a", encoding="ascii") as f:
        for i in range(2):
            f.write(json.dumps({"ts": "2026-11-04T10:00:00.000Z", "seq": 900 + i, "session_id": "px",
                                "phase": "pre", "tool": "http", "source": "proxy"}) + "\n")
    w.file_seq[w._source_path(key)] = 901
    drive(w, clock, 9, spy)
    holes = [h for h in w.holes if h["kind"] == "suspect-unsendable"]
    assert len(holes) == 1 and "source proxy not sendable" in holes[0]["detail"]
    # M7.5 Q-11: "900" alone also matched a salted hash (one run id in 13): the proxy lines' own seqs are what must not go
    sent = "".join(spy.users)
    assert w.trees[key]["suspect_unsendable"] == ["proxy"] and not re.search(r'"seq": ?90[01]\b', sent)
    assert '"px"' not in sent and '"proxy"' not in sent
    assert "source proxy not sendable" in w.finish()[0]


def test_redo_k3_at_most_one_call_in_flight_with_a_slow_backend(home):
    spy = Spy(delay=0.3)
    w, clock = make_host(home, five_remotes(45), suspect=spy, suspect_timeout=0.1)
    for _ in range(45):
        w.tick(wait=30)
        clock.t += w.every
    assert spy.max_inflight == 1
    assert any(h["kind"] == "suspect-held" for h in w.holes) or any(h["kind"] == "suspect-late" for h in w.holes)
    threads = [t for t in threading.enumerate() if t.name == "raqib-host-suspect"]
    w.finish()
    assert spy.max_inflight == 1
    for t in threads:
        t.join(5)
    assert not any(t.is_alive() for t in threads)   # no thread left running unrecorded


def test_redo_k3_a_call_still_out_at_the_end_is_recorded(home, monkeypatch):
    gate = threading.Event()

    class Stuck(Spy):
        def judge(self, system, user, schema):
            gate.wait()   # V-5: the test sets the gate
            return {"suspicion": 0.0, "reasons": [], "cited_seq": []}
    monkeypatch.setattr(host, "SUSPECT_JOIN_SECONDS", 0.05)
    w, clock = make_host(home, scenario("cycle", 10), suspect=Stuck())
    rounds(w, clock, 10)
    assert w.suspect_call is not None
    w.finish()
    gate.set()
    assert any(h["kind"] == "suspect-out" for h in w.holes) and any(h["kind"] == "suspect-late" for h in w.holes)


def test_redo_k3_the_budget_is_passed_to_the_backend_call_as_its_timeout(home, monkeypatch):
    seen = []

    class Opener:
        def open(self, request, timeout=None):
            seen.append(timeout)
            raise OSError("test: no network")
    ollama = backends.OllamaBackend()
    ollama._opener = Opener()
    assert ollama.timeout == 300
    w, clock = make_host(home, scenario("cycle", 10), suspect=ollama)
    rounds(w, clock, 10)
    settle(w)
    assert seen and all(0 < t <= host.SUSPECT_TIMEOUT for t in seen) and ollama.timeout == 300
    sdk_calls = []

    class Messages:
        def create(self, **kw):
            sdk_calls.append(kw)
            raise RuntimeError("test")

    class Client:
        beta = type("B", (), {"messages": Messages()})()
    anthropic = backends.AnthropicBackend(client=Client())
    monkeypatch.setattr(backends.AnthropicBackend, "_sdk", staticmethod(lambda: type("SDK", (), {
        "AuthenticationError": KeyError, "RateLimitError": KeyError, "APIStatusError": KeyError,
        "APIConnectionError": KeyError})))
    call = host.SuspectCall([{"key": (1, "x", None), "records": [
        {"ts": "2026-11-04T10:00:00.000Z", "seq": 1, "session_id": "t1", "phase": "pre", "tool": "HostChild"}],
        "findings": [], "fields": ("seq",), "meta": {}}], anthropic, 0.5, budget=7.0)
    call.thread.join(5)
    assert sdk_calls and 0 < sdk_calls[0]["timeout"] <= 7.0 and anthropic.timeout is None


def test_redo_k4_no_pid_leaves_and_hashes_are_salted_with_the_run(home):
    spy = Spy()
    w, clock = make_host(home, scenario("cycle", 10), suspect=spy)
    rounds(w, clock, 10)
    settle(w)
    (user,) = spy.users
    (key,) = list(w.trees)
    own = [json.loads(x) for x in Path(w._source_path(key)).read_text(encoding="ascii").splitlines()]
    assert "4400" not in user and "host-4400" not in user and w.run not in user and '"session_id": "t1"' in user
    for line in own:
        if line.get("input_sha256"):
            assert line["input_sha256"] not in user                    # unsalted: never sent
            assert host.suspect_salt(w.run, line["input_sha256"]) in user   # salted with the run id
    assert own[0]["session_id"] == "host-4400"                         # the tree's own file keeps its shape
    assert host.suspect_salt("run-a", "x") != host.suspect_salt("run-b", "x")


def test_redo_k5_a_kept_alive_connection_without_bytes_is_one_talk(home):
    invs = scenario("cycle", 8, bytes_moved=False)
    w, clock = make_host(home, invs)
    rounds(w, clock, 8)
    rh = [l["input_meta"]["rhythm"] for l in tree_lines(w)]
    assert [bool(r["talks"]) for r in rh] == [True] + [False] * 7
    assert max(r["cycles"] for r in rh) <= 1 and rhythm_findings(w) == []
    assert any("repeated talks on one long connection are unseen without bytes" in h for h in RULE.holes)


def test_redo_k5_an_established_connection_whose_bytes_moved_is_a_talk_and_one_that_did_not_is_not(home):
    invs = scenario("cycle", 6)
    for i in invs[2:]:   # rounds 3..6: the counts stay as in round 2
        i["conn_bytes"]["by"]["4400 192.0.2.10:443"].update(bytes_sent=2000, bytes_received=10000)
    w, clock = make_host(home, invs)
    rounds(w, clock, 6)
    rh = [l["input_meta"]["rhythm"] for l in tree_lines(w)]
    assert [bool(r["talks"]) for r in rh] == [True, True, False, False, False, False]
    assert rhythm_findings(w) == [] and max(r["cycles"] for r in rh) == 2


def test_redo_k5_a_new_connection_each_round_is_a_talk_each_round(home):
    invs = scenario("cycle", 4, bytes_moved=False)
    for k, i in enumerate(invs, 1):   # the same destination, a new socket each round: closed then new
        if k % 2 == 0:
            i["candidates"][0]["talks"] = []
    w, clock = make_host(home, invs)
    rounds(w, clock, 4)
    assert [bool(l["input_meta"]["rhythm"]["talks"]) for l in tree_lines(w)] == [True, False, True, False]


def test_redo_k5_linux_act_time_is_proc_stat_starttime_plus_btime(tmp_path):
    proc = tmp_path / "proc"
    (proc / "77").mkdir(parents=True)
    (proc / "stat").write_text("cpu 1 2 3\nbtime 1793700000\nprocesses 9\n", encoding="ascii")
    fields = ["S"] + ["0"] * 18 + ["2500"] + ["0"] * 10   # field 3 .. ; starttime (field 22) = 2500 ticks
    (proc / "77" / "stat").write_text("77 (a (b) c) %s\n" % " ".join(fields), encoding="ascii")
    by, hole = discover.proc_start_times([77, 78], proc_root=str(proc), clk_tck=100)
    assert by == {77: discover.iso(discover._ts("2026-11-04T00:00:00Z").fromtimestamp(
        1793700025, discover.datetime.timezone.utc))} and "1 of 2 child pid(s)" in hole
    assert discover.parse_stat_starttime("1 (x) S") is None and discover.parse_btime("cpu 1") is None
    (proc / "stat").write_text("cpu 1\n", encoding="ascii")
    assert discover.proc_start_times([77], proc_root=str(proc), clk_tck=100)[0] == {}


def test_redo_k5_the_watch_places_a_linux_act_at_its_stat_time_so_w_is_real(home):
    invs = scenario("cycle", 4)
    for k, i in enumerate(invs, 1):
        by = {}
        for a in i["candidates"][0]["acts"]:
            by[str(a["pid"])] = a["started"]
            a["started"] = None
        i["child_started"] = {"from": "test", "hole": None, "by": by}
    w, clock = make_host(home, invs, platform="linux")
    rounds(w, clock, 4)
    line = tree_lines(w)[-1]["input_meta"]["rhythm"]
    assert line["act_basis"] == ["stat"] and [f["round"] for f in rhythm_findings(w)] == [4]
    assert not any(b["kind"] == "started" for b in w.blind)
    late = scenario("cycle", 4)   # the same rounds with every child started 31 s after its round's talk
    for i in late:
        by = {}
        for a in i["candidates"][0]["acts"]:
            by[str(a["pid"])] = host_fixtures._iso_at(500 + a["pid"])
            a["started"] = None
        i["child_started"] = {"from": "test", "hole": None, "by": by}
    (home / "b").mkdir()
    w2, clock2 = make_host(home / "b", late, platform="linux")
    rounds(w2, clock2, 4)
    assert rhythm_findings(w2) == []   # W excludes them: not the round's own time


def test_redo_k5_the_live_reader_reads_child_start_times_on_linux_only(monkeypatch):
    got = []
    monkeypatch.setattr(discover, "collect_live", lambda *a, **k: ({}, [], 1))
    monkeypatch.setattr(discover, "run", lambda *a, **k: {"candidates": [{"acts": [
        {"how": "process", "pid": 9}, {"how": "file", "pid": 10}]}]})
    monkeypatch.setattr(discover, "read_conn_bytes", lambda paths: ({}, "ss", None))
    monkeypatch.setattr(discover, "proc_start_times", lambda pids: got.append(pids) or ({9: "T"}, None))
    inv = host.live_reader(CATALOG, platform="linux")()
    assert got == [[9]] and inv["child_started"]["by"] == {"9": "T"}
    assert "child_started" not in host.live_reader(CATALOG, platform="win32")() and len(got) == 1


def test_redo_k6_a_long_lived_connection_writes_no_line_per_round(home):
    w, clock = make_host(home, scenario("between", 12, bytes_moved=False))
    rounds(w, clock, 12)
    (key,) = list(w.trees)
    conns = [json.loads(x) for x in Path(w._source_path(key)).read_text(encoding="ascii").splitlines()
             if '"HostConnection"' in x]
    assert [(c["input_meta"]["round"], c["input_meta"]["change"]) for c in conns] == [(1, "new")]
    gone = scenario("between", 3, bytes_moved=False)
    gone[2]["candidates"][0]["talks"] = []
    (home / "b").mkdir()
    w2, clock2 = make_host(home / "b", gone)
    rounds(w2, clock2, 3)
    (key,) = list(w2.trees)
    conns = [json.loads(x) for x in Path(w2._source_path(key)).read_text(encoding="ascii").splitlines()
             if '"HostConnection"' in x]
    assert [c["input_meta"]["change"] for c in conns] == ["new", "closed"]


def test_redo_k7_rhythm_cites_carry_round_and_seq(home):
    w, clock = make_host(home, scenario("cycle", 4))
    rounds(w, clock, 4)
    (f,) = rhythm_findings(w)
    assert f["cites"] and all(isinstance(c["round"], int) and isinstance(c["seq"], int) for c in f["cites"])
    text = w.finish()[0]
    line = next(l for l in text.splitlines() if "] HOST-RHYTHM round" in l)
    assert re.search(r"cites round 1 seq [0-9]+ win-tcp:2, round 2 seq [0-9]+ win-process:4", line), line
    state = json.loads(json.dumps(w.state(clock())))
    assert "round 2 seq" in ui.host_page(state)
    assert "talk round 1 seq" in app.host_finding_line(f) or "talk round 2 seq" in app.host_finding_line(f)


def test_redo_k8_blind_spots_are_said_once_counted_apart_and_never_exit_3_alone(home):
    invs = scenario("between", 6, bytes_moved=False)
    for k, i in enumerate(invs, 1):   # a text that changes each round (P8): one blind spot all the same
        i["conn_bytes"] = {"from": "ss", "hole": "%d socket(s) with no owner shown" % k, "by": None}
    w, clock = make_host(home, invs, platform="linux")
    rounds(w, clock, 6)
    (b,) = [b for b in w.blind if b["kind"] == "bytes"]
    assert b["rounds"] == [1, 2, 3, 4, 5, 6] and b["detail"].endswith("(does not change the result)")
    assert not any(h["kind"] == "blind spot" or "socket(s) with no owner" in h["detail"] for h in w.holes)
    text, code = w.finish()
    assert code == 0 and "RESULT: CLEAN" in text
    assert "BLIND SPOTS (K-8, holes of the class blind spot, counted apart; they do not change the result): 1" in text
    assert "HOLES (A3): 0" in text
    (home / "b").mkdir()
    w2, clock2 = make_host(home / "b", scenario("cycle", 3), platform="win32")
    rounds(w2, clock2, 3)
    assert w2.finish()[1] == 0 and len(w2.blind) == 1


def test_redo_k11_the_network_guard_covers_every_module(monkeypatch):
    """AST guard: urllib, http.client, socket and ssl are imported only by the modules that own them
    (suspect/backends.py: the one allowed network caller, reached only from host.SuspectCall's thread;
    hooks/proxy.py: the proxy source, ADR-0003; ui.py: the local page's http.server/socketserver; hooks/common.py:
    urllib.parse, no I/O); subprocess never runs curl or wget in any module."""
    allowed = {"raqib/suspect/backends.py": {"urllib.error", "urllib.parse", "urllib.request"},
               "raqib/hooks/proxy.py": {"http.client", "http.server", "socket", "socketserver", "ssl",
                                        "urllib.parse"},
               "raqib/ui.py": {"http.server", "socketserver"},
               "raqib/hooks/common.py": {"urllib.parse"}}
    net = ("urllib", "http.client", "http.server", "socket", "socketserver", "ssl", "requests", "httpx", "aiohttp")
    for path in sorted((ROOT / "raqib").rglob("*.py")):
        rel = path.relative_to(ROOT).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"))
        mods = set()
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                mods |= {a.name for a in n.names}
            elif isinstance(n, ast.ImportFrom) and n.module:
                mods.add(n.module)
        bad = {m for m in mods if m.split(".")[0] in {x.split(".")[0] for x in net}
               and (m.startswith(net) or m in ("http", "urllib"))} - allowed.get(rel, set())
        assert not bad, (rel, bad)
        for n in ast.walk(tree):   # subprocess with curl or wget, in any spelling
            if isinstance(n, ast.Call) and "subprocess" in ast.unparse(n.func) or (
                    isinstance(n, ast.Call) and ast.unparse(n.func).split(".")[-1] in ("Popen", "check_output",
                                                                                        "call", "check_call")):
                text = ast.unparse(n).lower()
                assert "curl" not in text and "wget" not in text, (rel, ast.unparse(n)[:120])
    # the backends module is imported by host.py only inside suspect_backend, and judge is reached only
    # through core.run in SuspectCall._run (the suspect thread)
    tree = ast.parse((ROOT / "raqib" / "host.py").read_text(encoding="utf-8"))
    for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        for n in ast.walk(fn):
            if isinstance(n, ast.ImportFrom) and n.module == "raqib.suspect" and "backends" in [a.name for a in n.names]:
                assert fn.name == "suspect_backend"
            if isinstance(n, ast.Call) and ast.unparse(n.func) in ("core.run", "self.backend.judge",
                                                                     "self.suspect.judge"):
                assert fn.name == "_run"
    importers = [p.relative_to(ROOT).as_posix() for p in (ROOT / "raqib").rglob("*.py")
                 if "suspect" in p.read_text(encoding="utf-8") and "backends" in p.read_text(encoding="utf-8")
                 and re.search(r"from raqib\.suspect import (backends|core)", p.read_text(encoding="utf-8"))]
    assert set(importers) <= {"raqib/host.py", "raqib/cli.py", "raqib/eval.py", "raqib/suspect/backends.py"}


def test_redo_k13_ci_asserts_check_rules_lists_host_rhythm_with_its_budget():
    gate = (ROOT / ".github" / "workflows" / "gate.yml").read_text(encoding="utf-8")
    assert "K-13" in gate and "check-rules.txt" in gate
    assert r'^HOST-RHYTHM +ok +[0-9.]+ +0 +' in gate


def test_redo_questions_file_has_the_redo_section():
    text = QUESTIONS.read_text(encoding="utf-8")
    redo = text.split("## REDO (Amendment K)", 1)[1]
    assert "2698 passed, 19 skipped" in redo and "CI: not run; pushes held" in redo
    for k in ("K-1", "K-2", "K-3", "K-4", "K-5", "K-6", "K-7", "K-8", "K-9", "K-11", "K-13"):
        assert k in redo, k
    assert "S-1" in redo


def test_redo_k1_a_failing_backend_is_not_retried_every_tick(home):
    calls = []

    class Down(Spy):
        def judge(self, system, user, schema):
            calls.append(1)
            raise core.BackendError("down")
    w, clock = make_host(home, five_remotes(10), suspect=Down())
    rounds(w, clock, 10)
    for _ in range(20):
        if w.suspect_call is not None:
            w.suspect_call.thread.join(5)
        w.tick(wait=0)
    assert len(calls) == 1 and w.suspect_call is None
