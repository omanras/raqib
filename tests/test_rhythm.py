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
    w = host.HostWatch(lambda: next(feed), CATALOG, RULES, notifier, every=10, out=io.StringIO(), err=io.StringIO(),
                       clock=clock, wall=lambda: host_fixtures.WALL0 + clock.t, home=str(home), platform=platform,
                       sysmon=NO_SYSMON, **kw)
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
    assert len(measured) == 6 and not any(n["fired"] for n in measured)
    arrivals = {Path(n["path"]).as_posix() for n in measured if "negative-arrival-" in str(n["path"])}
    assert arrivals == {"tests/fixtures/rules/NEW-AGENT/negative-arrival-linux-desktop.json",
                        "tests/fixtures/rules/NEW-AGENT/negative-arrival-windows-desktop.json"}
    built = host_fixtures.build()
    for name in host_fixtures.RHYTHM_SCENARIOS:
        assert (ROOT / "tests" / "fixtures" / "rules" / name).read_text(encoding="ascii") == built[name], name


def test_e2_rhythm_is_a_tree_rule_and_class_host():
    assert host.RHYTHM in host.TREE_RULES and host.RHYTHM in host.RULES
    assert engine.CLASSES[-1] == "HOST"


# --- E1: the two beats on the host source; bytes; start times -------------------------------------------------

def test_e1_host_connection_lines_are_talk_beats_new_or_still_established(home):
    w, clock = make_host(home, scenario("cycle", 3))
    rounds(w, clock, 3)
    (key,) = list(w.trees)
    got = [json.loads(x) for x in Path(w._source_path(key)).read_text(encoding="ascii").splitlines()]
    conns = [l for l in got if l["tool"] == "HostConnection"]
    assert [(l["input_meta"]["round"], l["input_meta"]["new"]) for l in conns] == [(1, True), (2, False), (3, False)]
    assert all(l["input_meta"]["bytes"] == "not read" for l in conns)
    children = [c for l in got if l["tool"] == "HostChild" for c in l["input_meta"]["children"]]
    assert children and all(c["started"] and c["started"].endswith("Z") for c in children)


def test_e1_windows_bytes_hole_is_named_once_per_run(home):
    w, clock = make_host(home, scenario("cycle", 3), platform="win32")
    rounds(w, clock, 3)
    assert w.notes.count(host.WIN_BYTES_HOLE) == 1 and "GetExtendedTcpTable" in host.WIN_BYTES_HOLE


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


def test_e1_a_linux_round_without_child_start_times_uses_the_round_time_with_a_note(home):
    invs = scenario("cycle", 4)
    for i in invs:
        for a in i["candidates"][0]["acts"]:
            a["started"] = None
    w, clock = make_host(home, invs, platform="linux")
    rounds(w, clock, 4)
    assert host.LINUX_STARTED_HOLE in w.notes and w.notes.count(host.LINUX_STARTED_HOLE) == 1
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
    assert len(seen) == 1 and '"session_id": "host-4400"' in seen[0] and "5500" not in seen[0]


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
            gate.wait(10)
            return {"suspicion": 0.0, "reasons": [], "cited_seq": []}
    (home / "b").mkdir()
    w2, clock2 = make_host(home / "b", scenario("between", 10), suspect=Slow({}), suspect_timeout=5)
    rounds(w2, clock2, 10)
    assert w2.suspect_call is not None
    clock2.t += 10
    w2.tick(wait=0)
    gate.set()
    assert any(h["kind"] == "suspect-late" for h in w2.holes) and w2.suspect_call is None
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
    assert "tk.Label(row, text=SUSPECT_TEXT)" in src and "self.c.options.suspect = str(self.suspect_var.get()" in src


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
    assert len(lines) == 9
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
