"""M7.2 raqib watch --host (HANDOFF.md E1-E6, ADR-0007 decision 2).

No live host is read here: every HostWatch gets a reader that returns
inventories of the discover fixtures (or fake ones in the inventory shape),
and every notifier a fake runner (tests/test_watch.py's), or is off.
"""
import datetime
import io
import json
import os
import re
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from raqib import cli, discover, host, notify, ui, watch  # noqa: E402
from raqib.rules import engine, fixtures  # noqa: E402

sys.path.insert(0, str(ROOT / "tests"))
from test_watch import FakeRunner, make_notifier  # noqa: E402

sys.path.insert(0, str(ROOT / "tests" / "fixtures" / "host"))
import make as host_fixtures  # noqa: E402

CATALOG = discover.load_catalog(discover.CATALOG)
RULES = engine.load_catalog(ROOT / "raqib" / "rules" / "catalog")
RULE_FIXTURES = ROOT / "tests" / "fixtures" / "rules"
QUESTIONS = ROOT / "docs" / "review" / "2026-11-04-M7.2-questions.md"


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    path = tmp_path / "home"
    path.mkdir()
    monkeypatch.setenv("HOME", str(path))
    monkeypatch.setenv("USERPROFILE", str(path))
    return path


def inv(name):
    return host_fixtures.inventory(name, CATALOG)


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


def make_host(tmp_path, names=None, reader=None, runner=None, every=10, rounds=None, notifier=None):
    """A HostWatch fed the inventories of these discover fixtures, in order."""
    if reader is None:
        feed = iter([inv(n) if isinstance(n, str) else n for n in names])
        reader = lambda: next(feed)   # noqa: E731
    clock = Clock()
    notifier = notifier or make_notifier(runner or FakeRunner())
    notifier.host = True
    w = host.HostWatch(reader, CATALOG, RULES, notifier, every=every, rounds_max=rounds, out=io.StringIO(),
                       err=io.StringIO(), clock=clock, wall=lambda: 1793700000.0 + clock.t - 1000.0,
                       home=str(tmp_path / "home"), platform="test")
    return w, clock


def run_rounds(w, clock, n):
    for _ in range(n):
        w.tick(wait=30)
        clock.t += w.every


def said(w):
    return w.out.getvalue()


# --- E1: rounds, the files, the end ------------------------------------------------------------

def test_e1_a_round_is_one_inventory_kept_in_inventory_json_and_rounds_jsonl(tmp_path):
    w, clock = make_host(tmp_path, ["linux", "linux"])
    run_rounds(w, clock, 2)
    base = tmp_path / "home" / ".raqib" / "host"
    assert Path(w.inventory_path) == base / "inventory.json" and Path(w.rounds_path) == base / "rounds.jsonl"
    latest = json.loads((base / "inventory.json").read_text(encoding="ascii"))
    assert latest["records"] == inv("linux")["records"] and latest["candidates"]
    lines = [json.loads(x) for x in (base / "rounds.jsonl").read_text(encoding="ascii").splitlines()]
    assert [r["round"] for r in lines] == [1, 2] and [r["history"] for r in lines] == [True, False]
    for r in lines:   # A5: the round, the sample, the record lines behind each claim
        assert r["records"] == 30 and r["sample"].startswith("window ") and r["lines"]
        for line in r["lines"]:
            assert line["input_meta"]["round"] == r["round"] and line["input_meta"]["sample"] == r["sample"]
            assert line["input_meta"]["cites"] and all(re.match(r"[a-z-]+(-[0-9]+)?:[0-9]+$", c)
                                                       for c in line["input_meta"]["cites"])
    st = json.loads(Path(w.state_path).read_text(encoding="ascii"))
    assert st["mode"] == "host" and st["host"]["rounds"] == 2 and st["heartbeat"] and st["band"] == "WATCHING"


def test_e1_rounds_start_every_t_seconds_and_rounds_n_ends_it(tmp_path):
    w, clock = make_host(tmp_path, ["linux"] * 3, rounds=2)
    w.tick(wait=30)
    assert w.rounds == 1
    clock.t += 5
    w.tick(wait=30)
    assert w.rounds == 1                       # not yet T
    clock.t += 5
    w.tick(wait=30)
    assert w.rounds == 2 and w.done_rounds()
    clock.t += 50
    w.tick(wait=30)
    assert w.rounds == 2                       # --rounds: no third


def test_e1_the_reader_is_the_live_discover_path_one_sample_on_windows(monkeypatch):
    calls = []

    def collect_live(catalog, **kw):
        calls.append(kw)
        texts, holes = discover.read_dir(str(ROOT / "tests" / "fixtures" / "discover" / "linux"))
        return texts, holes, 1
    monkeypatch.setattr(discover, "collect_live", collect_live)
    got = host.live_reader(CATALOG, 0.0, "win32")()
    assert calls[0]["win_samples"] == 1 and calls[0]["platform"] == "win32" and calls[0]["window"] == 0.0
    assert got["live"] is True and got["candidates"]
    host.live_reader(CATALOG, 3.0, "linux")()
    assert calls[1]["window"] == 3.0


def test_e1_the_final_report_lists_the_trees_and_the_exit(tmp_path):
    w, clock = make_host(tmp_path, ["benign/windows-desktop", "windows"])
    run_rounds(w, clock, 2)
    text, code = w.finish()
    assert code == 1 and "RESULT: ALARM (exit 1)" in text
    assert "TREES SEEN: 6 (4 now)" in text
    assert re.search(r"\[candidate\] pid 7000 scribe \(unknown\): now; first round 2; last round 2; 1 act\(s\);.*"
                     r"NEW-AGENT folded", text), text
    assert "[candidate] pid 5100 explorer (unknown): gone; first round 1 (history, not knocked)" in text
    assert "FINDINGS: 4" in text and "cites win-process:" in text


# --- E2: NEW-AGENT -------------------------------------------------------------------------------

def test_e2_round_one_is_history_listed_not_knocked(tmp_path):
    runner = FakeRunner()
    w, clock = make_host(tmp_path, ["linux", "linux"], runner=runner)
    run_rounds(w, clock, 2)
    assert runner.calls == [] and w.findings == []
    assert all(t["history"] for t in w.trees.values()) and len(w.trees) == 2
    assert "history (there at the start, not knocked)" in said(w)


def test_e2_a_new_unknown_tree_knocks_once_with_the_a4_text(tmp_path):
    runner = FakeRunner()
    w, clock = make_host(tmp_path, ["benign/windows-desktop", "windows", "windows"], runner=runner)
    run_rounds(w, clock, 3)
    texts = [c["text"] for c in runner.calls]
    assert texts[0] == "Raqib: NEW-AGENT\nhost, claude pid 2100 (named)\n"
    # one per rule per minute: the rest are folded, never dropped
    assert [f["rule_id"] for f in w.findings] == ["NEW-AGENT"] * 4
    assert {f["image"]: (f["named"], f["round"]) for f in w.findings} == {
        "claude": ("named", 2), "nimbus": ("named", 2), "msedge": ("unknown", 2), "scribe": ("unknown", 2)}
    assert [f["notice"] for f in w.findings] == ["sent", "folded", "folded", "folded"]
    clock.t += 60
    w.tick()
    assert runner.calls[-1]["text"] == "Raqib: NEW-AGENT\nhost, 3 more (first nimbus pid 3300 (named), last scribe pid" \
                                      " 7000 (unknown))\n"
    # round 3: the same trees, no new knock (once per tree)
    assert len([f for f in w.findings if f["round"] == 3]) == 0


def test_e2_notification_text_alphabet_and_length(tmp_path):
    n = make_notifier(FakeRunner())
    n.host = True
    title, body = n.texts("NEW-AGENT", "x" * 300 + " pid 4 (unknown)")
    assert title == "Raqib: NEW-AGENT" and len(body) <= notify.TEXT_MAX and body.startswith("host, x")
    title, body = n.texts("NEW-AGENT", "C:\\Users\\u\\evil;rm -rf /.exe pid 4 (unknown)")
    assert not re.search(r"[^A-Za-z0-9 ._,:+()-]", title + body) and "\\" not in body and "/" not in body
    # never a command line or a path: the host line's image is a name, the where text has nothing else
    w, clock = make_host(tmp_path, ["benign/windows-desktop", "windows"], runner=FakeRunner())
    run_rounds(w, clock, 2)
    for f in w.findings:
        where = "%s pid %s (%s)" % (f["image"], f["pid"], f["named"])
        assert "\\" not in where and "/" not in where and " -" not in where


def test_e2_an_act_root_that_becomes_a_candidate_is_new(tmp_path):
    runner = FakeRunner()
    w, clock = make_host(tmp_path, ["kimi/one-sample", "kimi/two-samples"], runner=runner)
    run_rounds(w, clock, 2)
    (f,) = w.findings
    assert (f["rule_id"], f["image"], f["pid"], f["named"]) == ("NEW-AGENT", "kimi", 10728, "named")
    assert runner.calls[0]["text"] == "Raqib: NEW-AGENT\nhost, kimi pid 10728 (named)\n"
    line = [x for x in w.round_lines[-1]["lines"] if x["input_meta"].get("image") == "kimi"][0]
    assert line["input_meta"]["was"] == "act-root" and line["input_meta"]["started"] == "11/2/2026 10:21:05 AM"


def test_e2_an_act_root_alone_is_listed_not_new_agent(tmp_path):
    w, clock = make_host(tmp_path, ["benign/linux-desktop", "linux-agent"])
    run_rounds(w, clock, 2)
    assert w.findings == [] and [t["class"] for t in w.trees.values() if t["image"] == "agent"] == ["act-root"]


def test_e2_gone_and_back_is_not_new_again(tmp_path):
    runner = FakeRunner()
    w, clock = make_host(tmp_path, ["benign/windows-desktop", "windows", "benign/windows-desktop", "windows"],
                         runner=runner)
    run_rounds(w, clock, 4)
    assert [f["round"] for f in w.findings] == [2, 2, 2, 2]
    assert w.round_lines[2]["gone"] and w.round_lines[3]["back"]
    assert "back: 2100:claude:" in said(w)


def test_e2_the_tree_key_is_pid_image_and_creation_time(tmp_path):
    a = inv("windows")
    b = json.loads(json.dumps(a))
    for c in b["candidates"]:
        if c["pid"] == 7000:
            c["started"] = "11/1/2026 9:59:59 AM"   # the pid reused by a new scribe: a new tree
    w, clock = make_host(tmp_path, [inv("benign/windows-desktop"), a, b])
    run_rounds(w, clock, 3)
    assert [(f["image"], f["round"]) for f in w.findings if f["round"] == 3] == [("scribe", 3)]


def test_e2_both_rules_are_catalog_anchors_with_budgets_and_fixtures():
    rules = {r.id: r for r in RULES}
    for rule_id, severity in (("NEW-AGENT", "high"), ("AGENT-DARK-LIVE", "medium")):
        r = rules[rule_id]
        assert (r.kind, r.severity, r.status) == ("anchor", severity, "active") and 0 < r.fp_budget < 1
        assert r.holes and r.fixtures["positive"] and r.fixtures["negative"]
        report = fixtures.check_rule(r, ROOT, ())
        assert report["verdict"] == "ok" and report["fp_rate"] == 0.0, report
        assert all(p["fired"] for p in report["positives"])
    assert set(host.RULES) == {"NEW-AGENT", "AGENT-DARK-LIVE"}


def test_e2_the_fixtures_are_what_make_py_makes():
    made = host_fixtures.build()
    on_disk = {"%s/%s" % (p.parent.name, p.name): p.read_text(encoding="ascii")
               for rule in host.RULES for p in (RULE_FIXTURES / rule).glob("*.json")}
    assert made == on_disk
    used = {p.split("/", 3)[3] for r in RULES if r.id in host.RULES for k in ("positive", "negative")
            for p in r.fixtures[k]}
    assert used == set(on_disk)


def test_e2_the_rules_only_judge_host_lines(tmp_path):
    """A hook trace never fires them; the benign corpus counts as measured negatives."""
    trace = fixtures.load_fixture(ROOT / "tests" / "fixtures" / "quickstart-d7841d1-claude-code-2.1.301.log")[0]
    found, notes = engine.evaluate([r for r in RULES if r.id in host.RULES], trace)
    assert found == [] and notes == []


# --- E3: AGENT-DARK-LIVE ---------------------------------------------------------------------------

def test_e3_dark_three_rounds_knocks_once(tmp_path):
    runner = FakeRunner()
    w, clock = make_host(tmp_path, ["windows"] * 5, runner=runner)
    run_rounds(w, clock, 5)
    darks = [f for f in w.findings if f["rule_id"] == "AGENT-DARK-LIVE"]
    assert [(f["agent"], f["round"], f["streak"]) for f in darks] == [("codex", 3, 3), ("gemini", 3, 3)]
    assert runner.calls[0]["text"] == "Raqib: AGENT-DARK-LIVE\nhost, codex footprint, 3 rounds (round 3)\n"
    assert all(f["cites"] and f["cites"][0]["src"] == "footprints" for f in darks)
    st = json.loads(Path(w.state_path).read_text(encoding="ascii"))
    assert len(st["host"]["dark"]) == 2 and st["host"]["footprints"][2]["streak"] == 5


def test_e3_dark_then_linked_clears_with_a_note(tmp_path):
    w, clock = make_host(tmp_path, ["kimi-gone"] * 3 + ["kimi/one-sample", "kimi-gone"])
    run_rounds(w, clock, 5)
    darks = [f for f in w.findings if f["rule_id"] == "AGENT-DARK-LIVE"]
    assert [(f["agent"], f["round"]) for f in darks] == [("kimi", 3)]
    assert w.notes[-1] == "round 4: AGENT-DARK-LIVE of the kimi footprint cleared: linked to tree A1"
    assert "cleared: linked to tree A1" in said(w)
    fp = w.footprints["C:\\Users\\user\\.kimi"]
    assert (fp["state"], fp["streak"], fp["fired"]) == ("dark", 1, False)   # a new streak after round 5
    text, _ = w.finish()
    assert "round 4: AGENT-DARK-LIVE of the kimi footprint cleared" in text


def test_e3_a_round_without_an_inventory_neither_counts_nor_clears(tmp_path):
    seq = [inv("windows"), None, inv("windows"), inv("windows")]
    feed = iter(seq)

    def reader():
        got = next(feed)
        if got is None:
            raise OSError("snapshot failed")
        return got
    w, clock = make_host(tmp_path, reader=reader)
    run_rounds(w, clock, 4)
    assert [(f["rule_id"], f["round"]) for f in w.findings] == [("AGENT-DARK-LIVE", 4)] * 2
    assert w.holes[0]["kind"] == "reader-failed" and "OSError: snapshot failed" in w.holes[0]["detail"]


# --- E4: silence is said; a late reader is a hole and a knock ----------------------------------------

def test_e4_a_round_with_no_candidate_prints_one_line():
    empty = dict(inv("benign/windows-desktop"), candidates=[], act_roots=[])
    w, clock = make_host(Path(os.environ["HOME"]).parent, [empty, empty])
    run_rounds(w, clock, 2)
    lines = [x for x in said(w).splitlines() if " round " in x or "] round" in x]
    assert len(lines) == 2
    assert re.search(r"round 2: 92 records read, \d+ holes; NO AGENT SEEN \(window .*\)\. Not a clearance\.$",
                     lines[1]), lines
    text, code = w.finish()
    assert "NO AGENT SEEN in 2 round(s) with an inventory (records read: 92, 92). Not a clearance." in text


def test_e4_a_reader_not_back_in_2t_is_a_hole_and_a_knock_and_no_second_reader(tmp_path):
    release = threading.Event()
    started = []

    def reader():
        started.append(1)
        if len(started) == 1:
            release.wait(30)
        return inv("linux")
    runner = FakeRunner()
    w, clock = make_host(tmp_path, reader=reader, runner=runner, every=1)
    w.tick()
    clock.t += 1.5
    w.tick()
    assert w.holes == [] and len(started) == 1
    clock.t += 0.6                          # 2.1 s > 2 x T
    w.tick()
    assert [h["kind"] for h in w.holes] == ["reader-late"] and runner.calls[0]["text"] == \
        "Raqib: HOST-HOLE\nhost, round 1, reader not back in 2 s\n"
    assert json.loads(Path(w.state_path).read_text(encoding="ascii"))["band"] == "READER LATE"
    clock.t += 10
    w.tick()
    assert len(started) == 1 and w.rounds == 1   # never two readers at once
    release.set()
    w.tick(wait=30)
    assert w.applied == 1 and w.round_lines[-1]["late"] is True and "round 1 (late," in said(w)
    w.tick(wait=30)
    assert len(started) == 2 and w.rounds == 2   # the next round starts once it is back
    text, code = w.finish()
    assert code == 1 and "1 reader hole(s)" in text


def test_e4_a_reader_out_at_the_end_is_a_hole(tmp_path):
    release = threading.Event()
    w, clock = make_host(tmp_path, reader=lambda: release.wait(30) and inv("linux"))
    w.tick()
    text, code = w.finish()
    release.set()
    assert "reader-out: round 1: the reader was still out at the end" in text
    assert "no round gave an inventory: nothing read (A3)" in text and code == 1


# --- E5: the page, the registry, watch.json --------------------------------------------------------

def test_e5_the_host_page_has_the_band_and_the_trees_and_runs_no_script(tmp_path):
    w, clock = make_host(tmp_path, ["benign/windows-desktop", "windows"])
    run_rounds(w, clock, 2)
    page = w.page()
    assert 'content="%s"' % ui.CSP in page and "<script" not in page.lower() and "on" + "click" not in page
    for item in ("trees now: 4", "new this session: 4", "dark: 2", "last round: 2 at "):
        assert item in page, item
    assert '<h2 id="host">Host (6 trees seen, 4 now)</h2>' in page
    assert "<td>scribe</td><td>7000</td><td>candidate</td><td>unknown</td>" in page
    assert "named: image claude is the catalog&#x27;s claude" in page
    assert "win-process:" in page and "NEW-AGENT" in page and "AGENT-DARK" not in page.split("Host findings")[1][:20]


def test_e5_the_page_escapes_what_the_host_holds(tmp_path):
    bad = inv("windows")
    for c in bad["candidates"]:
        c["image"] = "<img src=x>" + c["image"]
    w, clock = make_host(tmp_path, [inv("benign/windows-desktop"), bad])
    run_rounds(w, clock, 2)
    assert "<img" not in w.page() and "&lt;img src=x&gt;" in w.page()


def test_e5_watch_host_from_the_cli_registers_a_host_row_and_serves(tmp_path, monkeypatch, _home):
    monkeypatch.setattr(host, "live_reader", lambda catalog, window, platform: lambda: inv("linux"))
    monkeypatch.setattr(host, "_sleep", lambda s: None)
    out = io.StringIO()
    code = cli.main(["watch", "--host", "--every", "1", "--rounds", "2", "--no-notify", "--no-open", "--port", "0"],
                    out=out)
    text = out.getvalue()
    assert code == 1 and "raqib watch --host: 2 round(s) done (--rounds)" in text
    assert "RESULT: ALARM (exit 1)" in text and "TREES SEEN: 2" in text
    reg = json.loads((_home / ".raqib" / "watches.json").read_text(encoding="ascii"))
    (row,) = reg["watches"]
    assert (row["project"], row["mode"], row["status"]) == ("host", "host", "finished")
    assert row["trace"] == str(_home / ".raqib" / "host" / "rounds.jsonl")
    st = json.loads(Path(row["trace"] + ".watch.json").read_text(encoding="ascii"))
    assert st["mode"] == "host" and st["finished"] and st["band"] == "FINISHED"
    # A4: nothing written outside ~/.raqib
    assert sorted(p.name for p in _home.iterdir()) == [".raqib"]
    assert sorted(p.name for p in (_home / ".raqib").iterdir()) == ["host", "watches.json"]
    assert sorted(p.name for p in (_home / ".raqib" / "host").iterdir()) == [
        "inventory.json", "rounds.jsonl", "rounds.jsonl.watch.json"]


def test_e5_a_host_row_on_another_watch_page_is_judged_like_any_row(tmp_path, _home):
    w, clock = make_host(tmp_path, ["linux"])
    run_rounds(w, clock, 1)
    raw = {"pid": os.getpid(), "project": "host", "trace": w.rounds_path, "started": w.at(w.t0), "port": 1}
    row = ui.judge_row(raw, w.wall(), 30, alive=lambda pid: True)
    assert row["watch_band"] == "WATCHING" and row["word"] == "WATCHING"


def test_e1_a_stop_ends_the_host_watch_with_the_final_report(tmp_path, _home):
    stop = watch.Stop()
    running = host.start(CATALOG, RULES, every=10, no_open=True, no_notify=True, port=0, out=io.StringIO(),
                         err=io.StringIO(), environ={}, home=str(_home), reader=lambda: inv("linux"),
                         platform="test")
    try:
        stop.set("the window's Stop")
        crash = host.loop(running, stop)
        text, code = host.conclude(running, crash)
    finally:
        host.close(running)
    assert crash is None and code == 1 and "stopped (the window's Stop)" in running.out.getvalue()
    assert text.startswith("Raqib watch --host") and "RESULT: ALARM (exit 1)" in text


# --- E6 / cli: usage ---------------------------------------------------------------------------------

@pytest.mark.parametrize("argv,message", [
    (["watch", "--host", "proj"], "--host watches this host, not a project"),
    (["watch", "--host", "--log", "x.jsonl"], "--host keeps its record under ~/.raqib/host/"),
    (["watch", "--host", "--every", "0"], "--every must be a number of seconds from 0.1 to 86400"),
    (["watch", "--host", "--rounds", "0"], "--rounds must be a whole number from 1 to 1000000"),
    (["watch", "--rounds", "2"], "--every, --window and --rounds apply to watch --host only"),
])
def test_e6_usage_errors_exit_2(argv, message, capsys):
    assert cli.main(argv, out=io.StringIO()) == 2
    assert message in capsys.readouterr().err


def test_e6_host_mode_installs_nothing_and_touches_no_project():
    source = (ROOT / "raqib" / "host.py").read_text(encoding="ascii")
    code = source.split('"""', 2)[2]
    for banned in ("install_project", "install_hooks", "subprocess", "os.kill", "signal", "socket.", "urllib",
                   "http.client", "choose_trace"):
        assert banned not in code, banned


def test_e6_ci_and_readme_and_questions():
    gate = (ROOT / ".github" / "workflows" / "gate.yml").read_text(encoding="utf-8")
    assert "raqib watch --host --every 1 --rounds 2 --no-notify" in gate
    assert gate.count("runs-on:") == 2   # two jobs with matrices: six jobs, as before
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "`raqib watch --host`" in readme
    text = QUESTIONS.read_text(encoding="utf-8")
    for q in ("Q-1", "Q-2", "Q-3", "Q-4"):
        assert q in text
    assert "2496 passed, 16 skipped" in text
