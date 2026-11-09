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
            assert line["input_meta"]["cites"] and all(re.match(r"[a-z-]+(-[0-9]+)?$", c["src"])
                                                       and isinstance(c["line"], int)
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
    assert code == 1 and "RESULT: ALARM (exit 1: a finding)" in text
    assert "TREES SEEN: 6 (4 now)" in text
    assert re.search(r"\[candidate\] pid 7000 scribe \(unknown\): now; first round 2; last round 2; 1 act\(s\);.*"
                     r"NEW-AGENT-UNKNOWN sent", text), text
    assert "[candidate] pid 5100 explorer (unknown): gone; first round 1 (history, not knocked)" in text
    assert re.search(r"\[candidate\] pid 4100 msedge \(unknown\): now; first round 2 \(benign: c:/program files"
                     r" \(x86\)/\*, not knocked\)", text), text
    assert "FINDINGS: 3" in text and "cites win-process:" in text


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
    # C-5: each tree knocks under its own rate-limit id; C-1c: named high, unknown medium; C-1d: msedge
    # from Program Files (x86) is benign, listed and not knocked
    assert texts == ["Raqib: NEW-AGENT claude\nhost, claude pid 2100 (named)\n",
                     "Raqib: NEW-AGENT nimbus\nhost, nimbus pid 3300 (named)\n",
                     "Raqib: NEW-AGENT-UNKNOWN scribe\nhost, scribe pid 7000 (unknown)\n"]
    assert [(f["rule_id"], f["severity"]) for f in w.findings] == [
        ("NEW-AGENT", "high"), ("NEW-AGENT", "high"), ("NEW-AGENT-UNKNOWN", "medium")]
    assert {f["image"]: (f["named"], f["round"]) for f in w.findings} == {
        "claude": ("named", 2), "nimbus": ("named", 2), "scribe": ("unknown", 2)}
    assert [f["notice"] for f in w.findings] == ["sent", "sent", "sent"]
    assert w.round_lines[1]["benign"] == ["4100:msedge:11/1/2026 8:30:02 AM"]
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
    assert runner.calls[0]["text"] == "Raqib: NEW-AGENT kimi\nhost, kimi pid 10728 (named)\n"
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
    assert [f["round"] for f in w.findings] == [2, 2, 2]
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
    """C-1c, C-1e, C-13: three anchors of class HOST; each budget is the rate measured on its negatives."""
    rules = {r.id: r for r in RULES}
    for rule_id, severity, rate in (("NEW-AGENT", "high", 0.0), ("NEW-AGENT-UNKNOWN", "medium", 0.4),
                                    ("AGENT-DARK-LIVE", "medium", 0.0)):
        r = rules[rule_id]
        assert (r.kind, r.cls, r.severity, r.status) == ("anchor", "HOST", severity, "active") and 0 <= r.fp_budget < 1
        assert r.holes and r.fixtures["positive"] and r.fixtures["negative"]
        report = fixtures.check_rule(r, ROOT, ())
        assert report["verdict"] == "ok" and report["fp_rate"] == rate == r.fp_budget, report
        assert all(p["fired"] for p in report["positives"])
    assert set(host.RULES) == {"NEW-AGENT", "NEW-AGENT-UNKNOWN", "AGENT-DARK-LIVE", "HOST-UNWATCHED", "HOST-RHYTHM"}   # M7.2b


def test_e2_the_fixtures_are_what_make_py_makes():
    made = host_fixtures.build()
    on_disk = {"%s/%s" % (p.parent.name, p.name): p.read_text(encoding="ascii")
               for rule in host.RULES for p in (RULE_FIXTURES / rule).glob("*.json")}
    # M7.2b: the host-source fixtures of NET-TOOL and DESTRUCT-CMD are made too
    on_disk.update({name: (RULE_FIXTURES / name).read_text(encoding="ascii") for name in host_fixtures.SOURCE_SCENARIOS})
    assert made == on_disk
    used = {p.split("/", 3)[3] for r in RULES if r.id in host.RULES for k in ("positive", "negative")
            for p in r.fixtures[k]}
    assert used | set(host_fixtures.SOURCE_SCENARIOS) == set(on_disk)


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
    assert "NO AGENT SEEN in 2 round(s) that read records (records read: 92, 92). Not a clearance." in text


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
    # C-10: a late round is a hole, exit 3 (incomplete), not an alarm
    assert code == 3 and "1 round(s) whose reader was not back within 2 s (round 1): a hole" in text


def test_e4_a_reader_out_at_the_end_is_a_hole(tmp_path):
    release = threading.Event()
    w, clock = make_host(tmp_path, reader=lambda: release.wait(30) and inv("linux"))
    w.tick()
    text, code = w.finish()
    release.set()
    assert "reader-out: round 1: the reader was still out at the end" in text
    assert "no round gave an inventory: nothing read (A3)" in text and code == 3   # C-10
    assert "RESULT: INCOMPLETE (exit 3: a round could not be read or the watch has a hole)" in text


# --- E5: the page, the registry, watch.json --------------------------------------------------------

def test_e5_the_host_page_has_the_band_and_the_trees_and_runs_no_script(tmp_path):
    w, clock = make_host(tmp_path, ["benign/windows-desktop", "windows"])
    run_rounds(w, clock, 2)
    page = w.page()
    assert 'content="%s"' % ui.CSP in page and "<script" not in page.lower() and "on" + "click" not in page
    for item in ("trees now: 4", "new this session: 3", "dark: 2", "last round: 2 at "):
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
    assert code == 0 and "raqib watch --host: 2 round(s) done (--rounds)" in text   # C-10: history only
    assert "RESULT: CLEAN (exit 0: trees listed, nothing new)" in text and "TREES SEEN: 2" in text
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
        "inventory.json", "rounds.jsonl", "rounds.jsonl.watch.json", "sources"]   # M7.2b: the per-tree sources


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
    assert crash is None and "stopped (the window's Stop)" in running.out.getvalue()
    # the first tick read round 1 (history only), then Stop ended it: C-10 exit 0 with the trees named
    assert text.startswith("Raqib watch --host") and code == 0 and "RESULT: CLEAN (exit 0" in text


# --- E6 / cli: usage ---------------------------------------------------------------------------------

@pytest.mark.parametrize("argv,message", [
    (["watch", "--host", "proj"], "--host watches this host, not a project"),
    (["watch", "--host", "--log", "x.jsonl"], "--host keeps its record under ~/.raqib/host/"),
    (["watch", "--host", "--every", "0"], "--every must be a number of seconds from 0.1 to 86400"),
    (["watch", "--host", "--rounds", "0"], "--rounds must be a whole number from 1 to 1000000"),
    (["watch", "--rounds", "2"], "--every, --window, --rounds, --attach-hooks and --suspect apply to watch --host only"),
    (["watch", "--attach-hooks"], "--every, --window, --rounds, --attach-hooks and --suspect apply to watch --host only"),
])
def test_e6_usage_errors_exit_2(argv, message, capsys):
    assert cli.main(argv, out=io.StringIO()) == 2
    assert message in capsys.readouterr().err


def test_e6_host_mode_installs_nothing_and_touches_no_project():
    """M7.2b (H-1, A4): install_project is called in one method only,
    _attach_hooks, after its `if not self.attach_hooks: return`; nothing
    else of host.py may name it, and nothing signals or dials out. REDO I-2:
    choose_trace is called nowhere (the trace is always Raqib's own default
    under ~/.raqib/traces, never one the project's settings name)."""
    import ast
    source = (ROOT / "raqib" / "host.py").read_text(encoding="ascii")
    code = source.split('"""', 2)[2]
    for banned in ("install_hooks", "subprocess", "os.kill", "signal", "socket.", "urllib", "http.client"):
        assert banned not in code, banned
    tree = ast.parse(source)
    callers = {}
    for fn in ast.walk(tree):
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for node in ast.walk(fn):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in (
                        "install_project", "choose_trace"):
                    callers.setdefault(node.func.attr, set()).add(fn.name)
    assert callers == {"install_project": {"_attach_hooks"}}
    (method,) = [f for f in ast.walk(tree) if isinstance(f, ast.FunctionDef) and f.name == "_attach_hooks"]
    first = [n for n in method.body if not (isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant))][0]
    assert isinstance(first, ast.If) and ast.unparse(first.test) == "not self.attach_hooks"
    assert isinstance(first.body[0], ast.Return)


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


# --- M7.2 REDO: ADR-0007 Amendment C (C-1..C-13), one test per behaviour (C-14, D-8) ----------------

def _rule_doc(match, **kw):
    doc = {"id": "TEST-GATE", "title": "t", "class": "HOST", "kind": "anchor", "severity": "low", "fp_budget": 0.5,
           "match": match, "fixtures": {"positive": ["p.json"], "negative": ["n.json"]}}
    doc.update(kw)
    return doc


def _line(seq, **fields):
    rec = {"ts": "2026-11-04T10:00:00.000Z", "seq": seq, "session_id": "s", "phase": "pre", "tool": "Bash",
           "cwd": "/w", "input_meta": {}}
    rec.update(fields)
    return rec


def test_redo_c1a_a_negative_no_line_of_which_passes_the_gate_is_unmeasured(tmp_path):
    (tmp_path / "hook.json").write_text(json.dumps([_line(1)]), encoding="ascii")
    (tmp_path / "host.json").write_text(json.dumps([_line(1, tool="HostTree", source="os",
                                                          input_meta={"x": 0})]), encoding="ascii")
    rule = engine.compile_rule(_rule_doc({"all": [{"field": "tool", "eq": "HostTree"}, {"field": "source", "eq": "os"},
                                                  {"field": "input_meta.x", "eq": 1}]}))
    assert fixtures.gate_of(rule) == {"tool": "HostTree", "source": "os"}
    assert fixtures.outcome(rule, tmp_path / "hook.json") == (False, set(), False)    # cannot match: unmeasured
    assert fixtures.outcome(rule, tmp_path / "host.json") == (False, set(), True)     # passes the gate: measured
    ungated = engine.compile_rule(_rule_doc({"field": "input_meta.x", "eq": 1}))
    assert fixtures.gate_of(ungated) == {} and fixtures.outcome(ungated, tmp_path / "hook.json")[2] is False
    # a code rule declares its gate
    assert fixtures.outcome(ungated, tmp_path / "host.json", gate={"tool": "Bash"}) == (False, set(), False)


def test_redo_c1a_check_rules_counts_before_and_after_are_in_the_questions_file():
    """The measured counts move only where a negative holds no line of the rule's gate (questions file)."""
    reports = {r["rule_id"]: r for r in fixtures.check_catalog(RULES, ROOT, cli.benign_default(ROOT))}
    got = {k: (r["measured"], r["unmeasured"]) for k, r in reports.items()}
    # M7.2b: DESTRUCT-CMD and NET-TOOL gain their host-source negative; DESTRUCT-CMD's `tool: Bash` moved inside an
    # `any` (Bash or source host + HostChild), so it has no top-level gate (C-1a, as NET-TOOL never had) and its two
    # formerly unmeasured benign files count as measured (Q-6 of the M7.2b questions file); HOST-UNWATCHED joins.
    # M7.5 (A6, re-measured): AGENT-DARK-LIVE gains negative-live-then-gone and negative-linked-again (E1),
    # HOST-RHYTHM negative-os-two-cycles (E2).
    # M7.5 REDO N-2: AGENT-DARK-LIVE's two was_live negatives are not listed (its match cannot see them): 2 again.
    # M7.6c REDO E-2: AGENT-DARK-LIVE and HOST-RHYTHM gain their edge negatives (M7.6c questions file)
    assert got == {"AGENT-DARK-LIVE": (3, 10), "DESTRUCT-CMD": (11, 0), "DRIFT-FILES": (4, 7), "EDIT-NO-TEST": (9, 0),
                   "HOST-RHYTHM": (7, 8), "HOST-UNWATCHED": (4, 8),
                   "LANDED-NO-GATE": (8, 2), "NET-TOOL": (11, 0), "NEW-AGENT": (5, 8), "NEW-AGENT-UNKNOWN": (5, 8),
                   "SCOPE-CWD-MOVED": (10, 0), "SCOPE-CWD-ROOT": (10, 0), "SCOPE-PATH": (10, 0),
                   "SECRET-OUTPUT": (7, 2)}
    text = (ROOT / "docs" / "review" / "2026-11-04-M7.2b-questions.md").read_text(encoding="utf-8")
    text += (ROOT / "docs" / "review" / "2026-11-04-M7.4-questions.md").read_text(encoding="utf-8")   # M7.4: HOST-RHYTHM
    text += (ROOT / "docs" / "review" / "2026-11-09-M7.5-questions.md").read_text(encoding="utf-8")   # M7.5: both again
    text += (ROOT / "docs" / "review" / "2026-11-09-M7.6c-questions.md").read_text(encoding="utf-8")   # M7.6c REDO: both again
    for rule_id, (m, u) in got.items():
        assert re.search(r"%s +ok .* %d measured, %d unmeasured" % (re.escape(rule_id), m, u), text), rule_id


def test_redo_c1b_the_benign_arrivals_are_made_for_every_benign_discover_fixture():
    assert host_fixtures.BENIGN == ["benign/linux-desktop", "benign/windows-desktop"]
    for name in host_fixtures.BENIGN:
        before = inv(name + host_fixtures.BEFORE)
        assert before["candidates"] == [] and before["act_roots"] == [] and before["result"] == "none-seen", name
        assert host_fixtures.SCENARIOS["NEW-AGENT/negative-arrival-%s.json" % name.split("/")[1]] == [
            name + host_fixtures.BEFORE, name]
    for rule_id in ("NEW-AGENT", "NEW-AGENT-UNKNOWN", "AGENT-DARK-LIVE"):
        neg = next(r for r in RULES if r.id == rule_id).fixtures["negative"]
        assert {"tests/fixtures/rules/NEW-AGENT/negative-arrival-%s.json" % n.split("/")[1]
                for n in host_fixtures.BENIGN} <= set(neg), rule_id


def test_redo_c1c_named_is_high_and_unknown_is_medium(tmp_path):
    w, clock = make_host(tmp_path, ["benign/linux-desktop:before", "benign/linux-desktop", "linux"])
    run_rounds(w, clock, 3)
    got = {(f["image"], f["rule_id"], f["severity"]) for f in w.findings}
    assert got == {("jetbrains-toolbox", "NEW-AGENT-UNKNOWN", "medium"), ("claude", "NEW-AGENT", "high"),
                   ("environment-manager", "NEW-AGENT", "high")}


def test_redo_c1d_benign_needs_the_name_and_a_system_directory_from_the_record():
    cat = CATALOG
    assert discover.benign_image("msedge", r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                                 "record", cat, "c") == "c:/program files (x86)/*"
    assert discover.benign_image("explorer", r"C:\Windows\explorer.exe", "record", cat, "c") == "c:/windows/*"
    assert discover.benign_image("firefox", "/usr/lib/firefox/firefox", "record", cat) == "/usr/*"
    # the evasion's limits: a name outside the directories, a denied or blank path, argv[0], a dotted path
    assert discover.benign_image("code", r"C:\Users\u\AppData\Local\Programs\Microsoft VS Code\Code.exe",
                                 "record", cat) is None
    assert discover.benign_image("firefox", "/home/u/.local/firefox", "record", cat) is None
    assert discover.benign_image("msedge", "", "record", cat) is None
    assert discover.benign_image("msedge", None, None, cat) is None
    assert discover.benign_image("firefox", "/usr/lib/firefox/firefox", "argv", cat) is None
    assert discover.benign_image("firefox", "/usr/../home/u/firefox", "record", cat) is None
    assert discover.benign_image("agent", "/usr/bin/agent", "record", cat) is None        # not a listed name
    assert discover.benign_image("claude", "/usr/bin/firefox", "record", cat) is None     # name and path disagree
    assert discover.benign_image("firefox", "/USR/lib/firefox/firefox", "record", cat) is None   # POSIX is case-exact


def test_redo_c1d_benign_images_is_a_signature_with_its_evasion_in_the_rules_holes():
    spec = CATALOG["benign_images"]
    assert "explorer" in spec["names"] and "runner.worker" not in spec["names"] and spec["evasion"]
    assert any("takes a benign program's name" in e for e in spec["evasion"])
    for rule_id in ("NEW-AGENT", "NEW-AGENT-UNKNOWN"):
        rule = next(r for r in RULES if r.id == rule_id)
        assert any("benign_images" in h and "benign program's name" in h for h in rule.holes), rule_id
        assert {"field": "input_meta.benign", "eq": False} in rule.doc["match"]["all"], rule_id
    text = Path(discover.CATALOG).read_text(encoding="utf-8")
    bad = text.replace("benign_images:\n  kind: signature", "benign_images:\n  kind: anchor")
    path = Path(os.environ["HOME"]) / "endpoints.yaml"
    path.write_text(bad, encoding="utf-8")
    with pytest.raises(discover.CatalogError, match="benign_images.kind"):
        discover.load_catalog(str(path))
    path.write_text(re.sub(r"(benign_images:\n(?:.*\n)*?)  evasion:\n(    - .*\n)+", r"\1  evasion: []\n", text),
                    encoding="utf-8")
    with pytest.raises(discover.CatalogError, match="benign_images.evasion"):
        discover.load_catalog(str(path))


def test_redo_c1d_a_benign_new_tree_is_listed_with_benign_not_knocked(tmp_path):
    runner = FakeRunner()
    w, clock = make_host(tmp_path, ["benign/windows-desktop:before", "benign/windows-desktop"], runner=runner)
    run_rounds(w, clock, 2)
    explorer = next(t for t in w.trees.values() if t["image"] == "explorer")
    assert explorer["benign"] and explorer["benign_by"] == "c:/windows/*" and not explorer["knocked"]
    line = next(x for x in w.round_lines[-1]["lines"] if x["input_meta"].get("image") == "explorer")
    assert line["input_meta"]["benign"] is True
    assert [(f["image"], f["rule_id"]) for f in w.findings] == [("code", "NEW-AGENT-UNKNOWN")]   # user install
    assert "<span class=\"tag\">benign</span>" in w.page()


def test_redo_c1e_each_budget_names_the_fixture_it_came_from():
    for rule_id in ("NEW-AGENT", "NEW-AGENT-UNKNOWN", "AGENT-DARK-LIVE"):
        rule = next(r for r in RULES if r.id == rule_id)
        head = Path(rule.source).read_text(encoding="ascii").split("\nfp_budget:")[0].rsplit("\nseverity:", 1)[1]
        assert "C-1e" in head and "negative-arrival-linux-desktop.json" in head, rule_id
        report = fixtures.check_rule(rule, ROOT, cli.benign_default(ROOT))
        assert report["fp_rate"] == rule.fp_budget, (rule_id, report["fp_rate"])


def test_redo_c2_every_line_carries_the_run_and_seqs_continue(tmp_path):
    w, clock = make_host(tmp_path, ["linux", "linux"])
    run_rounds(w, clock, 2)
    w.finish()
    first, last1 = w.run, w.seq
    clock2 = Clock(5000.0)
    w2 = host.HostWatch(lambda: inv("linux"), CATALOG, RULES, make_notifier(FakeRunner()), every=10,
                        out=io.StringIO(), err=io.StringIO(), clock=clock2, wall=lambda: 1793800000.0 + clock2.t,
                        home=str(tmp_path / "home"), platform="test")
    assert w2.run != first and w2.first_seq == last1
    w2.tick(wait=30)
    lines = [json.loads(x) for x in Path(w.rounds_path).read_text(encoding="ascii").splitlines()]
    assert [r["run"] for r in lines] == [first, first, w2.run]
    assert all(l["input_meta"]["run"] == r["run"] for r in lines for l in r["lines"])
    seqs = [(r["run"], l["seq"]) for r in lines for l in r["lines"]]
    assert len(seqs) == len(set(seqs)) and len({q for _, q in seqs}) == len(seqs)   # a seq resolves to one line
    assert min(l["seq"] for l in lines[2]["lines"]) == last1 + 1
    assert json.loads(Path(w.inventory_path).read_text(encoding="ascii"))["host_watch"]["run"] == w2.run
    assert json.loads(Path(w.state_path).read_text(encoding="ascii"))["run"] == w2.run


def test_redo_c2_a_corrupt_last_line_is_a_hole_and_seqs_continue_after_the_last_good_one(tmp_path):
    w, clock = make_host(tmp_path, ["linux"])
    run_rounds(w, clock, 1)
    w.finish()
    last = w.seq
    with open(w.rounds_path, "a", encoding="ascii") as f:
        f.write('{"round": 2, "lines": [{"seq": 9')     # a torn write
    w2, clock2 = make_host(tmp_path, ["linux"])
    assert w2.first_seq == last and [h["kind"] for h in w2.holes] == ["rounds-corrupt"]
    run_rounds(w2, clock2, 1)
    lines = Path(w.rounds_path).read_text(encoding="ascii").splitlines()
    assert json.loads(lines[-1])["lines"][0]["seq"] == last + 1 and lines[-2].startswith('{"round": 2, "lines"')


def test_redo_c2_a_second_host_watch_on_a_fresh_home_is_refused(tmp_path, _home, monkeypatch, capsys):
    w, clock = make_host(tmp_path, ["linux"])
    w.tick(wait=30)                                   # running: a fresh heartbeat, not finished
    with pytest.raises(host.HostError, match="one host watch per home"):
        make_host(tmp_path, ["linux"])
    monkeypatch.setattr(host, "live_reader", lambda catalog, window, platform: lambda: inv("linux"))
    state = json.loads(Path(w.state_path).read_text(encoding="ascii"))
    state["heartbeat"] = host.iso(datetime.datetime.now(datetime.timezone.utc))
    Path(str(_home / ".raqib" / "host" / "rounds.jsonl.watch.json")).parent.mkdir(parents=True, exist_ok=True)
    Path(str(_home / ".raqib" / "host" / "rounds.jsonl.watch.json")).write_text(json.dumps(state), encoding="ascii")
    assert cli.main(["watch", "--host", "--rounds", "1", "--no-notify", "--no-open", "--port", "0"],
                    out=io.StringIO()) == 2
    err = capsys.readouterr().err
    assert err.count("\n") == 1 and "one host watch per home" in err
    clock.t += 100                                    # stale (or finished): the next watch may start
    w.finish()
    make_host(tmp_path, ["linux"])


def test_redo_c3_rounds_end_at_the_outstanding_readers_deadline(tmp_path, monkeypatch):
    never = threading.Event()
    w, clock = make_host(tmp_path, reader=lambda: never.wait(3600), rounds=1, every=1)
    monkeypatch.setattr(host, "_sleep", lambda s: setattr(clock, "t", clock.t + s))
    running = host.Running(w, None, w.notifier, None, True, {}, io.StringIO(), io.StringIO())
    w.port, w.url = {"warning": None}, "http://127.0.0.1:1/"
    assert host.loop(running) is None
    assert clock.t - w.t0 <= w.deadline_seconds + host.POLL_SECONDS
    assert "past its deadline (2 s) and is left out: a hole" in running.out.getvalue()
    text, code = w.finish()
    assert code == 3 and "reader-out: round 1" in text


def test_redo_c3_stop_ends_at_the_outstanding_readers_deadline(tmp_path, monkeypatch):
    never = threading.Event()
    w, clock = make_host(tmp_path, reader=lambda: never.wait(3600), every=1)

    class FakeStop:
        reason = "the window's Stop"

        def is_set(self):
            return clock.t - w.t0 >= 0.5

        def wait(self, s):
            clock.t += s
            return self.is_set()
    monkeypatch.setattr(host, "_sleep", lambda s: setattr(clock, "t", clock.t + s))
    running = host.Running(w, None, w.notifier, None, True, {}, io.StringIO(), io.StringIO())
    w.port, w.url = {"warning": None}, "http://127.0.0.1:1/"
    assert host.loop(running, FakeStop()) is None
    assert w.rounds == 1 and clock.t - w.t0 <= w.deadline_seconds + host.POLL_SECONDS
    assert "stopped (the window's Stop)" in running.out.getvalue()


def test_redo_c4_a_round_one_act_root_that_becomes_a_candidate_knocks(tmp_path):
    w, clock = make_host(tmp_path, ["kimi/one-sample", "kimi/two-samples"])
    run_rounds(w, clock, 2)
    assert [(f["image"], f["rule_id"]) for f in w.findings] == [("kimi", "NEW-AGENT")]
    assert "tests/fixtures/rules/NEW-AGENT/positive-act-root-becomes-candidate.json" in next(
        r for r in RULES if r.id == "NEW-AGENT").fixtures["positive"]


def test_redo_c5_four_new_trees_in_one_round_give_four_toasts_and_folds_are_reported(tmp_path):
    base = inv("benign/linux-desktop:before")
    four = json.loads(json.dumps(inv("windows")))
    four["candidates"] = [c for c in four["candidates"] if c["image"] != "msedge"]
    extra = json.loads(json.dumps(next(c for c in four["candidates"] if c["image"] == "scribe")))
    extra.update(pid=7100, id="C9")
    four["candidates"].append(extra)
    runner = FakeRunner()
    w, clock = make_host(tmp_path, [base, four, four], runner=runner)
    run_rounds(w, clock, 2)
    assert len(runner.calls) == 4 and [f["notice"] for f in w.findings] == ["sent"] * 4
    assert sorted(c["text"].split("\n")[1] for c in runner.calls) == [
        "host, claude pid 2100 (named)", "host, nimbus pid 3300 (named)", "host, scribe pid 7000 (unknown)",
        "host, scribe pid 7100 (unknown)"]
    assert w.notifier.on_folds == w._folds
    # a second knock of one tree within the minute folds and is reported waiting, then delivered
    w.notifier.notify("NEW-AGENT", "claude pid 2100 (named)", clock.t, token=(w.findings[0], "notice"),
                      limit_id="NEW-AGENT pid 2100")
    text, _ = w.finish(now=clock.t)
    assert "folded 1 (1 still waiting)" in text
    clock.t += 61
    w.tick()
    assert w.findings[0]["notice"] == "folded: sent as 1 more"


def test_redo_c6_each_host_line_carries_the_cited_lines_text_bounded_and_safe(tmp_path):
    bad = json.loads(json.dumps(inv("windows")))
    bad["candidates"][0]["cites"][0]["text"] = "x\x1b[31m" + "y" * 1000
    w, clock = make_host(tmp_path, [inv("benign/windows-desktop"), bad])
    run_rounds(w, clock, 2)
    lines = [json.loads(x) for x in Path(w.rounds_path).read_text(encoding="ascii").splitlines()]
    for r in lines:
        for l in r["lines"]:
            for c in l["input_meta"]["cites"]:
                assert set(c) == {"src", "line", "text"} and c["text"] and len(c["text"]) <= host.CITE_TEXT_MAX
                assert all(ch.isprintable() for ch in c["text"])
    claude = next(l for l in lines[1]["lines"] if l["input_meta"].get("image") == "claude")
    assert claude["input_meta"]["cites"][0]["text"].startswith("x?[31myyy") and "..." in claude["input_meta"]["cites"][0]["text"]


def test_redo_c7_the_band_says_reader_failed_or_late_before_watching(tmp_path):
    feed = iter([inv("linux"), None])

    def reader():
        got = next(feed)
        if got is None:
            raise OSError("denied")
        return got
    w, clock = make_host(tmp_path, reader=reader)
    run_rounds(w, clock, 1)
    assert json.loads(Path(w.state_path).read_text(encoding="ascii"))["band"] == "WATCHING"
    run_rounds(w, clock, 1)
    st = json.loads(Path(w.state_path).read_text(encoding="ascii"))
    assert st["band"] == "HOST READER FAILED" and ui.status(st)[1] == "alarm"
    page = w.page()
    assert '<span class="badge state alarm">HOST READER FAILED</span>' in page and "OSError: denied" in page
    late = dict(st, host=dict(st["host"], last_round=dict(st["host"]["last_round"], error=None, late=True,
                                                            seconds=25.0)))
    assert ui.status(late)[0] == "READER LATE"
    assert '<span class="badge state alarm">READER LATE</span>' in ui.host_page(late)


def test_redo_c8_the_ci_step_checks_discovers_candidates_and_stderr():
    gate = (ROOT / ".github" / "workflows" / "gate.yml").read_text(encoding="utf-8")
    step = gate.split("raqib watch --host --every 1 --rounds 2 --no-notify", 1)[1].split("# Doctor from the venv", 1)[0]
    assert "raqib discover $one --json -o host-discover.json" in gate and 'one="--samples 1"' in gate
    assert "host-err.txt" in step and "Traceback" in step and "gone between" in step   # D-7 replaced the subset
    assert 'expect = 0 if os.name == "nt"' in step


def test_redo_c10_exit_codes_clean_finding_incomplete(tmp_path):
    w, clock = make_host(tmp_path, ["linux", "linux"])
    run_rounds(w, clock, 2)
    text, code = w.finish()
    assert code == 0 and "CLEAN: 2 tree(s) listed, none new" in text and "RESULT: CLEAN (exit 0" in text
    w, clock = make_host(tmp_path, ["benign/windows-desktop", "windows"])
    run_rounds(w, clock, 2)
    assert w.finish()[1] == 1
    feed = iter([inv("linux"), None])

    def reader():
        got = next(feed)
        if got is None:
            raise OSError("x")
        return got
    w, clock = make_host(tmp_path, reader=reader)
    run_rounds(w, clock, 2)
    text, code = w.finish()
    assert code == 3 and "1 round(s) could not be read (round 2)" in text
    empty = dict(inv("benign/windows-desktop"), candidates=[], act_roots=[], result="none-seen")
    w, clock = make_host(tmp_path, [empty])
    run_rounds(w, clock, 1)
    assert w.finish()[1] == 0 and "RESULT: NONE-SEEN (exit 0" in w.final_text


def test_redo_c11_no_set_aside_in_test_rules():
    text = (ROOT / "tests" / "test_rules.py").read_text(encoding="utf-8")
    assert "host_rules" not in text and "M72_NOTE" in text


def test_redo_c12_dark_rounds_is_the_yamls_eq():
    rule = next(r for r in RULES if r.id == "AGENT-DARK-LIVE")
    (streak,) = [p["eq"] for p in rule.doc["match"]["all"] if p.get("field") == "input_meta.streak"]
    assert streak == host.DARK_ROUNDS == 3


def test_redo_c13_engine_classes_has_host_and_the_rules_use_it():
    assert "HOST" in engine.CLASSES
    assert {r.id: r.cls for r in RULES if r.id in host.RULES} == {
        "NEW-AGENT": "HOST", "NEW-AGENT-UNKNOWN": "HOST", "AGENT-DARK-LIVE": "HOST", "HOST-UNWATCHED": "HOST",
        "HOST-RHYTHM": "HOST"}


# --- REDO-2 (ADR-0007 Amendment D): D-1, D-2, D-3, D-6, D-7, each with its behaviour (D-9) -------------

def test_redo2_d1_rounds_two_with_a_reader_that_never_returns_ends_at_the_second_deadline(tmp_path, monkeypatch):
    never = threading.Event()
    started = []

    def reader():
        started.append(1)
        never.wait(3600)
    w, clock = make_host(tmp_path, reader=reader, rounds=2, every=1)
    monkeypatch.setattr(host, "_sleep", lambda s: setattr(clock, "t", clock.t + s))
    running = host.Running(w, None, w.notifier, None, True, {}, io.StringIO(), io.StringIO())
    w.port, w.url = {"warning": None}, "http://127.0.0.1:1/"
    assert host.loop(running) is None
    # round 1's reader reaches its deadline at 2 s (round 1 attempted); round 2 is held to its own deadline, 4 s
    assert 2 * w.deadline_seconds <= clock.t - w.t0 <= 2 * w.deadline_seconds + host.POLL_SECONDS
    assert w.rounds == 2 and len(started) == 1            # never two readers at once
    said_ = running.out.getvalue()
    assert "2 round(s) done (--rounds)" in said_ and "round(s) 2..2 attempted without a reader (D-1)" in said_
    assert [h["kind"] for h in w.holes] == ["reader-late", "reader-held"] and w.holes[1]["round"] == 2
    text, code = w.finish()
    assert code == 3 and "2 round(s) could not be read (round 1, 2)" in text and "reader-out: round 1" in text


def test_redo2_d1_rounds_n_counts_attempted_rounds_on_the_tick_too(tmp_path):
    never = threading.Event()
    w, clock = make_host(tmp_path, reader=lambda: never.wait(3600), rounds=3, every=1)
    for _ in range(int(3 * w.deadline_seconds / host.POLL_SECONDS)):
        w.tick()
        assert not w.done_rounds() or clock.t - w.t0 >= 3 * w.deadline_seconds
        clock.t += host.POLL_SECONDS
    w.tick()
    assert w.rounds == 3 and w.done_rounds()
    w.finish()
    # a reader that came back: --rounds N is N rounds read, as before
    w, clock = make_host(tmp_path, ["linux"] * 3, rounds=2)
    run_rounds(w, clock, 2)
    assert w.rounds == 2 and w.done_rounds() and not w.holes


def test_redo2_d2_two_rounds_that_read_nothing_exit_3_never_none_seen(tmp_path):
    w, clock = make_host(tmp_path, [discover.run({}, CATALOG), discover.run({}, CATALOG)])
    run_rounds(w, clock, 2)
    text, code = w.finish()
    assert code == 3 and "RESULT: INCOMPLETE (exit 3" in text and "NONE-SEEN" not in text
    assert "2 round(s) read nothing (round 1, 2): unread round(s)" in text
    assert "NO AGENT SEEN" not in text and "NOTHING READ in 2 round(s)" in text
    assert "round 1: 0 records read, " in said(w) and "NOTHING READ: an unread round" in said(w)


def test_redo2_d2_two_rounds_of_unparseable_proc_lines_exit_3(tmp_path):
    bad = lambda: discover.run({"proc": ("proc", "not json\n{bad\n", None)}, CATALOG)   # noqa: E731
    w, clock = make_host(tmp_path, [bad(), bad()])
    run_rounds(w, clock, 2)
    text, code = w.finish()
    assert code == 3 and "NONE-SEEN" not in text and "NO AGENT SEEN" not in text
    assert "2 round(s) with line(s) that could not be read (round 1, 2)" in text
    assert "lines-unread: round 1: 2 line(s) could not be read (A3): proc:1 not a JSON line" in text


def test_redo2_d2_a_finding_plus_an_unread_line_exits_1(tmp_path):
    second = json.loads(json.dumps(inv("windows")))
    second["problems"] = [{"src": "win-process", "line": 99, "reason": "not a row"}]
    w, clock = make_host(tmp_path, [inv("benign/windows-desktop"), second])
    run_rounds(w, clock, 2)
    text, code = w.finish()
    assert w.findings and code == 1 and "RESULT: ALARM (exit 1" in text
    assert "1 round(s) with line(s) that could not be read (round 2)" in text
    assert "round 2: 74 records read, 7 holes, 1 line(s) could not be read" in said(w)


def test_redo2_d2_no_agent_seen_is_said_only_of_rounds_that_read_records(tmp_path):
    empty = dict(inv("benign/windows-desktop"), candidates=[], act_roots=[], result="none-seen")
    w, clock = make_host(tmp_path, [empty, discover.run({}, CATALOG)])
    run_rounds(w, clock, 2)
    text, code = w.finish()
    assert "NO AGENT SEEN in 1 round(s) that read records (records read: 92)" in text
    assert "NOTHING READ in 1 round(s)" in text and code == 3


def test_redo2_d3_the_benign_globs_are_the_system_drives_minus_its_user_writable_places():
    cat = CATALOG
    assert discover.benign_image("explorer", r"C:\Windows\explorer.exe", "record", cat, "c") == "c:/windows/*"
    # a user-writable place under SystemRoot is not benign
    for place in (r"Windows\Temp", r"Windows\Tasks", r"Windows\Tracing", r"Windows\Registration",
                  r"Windows\System32\Tasks", r"Windows\System32\spool\drivers", r"Windows\SysWOW64\Tasks"):
        assert discover.benign_image("explorer", "C:\\%s\\explorer.exe" % place, "record", cat, "c") is None, place
    # another drive's windows/ and program files/ is not benign
    assert discover.benign_image("explorer", r"D:\Windows\explorer.exe", "record", cat, "c") is None
    assert discover.benign_image("msedge", r"D:\Program Files\Edge\msedge.exe", "record", cat, "c") is None
    assert discover.benign_image("explorer", r"D:\Windows\explorer.exe", "record", cat, "d") == "d:/windows/*"
    # no drive in the run record: no Windows image is benign, and the check says why (a hole)
    assert discover.benign_check("explorer", r"C:\Windows\explorer.exe", "record", cat, None) == (None, discover.NO_DRIVE)
    assert discover.benign_check("explorer", r"C:\Windows\explorer.exe", "record", cat, "?") == (None, discover.NO_DRIVE)
    assert discover.benign_check("firefox", "/usr/lib/firefox/firefox", "record", cat, None) == ("/usr/*", None)
    spec = cat["benign_images"]
    assert not any("?" in d for d in spec["dirs"] + spec["exclude"])
    assert sorted(spec["exclude"]) == sorted("%%systemdrive%%/%s/*" % p for p in (
        "windows/temp", "windows/tasks", "windows/tracing", "windows/registration", "windows/system32/tasks",
        "windows/system32/spool", "windows/syswow64/tasks"))


def test_redo2_d3_both_evasions_are_in_the_catalog_and_both_new_rules_holes():
    evasion = " ".join(CATALOG["benign_images"]["evasion"])
    for words in ("another drive's windows/", "a user-writable place under SystemRoot"):
        assert words in evasion, words
        for rule_id in host.NEW_RULES:
            rule = next(r for r in RULES if r.id == rule_id)
            assert any(words in h for h in rule.holes), (rule_id, words)
    text = Path(discover.CATALOG).read_text(encoding="utf-8")
    path = Path(os.environ["HOME"]) / "endpoints.yaml"
    path.write_text(text.replace('"%systemdrive%/windows/*"', '"?:/windows/*"'), encoding="utf-8")
    with pytest.raises(discover.CatalogError, match="benign_images.dirs"):
        discover.load_catalog(str(path))


def test_redo2_d3_a_round_without_the_drive_takes_no_windows_image_as_benign_said_as_a_hole(tmp_path):
    before = dict(inv("benign/windows-desktop:before"), system_drive=None)
    after = dict(inv("benign/windows-desktop"), system_drive=None)
    w, clock = make_host(tmp_path, [before, after])
    run_rounds(w, clock, 2)
    explorer = next(t for t in w.trees.values() if t["image"] == "explorer")
    assert not explorer["benign"] and explorer["knocked"]
    (hole,) = [h for h in w.holes if h["kind"] == "benign-no-drive"]
    assert hole["round"] == 2 and "explorer pid" in hole["detail"] and discover.NO_DRIVE in hole["detail"]
    assert inv("benign/windows-desktop")["system_drive"] == "c" and inv("linux")["system_drive"] is None


def test_redo2_d3_hostwin_records_systemroots_drive_in_run_json(tmp_path, monkeypatch):
    import test_hostwin
    from raqib import hostwin
    assert hostwin.system_drive("C:\\Windows") == "c" and hostwin.system_drive("E:\\WINDOWS") == "e"
    assert hostwin.system_drive(None) is None and hostwin.system_drive("\\\\server\\share\\Windows") is None
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(hostwin, "Api", lambda: test_hostwin.Samples(test_hostwin.KIMI1, 1))
    monkeypatch.setattr(discover.time, "sleep", lambda s: None)
    monkeypatch.setattr(notify, "windows_root", lambda environ, isdir=None: ("D:\\Windows", None))
    monkeypatch.chdir(tmp_path)
    assert cli.main(["discover", "--samples", "1", "--every", "0", "--home", str(tmp_path), "--save", "live-run",
                     "--json", "-o", "live.json"], out=io.StringIO()) == 1
    assert json.loads((tmp_path / "live-run" / "run.json").read_text(encoding="ascii"))["system_drive"] == "d"
    assert json.loads((tmp_path / "live.json").read_text(encoding="ascii"))["system_drive"] == "d"
    monkeypatch.setattr(sys, "platform", "linux")
    assert cli.main(["discover", "--from", "live-run", "--json", "-o", "replay.json"], out=io.StringIO()) == 1
    assert json.loads((tmp_path / "replay.json").read_text(encoding="ascii"))["system_drive"] == "d"
    # the host round's reader carries it too
    monkeypatch.setattr(sys, "platform", "win32")
    got = host.live_reader(CATALOG, 0.0, "win32", homes=[])()
    assert got["system_drive"] == "d"
    monkeypatch.setattr(notify, "windows_root", lambda environ, isdir=None: (None, "SystemRoot is not set"))
    assert host.live_reader(CATALOG, 0.0, "win32", homes=[])()["system_drive"] is None


def test_redo2_d6_an_unparseable_heartbeat_refuses_the_second_watch_naming_the_state_file(tmp_path, _home, capsys,
                                                                                          monkeypatch):
    w, clock = make_host(tmp_path, ["linux"])
    w.tick(wait=30)
    state = json.loads(Path(w.state_path).read_text(encoding="ascii"))
    for beat in ("not a time", None, 12):
        Path(w.state_path).write_text(json.dumps(dict(state, heartbeat=beat)), encoding="ascii")
        with pytest.raises(host.HostError, match="heartbeat that cannot be parsed") as got:
            make_host(tmp_path, ["linux"])
        assert w.state_path in str(got.value)
    monkeypatch.setattr(host, "live_reader", lambda catalog, window, platform: lambda: inv("linux"))
    path = _home / ".raqib" / "host" / "rounds.jsonl.watch.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(dict(state, heartbeat="garbled")), encoding="ascii")
    assert cli.main(["watch", "--host", "--rounds", "1", "--no-notify", "--no-open", "--port", "0"],
                    out=io.StringIO()) == 2
    err = capsys.readouterr().err
    assert err.count("\n") == 1 and str(path) in err and "cannot be parsed" in err
    path.write_text(json.dumps(dict(state, heartbeat="garbled", finished="2026-11-04T00:00:00.000Z")), encoding="ascii")
    make_host(tmp_path, ["linux"])     # a finished state is no other watch


def comparison_line():
    """The D-7 comparison of .github/workflows/gate.yml, as CI runs it."""
    text = (ROOT / ".github" / "workflows" / "gate.yml").read_text(encoding="utf-8")
    (line,) = [x.strip() for x in text.splitlines() if x.strip().startswith('python -c "import json, os, re; inv =')]
    return line[len('python -c "'):-1]


def test_redo2_d7_the_ci_comparison_is_over_pids_in_both_and_gone_between_is_not_a_failure(tmp_path):
    import subprocess
    code = comparison_line()
    report = ("TREES SEEN: 2 (2 now)\n  [candidate] pid 2100 claude (named: x): now\n"
              "  [act-root] pid 10728 kimi (unknown): now\n")

    def run(candidates, text, nt):
        (tmp_path / "host-discover.json").write_text(json.dumps({"candidates": candidates}), encoding="ascii")
        (tmp_path / "host.txt").write_text(text, encoding="utf-8")
        shim = "import os; os.name = %r; exec(%r)" % ("nt" if nt else "posix", code)
        return subprocess.run([sys.executable, "-c", shim], cwd=tmp_path, capture_output=True, text=True)
    both = [{"pid": 2100, "image": "claude"}, {"pid": 4242, "image": "gone"}]
    for nt in (True, False):
        done = run(both, report, nt)
        assert done.returncode == 0, done
        assert "in both: [2100]" in done.stdout and "gone between: pid 4242" in done.stdout
    done = run([{"pid": 4242, "image": "gone"}], report, True)      # no candidate pid at all on Windows: fail
    assert done.returncode != 0 and "no discover candidate pid among the watch trees on Windows" in done.stderr
    assert run([{"pid": 4242, "image": "gone"}], report, False).returncode == 0
    assert run([], report, False).returncode == 0 and run([], report, True).returncode != 0
