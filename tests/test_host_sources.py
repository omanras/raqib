"""M7.2b reading sources attach themselves (HANDOFF.md E1-E5; ADR-0007
decision 3 as narrowed by Amendment H).

No live host, no Sysmon channel and no real project is touched: every
HostWatch gets a reader of discover-fixture inventories, a Sysmon check
and an os follow that are fakes, and every project is a directory under
tmp_path. A tree whose cwd the fixtures give as a real path is moved to a
tmp project before any --attach-hooks test (the "linux" fixture's cwd is
/home/claude, which may exist where the tests run).
"""
import builtins
import copy
import io
import json
import os
import re
import sys
import tempfile
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from raqib import app, cli, discover, host, install, notify, ui  # noqa: E402
from raqib.hooks import os_sysmon  # noqa: E402
from raqib.rules import engine, fixtures, silence, trace  # noqa: E402

sys.path.insert(0, str(ROOT / "tests"))
from test_watch import FakeRunner, make_notifier  # noqa: E402

sys.path.insert(0, str(ROOT / "tests" / "fixtures" / "host"))
import make as host_fixtures  # noqa: E402

CATALOG = discover.load_catalog(discover.CATALOG)
RULES = engine.load_catalog(ROOT / "raqib" / "rules" / "catalog")
QUESTIONS = ROOT / "docs" / "review" / "2026-11-04-M7.2b-questions.md"
SYSMON_XML = ROOT / "tests" / "fixtures" / "os" / "sysmon-synthetic.xml"
NO_SYSMON = lambda: (False, "test: no Sysmon channel")   # noqa: E731
SYSMON = lambda: (True, "test: the Sysmon channel is registered")   # noqa: E731


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
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


def make_host(home, names, runner=None, sysmon=NO_SYSMON, **kw):
    feed = iter([inv(n) if isinstance(n, str) else n for n in names])
    clock = Clock()
    notifier = make_notifier(runner or FakeRunner())
    notifier.host = True
    w = host.HostWatch(lambda: next(feed), CATALOG, RULES, notifier, every=10, out=io.StringIO(), err=io.StringIO(),
                       clock=clock, wall=lambda: 1793700000.0 + clock.t - 1000.0, home=str(home), platform="test",
                       sysmon=sysmon, **kw)
    return w, clock


def rounds(w, clock, n):
    for _ in range(n):
        w.tick(wait=30)
        clock.t += w.every


def source_file(w, pid):
    return Path(w.sources_dir) / ("%s-%s.jsonl" % (w.run, pid))


def lines_of(path):
    return [json.loads(x) for x in Path(path).read_text(encoding="ascii").splitlines() if x.strip()]


def tree_of(w, pid):
    (t,) = [t for t in w.trees.values() if t["pid"] == pid]
    return t


def moved(name, project, pid=None):
    """An inventory whose candidates (or the one of pid) work in `project`."""
    i = copy.deepcopy(inv(name))
    for c in i["candidates"] + i.get("act_roots", []):
        if pid is None or c["pid"] == pid:
            c["cwd"] = str(project)
    return i


# --- E1 (b) the host source --------------------------------------------------------------------------------

def test_e1b_without_sysmon_every_tree_gets_the_host_source_recorded_on_the_tree_and_round(home):
    w, clock = make_host(home, ["linux", "linux"])
    rounds(w, clock, 2)
    for pid in (87, 95):
        t = tree_of(w, pid)
        assert t["source"] == "host" and t["source_round"] == 1
    rec = json.loads(Path(w.rounds_path).read_text(encoding="ascii").splitlines()[-1])
    assert set(rec["sources"]) == {"87:environment-manager:-", "95:claude:-"}
    assert all(v.startswith("host: ") or "host: " in v for v in rec["sources"].values())
    (line,) = [l for l in rec["lines"] if l["tool"] == "HostTree" and l["input_meta"]["pid"] == 95]
    assert line["input_meta"]["source"] == "host" and line["input_meta"]["hooks"] == "hooks: not attached (no --attach-hooks)"


def test_e2_host_lines_child_connection_gone_are_strict_and_never_bash(home):
    w, clock = make_host(home, ["benign/linux-desktop", "linux-agent", "benign/linux-desktop"])
    rounds(w, clock, 3)
    got = lines_of(source_file(w, 1600))
    assert [l["tool"] for l in got] == ["HostChild", "HostGone"]
    child, gone = got
    assert child["input_meta"]["command_programs"] == ["bash", "curl"] and child["source"] == "host"
    assert child["input_meta"]["round"] == 2 and child["input_meta"]["run"] == w.run and child["input_meta"]["sample"]
    assert child["input_meta"]["tree_seq"] == tree_of(w, 1600)["line_seq"] or child["input_meta"]["tree_seq"]
    assert gone["input_meta"]["round"] == 3
    for l in got:
        assert trace.strict_problem(l) is None and l["tool"] != "Bash" and l["cwd"] == host.CWD
        assert all(set(c) == {"src", "line", "text_sha256"} for c in l["input_meta"].get("cites", []))   # hashes only
    assert "argv" not in source_file(w, 1600).read_text(encoding="ascii")


def test_e2_host_connection_line_carries_the_remote_and_its_hash(home):
    w, clock = make_host(home, ["benign/windows-desktop", "windows"])
    rounds(w, clock, 2)
    got = lines_of(source_file(w, 3300))
    conns = [l for l in got if l["tool"] == "HostConnection"]
    assert {l["input_meta"]["remote"] for l in conns} == {"127.0.0.1:11434", "104.18.33.45:443"}
    for l in conns:
        assert l["input_sha256"] == host.common.canonical_sha256({"destination": l["input_meta"]["remote"]})
        assert trace.strict_problem(l) is None
    local = next(l for l in conns if l["input_meta"]["remote"].startswith("127."))
    assert local["input_meta"]["dest_private"] is True and local["input_meta"]["dest_port"] == 11434


def test_e2_a_child_name_that_is_not_a_plain_program_is_a_hole_not_a_line(home):
    i = copy.deepcopy(inv("linux-agent"))
    for a in i["act_roots"][0]["acts"]:   # the agent of linux-agent is an act-root (talk not seen)
        if a["image"] == "curl":
            a["image"] = "cu rl"
    w, clock = make_host(home, ["benign/linux-desktop", i])
    rounds(w, clock, 2)
    (child,) = lines_of(source_file(w, 1600))
    assert child["input_meta"]["command_programs"] == ["bash"]
    assert any(h["kind"] == "host-source-unfit" for h in w.holes)


def test_e2_net_tool_on_host_lines_finds_on_the_tree_knocks_and_alarms(home):
    runner = FakeRunner()
    w, clock = make_host(home, ["benign/linux-desktop", "linux-agent"], runner=runner)
    rounds(w, clock, 2)
    (f,) = [f for f in w.source_findings if f["rule_id"] == "NET-TOOL"]
    assert f["pid"] == 1600 and f["source"] == "host" and not f["history"] and f["notice"] == "sent"
    assert tree_of(w, 1600)["source_findings"] == {"medium": 1}
    text, code = w.finish()
    assert code == 1 and "source finding(s): NET-TOOL on pid 1600" in text
    assert "source: host (host: the host's own record of the tree: " in text and "findings medium 1" in text


def test_e2_destruct_cmd_on_host_lines_and_only_hostchild_is_judged(home):
    w, clock = make_host(home, ["benign/linux-desktop", "linux-agent" + host_fixtures.RM])
    rounds(w, clock, 2)
    assert [f["rule_id"] for f in w.source_findings] == ["DESTRUCT-CMD"]
    rules = [r for r in RULES if r.id in ("NET-TOOL", "DESTRUCT-CMD")]
    base = {"ts": "2026-11-04T10:00:00.000Z", "seq": 1, "session_id": "host-1", "phase": "pre", "cwd": "host",
            "source": "host"}
    for tool in ("HostConnection", "HostGone", "HostTree"):
        line = dict(base, tool=tool, input_meta={"command_programs": ["curl", "rm"], "remote": "192.0.2.1:22"})
        assert engine.evaluate(rules, [line])[0] == [], tool
    child = dict(base, tool="HostChild", input_meta={"command_programs": ["curl", "rm"]})
    assert sorted(f["rule_id"] for f in engine.evaluate(rules, [child])[0]) == ["DESTRUCT-CMD", "NET-TOOL"]
    # an os line of the same shape is still not judged by NET-TOOL (M5.3 C-5)
    assert [f["rule_id"] for f in engine.evaluate(rules, [dict(child, source="os")])[0]] == []


def test_e2_the_two_rules_carry_host_fixtures_positive_and_negative_and_the_measured_budget():
    reports = {r["rule_id"]: r for r in fixtures.check_catalog(RULES, ROOT, cli.benign_default(str(ROOT)))}
    for rule_id in ("NET-TOOL", "DESTRUCT-CMD"):
        rule = next(r for r in RULES if r.id == rule_id)
        pos = "tests/fixtures/rules/%s/positive-host-child.json" % rule_id
        neg = "tests/fixtures/rules/%s/negative-host-child.json" % rule_id
        assert pos in rule.fixtures["positive"] and neg in rule.fixtures["negative"]
        report = reports[rule_id]
        assert report["verdict"] == "ok" and all(p["fired"] for p in report["positives"])
        (n,) = [n for n in report["negatives"] if Path(n["path"]).as_posix() == neg]   # relpath: \\ on Windows
        assert n["measured"] and not n["fired"]
        assert {l["source"] for l in fixtures.load_fixture(ROOT / neg)[0]} == {"host"}
        assert round(report["fp_rate"], 3) == 0.091 and report["fp_rate"] <= rule.fp_budget   # 1 of 11
        assert any(e.startswith("host source (M7.2b") for e in rule.evasion)


def test_e2_silence_rules_skip_source_host_and_only_it():
    host_lines = lines_of_fixture("NET-TOOL/positive-host-child.json")
    assert host_lines and silence.findings(host_lines) == []
    hook = [{"ts": "2026-11-04T10:00:00.000Z", "seq": 1, "session_id": "s", "phase": "session_start", "tool": "-",
             "cwd": "/w"}]
    found = silence.findings(host_lines + hook)
    assert [f["rule_id"] for f in found] == ["SILENCE-OPEN"] and found[0]["session_id"] == "s"
    # the same lines as os lines are judged (OPEN/HALF/EMPTY run over os sessions)
    as_os = [dict(l, source="os") for l in host_lines]
    assert any(f["rule_id"] == "SILENCE-HALF" for f in silence.findings(as_os))


def lines_of_fixture(name):
    return fixtures.load_fixture(ROOT / "tests" / "fixtures" / "rules" / name)[0]


def test_e2_a_tree_there_at_the_start_its_first_round_lines_are_history_not_knocked(home):
    runner = FakeRunner()
    w, clock = make_host(home, ["linux-agent", "linux-agent"], runner=runner)
    rounds(w, clock, 2)
    (f,) = w.source_findings
    assert f["rule_id"] == "NET-TOOL" and f["history"] and f["notice"] == "history: not knocked"
    assert runner.calls == [] and tree_of(w, 1600)["source_findings"] == {"history": 1}
    assert w.finish()[1] == 0


# --- E1 (a) the os source -----------------------------------------------------------------------------------

class FakeFollow:
    """os_sysmon.follow's API: appends os-sysmon lines (of the synthetic
    export, rooted at 4100) to the log on its first pass, then waits for
    stop; or raises; or ignores stop (a pass that never ends)."""

    def __init__(self, raise_on=None, stubborn=False):
        self.calls = []
        self.raise_on = raise_on
        self.stubborn = stubborn
        self.release = threading.Event()

    def __call__(self, root, log, stop, every=None, out=None, err=None, on_pass=None, after_record=None):
        self.calls.append({"root": root, "log": log, "every": every, "after": after_record})
        if self.raise_on is not None and root == self.raise_on:
            raise os_sysmon.UsageError("cannot write the trace %s: test" % log)
        info = {}
        lines, _ = os_sysmon.build(SYSMON_XML.read_text(encoding="utf-8"), 4100, info=info)
        os_sysmon.append(log, lines)
        if on_pass:
            on_pass(1, info["top_record"])
        if self.stubborn:
            self.release.wait(10)
            return 1
        stop.wait(60)
        return 1


def test_e1a_sysmon_present_attaches_os_sysmon_rooted_at_the_root_pid_in_a_thread_with_a_stop(home):
    follow = FakeFollow()
    w, clock = make_host(home, ["windows", "windows"], sysmon=SYSMON, os_follow=follow)
    rounds(w, clock, 1)
    pids = sorted(c["root"] for c in follow.calls)
    assert pids == sorted(t["pid"] for t in w.trees.values())
    for key, src in w.sources.items():
        assert src.kind == "os" and src.thread.is_alive() and not src.stop.is_set()
        assert src.path == str(source_file(w, key[0])) and src.path.startswith(str(home / ".raqib" / "host" / "sources"))
        assert ("os: Sysmon, rooted at pid %s: " % key[0]) in src.text
    for src in w.sources.values():
        src.first_pass.wait(5)
    rounds(w, clock, 1)
    assert all(tree_of(w, k[0])["source"] == "os" for k in w.sources)
    w.finish()
    for src in w.sources.values():   # E4: Stop ends every source thread
        assert src.stop.is_set() and not src.thread.is_alive() and src.ended == "stopped"
    os_lines = lines_of(source_file(w, 2100))
    assert {l["source"] for l in os_lines} == {"os"} and os_lines[0]["session_id"] == "os-4100"


def test_e1a_sysmon_present_is_read_from_doctors_registry_check_on_windows_only():
    assert host.sysmon_present("linux")[0] is False
    ok = host.sysmon_present("win32", registry=lambda key: {"Enabled": 1})
    no = host.sysmon_present("win32", registry=lambda key: None)
    assert ok[0] is True and no[0] is False and "Sysmon" in no[1]


def test_e1a_an_os_source_that_fails_is_a_hole_and_the_tree_falls_to_the_host_source_next_round(home):
    follow = FakeFollow(raise_on=2100)
    w, clock = make_host(home, ["windows", "windows", "windows"], sysmon=SYSMON, os_follow=follow)
    rounds(w, clock, 1)
    src = next(s for k, s in w.sources.items() if k[0] == 2100)
    src.thread.join(5)
    assert src.error and "UsageError" in src.error
    rounds(w, clock, 1)
    assert any(h["kind"] == "source-ended" and "2100" in h["detail"] for h in w.holes)
    t = tree_of(w, 2100)
    assert t["source"] == "host" and "the os source ended with a hole" in t["source_text"]
    w.finish()


def test_e4_stop_with_a_source_thread_still_in_a_pass_is_a_hole(home, monkeypatch):
    monkeypatch.setattr(host, "SOURCE_JOIN_SECONDS", 0.2)
    follow = FakeFollow(stubborn=True)
    w, clock = make_host(home, ["linux"], sysmon=SYSMON, os_follow=follow)
    rounds(w, clock, 1)
    text, code = w.finish()
    follow.release.set()
    assert [h["kind"] for h in w.holes].count("source-out") == 2 and code == 3
    assert "its os source was still in a pass at the end" in text


def test_e1a_os_follow_api_resumes_after_a_record_and_stops(tmp_path):
    log = tmp_path / "os.jsonl"
    text = SYSMON_XML.read_text(encoding="utf-8")
    stop = threading.Event()
    seen = []

    def on_pass(n, top):
        seen.append((n, top))
        if n == 2:
            stop.set()
    passes = os_sysmon.follow(4100, str(log), stop, every=0.01, live=lambda: (text, None), on_pass=on_pass,
                              out=io.StringIO(), err=io.StringIO())
    assert passes == 2 and seen[0][1] == seen[1][1] == 70017
    assert len(lines_of(log)) == 24   # the second pass appended nothing: no history again
    stop2 = threading.Event()
    stop2.set()
    err = io.StringIO()
    os_sysmon.follow(4100, str(log), stop2, live=lambda: (None, "wevtutil exited 15007"), out=io.StringIO(), err=err)
    assert err.getvalue().startswith("RAQIB-SILENCE: os-sysmon root=4100 wevtutil exited 15007")
    with pytest.raises(os_sysmon.UsageError, match="Windows only"):
        os_sysmon.follow(4100, str(log), stop2, nt=False)


# --- E1 (c) hooks: only with --attach-hooks / the checkbox --------------------------------------------------

def test_e1c_without_the_flag_a_claude_code_tree_gets_no_hooks_and_the_reason(home, tmp_path):
    project = tmp_path / "proj"
    project.mkdir()
    w, clock = make_host(home, [moved("linux", project), moved("linux", project)])
    rounds(w, clock, 2)
    t = tree_of(w, 95)
    assert t["source"] == "host" and t["source_text"].startswith("hooks: not attached (no --attach-hooks); host: ")
    assert not (project / ".claude").exists()
    assert "HOOKS: not attached (no --attach-hooks): nothing is written into any project" in w.finish()[0]


def test_e1c_with_the_flag_the_hooks_go_into_the_trees_cwd_as_raqib_watch_installs_them(home, tmp_path):
    project = tmp_path / "proj"
    project.mkdir()
    w, clock = make_host(home, [moved("linux", project, pid=95), moved("linux", project, pid=95)], attach_hooks=True)
    rounds(w, clock, 1)
    t = tree_of(w, 95)
    assert t["source"] == "hooks" and t["source_project"] == str(project)
    settings = json.loads((project / ".claude" / "settings.json").read_text(encoding="utf-8"))
    commands = [h["command"] for e in settings["hooks"].values() for g in e for h in g["hooks"]]
    assert len(commands) == 6 and all(install.MARK in c or "capture.py" in c for c in commands)
    src = w.sources[next(k for k in w.sources if k[0] == 95)]
    trace_path = src.feeds[0].path
    assert trace_path.startswith(str(home / ".raqib" / "traces")) and not trace_path.startswith(str(project))
    # the installer writes the Windows command's paths with / (install.windows_word): compare in that form
    assert all(trace_path.replace("\\", "/") in c.replace("\\", "/") for c in commands)
    # the hooks' lines are judged incrementally: a Bash curl knocks on the tree
    hook = {"ts": "2026-11-04T10:00:00.000Z", "seq": 1, "session_id": "s1", "phase": "pre", "tool": "Bash",
            "cwd": str(project), "input_meta": {"command_head": "curl", "command_programs": ["curl"]}}
    with open(trace_path, "a", encoding="ascii") as f:
        f.write(json.dumps(hook) + "\n")
    w.tick()
    (f,) = [f for f in w.source_findings if f["rule_id"] == "NET-TOOL"]
    assert f["source"] == "hooks" and f["pid"] == 95 and not f["history"]
    assert tree_of(w, 87)["source"] == "host"   # environment-manager is no Claude Code tree
    w.finish()


@pytest.mark.parametrize("where, why", [
    ("none", "no cwd read"),
    ("home", "the cwd is the home directory"),
    ("raqib", "is under ~/.raqib"),
    ("missing", "is not a directory here"),
])
def test_e1c_with_the_flag_a_tree_whose_cwd_cannot_take_hooks_is_said_and_falls_to_host(home, tmp_path, where, why):
    target = {"none": None, "home": home, "raqib": home / ".raqib" / "x", "missing": tmp_path / "gone"}[where]
    if where == "raqib":
        target.mkdir(parents=True)
    i = copy.deepcopy(inv("linux"))
    for c in i["candidates"]:
        c["cwd"] = str(target) if target is not None else None
    w, clock = make_host(home, [i], attach_hooks=True)
    rounds(w, clock, 1)
    t = tree_of(w, 95)
    assert t["source"] == "host" and t["source_text"].startswith("hooks: not attached (") and why in t["source_text"]
    assert any(h["kind"] == "hooks-not-attached" and why in h["detail"] for h in w.holes)
    assert not (home / ".claude").exists()


def test_e1c_windows_gives_no_cwd_live_h4(home):
    w, clock = make_host(home, ["windows"], attach_hooks=True)
    w.platform = "win32"
    rounds(w, clock, 1)
    t = tree_of(w, 2100)
    assert "hooks: not attached (no cwd read: Windows gives no cwd live (ADR-0007 A-15, H-4))" in t["source_text"]


def test_e1c_claude_code_is_claude_not_desktop_or_node_with_cli_js_where_argv_was_read():
    ok, _ = host.claude_code({"image": "claude", "exe": "/opt/claude-code/bin/claude", "cites": []}, CATALOG)
    desk, why = host.claude_code({"image": "claude", "exe": "C:/Users/u/AppData/Local/AnthropicClaude/claude.exe",
                                  "cites": []}, CATALOG)
    assert ok and not desk and "Claude Desktop" in why
    cite = {"text": json.dumps({"pid": 7, "argv": ["node", "/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js"]})}
    assert host.claude_code({"image": "node", "pid": 7, "cites": [cite]}, CATALOG)[0]
    other = {"text": json.dumps({"pid": 7, "argv": ["node", "server.js"]})}
    assert not host.claude_code({"image": "node", "pid": 7, "cites": [other]}, CATALOG)[0]
    no, why = host.claude_code({"image": "node", "pid": 7, "cites": [{"text": '"7","1","node.exe"'}]}, CATALOG)
    assert not no and "argv was not read" in why


class Writes:
    """A fake filesystem watcher: every path opened for writing, created,
    replaced or made while it is on (builtins.open, os.open, os.replace,
    os.rename, os.makedirs, os.mkdir, tempfile.mkstemp)."""

    def __init__(self, monkeypatch):
        self.paths = []
        real_open, real_os_open = builtins.open, os.open
        real_replace, real_rename, real_makedirs, real_mkdir = os.replace, os.rename, os.makedirs, os.mkdir
        real_mkstemp = tempfile.mkstemp
        writes = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND

        def fake_open(file, mode="r", *a, **k):
            if isinstance(file, (str, bytes, os.PathLike)) and any(c in mode for c in "wax+"):
                self.paths.append(os.path.abspath(os.fsdecode(file)))
            return real_open(file, mode, *a, **k)

        def fake_os_open(path, flags, *a, **k):
            if flags & writes:
                self.paths.append(os.path.abspath(os.fsdecode(path)))
            return real_os_open(path, flags, *a, **k)

        def fake_replace(src, dst, *a, **k):
            self.paths.append(os.path.abspath(os.fsdecode(dst)))
            return real_replace(src, dst, *a, **k)

        def fake_rename(src, dst, *a, **k):
            self.paths.append(os.path.abspath(os.fsdecode(dst)))
            return real_rename(src, dst, *a, **k)

        def fake_makedirs(name, *a, **k):
            self.paths.append(os.path.abspath(os.fsdecode(name)))
            return real_makedirs(name, *a, **k)

        def fake_mkdir(name, *a, **k):
            self.paths.append(os.path.abspath(os.fsdecode(name)))
            return real_mkdir(name, *a, **k)

        def fake_mkstemp(*a, **k):
            fd, name = real_mkstemp(*a, **k)
            self.paths.append(os.path.abspath(name))
            return fd, name
        for target, name, fn in ((builtins, "open", fake_open), (os, "open", fake_os_open),
                                 (os, "replace", fake_replace), (os, "rename", fake_rename),
                                 (os, "makedirs", fake_makedirs), (os, "mkdir", fake_mkdir),
                                 (tempfile, "mkstemp", fake_mkstemp)):
            monkeypatch.setattr(target, name, fn)

    def outside(self, root):
        root = os.path.realpath(root)
        return sorted({p for p in self.paths if os.path.commonpath([os.path.realpath(p), root]) != root})


def test_a4_without_the_flag_no_path_outside_raqib_is_written_and_with_it_only_the_hook_settings(home, tmp_path,
                                                                                                monkeypatch):
    """A4, the heart of M7.2b: the only write into any project is the hook
    settings, and only under --attach-hooks; every other source reads."""
    project = tmp_path / "proj"
    project.mkdir()
    names = [moved("linux", project), moved("linux-agent", project), moved("linux", project)]
    notifier = notify.Notifier(host.HOST, enabled=False, reason="test", host=True)
    writes = Writes(monkeypatch)
    w = host.HostWatch(iter(names).__next__, CATALOG, RULES, notifier, every=10, out=io.StringIO(),
                       err=io.StringIO(), home=str(home), platform="test", sysmon=NO_SYSMON)
    for _ in names:
        w.tick(wait=30)
        w.next_round = 0
    w.finish()
    assert writes.paths and writes.outside(home / ".raqib") == []
    assert not (project / ".claude").exists() and sorted(p.name for p in project.iterdir()) == []

    writes.paths.clear()
    names = [moved("linux", project), moved("linux", project)]
    w = host.HostWatch(iter(names).__next__, CATALOG, RULES, notifier, every=10, out=io.StringIO(),
                       err=io.StringIO(), home=str(home), platform="test", sysmon=NO_SYSMON, attach_hooks=True)
    for _ in names:
        w.tick(wait=30)
        w.next_round = 0
    w.finish()
    outside = writes.outside(home / ".raqib")
    norm = lambda p: os.path.normcase(os.path.normpath(str(p)))   # noqa: E731  (\\ and / alike on Windows)
    claude_dir = norm(project / ".claude")
    assert outside and all(norm(p) in (norm(project / ".claude" / "settings.json"), claude_dir) or
                           os.path.dirname(norm(p)) == claude_dir for p in outside), outside
    assert sorted(os.path.normpath(str(p.relative_to(project))) for p in project.rglob("*")) == [
        ".claude", os.path.join(".claude", "settings.json")]


def test_a4_the_docstrings_say_so():
    flat = lambda text: " ".join(text.split())   # noqa: E731
    assert "THIS IS THE ONLY WRITE INTO ANY PROJECT, and without the flag it never happens" in flat(host.__doc__)
    assert "every source but the hooks only reads" in flat(host.__doc__)
    assert "without it no file is written into any project" in flat(host.HostWatch.__init__.__doc__)
    assert "without it nothing is written into any project" in flat(host.start.__doc__)
    assert "The ONLY write into a project, and only under attach_hooks" in flat(host.HostWatch._attach_hooks.__doc__)
    assert "the only file ever written into a project, and only with this flag" in flat(cli.__doc__)


# --- E3 HOST-UNWATCHED --------------------------------------------------------------------------------------

def block_sources(home):
    (home / ".raqib" / "host").mkdir(parents=True, exist_ok=True)
    (home / ".raqib" / "host" / "sources").write_text("a file, not a directory\n", encoding="ascii")


def test_e3_a_candidate_with_no_source_for_two_rounds_is_host_unwatched_high_and_knocks_once(home):
    block_sources(home)
    runner = FakeRunner()
    w, clock = make_host(home, ["linux", "linux", "linux"], runner=runner)
    rounds(w, clock, 3)
    found = [f for f in w.findings if f["rule_id"] == "HOST-UNWATCHED"]
    assert sorted((f["pid"], f["round"], f["severity"]) for f in found) == [(87, 2, "high"), (95, 2, "high")]
    assert all(f["notice"] == "sent" for f in found) and tree_of(w, 95)["unwatched"] == "sent"
    assert sum(1 for c in runner.calls if "HOST-UNWATCHED" in c["text"]) == 2
    assert all(t["source"] == "none" for t in w.trees.values())
    assert any(h["kind"] == "source-none" for h in w.holes)
    assert w.finish()[1] == 1


def test_e3_one_round_with_no_source_or_a_tree_with_a_source_is_not_host_unwatched(home, tmp_path):
    block_sources(home)
    w, clock = make_host(home, ["linux"])
    rounds(w, clock, 1)
    assert not [f for f in w.findings if f["rule_id"] == "HOST-UNWATCHED"]
    w2, clock2 = make_host(tmp_path / "home2", ["linux", "linux", "linux"])
    rounds(w2, clock2, 3)
    assert not [f for f in w2.findings if f["rule_id"] == "HOST-UNWATCHED"]


def test_e3_host_unwatched_is_a_catalog_anchor_with_fixtures_from_make_py_and_its_eq_is_the_codes():
    rule = next(r for r in RULES if r.id == "HOST-UNWATCHED")
    assert (rule.kind, rule.cls, rule.severity, rule.fp_budget, rule.status) == ("anchor", "HOST", "high", 0.0, "active")
    assert rule.holes and rule.evasion == ()
    (eq,) = [p["eq"] for p in rule.doc["match"]["all"] if p.get("field") == "input_meta.none_rounds"]
    assert eq == host.UNWATCHED_ROUNDS == 2
    report = fixtures.check_rule(rule, ROOT, ())
    assert report["verdict"] == "ok" and report["fp_rate"] == 0.0 and report["measured"] == 4
    assert set(host_fixtures.NO_SOURCES) <= set(host_fixtures.SCENARIOS)
    assert host.UNWATCHED in host.RULES and host.UNWATCHED in host.TREE_RULES


# --- E4 report, page, window ---------------------------------------------------------------------------------

def test_e4_the_page_shows_the_source_column_and_the_source_findings(home):
    w, clock = make_host(home, ["benign/linux-desktop", "linux-agent"])
    rounds(w, clock, 2)
    page = w.page()
    assert "<th>source</th>" in page and "<th>source findings</th>" in page
    assert "host: the host&#x27;s own record of the tree" in page and "medium 1" in page
    assert "Source findings (1)" in page and "NET-TOOL" in page
    assert "hooks: not attached (no --attach-hooks)" in page and "<script" not in page.lower()
    w.finish()


def test_e4_the_window_rows_carry_the_source_and_findings_by_severity(home):
    w, clock = make_host(home, ["benign/linux-desktop", "linux-agent"])
    rounds(w, clock, 2)
    view = app.host_watch_view(w.state(clock()))
    (row,) = [r for r in view["rows"] if r[1] == "1600"]
    assert row[5] == "host" and row[6] == "medium 1"
    head = app.host_table(view["rows"])[0]
    assert "source" in head and "findings" in head
    w.finish()


def test_e4_the_checkbox_is_off_by_default_and_is_passed_to_the_host_watch(home):
    seen = {}

    def starter(catalog, rules, **kw):
        seen.update(kw)
        raise RuntimeError("stop here")
    o = app.Options(None, RULES, 60, environ={}, home=str(home), catalog=CATALOG, host_reader=lambda: inv("linux"))
    assert o.attach_hooks is False and app.ATTACH_TEXT == "attach hooks to Claude Code projects"
    s = app.HostSession(o, starter=starter)
    with pytest.raises(RuntimeError):
        s._open()
    assert seen["attach_hooks"] is False
    o.attach_hooks = True
    with pytest.raises(RuntimeError):
        app.HostSession(o, starter=starter)._open()
    assert seen["attach_hooks"] is True
    src = (ROOT / "raqib" / "app.py").read_text(encoding="ascii")
    assert "tk.Checkbutton(row, text=ATTACH_TEXT" in src and "self.c.options.attach_hooks = bool(self.attach_var.get())" in src


def test_e4_cli_attach_hooks_reaches_the_host_watch(monkeypatch):
    seen = {}
    monkeypatch.setattr(host, "command", lambda catalog, rules, **kw: seen.update(kw) or 0)
    assert cli.main(["watch", "--host", "--rounds", "1", "--attach-hooks"], out=io.StringIO()) == 0
    assert seen["attach_hooks"] is True
    assert cli.main(["watch", "--host", "--rounds", "1"], out=io.StringIO()) == 0
    assert seen["attach_hooks"] is False


# --- E5 CI, README, the questions file ------------------------------------------------------------------------

def test_e5_ci_asserts_every_tree_has_a_source_or_host_unwatched():
    gate = (ROOT / ".github" / "workflows" / "gate.yml").read_text(encoding="utf-8")
    assert "M7.2b" in gate and "every tree has a source or HOST-UNWATCHED" in gate
    assert 're.findall(r"^      source: (\\S+)", text, re.M)' in gate


def test_e5_readme_three_lines():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    section = text.split("## Watch the host\n", 1)[1].split("\n## ", 1)[0]
    lines = [l for l in section.split("\n") if l.strip()]
    assert len(lines) == 6
    assert "os source (Sysmon)" in lines[3] and "--attach-hooks" in lines[4] and "HOST-UNWATCHED" in lines[5]
    assert "only thing ever written into a project" in lines[4]


def test_e5_questions_file_has_the_gate_numbers_the_tests_and_what_the_table_must_write():
    text = QUESTIONS.read_text(encoding="utf-8")
    for q in ("Q-1", "Q-2", "Q-3", "Q-4", "Q-5", "Q-6"):
        assert q in text
    assert "2602 passed, 18 skipped" in text and "test_host_sources.py" in text
    assert "| HOST-UNWATCHED   | anchor    | -" in text and "Ratio after M7.2b: 4 : 7 : 10." in text
    assert "Note (2026-11-04, M7.2b, ADR-0007 Amendment H" in text


def test_ascii():
    for name in ("raqib/host.py", "raqib/hooks/os_sysmon.py", "raqib/ui.py", "raqib/app.py", "raqib/cli.py",
                 "raqib/rules/catalog/HOST-UNWATCHED.yaml", "tests/test_host_sources.py", "tests/fixtures/host/make.py"):
        (ROOT / name).read_bytes().decode("ascii")
