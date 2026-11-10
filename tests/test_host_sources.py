"""M7.2b reading sources attach themselves (HANDOFF.md E1-E5; ADR-0007
decision 3 as narrowed by Amendment H).

No live host, no Sysmon channel and no real project is touched: every
HostWatch gets a reader of discover-fixture inventories, a Sysmon check
and an os follow that are fakes, and every project is a directory under
tmp_path. A tree whose cwd the fixtures give as a real path is moved to a
tmp project before any --attach-hooks test (the "linux" fixture's cwd is
/home/user since M7.6d, which may exist where the tests run).
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
    """I-8: the per-tree file is keyed (run, pid, started)."""
    (key,) = [k for k in w.trees if k[0] == pid]
    return Path(w._source_path(key))


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
        assert round(report["fp_rate"], 3) == 0.083 and report["fp_rate"] <= rule.fp_budget   # 1 of 12 (M7.8: + os lines)
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

    def __call__(self, root, log, stop, every=None, out=None, err=None, on_pass=None, after_record=None,
                 helpers=None):
        self.calls.append({"root": root, "log": log, "every": every, "after": after_record, "helpers": helpers})
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
    replaced, linked, truncated, copied or made while it is on. REDO I-9
    (P10): builtins.open and io.open, os.open, os.replace, os.rename,
    os.makedirs, os.mkdir, os.symlink, os.link, os.truncate, os.remove,
    os.unlink, os.rmdir; pathlib's write_text, write_bytes, open, mkdir,
    touch, symlink_to, hardlink_to; shutil's copy, copy2, copyfile,
    copytree, move, rmtree; tempfile's mkstemp, mkdtemp, NamedTemporaryFile,
    TemporaryFile; and subprocess (Popen, run, call, check_call,
    check_output) with every file argument and redirect it names. A program
    run through subprocess is also recorded in `programs` (none may run)."""

    def __init__(self, monkeypatch):
        import shutil
        import subprocess
        self.paths = []
        self.programs = []
        writes = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | getattr(os, "O_TRUNC", 0)
        real = {}

        def note(path):
            if isinstance(path, (str, bytes, os.PathLike)):
                self.paths.append(os.path.abspath(os.fsdecode(path)))

        def wrap(target, name, picks):
            original = getattr(target, name)
            real[(target, name)] = original

            def fake(*a, **k):
                for p in picks(*a, **k):
                    note(p)
                return original(*a, **k)
            monkeypatch.setattr(target, name, fake)
            return original

        real_open = io.open

        def fake_open(file, mode="r", *a, **k):
            if isinstance(file, (str, bytes, os.PathLike)) and any(c in mode for c in "wax+"):
                note(file)
            return real_open(file, mode, *a, **k)
        monkeypatch.setattr(builtins, "open", fake_open)
        monkeypatch.setattr(io, "open", fake_open)
        real_os_open = os.open

        def fake_os_open(path, flags, *a, **k):
            if flags & writes:
                note(path)
            return real_os_open(path, flags, *a, **k)
        monkeypatch.setattr(os, "open", fake_os_open)
        dst = lambda src, dst, *a, **k: [dst]           # noqa: E731
        first = lambda path, *a, **k: [path]             # noqa: E731
        both = lambda src, dst, *a, **k: [dst]           # noqa: E731
        for name in ("replace", "rename", "symlink", "link"):
            wrap(os, name, dst)
        for name in ("makedirs", "mkdir", "truncate", "remove", "unlink", "rmdir"):
            if name == "truncate" and not hasattr(os, "truncate"):
                continue
            wrap(os, name, first)
        for name in ("copy", "copy2", "copyfile", "copytree", "move"):
            wrap(shutil, name, both)
        wrap(shutil, "rmtree", first)
        self_path = lambda self, *a, **k: [self]          # noqa: E731
        for name in ("write_text", "write_bytes", "mkdir", "touch", "symlink_to", "hardlink_to"):
            if hasattr(Path, name):
                wrap(Path, name, self_path)
        path_open = Path.open

        def fake_path_open(self, mode="r", *a, **k):
            if any(c in mode for c in "wax+"):
                note(self)
            return path_open(self, mode, *a, **k)
        monkeypatch.setattr(Path, "open", fake_path_open)
        real_mkstemp, real_mkdtemp = tempfile.mkstemp, tempfile.mkdtemp

        def fake_mkstemp(*a, **k):
            fd, name = real_mkstemp(*a, **k)
            note(name)
            return fd, name

        def fake_mkdtemp(*a, **k):
            name = real_mkdtemp(*a, **k)
            note(name)
            return name
        monkeypatch.setattr(tempfile, "mkstemp", fake_mkstemp)
        monkeypatch.setattr(tempfile, "mkdtemp", fake_mkdtemp)
        for name in ("NamedTemporaryFile", "TemporaryFile"):
            original = getattr(tempfile, name)

            def fake_tmp(*a, _original=original, **k):
                f = _original(*a, **k)
                note(getattr(f, "name", None) if isinstance(getattr(f, "name", None), str) else
                     k.get("dir") or tempfile.gettempdir())
                return f
            monkeypatch.setattr(tempfile, name, fake_tmp)

        def files_of(argv, k):
            argv = [argv] if isinstance(argv, (str, bytes, os.PathLike)) else list(argv or ())
            out = [a for a in argv[1:] if isinstance(a, (str, os.PathLike)) and os.path.isabs(os.fsdecode(a))]
            out += [getattr(k.get(r), "name", None) for r in ("stdin", "stdout", "stderr")
                    if isinstance(getattr(k.get(r), "name", None), str)]
            if k.get("cwd") is not None:
                out.append(k["cwd"])
            return out
        for name in ("Popen", "run", "call", "check_call", "check_output"):
            original = getattr(subprocess, name)

            def fake_sub(argv, *a, _original=original, **k):
                self.programs.append(argv)
                for p in files_of(argv, k):
                    note(p)
                return _original(argv, *a, **k)
            monkeypatch.setattr(subprocess, name, fake_sub)

    def runner(self, inner):
        """A notifier runner (I-9: the notifier on): the text file it is
        handed (its last argument, which the program would read) is noted."""
        def run(argv, env, timeout, wait=True):
            self.paths.append(os.path.abspath(argv[-1]))
            return inner(argv, env, timeout, wait)
        return run

    def outside(self, root):
        root = os.path.realpath(root)
        return sorted({p for p in self.paths if os.path.commonpath([os.path.realpath(p), root]) != root})


class FakeChannel:
    """A fake Sysmon channel (I-9): stands in for subprocess.Popen of
    wevtutil, by its absolute path and LIVE_ARGS, and returns the synthetic
    export; no process is started."""

    def __init__(self):
        self.calls = []

    def __call__(self, argv, **kw):
        assert argv[0] == os_sysmon.WEVTUTIL and list(argv[1:]) == list(os_sysmon.LIVE_ARGS)
        self.calls.append(argv)
        data = SYSMON_XML.read_bytes()

        class Proc:
            pid, returncode = 4242, 0

            def communicate(self, timeout=None):
                return data, b""
        return Proc()


def a4_watch(names, home, writes, attach=False, sysmon=NO_SYSMON, os_follow=None):
    runner = FakeRunner()
    notifier = make_notifier(writes.runner(runner))   # I-9: the notifier on, through a fake runner
    notifier.host = True
    w = host.HostWatch(iter(names).__next__, CATALOG, RULES, notifier, every=10, out=io.StringIO(),
                       err=io.StringIO(), home=str(home), platform="test", sysmon=sysmon, attach_hooks=attach,
                       os_follow=os_follow)
    for _ in names:
        w.tick(wait=30)
        for src in w.sources.values():
            if src.thread is not None:
                src.first_pass.wait(10)
        w.next_round = 0
    w.finish()
    return w, runner


def test_a4_without_the_flag_no_path_outside_raqib_is_written_and_with_it_only_the_hook_settings(home, tmp_path,
                                                                                                monkeypatch):
    """A4, the heart of M7.2b: the only write into any project is the hook
    settings, and only under --attach-hooks; every other source reads. REDO
    I-9: the watcher sees every write path named in Writes, the notifier
    is on (a fake runner), an os source follows a fake Sysmon channel, and
    a symlinked `.claude` (I-1) and a kept foreign trace (I-2) are probed."""
    project = tmp_path / "proj"
    project.mkdir()
    channel = FakeChannel()
    real_bounded = os_sysmon.read_live_bounded
    monkeypatch.setattr(os_sysmon, "read_live_bounded",
                        lambda timeout, helpers: real_bounded(timeout=timeout, helpers=helpers, popen=channel))

    def follow(root, log, stop, every=None, out=None, err=None, on_pass=None, after_record=None, helpers=None):
        return os_sysmon.follow(root, log, stop, every=every, out=out, err=err, nt=True, on_pass=on_pass,
                                after_record=after_record, helpers=helpers)
    writes = Writes(monkeypatch)
    # 1. no flag, the host source; the notifier knocks (NEW-AGENT, NET-TOOL)
    w, runner = a4_watch([moved("linux", project), moved("linux-agent", project), moved("linux", project)], home,
                         writes)
    assert writes.paths and writes.outside(home / ".raqib") == [] and runner.calls
    assert not (project / ".claude").exists() and sorted(p.name for p in project.iterdir()) == []
    # 2. no flag, the os source over the fake Sysmon channel
    w, runner = a4_watch([moved("windows", project), moved("windows", project)], home, writes, sysmon=SYSMON,
                         os_follow=follow)
    assert channel.calls and any(s.kind == "os" for s in w.sources.values())
    assert lines_of(source_file(w, 4100)) and writes.outside(home / ".raqib") == []
    assert sorted(p.name for p in project.iterdir()) == [] and writes.programs == []

    # 3. the flag: only <project>/.claude and its settings.json
    writes.paths.clear()
    a4_watch([moved("linux", project), moved("linux", project)], home, writes, attach=True)
    outside = writes.outside(home / ".raqib")
    norm = lambda p: os.path.normcase(os.path.normpath(str(p)))   # noqa: E731  (\\ and / alike on Windows)
    claude_dir = norm(project / ".claude")
    assert outside and all(norm(p) in (norm(project / ".claude" / "settings.json"), claude_dir) or
                           os.path.dirname(norm(p)) == claude_dir for p in outside), outside
    assert sorted(os.path.normpath(str(p.relative_to(project))) for p in project.rglob("*")) == [
        ".claude", os.path.join(".claude", "settings.json")]

    # 4. the flag over a project naming a foreign trace (I-2) and one whose .claude is a link (I-1)
    kept = tmp_path / "proj2"
    kept.mkdir()
    install.install_project(str(kept), log=str(tmp_path / "elsewhere" / "x.log"), out=io.StringIO(), err=io.StringIO())
    writes.paths.clear()
    a4_watch([moved("linux", kept, pid=95)] * 2, home, writes, attach=True)
    assert not (tmp_path / "elsewhere").exists()
    assert all(norm(p).startswith(norm(kept / ".claude")) for p in writes.outside(home / ".raqib"))
    if can_symlink(tmp_path):
        (tmp_path / "x").mkdir()
        linked = linked_project(home, tmp_path / "x")
        writes.paths.clear()
        a4_watch([moved("linux", linked, pid=95)] * 2, home, writes, attach=True)
        assert writes.outside(home / ".raqib") == [] and os.listdir(str(home / ".claude")) == []
    assert writes.programs == []


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
    assert len(lines) == 14   # M7.8: + three at the end (test_acts_judged.py); M7.4: + three lines (HOST-RHYTHM, --suspect, the only network call): test_rhythm.py; M7.5: + two
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


# --- REDO (ADR-0007 Amendment I): every change carries its test (I-14) ---------------------------------------

def can_symlink(tmp_path):
    try:
        os.symlink(str(tmp_path), str(tmp_path / "probe-link"), target_is_directory=True)
    except (OSError, NotImplementedError, AttributeError):
        return False
    os.unlink(str(tmp_path / "probe-link"))
    return True


def linked_project(home, tmp_path):
    """The reviewer's probe (P1): proj/.claude -> ~/.claude."""
    (home / ".claude").mkdir(exist_ok=True)
    project = tmp_path / "proj"
    project.mkdir()
    os.symlink(str(home / ".claude"), str(project / ".claude"), target_is_directory=True)
    return project


def test_redo_i1_a_symlinked_claude_writes_nothing_to_the_home_settings(home, tmp_path):
    if not can_symlink(tmp_path):
        pytest.skip("no symlinks here (recorded in the questions file: the junction-shaped test covers Windows)")
    project = linked_project(home, tmp_path)
    w, clock = make_host(home, [moved("linux", project, pid=95), moved("linux", project, pid=95)], attach_hooks=True)
    rounds(w, clock, 2)
    assert not (home / ".claude" / "settings.json").exists() and os.listdir(str(home / ".claude")) == []
    t = tree_of(w, 95)
    assert t["source"] == "host" and t["source_text"].startswith(host.HOOKS_LINK)
    assert host.HOOKS_LINK == "hooks: not attached (.claude is a link / outside the project)"
    assert any(h["kind"] == "hooks-not-attached" and host.HOOKS_LINK in h["detail"] for h in w.holes)
    assert any("is a link" in n for n in w.notes)
    assert w.finish()[1] == 3


def test_redo_i1_a_symlinked_settings_file_and_a_settings_outside_the_project_are_refused(home, tmp_path):
    if not can_symlink(tmp_path):
        pytest.skip("no symlinks here")
    project = tmp_path / "proj"
    (project / ".claude").mkdir(parents=True)
    other = tmp_path / "other.json"
    other.write_text("{}\n", encoding="ascii")
    os.symlink(str(other), str(project / ".claude" / "settings.json"))
    why = host.link_in_path(str(project), (".claude", "settings.json"))
    assert why and "is a link" in why
    w, clock = make_host(home, [moved("linux", project, pid=95)], attach_hooks=True)
    rounds(w, clock, 1)
    assert other.read_text(encoding="ascii") == "{}\n" and tree_of(w, 95)["source"] == "host"
    # a link above the project is not a component between it and the settings: the realpath decides
    real = tmp_path / "real"
    (real / "p").mkdir(parents=True)
    os.symlink(str(real), str(tmp_path / "via"), target_is_directory=True)
    assert host.link_in_path(str(tmp_path / "via" / "p"), (".claude", "settings.json")) is None
    w.finish()


def test_redo_i1_a_junction_shaped_claude_is_refused(home, tmp_path, monkeypatch):
    """A junction is not a symlink to os.path.islink on every Python: lstat's
    reparse-point attribute and os.path.isjunction are read too (shape test,
    on every platform; a real junction is made on Windows below)."""
    project = tmp_path / "proj"
    (project / ".claude").mkdir(parents=True)
    monkeypatch.setattr(os.path, "isjunction", lambda p: os.path.basename(str(p)) == ".claude", raising=False)
    assert "is a link" in host.link_in_path(str(project), (".claude", "settings.json"))
    w, clock = make_host(home, [moved("linux", project, pid=95)], attach_hooks=True)
    rounds(w, clock, 1)
    assert not (project / ".claude" / "settings.json").exists() and tree_of(w, 95)["source"] == "host"
    w.finish()


@pytest.mark.skipif(sys.platform != "win32", reason="a real NTFS junction needs Windows")
def test_redo_i1_a_real_junction_on_windows_writes_nothing_to_the_home_settings(home, tmp_path):
    import _winapi
    (home / ".claude").mkdir()
    project = tmp_path / "proj"
    project.mkdir()
    _winapi.CreateJunction(str(home / ".claude"), str(project / ".claude"))
    assert "is a link" in host.link_in_path(str(project), (".claude", "settings.json"))
    w, clock = make_host(home, [moved("linux", project, pid=95)], attach_hooks=True)
    rounds(w, clock, 1)
    assert os.listdir(str(home / ".claude")) == [] and tree_of(w, 95)["source"] == "host"
    w.finish()


def test_redo_i2_a_trace_the_project_settings_name_is_foreign_never_used_and_nothing_is_created_there(home,
                                                                                                    tmp_path):
    project = tmp_path / "proj"
    project.mkdir()
    elsewhere = tmp_path / "elsewhere" / "deep" / "x.log"
    install.install_project(str(project), log=str(elsewhere), out=io.StringIO(), err=io.StringIO())
    assert not (tmp_path / "elsewhere").exists()
    w, clock = make_host(home, [moved("linux", project, pid=95), moved("linux", project, pid=95)], attach_hooks=True)
    rounds(w, clock, 2)
    assert not (tmp_path / "elsewhere").exists()   # P2: no directory is made where the project points
    src = w.sources[next(k for k in w.sources if k[0] == 95)]
    assert src.kind == "hooks" and src.feeds[0].path.startswith(str(home / ".raqib" / "traces"))
    norm = lambda p: os.path.normcase(os.path.normpath(str(p)))   # noqa: E731  (\\ and / alike on Windows)
    assert [norm(p) for p in install.installed_traces(str(project))] == [norm(src.feeds[0].path)]   # replaced
    (note,) = [n for n in w.notes if "is foreign" in n]
    assert "elsewhere" in note and "x.log" in note and "nothing was created there" in note
    w.finish()


def hooked(home, tmp_path, names=None):
    project = tmp_path / "proj"
    project.mkdir(exist_ok=True)
    names = names or [moved("linux", project, pid=95)] * 3
    runner = FakeRunner()
    w, clock = make_host(home, [copy.deepcopy(n) for n in names], runner=runner, attach_hooks=True)
    rounds(w, clock, 1)
    src = w.sources[next(k for k in w.sources if k[0] == 95)]
    assert src.kind == "hooks"
    return w, clock, src, project, runner


def hook_line(project, seq, phase, tool="-", session="s1", cwd=None, **meta):
    line = {"ts": "2026-11-04T10:00:%02d.000Z" % seq, "seq": seq, "session_id": session, "phase": phase,
            "tool": tool, "cwd": str(cwd or project)}
    if meta:
        line["input_meta"] = meta
    return line


def write_hooks(src, lines):
    with open(src.feeds[0].path, "a", encoding="ascii") as f:
        for line in lines:
            f.write(json.dumps(line) + "\n")


def test_redo_i3_a_source_silence_pending_at_stop_is_an_alarm_of_the_tree_pending_at_exit(home, tmp_path):
    w, clock, src, project, runner = hooked(home, tmp_path)
    write_hooks(src, [hook_line(project, 1, "session_start")])
    w.tick()
    assert not w.source_findings   # pending: not judged live (later lines can take it back)
    text, code = w.finish()
    (f,) = [f for f in w.source_findings if f["rule_id"] == "SILENCE-OPEN"]
    assert f["pending"] and f["state"] == host.PENDING_EXIT and f in w.source_alarms()
    assert code == 1 and "SILENCE-OPEN on pid 95 (pending at exit)" in text
    assert "1 live, of them 1 pending at exit" in text and "pending for good is silence (ADR-0005 B-1)" in text
    assert tree_of(w, 95)["source_findings"] == {host.PENDING_EXIT: 1}


def test_redo_i3_a_closed_session_leaves_nothing_pending(home, tmp_path):
    w, clock, src, project, runner = hooked(home, tmp_path)
    write_hooks(src, [hook_line(project, 1, "session_start"), hook_line(project, 2, "stop")])
    w.tick()
    text, code = w.finish()
    assert not [f for f in w.source_findings if f["pending"]] and "SILENCE-OPEN" not in text


def test_redo_i4_hooks_with_no_line_after_two_rounds_are_a_hole_said_once(home, tmp_path):
    w, clock, src, project, runner = hooked(home, tmp_path, [moved("linux", tmp_path / "proj", pid=95)] * 4)
    rounds(w, clock, 3)
    (hole,) = [h for h in w.holes if h["kind"] == "hooks-silent"]
    assert host.HOOKS_SILENT == "hooks attached, no line yet" and host.HOOKS_SILENT in hole["detail"]
    assert host.HOOKS_SILENT in tree_of(w, 95)["source_text"] or host.HOOKS_SILENT in src.text
    assert w.finish()[1] == 3


def test_redo_i4_hooks_that_write_are_not_silent(home, tmp_path):
    w, clock, src, project, runner = hooked(home, tmp_path, [moved("linux", tmp_path / "proj", pid=95)] * 4)
    write_hooks(src, [hook_line(project, 1, "session_start"), hook_line(project, 2, "stop")])
    rounds(w, clock, 3)
    assert not [h for h in w.holes if h["kind"] == "hooks-silent"]
    w.finish()


def without(name, pid):
    i = copy.deepcopy(inv(name))
    i["candidates"] = [c for c in i["candidates"] if c["pid"] != pid]
    i["act_roots"] = [c for c in i.get("act_roots", []) if c["pid"] != pid]
    return i


def test_redo_i4_gone_and_back_under_sysmon_names_the_real_reason_and_keeps_the_os_source(home):
    follow = FakeFollow()
    w, clock = make_host(home, ["windows", without("windows", 2100), "windows"], sysmon=SYSMON, os_follow=follow)
    rounds(w, clock, 3)
    t = tree_of(w, 2100)
    assert t["source"] == "os", t["source_text"]
    assert "None" not in t["source_text"] and "the os source ended: the tree is gone (round 2)" in t["source_text"]
    assert [c["root"] for c in follow.calls].count(2100) == 2
    w.finish()


class Sleeper:
    """A stand-in for wevtutil that does not return: a real child (this
    Python, sleeping), so terminate() is real. Never the agent's."""

    def __init__(self):
        self.procs = []

    def __call__(self, argv, **kw):
        import subprocess
        assert argv[0] == os_sysmon.WEVTUTIL and list(argv[1:]) == list(os_sysmon.LIVE_ARGS)
        kw["env"] = dict(os.environ)
        kw.pop("creationflags", None)
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], **kw)
        self.procs.append(proc)
        return proc


def test_redo_i5_a_wevtutil_pass_that_does_not_return_is_ended_and_recorded():
    assert os_sysmon.FOLLOW_TIMEOUT == 10.0 == notify.TIMEOUT_SECONDS
    sleeper = Sleeper()
    helpers = os_sysmon.Helpers()
    text, why = os_sysmon.read_live_bounded(timeout=0.3, helpers=helpers, popen=sleeper)
    (proc,) = sleeper.procs
    assert text is None and why.startswith("wevtutil did not return in 0.3 s") and proc.poll() is not None
    (rec,) = helpers.record
    assert "Raqib's own helper" in rec and "terminated" in rec and helpers.running == {}


def test_redo_i5_a_hung_pass_is_a_hole_of_the_tree_and_stop_ends_the_helper_still_out(home, monkeypatch):
    monkeypatch.setattr(host, "SOURCE_JOIN_SECONDS", 0.3)
    sleeper = Sleeper()
    real = os_sysmon.read_live_bounded
    monkeypatch.setattr(os_sysmon, "read_live_bounded",
                        lambda timeout, helpers: real(timeout=timeout, helpers=helpers, popen=sleeper))

    def follow(root, log, stop, every=None, out=None, err=None, on_pass=None, after_record=None, helpers=None):
        timeout = 0.2 if root == 2100 else 30.0   # 2100: its pass hangs (a hole); 3300: still out at Stop
        live = None if root in (2100, 3300) else (lambda: (None, "test: no channel"))
        return os_sysmon.follow(root, log, stop, every=5.0, out=out, err=err, nt=True, on_pass=on_pass,
                                helpers=helpers, timeout=timeout, live=live)
    w, clock = make_host(home, ["windows"], sysmon=SYSMON, os_follow=follow)
    rounds(w, clock, 1)
    src = next(s for k, s in w.sources.items() if k[0] == 2100)
    assert src.first_pass.wait(10) and src.helpers.record
    w.tick()
    assert any(h["kind"] == "source-helper" and "2100" in h["detail"] and "did not return in 0.2 s" in h["detail"]
               for h in w.holes)
    text, code = w.finish()
    for p in sleeper.procs:   # nothing of Raqib's outlives the watch
        p.wait(10)
    assert len(sleeper.procs) == 2 and all(p.poll() is not None for p in sleeper.procs)
    assert any(h["kind"] == "source-helper" and "3300" in h["detail"] and "the watch stopped" in h["detail"]
               for h in w.holes)
    assert code == 3 and "RAQIB-SILENCE" in Path(src.path).read_text(encoding="ascii")


def test_redo_i6_an_aggregate_source_finding_that_grows_is_handed_over_not_knocked_again(home, tmp_path):
    w, clock, src, project, runner = hooked(home, tmp_path)
    write_hooks(src, [hook_line(project, 1, "session_start"), hook_line(project, 2, "stop", cwd=tmp_path / "a")])
    w.tick()
    (f,) = [f for f in w.source_findings if f["rule_id"] == "SCOPE-CWD-MOVED"]
    assert f["summary"].startswith("session ran in 2 ") and f["grown"] == 0 and f.get("first")
    knocks = len(runner.calls)
    write_hooks(src, [hook_line(project, 3, "stop", cwd=tmp_path / "b")])
    w.tick()
    (g,) = [f for f in w.source_findings if f["rule_id"] == "SCOPE-CWD-MOVED"]
    assert g is f and g["grown"] == 1 and g["summary"].startswith("session ran in 3 ")
    assert len(runner.calls) == knocks   # C-2/E-2: grown, not knocked again
    text, code = w.finish()
    assert "grown 1 (not knocked again)" in text and tree_of(w, 95)["source_findings"] == {"medium": 1}


def test_redo_i6_rules_that_cannot_run_on_a_source_are_listed_once_per_source(home, tmp_path):
    w, clock, src, project, runner = hooked(home, tmp_path)
    for seq in (1, 2, 3):
        write_hooks(src, [hook_line(project, seq, "stop")])
        w.tick()
    said = [n for n in w.notes if "rule(s) did not run on it" in n]
    assert len(said) == 1 and "its hooks source" in said[0]
    assert "DRIFT-FILES (needs context: scope)" in said[0]
    assert "rule(s) did not run on it" in w.finish()[0]


def test_redo_i6_knocks_are_high_findings_and_the_first_finding_of_each_tree(home, tmp_path):
    w, clock, src, project, runner = hooked(home, tmp_path)
    curl = dict(hook_line(project, 1, "pre", tool="Bash"), input_meta={"command_head": "curl",
                                                                        "command_programs": ["curl"]})
    wget = dict(curl, seq=2, ts="2026-11-04T10:00:02.000Z")
    write_hooks(src, [curl])
    w.tick()
    (first,) = [f for f in w.source_findings if f["rule_id"] == "NET-TOOL"]
    assert first["severity"] == "medium" and first["notice"] == "sent" and first.get("first")
    assert runner.titles()[-1] == "Raqib: " + notify.FIRST_EVENT
    calls = len(runner.calls)
    write_hooks(src, [wget])
    w.tick()
    second = [f for f in w.source_findings if f["rule_id"] == "NET-TOOL"][1]
    assert second["notice"] == "not notified: severity medium" and len(runner.calls) == calls
    # a high one knocks as its rule (A-4): SILENCE-EMPTY, a session with no work
    write_hooks(src, [hook_line(project, 1, "session_start", session="s2"),
                      hook_line(project, 2, "session_end", session="s2")])
    w.tick()
    (high,) = [f for f in w.source_findings if f["rule_id"] == "SILENCE-EMPTY"]
    assert high["severity"] == "high" and high["notice"] == "sent" and runner.titles()[-1] == "Raqib: SILENCE-EMPTY"
    assert tree_of(w, 95)["first_knock"]["rule_id"] == "NET-TOOL"
    w.finish()


def test_redo_i6_a_high_first_finding_knocks_once_by_the_rule(home, tmp_path):
    w, clock, src, project, runner = hooked(home, tmp_path)
    write_hooks(src, [hook_line(project, 1, "session_start"), hook_line(project, 2, "session_end")])
    w.tick()
    (f,) = [f for f in w.source_findings if f["rule_id"] == "SILENCE-EMPTY"]
    assert f["notice"] == "sent" and runner.titles() == ["Raqib: SILENCE-EMPTY"]
    assert tree_of(w, 95)["first_knock"]["status"] == notify.BY_THE_RULE
    w.finish()


def test_redo_i8_a_pid_reused_within_a_run_gets_its_own_file(home):
    second = copy.deepcopy(inv("windows"))
    for c in second["candidates"] + second.get("act_roots", []):
        if c["pid"] == 3300:
            c["started"] = "11/1/2026 9:30:00 AM"   # the same pid, a new process
    w, clock = make_host(home, ["benign/windows-desktop", "windows", second])
    rounds(w, clock, 3)
    keys = sorted((k for k in w.trees if k[0] == 3300), key=str)
    assert len(keys) == 2
    paths = {w._source_path(k) for k in keys}
    assert len(paths) == 2 and all(os.path.basename(p).startswith("%s-3300-" % w.run) for p in paths)
    assert host.started_tag(None) == "nostart" and host.started_tag("x") != host.started_tag("y")
    assert w.sources[keys[0]].path != w.sources[keys[1]].path
    w.finish()


def test_redo_i10_stop_leaves_the_hooks_in_place_and_the_report_says_so_per_project(home, tmp_path):
    w, clock, src, project, runner = hooked(home, tmp_path)
    text, code = w.finish()
    assert (project / ".claude" / "settings.json").exists()
    assert ("HOOKS LEFT IN PLACE: %s/.claude/settings.json keeps the Raqib hooks after this watch" % project) in text
    w2, clock2 = make_host(tmp_path / "h2", ["linux"])
    rounds(w2, clock2, 1)
    assert "HOOKS LEFT IN PLACE" not in w2.finish()[0]
