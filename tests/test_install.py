"""M0.3 install script: exit criteria E1-E3 (HANDOFF.md), ADR-0001 Amendment A-3/A-4,
the M0.3 REDO from docs/review/2026-10-16-M0.3.md, and M5.1 E1 (tools/install_hooks.py,
the Windows command form of ruling Amendment 2, P3)."""
import importlib.util
import json
import os
import shlex
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from raqib.rules import silence, trace  # noqa: E402

WINDOWS = os.name == "nt"
INSTALL = ROOT / "tools" / "install_hooks.py"
WRAPPER = ROOT / "tools" / "install-hooks.sh"
# POSIX tests go through the one-line wrapper, as a user does; Windows has no sh.
DEFAULT_INSTALLER = INSTALL if WINDOWS else WRAPPER
CAPTURE = ROOT / "raqib" / "hooks" / "capture.py"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
TOOL_EVENTS = ["PreToolUse", "PostToolUse", "PostToolUseFailure"]
SESSION_EVENTS = ["SessionStart", "SessionEnd", "Stop"]
EVENTS = TOOL_EVENTS + SESSION_EVENTS


# Ruling Amendment 2 (P3), written out here so the test does not take it from the code.
LAUNCHER = ("import os,runpy,sys;p=sys.argv[1];os.path.isfile(p) or sys.exit('RAQIB-SILENCE: capture "
            "hook failed, missing '+p);sys.argv[:]=sys.argv[1:];runpy.run_path(p,run_name='__main__')")


def command_for(log, capture=CAPTURE, windows=WINDOWS, interpreter=None):
    if windows:
        interpreter, capture, log = (str(w).replace("\\", "/")
                                     for w in (interpreter or sys.executable, capture, log))
        return '"%s" -I -c "%s" "%s" "%s"' % (interpreter, LAUNCHER, capture, log)
    q = shlex.quote(str(capture))
    return ("RAQIB_HOOK=capture RAQIB_LOG=%s python3 -I %s || echo 'RAQIB-SILENCE: capture hook "
            "failed, exit' \"$?\" %s >&2" % (shlex.quote(str(log)), q, q))


def clean_env(tmp_path, **extra):
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("RAQIB_", "PYTHON", "CDPATH"))}
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    env["HOME"] = str(home)
    env["USERPROFILE"] = str(home)  # what expanduser("~") reads on Windows
    env.update(extra)
    return env


def install(tmp_path, *args, cwd=None, installer=DEFAULT_INSTALLER, **env):
    argv = ["bash", str(installer)] if str(installer).endswith(".sh") else [sys.executable, "-I", str(installer)]
    return subprocess.run([*argv, *map(str, args)], capture_output=True,
                          text=True, cwd=cwd, timeout=60, env=clean_env(tmp_path, **env))


def project(tmp_path, name="proj"):
    path = tmp_path / name
    path.mkdir()
    return path


def settings_of(proj):
    return json.loads((proj / ".claude" / "settings.json").read_text(encoding="utf-8"))


def raqib_hooks(settings, event):
    return [(g, h) for g in settings["hooks"][event] for h in g["hooks"]
            if h["command"].startswith(("RAQIB_HOOK=capture ", '"'))]


def write_settings(proj, value):
    (proj / ".claude").mkdir(parents=True, exist_ok=True)
    path = proj / ".claude" / "settings.json"
    path.write_text(value if isinstance(value, str) else json.dumps(value, indent=2), encoding="utf-8")
    return path


def fixture(name):
    return json.loads((FIXTURES / name).read_text())


# --- E1: empty project -> six entries; idempotent ---------------------------

def test_e1_empty_project_gets_six_hook_entries(tmp_path):
    proj = project(tmp_path)
    proc = install(tmp_path, proj)
    assert proc.returncode == 0, proc.stderr
    settings = settings_of(proj)
    assert sorted(settings["hooks"]) == sorted(EVENTS)
    for event in EVENTS:
        (group, hook), = raqib_hooks(settings, event)
        assert hook == {"timeout": 10, "type": "command",
                        "command": command_for(proj / "raqib.log.jsonl")}
        if event in TOOL_EVENTS:
            assert group["matcher"] == "*"
        else:
            assert "matcher" not in group
    assert proc.stdout.count("added") == 6
    assert "(default)" in proc.stdout and "note: the trace is inside the project" in proc.stdout


def test_e1_second_run_does_not_rewrite_the_file(tmp_path):
    proj = project(tmp_path)
    assert install(tmp_path, proj).returncode == 0
    path = proj / ".claude" / "settings.json"
    first = path.read_bytes()
    os.utime(path, (1, 1))
    proc = install(tmp_path, proj)
    assert proc.returncode == 0
    assert path.read_bytes() == first
    assert path.stat().st_mtime == 1
    assert "(file not rewritten)" in proc.stdout and proc.stdout.count("unchanged") == 6


def test_e1_installed_but_unchanged_user_formatting_is_not_rewritten(tmp_path):
    proj = project(tmp_path)
    assert install(tmp_path, proj).returncode == 0
    path = proj / ".claude" / "settings.json"
    compact = json.dumps(settings_of(proj), separators=(",", ":"))
    path.write_text(compact)
    assert install(tmp_path, proj).returncode == 0
    assert path.read_text() == compact


def test_e1_empty_settings_file_is_an_empty_object(tmp_path):
    proj = project(tmp_path)
    write_settings(proj, "  \n")
    assert install(tmp_path, proj).returncode == 0
    assert sorted(settings_of(proj)["hooks"]) == sorted(EVENTS)


def test_e1_relative_project_path_even_with_cdpath(tmp_path):
    proj = project(tmp_path)
    elsewhere = project(tmp_path, "elsewhere")
    (elsewhere / "proj").mkdir()
    proc = install(tmp_path, "proj", cwd=tmp_path, CDPATH=str(elsewhere))
    assert proc.returncode == 0, proc.stderr
    assert raqib_hooks(settings_of(proj), "Stop")
    assert not (elsewhere / "proj" / ".claude").exists()


# --- E2: other hooks and settings are preserved -----------------------------

OTHER = {
    "model": "sonnet",
    "permissions": {"allow": ["Bash(ls *)"], "deny": ["WebFetch"]},
    "hooks": {
        "PreToolUse": [{"matcher": "Edit|Write",
                        "hooks": [{"type": "command", "command": "/opt/guard.sh"}]}],
        "Stop": [{"hooks": [{"type": "command", "command": "/opt/exit-gate.sh"}]}],
        "Notification": [{"hooks": [{"type": "command", "command": "notify-send hi"}]}],
    },
    "note": "\u0631\u0642\u064a\u0628",
}


def test_e2_existing_hooks_and_settings_are_kept(tmp_path):
    proj = project(tmp_path)
    write_settings(proj, OTHER)
    assert install(tmp_path, proj).returncode == 0
    settings = settings_of(proj)
    for key in ("model", "permissions", "note"):
        assert settings[key] == OTHER[key]
    for event, groups in OTHER["hooks"].items():
        assert settings["hooks"][event][:len(groups)] == groups
    for event in EVENTS:
        assert len(raqib_hooks(settings, event)) == 1
    assert install(tmp_path, proj).stdout.count("unchanged") == 6
    assert "\u0631\u0642\u064a\u0628" in (proj / ".claude" / "settings.json").read_text("utf-8")


def test_e2_legacy_entry_is_replaced_and_reported(tmp_path):
    proj = project(tmp_path)
    stale = "python3 /old/place/raqib/hooks/capture.py"
    write_settings(proj, {"hooks": {"PreToolUse": [
        {"matcher": "*", "hooks": [{"type": "command", "command": "/opt/keep.sh"},
                                   {"type": "command", "command": stale}]},
        {"matcher": "*", "hooks": [{"type": "command", "command": stale}]},
    ]}})
    proc = install(tmp_path, proj)
    assert proc.returncode == 0
    assert "PreToolUse          updated" in proc.stdout
    assert "replaced: " + stale in proc.stdout
    groups = settings_of(proj)["hooks"]["PreToolUse"]
    assert groups == [
        {"matcher": "*", "hooks": [{"type": "command", "command": "/opt/keep.sh"}]},
        {"matcher": "*", "hooks": [{"timeout": 10, "type": "command",
                                    "command": command_for(proj / "raqib.log.jsonl")}]},
    ]
    assert install(tmp_path, proj).stdout.count("unchanged") == 6


def test_e2_foreign_hook_mentioning_the_path_is_kept(tmp_path):
    proj = project(tmp_path)
    foreign = {"type": "command", "command": "sha256sum /x/raqib/hooks/capture.py >> /tmp/audit"}
    write_settings(proj, {"hooks": {"PostToolUse": [{"matcher": "*", "hooks": [foreign]}]}})
    assert install(tmp_path, proj).returncode == 0
    assert settings_of(proj)["hooks"]["PostToolUse"][0] == {"matcher": "*", "hooks": [foreign]}


def test_e2_user_keys_on_our_entry_survive_an_update(tmp_path):
    proj = project(tmp_path)
    assert install(tmp_path, proj).returncode == 0
    settings = settings_of(proj)
    settings["hooks"]["Stop"][0]["hooks"][0]["timeout"] = 30
    settings["hooks"]["Stop"][0]["hooks"][0]["command"] = "python3 /moved/raqib/hooks/capture.py"
    write_settings(proj, settings)
    assert install(tmp_path, proj).returncode == 0
    (_, hook), = raqib_hooks(settings_of(proj), "Stop")
    assert hook["timeout"] == 30


def test_e2_raqib_entry_with_wrong_matcher_is_fixed(tmp_path):
    proj = project(tmp_path)
    assert install(tmp_path, proj).returncode == 0
    settings = settings_of(proj)
    settings["hooks"]["PostToolUse"][0]["matcher"] = "Bash"
    write_settings(proj, settings)
    assert "PostToolUse         updated" in install(tmp_path, proj).stdout
    (group, _), = raqib_hooks(settings_of(proj), "PostToolUse")
    assert group["matcher"] == "*"


@pytest.mark.parametrize("content", [
    "{not json",
    "[1, 2]",
    '{"hooks": []}',
    '{"hooks": {"Stop": {}}}',
    '{"model": "a", "model": "b"}',
    '{"x": NaN}',
])
def test_e2_unreadable_settings_are_left_untouched(tmp_path, content):
    proj = project(tmp_path)
    path = write_settings(proj, content)
    proc = install(tmp_path, proj)
    assert proc.returncode == 1
    assert proc.stderr.startswith("install-hooks:")
    assert path.read_text() == content
    assert [p.name for p in path.parent.iterdir()] == ["settings.json"]


def symlinked_settings(tmp_path, proj):
    shared = tmp_path / "shared.json"
    shared.write_text(json.dumps({"model": "sonnet"}))
    (proj / ".claude").mkdir()
    try:
        (proj / ".claude" / "settings.json").symlink_to(shared)
    except OSError as exc:  # Windows without the symlink privilege
        pytest.skip("cannot create a symlink here: %s" % exc)
    return shared


@pytest.mark.skipif(WINDOWS, reason="POSIX file modes; Windows has none (M5.1 E1)")
def test_e2_mode_is_kept_and_symlink_is_followed(tmp_path):
    proj = project(tmp_path)
    shared = symlinked_settings(tmp_path, proj)
    shared.chmod(0o640)
    assert install(tmp_path, proj).returncode == 0
    assert (proj / ".claude" / "settings.json").is_symlink()
    assert stat.S_IMODE(shared.stat().st_mode) == 0o640
    assert json.loads(shared.read_text())["model"] == "sonnet"
    assert len(raqib_hooks(json.loads(shared.read_text()), "Stop")) == 1


def test_m51_e1_symlink_is_followed_on_every_platform(tmp_path):
    proj = project(tmp_path)
    shared = symlinked_settings(tmp_path, proj)
    assert install(tmp_path, proj).returncode == 0
    assert (proj / ".claude" / "settings.json").is_symlink()
    assert json.loads(shared.read_text())["model"] == "sonnet"
    assert len(raqib_hooks(json.loads(shared.read_text()), "Stop")) == 1


def test_e2_unwritable_settings_dir_is_a_clean_error(tmp_path):
    proj = project(tmp_path)
    (proj / ".claude").write_text("not a directory")
    proc = install(tmp_path, proj)
    assert proc.returncode == 1
    assert proc.stderr.startswith("install-hooks:") and "Traceback" not in proc.stderr


def test_disable_all_hooks_is_an_alarm(tmp_path):
    proj = project(tmp_path)
    (proj / ".claude").mkdir()
    (proj / ".claude" / "settings.local.json").write_text('{"disableAllHooks": true}')
    proc = install(tmp_path, proj)
    assert proc.returncode == 3
    assert proc.stderr.startswith("RAQIB-SILENCE: disableAllHooks is true in ")
    assert len(raqib_hooks(settings_of(proj), "Stop")) == 1


@pytest.mark.parametrize("args", [[], ["--log"], ["proj", "--log"], ["--log", "", "proj"],
                                  ["--bogus", "proj"], ["proj", "proj"]])
def test_usage_errors_exit_2(tmp_path, args):
    proj = project(tmp_path)
    assert install(tmp_path, *args, cwd=tmp_path).returncode == 2
    assert not (proj / ".claude").exists()


def test_missing_project_exits_2(tmp_path):
    proc = install(tmp_path, tmp_path / "nope")
    assert proc.returncode == 2
    assert not (tmp_path / "nope").exists()


# --- the trace location -----------------------------------------------------

def test_log_option_is_absolute_and_kept_on_reinstall(tmp_path):
    proj = project(tmp_path)
    proc = install(tmp_path, "--log", "outside/trace.jsonl", proj, cwd=tmp_path)
    assert proc.returncode == 0
    log = tmp_path / "outside" / "trace.jsonl"
    (_, hook), = raqib_hooks(settings_of(proj), "PreToolUse")
    assert hook["command"] == command_for(log)
    proc = install(tmp_path, proj)
    assert "kept from the existing install" in proc.stdout
    assert proc.stdout.count("unchanged") == 6


# --- E3: the installed commands really capture, and never block -------------

def run_hook(command, payload, cwd, env, shell=None):
    """Run a hook command through a shell, as Claude Code does. Windows: the
    command line Node's spawn(..., {shell: true}) gives cmd.exe."""
    if shell is None:
        shell = "cmd" if WINDOWS else "/bin/sh"
    argv = 'cmd.exe /d /s /c "%s"' % command if shell == "cmd" else [shell, "-c", command]
    return subprocess.run(argv, input=json.dumps(payload).encode(),
                          capture_output=True, cwd=cwd, env=env, timeout=30)


SESSION = [
    ("SessionStart", "sessionstart.json"),
    ("PreToolUse", "pretooluse-bash.json"),
    ("PostToolUse", "posttooluse-bash.json"),
    ("Stop", "stop.json"),
    ("SessionEnd", "sessionend.json"),
]


def simulate(proj, env, cwd=None):
    settings = settings_of(proj)
    for event, name in SESSION:
        (_, hook), = raqib_hooks(settings, event)
        proc = run_hook(hook["command"], fixture(name), cwd or proj, env)
        assert (proc.returncode, proc.stdout, proc.stderr) == (0, b"", b"")


def trace_lines(path):
    return [json.loads(x) for x in path.read_text().splitlines()]


def test_e3_installed_commands_write_one_clean_session(tmp_path):
    proj = project(tmp_path)
    assert install(tmp_path, proj).returncode == 0
    elsewhere = project(tmp_path, "agent-cd-here")
    simulate(proj, clean_env(tmp_path), cwd=elsewhere)
    recs = trace_lines(proj / "raqib.log.jsonl")
    assert [(r["phase"], r["seq"]) for r in recs] == [
        ("session_start", 1), ("pre", 2), ("post", 2), ("stop", 3), ("session_end", 4)]
    assert silence.findings(recs) == []
    assert not (elsewhere / "raqib.log.jsonl").exists()


def copy_checkout(dest):
    shutil.copytree(ROOT / "raqib", dest / "raqib")
    shutil.copytree(ROOT / "tools", dest / "tools")
    return dest / "tools" / DEFAULT_INSTALLER.name


@pytest.mark.skipif(WINDOWS, reason="$ is refused on Windows; see test_m51_e1_windows_paths_*")
def test_e3_paths_with_spaces_quotes_and_dollars(tmp_path):
    odd = tmp_path / "it's a $HOME dir"
    copy_checkout(odd)
    proj = project(tmp_path, "my proj")
    proc = install(tmp_path, proj, installer=odd / "tools" / "install-hooks.sh")
    assert proc.returncode == 0, proc.stderr
    (_, hook), = raqib_hooks(settings_of(proj), "PreToolUse")
    assert hook["command"] == command_for(proj / "raqib.log.jsonl", odd / "raqib" / "hooks" / "capture.py")
    simulate(proj, clean_env(tmp_path))
    assert len(trace_lines(proj / "raqib.log.jsonl")) == 5


@pytest.mark.skipif(WINDOWS, reason="POSIX wrapper; Windows: test_m51_*_never_exits_2")
def test_b1_missing_capture_never_blocks(tmp_path):
    copy = tmp_path / "checkout"
    installer = copy_checkout(copy)
    proj = project(tmp_path)
    assert install(tmp_path, proj, installer=installer).returncode == 0
    shutil.rmtree(copy)
    for event in EVENTS:
        (_, hook), = raqib_hooks(settings_of(proj), event)
        proc = run_hook(hook["command"], fixture("pretooluse-bash.json"), proj, clean_env(tmp_path))
        assert proc.returncode == 0
        assert proc.stdout == b""
        assert any(line.startswith("RAQIB-SILENCE: capture hook failed, exit 2 ")
                   for line in proc.stderr.decode().splitlines())


@pytest.mark.skipif(WINDOWS, reason="POSIX wrapper; Windows: test_m51_*_never_exits_2")
def test_b1_missing_python_never_blocks(tmp_path):
    proj = project(tmp_path)
    assert install(tmp_path, proj).returncode == 0
    (_, hook), = raqib_hooks(settings_of(proj), "Stop")
    env = clean_env(tmp_path, PATH=str(tmp_path / "empty-bin"))
    proc = run_hook(hook["command"], fixture("stop.json"), proj, env)
    assert proc.returncode == 0
    assert "RAQIB-SILENCE: capture hook failed, exit 127 " in proc.stderr.decode()


def test_b2_pythonpath_cannot_shadow_the_stdlib(tmp_path):
    evil = tmp_path / "evil"
    evil.mkdir()
    (evil / "json.py").write_text("raise SystemExit(2)\n")
    proj = project(tmp_path)
    assert install(tmp_path, proj, cwd=evil, PYTHONPATH=str(evil)).returncode == 0
    simulate(proj, clean_env(tmp_path, PYTHONPATH=str(evil)), cwd=evil)
    assert len(trace_lines(proj / "raqib.log.jsonl")) == 5


def test_e3_real_quickstart_trace_is_clean():
    """Raw trace of the README quickstart: fresh clone of b72f109, Claude Code 2.1.301."""
    recs, problems = trace.read(FIXTURES / "quickstart-claude-code-2.1.301.log")
    assert problems == []
    assert [(r["phase"], r["seq"]) for r in recs] == [
        ("session_start", 1), ("pre", 2), ("post", 2), ("stop", 3), ("session_end", 4)]
    pre, post = recs[1], recs[2]
    assert pre["tool_use_id"] == post["tool_use_id"]
    assert pre["input_meta"] == {"command_head": "echo"}
    assert post["ok"] is True
    assert silence.findings(recs) == []


def test_e3_real_blocked_calls_leave_a_pre_without_post():
    """Raw trace: Claude Code blocked `ls` and `cd` outside the project; `whoami` ran.
    A blocked call fires PreToolUse only, so SILENCE-HALF reports it (M0.3 questions)."""
    recs, problems = trace.read(FIXTURES / "blocked-calls-claude-code-2.1.301.log")
    assert problems == []
    assert [(r["phase"], r["seq"], r["input_meta"].get("command_head") if "input_meta" in r else None)
            for r in recs] == [
        ("session_start", 1, None), ("pre", 2, "ls"), ("pre", 3, "cd"), ("pre", 4, "whoami"),
        ("post", 4, "whoami"), ("stop", 5, None), ("session_end", 6, None)]
    assert [(f["rule_id"], f["cited_seq"]) for f in silence.findings(recs)] == [
        ("SILENCE-HALF", [2]), ("SILENCE-HALF", [3])]


# --- M1.2 REDO: installer residuals from docs/review/2026-10-16-M1.1.md -----

@pytest.mark.parametrize("stale", [
    "python3 '/old place/raqib/hooks/capture.py'",
    "RAQIB_LOG='/t r/x.jsonl' python3 \"/old place/raqib/hooks/capture.py\"",
    "python3 raqib/hooks/capture.py",
], ids=["quoted-path", "quoted-log-and-path", "relative"])
def test_redo_m3_quoted_legacy_entries_are_replaced(tmp_path, stale):
    proj = project(tmp_path)
    write_settings(proj, {"hooks": {"Stop": [{"hooks": [{"type": "command", "command": stale}]}]}})
    proc = install(tmp_path, "--log", tmp_path / "t.jsonl", proj)
    assert proc.returncode == 0
    assert "replaced: " + stale in proc.stdout
    assert [h["command"] for g in settings_of(proj)["hooks"]["Stop"] for h in g["hooks"]] == [
        command_for(tmp_path / "t.jsonl")]


@pytest.mark.parametrize("command", [
    "python3 /x/raqib/hooks/capture.py --extra",
    "python3 /x/not-raqib/hooks/capture.py.bak",
    "python3 '/x/raqib/hooks/capture.py",
], ids=["extra-argument", "other-file", "unbalanced-quote"])
def test_redo_m3_lookalike_commands_are_foreign(tmp_path, command):
    proj = project(tmp_path)
    foreign = {"type": "command", "command": command}
    write_settings(proj, {"hooks": {"Stop": [{"hooks": [foreign]}]}})
    assert install(tmp_path, proj).returncode == 0
    assert settings_of(proj)["hooks"]["Stop"][0] == {"hooks": [foreign]}


def test_redo_m4_disagreeing_existing_logs_are_refused(tmp_path):
    proj = project(tmp_path)
    assert install(tmp_path, "--log", tmp_path / "a.jsonl", proj).returncode == 0
    settings = settings_of(proj)
    settings["hooks"]["Stop"][0]["hooks"][0]["command"] = command_for(tmp_path / "b.jsonl")
    path = write_settings(proj, settings)
    before = path.read_bytes()
    proc = install(tmp_path, proj)
    assert proc.returncode == 1
    assert "different traces" in proc.stderr and "--log" in proc.stderr
    assert path.read_bytes() == before
    assert install(tmp_path, "--log", tmp_path / "b.jsonl", proj).returncode == 0


def test_redo_m4_kept_relative_log_is_made_absolute(tmp_path):
    proj = project(tmp_path)
    stale = "RAQIB_LOG=logs/trace.jsonl python3 /old/raqib/hooks/capture.py"
    write_settings(proj, {"hooks": {"Stop": [{"hooks": [{"type": "command", "command": stale}]}]}})
    proc = install(tmp_path, proj)
    assert proc.returncode == 0
    assert "trace: %s (kept" % (proj / "logs" / "trace.jsonl") in proc.stdout
    (_, hook), = raqib_hooks(settings_of(proj), "Stop")
    assert hook["command"] == command_for(proj / "logs" / "trace.jsonl")


@pytest.mark.skipif(WINDOWS, reason="POSIX umask; Windows has none (M5.1 E1)")
def test_redo_m2_new_settings_file_follows_the_umask(tmp_path):
    proj = project(tmp_path)
    proc = subprocess.run(["bash", "-c", 'umask 077 && exec bash "$0" "$1"', str(WRAPPER), str(proj)],
                          capture_output=True, text=True, timeout=60, env=clean_env(tmp_path))
    assert proc.returncode == 0, proc.stderr
    assert stat.S_IMODE((proj / ".claude" / "settings.json").stat().st_mode) == 0o600


# --- M1.2 REDO: real traces written by the current capture ------------------

def test_redo_real_quickstart_with_output_meta():
    """README quickstart from a fresh clone of d7841d1, Claude Code 2.1.301."""
    recs, problems = trace.read(FIXTURES / "quickstart-d7841d1-claude-code-2.1.301.log")
    assert problems == []
    assert [(r["phase"], r["seq"]) for r in recs] == [
        ("session_start", 1), ("pre", 2), ("post", 2), ("stop", 3), ("session_end", 4)]
    assert recs[1]["input_meta"] == {"command_head": "echo"}
    assert recs[2]["output_meta"] == {"scan": "full", "secret_kinds": []}
    assert silence.findings(recs) == []


def test_redo_real_file_tools_and_a_real_failure():
    """Write, Edit, Read and a Read of a missing file (d7841d1, Claude Code 2.1.301).
    The missing file fired PostToolUseFailure: ok false, error_class "failure"."""
    recs, problems = trace.read(FIXTURES / "file-tools-d7841d1-claude-code-2.1.301.log")
    assert problems == []
    posts = [(r["seq"], r["tool"], r["ok"], r.get("error_class"), r["output_meta"]["scan"])
             for r in recs if r["phase"] == "post"]
    assert posts == [(2, "Write", True, None, "full"), (3, "Edit", True, None, "full"),
                     (4, "Read", True, None, "full"), (5, "Read", False, "failure", "full")]
    assert all(r["input_meta"]["path"].startswith(r["cwd"] + "/") for r in recs if r["phase"] == "pre")
    assert silence.findings(recs) == []


@pytest.mark.skipif(WINDOWS, reason="Windows cannot sync a directory; the installer skips it (M5.1 E1)")
def test_redo2_a_failed_directory_sync_is_a_warning_not_nothing_changed(tmp_path):
    # Run the installer's Python with os.fsync failing on directories only;
    # without -I, so the shim on PYTHONPATH is loaded.
    proj = project(tmp_path)
    shim = tmp_path / "shim"
    shim.mkdir()
    (shim / "sitecustomize.py").write_text(
        "import os, stat\n"
        "_fsync = os.fsync\n"
        "def fsync(fd):\n"
        "    if stat.S_ISDIR(os.fstat(fd).st_mode):\n"
        "        raise OSError(5, 'simulated directory fsync failure')\n"
        "    return _fsync(fd)\n"
        "os.fsync = fsync\n")
    proc = subprocess.run([sys.executable, str(INSTALL), str(proj)], capture_output=True, text=True,
                          timeout=60, env=clean_env(tmp_path, PYTHONPATH=str(shim)))
    assert proc.returncode == 0, proc.stderr
    assert "could not be synced" in proc.stderr and "nothing changed" not in proc.stderr
    assert len(settings_of(proj)["hooks"]) == 6


# --- M5.1 E1: the Python installer and the Windows command form -------------

def load_installer():
    spec = importlib.util.spec_from_file_location("raqib_install_hooks_under_test", INSTALL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_m51_e1_the_sh_installer_is_a_one_line_wrapper():
    lines = WRAPPER.read_text().splitlines()
    assert lines[0].startswith("#!") and len(lines) == 2
    assert lines[1] == 'exec python3 -I "$(dirname "$0")/install_hooks.py" "$@"'


def test_m51_e1_posix_command_is_unchanged():
    mod = load_installer()
    log, capture = "/t r/it's.jsonl", "/a $b/raqib/hooks/capture.py"
    assert mod.posix_command(log, capture) == command_for(log, capture, windows=False)


WIN_PY = r"C:\Program Files\Python312\python.exe"
WIN_CAPTURE = r"C:\Users\me\src\raqib\raqib\hooks\capture.py"
WIN_LOG = r"D:\traces\proj\raqib.log.jsonl"


def test_m51_e1_windows_command_form():
    mod = load_installer()
    command = mod.windows_command(WIN_LOG, WIN_CAPTURE, WIN_PY)
    assert command == ('"C:/Program Files/Python312/python.exe" -I -c "' + LAUNCHER + '" '
                       '"C:/Users/me/src/raqib/raqib/hooks/capture.py" "D:/traces/proj/raqib.log.jsonl"')
    assert command == command_for(WIN_LOG, WIN_CAPTURE, windows=True, interpreter=WIN_PY)
    # No shell syntax: outside the quotes there is only -I, -c and spaces; inside,
    # nothing that cmd.exe or a POSIX shell expands within double quotes.
    assert "".join(command.split('"')[0::2]) == " -I -c   "
    assert not set('%$`!\\') & set(LAUNCHER)
    hook = {"type": "command", "command": command}
    assert mod.is_raqib(hook) and mod.log_of(hook) == "D:/traces/proj/raqib.log.jsonl"
    unc = mod.windows_command(r"\\srv\share\t.jsonl", r"\\srv\share\raqib\raqib\hooks\capture.py", WIN_PY)
    assert unc.endswith('"//srv/share/raqib/raqib/hooks/capture.py" "//srv/share/t.jsonl"')
    assert mod.log_of({"command": unc}) == "//srv/share/t.jsonl"


@pytest.mark.parametrize("command, ours", [
    (command_for("C:/t.jsonl", "C:/r/raqib/hooks/capture.py", windows=True, interpreter="C:/py.exe"), True),
    ('"C:/py.exe" -I -c "import x" "C:/r/raqib/hooks/capture.py"', True),
    ('"C:/py.exe" -I "C:/r/raqib/hooks/capture.py"', True),
    ('  "py" -I "C:\\r\\raqib\\hooks\\capture.py"  "C:/t.jsonl" ', True),
    ('"C:/py.exe" "C:/r/raqib/hooks/capture.py"', False),
    ('"C:/py.exe" -I "C:/r/raqib/hooks/capture.py" "a" "b"', False),
    ('"C:/py.exe" -I "C:/r/not-raqib/hooks/capture.py.bak"', False),
    ('python3 -I /x/raqib/hooks/capture.py', False),
], ids=["p3", "other-launcher-no-log", "no-launcher-no-log", "backslashes-and-spaces",
        "no-isolation-flag", "extra-word", "other-file", "unquoted"])
def test_m51_e1_windows_form_is_recognised_exactly(command, ours):
    assert load_installer().is_raqib({"type": "command", "command": command}) is ours


@pytest.mark.parametrize("char", ["%", "$", "`", "!", '"', "\n"])
def test_m51_e1_windows_command_refuses_what_a_shell_would_expand(char):
    mod = load_installer()
    with pytest.raises(mod.Exit) as exc:
        mod.windows_command("C:\\t%s\\raqib.log.jsonl" % char, WIN_CAPTURE, WIN_PY)
    assert exc.value.code == 2 and "may expand" in exc.value.message


def run_windows_installer(mod, monkeypatch, tmp_path, *args):
    """The installer in-process with the Windows branch on, on any platform."""
    monkeypatch.setattr(mod, "WINDOWS", True)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "home"))
    return mod.main([str(a) for a in args])


def test_m51_e1_windows_form_fresh_merge_and_second_run(tmp_path, monkeypatch, capsys):
    mod = load_installer()
    proj = project(tmp_path)
    path = write_settings(proj, OTHER)
    assert run_windows_installer(mod, monkeypatch, tmp_path, proj) == 0
    assert capsys.readouterr().out.count("added") == 6
    settings = settings_of(proj)
    for key in ("model", "permissions", "note"):
        assert settings[key] == OTHER[key]
    for event, groups in OTHER["hooks"].items():
        assert settings["hooks"][event][:len(groups)] == groups
    expected = command_for(proj / "raqib.log.jsonl", windows=True)
    for event in EVENTS:
        (_, hook), = raqib_hooks(settings, event)
        assert hook == {"timeout": 10, "type": "command", "command": expected}
    first = path.read_bytes()
    os.utime(path, (1, 1))
    assert run_windows_installer(mod, monkeypatch, tmp_path, proj) == 0
    out = capsys.readouterr().out
    assert "(file not rewritten)" in out and out.count("unchanged") == 6
    assert path.read_bytes() == first and path.stat().st_mtime == 1


def test_m51_e1_windows_form_replaces_a_posix_entry_and_keeps_its_trace(tmp_path, monkeypatch, capsys):
    mod = load_installer()
    proj = project(tmp_path)
    log = tmp_path / "elsewhere" / "t.jsonl"
    posix = command_for(log, windows=False)
    write_settings(proj, {"hooks": {"Stop": [{"hooks": [{"type": "command", "command": posix}]}]}})
    assert run_windows_installer(mod, monkeypatch, tmp_path, proj) == 0
    out = capsys.readouterr().out
    assert "Stop                updated" in out and "replaced: " + posix in out
    assert "(kept from the existing install)" in out
    (_, hook), = raqib_hooks(settings_of(proj), "Stop")
    assert hook["command"] == command_for(os.path.normpath(str(log)), windows=True)
    # And back: a POSIX install replaces the Windows entry the same way.
    monkeypatch.setattr(mod, "WINDOWS", False)
    assert mod.main([str(proj)]) == 0
    assert "kept from the existing install" in capsys.readouterr().out


@pytest.mark.skipif(WINDOWS, reason="runs the form under /bin/sh; Windows: test_m51_windows_hook_*")
def test_m51_e1_windows_form_means_the_same_with_or_without_a_shell(tmp_path):
    """No shell syntax: sh -c and a plain exec of the split words both run
    the launcher, which runs capture with the log as its argument, from any cwd."""
    log = tmp_path / "trace.jsonl"
    command = load_installer().windows_command(str(log), str(CAPTURE), sys.executable)
    elsewhere = project(tmp_path, "agent-cd-here")
    env = clean_env(tmp_path, RAQIB_LOG=str(tmp_path / "decoy.jsonl"))
    for argv in (["/bin/sh", "-c", command], shlex.split(command)):
        proc = subprocess.run(argv, input=json.dumps(fixture("stop.json")).encode(),
                              capture_output=True, cwd=elsewhere, env=env, timeout=30)
        assert (proc.returncode, proc.stdout, proc.stderr) == (0, b"", b"")
    assert [r["phase"] for r in trace_lines(log)] == ["stop", "stop"]
    assert not (tmp_path / "decoy.jsonl").exists()
    assert not (elsewhere / "raqib.log.jsonl").exists()


@pytest.mark.skipif(not WINDOWS, reason="cmd.exe and Git for Windows")
def test_m51_windows_hook_runs_under_cmd_and_git_bash(tmp_path):
    proj = project(tmp_path)
    assert install(tmp_path, proj).returncode == 0
    (_, hook), = raqib_hooks(settings_of(proj), "Stop")
    # Git for Windows is on windows-latest; its absence is a failure, not a
    # quiet loss of the Git Bash evidence (A3, review F6).
    git = shutil.which("git")
    assert git, "git is not on PATH"
    # git.exe sits in <Git>/cmd, <Git>/bin or <Git>/mingw64/bin; bash.exe in <Git>/bin.
    found = [p / "bin" / "bash.exe" for p in list(Path(git).resolve().parents)[:3]
             if (p / "bin" / "bash.exe").is_file()]
    assert found, "Git Bash not found near %s" % git
    shells = ["cmd", str(found[0])]
    for shell in shells:
        proc = run_hook(hook["command"], fixture("stop.json"), tmp_path, clean_env(tmp_path), shell=shell)
        assert (proc.returncode, proc.stdout, proc.stderr) == (0, b"", b""), shell
    assert len(trace_lines(proj / "raqib.log.jsonl")) == len(shells)


@pytest.mark.skipif(not WINDOWS, reason="the Windows refusal of shell characters, end to end")
def test_m51_e1_windows_paths_with_spaces_and_quotes(tmp_path):
    odd = tmp_path / "it's a dir"
    installer = copy_checkout(odd)
    proj = project(tmp_path, "my proj")
    proc = install(tmp_path, proj, installer=installer)
    assert proc.returncode == 0, proc.stderr
    (_, hook), = raqib_hooks(settings_of(proj), "PreToolUse")
    assert hook["command"] == command_for(proj / "raqib.log.jsonl", odd / "raqib" / "hooks" / "capture.py")
    simulate(proj, clean_env(tmp_path))
    assert len(trace_lines(proj / "raqib.log.jsonl")) == 5
    dollar = project(tmp_path, "a $HOME proj")
    proc = install(tmp_path, dollar)
    assert proc.returncode == 2 and "may expand" in proc.stderr
    assert not (dollar / ".claude").exists()


# --- M5.1 E1: a missing capture.py is never exit 2 (ruling Amendment 2, Q-1) -

def test_m51_e1_python_itself_exits_2_when_the_script_is_missing(tmp_path):
    """Why the launcher exists: CPython's status for a missing script is 2,
    the status Claude Code reads as "block"."""
    gone = tmp_path / "gone" / "raqib" / "hooks" / "capture.py"
    proc = subprocess.run([sys.executable, "-I", str(gone)], input=b"{}", capture_output=True, timeout=30)
    assert proc.returncode == 2


def plain_exec(command):
    """The command run with no shell: split by POSIX rules, or on Windows
    handed to CreateProcess as it is."""
    return command if WINDOWS else shlex.split(command)


def test_m51_e1_windows_form_missing_capture_exits_1_with_silence(tmp_path):
    gone = tmp_path / "gone" / "raqib" / "hooks" / "capture.py"
    log = tmp_path / "trace.jsonl"
    command = command_for(log, gone, windows=True)
    for shell in ("shell", "exec"):
        if shell == "shell":
            proc = run_hook(command, fixture("pretooluse-bash.json"), tmp_path, clean_env(tmp_path))
        else:
            proc = subprocess.run(plain_exec(command), input=b"{}", capture_output=True, cwd=tmp_path,
                                  env=clean_env(tmp_path), timeout=30)
        assert (proc.returncode, proc.stdout) == (1, b""), shell
        (line,) = proc.stderr.decode().splitlines()
        assert line == "RAQIB-SILENCE: capture hook failed, missing " + str(gone).replace("\\", "/")
    assert not log.exists()


@pytest.mark.skipif(not WINDOWS, reason="the installed Windows command, run through cmd.exe")
def test_m51_windows_installed_hook_with_capture_or_python_missing_never_exits_2(tmp_path):
    copy = tmp_path / "checkout"
    installer = copy_checkout(copy)
    proj = project(tmp_path)
    assert install(tmp_path, proj, installer=installer).returncode == 0
    shutil.rmtree(copy)
    (_, hook), = raqib_hooks(settings_of(proj), "PreToolUse")
    proc = run_hook(hook["command"], fixture("pretooluse-bash.json"), proj, clean_env(tmp_path))
    assert proc.returncode == 1
    assert proc.stderr.decode().startswith("RAQIB-SILENCE: capture hook failed, missing ")
    # A missing python.exe is a hook error from cmd.exe: no RAQIB-SILENCE line,
    # and not 2 (block). Both cmd.exe paths: the file gone, or its directory.
    (tmp_path / "no").mkdir()
    for interpreter in (tmp_path / "no" / "python.exe", tmp_path / "gone-dir" / "python.exe"):
        command = command_for(proj / "raqib.log.jsonl", CAPTURE, interpreter=interpreter)
        proc = run_hook(command, fixture("pretooluse-bash.json"), proj, clean_env(tmp_path))
        assert proc.returncode not in (0, 2), (interpreter, proc.returncode)
        assert b"RAQIB-SILENCE" not in proc.stderr
