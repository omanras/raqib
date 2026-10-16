"""M0.3 install script: exit criteria E1-E3 (HANDOFF.md), ADR-0001 Amendment A-3/A-4,
and the M0.3 REDO from docs/review/2026-10-16-M0.3.md."""
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

INSTALL = ROOT / "tools" / "install-hooks.sh"
CAPTURE = ROOT / "raqib" / "hooks" / "capture.py"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
TOOL_EVENTS = ["PreToolUse", "PostToolUse", "PostToolUseFailure"]
SESSION_EVENTS = ["SessionStart", "SessionEnd", "Stop"]
EVENTS = TOOL_EVENTS + SESSION_EVENTS


def command_for(log, capture=CAPTURE):
    q = shlex.quote(str(capture))
    return ("RAQIB_HOOK=capture RAQIB_LOG=%s python3 -I %s || echo 'RAQIB-SILENCE: capture hook "
            "failed, exit' \"$?\" %s >&2" % (shlex.quote(str(log)), q, q))


def clean_env(tmp_path, **extra):
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("RAQIB_", "PYTHON", "CDPATH"))}
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    env["HOME"] = str(home)
    env.update(extra)
    return env


def install(tmp_path, *args, cwd=None, installer=INSTALL, **env):
    return subprocess.run(["bash", str(installer), *map(str, args)], capture_output=True,
                          text=True, cwd=cwd, timeout=60, env=clean_env(tmp_path, **env))


def project(tmp_path, name="proj"):
    path = tmp_path / name
    path.mkdir()
    return path


def settings_of(proj):
    return json.loads((proj / ".claude" / "settings.json").read_text())


def raqib_hooks(settings, event):
    return [(g, h) for g in settings["hooks"][event] for h in g["hooks"]
            if h["command"].startswith("RAQIB_HOOK=capture ")]


def write_settings(proj, value):
    (proj / ".claude").mkdir(parents=True, exist_ok=True)
    path = proj / ".claude" / "settings.json"
    path.write_text(value if isinstance(value, str) else json.dumps(value, indent=2))
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


def test_e2_mode_is_kept_and_symlink_is_followed(tmp_path):
    proj = project(tmp_path)
    shared = tmp_path / "shared.json"
    shared.write_text(json.dumps({"model": "sonnet"}))
    shared.chmod(0o640)
    (proj / ".claude").mkdir()
    (proj / ".claude" / "settings.json").symlink_to(shared)
    assert install(tmp_path, proj).returncode == 0
    assert (proj / ".claude" / "settings.json").is_symlink()
    assert stat.S_IMODE(shared.stat().st_mode) == 0o640
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

def run_hook(command, payload, cwd, env):
    return subprocess.run(["/bin/sh", "-c", command], input=json.dumps(payload).encode(),
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


def test_e3_paths_with_spaces_quotes_and_dollars(tmp_path):
    odd = tmp_path / "it's a $HOME dir"
    shutil.copytree(ROOT / "raqib", odd / "raqib")
    shutil.copytree(ROOT / "tools", odd / "tools")
    proj = project(tmp_path, "my proj")
    proc = install(tmp_path, proj, installer=odd / "tools" / "install-hooks.sh")
    assert proc.returncode == 0, proc.stderr
    (_, hook), = raqib_hooks(settings_of(proj), "PreToolUse")
    assert hook["command"] == command_for(proj / "raqib.log.jsonl", odd / "raqib" / "hooks" / "capture.py")
    simulate(proj, clean_env(tmp_path))
    assert len(trace_lines(proj / "raqib.log.jsonl")) == 5


def test_b1_missing_capture_never_blocks(tmp_path):
    copy = tmp_path / "checkout"
    shutil.copytree(ROOT / "raqib", copy / "raqib")
    shutil.copytree(ROOT / "tools", copy / "tools")
    proj = project(tmp_path)
    assert install(tmp_path, proj, installer=copy / "tools" / "install-hooks.sh").returncode == 0
    shutil.rmtree(copy)
    for event in EVENTS:
        (_, hook), = raqib_hooks(settings_of(proj), event)
        proc = run_hook(hook["command"], fixture("pretooluse-bash.json"), proj, clean_env(tmp_path))
        assert proc.returncode == 0
        assert proc.stdout == b""
        assert any(line.startswith("RAQIB-SILENCE: capture hook failed, exit 2 ")
                   for line in proc.stderr.decode().splitlines())


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


def test_redo_m2_new_settings_file_follows_the_umask(tmp_path):
    proj = project(tmp_path)
    proc = subprocess.run(["bash", "-c", 'umask 077 && exec bash "$0" "$1"', str(INSTALL), str(proj)],
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
