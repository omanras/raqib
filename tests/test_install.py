"""M0.3 install script: exit criteria E1-E3 (HANDOFF.md), ADR-0001 Amendment A-3/A-4."""
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from raqib.rules import silence  # noqa: E402

INSTALL = ROOT / "tools" / "install-hooks.sh"
CAPTURE = ROOT / "raqib" / "hooks" / "capture.py"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
COMMAND = "python3 " + shlex.quote(str(CAPTURE))
TOOL_EVENTS = ["PreToolUse", "PostToolUse", "PostToolUseFailure"]
SESSION_EVENTS = ["SessionStart", "SessionEnd", "Stop"]
EVENTS = TOOL_EVENTS + SESSION_EVENTS


def install(*args, cwd=None):
    return subprocess.run(["bash", str(INSTALL), *map(str, args)], capture_output=True,
                          text=True, cwd=cwd, timeout=60)


def settings_of(project):
    return json.loads((project / ".claude" / "settings.json").read_text())


def raqib_hooks(settings, event):
    return [(g, h) for g in settings["hooks"][event] for h in g["hooks"]
            if "raqib/hooks/capture.py" in h["command"]]


def write_settings(project, value):
    (project / ".claude").mkdir(parents=True, exist_ok=True)
    path = project / ".claude" / "settings.json"
    path.write_text(value if isinstance(value, str) else json.dumps(value, indent=2))
    return path


def fixture(name):
    return json.loads((FIXTURES / name).read_text())


# --- E1: empty project -> six entries; idempotent ---------------------------

def test_e1_empty_project_gets_six_hook_entries(tmp_path):
    proc = install(tmp_path)
    assert proc.returncode == 0, proc.stderr
    settings = settings_of(tmp_path)
    assert sorted(settings["hooks"]) == sorted(EVENTS)
    for event in EVENTS:
        (group, hook), = raqib_hooks(settings, event)
        assert hook == {"type": "command", "command": COMMAND}
        if event in TOOL_EVENTS:
            assert group["matcher"] == "*"
        else:
            assert "matcher" not in group
    assert proc.stdout.count("added") == 6


def test_e1_second_run_changes_nothing(tmp_path):
    assert install(tmp_path).returncode == 0
    first = (tmp_path / ".claude" / "settings.json").read_bytes()
    proc = install(tmp_path)
    assert proc.returncode == 0
    assert (tmp_path / ".claude" / "settings.json").read_bytes() == first
    assert proc.stdout.count("unchanged") == 6


def test_e1_empty_settings_file_is_an_empty_object(tmp_path):
    write_settings(tmp_path, "  \n")
    assert install(tmp_path).returncode == 0
    assert sorted(settings_of(tmp_path)["hooks"]) == sorted(EVENTS)


def test_e1_relative_project_path(tmp_path):
    (tmp_path / "proj").mkdir()
    assert install("proj", cwd=tmp_path).returncode == 0
    assert raqib_hooks(settings_of(tmp_path / "proj"), "Stop")


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
    write_settings(tmp_path, OTHER)
    assert install(tmp_path).returncode == 0
    settings = settings_of(tmp_path)
    for key in ("model", "permissions", "note"):
        assert settings[key] == OTHER[key]
    for event, groups in OTHER["hooks"].items():
        assert settings["hooks"][event][:len(groups)] == groups
    assert settings["hooks"]["Notification"] == OTHER["hooks"]["Notification"]
    for event in EVENTS:
        assert len(raqib_hooks(settings, event)) == 1
    assert install(tmp_path).stdout.count("unchanged") == 6


def test_e2_non_ascii_settings_survive(tmp_path):
    write_settings(tmp_path, OTHER)
    assert install(tmp_path).returncode == 0
    assert "\u0631\u0642\u064a\u0628" in (tmp_path / ".claude" / "settings.json").read_text("utf-8")


def test_e2_stale_raqib_entry_is_replaced_not_doubled(tmp_path):
    stale = "python3 /old/place/raqib/hooks/capture.py"
    write_settings(tmp_path, {"hooks": {
        "PreToolUse": [
            {"matcher": "*", "hooks": [{"type": "command", "command": "/opt/keep.sh"},
                                       {"type": "command", "command": stale}]},
            {"matcher": "*", "hooks": [{"type": "command", "command": stale}]},
        ],
    }})
    proc = install(tmp_path)
    assert proc.returncode == 0
    assert "PreToolUse          updated" in proc.stdout
    groups = settings_of(tmp_path)["hooks"]["PreToolUse"]
    assert groups == [
        {"matcher": "*", "hooks": [{"type": "command", "command": "/opt/keep.sh"}]},
        {"matcher": "*", "hooks": [{"type": "command", "command": COMMAND}]},
    ]
    assert install(tmp_path).stdout.count("unchanged") == 6


def test_e2_raqib_entry_with_wrong_matcher_is_fixed(tmp_path):
    write_settings(tmp_path, {"hooks": {"PostToolUse": [
        {"matcher": "Bash", "hooks": [{"type": "command", "command": COMMAND}]}]}})
    assert install(tmp_path).returncode == 0
    assert settings_of(tmp_path)["hooks"]["PostToolUse"] == [
        {"matcher": "*", "hooks": [{"type": "command", "command": COMMAND}]}]


@pytest.mark.parametrize("content", [
    "{not json",
    "[1, 2]",
    '{"hooks": []}',
    '{"hooks": {"Stop": {}}}',
])
def test_e2_unreadable_settings_are_left_untouched(tmp_path, content):
    path = write_settings(tmp_path, content)
    proc = install(tmp_path)
    assert proc.returncode == 1
    assert proc.stderr.startswith("install-hooks:")
    assert path.read_text() == content
    assert [p.name for p in path.parent.iterdir()] == ["settings.json"]


@pytest.mark.parametrize("args", [[], ["--log"], ["--bogus", "x"], ["a", "b"]])
def test_usage_errors_exit_2(tmp_path, args):
    assert install(*args, cwd=tmp_path).returncode == 2


def test_missing_project_exits_2(tmp_path):
    proc = install(tmp_path / "nope")
    assert proc.returncode == 2
    assert not (tmp_path / "nope").exists()


# --- E3: the installed commands really capture ------------------------------

def run_hook(command, payload, cwd):
    env = {k: v for k, v in os.environ.items() if not k.startswith("RAQIB_")}
    return subprocess.run(["sh", "-c", command], input=json.dumps(payload).encode(),
                          capture_output=True, cwd=cwd, env=env, timeout=30)


SESSION = [
    ("SessionStart", "sessionstart.json"),
    ("PreToolUse", "pretooluse-bash.json"),
    ("PostToolUse", "posttooluse-bash.json"),
    ("Stop", "stop.json"),
    ("SessionEnd", "sessionend.json"),
]


def simulate(project):
    settings = settings_of(project)
    for event, name in SESSION:
        (_, hook), = raqib_hooks(settings, event)
        proc = run_hook(hook["command"], fixture(name), project)
        assert (proc.returncode, proc.stdout, proc.stderr) == (0, b"", b"")


def trace_lines(path):
    return [json.loads(x) for x in path.read_text().splitlines()]


def test_e3_installed_commands_write_one_clean_session(tmp_path):
    assert install(tmp_path).returncode == 0
    simulate(tmp_path)
    recs = trace_lines(tmp_path / "raqib.log.jsonl")
    assert [(r["phase"], r["seq"]) for r in recs] == [
        ("session_start", 1), ("pre", 2), ("post", 2), ("stop", 3), ("session_end", 4)]
    assert silence.findings(recs) == []


def test_e3_log_option_sets_raqib_log(tmp_path):
    project = tmp_path / "proj"
    project.mkdir()
    log = tmp_path / "outside" / "trace.jsonl"
    log.parent.mkdir()
    assert install("--log", log, project).returncode == 0
    (_, hook), = raqib_hooks(settings_of(project), "PreToolUse")
    assert hook["command"] == "RAQIB_LOG=%s %s" % (shlex.quote(str(log)), COMMAND)
    simulate(project)
    assert len(trace_lines(log)) == 5
    assert not (project / "raqib.log.jsonl").exists()


def test_e3_real_claude_code_trace_is_clean():
    """Trace from the README quickstart, recorded with Claude Code 2.1.301."""
    recs = fixture("quickstart-claude-code-2.1.301.json")
    assert [(r["phase"], r["seq"]) for r in recs] == [
        ("session_start", 1), ("pre", 2), ("post", 2), ("stop", 3), ("session_end", 4)]
    pre, post = recs[1], recs[2]
    assert pre["tool_use_id"] == post["tool_use_id"]
    assert pre["input_meta"] == {"command_head": "echo"}
    assert post["ok"] is True
    assert silence.findings(recs) == []
