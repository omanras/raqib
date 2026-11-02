"""raqib doctor (M6.3 E2, raqib/doctor.py): one line per check, OK or
MISSING, exit 1 when any is MISSING; read-only; the only program it runs is
`claude --version`, by absolute path, with a minimal environment."""
import hashlib
import io
import json
import os
import stat
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from raqib import cli, doctor, install  # noqa: E402

WINDOWS = os.name == "nt"
ORDER = ["python", "claude", "hooks", "notifier", "trace"]


class Fakes:
    """which() and runner() of a host where claude and python3 are found."""

    def __init__(self, tmp_path, found=None, answer=(0, "2.1.316 (Claude Code)\n", None)):
        bin_dir = tmp_path / "bin"
        self.claude = str(bin_dir / "claude")
        self.found = {"claude": self.claude, "python3": str(bin_dir / "python3")} if found is None else found
        self.answer = answer
        self.calls = []
        self.which_paths = []

    def which(self, name, path=None):
        self.which_paths.append(path)
        return self.found.get(name)

    def runner(self, argv, env, timeout):
        self.calls.append((list(argv), dict(env), timeout))
        return self.answer


@pytest.fixture
def home(tmp_path, monkeypatch):
    path = tmp_path / "home"
    path.mkdir()
    monkeypatch.setenv("HOME", str(path))          # ~/.claude/settings.json (disableAllHooks)
    monkeypatch.setenv("USERPROFILE", str(path))
    return path


def make_project(tmp_path, name="proj"):
    path = tmp_path / name
    path.mkdir()
    return path


def installed(proj, trace, windows=False):
    install.install_project(str(proj), log=str(trace), out=io.StringIO(), err=io.StringIO(), windows=windows)


def notify_send(path):
    return path in ("/usr/bin/notify-send", "/bin/sh")


def run(tmp_path, proj, home, fakes=None, environ=None, platform="linux", **kw):
    fakes = fakes or Fakes(tmp_path)
    environ = {"PATH": str(tmp_path / "bin"), "HOME": str(home)} if environ is None else environ
    kw.setdefault("isfile", notify_send)
    out = io.StringIO()
    code = doctor.run(None if proj is None else str(proj), out, environ=environ, platform=platform, which=fakes.which, runner=fakes.runner,
                      home=str(home), **kw)
    text = out.getvalue()
    lines = text.splitlines()
    checks = {line[8:17].strip(): (line[:8].strip(), line[17:]) for line in lines[1:-1]}
    return code, text, checks, fakes


def snapshot(root):
    """Every path under root with its kind, bytes and mtime: what read-only keeps."""
    seen = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames:
            seen[os.path.join(dirpath, name)] = "dir"
        for name in filenames:
            path = os.path.join(dirpath, name)
            st = os.lstat(path)
            with open(path, "rb") as f:
                seen[path] = (hashlib.sha256(f.read()).hexdigest(), st.st_mtime_ns, stat.S_IMODE(st.st_mode))
    return seen


# --- all OK, and the shape of the screen ---------------------------------------------

def test_e2_all_ok_exits_0_with_one_line_per_check(tmp_path, home):
    proj = make_project(tmp_path)
    trace = tmp_path / "traces" / "t.jsonl"
    installed(proj, trace)
    code, text, checks, fakes = run(tmp_path, proj, home)
    assert code == 0, text
    lines = text.splitlines()
    assert lines[0].startswith("raqib doctor: raqib ") and lines[0].endswith("; project %s" % proj)
    assert lines[-1] == "raqib doctor: all OK"
    assert list(checks) == ORDER and {v for v, _ in checks.values()} == {"OK"}
    assert checks["claude"][1] == "2.1.316 (Claude Code) at %s" % fakes.claude
    assert checks["hooks"][1] == "%s: installed for all 6 events (trace %s)" % (
        proj / ".claude" / "settings.json", trace)
    assert checks["notifier"][1] == "notify-send (/usr/bin/notify-send)"
    assert checks["trace"][1] == "%s (kept from the existing install) can be created under %s" % (trace, tmp_path)
    assert "the hooks run python3 from PATH: %s" % (tmp_path / "bin" / "python3") in checks["python"][1]


def test_e2_cli_doctor_runs_the_checks_and_says_missing(tmp_path, home, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path / "empty-bin"))   # no claude, no python3: MISSING, nothing run
    proj = make_project(tmp_path)
    out = io.StringIO()
    code = cli.main(["doctor", str(proj)], out=out)
    lines = out.getvalue().splitlines()
    assert code == 1
    assert lines[-1].startswith("raqib doctor: ") and lines[-1].endswith(" MISSING")
    assert any(line.startswith("MISSING claude   not on PATH") for line in lines)
    assert cli.main(["doctor", "--help"], out=io.StringIO()) == 0


def test_e2_default_project_is_the_current_directory(tmp_path, home, monkeypatch):
    proj = make_project(tmp_path)
    monkeypatch.chdir(proj)
    monkeypatch.delenv("PWD", raising=False)
    code, text, _, _ = run(tmp_path, None, home)
    assert text.splitlines()[0].endswith("; project %s" % os.getcwd())


# --- python ----------------------------------------------------------------------------

def test_e2_python_older_than_the_floor_is_missing(tmp_path, home):
    proj = make_project(tmp_path)
    code, _, checks, _ = run(tmp_path, proj, home, version_info=(3, 10, 4), executable="/x/python3.10")
    assert code == 1
    assert checks["python"] == ("MISSING", "3.10.4 at /x/python3.10; the hooks run python3 from PATH: %s;"
                                           " Raqib needs Python 3.11 or newer" % (tmp_path / "bin" / "python3"))


def test_e2_posix_hooks_need_python3_on_path(tmp_path, home):
    proj = make_project(tmp_path)
    fakes = Fakes(tmp_path, found={"claude": str(tmp_path / "bin" / "claude")})
    _, _, checks, _ = run(tmp_path, proj, home, fakes=fakes)
    assert checks["python"][0] == "MISSING"
    assert checks["python"][1].endswith("the hooks run python3 and there is none on PATH")


def test_e2_windows_hooks_run_this_python_by_its_path(tmp_path, home):
    proj = make_project(tmp_path)
    _, _, checks, _ = run(tmp_path, proj, home, platform="win32", registry=lambda key: {"Enabled": 1})
    assert checks["python"] == ("OK", "%s at %s; the hooks run this Python by its path" % (
        ".".join(map(str, sys.version_info[:3])), sys.executable))
    _, _, checks, _ = run(tmp_path, proj, home, platform="win32", registry=lambda key: {"Enabled": 1},
                          executable="")
    assert checks["python"][0] == "MISSING" and "cannot tell which Python runs this" in checks["python"][1]


def test_e2_which_searches_only_the_given_path(tmp_path, home):
    proj = make_project(tmp_path)
    _, _, checks, fakes = run(tmp_path, proj, home, environ={"HOME": str(home)})   # no PATH at all
    assert fakes.which_paths == [] and fakes.calls == []
    assert checks["claude"] == ("MISSING", "not on PATH (install Claude Code; the hooks are Claude Code hooks)")
    assert checks["python"][0] == "MISSING"


# --- claude ----------------------------------------------------------------------------

def test_e2_claude_is_run_by_absolute_path_with_a_minimal_environment(tmp_path, home):
    proj = make_project(tmp_path)
    environ = {"PATH": str(tmp_path / "bin"), "HOME": str(home), "ANTHROPIC_API_KEY": "x", "LD_PRELOAD": "/evil.so",
               "NODE_OPTIONS": "--require /evil.js"}
    _, _, checks, fakes = run(tmp_path, proj, home, environ=environ)
    (argv, env, timeout), = fakes.calls
    assert argv == [fakes.claude, "--version"] and os.path.isabs(argv[0])
    assert env == {"PATH": str(tmp_path / "bin"), "HOME": str(home), "LC_ALL": "C"}
    assert timeout == doctor.CLAUDE_TIMEOUT == 10


def test_e2_windows_environment_for_claude(tmp_path, home):
    environ = {"Path": "C:\\bin", "PATHEXT": ".EXE;.CMD", "SystemRoot": "C:\\Windows", "COMSPEC": "C:\\cmd.exe",
               "USERPROFILE": "C:\\Users\\me", "APPDATA": "a", "LOCALAPPDATA": "l", "TEMP": "t", "TMP": "t2",
               "SECRET": "s", "HOME": "h"}
    assert doctor.claude_env(environ, windows=True) == {
        "PATH": "C:\\bin", "PATHEXT": ".EXE;.CMD", "SystemRoot": "C:\\Windows", "ComSpec": "C:\\cmd.exe",
        "USERPROFILE": "C:\\Users\\me", "APPDATA": "a", "LOCALAPPDATA": "l", "TEMP": "t", "TMP": "t2"}


@pytest.mark.parametrize("found", ["claude", os.path.join(".", "claude.cmd"), os.path.join("bin", "claude")])
def test_e2_a_relative_claude_is_refused_and_never_run(tmp_path, home, found):
    proj = make_project(tmp_path)
    fakes = Fakes(tmp_path, found={"claude": found, "python3": str(tmp_path / "bin" / "python3")})
    code, _, checks, _ = run(tmp_path, proj, home, fakes=fakes)
    assert code == 1 and fakes.calls == []
    assert checks["claude"][0] == "MISSING"
    assert checks["claude"][1].startswith("found only as %s, a relative path" % found)


@pytest.mark.parametrize("answer, expected", [
    ((None, "", "could not be started: [Errno 13] Permission denied"),
     "--version could not be started: [Errno 13] Permission denied"),
    ((None, "", "did not answer within 10 s; it was left running, not signalled (A4)"),
     "--version did not answer within 10 s; it was left running, not signalled (A4)"),
    ((3, "oops\n", None), "--version exited 3"),
    ((0, "\n  \n", None), "--version printed no version"),
], ids=["not-started", "timeout", "exit-3", "no-output"])
def test_e2_claude_that_does_not_answer_is_missing(tmp_path, home, answer, expected):
    proj = make_project(tmp_path)
    code, _, checks, fakes = run(tmp_path, proj, home, fakes=Fakes(tmp_path, answer=answer))
    assert code == 1
    assert checks["claude"] == ("MISSING", fakes.claude + " " + expected)


def test_e2_claude_version_is_cleaned_and_bounded(tmp_path, home):
    proj = make_project(tmp_path)
    answer = (0, "\n1.0 \x1b[31mred\x1b[0m " + "x" * 200 + "\nsecond line\n", None)
    _, text, checks, _ = run(tmp_path, proj, home, fakes=Fakes(tmp_path, answer=answer))
    assert "\x1b" not in text and "second line" not in text
    version = checks["claude"][1].split(" at ")[0]
    assert version.startswith("1.0 ?[31mred?[0m xxx") and len(version) == doctor.VERSION_MAX
    assert version.endswith("...")


def test_e2_run_version_refuses_a_relative_program():
    assert doctor.run_version(["claude", "--version"], {}) == (
        None, "", "['claude'] is not an absolute path: nothing is looked up through PATH")


def fake_claude(directory, body_posix, body_windows):
    directory.mkdir(exist_ok=True)
    if WINDOWS:
        path = directory / "claude.bat"
        path.write_text("@echo off\r\n" + body_windows + "\r\n")
    else:
        path = directory / "claude"
        path.write_text("#!/bin/sh\n" + body_posix + "\n")
        path.chmod(0o755)
    return path


def test_e2_real_version_query_gets_no_inherited_variables(tmp_path, home):
    """The real runner: shutil.which on PATH, the absolute path run with
    CLAUDE_ENV only, so a variable of the caller does not reach it."""
    bin_dir = tmp_path / "bin"
    fake_claude(bin_dir, 'echo "9.9.9 (Claude Code) probe=${RAQIB_DOCTOR_PROBE:-none}"',
                "echo 9.9.9 (Claude Code) probe=%RAQIB_DOCTOR_PROBE%")
    environ = dict(os.environ, PATH=str(bin_dir) + os.pathsep + os.environ.get("PATH", ""),
                   RAQIB_DOCTOR_PROBE="leaked")
    proj = make_project(tmp_path)
    out = io.StringIO()
    doctor.run(str(proj), out, environ=environ, platform=sys.platform, home=str(home), isfile=notify_send)
    line = next(x for x in out.getvalue().splitlines() if x[8:17].strip() == "claude")
    assert line.startswith("OK      claude   9.9.9 (Claude Code) probe=")
    assert "leaked" not in line and str(bin_dir) in line


@pytest.mark.skipif(WINDOWS, reason="a sleeping sh script; the Windows path is the same Popen call")
def test_e2_real_version_query_that_hangs_is_left_running(tmp_path, home, monkeypatch):
    monkeypatch.setattr(doctor, "CLAUDE_TIMEOUT", 0.5)
    bin_dir = tmp_path / "bin"
    fake_claude(bin_dir, "sleep 3", "")
    proj = make_project(tmp_path)
    out = io.StringIO()
    environ = {"PATH": str(bin_dir) + os.pathsep + os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(home)}
    doctor.run(str(proj), out, environ=environ, platform="linux", home=str(home), isfile=notify_send)
    assert ("MISSING claude   %s --version did not answer within 0.5 s; it was left running, not signalled (A4)"
            % (bin_dir / "claude")) in out.getvalue().splitlines()


# --- hooks -----------------------------------------------------------------------------

def test_e2_hooks_missing(tmp_path, home):
    proj = make_project(tmp_path)
    code, _, checks, _ = run(tmp_path, proj, home)
    assert code == 1
    assert checks["hooks"] == ("MISSING", "%s: missing for all 6 events; `raqib watch` installs this raqib's"
                               % (proj / ".claude" / "settings.json"))


def test_e2_hooks_foreign_and_partly_missing(tmp_path, home):
    proj = make_project(tmp_path)
    trace = tmp_path / "t.jsonl"
    installed(proj, trace)
    path = proj / ".claude" / "settings.json"
    settings = json.loads(path.read_text())
    other = "/other/checkout/raqib/hooks/capture.py"
    settings["hooks"]["Stop"][0]["hooks"][0]["command"] = install.posix_command(str(trace), other)
    settings["hooks"]["SessionStart"][0]["hooks"][0]["command"] = "python3 /old/raqib/hooks/capture.py"
    settings["hooks"]["PostToolUse"][0]["matcher"] = "Bash"          # our command, not our entry
    settings["hooks"]["PreToolUse"] = [{"matcher": "*", "hooks": [{"type": "command", "command": "/opt/guard.sh"}]}]
    del settings["hooks"]["SessionEnd"]
    path.write_text(json.dumps(settings))
    code, _, checks, _ = run(tmp_path, proj, home)
    assert code == 1
    verdict, text = checks["hooks"]
    assert verdict == "MISSING"
    assert text == ("%s: missing for PreToolUse, SessionEnd; foreign for PostToolUse, SessionStart, Stop (a Raqib"
                    " entry unlike the one this raqib writes; it runs %s; /old/raqib/hooks/capture.py; %s);"
                    " `raqib watch` installs this raqib's" % (path, install.capture_path(), other))


def test_e2_hooks_installed_but_disabled(tmp_path, home):
    proj = make_project(tmp_path)
    installed(proj, tmp_path / "t.jsonl")
    (proj / ".claude" / "settings.local.json").write_text('{"disableAllHooks": true}')
    code, _, checks, _ = run(tmp_path, proj, home)
    assert code == 1
    assert checks["hooks"] == ("MISSING", "%s: disableAllHooks is true in %s, so capture will not run" % (
        proj / ".claude" / "settings.json", proj / ".claude" / "settings.local.json"))


@pytest.mark.parametrize("content", ["{not json", '{"hooks": []}', '{"a": 1, "a": 2}'])
def test_e2_unreadable_settings_are_missing_and_untouched(tmp_path, home, content):
    proj = make_project(tmp_path)
    (proj / ".claude").mkdir()
    (proj / ".claude" / "settings.json").write_text(content)
    code, _, checks, _ = run(tmp_path, proj, home)
    assert code == 1 and checks["hooks"][0] == "MISSING"
    assert checks["hooks"][1].startswith("install-hooks: ") and "nothing changed" in checks["hooks"][1]
    assert checks["trace"][0] == "MISSING" and checks["trace"][1].startswith("watch cannot choose one: ")
    assert (proj / ".claude" / "settings.json").read_text() == content


def test_e2_project_that_is_not_a_directory(tmp_path, home):
    code, _, checks, _ = run(tmp_path, tmp_path / "nope", home)
    assert code == 1
    assert checks["hooks"] == ("MISSING", "not a directory: %s" % (tmp_path / "nope"))
    assert checks["trace"][0] == "MISSING"
    assert not (tmp_path / "nope").exists()


def test_e2_windows_form_is_installed_for_a_windows_doctor_and_foreign_for_posix(tmp_path, home):
    proj = make_project(tmp_path)
    installed(proj, tmp_path / "t.jsonl", windows=True)
    windows = tmp_path / "Windows"
    windows.mkdir()
    environ = {"PATH": str(tmp_path / "bin"), "SystemRoot": str(windows)}
    code, text, checks, _ = run(tmp_path, proj, home, environ=environ, platform="win32",
                                isfile=lambda p: True, registry=lambda key: {"Enabled": 1})
    assert checks["hooks"][0] == "OK", text
    assert checks["notifier"][0] == "OK" and checks["notifier"][1].startswith("windows-toast (")
    assert list(checks) == ["python", "claude", "hooks", "notifier", "sysmon", "trace"]
    _, _, checks, _ = run(tmp_path, proj, home)
    assert checks["hooks"][0] == "MISSING" and "foreign for PreToolUse, PostToolUse" in checks["hooks"][1]


def test_e2_a_raqib_without_capture_cannot_have_its_hooks_installed(tmp_path, home):
    proj = make_project(tmp_path)
    states = doctor.hook_states(str(proj), False, capture=str(tmp_path / "gone" / "capture.py"))
    assert states == (None, None, "this raqib has no capture hook at %s" % (tmp_path / "gone" / "capture.py"))


# --- notifier and sysmon -----------------------------------------------------------------

def test_e2_notifier_terminal_only_is_missing(tmp_path, home):
    proj = make_project(tmp_path)
    _, _, checks, _ = run(tmp_path, proj, home, isfile=lambda p: p == "/bin/sh")
    assert checks["notifier"] == ("MISSING", "terminal bell and stderr only (no /usr/bin/notify-send or"
                                             " /bin/notify-send)")


def test_e2_notifier_off_under_ci_is_missing(tmp_path, home):
    proj = make_project(tmp_path)
    environ = {"PATH": str(tmp_path / "bin"), "CI": "true"}
    _, _, checks, _ = run(tmp_path, proj, home, environ=environ)
    assert checks["notifier"] == ("MISSING", "off (CI is set: no notification is shown in CI)")


def test_e2_notifier_with_untrusted_systemroot_is_missing(tmp_path, home):
    proj = make_project(tmp_path)
    environ = {"PATH": str(tmp_path / "bin"), "SystemRoot": str(tmp_path)}
    _, _, checks, _ = run(tmp_path, proj, home, environ=environ, platform="win32", registry=lambda key: None)
    assert checks["notifier"][0] == "MISSING" and "is not an existing directory named Windows" in checks["notifier"][1]


def test_e2_no_sysmon_line_off_windows(tmp_path, home):
    proj = make_project(tmp_path)
    _, _, checks, _ = run(tmp_path, proj, home, platform="darwin", isfile=lambda p: p == "/usr/bin/osascript")
    assert "sysmon" not in checks
    assert checks["notifier"] == ("OK", "osascript (/usr/bin/osascript)")


def denied(key):
    raise PermissionError(13, "Access is denied")


@pytest.mark.parametrize("registry, verdict, start", [
    (lambda key: {"Enabled": 1, "Type": 1}, "OK", "event channel Microsoft-Windows-Sysmon/Operational registered"
                                                  " and enabled"),
    (lambda key: None, "MISSING", "no event channel Microsoft-Windows-Sysmon/Operational: Sysmon is not installed"),
    (lambda key: {"Enabled": 0}, "MISSING", "event channel Microsoft-Windows-Sysmon/Operational is registered but"
                                            " not enabled"),
    (denied, "MISSING", "cannot read HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\"
                        "Microsoft-Windows-Sysmon/Operational: "),
], ids=["enabled", "absent", "disabled", "unreadable"])
def test_e2_sysmon_on_windows(tmp_path, home, registry, verdict, start):
    proj = make_project(tmp_path)
    keys = []

    def reader(key):
        keys.append(key)
        return registry(key)
    _, _, checks, _ = run(tmp_path, proj, home, platform="win32", registry=reader)
    assert keys == [doctor.SYSMON_KEY]
    assert checks["sysmon"][0] == verdict and checks["sysmon"][1].startswith(start)


@pytest.mark.skipif(not WINDOWS, reason="the real registry")
def test_e2_real_registry_is_read_without_error():
    assert doctor.read_registry_key("SOFTWARE\\Raqib\\no-such-key-%d" % os.getpid()) is None
    assert isinstance(doctor.read_registry_key("SOFTWARE\\Microsoft\\Windows\\CurrentVersion"), dict)
    values = doctor.read_registry_key(doctor.SYSMON_KEY)
    assert values is None or isinstance(values, dict)
    ok, text = doctor.check_sysmon(doctor.read_registry_key)
    assert text.split(" ")[0] in ("event", "no")


# --- trace -----------------------------------------------------------------------------

def test_e2_trace_default_can_be_created(tmp_path, home):
    proj = make_project(tmp_path)
    _, _, checks, _ = run(tmp_path, proj, home)
    verdict, text = checks["trace"]
    assert verdict == "OK"
    assert text.startswith(str(home / ".raqib" / "traces" / "proj-"))
    assert text.endswith("raqib.log.jsonl (watch default, outside the project) can be created under %s" % home)


def test_e2_trace_blocked_by_a_file_is_missing(tmp_path, home):
    proj = make_project(tmp_path)
    (home / ".raqib").write_text("not a directory")
    _, _, checks, _ = run(tmp_path, proj, home)
    assert checks["trace"][0] == "MISSING"
    assert checks["trace"][1].endswith("cannot be created: %s is not a directory" % (home / ".raqib"))


def test_e2_trace_that_exists_is_checked_for_writing(tmp_path, home):
    proj = make_project(tmp_path)
    trace = tmp_path / "t.jsonl"
    trace.write_text("")
    installed(proj, trace)
    _, _, checks, _ = run(tmp_path, proj, home)
    assert checks["trace"] == ("OK", "%s (kept from the existing install) exists and is writable" % trace)
    assert doctor.writable(str(tmp_path)) == (False, "is a directory")


@pytest.mark.skipif(WINDOWS or os.geteuid() == 0, reason="POSIX permissions; root may write anything")
def test_e2_trace_in_a_read_only_directory_is_missing(tmp_path, home):
    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(0o555)
    try:
        assert doctor.writable(str(locked / "t.jsonl")) == (False, "cannot be created: %s is not writable" % locked)
    finally:
        locked.chmod(0o755)


def test_e2_trace_that_watch_cannot_choose_is_missing(tmp_path, home):
    proj = make_project(tmp_path)
    installed(proj, tmp_path / "a.jsonl")
    path = proj / ".claude" / "settings.json"
    settings = json.loads(path.read_text())
    settings["hooks"]["Stop"][0]["hooks"][0]["command"] = install.posix_command(
        str(tmp_path / "b.jsonl"), install.capture_path())
    path.write_text(json.dumps(settings))
    _, _, checks, _ = run(tmp_path, proj, home)
    assert checks["hooks"][0] == "OK"      # each entry is this raqib's ...
    assert checks["trace"][0] == "MISSING" and "write to different traces" in checks["trace"][1]   # ... but not one trace


# --- read-only ---------------------------------------------------------------------------

def test_e2_doctor_writes_nothing(tmp_path, home):
    """Doctor in every state above leaves the tree as it was: no file, no
    directory, no mode or mtime changed."""
    proj = make_project(tmp_path)
    other = make_project(tmp_path, "other")
    installed(other, tmp_path / "t.jsonl")
    (other / ".claude" / "settings.local.json").write_text('{"disableAllHooks": true}')
    bad = make_project(tmp_path, "bad")
    (bad / ".claude").mkdir()
    (bad / ".claude" / "settings.json").write_text("{not json")
    before = snapshot(tmp_path)
    for target in (proj, other, bad, tmp_path / "nope"):
        for platform in ("linux", "win32"):
            run(tmp_path, target, home, platform=platform, registry=lambda key: None)
    assert snapshot(tmp_path) == before
