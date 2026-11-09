"""M6.3 E1 packaging: pyproject.toml (stdlib-only runtime, pytest the only
test extra, raqib = raqib.cli:main, package data = catalog YAMLs and
endpoints.yaml), the installer moved into the package (W14: watch imports
it; tools/install_hooks.py is a thin wrapper), and every path to the data
working from an installed layout, outside any checkout. The real wheel is
built and installed by the install job of .github/workflows/gate.yml."""
import ast
import glob
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from raqib import cli, discover, doctor, install, watch  # noqa: E402
from raqib.rules import engine  # noqa: E402

WINDOWS = os.name == "nt"
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
SETUPTOOLS = PYPROJECT["tool"]["setuptools"]
CATALOG_FILES = sorted("raqib/rules/catalog/%s" % p.name for p in (ROOT / "raqib" / "rules" / "catalog").glob("*.yaml"))


def package_dir(name):
    return ROOT.joinpath(*name.split("."))


def wheel_files():
    """The files the wheel holds, by pyproject.toml: every .py of each listed
    package, and the package data globs (relative to their package)."""
    files = set()
    for name in SETUPTOOLS["packages"]:
        files |= {p.relative_to(ROOT).as_posix() for p in package_dir(name).glob("*.py")}
    for name, patterns in SETUPTOOLS["package-data"].items():
        for pattern in patterns:
            matched = glob.glob(str(package_dir(name) / pattern))
            assert matched, (name, pattern)
            files |= {Path(m).relative_to(ROOT).as_posix() for m in matched}
    return files


# --- pyproject.toml ---------------------------------------------------------------------

def test_e1_runtime_is_stdlib_only_and_pytest_the_only_test_extra():
    project = PYPROJECT["project"]
    assert project["name"] == "raqib"
    assert project["dependencies"] == []
    assert project["optional-dependencies"] == {"test": ["pytest"]}
    assert PYPROJECT["build-system"]["requires"] == ["setuptools>=61"]


def test_e1_entry_point_is_cli_main():
    assert PYPROJECT["project"]["scripts"] == {"raqib": "raqib.cli:main"}
    assert callable(cli.main)


def test_m64_e1_gui_script_is_raqib_app():
    """The window's gui-script (pythonw on Windows: no console)."""
    from raqib import app
    assert PYPROJECT["project"]["gui-scripts"] == {"raqib-app": "raqib.app:gui_main"}
    assert callable(app.gui_main)


def test_e1_version_and_python_floor_have_one_source():
    assert PYPROJECT["project"]["dynamic"] == ["version"]
    assert PYPROJECT["tool"]["setuptools"]["dynamic"]["version"] == {"attr": "raqib.__version__"}
    assert PYPROJECT["project"]["requires-python"] == ">=%d.%d" % doctor.MIN_PYTHON


def test_e1_every_code_directory_is_a_listed_package():
    found = {os.path.relpath(d, ROOT).replace(os.sep, ".") for d, dirs, files in os.walk(ROOT / "raqib")
             if "__pycache__" not in d and any(f.endswith(".py") for f in files)}
    assert sorted(found) == sorted(SETUPTOOLS["packages"]) == ["raqib", "raqib.hooks", "raqib.rules", "raqib.suspect"]


def test_e1_package_data_is_the_catalog_and_endpoints_and_nothing_is_left_out():
    assert SETUPTOOLS["include-package-data"] is False
    data = sorted(f for f in wheel_files() if not f.endswith(".py"))
    # M7.6c: and the inventories fixturegen replays (raqib/rules/hostdata/inventories.json)
    assert data == sorted(CATALOG_FILES + ["raqib/discover/endpoints.yaml", "raqib/rules/hostdata/inventories.json"])
    # The catalog count is derived from the checkout, never a literal (ADR-0002 D-2):
    # the tracked rule files, as the gate counts them, and what the loader loads.
    tracked = subprocess.run(["git", "-C", str(ROOT), "ls-files", "raqib/rules/catalog"], capture_output=True,
                             text=True, check=True).stdout.split()
    assert CATALOG_FILES and CATALOG_FILES == sorted(p for p in tracked if p.endswith(".yaml") and p.count("/") == 3)
    assert len(CATALOG_FILES) == len(engine.load_catalog(ROOT / "raqib" / "rules" / "catalog"))
    # Every file under raqib/ is in the wheel: nothing the code may read stays behind.
    tree = {p.relative_to(ROOT).as_posix() for p in (ROOT / "raqib").rglob("*")
            if p.is_file() and "__pycache__" not in p.parts}
    assert tree == wheel_files()


def test_e1_data_and_capture_are_located_module_relatively():
    assert Path(cli.CATALOG) == Path(cli.__file__).parent / "rules" / "catalog"
    assert Path(discover.CATALOG) == Path(discover.__file__).parent / "discover" / "endpoints.yaml"
    assert Path(install.capture_path()) == Path(install.__file__).parent / "hooks" / "capture.py"
    assert Path(install.PACKAGE_ROOT) / "raqib" == Path(install.__file__).parent


# --- W14: the installer is a package module ---------------------------------------------

def test_w14_watch_imports_the_installer_from_the_package():
    assert watch.load_installer() is install
    tree = ast.parse((ROOT / "raqib" / "watch.py").read_text(encoding="utf-8"))
    names = {n.id if isinstance(n, ast.Name) else n.attr for n in ast.walk(tree)
             if isinstance(n, (ast.Name, ast.Attribute))}
    strings = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
    assert "importlib" not in names and "spec_from_file_location" not in names
    assert not any("install_hooks" in s or s == "tools" for s in strings)


def test_w14_tools_installer_is_a_thin_wrapper():
    source = (ROOT / "tools" / "install_hooks.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    assert [n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.ClassDef))] == ["main"]
    assert len(source.splitlines()) < 60
    import importlib.util
    spec = importlib.util.spec_from_file_location("raqib_wrapper_under_test", ROOT / "tools" / "install_hooks.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    for name in ("Exit", "is_raqib", "log_of", "posix_command", "windows_command", "EVENTS", "LAUNCHER", "TIMEOUT"):
        assert getattr(mod, name) is getattr(install, name), name
    assert mod.install is install and mod.WINDOWS == install.WINDOWS


def copy_checkout(dest):
    shutil.copytree(ROOT / "raqib", dest / "raqib", ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copytree(ROOT / "tools", dest / "tools", ignore=shutil.ignore_patterns("__pycache__"))
    return dest / "tools" / "install_hooks.py"


def test_w14_wrapper_imports_its_own_checkout_not_another_raqib(tmp_path):
    """Another raqib earlier on sys.path (here through PYTHONPATH, run
    without -I) does not replace the checkout's: the wrapper puts its
    checkout first, so the installer and capture.py are the checkout's."""
    installer = copy_checkout(tmp_path / "checkout")
    decoy = tmp_path / "decoy" / "raqib"
    decoy.mkdir(parents=True)
    (decoy / "__init__.py").write_text("")
    (decoy / "install.py").write_text("raise SystemExit('decoy raqib imported')\n")
    proj = tmp_path / "proj"
    proj.mkdir()
    env = dict(os.environ, PYTHONPATH=str(tmp_path / "decoy"), HOME=str(tmp_path), USERPROFILE=str(tmp_path))
    proc = subprocess.run([sys.executable, str(installer), str(proj)], capture_output=True, text=True,
                          timeout=60, env=env, cwd=str(tmp_path))
    assert proc.returncode == 0, proc.stderr
    capture = tmp_path / "checkout" / "raqib" / "hooks" / "capture.py"
    command = json.loads((proj / ".claude" / "settings.json").read_text())["hooks"]["Stop"][0]["hooks"][0]["command"]
    assert str(capture).replace("\\", "/") in command.replace("\\", "/")


# --- the installed layout, outside any checkout ------------------------------------------

def site_layout(dest):
    """What `pip install .` puts in site-packages, by pyproject.toml: only the
    wheel's files, and no tests/, tools/ or docs/ beside them."""
    for rel in wheel_files():
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / rel, target)
    return dest


def run_installed(site, cwd, *argv, env=None):
    """The console script's call (raqib.cli:main) with only `site` on the
    path: isolated mode, so neither the checkout nor PYTHONPATH is seen."""
    code = ("import sys; sys.path.insert(0, sys.argv[1]); import raqib.cli; "
            "assert raqib.cli.__file__.startswith(sys.argv[1]), raqib.cli.__file__; "
            "sys.exit(raqib.cli.main(sys.argv[2:]))")
    return subprocess.run([sys.executable, "-I", "-c", code, str(site), *map(str, argv)], cwd=str(cwd),
                          capture_output=True, text=True, timeout=120, env=env)


@pytest.fixture(scope="module")
def installed(tmp_path_factory):
    base = tmp_path_factory.mktemp("installed")
    site = site_layout(base / "site-packages")
    outside = base / "outside"
    outside.mkdir()
    return site, outside


def test_e1_installed_layout_help_and_watch_help(installed):
    site, outside = installed
    for argv, start in ((["--help"], "usage: raqib "), (["watch", "--help"], "usage: raqib watch "),
                        (["doctor", "--help"], "usage: raqib doctor "), (["app", "--help"], "usage: raqib app ")):
        proc = run_installed(site, outside, *argv)
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout.startswith(start)
    assert "doctor" in run_installed(site, outside, "--help").stdout


def test_e1_installed_layout_reads_its_catalog_and_endpoints(installed):
    site, outside = installed
    proc = run_installed(site, outside, "check-rules", "--fixtures-root", ROOT)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == cli_output("check-rules")
    proc = run_installed(site, outside, "discover", "--from", ROOT / "tests" / "fixtures" / "discover" / "linux")
    assert proc.returncode == 1, proc.stderr    # a candidate is found in the Linux fixtures
    assert proc.stdout.startswith("Raqib discover (ADR-0004)")
    # The output names the catalog it read: the installed one, not the checkout's.
    endpoints = os.path.join("raqib", "discover", "endpoints.yaml")
    assert os.path.join(str(site), endpoints) in proc.stdout and str(ROOT) + os.sep + endpoints not in proc.stdout
    here = cli_output("discover", "--from", ROOT / "tests" / "fixtures" / "discover" / "linux")
    assert proc.stdout == here.replace(os.path.join(str(ROOT), endpoints), os.path.join(str(site), endpoints))


def test_e1_installed_layout_check_rules_without_fixtures_says_so(installed):
    site, outside = installed
    proc = run_installed(site, outside, "check-rules")
    assert proc.returncode == 2 and proc.stdout == ""
    assert proc.stderr == ("raqib: no rule fixtures in %s: check-rules measures each rule on the fixtures of a"
                           " Raqib checkout, which an installed raqib does not carry; pass --fixtures-root"
                           " CHECKOUT\n" % os.path.join(str(site), "tests", "fixtures"))


def run_hook(command, payload, cwd, env):
    """A hook command run as Claude Code runs it: cmd.exe on Windows, else /bin/sh."""
    argv = 'cmd.exe /d /s /c "%s"' % command if WINDOWS else ["/bin/sh", "-c", command]
    return subprocess.run(argv, input=json.dumps(payload).encode(), capture_output=True, cwd=str(cwd), env=env,
                          timeout=60)


def test_w14_installed_layout_installs_hooks_that_run_its_own_capture(installed, tmp_path):
    """The installer as watch imports it, from the installed layout: the hooks
    run site-packages/raqib/hooks/capture.py, and that capture writes."""
    site, outside = installed
    proj = tmp_path / "proj"
    proj.mkdir()
    trace = tmp_path / "traces" / "t.jsonl"
    code = ("import sys; sys.path.insert(0, sys.argv[1]); from raqib import watch; "
            "i = watch.load_installer(); r = i.install_project(sys.argv[2], log=sys.argv[3]); print(r['code'])")
    env = dict(os.environ, HOME=str(tmp_path), USERPROFILE=str(tmp_path))
    proc = subprocess.run([sys.executable, "-I", "-c", code, str(site), str(proj), str(trace)], cwd=str(outside),
                          capture_output=True, text=True, timeout=60, env=env)
    assert proc.returncode == 0 and proc.stdout.endswith("\n0\n"), proc.stderr
    capture = site / "raqib" / "hooks" / "capture.py"
    settings = json.loads((proj / ".claude" / "settings.json").read_text())
    command = settings["hooks"]["Stop"][0]["hooks"][0]["command"]
    assert str(capture).replace("\\", "/") in command.replace("\\", "/")
    trace.parent.mkdir()
    hook = run_hook(command, {"hook_event_name": "Stop", "session_id": "s", "cwd": str(proj)}, outside, env)
    assert (hook.returncode, hook.stdout, hook.stderr) == (0, b"", b"")
    (line,) = trace.read_text().splitlines()
    assert json.loads(line)["phase"] == "stop"


def test_e2_installed_layout_doctor_runs(installed, tmp_path):
    site, outside = installed
    env = dict(os.environ, HOME=str(tmp_path), USERPROFILE=str(tmp_path), PATH=str(tmp_path / "empty-bin"))
    proc = run_installed(site, outside, "doctor", tmp_path, env=env)
    assert proc.returncode == 1, proc.stderr
    lines = proc.stdout.splitlines()
    assert lines[0].startswith("raqib doctor: raqib ") and str(site / "raqib") in lines[0]
    assert re.fullmatch(r"raqib doctor: [1-9][0-9]* MISSING, [0-9]+ UNSURE", lines[-1]), lines[-1]
    assert "Traceback" not in proc.stderr


# --- check-rules --fixtures-root -----------------------------------------------------------

def cli_output(*argv):
    out = io.StringIO()
    code = cli.main([str(a) for a in argv], out=out)
    assert code in (0, 1), code
    return out.getvalue()


def test_check_rules_fixtures_root_is_the_root_it_reads(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    default = cli_output("check-rules")
    assert cli_output("check-rules", "--fixtures-root", ROOT) == default
    copy = tmp_path / "copy"
    shutil.copytree(ROOT / "tests" / "fixtures", copy / "tests" / "fixtures")
    assert cli_output("check-rules", "--fixtures-root", copy) == default
    # The copy is what is read: a positive fixture gone from it is an error there, not here.
    (copy / "tests" / "fixtures" / "rules" / "NET-TOOL" / "positive-curl.json").unlink()
    assert cli.main(["check-rules", "--fixtures-root", str(copy)], out=io.StringIO()) == 2
    assert "positive-curl.json" in capsys.readouterr().err
    assert cli_output("check-rules") == default


def test_check_rules_without_fixtures_is_a_usage_error(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "ROOT", str(tmp_path))
    assert cli.main(["check-rules"], out=io.StringIO()) == 2
    assert "no rule fixtures in %s" % os.path.join(str(tmp_path), "tests", "fixtures") in capsys.readouterr().err
    assert cli.main(["check-rules", "--fixtures-root", str(tmp_path / "nope")], out=io.StringIO()) == 2


# --- the console script's stdout ----------------------------------------------------------

def test_main_escapes_what_the_console_cannot_encode(tmp_path):
    """main() with no `out` (the console script, python -m raqib) escapes a
    character stdout cannot encode instead of crashing."""
    proj = tmp_path / ("proj-" + "".join(map(chr, (0x631, 0x642, 0x64A, 0x628))))
    proj.mkdir()
    env = dict(os.environ, PYTHONIOENCODING="ascii", HOME=str(tmp_path), USERPROFILE=str(tmp_path),
               PATH=str(tmp_path / "empty-bin"))
    proc = subprocess.run([sys.executable, "-m", "raqib", "doctor", str(proj)], cwd=str(ROOT), capture_output=True,
                          timeout=60, env=env)
    assert proc.returncode == 1, proc.stderr
    assert b"proj-\\u0631\\u0642\\u064a\\u0628" in proc.stdout and b"Traceback" not in proc.stderr


def test_g2_console_script_main_escapes_in_process(tmp_path, monkeypatch, capsys):
    """Amendment G-2 (P2): the console script's own call, cli.main() with no
    `out`, on a stdout that cannot encode the project's name (cp1252, as a
    redirected Windows console): escaped, no crash."""
    import io as _io
    proj = tmp_path / ("proj-" + chr(0x631))
    proj.mkdir()
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("PATH", str(tmp_path / "empty-bin"))
    raw = _io.BytesIO()
    stream = _io.TextIOWrapper(raw, encoding="cp1252", errors="strict")
    monkeypatch.setattr(sys, "stdout", stream)
    assert cli.main(["doctor", str(proj)]) == 1
    stream.flush()
    assert b"proj-\\u0631" in raw.getvalue() and stream.errors == "backslashreplace"


def test_g6_eval_without_events_in_an_installed_raqib_exits_2(installed, tmp_path, monkeypatch, capsys):
    site, outside = installed
    proc = run_installed(site, outside, "eval")
    assert proc.returncode == 2 and proc.stdout == ""
    assert proc.stderr == ("raqib: no labelled events at %s: eval reads a checkout's tests/fixtures/eval/events.json"
                           " or --events FILE; an installed raqib carries none\n"
                           % os.path.join(str(site), "tests", "fixtures", "eval", "events.json"))
    proc = run_installed(site, outside, "eval", "--events", ROOT / "tests" / "fixtures" / "eval" / "events.json")
    assert proc.returncode == 0, proc.stderr
    # In-process, the same rule: the default file missing is exit 2; a checkout's default is read.
    monkeypatch.setattr(cli, "EVENTS", str(tmp_path / "none.json"))
    assert cli.main(["eval"], out=io.StringIO()) == 2
    assert "eval reads a checkout's tests/fixtures/eval/events.json or --events FILE" in capsys.readouterr().err
    assert "--events FILE" in run_installed(site, outside, "eval", "--help").stdout


def test_g6_gitignore_covers_what_pip_install_leaves():
    lines = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert "build/" in lines and "*.egg-info/" in lines
    git = shutil.which("git")
    if git and (ROOT / ".git").exists():
        proc = subprocess.run([git, "check-ignore", "build/lib/raqib/cli.py", "raqib.egg-info/PKG-INFO"],
                              cwd=str(ROOT), capture_output=True, text=True, timeout=30)
        assert proc.returncode == 0 and len(proc.stdout.splitlines()) == 2, proc.stderr
