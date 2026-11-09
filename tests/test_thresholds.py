"""M7.6c thresholds that can be measured (HANDOFF.md E1-E5, ADR-0008
Amendment B, Q-15): the host rules' fixtures generated at any values by
raqib/rules/fixturegen.py (the package, so an installed raqib measures),
the bounds declared in each host YAML, a changed threshold measured on the
fixtures made at it and on the benign arrivals. Every test runs under a
temporary HOME."""
import copy
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "tests" / "fixtures" / "host"))

from raqib import app, cli, host, overlay  # noqa: E402
from raqib.rules import engine, fixturegen  # noqa: E402
import make as host_fixtures  # noqa: E402

CATALOG_DIR = ROOT / "raqib" / "rules" / "catalog"
QUESTIONS = ROOT / "docs" / "review" / "2026-11-09-M7.6c-questions.md"
HOST_RULES = ("HOST-RHYTHM", "AGENT-DARK-LIVE", "NEW-AGENT", "NEW-AGENT-UNKNOWN", "HOST-UNWATCHED")
WINDOWS = os.name == "nt"


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    path = tmp_path / "home"
    path.mkdir()
    monkeypatch.setenv("HOME", str(path))
    monkeypatch.setenv("USERPROFILE", str(path))
    return path


def catalog():
    return engine.load_catalog(CATALOG_DIR)


def by_id(rules, rid):
    return next(r for r in rules if r.id == rid)


def at(rid, bounds=True, **values):
    """The catalog rule rid with these eq values (as the overlay compiles it; bounds False: without its
    bounds block, for a value outside them)."""
    rule = by_id(catalog(), rid)
    doc = copy.deepcopy(rule.doc)
    if not bounds:
        doc.pop("bounds")
    for p in engine.eq_predicates(doc["match"]):
        name = p["field"].rsplit(".", 1)[-1]
        if name in values:
            p["eq"] = values[name]
    return engine.compile_rule(doc, rule.source)


def run_cli(argv):
    import io
    out = io.StringIO()
    code = cli.main(argv, out=out)
    return code, out.getvalue()


def tree_line(lines):
    (line,) = [l for l in lines if l["tool"] == host.TREE_TOOL]
    return line["input_meta"]


# --- E1: the generator is package code; the shipped fixtures are its output ----------------------------------

@pytest.mark.parametrize("rid", fixturegen.GENERATED)
def test_e1_generate_at_the_declared_values_is_the_shipped_files_byte_for_byte(rid):
    rule = by_id(catalog(), rid)
    made = fixturegen.generate(rule)
    assert [p for p, _ in made["positive"]] == rule.fixtures["positive"]
    assert [p for p, _ in made["negative"]][:len(rule.fixtures["negative"])] == rule.fixtures["negative"]
    assert set(made["arrivals"]) <= {p for p, _ in made["negative"]}   # E4: the arrivals measured for every one
    for kind in ("positive", "negative"):
        for path, doc in made[kind]:
            assert fixturegen.dumps(doc) == (ROOT / path).read_text(encoding="ascii"), path
            assert made["runs"][path][-1] == doc["lines"]   # the shipped file is the run's last round


def test_e1_make_py_is_a_thin_writer_over_fixturegen_and_hostdata_is_what_it_makes():
    text = (ROOT / "tests" / "fixtures" / "host" / "make.py").read_text(encoding="ascii")
    for gone in ("def rhythm_inventory", "def os_lines", "def rounds_of(names, catalog, rules, home, sources=True,"
                 " os_rounds=None):\n    \"\"\"The round records"):
        assert gone not in text
    assert host_fixtures.rhythm_inventory is fixturegen.rhythm_inventory and host_fixtures.os_lines is fixturegen.os_lines
    assert host_fixtures.DECLARED == {"k": 3, "w": 30, "r": 10, "streak": 3, "live_window": 9}
    assert host_fixtures.RHYTHM_SCENARIOS == fixturegen.rhythm_scenarios(3)
    assert host_fixtures.OS_ROUNDS == {name: tuple(v) for name, v in fixturegen.os_rounds(3).items()}
    # the packaged inventories are the exports' as discover reads them now (no drift), the catalog path relative
    assert Path(fixturegen.HOSTDATA).read_text(encoding="ascii") == host_fixtures.build_hostdata()
    data = json.loads(Path(fixturegen.HOSTDATA).read_text(encoding="ascii"))["inventories"]
    assert sorted(data) == host_fixtures.HOSTDATA_NAMES == sorted(
        ["benign/linux-desktop", "benign/linux-desktop:before", "benign/windows-desktop",
         "benign/windows-desktop:before", "kimi-gone", "kimi/one-sample", "windows"])
    assert fixturegen.benign_names() == host_fixtures.BENIGN
    assert all(inv["catalog"] == "raqib/discover/endpoints.yaml" for inv in data.values())
    assert os.path.getsize(fixturegen.HOSTDATA) < 100 * 1024


def test_e1_generate_is_parametric_in_k_w_and_the_streak():
    made = fixturegen.generate(at("HOST-RHYTHM", k=5))
    docs = dict(made["positive"] + made["negative"])
    pos = tree_line(docs["tests/fixtures/rules/HOST-RHYTHM/positive-three-cycles.json"]["lines"])["rhythm"]
    assert (pos["k"], pos["cycles"], pos["fires"]) == (5, 5, True)                 # positives regenerated at 5
    neg = tree_line(docs["tests/fixtures/rules/HOST-RHYTHM/negative-two-cycles.json"]["lines"])["rhythm"]
    assert (neg["k"], neg["cycles"], neg["fires"]) == (5, 4, False)                # k-1 cycles
    assert len(made["runs"]["tests/fixtures/rules/HOST-RHYTHM/positive-three-cycles.json"]) == 6   # k+1 rounds
    made = fixturegen.generate(at("HOST-RHYTHM", w=2))   # the gaps stay inside W
    for path, doc in made["positive"]:
        assert tree_line(doc["lines"])["rhythm"]["w"] == 2 and engine.judge(at("HOST-RHYTHM", w=2), doc["lines"], {})[0]
    made = fixturegen.generate(at("AGENT-DARK-LIVE", streak=5, live_window=15))
    docs = dict(made["positive"] + made["negative"])
    fps = [l["input_meta"] for l in docs["tests/fixtures/rules/AGENT-DARK-LIVE/positive-dark-three-rounds.json"]["lines"]
           if l["tool"] == host.FOOTPRINT_TOOL and l["input_meta"]["dark"]]
    assert fps and all((fp["streak"], fp["live_window"]) == (5, 15) for fp in fps)


def test_e1_generate_writes_nothing_outside_its_temporary_home(home, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    before = sorted(os.listdir(tmp_path))
    fixturegen.generate(at("AGENT-DARK-LIVE", streak=4))
    assert sorted(os.listdir(tmp_path)) == before and os.listdir(home) == []


def test_e1_a_rule_without_a_generator_or_a_streak_of_one_cannot_be_generated():
    with pytest.raises(fixturegen.GenerateError, match="no generator for NEW-AGENT"):
        fixturegen.generate(by_id(catalog(), "NEW-AGENT"))
    with pytest.raises(fixturegen.GenerateError, match="streak 1: its negative"):
        fixturegen.plan(at("AGENT-DARK-LIVE", bounds=False, streak=1))


# --- E2: bounds in each host YAML; the engine loads them; overlay uses them --------------------------------------

def test_e2_every_host_yaml_declares_its_bounds_and_the_engine_loads_them():
    rules = {r.id: r for r in catalog()}
    assert all(rules[rid].bounds is not None for rid in HOST_RULES)
    rh = rules["HOST-RHYTHM"].bounds
    assert {n: (b["min"], b["max"]) for n, b in rh["fields"].items()} == {
        "k": (1, 100), "w": (1, 3600), "r": (1, 1000), "suspect_every": (1, 1000)}
    assert rh["relations"] == [("k", "r", "k <= r")]
    dark = rules["AGENT-DARK-LIVE"].bounds
    assert {n: (b["min"], b["max"]) for n, b in dark["fields"].items()} == {"streak": (2, 100), "live_window": (2, 1000)}
    assert dark["relations"] == [("streak", "live_window", "live_window >= streak")]
    for rid in ("NEW-AGENT", "NEW-AGENT-UNKNOWN", "HOST-UNWATCHED"):
        assert rules[rid].bounds == {"fields": {}, "relations": []}, rid
    assert all(r.bounds is None for r in rules.values() if r.id not in HOST_RULES)   # trace rules: none declared
    assert not hasattr(overlay, "BOUNDS") and not hasattr(overlay, "ORDER")       # no built-in bounds left


BASE = {"id": "USER-X-Y", "title": "t", "class": "NET", "kind": "anchor", "severity": "low", "fp_budget": 0.5,
        "match": {"all": [{"field": "tool", "eq": "Bash"}, {"field": "input_meta.argc", "eq": 3},
                          {"field": "input_meta.depth", "eq": 2}]},
        "fixtures": {"positive": ["p.json"], "negative": ["n.json"]}}


@pytest.mark.parametrize("bounds, word", [
    ([1], "must be a mapping"),
    ({"tool": {"min": 1, "max": 2}}, "'tool' is not a declared threshold"),
    ({"argc": {"min": 1}}, "argc: must be {min: N, max: M}"),
    ({"argc": {"min": 0, "max": 5}}, "1 <= min <= max"),
    ({"argc": {"min": 4, "max": 5}}, "own value 3 is outside 4..5"),
    ({"argc": {"min": 1, "max": 5}, "relations": "argc <= depth"}, "relations: must be a list"),
    ({"argc": {"min": 1, "max": 5}, "relations": ["argc < depth"]}, "must read"),
    ({"argc": {"min": 1, "max": 5}, "relations": ["argc <= depth"]}, "names depth, which has no bounds"),
    ({"argc": {"min": 1, "max": 5}, "depth": {"min": 1, "max": 5}, "relations": ["argc <= depth"]},
     "own values break 'argc <= depth'"),
])
def test_e2_the_engine_refuses_unsound_bounds(bounds, word):
    with pytest.raises(engine.RuleError, match="bounds: .*" + word.replace("(", "\\(").replace("{", "\\{")):
        engine.compile_rule(dict(BASE, bounds=bounds))
    ok = engine.compile_rule(dict(BASE, bounds={"argc": {"min": 1, "max": 5}, "depth": {"min": 1, "max": 5},
                                                "relations": ["argc >= depth"]}))
    assert ok.bounds["relations"] == [("depth", "argc", "argc >= depth")]


def test_e2_raqib_rules_says_which_thresholds_are_fixed(home):
    code, text = run_cli(["rules"])
    assert code == 0
    assert "none_rounds=2 (fixed: its YAML gives it no bounds)" in text
    assert "streak=3 [2..100], live_window=9 [2..1000]" in text
    code, _ = run_cli(["rules", "--threshold", "HOST-UNWATCHED", "none_rounds", "3"])
    assert code == 2
    with pytest.raises(overlay.OverlayError, match="HOST-UNWATCHED none_rounds is not editable"):
        overlay.set_threshold("HOST-UNWATCHED", "none_rounds", "3", str(home))


# --- E3 / E4: measuring ------------------------------------------------------------------------------------------

def test_e5_k_5_is_accepted_and_measured(home):
    said = overlay.set_threshold("HOST-RHYTHM", "k", "5", str(home))
    assert "HOST-RHYTHM k = 5" in said and "measured at k=5 on fixtures generated at it: 4 of 4 positives fire" in said
    assert "0 of 7 measured negatives fire (2 benign arrivals among the 7 negatives)" in said
    overlay._MEASURED.clear()   # at load it is measured again (here: not from this process's memory)
    rules = overlay.load(str(home))
    info = overlay.describe(rules)
    assert info["refused"] == [] and host.rhythm_params(by_id(rules, "HOST-RHYTHM")) == (5, 30, 10)
    assert "HOST-RHYTHM k = 5 (its YAML: 3)" in info["applied"]


def test_e5_k_100_with_r_10_is_refused_by_the_bounds(home):
    with pytest.raises(overlay.OverlayError, match="k = 100 is above its r \\(10\\): its YAML's bounds say k <= r"):
        overlay.set_threshold("HOST-RHYTHM", "k", "100", str(home))
    p = Path(overlay.overlay_path(str(home)))
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("rules:\n  HOST-RHYTHM:\n    thresholds: {k: 100, r: 10}\n", encoding="ascii")
    info = overlay.describe(overlay.load(str(home)))
    assert any("k = 100 is above its r (10)" in r for r in info["refused"])


def test_e5_streak_5_is_accepted_and_one_is_outside_the_bounds(home):
    said = overlay.set_threshold("AGENT-DARK-LIVE", "streak", "5", str(home))
    assert "measured at streak=5 on fixtures generated at it: 2 of 2 positives fire" in said
    with pytest.raises(overlay.OverlayError, match="streak = 1 is outside its bounds 2..100"):
        overlay.set_threshold("AGENT-DARK-LIVE", "streak", "1", str(home))


def test_e3_a_value_the_generated_fixtures_cannot_carry_is_refused_naming_the_fixture(home):
    with pytest.raises(overlay.OverlayError, match="k=1: negative-changing-destination fires"):
        overlay.set_threshold("HOST-RHYTHM", "k", "1", str(home))
    with pytest.raises(overlay.OverlayError, match="k=9: positive-host-talks-os-acts no longer fires"):
        overlay.set_threshold("HOST-RHYTHM", "k", "9", str(home))   # r=10: the os act's k-th cycle is a round late
    assert not Path(overlay.overlay_path(str(home))).exists()


def test_e3_the_measure_judges_every_round_but_the_one_that_clears():
    """A host rule fires once per streak: k=1's negative fires in round 2, not in its last round."""
    rule = at("HOST-RHYTHM", k=1)
    made = fixturegen.generate(rule)
    path = "tests/fixtures/rules/HOST-RHYTHM/negative-changing-destination.json"
    runs = made["runs"][path]
    assert not engine.judge(rule, runs[-1], {})[0] and any(engine.judge(rule, l, {})[0] for l in runs)
    dark = fixturegen.generate(by_id(catalog(), "AGENT-DARK-LIVE"))
    path = "tests/fixtures/rules/AGENT-DARK-LIVE/negative-dark-then-linked.json"
    assert dark["last_round_only"] == [path] and overlay.measure_generated(by_id(catalog(), "AGENT-DARK-LIVE"),
                                                                           "streak=3")[0] == []


# --- E5: a person's rule without bounds; the panel; an installed raqib ---------------------------------------------

USER_RULE = """id: USER-ARGC
title: A Bash call with three arguments
class: DESTRUCT
kind: signature
evasion:
  - "the arguments in one quoted string are one"
severity: low
fp_budget: 0.5
match:
  all:
    - {field: tool, eq: Bash}
    - {field: phase, eq: pre}
    - {field: input_meta.argc, eq: 3}
fixtures:
  positive:
    - fx/positive.json
  negative:
    - fx/negative.json
%s"""


def user_rule(folder, bounds=""):
    folder = Path(folder)
    (folder / "fx").mkdir(parents=True, exist_ok=True)
    (folder / "USER-ARGC.yaml").write_text(USER_RULE % bounds, encoding="ascii")

    def rec(argc):
        return [{"ts": "2026-11-09T10:00:01.000Z", "seq": 1, "session_id": "s-user", "phase": "pre", "tool": "Bash",
                 "cwd": "/work/demo", "input_sha256": "0" * 64, "input_meta": {"argc": argc}}]
    (folder / "fx" / "positive.json").write_text(json.dumps(rec(3)), encoding="ascii")
    (folder / "fx" / "negative.json").write_text(json.dumps(rec(1)), encoding="ascii")
    return folder / "USER-ARGC.yaml"


def test_e5_a_user_rule_without_bounds_is_not_editable_and_one_with_bounds_is_measured(home, tmp_path):
    overlay.add_rule(str(user_rule(tmp_path / "a")), str(home))
    rows = {r["id"]: r for r in overlay.listing(overlay.load(str(home)))}
    assert rows["USER-ARGC"]["thresholds"] == [] and rows["USER-ARGC"]["fixed"] == [
        {"name": "argc", "value": 3, "why": overlay.FIXED_NO_BLOCK}]
    code, text = run_cli(["rules"])
    assert "argc=3 (fixed: its YAML has no bounds block)" in text
    with pytest.raises(overlay.OverlayError, match="USER-ARGC argc is not editable \\(fixed: its YAML has no bounds"):
        overlay.set_threshold("USER-ARGC", "argc", "4", str(home))
    # with bounds it is editable, and measured on its own fixture files (which carry argc 3): refused at 4
    shutil.rmtree(overlay.user_dir(str(home)))
    overlay.add_rule(str(user_rule(tmp_path / "b", "bounds:\n  argc: {min: 1, max: 9}\n")), str(home))
    with pytest.raises(overlay.OverlayError, match="argc=4: positive no longer fires"):
        overlay.set_threshold("USER-ARGC", "argc", "4", str(home))


def test_e5_the_panels_threshold_edit_shows_the_measurement(home):
    p = app.RulesPanel(home=str(home))
    p.threshold("HOST-RHYTHM", "w", "60")
    assert p.level == "clean" and p.message.startswith("threshold ok (measured): HOST-RHYTHM w = 60")
    assert "measured at w=60 on fixtures generated at it: 4 of 4 positives fire" in p.message
    p.threshold("HOST-RHYTHM", "k", "1")
    assert p.level == "alarm" and p.message.startswith("REFUSED: threshold refused: HOST-RHYTHM: k=1, w=60:")
    assert "negative-changing-destination fires" in p.message
    assert "measured before it is allowed" in app.RULES_INTRO


def test_e5_an_installed_layout_sets_measures_and_resets_with_no_checkout(home, tmp_path):
    """CI's install pair from the package files alone (tests/test_packaging.py's site layout: the wheel's files,
    `python -I`, cwd outside the checkout): `raqib rules --threshold HOST-RHYTHM k 4`, then `--reset`."""
    import test_packaging
    site = test_packaging.site_layout(tmp_path / "site-packages")
    assert not (site / "tests").exists() and (site / "raqib" / "rules" / "hostdata" / "inventories.json").is_file()
    outside = tmp_path / "outside"
    outside.mkdir()
    env = dict(os.environ, HOME=str(home), USERPROFILE=str(home))
    env.pop("PYTHONPATH", None)
    set_ = test_packaging.run_installed(site, outside, "rules", "--threshold", "HOST-RHYTHM", "k", "4", env=env)
    assert set_.returncode == 0, set_.stderr
    assert "measured at k=4 on fixtures generated at it: 4 of 4 positives fire" in set_.stdout
    assert "k=4* [1..100]" in set_.stdout and "rules overlay" in set_.stdout and "1 applied, 0 refused" in set_.stdout
    no = test_packaging.run_installed(site, outside, "rules", "--threshold", "HOST-RHYTHM", "k", "1", env=env)
    assert no.returncode == 2 and "k=1: negative-changing-destination fires" in no.stderr
    back = test_packaging.run_installed(site, outside, "rules", "--reset", "HOST-RHYTHM", env=env)
    assert back.returncode == 0 and "HOST-RHYTHM reset" in back.stdout and "k=3 [1..100]" in back.stdout


def _can_build_a_wheel():
    return importlib.util.find_spec("setuptools") is not None and importlib.util.find_spec("ensurepip") is not None


@pytest.mark.skipif(not _can_build_a_wheel(), reason="no setuptools or ensurepip in this Python: the wheel cannot be"
                                                      " built offline (the site-layout test above still runs)")
def test_e5_a_wheel_installed_in_a_clean_venv_sets_measures_and_resets(home, tmp_path):
    """CI's install pair from a real wheel: built offline from a copy of the package files (setuptools of this
    Python, no build isolation), installed with pip into a fresh venv, run from outside any checkout."""
    src = tmp_path / "src"
    src.mkdir()
    for name in ("pyproject.toml", "README.md"):
        shutil.copyfile(ROOT / name, src / name)
    shutil.copytree(ROOT / "raqib", src / "raqib", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    env = dict(os.environ, HOME=str(home), USERPROFILE=str(home), PIP_DISABLE_PIP_VERSION_CHECK="1")
    env.pop("PYTHONPATH", None)
    dist = tmp_path / "dist"
    built = subprocess.run([sys.executable, "-m", "pip", "wheel", "--no-deps", "--no-build-isolation", "--no-index",
                            "-w", str(dist), str(src)], capture_output=True, text=True, timeout=300, env=env)
    if built.returncode != 0:
        pytest.skip("pip could not build the wheel offline here: %s" % built.stderr.strip()[-300:])
    (wheel,) = dist.glob("raqib-*.whl")
    venv = tmp_path / "venv"
    subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True, timeout=300, env=env)
    bindir = venv / ("Scripts" if WINDOWS else "bin")
    py = bindir / ("python.exe" if WINDOWS else "python")
    subprocess.run([str(py), "-m", "pip", "install", "--no-index", "--no-deps", str(wheel)], check=True,
                   capture_output=True, timeout=300, env=env)
    outside = tmp_path / "outside"
    outside.mkdir()
    where = subprocess.run([str(py), "-c", "import raqib; print(raqib.__file__)"], cwd=str(outside), env=env,
                           capture_output=True, text=True, timeout=60).stdout.strip()
    assert os.path.realpath(where).startswith(os.path.realpath(str(venv))), where   # the venv's, not the checkout's
    raqib = bindir / ("raqib.exe" if WINDOWS else "raqib")

    def run(*argv):
        return subprocess.run([str(raqib), "rules"] + list(argv), cwd=str(outside), env=env, capture_output=True,
                              text=True, timeout=300)
    set_ = run("--threshold", "HOST-RHYTHM", "k", "4")
    assert set_.returncode == 0 and "measured at k=4 on fixtures generated at it" in set_.stdout, set_.stderr
    back = run("--reset", "HOST-RHYTHM")
    assert back.returncode == 0 and "HOST-RHYTHM reset" in back.stdout, back.stderr


def test_e5_the_rule_kinds_are_unchanged():
    """No rule added or removed: the catalog's YAML kinds as before (the gate's line, 4 : 7 : 11, counts the
    code and silence rules too and is recorded in the questions file)."""
    kinds = [r.kind for r in catalog()]
    assert (kinds.count("signature"), kinds.count("demand"), kinds.count("anchor"), len(kinds)) == (4, 2, 8, 14)


def test_e5_new_and_changed_files_are_ascii_and_the_readme_says_it_in_two_lines():
    for name in ("raqib/rules/fixturegen.py", "raqib/rules/hostdata/inventories.json", "raqib/overlay.py",
                 "raqib/rules/engine.py", "raqib/app.py", "tests/fixtures/host/make.py", "tests/test_thresholds.py"):
        (ROOT / name).read_bytes().decode("ascii")
    section = (ROOT / "README.md").read_text(encoding="utf-8").split("## Choose the rules\n", 1)[1].split("\n## ", 1)[0]
    assert "within the bounds its rule's YAML declares" in section and "generated at the new value" in section


def test_e5_the_questions_file_has_the_gate_numbers_and_the_tests():
    text = QUESTIONS.read_text(encoding="utf-8")
    for q in ("Q-1", "Q-2", "Q-3", "Q-4", "Q-5", "Q-6"):
        assert q in text
    assert "2854 passed, 22 skipped" in text and "test_thresholds.py" in text


# --- follow-up (CI run 42584260231): machine-independent paths in shipped host data -------------------------------

def _root_forms():
    forms = set()
    for r in (str(ROOT), os.path.realpath(str(ROOT))):
        forms |= {r, r.replace("\\", "\\\\"), r.replace("\\", "/")}
    return forms


def test_followup_no_shipped_or_generated_file_holds_this_checkouts_path():
    files = [p for p in (ROOT / "raqib").rglob("*") if p.is_file() and p.suffix in (".json", ".yaml")]
    files += list((ROOT / "tests" / "fixtures" / "rules").rglob("*.json"))
    files += list((ROOT / "tests" / "fixtures" / "host" / "notes").rglob("*.json"))
    assert len(files) > 50
    for p in files:
        text = p.read_text(encoding="utf-8")
        assert not any(f in text for f in _root_forms()), p
    made = fixturegen.generate(at("HOST-RHYTHM", k=4))
    text = json.dumps(made["runs"])
    assert not any(f in text for f in _root_forms())


def test_followup_the_package_data_has_no_local_home_path():
    """The generated package data (hostdata): only the exports' redaction placeholders (user, field) as homes.
    The catalog YAMLs' comments name illustrative homes (/home/alice in SCOPE-CWD-ROOT); they are covered by the
    checkout-path test above, not this one."""
    files = list((ROOT / "raqib" / "rules" / "hostdata").glob("*.json"))
    assert files
    for p in files:
        assert fixturegen.machine_path_problem(p.read_text(encoding="utf-8")) is None, p
    for bad in ("/home/claude/x", "/Users/bob/x", "C:\\Users\\bob\\x", "C:\\\\Users\\\\bob", "C:/Users/bob",
                str(ROOT / "tests" / "x.txt")):
        assert fixturegen.machine_path_problem(bad), bad
    for ok in ("/home/user/x", "C:\\\\Users\\\\field\\\\x", "tests/fixtures/discover/linux/proc.txt"):
        assert fixturegen.machine_path_problem(ok) is None, ok


def test_followup_one_helper_writes_paths_relative_and_the_replay_refuses_machine_data(tmp_path, monkeypatch):
    root = str(tmp_path / "checkout")
    sep = os.sep
    got = fixturegen.portable({"catalog": root + sep + "raqib" + sep + "discover" + sep + "endpoints.yaml",
                               "label": [root + sep + "tests" + sep + "a.txt (saved from live /proc)"], "n": 3}, root)
    assert got == {"catalog": "raqib/discover/endpoints.yaml", "label": ["tests/a.txt (saved from live /proc)"], "n": 3}
    text = (ROOT / "tests" / "fixtures" / "host" / "make.py").read_text(encoding="ascii")
    assert "fixturegen.portable(inventory(name, catalog), ROOT)" in text and "CATALOG_WORD" not in text
    data = json.loads(Path(fixturegen.HOSTDATA).read_text(encoding="ascii"))
    data["inventories"]["windows"]["note"] = str(ROOT / "tests" / "fixtures" / "discover" / "windows")
    doctored = tmp_path / "inventories.json"
    doctored.write_text(json.dumps(data), encoding="ascii")
    monkeypatch.setattr(fixturegen, "HOSTDATA", str(doctored))
    monkeypatch.setattr(fixturegen, "_PACKAGED", {})
    with pytest.raises(fixturegen.GenerateError, match="the absolute path .* of this machine"):
        fixturegen.packaged()
