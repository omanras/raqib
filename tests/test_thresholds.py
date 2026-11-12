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
import re
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


def gen(rule, **kw):
    """fixturegen.generate with the round builder host.py hands it (E-8)."""
    return fixturegen.generate(rule, host.fixture_builder(), **kw)


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
    made = gen(rule)
    assert [p for p, _ in made["positive"]] == rule.fixtures["positive"]
    assert [p for p, _ in made["negative"]][:len(rule.fixtures["negative"])] == rule.fixtures["negative"]
    assert set(made["arrivals"]) <= {p for p, _ in made["negative"]}   # E4: the arrivals measured for every one
    for kind in ("positive", "negative"):
        for path, doc in made[kind]:
            assert fixturegen.dumps(doc) == (ROOT / path).read_text(encoding="ascii"), path
            assert made["runs"][path][-1] == doc["lines"]   # the shipped file is the run's last round


def test_e1_make_py_is_a_thin_writer_over_fixturegen_and_hostdata_is_what_it_makes():
    text = (ROOT / "tests" / "fixtures" / "host" / "make.py").read_text(encoding="ascii")
    for gone in ("def rhythm_inventory", "def os_lines", "watch = host.HostWatch("):
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
         "benign/windows-desktop:before", "kimi-gone", "kimi/one-sample", "kimi/two-samples", "windows"])
    assert fixturegen.benign_names() == host_fixtures.BENIGN
    assert all(inv["catalog"] == "raqib/discover/endpoints.yaml" for inv in data.values())
    assert os.path.getsize(fixturegen.HOSTDATA) < 100 * 1024


def test_e1_generate_is_parametric_in_k_w_and_the_streak():
    made = gen(at("HOST-RHYTHM", k=5))
    docs = dict(made["positive"] + made["negative"])
    pos = tree_line(docs["tests/fixtures/rules/HOST-RHYTHM/positive-three-cycles.json"]["lines"])["rhythm"]
    assert (pos["k"], pos["cycles"], pos["fires"]) == (5, 5, True)                 # positives regenerated at 5
    neg = tree_line(docs["tests/fixtures/rules/HOST-RHYTHM/negative-two-cycles.json"]["lines"])["rhythm"]
    assert (neg["k"], neg["cycles"], neg["fires"]) == (5, 4, False)                # k-1 cycles
    assert len(made["runs"]["tests/fixtures/rules/HOST-RHYTHM/positive-three-cycles.json"]) == 6   # k+1 rounds
    made = gen(at("HOST-RHYTHM", w=2))   # the gaps stay inside W
    for path, doc in made["positive"]:
        assert tree_line(doc["lines"])["rhythm"]["w"] == 2 and engine.judge(at("HOST-RHYTHM", w=2), doc["lines"], {})[0]
    made = gen(at("AGENT-DARK-LIVE", streak=5, live_window=15))
    docs = dict(made["positive"] + made["negative"])
    fps = [l["input_meta"] for l in docs["tests/fixtures/rules/AGENT-DARK-LIVE/positive-dark-three-rounds.json"]["lines"]
           if l["tool"] == host.FOOTPRINT_TOOL and l["input_meta"]["dark"]]
    assert fps and all((fp["streak"], fp["live_window"]) == (5, 15) for fp in fps)


def test_e1_generate_writes_nothing_outside_its_temporary_home(home, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    before = sorted(os.listdir(tmp_path))
    gen(at("AGENT-DARK-LIVE", streak=4))
    assert sorted(os.listdir(tmp_path)) == before and os.listdir(home) == []


def test_e1_a_rule_without_a_generator_or_a_streak_of_one_cannot_be_generated():
    with pytest.raises(fixturegen.GenerateError, match="no generator for NEW-AGENT"):
        gen(by_id(catalog(), "NEW-AGENT"))
    with pytest.raises(fixturegen.GenerateError, match="streak 1: its negative"):
        fixturegen.plan(at("AGENT-DARK-LIVE", bounds=False, streak=1))


# --- E2: bounds in each host YAML; the engine loads them; overlay uses them --------------------------------------

def test_e2_every_host_yaml_declares_its_bounds_and_the_engine_loads_them():
    rules = {r.id: r for r in catalog()}
    assert all(rules[rid].bounds is not None for rid in HOST_RULES)
    rh = rules["HOST-RHYTHM"].bounds
    assert {n: (b["min"], b["max"]) for n, b in rh["fields"].items()} == {   # REDO E-3: no suspect_every
        "k": (1, 100), "w": (1, 3600), "r": (1, 200)}
    assert rh["relations"] == [("k", "r", "k <= r")]
    dark = rules["AGENT-DARK-LIVE"].bounds
    assert {n: (b["min"], b["max"]) for n, b in dark["fields"].items()} == {"streak": (2, 100), "live_window": (2, 300)}
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
    assert "streak=3 [2..100; measured 2..9], live_window=9 [2..300; measured 3..300]" in text   # REDO E-6
    assert "k=3 [1..100; measured 2..8], w=30 [1..3600], r=10 [1..200; measured 5..200]" in text
    code, _ = run_cli(["rules", "--threshold", "HOST-UNWATCHED", "none_rounds", "3"])
    assert code == 2
    with pytest.raises(overlay.OverlayError, match="HOST-UNWATCHED none_rounds is not editable"):
        overlay.set_threshold("HOST-UNWATCHED", "none_rounds", "3", str(home))


# --- E3 / E4: measuring ------------------------------------------------------------------------------------------

def test_e5_k_5_is_accepted_and_measured(home):
    said = overlay.set_threshold("HOST-RHYTHM", "k", "5", str(home))
    assert "HOST-RHYTHM k = 5" in said and "measured at k=5 on fixtures generated at it (sensitive:" in said
    assert "positive-three-cycles stops firing at k=6; negative-two-cycles fires at k=4" in said
    # ADR-0007 AP-3: with the quiet positive and the two quiet negatives
    assert "7 of 7 positives fire; 0 of 9 measured negatives fire; the 2 synthetic desktops do not fire" in said
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
    assert "measured at streak=5 on fixtures generated at it (sensitive: positive-dark-three-rounds stops firing at" \
           " streak=6; negative-dark-two-rounds fires at streak=4): 3 of 3 positives fire" in said
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
    made = gen(rule)
    path = "tests/fixtures/rules/HOST-RHYTHM/negative-changing-destination.json"
    runs = made["runs"][path]
    assert not engine.judge(rule, runs[-1], {})[0] and any(engine.judge(rule, l, {})[0] for l in runs)
    dark = gen(by_id(catalog(), "AGENT-DARK-LIVE"))
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


def test_e5_a_user_rule_without_bounds_is_not_editable_and_one_with_bounds_is_fixed(home, tmp_path):
    overlay.add_rule(str(user_rule(tmp_path / "a")), str(home))
    rows = {r["id"]: r for r in overlay.listing(overlay.load(str(home)))}
    assert rows["USER-ARGC"]["thresholds"] == [] and rows["USER-ARGC"]["fixed"] == [
        {"name": "argc", "value": 3, "why": overlay.FIXED_NO_BLOCK}]
    code, text = run_cli(["rules"])
    assert "argc=3 (fixed: its YAML has no bounds block)" in text
    with pytest.raises(overlay.OverlayError, match="USER-ARGC argc is not editable \\(fixed: its YAML has no bounds"):
        overlay.set_threshold("USER-ARGC", "argc", "4", str(home))
    # REDO E-2: with bounds it is still FIXED: no generator makes an edge pair for a person's rule
    shutil.rmtree(overlay.user_dir(str(home)))
    overlay.add_rule(str(user_rule(tmp_path / "b", "bounds:\n  argc: {min: 1, max: 9}\n")), str(home))
    code, text = run_cli(["rules"])
    assert "argc=3 (not measurable: no fixture is sensitive to argc)" in text
    with pytest.raises(overlay.OverlayError, match="not measurable: no fixture is sensitive to argc"):
        overlay.set_threshold("USER-ARGC", "argc", "4", str(home))


def test_e5_the_panels_threshold_edit_shows_the_measurement(home):
    p = app.RulesPanel(home=str(home))
    p.threshold("HOST-RHYTHM", "w", "60")
    assert p.level == "clean" and p.message.startswith("threshold ok (measured): HOST-RHYTHM w = 60")
    assert "measured at w=60 on fixtures generated at it (sensitive: positive-w-edge stops firing at w=59;" \
           " negative-w-edge fires at w=61): 7 of 7 positives fire" in p.message
    assert p.measuring == ["measuring the overlay's thresholds..."]   # E-7: on set, once; not again on reload
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
    assert "measured at k=4 on fixtures generated at it (sensitive:" in set_.stdout
    assert "k=4* [1..100; measured 2..8]" in set_.stdout and "rules overlay" in set_.stdout and "1 applied, 0 refused" in set_.stdout
    no = test_packaging.run_installed(site, outside, "rules", "--threshold", "HOST-RHYTHM", "k", "1", env=env)
    assert no.returncode == 2 and "k=1: negative-changing-destination fires" in no.stderr
    back = test_packaging.run_installed(site, outside, "rules", "--reset", "HOST-RHYTHM", env=env)
    assert back.returncode == 0 and "HOST-RHYTHM reset" in back.stdout and "k=3 [1..100; measured 2..8]" in back.stdout


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
    from readme_text import GUIDE, flat, section as cut   # M9.2: docs/GUIDE.md, wrapped: compared flattened
    section = flat(cut("Choose the rules", GUIDE))
    assert "within the bounds its rule's YAML declares" in section and "generated at the new value" in section


def test_e5_the_questions_file_has_the_gate_numbers_and_the_tests():
    text = QUESTIONS.read_text(encoding="utf-8")
    for q in ("Q-1", "Q-2", "Q-3", "Q-4", "Q-5", "Q-6"):
        assert q in text
    assert "2854 passed, 22 skipped" in text and "test_thresholds.py" in text


# --- follow-up (CI run 42584260231): machine-independent paths in shipped host data -------------------------------

# M7.6d (HANDOFF E3, ADR-0008 E-1): the path test asserts on the pattern of a home directory, never on this
# checkout's own path, so it is the same test on every machine (a clone under /home/<name> no longer decides it).
HOME_DIR = re.compile(r"(?:/home/|/Users/|[A-Za-z]:(?:\\\\|\\|/)Users(?:\\\\|\\|/))([A-Za-z0-9._-]+)")
PLACEHOLDERS = ("user", "field")   # the exports' redaction placeholders (tests/fixtures/discover headers)
# Illustrative or built-in homes, each allowed only under the paths named (relative to the repository root):
# the HANDOFF's alice and bob and the other made-up names of the same synthetic fixtures and catalog comments;
# Public (C:\\Users\\Public, a Windows built-in) and ubuntu (the stock account of the sandbox image, listed by
# the M5.0 capture; not the sandbox's user) are not persons. Recorded: docs/review/2026-11-09-M7.6d-questions.md.
ILLUSTRATIVE = {
    "alice": ("raqib/rules/catalog/SCOPE-CWD-ROOT.yaml", "tests/fixtures/rules/SCOPE-CWD-ROOT/",
              "tests/fixtures/rules/SCOPE-PATH/", "tests/fixtures/rules/generate.py"),
    "bob": ("tests/fixtures/rules/SCOPE-CWD-ROOT/", "tests/fixtures/rules/generate.py"),
    "carol": ("tests/fixtures/rules/SCOPE-CWD-ROOT/", "tests/fixtures/rules/generate.py"),
    "dan": ("tests/fixtures/rules/SCOPE-CWD-ROOT/", "tests/fixtures/rules/generate.py"),
    "dev": ("tests/fixtures/eval/", "tests/fixtures/tree/"),
    "a": ("raqib/rules/catalog/SCOPE-CWD-MOVED.yaml",),
    "x": ("raqib/rules/catalog/SCOPE-CWD-ROOT.yaml",),
    "Public": ("raqib/rules/catalog/SCOPE-CWD-ROOT.yaml", "tests/fixtures/discover/windows/footprints.txt"),
    "ubuntu": ("tests/fixtures/discover/linux/footprints.txt",),
}


def _home_problems(rel, text):
    """The home directories in text that are neither a placeholder nor allowed at rel."""
    return [m.group(0) for m in HOME_DIR.finditer(text) if m.group(1) not in PLACEHOLDERS
            and not any(rel.startswith(w) for w in ILLUSTRATIVE.get(m.group(1), ()))]


def _scanned():
    """(rel, text) of the package data (every file under raqib/ but its code) and of every text file under
    tests/fixtures (data and the generators beside it)."""
    files = [p for p in (ROOT / "raqib").rglob("*") if p.is_file() and p.suffix not in (".py", ".pyc")]
    files += [p for p in (ROOT / "tests" / "fixtures").rglob("*") if p.is_file() and p.suffix != ".pyc"]
    out = []
    for p in sorted(files):
        try:
            text = p.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        out.append((p.relative_to(ROOT).as_posix(), text))
    return out


def test_followup_no_shipped_or_generated_file_holds_this_checkouts_path():
    """E3: no home directory but the placeholders (and the illustrative ones, where named) in package data,
    tests/fixtures or a generated run; the pattern, not this checkout's path, so every machine runs the same
    test."""
    scanned = _scanned()
    assert len(scanned) > 150 and any(r == "raqib/rules/hostdata/inventories.json" for r, _ in scanned)
    found = {}
    for rel, text in scanned:
        assert _home_problems(rel, text) == [], rel
        for m in HOME_DIR.finditer(text):
            found.setdefault(m.group(1), set()).add(rel)
    assert set(ILLUSTRATIVE) <= set(found)   # every allowance is still used (none kept by habit)
    made = gen(at("HOST-RHYTHM", k=4))
    assert _home_problems("<generated>", json.dumps(made["runs"])) == []


def test_e3_the_home_pattern_refuses_any_other_home_in_every_form():
    for bad in ("/home/claude/raqib", "/home/runner/work/raqib", "/Users/bob/x", "C:\\Users\\bob\\x",
                "C:\\\\Users\\\\alice", "C:/Users/dan", "d:\\Users\\Public", "/home/ubuntu"):
        assert _home_problems("tests/fixtures/x.json", bad), bad
    for ok in ("/home/user/x", "/home/field", "C:\\Users\\user\\x", "C:\\\\Users\\\\field\\\\x",
               "/Users/user", "tests/fixtures/discover/linux/proc.txt", "/root/.claude"):
        assert _home_problems("tests/fixtures/x.json", ok) == [], ok
    assert _home_problems("tests/fixtures/rules/SCOPE-CWD-ROOT/a.json", "/home/alice/p") == []
    assert _home_problems("tests/fixtures/discover/linux/footprints.txt", "/home/ubuntu") == []
    assert _home_problems("raqib/rules/hostdata/inventories.json", "/home/alice/p")   # allowed only where named
    test = (ROOT / "tests" / "test_thresholds.py").read_text(encoding="ascii")
    body = test.split("def test_followup_no_shipped_or_generated_file_holds_this_checkouts_path", 1)[1]
    assert "str(ROOT)" not in body.split("\ndef ", 1)[0]   # never this checkout's path


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


# --- REDO (ADR-0008 Amendment E): E-2..E-9, each with its test (E-11) ------------------------------------------------

def _fires(rule, rounds):
    return any(engine.judge(rule, lines, {})[0] for lines in rounds)


SWEEP = [("HOST-RHYTHM", "k", (2, 5, 8)), ("HOST-RHYTHM", "w", (1, 30, 3600)), ("HOST-RHYTHM", "r", (5, 10, 200)),
         ("AGENT-DARK-LIVE", "streak", (2, 5, 9)), ("AGENT-DARK-LIVE", "live_window", (3, 9, 300))]


@pytest.mark.parametrize("rid, field, values", SWEEP)
def test_redo_e2_each_editable_field_has_an_edge_pair_that_flips_across_its_bounds(rid, field, values):
    """E-2: generated at v, the edge positive fires under v and not under the stricter neighbour; the edge
    negative does not fire under v and fires under the looser one - at the low end, the declared value and the
    high end of the range the measurement accepts."""
    base = by_id(catalog(), rid)
    pos, neg = ("tests/fixtures/rules/" + p for p in fixturegen.EDGES[rid][field])
    step = fixturegen.STRICTER[field]
    for v in values:
        vals = dict(fixturegen.values_of(base), **{field: v})
        rule = fixturegen.with_values(base, vals)
        made = gen(rule, only={pos, neg})
        assert _fires(rule, made["runs"][pos]) and not _fires(rule, made["runs"][neg]), (field, v)
        for delta, path, want in ((step, pos, False), (-step, neg, True)):
            try:
                other = fixturegen.with_values(base, dict(vals, **{field: v + delta}))
            except engine.RuleError:
                continue   # outside the bounds or a relation: that side is not run
            assert _fires(other, gen(other, shape=vals, only={path})["runs"][path]) is want, (field, v, v + delta)


def test_redo_e2_editable_fields_and_a_field_without_an_edge_pair_is_fixed(home, monkeypatch):
    rules = {r.id: r for r in catalog()}
    assert sorted(overlay.thresholds(rules["HOST-RHYTHM"])) == ["k", "r", "w"]
    assert sorted(overlay.thresholds(rules["AGENT-DARK-LIVE"])) == ["live_window", "streak"]
    assert overlay.fixed_thresholds(rules["HOST-UNWATCHED"])["none_rounds"]["why"] == overlay.FIXED_NO_BOUND
    monkeypatch.setitem(fixturegen.EDGES, "HOST-RHYTHM", {"k": fixturegen.EDGES["HOST-RHYTHM"]["k"]})
    assert overlay.fixed_thresholds(rules["HOST-RHYTHM"])["w"]["why"] == "not measurable: no fixture is sensitive to w"
    code, text = run_cli(["rules"])
    assert "w=30 (not measurable: no fixture is sensitive to w)" in text
    with pytest.raises(overlay.OverlayError, match="HOST-RHYTHM w is not editable \\(not measurable: no fixture is"
                                                   " sensitive to w"):
        overlay.set_threshold("HOST-RHYTHM", "w", "60", str(home))


def test_redo_e2_the_measure_refuses_a_value_whose_edge_does_not_flip(home, monkeypatch):
    """A field whose edge pair does not flip at the new value is not measured there, and is refused."""
    real = fixturegen.generate

    def flat(rule, builder, rules=None, shape=None, only=None):   # the negative made at v under v-1: as made at v
        made = real(rule, builder, rules, shape, only)
        if shape is not None:
            for p in made["runs"]:
                made["runs"][p] = [[]]
        return made
    monkeypatch.setattr(fixturegen, "generate", flat)
    overlay._MEASURED.clear()
    with pytest.raises(overlay.OverlayError, match="k=5: not sensitive at k=4: negative-two-cycles does not fire"):
        overlay.set_threshold("HOST-RHYTHM", "k", "5", str(home))
    overlay._MEASURED.clear()


def test_redo_e3_suspect_every_is_a_watch_option_not_a_rule_threshold(home, capsys):
    text = (CATALOG_DIR / "HOST-RHYTHM.yaml").read_text(encoding="ascii")
    assert "input_meta.rhythm.suspect_every" not in text and "suspect_every:" not in text
    assert not hasattr(host, "SUSPECT_EVERY_FIELD") and host.SUSPECT_EVERY == 10
    with pytest.raises(overlay.OverlayError, match="HOST-RHYTHM has no field 'suspect_every'"):
        overlay.set_threshold("HOST-RHYTHM", "suspect_every", "5", str(home))
    for argv, word in ((["watch", "--host", "--suspect-every", "5"], "--suspect-every applies with --suspect"),
                       (["watch", "--host", "--suspect", "fake:x.json", "--suspect-every", "0"], "--suspect-every:"),
                       (["watch", "proj", "--suspect-every", "5"], "apply to watch --host only")):
        code, _ = run_cli(argv)
        assert code == 2 and word in capsys.readouterr().err, argv
    assert host.check_suspect_every(5) == 5
    for bad in (0, 1001, True, "5"):
        with pytest.raises(ValueError):
            host.check_suspect_every(bad)
    assert app.suspect_every_spec("") == (None, None) and app.suspect_every_spec(" 7 ") == (7, None)
    assert app.suspect_every_spec("x")[1] and app.suspect_every_spec("0")[1]
    o = app.Options(None, None, 60, environ={})
    assert o.suspect_every == ""
    import inspect
    assert "suspect_every" in inspect.signature(host.command).parameters
    assert "suspect_every" in inspect.signature(host.HostWatch).parameters


def test_redo_e4_e5_synthetic_desktops_are_named_so_and_not_counted(home):
    said = overlay.set_threshold("AGENT-DARK-LIVE", "streak", "4", str(home))
    assert "0 of 3 measured negatives fire; the 2 synthetic desktops do not fire (run, not counted" in said
    assert "benign desktop" not in said and "arrivals among" not in said
    src = (ROOT / "raqib" / "overlay.py").read_text(encoding="ascii")
    assert "would fire on a synthetic desktop" in src and "would fire on a benign desktop" not in src


def test_redo_e6_a_refusal_names_the_fixture_and_the_condition_and_the_ranges_hold(home):
    with pytest.raises(overlay.OverlayError, match="k=9: positive-host-talks-os-acts no longer fires: r must be >= k\\+2:"
                                                   " an os act is read one round late"):
        overlay.set_threshold("HOST-RHYTHM", "k", "9", str(home))
    with pytest.raises(overlay.OverlayError, match="k=1: negative-changing-destination fires: k must be >= 2"):
        overlay.set_threshold("HOST-RHYTHM", "k", "1", str(home))
    with pytest.raises(overlay.OverlayError, match="r must be >= k\\+2"):
        overlay.set_threshold("HOST-RHYTHM", "r", "4", str(home))
    # the effective range shown is what the measurement accepts: its ends pass
    rows = {r["id"]: {t["name"]: t for t in r["thresholds"]} for r in overlay.listing(catalog())}
    assert (rows["HOST-RHYTHM"]["k"]["lo"], rows["HOST-RHYTHM"]["k"]["hi"]) == (2, 8)
    assert (rows["HOST-RHYTHM"]["r"]["lo"], rows["HOST-RHYTHM"]["r"]["hi"]) == (5, 200)
    for rid, field, value in (("HOST-RHYTHM", "k", 2), ("HOST-RHYTHM", "k", 8), ("HOST-RHYTHM", "r", 5),
                              ("AGENT-DARK-LIVE", "streak", 9), ("AGENT-DARK-LIVE", "live_window", 3)):
        assert "measured at %s=%d" % (field, value) in overlay.set_threshold(rid, field, str(value), str(home))
        overlay.reset(rid, str(home))


def test_redo_e7_a_load_measures_only_when_the_overlay_or_catalog_changed(home, monkeypatch, capsys):
    calls = []
    real = overlay.measure_generated

    def counted(rule, label, fields=None):
        calls.append(label)
        return real(rule, label, fields)
    monkeypatch.setattr(overlay, "measure_generated", counted)
    overlay._MEASURED.clear()
    p = Path(overlay.overlay_path(str(home)))
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("rules:\n  HOST-RHYTHM:\n    thresholds: {k: 4}\n", encoding="ascii")
    said = []
    overlay.load(str(home), say=said.append)
    assert calls == ["k=4"] and said == [overlay.MEASURING]
    cache = json.loads(Path(overlay.measured_path(str(home))).read_text(encoding="ascii"))
    assert cache["results"]["HOST-RHYTHM|k=4"]["reasons"] == [] and cache["stamp"]
    overlay._MEASURED.clear()   # a new process: only the file remembers
    said = []
    rules = overlay.load(str(home), say=said.append)
    assert calls == ["k=4"] and said == []                     # no change: nothing measured, nothing said
    assert host.rhythm_params(by_id(rules, "HOST-RHYTHM"))[0] == 4 and "measured at k=4" in by_id(rules, "HOST-RHYTHM").measured
    p.write_text("rules:\n  HOST-RHYTHM:\n    thresholds: {k: 5}\n", encoding="ascii")   # the overlay changed
    overlay.load(str(home), say=said.append)
    assert calls == ["k=4", "k=5"] and said == [overlay.MEASURING]
    # the CLI says it while it runs (stderr), and not on a load with no change
    p.write_text("rules:\n  HOST-RHYTHM:\n    thresholds: {k: 6}\n", encoding="ascii")
    overlay._MEASURED.clear()
    capsys.readouterr()
    assert run_cli(["rules"])[0] == 0
    assert "raqib: measuring the overlay's thresholds..." in capsys.readouterr().err
    assert run_cli(["rules"])[0] == 0
    assert "measuring" not in capsys.readouterr().err
    # the panel measures on set, not on every reload
    panel = app.RulesPanel(home=str(home))
    n = len(calls)
    panel.reload()
    panel.reload()
    assert len(calls) == n and panel.measuring == []
    panel.threshold("HOST-RHYTHM", "k", "7")
    assert panel.measuring == [overlay.MEASURING] and len(calls) == n + 1
    panel.reload()
    assert len(calls) == n + 1
