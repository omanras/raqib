"""The gate (M-REV E4, ADR-0001 B-3; M5.1 E4: tools/gate.py makes the checks,
tools/gate.sh calls it on POSIX; M4.1 E4: the rule kinds). Each check is run
on a scratch git repository that holds a copy of the gate, so the real tree
and its tests are not involved."""
import contextlib
import importlib.util
import io
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
GATE_SH = ROOT / "tools" / "gate.sh"
GATE_PY = ROOT / "tools" / "gate.py"
BACKEND = 'def sdk():\n    import anthropic\n    return anthropic\n'
# Built here, so that this file itself holds no secret-like or private-tree string.
AWS_KEY = "AK" + "IA" + "Q" * 16
LEAK = "fal" + "ak.git"
# The scratch repository's own test suite: one test that passes.
SCRATCH_TESTS = {"tests/test_ok.py": "def test_ok():\n    pass\n"}
# M4.1 E4: the rule-kinds check loads the catalog with the checkout's own
# loader, so every scratch repository holds a copy of raqib/rules and its catalog.
RULE_FILES = ["raqib/__init__.py", "raqib/rules/__init__.py"] + [
    "raqib/rules/%s.py" % name for name in ("engine", "yamlite", "trace", "silence")] + sorted(
    p.relative_to(ROOT).as_posix() for p in (ROOT / "raqib" / "rules" / "catalog").glob("*.yaml"))
RULES_BASE = {rel: (ROOT / rel).read_bytes() for rel in RULE_FILES}
SCRATCH_BASE = dict({"raqib/suspect/backends.py": BACKEND}, **RULES_BASE)


def gate(tmp_path, files, handoff="# HANDOFF\n", via=None, base=None, add=True):
    repo = tmp_path / "repo"
    (repo / "tools").mkdir(parents=True)
    shutil.copy(GATE_SH, repo / "tools" / "gate.sh")
    shutil.copy(GATE_PY, repo / "tools" / "gate.py")
    (repo / "HANDOFF.md").write_bytes(handoff.encode())
    base = dict(SCRATCH_BASE, **SCRATCH_TESTS) if base is None else base
    for rel, text in dict(base, **files).items():
        if text is None:  # None: leave this base file out
            continue
        path = repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text if isinstance(text, bytes) else text.encode())
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    if add:
        subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
    argv = ["bash", str(repo / "tools" / "gate.sh")] if via == "sh" else [sys.executable, str(repo / "tools" / "gate.py")]
    proc = subprocess.run(argv, capture_output=True, text=True, cwd=tmp_path, timeout=120)
    return proc.returncode, proc.stdout + proc.stderr


@pytest.mark.parametrize("rel, text, where", [
    ("raqib/other.py", "import anthropic\n", "raqib/other.py:1"),
    ("raqib/other.py", "x = 1\nfrom anthropic import Anthropic\n", "raqib/other.py:2"),
    ("raqib/other.py", "import os, anthropic.types as t\n", "raqib/other.py:1"),
    ("raqib/other.py", "import importlib\nm = importlib.import_module('anthropic')\n", "raqib/other.py:2"),
    ("raqib/other.py", "m = __import__('anthropic.types')\n", "raqib/other.py:1"),
    ("tests/conftest.py", "def f():\n    import anthropic\n", "tests/conftest.py:2"),
    ("tools/run.sh", "#!/bin/sh\npython3 -c 'import anthropic'\n", "tools/run.sh:2"),
    ("raqib/broken.py", "def (:\n", "raqib/broken.py:1: cannot be parsed"),
], ids=["import", "from-import", "import-list", "import-module", "dunder-import", "tests-too",
        "shell", "unparseable"])
def test_anthropic_outside_the_backend_is_red(tmp_path, rel, text, where):
    code, out = gate(tmp_path, {rel: text})
    assert code == 1, out
    assert "RED: anthropic imported outside raqib/suspect/backends.py" in out
    assert "[gate]   " + where in out
    assert "[gate] GREEN" not in out


def test_the_backend_and_mere_mentions_are_green(tmp_path):
    code, out = gate(tmp_path, {
        "raqib/doc.py": '"""We never import anthropic here."""\n# import anthropic\n'
                        'import anthropic_tools\nfrom .anthropic import x\nNAME = "anthropic"\n',
        "README.md": "pip install anthropic, then `import anthropic`.\n",
        "tools/note.sh": "#!/bin/sh\necho anthropic\n",
    })
    assert code == 0, out
    assert "anthropic SDK imported only by raqib/suspect/backends.py" in out and "[gate] GREEN" in out


# --- M5.1 E4: the other checks, ported from gate.sh -------------------------

@pytest.mark.parametrize("files, handoff, red", [
    ({"docs/a.md": "key " + AWS_KEY + "\n"}, "# H\n", "RED: secret-like string in tree"),
    ({"data.bin": b"\0\0" + AWS_KEY.encode()}, "# H\n", "RED: secret-like string in tree"),
    ({"docs/a.md": "see " + LEAK + "\n"}, "# H\n", "RED: reference to a private tree"),
    ({}, "x\n" * 31, "RED: HANDOFF.md > 30 lines"),
    ({"tests/test_ok.py": "def test_ok():\n    assert False\n"}, "# H\n", None),
], ids=["secret", "secret-in-binary", "private-tree", "handoff-31-lines", "failing-test"])
def test_m51_e4_each_check_turns_the_gate_red(tmp_path, files, handoff, red):
    code, out = gate(tmp_path, files, handoff=handoff)
    assert code == 1, out
    assert (red is None or "[gate] " + red in out) and "[gate] GREEN" not in out


@pytest.mark.parametrize("files, handoff", [
    ({"docs/CONSTITUTION.md": "not " + LEAK + "\n"}, "# H\n"),
    ({"data.bin": b"\0\0" + LEAK.encode()}, "# H\n"),
    ({"docs/a.md": "AK" + "IA lower case: akia" + "q" * 16 + "\n"}, "x\n" * 30),
], ids=["constitution-may-name-it", "binary-file-is-not-leak-checked", "near-miss-and-30-lines"])
def test_m51_e4_the_same_checks_stay_green_on_near_misses(tmp_path, files, handoff):
    code, out = gate(tmp_path, files, handoff=handoff)
    assert code == 0, out
    assert out.rstrip().endswith("[gate] GREEN")


def test_m51_e4_an_untracked_file_is_not_scanned_and_git_must_work(tmp_path):
    code, out = gate(tmp_path, {})
    assert code == 0, out
    (tmp_path / "repo" / "untracked.md").write_text("key " + AWS_KEY + "\n")
    proc = subprocess.run([sys.executable, str(tmp_path / "repo" / "tools" / "gate.py")],
                          capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stdout
    # git that cannot find the repository: red, not a scan of nothing.
    proc = subprocess.run([sys.executable, str(tmp_path / "repo" / "tools" / "gate.py")],
                          capture_output=True, text=True, timeout=120,
                          env=dict(os.environ, GIT_DIR=str(tmp_path / "not-a-repo")))
    assert proc.returncode == 1 and "[gate] RED: cannot list tracked files" in proc.stdout


@pytest.mark.skipif(os.name == "nt", reason="gate.sh is the POSIX entry point")
def test_m51_e4_gate_sh_calls_gate_py(tmp_path):
    lines = GATE_SH.read_text().splitlines()
    assert lines[-1] == 'exec python3 -I "$(dirname "$0")/gate.py" "$@"'
    code, out = gate(tmp_path, {"raqib/other.py": "import anthropic\n"}, via="sh")
    assert code == 1 and "[gate]   raqib/other.py:1" in out
    shutil.rmtree(tmp_path / "repo")
    code, out = gate(tmp_path, {}, via="sh")
    assert code == 0 and out.rstrip().endswith("[gate] GREEN")


# --- M5.1 REDO 2: the leak pattern per alternative (F14); A3 (F15) ----------

def gate_module():
    spec = importlib.util.spec_from_file_location("raqib_gate_under_test", GATE_PY)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# One list of examples per alternative of gate.LEAK, in the pattern's order.
# They are built from pieces, so this file never matches the pattern itself.
LEAK_EXAMPLES = [
    ["haris" + sep + "backup" for sep in ("", "-", "_")],
    ["D:" + "\\" * n + "haris" for n in (1, 2, 4)],
    ["fal" + "ak.git"],
]
LEAK_NEAR_MISSES = ["haris" + "~backup", "D:" + "haris", "D:" + "/haris", "fal" + "ak-git", "D" + "\\" + "haris"]


def test_m51_f14_every_alternative_of_the_leak_pattern_has_examples():
    alternatives = gate_module().LEAK.pattern.split("|")
    assert len(alternatives) == len(LEAK_EXAMPLES)
    for alternative, examples in zip(alternatives, LEAK_EXAMPLES):
        for example in examples:
            assert re.fullmatch(alternative, example), (alternative, example)
    for miss in LEAK_NEAR_MISSES:
        assert not gate_module().LEAK.search(miss), miss


@pytest.mark.parametrize("n", range(len(LEAK_EXAMPLES)), ids=["backup", "drive-path", "repo"])
def test_m51_f14_each_leak_alternative_turns_the_gate_red(tmp_path, n):
    text = "".join("see %s\n" % e for e in LEAK_EXAMPLES[n])
    code, out = gate(tmp_path, {"docs/a.md": text})
    assert code == 1 and "[gate] RED: reference to a private tree" in out, out


def test_m51_f14_near_misses_stay_green(tmp_path):
    code, out = gate(tmp_path, {"docs/a.md": "".join("see %s\n" % m for m in LEAK_NEAR_MISSES)})
    assert code == 0, out


@pytest.mark.parametrize("case", ["nothing-tracked", "no-tests-dir", "no-test-files"])
def test_m51_f15_a_gate_that_would_read_nothing_is_red(tmp_path, case):
    if case == "nothing-tracked":
        code, out = gate(tmp_path, {}, add=False)
        red = "git ls-files listed no files"
    else:
        files = {} if case == "no-tests-dir" else {"tests/helper.py": "X = 1\n"}
        code, out = gate(tmp_path, files, base=SCRATCH_BASE)
        red = "no tests: tests/ is missing or holds no test_*.py"
    assert code == 1 and "[gate] RED: " + red in out, out
    assert "[gate] GREEN" not in out


# --- M4.1 E4: rule kinds (ADR-0002) -----------------------------------------

def real_text(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def without(rel, *starts):
    """The real file at rel without its lines that start with one of starts."""
    return "".join(line for line in real_text(rel).splitlines(True) if not line.startswith(starts))


def kinds_line(out):
    lines = [line for line in out.splitlines() if "rule kinds" in line]
    assert len(lines) == 1, out
    return lines[0]


def test_m41_e4_the_gate_prints_one_kinds_line_and_stays_green(tmp_path):
    code, out = gate(tmp_path, {})
    assert code == 0, out
    assert kinds_line(out) == "[gate] rule kinds: signature=4 demand=4 anchor=3"
    order = [line for line in out.splitlines() if line.startswith("[gate] ") and not line.startswith("[gate]  ")]
    assert order.index(kinds_line(out)) == order.index("[gate] tests") - 1     # after the scans, before the tests
    assert out.rstrip().endswith("[gate] GREEN")


CATALOG_REL = "raqib/rules/catalog/"
SILENCE_REL = "raqib/rules/silence.py"


@pytest.mark.parametrize("files, red", [
    ({CATALOG_REL + "NET-TOOL.yaml": without(CATALOG_REL + "NET-TOOL.yaml", "kind:")},
     "rule NET-TOOL: kind: missing"),
    ({CATALOG_REL + "SCOPE-CWD-ROOT.yaml": real_text(CATALOG_REL + "SCOPE-CWD-ROOT.yaml").replace(
        "kind: anchor\n", "kind: heuristic\n")},
     "rule SCOPE-CWD-ROOT: kind: must be one of signature|demand|anchor"),
    ({CATALOG_REL + "SECRET-OUTPUT.yaml": without(CATALOG_REL + "SECRET-OUTPUT.yaml", "evasion:", '  - "')},
     "rule SECRET-OUTPUT: evasion: missing"),
    ({CATALOG_REL + "DRIFT-FILES.yaml": real_text(CATALOG_REL + "DRIFT-FILES.yaml").replace(
        "kind: anchor\n", "kind: anchor\nevasion: [writes through Bash]\n")},
     "rule DRIFT-FILES: evasion: only a signature lists evasions"),
    ({SILENCE_REL: real_text(SILENCE_REL).replace('"SILENCE-HALF": "demand"', '"SILENCE-HALF": None')},
     "RED: rule kinds: no kind (one of signature|demand|anchor) for SILENCE-HALF"),
    ({SILENCE_REL: real_text(SILENCE_REL).replace("RULE_KINDS = {", "OTHER_NAME = {")},
     "RED: rule kinds: raqib/rules/silence.py declares no RULE_KINDS"),
    ({rel: None for rel in RULE_FILES if rel.startswith(CATALOG_REL)},
     "RED: rule kinds: the catalog does not load: "),
    ({rel: None for rel in RULE_FILES},
     "RED: rule kinds: cannot import raqib.rules from this checkout"),
], ids=["kind-missing", "kind-unknown", "signature-without-evasion", "evasion-on-an-anchor",
        "silence-rule-without-kind", "silence-declares-nothing", "no-catalog", "no-rules-in-the-checkout"])
def test_m41_e4_a_rule_without_a_kind_turns_the_gate_red(tmp_path, files, red):
    code, out = gate(tmp_path, files)
    assert code == 1, out
    assert red in out and "[gate] RED: rule kinds: " in out, out
    assert "rule kinds: signature=" not in out and "[gate] GREEN" not in out


def test_m41_e4_the_gate_counts_the_real_tree(monkeypatch):
    monkeypatch.setattr(sys, "path", [str(ROOT)] + sys.path)
    from raqib.rules import engine, silence
    module = gate_module()
    assert module.KINDS == engine.KINDS == ("signature", "demand", "anchor")
    rules = engine.load_catalog(ROOT / "raqib" / "rules" / "catalog")
    kinds = [r.kind for r in rules] + list(silence.RULE_KINDS.values())
    expected = "rule kinds: " + " ".join("%s=%d" % (k, kinds.count(k)) for k in engine.KINDS)
    text = io.StringIO()
    with contextlib.redirect_stdout(text):
        module.rule_kinds()
    assert text.getvalue() == "[gate] %s\n" % expected


def test_m41_e4_rules_imported_from_elsewhere_are_red(tmp_path, monkeypatch):
    """The gate reads the rules of the checkout it gates, never another copy
    (an installed raqib): modules that come from elsewhere are RED."""
    monkeypatch.setattr(sys, "path", [str(ROOT)] + sys.path)
    import raqib.rules.engine  # noqa: F401  (now imported from ROOT)
    (tmp_path / "raqib" / "rules" / "catalog").mkdir(parents=True)
    module = gate_module()
    monkeypatch.setattr(module, "ROOT", str(tmp_path))
    with pytest.raises(module.Red, match="rule kinds: raqib.rules.engine was imported from .*, not from this checkout"):
        module.rule_kinds()
