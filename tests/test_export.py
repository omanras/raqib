"""Tests for mizan.export and the export command (HANDOFF M2.1, ADR-0001 A6).

A fake adapter covers the success and the missing-package paths without
pySigma; the real-backend test is skipped when pySigma is absent.
"""

import ast
import importlib
import importlib.util
import io
import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from mizan import cli, export, loader  # noqa: E402

RULE = str(ROOT / "rules" / "win_whoami_discovery.yml")
INVALID = str(ROOT / "tests" / "fixtures" / "rules" / "missing_title.yml")


class FakeAdapter:
    version = "9.9.9-fake"

    def __init__(self, target):
        self.target = target
        self.seen = None

    def convert(self, rule_dict):
        self.seen = rule_dict
        return "FAKE[%s] %s" % (self.target, rule_dict["detection"]["condition"])


class FailingAdapter(FakeAdapter):
    def convert(self, rule_dict):
        raise export.ExportError("SigmaFeatureNotSupportedByBackendError: no can do")


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    code = cli.main(list(argv), stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


def pysigma_available(target="splunk"):
    try:
        importlib.import_module("sigma.rule")
        importlib.import_module(export.TARGETS[target]["module"])
    except ImportError:
        return False
    return True


# --- export_rule with a fake adapter ---------------------------------------------------------

def test_export_rule_success_with_fake_adapter():
    rule = loader.load(RULE)
    adapters = []

    def factory(target):
        adapter = FakeAdapter(target)
        adapters.append(adapter)
        return adapter

    result = export.export_rule(rule, "splunk", adapter_factory=factory)
    assert result == {"target": "splunk", "query": "FAKE[splunk] selection and not filter_system",
                      "backend_version": "9.9.9-fake"}
    assert set(result) == {"target", "query", "backend_version"}
    assert "x-mizan" not in adapters[0].seen
    assert adapters[0].seen["title"] == rule.title
    assert adapters[0].seen["detection"] == rule.detection


def test_sigma_mapping_strips_only_mizan_keys():
    rule = loader.load(RULE)
    mapping = export.sigma_mapping(rule)
    assert "x-mizan" in rule.raw and "x-mizan" not in mapping
    assert set(mapping) == set(rule.raw) - {"x-mizan"}


def test_export_rule_errors():
    rule = loader.load(RULE)
    with pytest.raises(export.UnknownTarget):
        export.export_rule(rule, "kusto", adapter_factory=FakeAdapter)
    with pytest.raises(export.ExportError) as info:
        export.export_rule(loader.load(INVALID), "splunk", adapter_factory=FakeAdapter)
    assert "rule is invalid" in str(info.value) and "title" in str(info.value)
    with pytest.raises(export.ExportError):
        export.export_rule(None, "splunk", adapter_factory=FakeAdapter)
    with pytest.raises(export.ExportError) as info:
        export.export_rule(rule, "elastic", adapter_factory=FailingAdapter)
    assert "no can do" in str(info.value)


def test_export_rule_never_imports_pysigma_with_an_injected_adapter(monkeypatch):
    calls = []
    monkeypatch.setattr(export, "_import_module", lambda name: calls.append(name) or (_ for _ in ()).throw(ImportError(name)))
    export.export_rule(loader.load(RULE), "splunk", adapter_factory=FakeAdapter)
    assert calls == []


# --- missing packages ------------------------------------------------------------------------

def _absent(*prefixes):
    real = importlib.import_module

    def fake_import(name):
        if any(name == p or name.startswith(p + ".") for p in prefixes):
            raise ImportError("No module named %r" % name)
        return real(name)
    return fake_import


def test_missing_pysigma_names_the_pip_line(monkeypatch):
    monkeypatch.setattr(export, "_import_module", _absent("sigma"))
    with pytest.raises(export.MissingDependency) as info:
        export.load_adapter("splunk")
    assert info.value.pip == "pip install pysigma pysigma-backend-splunk"
    assert "export to splunk needs pySigma" in str(info.value)
    with pytest.raises(export.MissingDependency) as info:
        export.load_adapter("elastic")
    assert info.value.pip == "pip install pysigma pysigma-backend-elasticsearch"


def test_missing_backend_only_names_the_backend(monkeypatch):
    if not pysigma_available():
        pytest.skip("pySigma core not installed; the full-absence path is tested above")
    monkeypatch.setattr(export, "_import_module", _absent("sigma.backends.splunk"))
    with pytest.raises(export.MissingDependency) as info:
        export.load_adapter("splunk")
    assert info.value.pip == "pip install pysigma-backend-splunk"


def test_cli_missing_package_is_exit_3_one_line_no_traceback(monkeypatch):
    monkeypatch.setattr(export, "_import_module", _absent("sigma"))
    code, out, err = run("export", RULE, "--target", "splunk")
    assert code == 3 and out == ""
    assert err == "mizan: export to splunk needs pySigma: pip install pysigma pysigma-backend-splunk\n"
    assert "Traceback" not in err
    code, out, err = run("export", RULE, "--target", "elastic", "--json")
    assert code == 3 and out == "" and err.endswith("pip install pysigma pysigma-backend-elasticsearch\n")


# --- the export command with a fake adapter -------------------------------------------------

def test_cli_export_text_and_json(monkeypatch):
    monkeypatch.setattr(export, "load_adapter", FakeAdapter)
    code, out, err = run("export", RULE, "--target", "splunk")
    assert code == 0 and err == ""
    assert out == "FAKE[splunk] selection and not filter_system\n"
    code, out, err = run("export", RULE, "--target", "elastic", "--json")
    assert code == 0 and err == ""
    assert json.loads(out) == {"target": "elastic", "query": "FAKE[elastic] selection and not filter_system",
                               "backend_version": "9.9.9-fake"}


def test_cli_export_errors(monkeypatch):
    monkeypatch.setattr(export, "load_adapter", FakeAdapter)
    code, out, err = run("export", RULE, "--target", "kusto")
    assert code == 2 and "invalid choice" in err
    code, out, err = run("export", RULE)
    assert code == 2 and "--target" in err
    code, out, err = run("export", INVALID, "--target", "splunk")
    assert code == 1 and out == "" and "export failed: rule is invalid" in err and "title" in err
    code, out, err = run("export", str(ROOT / "nope.yml"), "--target", "splunk")
    assert code == 3 and "not a file" in err
    monkeypatch.setattr(export, "load_adapter", FailingAdapter)
    code, out, err = run("export", RULE, "--target", "splunk")
    assert code == 1 and out == "" and err == "mizan: export failed: SigmaFeatureNotSupportedByBackendError: no can do\n"


# --- A6: pySigma stays inside export.py and is imported lazily ----------------------------------

def test_only_export_py_imports_sigma_and_only_lazily():
    for path in sorted((ROOT / "mizan").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="ascii"), str(path))
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for name in names:
                assert name.split(".")[0] != "sigma", "%s:%d imports pySigma at module level" % (path.name, node.lineno)
    # export.py reaches pySigma only through _import_module, inside load_adapter
    source = (ROOT / "mizan" / "export.py").read_text(encoding="ascii")
    assert "_import_module(\"sigma.rule\")" in source


def test_importing_the_cli_does_not_import_pysigma():
    """The engine commands must work without pySigma; importing mizan.cli
    (which imports mizan.export) must not pull sigma in."""
    before = {m for m in sys.modules if m == "sigma" or m.startswith("sigma.")}
    importlib.reload(export)
    importlib.reload(cli)
    after = {m for m in sys.modules if m == "sigma" or m.startswith("sigma.")}
    assert after == before  # nothing new was imported by the reload


# --- the real backend (skipped without pySigma) --------------------------------------------------

@pytest.mark.parametrize("target", ["splunk", "elastic"])
def test_real_backend_converts_the_example_rule(target):
    if not pysigma_available(target):
        pytest.skip("pySigma backend for %s not installed" % target)
    code, out, err = run("export", RULE, "--target", target, "--json")
    assert code == 0, err
    document = json.loads(out)
    assert document["target"] == target
    assert "whoami.exe" in document["query"]
    assert "AUTHORITY" in document["query"]  # Lucene escapes the space: NT\ AUTHORITY
    assert document["backend_version"] not in ("", None)
    code, out, err = run("export", RULE, "--target", target)
    assert code == 0 and out.strip() == document["query"].strip()


def test_real_backend_exports_every_example_rule():
    if not (pysigma_available("splunk") and pysigma_available("elastic")):
        pytest.skip("pySigma backends not installed")
    for path in sorted((ROOT / "rules").glob("*.yml")):
        for target in ("splunk", "elastic"):
            code, out, err = run("export", str(path), "--target", target)
            assert code == 0 and out.strip(), (path.name, target, err)
