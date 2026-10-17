"""The example rule set gates itself (HANDOFF M1.3, DEVELOPMENT_PLAN phase 1).

E1 ten synthetic rules over three logsources; E2 sidecars with a near
miss; E3 the committed corpora equal the generator's output; E4 ``check``
is green with the budget mechanism exercised and no budget above 50.
"""

import importlib.util
import io
import json
import os
import pathlib
import re
import sys

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from mizan import cli, loader  # noqa: E402

RULES = ROOT / "rules"
CORPUS = ROOT / "corpus"
GENERATOR = ROOT / "tools" / "make_corpus.py"
EXPECTED_LOGSOURCES = {
    ("windows", "process_creation", None): 4,
    ("linux", None, "auth"): 3,
    (None, "webserver", None): 3,
}
MAX_BUDGET = 50
MIN_EVENTS = 1000


def rule_paths():
    return sorted(str(p) for p in RULES.glob("*.yml"))


def jsonl(path):
    with open(str(path), "rb") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def load_generator():
    spec = importlib.util.spec_from_file_location("make_corpus", str(GENERATOR))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    code = cli.main(list(argv), stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


# --- E1 ---------------------------------------------------------------------------------------------

def test_ten_valid_rules_over_three_logsources():
    paths = rule_paths()
    assert len(paths) == 10
    seen = {}
    ids = set()
    for path in paths:
        rule = loader.load(path)
        assert isinstance(rule, loader.Rule), (path, rule)
        key = (rule.logsource.get("product"), rule.logsource.get("category"), rule.logsource.get("service"))
        seen[key] = seen.get(key, 0) + 1
        assert rule.id not in ids, "duplicate id %s" % rule.id
        ids.add(rule.id)
        assert rule.fp_budget >= 0
        assert rule.raw.get("status") and rule.raw.get("description") and rule.raw.get("tags")
    assert seen == EXPECTED_LOGSOURCES


def test_rules_are_synthetic():
    """No real host or user names and only documentation IP ranges."""
    ip_re = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
    allowed_prefixes = ("192.0.2.", "198.51.100.", "203.0.113.", "127.0.0.")
    for path in list(RULES.glob("*")) + list(CORPUS.glob("*.jsonl")):
        text = path.read_text(encoding="ascii")
        for match in ip_re.finditer(text):
            ip = match.group(0)
            assert ip.startswith(allowed_prefixes), (path.name, ip)
        for forbidden in ("corp.local", ".internal", "contoso", "acme.com", "@gmail", "@outlook"):
            assert forbidden not in text.lower(), (path.name, forbidden)


def test_sigma_shape_of_every_rule():
    for path in rule_paths():
        with open(path, encoding="ascii") as handle:
            raw = yaml.safe_load(handle)
        for key in ("title", "id", "status", "description", "author", "date", "tags", "logsource",
                    "detection", "falsepositives", "level", "x-mizan"):
            assert key in raw, (path, key)
        assert raw["x-mizan"]["fp_budget"] <= MAX_BUDGET


# --- E2 ---------------------------------------------------------------------------------------------

def test_every_rule_has_sidecars_with_a_near_miss():
    for path in rule_paths():
        stem = path[:-4]
        positive = jsonl(stem + ".positive.jsonl")
        negative = jsonl(stem + ".negative.jsonl")
        assert len(positive) >= 2, path
        assert len(negative) >= 2, path
        near_misses = [
            (i, j) for i, pos in enumerate(positive) for j, neg in enumerate(negative)
            if set(pos) == set(neg) and sum(1 for k in pos if pos[k] != neg[k]) == 1
        ]
        assert near_misses, "no near miss (one field differs) for %s" % path


# --- E3 ---------------------------------------------------------------------------------------------

def test_committed_corpora_equal_the_generator_output(tmp_path):
    generator = load_generator()
    paths = generator.generate(str(tmp_path))
    assert [os.path.basename(p) for p in paths] == [
        "windows-process_creation.jsonl", "linux-auth.jsonl", "webserver.jsonl"]
    for generated in paths:
        committed = CORPUS / os.path.basename(generated)
        assert committed.exists(), committed
        assert committed.read_bytes() == pathlib.Path(generated).read_bytes(), \
            "%s differs from tools/make_corpus.py output; regenerate and commit" % committed.name


def test_corpora_have_at_least_1000_benign_events_and_a_header():
    for name in ("windows-process_creation.jsonl", "linux-auth.jsonl", "webserver.jsonl"):
        lines = jsonl(CORPUS / name)
        header, events = lines[0], lines[1:]
        assert set(header) == {"_mizan"}
        assert header["_mizan"]["generator"] == "tools/make_corpus.py"
        assert header["_mizan"]["seed"] == load_generator().SEED
        assert len(events) >= MIN_EVENTS
        assert header["_mizan"]["events"] == len(events)
        assert all("_mizan" not in event for event in events)


def test_generator_is_deterministic(tmp_path):
    generator = load_generator()
    first = generator.generate(str(tmp_path / "a"))
    second = generator.generate(str(tmp_path / "b"))
    for a, b in zip(first, second):
        assert pathlib.Path(a).read_bytes() == pathlib.Path(b).read_bytes()


def test_generator_command_line(tmp_path, capsys):
    generator = load_generator()
    assert generator.main(["--out", str(tmp_path / "out")]) == 0
    printed = capsys.readouterr().out.splitlines()
    assert len(printed) == 3 and all(p.endswith(".jsonl") for p in printed)


# --- E4 ---------------------------------------------------------------------------------------------

def test_check_is_green_and_the_budget_is_exercised(monkeypatch):
    monkeypatch.chdir(str(ROOT))
    code, out, err = run("check", "rules/", "--corpus", "corpus/", "--json")
    assert code == 0, err + out
    document = json.loads(out)
    assert document["green"] is True
    assert len(document["rules"]) == 10
    non_zero = 0
    for result in document["rules"]:
        assert result["status"] == "pass", result
        corpus = result["corpus"]
        assert corpus["events"] >= MIN_EVENTS
        assert corpus["budget"] <= MAX_BUDGET
        assert corpus["fp_per_10k"] <= corpus["budget"]
        if corpus["fp_per_10k"] > 0:
            non_zero += 1
            assert corpus["matches"] >= 1
            # every corpus match is cited (A5)
            cited = [c for c in result["citations"] if c["reason"] == "match"]
            assert len(cited) == corpus["matches"]
        for side in ("positive", "negative"):
            assert result["fixtures"][side]["events"] >= 2
            assert result["fixtures"][side]["wrong"] == []
    assert non_zero >= 2


def test_check_text_output_with_defaults(monkeypatch):
    monkeypatch.chdir(str(ROOT))
    code, out, err = run("check")
    assert code == 0 and err == ""
    heads = [line for line in out.splitlines() if not line.startswith("  ")]
    assert len(heads) == 10 and all(h.startswith("pass ") for h in heads)
    assert "fp/10k=0 budget=0 events=1000" in out


def test_each_rule_passes_its_own_fixtures(monkeypatch):
    monkeypatch.chdir(str(ROOT))
    for path in rule_paths():
        code, out, _ = run("test", os.path.relpath(path, str(ROOT)))
        assert code == 0 and out.startswith("pass "), path


@pytest.mark.parametrize("feature", ["|windash", "|cidr", "|re|i", "|contains|all", "1 of selection_*",
                                     "all of selection_*", "and not filter_"])
def test_example_set_exercises_the_engine(feature):
    """The self-gate covers the supported Sigma subset, not just equality."""
    text = "\n".join(pathlib.Path(p).read_text(encoding="ascii") for p in rule_paths())
    assert feature in text
