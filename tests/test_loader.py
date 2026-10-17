"""Tests for mizan.loader (HANDOFF M0.1, ADR-0001 section 3).

One test per fixture in tests/fixtures/rules/, plus the contract tests:
load() returns a Rule or a Problems list and never raises.
"""

import os
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from mizan import loader  # noqa: E402
from mizan.loader import Problem, Problems, Rule  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures" / "rules"


def fx(name):
    return str(FIXTURES / name)


def problems_of(name):
    result = loader.load(fx(name))
    assert isinstance(result, Problems), "expected Problems, got %r" % (result,)
    assert len(result) >= 1
    assert result.path == fx(name)
    for problem in result:
        assert isinstance(problem, Problem)
        assert problem.field and problem.reason
    return result


def fields_of(problems):
    return [p.field for p in problems]


def assert_problem(name, field, reason_part=None):
    problems = problems_of(name)
    matching = [p for p in problems if p.field == field]
    assert matching, "no problem on field %r in %r" % (field, problems)
    if reason_part is not None:
        assert any(reason_part in p.reason for p in matching), \
            "no reason containing %r in %r" % (reason_part, matching)
    return problems


# --- E1: a valid rule ------------------------------------------------------

def test_valid_rule_returns_rule_with_every_attribute():
    rule = loader.load(fx("valid.yml"))
    assert isinstance(rule, Rule)
    assert rule.title == "Suspicious encoded PowerShell command line"
    assert rule.id == "6f1d2c3e-4b5a-4c6d-8e7f-9a0b1c2d3e4f"
    assert rule.logsource == {"product": "windows", "category": "process_creation"}
    assert isinstance(rule.detection, dict)
    assert set(rule.detection) == {"selection", "filter_admin", "condition"}
    assert rule.condition == "selection and not filter_admin"
    assert rule.level == "high"
    assert isinstance(rule.fp_budget, float)
    assert rule.fp_budget == 2.0
    assert rule.corpus is None
    assert rule.raw["status"] == "test"
    assert rule.raw["title"] == rule.title
    assert rule.path == fx("valid.yml")
    assert set(rule.selections) == {"selection", "filter_admin"}
    assert rule.selections["selection"]["Image|endswith"] == "\\\\powershell.exe"


def test_valid_rule_with_corpus_list():
    rule = loader.load(fx("valid_with_corpus.yml"))
    assert isinstance(rule, Rule)
    assert rule.corpus == ["linux-auth.jsonl", "linux-auth-extra.jsonl"]
    assert rule.fp_budget == 0.5
    assert rule.logsource == {"product": "linux", "service": "auth"}
    assert rule.selections == {"keywords": ["Accepted password for root"]}


def test_load_accepts_pathlike():
    rule = loader.load(FIXTURES / "valid.yml")
    assert isinstance(rule, Rule)
    assert rule.path == fx("valid.yml")


def test_load_accepts_relative_path(monkeypatch):
    monkeypatch.chdir(str(ROOT))
    rule = loader.load(os.path.join("tests", "fixtures", "rules", "valid.yml"))
    assert isinstance(rule, Rule)
    assert rule.path == os.path.join("tests", "fixtures", "rules", "valid.yml")


# --- E3: unknown Sigma fields are kept, not problems ------------------------

def test_unknown_top_level_fields_are_kept_in_raw():
    rule = loader.load(fx("unknown_fields.yml"))
    assert isinstance(rule, Rule)
    for key in ("related", "status", "description", "references", "author",
                "date", "modified", "tags", "fields", "falsepositives",
                "custom_vendor_field"):
        assert key in rule.raw, key
    assert rule.raw["custom_vendor_field"] == "anything goes here"
    assert rule.raw["tags"] == ["attack.execution", "attack.t1059.001"]
    assert rule.logsource == {"category": "webserver"}
    assert rule.level == "low"
    assert rule.fp_budget == 10.0


# --- E2: file-level problems -------------------------------------------------

def test_missing_path_is_a_problem_not_an_exception():
    problems = loader.load(fx("does_not_exist.yml"))
    assert isinstance(problems, Problems)
    assert fields_of(problems) == ["path"]
    assert "not a file" in problems[0].reason


def test_directory_is_not_a_file():
    assert_problem("is_a_directory.yml", "path", "not a file")


def test_not_utf8_is_a_problem(tmp_path):
    # Generated here rather than committed: every file in the tree stays
    # ASCII-safe (CLAUDE.md rule 7).
    path = tmp_path / "not_utf8.yml"
    with open(str(path), "wb") as handle:
        handle.write(b"title: \xff\xfe broken bytes\n"
                     b"id: 6f1d2c3e-4b5a-4c6d-8e7f-9a0b1c2d3e4f\n")
    problems = loader.load(str(path))
    assert isinstance(problems, Problems)
    assert fields_of(problems) == ["file"]
    assert "UTF-8" in problems[0].reason


def test_utf8_bom_is_tolerated(tmp_path):
    path = tmp_path / "bom.yml"
    with open(str(path), "wb") as handle:
        handle.write(b"\xef\xbb\xbf" + open(fx("valid.yml"), "rb").read())
    rule = loader.load(str(path))
    assert isinstance(rule, Rule)
    assert rule.title == "Suspicious encoded PowerShell command line"


def test_not_yaml():
    problems = assert_problem("not_yaml.yml", "yaml", "not valid YAML")
    assert len(problems) == 1


def test_not_a_mapping():
    assert_problem("not_a_mapping.yml", "yaml", "not a mapping")


def test_scalar_document_is_not_a_mapping():
    assert_problem("scalar_document.yml", "yaml", "not a mapping")


def test_several_documents():
    assert_problem("several_docs.yml", "yaml", "several YAML documents")


def test_empty_file():
    assert_problem("empty.yml", "yaml", "empty")


def test_duplicate_key_is_refused():
    assert_problem("duplicate_key.yml", "yaml", "duplicate key")


def test_file_over_size_limit(tmp_path):
    big = tmp_path / "big.yml"
    with open(str(big), "wb") as handle:
        handle.write(b"title: x\n")
        handle.write(b"# " + b"a" * loader.MAX_RULE_BYTES + b"\n")
    problems = loader.load(str(big))
    assert isinstance(problems, Problems)
    assert fields_of(problems) == ["file"]
    assert "larger than" in problems[0].reason


def test_unreadable_file(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("root reads everything; permission problem not reproducible")
    path = tmp_path / "secret.yml"
    path.write_text("title: x\n")
    path.chmod(0)
    try:
        problems = loader.load(str(path))
    finally:
        path.chmod(0o600)
    assert isinstance(problems, Problems)
    assert fields_of(problems) == ["path"]


def test_not_a_path_never_raises():
    for bad in (None, 12, 3.5, ["a"], {"b": 1}):
        problems = loader.load(bad)
        assert isinstance(problems, Problems)
        assert fields_of(problems) == ["path"]


def test_byte_path_is_accepted():
    rule = loader.load(os.fsencode(fx("valid.yml")))
    assert isinstance(rule, Rule)


# --- E2: title ------------------------------------------------------------------

def test_missing_title():
    assert fields_of(assert_problem("missing_title.yml", "title", "missing")) == ["title"]


def test_invalid_title():
    assert fields_of(assert_problem("invalid_title.yml", "title", "string")) == ["title"]


def test_blank_title():
    assert fields_of(assert_problem("blank_title.yml", "title", "non-empty")) == ["title"]


# --- E2: id ---------------------------------------------------------------------

def test_missing_id():
    assert fields_of(assert_problem("missing_id.yml", "id", "missing")) == ["id"]


def test_invalid_id():
    assert fields_of(assert_problem("invalid_id.yml", "id", "UUID")) == ["id"]


def test_compact_id_without_hyphens_is_rejected():
    assert fields_of(assert_problem("compact_id.yml", "id", "UUID")) == ["id"]


# --- E2: logsource ------------------------------------------------------------

def test_missing_logsource():
    assert fields_of(assert_problem("missing_logsource.yml", "logsource", "missing")) == ["logsource"]


def test_logsource_not_mapping():
    assert fields_of(assert_problem("logsource_not_mapping.yml", "logsource", "mapping")) == ["logsource"]


def test_logsource_without_product_category_service():
    assert fields_of(assert_problem("logsource_no_keys.yml", "logsource", "at least one")) == ["logsource"]


def test_logsource_value_not_string():
    assert fields_of(assert_problem("logsource_bad_value.yml", "logsource.product", "string")) == ["logsource.product"]


# --- E2: detection and condition -----------------------------------------------

def test_missing_detection():
    assert fields_of(assert_problem("missing_detection.yml", "detection", "missing")) == ["detection"]


def test_detection_not_mapping():
    assert fields_of(assert_problem("detection_not_mapping.yml", "detection", "mapping")) == ["detection"]


def test_missing_condition():
    assert fields_of(assert_problem("missing_condition.yml", "detection.condition", "missing")) == ["detection.condition"]


def test_condition_list_is_not_supported():
    problems = assert_problem("condition_list.yml", "detection.condition", "list of conditions")
    assert fields_of(problems) == ["detection.condition"]


def test_condition_not_string():
    assert fields_of(assert_problem("condition_not_string.yml", "detection.condition", "string")) == ["detection.condition"]


def test_detection_without_search_identifier():
    assert fields_of(assert_problem("detection_no_selection.yml", "detection", "search identifier")) == ["detection"]


def test_detection_identifier_not_string():
    assert fields_of(assert_problem("detection_bad_identifier.yml", "detection", "search identifier")) == ["detection"]


# --- E2: level ------------------------------------------------------------------

def test_missing_level():
    assert fields_of(assert_problem("missing_level.yml", "level", "missing")) == ["level"]


def test_invalid_level():
    problems = assert_problem("invalid_level.yml", "level", "one of")
    assert fields_of(problems) == ["level"]
    for level in loader.LEVELS:
        assert level in problems[0].reason


def test_level_wrong_case_is_rejected():
    assert fields_of(assert_problem("level_wrong_case.yml", "level", "one of")) == ["level"]


# --- E2: x-mizan ----------------------------------------------------------------

def test_missing_xmizan():
    assert fields_of(assert_problem("missing_xmizan.yml", "x-mizan", "missing")) == ["x-mizan"]


def test_xmizan_not_mapping():
    assert fields_of(assert_problem("xmizan_not_mapping.yml", "x-mizan", "mapping")) == ["x-mizan"]


def test_missing_fp_budget():
    assert fields_of(assert_problem("missing_fp_budget.yml", "x-mizan.fp_budget", "missing")) == ["x-mizan.fp_budget"]


def test_negative_fp_budget():
    assert fields_of(assert_problem("negative_fp_budget.yml", "x-mizan.fp_budget", "negative")) == ["x-mizan.fp_budget"]


def test_fp_budget_not_number():
    assert fields_of(assert_problem("fp_budget_not_number.yml", "x-mizan.fp_budget", "number")) == ["x-mizan.fp_budget"]


def test_fp_budget_bool_is_not_a_number():
    assert fields_of(assert_problem("fp_budget_bool.yml", "x-mizan.fp_budget", "number")) == ["x-mizan.fp_budget"]


def test_fp_budget_nan_is_not_a_number():
    assert fields_of(assert_problem("fp_budget_nan.yml", "x-mizan.fp_budget", "number")) == ["x-mizan.fp_budget"]


def test_xmizan_unknown_key():
    assert fields_of(assert_problem("xmizan_unknown_key.yml", "x-mizan.fp_budjet", "unknown key")) == ["x-mizan.fp_budjet"]


def test_corpus_not_list():
    assert fields_of(assert_problem("corpus_not_list.yml", "x-mizan.corpus", "list")) == ["x-mizan.corpus"]


def test_corpus_empty_list():
    assert fields_of(assert_problem("corpus_empty_list.yml", "x-mizan.corpus", "non-empty")) == ["x-mizan.corpus"]


def test_corpus_bad_entry():
    assert fields_of(assert_problem("corpus_bad_entry.yml", "x-mizan.corpus", "list")) == ["x-mizan.corpus"]


# --- problems accumulate ---------------------------------------------------------

def test_every_missing_field_is_named_at_once():
    problems = problems_of("missing_everything.yml")
    assert fields_of(problems) == ["title", "id", "logsource", "detection", "level", "x-mizan"]
    assert all(p.reason.startswith("missing") for p in problems)
    assert problems.as_list() == [p.as_dict() for p in problems]
    assert problems.as_list()[0] == {"field": "title", "reason": "missing"}


# --- every fixture is covered --------------------------------------------------

def test_every_fixture_file_has_a_verdict():
    """Every fixture in tests/fixtures/rules/ is either a Rule or Problems,
    and the valid ones are exactly the three expected."""
    valid = set()
    for name in sorted(os.listdir(str(FIXTURES))):
        result = loader.load(str(FIXTURES / name))
        assert isinstance(result, (Rule, Problems)), name
        if isinstance(result, Rule):
            valid.add(name)
    assert valid == {"valid.yml", "valid_with_corpus.yml", "unknown_fields.yml"}
