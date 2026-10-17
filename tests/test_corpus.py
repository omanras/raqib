"""Tests for mizan.corpus (HANDOFF M1.2, ADR-0001 section 7)."""

import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from mizan import corpus as corpus_module, loader, report  # noqa: E402
from mizan.corpus import Corpus, CorpusFile, compatible, measure, select  # noqa: E402

FIX = ROOT / "tests" / "fixtures"
CORPUS_OK = str(FIX / "corpus_ok")
CORPUS_BAD = str(FIX / "corpus_bad")
RULESET = FIX / "ruleset"


def rule(name):
    return loader.load(str(RULESET / name))


def reasons(result):
    return [c.reason for c in result.citations]


# --- E1: corpus files ------------------------------------------------------------------------

def test_corpus_file_header_and_events():
    corpus_file = CorpusFile(os.path.join(CORPUS_OK, "windows-process_creation.jsonl"))
    assert corpus_file.usable and corpus_file.problem is None
    assert corpus_file.logsource == {"product": "windows", "category": "process_creation"}
    assert len(corpus_file.events) == 50
    assert corpus_file.events[0][0] == 2  # physical line numbers; the header is line 1
    assert corpus_file.events[-1][0] == 51
    assert corpus_file.bad_lines == [] and corpus_file.blank == 0
    assert corpus_file.as_dict()["events"] == 50


def test_corpus_file_header_tolerates_extra_keys_inside_mizan():
    corpus_file = CorpusFile(os.path.join(CORPUS_OK, "windows-process_creation.jsonl"))
    assert corpus_file.usable  # the header carries "generator": "tests" inside _mizan


def test_corpus_bad_files_are_named():
    corpus = Corpus(CORPUS_BAD)
    problems = {name: f.problem for name, f in corpus.files.items()}
    assert problems["empty.jsonl"] == "empty: no header line"
    assert problems["header_only.jsonl"] == "empty: no event after the header"
    assert "header must be exactly" in problems["no_header.jsonl"]
    assert "header must be exactly" in problems["extra_key_header.jsonl"]
    assert "non-empty mapping" in problems["bad_header.jsonl"]
    assert "not a JSON object" in problems["not_object_header.jsonl"]
    assert problems["malformed_line.jsonl"] is None
    assert corpus.files["malformed_line.jsonl"].bad_lines[0][0] == 4
    assert len(corpus.files["malformed_line.jsonl"].events) == 3
    assert problems["blank_first.jsonl"] is None
    assert corpus.files["blank_first.jsonl"].blank == 2
    assert len(corpus.files["blank_first.jsonl"].events) == 2
    assert not corpus.complete
    assert {f.name for f in corpus.broken} == {
        "empty.jsonl", "header_only.jsonl", "no_header.jsonl", "extra_key_header.jsonl",
        "bad_header.jsonl", "not_object_header.jsonl"}


def test_corpus_directory_problems(tmp_path):
    corpus = Corpus(str(tmp_path / "nope"))
    assert corpus.problem == "missing" and corpus.files == {} and not corpus.complete
    file_path = tmp_path / "file.jsonl"
    file_path.write_text("x")
    assert Corpus(str(file_path)).problem == "not a directory"
    empty = tmp_path / "empty"
    empty.mkdir()
    corpus = Corpus(str(empty))
    assert corpus.problem is None and corpus.files == {} and corpus.complete


def test_corpus_ignores_non_jsonl_and_subdirectories():
    corpus = Corpus(CORPUS_OK)
    assert sorted(corpus.files) == ["linux-auth.jsonl", "windows-process_creation.jsonl"]
    assert corpus.complete


def test_header_validation():
    ok, problem = corpus_module._parse_header({"_mizan": {"logsource": {"product": "x"}}})
    assert ok == {"product": "x"} and problem is None
    for bad in ({"_mizan": {}}, {"_mizan": {"logsource": {"definition": "only"}}},
                {"_mizan": {"logsource": {"product": 1}}}, {"_mizan": {"logsource": {"product": " "}}},
                {"_mizan": "x"}, {"other": 1}, [], None):
        assert corpus_module._parse_header(bad)[1] is not None, bad


# --- E2: selection -----------------------------------------------------------------------------

def test_compatible_logsource():
    assert compatible({"product": "windows"}, {"product": "windows", "category": "process_creation"})
    assert compatible({"product": "windows", "category": "process_creation"},
                      {"product": "windows", "category": "process_creation"})
    assert not compatible({"product": "windows", "category": "ps_script"},
                          {"product": "windows", "category": "process_creation"})
    assert not compatible({"product": "windows", "service": "security"}, {"product": "windows"})
    assert not compatible({"category": "webserver"}, {"product": "linux", "service": "auth"})
    assert compatible({"category": "webserver", "definition": "ignored"}, {"category": "webserver"})


def test_select_by_logsource_and_by_name():
    corpus = Corpus(CORPUS_OK)
    files, by, citations = select(rule("r1_within_budget.yml"), corpus)
    assert by == "logsource" and [f.name for f in files] == ["windows-process_creation.jsonl"]
    assert citations == []
    files, by, citations = select(rule("r4_named_corpus.yml"), corpus)
    assert by == "x-mizan.corpus" and [f.name for f in files] == ["linux-auth.jsonl"]
    files, by, citations = select(rule("r5_named_missing.yml"), corpus)
    assert files == [] and citations[0][2] == "missing (named in x-mizan.corpus)"
    files, by, citations = select(rule("r3_no_corpus.yml"), corpus)
    assert files == [] and citations == []


def test_select_refuses_paths_in_named_corpus(tmp_path):
    src = (RULESET / "r4_named_corpus.yml").read_text().replace("linux-auth.jsonl", "../linux-auth.jsonl")
    (tmp_path / "r.yml").write_text(src)
    loaded = loader.load(str(tmp_path / "r.yml"))
    files, _, citations = select(loaded, Corpus(CORPUS_OK))
    assert files == [] and "plain file names" in citations[0][2]
    result = measure(loaded, Corpus(CORPUS_OK))
    assert result.status == "no_corpus"


def test_select_with_broken_files_cites_them_for_logsource_rules():
    corpus = Corpus(CORPUS_BAD)
    files, by, citations = select(rule("r1_within_budget.yml"), corpus)
    assert by == "logsource"
    assert sorted(f.name for f in files) == ["blank_first.jsonl", "malformed_line.jsonl"]
    assert len(citations) == 6  # every broken file, because it may belong to this rule
    files, by, citations = select(rule("r4_named_corpus.yml"), corpus)
    assert by == "x-mizan.corpus" and citations[0][2] == "missing (named in x-mizan.corpus)"


# --- E3: measure -----------------------------------------------------------------------------------

def test_measure_within_budget_cites_each_match():
    result = measure(rule("r1_within_budget.yml"), Corpus(CORPUS_OK))
    assert result.status == "pass" and result.green
    details = result.details["corpus"]
    assert details["events"] == 50 and details["matches"] == 1
    assert details["fp_per_10k"] == 200.0 and details["budget"] == 250.0
    assert details["selected_by"] == "logsource"
    assert [(os.path.basename(c.file), c.line, c.reason) for c in result.citations] == [
        ("windows-process_creation.jsonl", 22, "match")]
    assert corpus_module.summary_line(result) == "fp/10k=200 budget=250 events=50"


def test_measure_over_budget():
    result = measure(rule("r2_over_budget.yml"), Corpus(CORPUS_OK))
    assert result.status == "over_budget" and not result.green
    assert result.details["corpus"]["fp_per_10k"] == 200.0
    assert reasons(result) == ["match"]


def test_measure_budget_boundary_is_inclusive(tmp_path):
    src = (RULESET / "r2_over_budget.yml").read_text().replace("fp_budget: 100", "fp_budget: 200")
    (tmp_path / "r.yml").write_text(src)
    result = measure(loader.load(str(tmp_path / "r.yml")), Corpus(CORPUS_OK))
    assert result.status == "pass"
    src = src.replace("fp_budget: 200", "fp_budget: 199.99")
    (tmp_path / "r.yml").write_text(src)
    assert measure(loader.load(str(tmp_path / "r.yml")), Corpus(CORPUS_OK)).status == "over_budget"


def test_measure_zero_budget_zero_matches():
    result = measure(rule(os.path.join("sub", "r6_zero_fp.yml")), Corpus(CORPUS_OK))
    assert result.status == "pass"
    assert result.details["corpus"]["fp_per_10k"] == 0.0 and result.citations == []


def test_measure_no_corpus():
    result = measure(rule("r3_no_corpus.yml"), Corpus(CORPUS_OK))
    assert result.status == "no_corpus"
    assert reasons(result) == ["no compatible corpus for logsource {product=macos, category=process_creation}"]
    assert result.details["corpus"]["fp_per_10k"] is None
    assert corpus_module.summary_line(result) == "fp/10k=- budget=1 events=0"


def test_measure_named_corpus_and_named_missing():
    result = measure(rule("r4_named_corpus.yml"), Corpus(CORPUS_OK))
    assert result.status == "pass"
    assert result.details["corpus"]["selected_by"] == "x-mizan.corpus"
    assert [c.line for c in result.citations] == [5, 15, 25, 35]
    assert result.details["corpus"]["fp_per_10k"] == 1000.0
    result = measure(rule("r5_named_missing.yml"), Corpus(CORPUS_OK))
    assert result.status == "no_corpus"
    assert any("missing (named in x-mizan.corpus)" in r for r in reasons(result))


def test_measure_unknown_rule_and_invalid_rule():
    result = measure(rule("r8_unknown.yml"), Corpus(CORPUS_OK))
    assert result.status == "unknown"
    assert "base64" in result.citations[0].reason
    assert result.details["corpus"]["events"] == 50  # counted, not judged
    result = measure(rule("invalid.yml"), Corpus(CORPUS_OK))
    assert result.status == "invalid" and result.problems
    assert measure(None, Corpus(CORPUS_OK)).status == "invalid"


def test_measure_on_broken_corpus_is_unknown_citing_files_and_lines():
    result = measure(rule("r1_within_budget.yml"), Corpus(CORPUS_BAD))
    assert result.status == "unknown"
    cited = [(os.path.basename(c.file), c.line) for c in result.citations]
    assert ("malformed_line.jsonl", 4) in cited
    assert ("empty.jsonl", None) in cited and ("no_header.jsonl", None) in cited
    assert result.details["corpus"]["events"] == 5  # blank_first (2) + malformed_line (3)


def test_measure_missing_corpus_directory(tmp_path):
    result = measure(rule("r1_within_budget.yml"), Corpus(str(tmp_path / "none")))
    assert result.status == "no_corpus"
    assert any("corpus directory missing" in r for r in reasons(result))


def test_measure_unknown_line_in_event_is_cited(tmp_path):
    # a corpus event that the matcher cannot judge (not possible with a
    # compiled rule today, but an event that is not an object is)
    directory = tmp_path / "c"
    directory.mkdir()
    (directory / "windows-process_creation.jsonl").write_text(
        '{"_mizan": {"logsource": {"product": "windows", "category": "process_creation"}}}\n'
        '{"Image": "a.exe"}\n[1, 2]\n{"Image": "b.exe"}\n')
    result = measure(rule("r1_within_budget.yml"), Corpus(str(directory)))
    assert result.status == "unknown"
    assert [(c.line, c.reason.split(":")[0]) for c in result.citations] == [(3, "unknown")]


def test_number_formatting():
    assert corpus_module._number(200.0) == "200"
    assert corpus_module._number(0.5) == "0.5"
    assert corpus_module._number(33.33333) == "33.3333"
    assert corpus_module._number(0.0) == "0"
    assert corpus_module._number(1e-9) == "0"


# --- combine (check) --------------------------------------------------------------------------------

def test_combine_precedence_and_citations():
    corpus = Corpus(CORPUS_OK)
    fixtures_mod = __import__("mizan.fixtures", fromlist=["judge"])
    cases = {
        "r1_within_budget.yml": "pass",
        "r2_over_budget.yml": "over_budget",
        "r3_no_corpus.yml": "no_corpus",
        "r7_fixture_fail.yml": "fail",
        "r8_unknown.yml": "unknown",
        "invalid.yml": "invalid",
    }
    for name, expected in cases.items():
        loaded = rule(name)
        combined = report.combine(fixtures_mod.judge(loaded), measure(loaded, corpus))
        assert combined.status == expected, name
    loaded = rule("r8_unknown.yml")
    combined = report.combine(fixtures_mod.judge(loaded), measure(loaded, corpus))
    assert len(combined.citations) == 1  # the rule-level unknown is cited once, not twice
    loaded = rule("r7_fixture_fail.yml")
    combined = report.combine(fixtures_mod.judge(loaded), measure(loaded, corpus))
    assert [c.reason for c in combined.citations] == ["did not match (must match)", "match"]
    assert "fixtures" in combined.details and "corpus" in combined.details


def test_combine_fail_beats_over_budget_and_unknown_beats_fail():
    a = report.Result("fail", "x")
    b = report.Result("over_budget", "x")
    assert report.combine(a, b).status == "fail"
    assert report.combine(report.Result("unknown", "x"), a).status == "unknown"
    assert report.combine(report.Result("pass", "x"), report.Result("no_corpus", "x")).status == "no_corpus"
    assert report.combine(report.Result("pass", "x"), report.Result("pass", "x")).status == "pass"


def test_find_rules_is_recursive_sorted_and_yml_only():
    paths = loader.find_rules(str(RULESET))
    names = [os.path.relpath(p, str(RULESET)) for p in paths]
    assert names == ["invalid.yml", "r1_within_budget.yml", "r2_over_budget.yml", "r3_no_corpus.yml",
                     "r4_named_corpus.yml", "r5_named_missing.yml", "r7_fixture_fail.yml",
                     "r8_unknown.yml", os.path.join("sub", "r6_zero_fp.yml")]
    assert loader.find_rules(str(RULESET / "nope")) == []
    assert loader.find_rules(None) == []
