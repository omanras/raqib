"""The README's numbers and the threat model's citations against the tree
(review of M3.2, C5): a change to the rules, hooks or eval set that the docs
do not follow fails the gate."""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from raqib import eval as evaluation, report  # noqa: E402
from raqib.rules import engine  # noqa: E402

README = (ROOT / "README.md").read_text(encoding="utf-8")
THREAT = (ROOT / "docs" / "THREAT_MODEL.md").read_text(encoding="utf-8")
CATALOG = ROOT / "raqib" / "rules" / "catalog"
WORDS = {4: "4", 6: "Six", 7: "7", 11: "Eleven"}


def test_readme_counts_the_rules():
    rules = engine.load_catalog(CATALOG)
    table = report.rule_table(rules)
    silence = [r for r in table if r["class"] == "SILENCE" and r["fp_budget"] is None]
    assert "%s rules turn the trace into findings" % WORDS[len(table)] in README
    assert "%d silence rules and\n   %d YAML rules" % (len(silence), len(rules)) in README
    named = {"SILENCE-GAP", "SILENCE-OPEN", "SILENCE-HALF", "SILENCE-ORDER", "SCOPE-PATH",
             "SCOPE-CWD-ROOT", "SCOPE-CWD-MOVED", "NET-TOOL", "DESTRUCT-CMD", "SECRET-OUTPUT",
             "DRIFT-FILES"}
    assert {r["id"] for r in table} == named, "update the README rule table"


def test_readme_counts_the_hooks():
    install = (ROOT / "tools" / "install_hooks.py").read_text(encoding="utf-8")
    events = re.findall(r'^    \("(\w+)", (?:"\*"|None)\),$', install, re.M)
    assert len(events) == 6
    assert "%s Claude Code hooks" % WORDS[len(events)] in README
    assert "adds six hooks" in README


def test_readme_states_the_real_baseline():
    events = evaluation.load_events(ROOT / "tests" / "fixtures" / "eval" / "events.json")
    (row,) = evaluation.evaluate(events, engine.load_catalog(CATALOG))["rows"]
    benign = evaluation.label_counts(events)["benign"]
    assert "On %d labelled events the rules miss %d bad events and flag %d of %d benign" % (
        len(events), row["fn"], row["fp"], benign) in README.replace("\n", " ")
    baseline = (ROOT / "docs" / "review" / "2026-10-16-M2.2-baseline.md").read_text()
    assert "FN %d" % row["fn"] in baseline and "FP %d" % row["fp"] in baseline


def test_threat_model_citations_name_review_files():
    review = {p.name for p in (ROOT / "docs" / "review").glob("*.md")}
    for task in sorted(set(re.findall(r"\b(M\d\.\d)\b", THREAT))):
        assert any(name.startswith("2026-10-16-%s" % task) for name in review), task
