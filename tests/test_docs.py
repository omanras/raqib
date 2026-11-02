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
    install = (ROOT / "raqib" / "install.py").read_text(encoding="utf-8")  # M6.3: the installer's home
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


def section(title):
    return README.split("## %s\n" % title, 1)[1].split("\n## ", 1)[0]


def test_m63_e3_first_screen_is_install_and_watch():
    """M6.3 E3: the first screen is the install and `raqib watch`; the rest
    is below; the old quickstart is kept as manual steps; no stale branch."""
    headings = re.findall(r"^## (.+)$", README, re.M)
    assert headings[:3] == ["Install and watch", "Watch a project", "Doctor"]
    first_screen = README.split("\n## Doctor\n", 1)[0]
    assert len(first_screen.splitlines()) <= 25
    block = section("Install and watch").split("```bash\n", 1)[1].split("```", 1)[0].splitlines()
    assert [line.split("#")[0].strip() for line in block] == [
        "git clone https://github.com/omanras/raqib ~/raqib", "pipx install ~/raqib",
        "raqib doctor ~/my-project", "raqib watch ~/my-project"]
    assert "pip install ~/raqib" in block[1] and "Python %d.%d or newer" % (3, 11) in section("Install and watch")
    assert "raqib watch /path/to/project` installs the hooks" in section("Watch a project")
    manual = section("Manual steps")
    for step in ("~/raqib/tools/gate.sh", "~/raqib/tools/install-hooks.sh /path/to/project",
                 "python3 -m raqib report /path/to/project/raqib.log.jsonl --scope ."):
        assert step in manual, step
    assert "claude/v0.1" not in README and "--branch" not in README
    assert headings.index("Manual steps") > headings.index("How it works")


def test_m63_e3_readme_commands_are_the_installed_ones():
    commands = section("Commands")
    rows = [line for line in commands.splitlines() if line.startswith("| `")]
    assert rows and all(line.startswith("| `raqib ") for line in rows)
    for name in ("watch", "doctor", "report", "rules", "ui", "check-rules", "suspect", "eval"):
        assert any(line.startswith("| `raqib %s" % name) for line in rows), name
    assert "--fixtures-root" in commands and "`python3 -m raqib COMMAND`" in commands
    doctor = " ".join(section("Doctor").split())
    for phrase in ("OK or MISSING", "exit 1", "installed; foreign", "or missing", "Sysmon on Windows",
                   "read-only", "`claude --version`", "absolute path"):
        assert phrase in doctor, phrase
