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
WORDS = {4: "4", 6: "Six", 7: "7", 11: "Eleven", 12: "Twelve"}


def test_readme_counts_the_rules():
    rules = engine.load_catalog(CATALOG)
    table = report.rule_table(rules)
    silence = [r for r in table if r["class"] == "SILENCE" and r["fp_budget"] is None]
    assert "%s rules turn the trace into findings" % WORDS[len(table)] in README
    assert "%d silence rules and\n   %d YAML rules" % (len(silence), len(rules)) in README
    named = {"SILENCE-GAP", "SILENCE-OPEN", "SILENCE-HALF", "SILENCE-ORDER", "SILENCE-EMPTY", "SCOPE-PATH",
             "SCOPE-CWD-ROOT", "SCOPE-CWD-MOVED", "NET-TOOL", "DESTRUCT-CMD", "SECRET-OUTPUT",
             "DRIFT-FILES"}
    assert {r["id"] for r in table} == named, "update the README rule table"
    # Every rule has a row of the README's rule table, alone or in a row of its family (M4.2).
    rows = [line.split("|")[1].strip() for line in section("What it catches").splitlines()
            if line.startswith("| ") and not line.startswith("| Rule ")]
    for rule_id in named:
        family, last = rule_id.split("-")[0], rule_id.rsplit("-", 1)[1]
        assert any(rule_id == row or (re.split(r"[ /-]+", row)[0] == family and last in re.split(r"[ /-]+", row))
                   for row in rows), rule_id
    assert "| SILENCE-EMPTY |" in README


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
    # G-7: the Windows path-rules line is on the first screen; since M5.1b it
    # says what the rules do with Windows paths (ruling C-4), not a caveat;
    # UNC by backslashes only, the forward-slash form a hole (C-12); ASCII case (C-11).
    assert ("On Windows the path rules judge drive (`C:\\`) and UNC paths (`\\\\server\\share`, recognised by"
            " its two leading backslashes only) in any ASCII case, with `\\` or `/`; the forward-slash form"
            " `//server/share` is read as a POSIX path (a hole), `/mnt/c/...` (WSL) and `C:\\...` are different"
            " paths, and `--root /x` means `\\x` on the current drive.") in section("Install and watch").splitlines()
    assert "until M5.1b" not in README and "bad-context" not in README


def test_m51b_threat_model_section_7_says_what_the_path_rules_do_on_windows():
    """M5.1b C-4: section 7 no longer reports the silent SCOPE-CWD-ROOT gap
    that M5.1b closed; it names the Windows list and the holes."""
    platform = " ".join(THREAT.split("\n## 7. Platform\n", 1)[1].split("\n## ", 1)[0].split())
    assert "Known silent gap" not in platform and "do not yet judge Windows paths" not in platform
    assert "Linux, macOS and Windows: capture, installer and the path rules" in platform
    for hole in ("`/mnt/c/...` (WSL) and `C:\\...` are different paths", "the Git Bash form `/c/...`",
                 "8.3 short names", "OneDrive-redirected homes",
                 "macOS paths compare case-sensitively", "cannot be placed; the rules report it as partial",
                 "on Windows, `/x` means `\\x` on the current drive",
                 # C-16: the list is complete against the rule descriptions.
                 "from WSL, SCOPE-CWD-ROOT lists only `/mnt/<drive>` and `/mnt/<drive>/Users/<name>`",
                 "no Git Bash form (`/c/Users/<name>`)",
                 "the forward-slash UNC form `//server/share` is read as a POSIX path (C-12)",
                 # C-18: an fp source, not an evasion.
                 "a non-ASCII letter that Windows folds is not folded here (C-11, C-18): two spellings that Windows"
                 " reads as one directory are two, so SCOPE-PATH can fire on a path inside the project. This is a"
                 " known false-positive source, named in SCOPE-PATH's description; it adds findings and hides none;",
                 "the subfolders of `C:\\Users\\Public` (`Public\\Documents`, `Public\\Desktop`) are not listed;"
                 " `C:\\Users\\Public` itself fires as a home (C-14)",
                 "a cwd with `.` or `..` inside it (`C:\\.\\Users`, `/tmp/../home`) is a judged negative on both"
                 " branches (C-15)",
                 "the macOS temporary directories (`/private/tmp`, `/var/folders/...`) are not listed"):
        assert hole in platform, hole
    # C-16: the phrase is no longer doubled in the Git Bash item; C-18 adds the one for non-ASCII case.
    assert "(a false-positive source)" not in platform
    assert platform.count("false-positive source") == 2, platform
    assert "evasion listed" not in platform
    # C-8: the Git Bash form is a known false-positive source on Windows, its fixture a positive.
    assert ("This is a known false-positive source on Windows: an agent run from Git Bash that names its own"
            " project as `/c/...` gets SCOPE-PATH findings. A positive fixture records the firing (ruling C-8)"
            in platform)
    # C-9, C-16: the strip condition is stated; C-11: ASCII case only; C-12: UNC by backslashes.
    assert ("A `\\\\?\\` or `\\\\.\\` prefix is stripped only where a drive path or `UNC\\` follows it; any other"
            " prefixed path (`\\\\.\\pipe\\x`) keeps the UNC reading and is outside every project.") in platform
    assert "ASCII case is folded (A-Z only)" in platform
    assert "a UNC path (`\\\\server\\share`, recognised by its two leading backslashes only)" in platform


def test_m51b_c7_readme_platform_line_says_since_m51b():
    """C-7: README.md:68 no longer reads as if the Windows path rules were to
    come; line 122's count is held by tests/test_rules.py (M4.2 REDO-2 E-1)."""
    manual = section("Manual steps")
    assert "Linux, macOS; Windows: capture and installer (path rules since M5.1b). You need" in manual
    assert "path rules in M5.1b" not in README


def test_g1_readme_says_what_a_moved_package_does_per_platform():
    """Amendment G-1 (P1): POSIX, the hook wrapper prints RAQIB-SILENCE;
    Windows, a hook error from Claude Code and no line."""
    doctor = " ".join(section("Doctor").split())
    assert ("If the installed package moves on Linux or macOS, the hook command's own `|| echo` prints one"
            " `RAQIB-SILENCE:` line, because `capture.py` is gone.") in doctor
    assert ("If the venv moves on Windows, the hook names its `python.exe` by path, so Claude Code shows a hook"
            " error and no `RAQIB-SILENCE:` line is printed.") in doctor
    assert "capture prints `RAQIB-SILENCE:`" not in doctor
    assert ("A check that cannot be made on this host is UNSURE, counted apart and never a failure: today the"
            ' Windows trace line, which says "not checked"') in doctor   # H-1


def test_g6_readme_and_help_say_where_eval_events_come_from():
    from raqib import cli
    source = "a checkout's tests/fixtures/eval/events.json or --events FILE"
    assert cli.EVENTS_SOURCE == source
    assert source + " (an installed raqib has none and exits 2)" in section("Commands")


def test_m63_e3_readme_commands_are_the_installed_ones():
    commands = section("Commands")
    rows = [line for line in commands.splitlines() if line.startswith("| `")]
    assert rows and all(line.startswith("| `raqib ") for line in rows)
    for name in ("watch", "doctor", "report", "rules", "ui", "check-rules", "suspect", "eval"):
        assert any(line.startswith("| `raqib %s" % name) for line in rows), name
    assert "--fixtures-root" in commands and "`python3 -m raqib COMMAND`" in commands
    doctor = " ".join(section("Doctor").split())
    for phrase in ("OK, MISSING or UNSURE", "exit 1", "installed; foreign", "or missing", "Sysmon on Windows",
                   "read-only", "`claude --version`", "absolute path"):
        assert phrase in doctor, phrase


def test_m42_redo2_e2_e6_readme_names_the_holes():
    """E-2: the SILENCE-EMPTY row says "no start and no tool call" and names
    the open SILENCE-NOSTART; E-6: code on stdin, here-doc or script."""
    (row,) = [line for line in section("What it catches").splitlines() if line.startswith("| SILENCE-EMPTY |")]
    assert "or ended with no start and no tool call" in row and "SILENCE-NOSTART, M4.3" in row
    cannot = " ".join(section("What it cannot see").split())
    assert ("code given to a shell on stdin, by a here-document or a here-string, or in a script file: only the"
            " shell or the script is recorded") in cannot


def test_m42_redo2_e11_threat_model_no_longer_says_only_the_first_program():
    flat = " ".join(THREAT.split())
    assert "show only the first program (M1.1 3h-7" not in flat
    assert ("`cd x && rm -rf y`, pipes, `$(...)` and one level of `bash -c` are read into `command_programs` since"
            " ADR-0002 Amendment D") in flat
    assert "`sudo rm`, `env curl`, `xargs rm`, `eval`, `zsh -c` and code given to a shell on stdin show only" in flat
