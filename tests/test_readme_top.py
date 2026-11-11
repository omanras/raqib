"""M9.2 (ADR-0010 decision 7): the README's top is one screen. README.md says what Raqib is, how to install
and start it, what an alarm looks like, where it runs and the commands; docs/GUIDE.md holds everything else
the README said, under the README's own headings, word for word. No sentence is lost: the README as it was
before (c13b9ad) is kept as a fixture and every sentence of it is found in one of the two files."""
import contextlib
import hashlib
import io
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from raqib import cli  # noqa: E402
from readme_text import GUIDE, GUIDE_PATH, README, README_PATH, flat, headings, section, units  # noqa: E402

DOCS = ROOT / "tests" / "fixtures" / "docs"
BEFORE = DOCS / "README-before-M9.2.md"
BEFORE_SHA256 = "2df4f35816a778d5d702641f2184cd7ee6993e865df6ebec65555c66e5eeda42"   # git show c13b9ad:README.md
# The README's headings before this task, in their order (E3).
OLD_HEADINGS = ["Install and watch", "Watch a project", "Doctor", "Watch the host", "The window", "Choose the rules",
                "How it works", "Manual steps", "What it catches", "What it cannot see", "Commands",
                "Watch another agent", "Watch what the system saw (os-sysmon)", "Find the agents on a host (discover)",
                "More", "Licence"]
NEW_HEADINGS = ["Install and watch", "Watch a project", "Doctor", "What an alarm looks like", "Where it runs",
                "Commands", "More", "Licence"]
# Sentences deliberately changed on the way: none. Link targets are not words: a guide link is relative to
# docs/, and the comparison below reads every link as the repository path it names.
CHANGED = {}


def before():
    """The old README. The fixture is ASCII (tests stay ASCII): its one non-ASCII line, the name in Arabic,
    is kept as \\uXXXX escapes, and the old README held no such escape of its own."""
    text = BEFORE.read_text(encoding="ascii")
    return re.sub(r"\\u([0-9a-f]{4})", lambda m: chr(int(m.group(1), 16)), text)


def root_links(text, base):
    """Every relative markdown link target rewritten as the repository path it names (base: the file's dir)."""
    def one(m):
        target = m.group(2)
        if re.match(r"^[a-z]+:", target) or target.startswith("#"):
            return m.group(0)
        path, _, anchor = target.partition("#")
        resolved = os.path.normpath(os.path.join(base, path)).replace(os.sep, "/") if path else ""
        return "%s%s%s)" % (m.group(1), resolved, "#" + anchor if anchor else "")
    return re.sub(r"(\]\()([^)\s]+)\)", one, text)


def links(text):
    return re.findall(r"\]\(([^)\s]+)\)", text)


def slug(title):
    return re.sub(r"[^a-z0-9 -]", "", title.lower()).replace(" ", "-")


def pieces(text):
    """The old README cut into what must survive: each heading line, each line of a code block or a table,
    and each sentence of a paragraph or list item (flattened)."""
    out, para, fence = [], [], False

    def flush():
        if para:
            for s in re.split(r"(?<=[.!?:;])\s+(?=[A-Z`\"*(\[])", flat(" ".join(para))):
                out.append(("sentence", s))
            del para[:]
    for line in text.split("\n"):
        if line.startswith("```"):
            flush()
            fence = not fence
            out.append(("line", line))
        elif fence or line.startswith("|") or line.startswith("#"):
            flush()
            if line.strip():
                out.append(("line", line))
        elif not line.strip() or re.match(r"^(- |\d+\. )", line):
            flush()
            if line.strip():
                para.append(line)
        else:
            para.append(line)
    flush()
    return out


def test_e1_readme_is_one_screen_then_the_alarm_where_it_runs_the_commands_more_and_the_licence():
    lines = README.split("\n")
    assert lines[-1] == "" and len(lines) - 1 <= 120, len(lines)
    assert max(len(line) for line in lines) <= 120
    assert headings(README) == NEW_HEADINGS
    assert lines[0] == before().split("\n")[0] and lines[2:5] == before().split("\n")[2:5]   # the name, three lines
    assert len(README.split("\n## Doctor\n", 1)[0].splitlines()) <= 25
    assert section("Licence") == section("Licence", before())   # as it is


def test_e1_where_it_runs_is_built_from_sentences_the_readme_had():
    old = flat(before())
    said = [s for kind, s in pieces(section("Where it runs")) if kind == "sentence"]
    assert len(said) >= 4
    for s in said:
        assert s in old, s
    where = flat(section("Where it runs"))
    for words in ("On Windows: `pipx install", "(Windows or WSL)", "It needs tkinter", "on Windows without Sysmon"):
        assert words in where, words
    assert "Python 3.11 or newer and Claude Code" in flat(section("Install and watch"))


def test_e1_the_short_table_is_cut_from_the_guides_full_table():
    full = {}
    for row in section("Commands", GUIDE).splitlines():
        if row.startswith("| `"):
            command, does = row[2:].rsplit(" |", 1)[0].split(" | ", 1)
            full[command.split("`")[1]] = does
    short = [row for row in section("Commands").splitlines() if row.startswith("| `")]
    assert len(short) >= 8 and all(len(row) <= 120 for row in short)
    for row in short:
        command, does = row[2:].rsplit(" |", 1)[0].split(" | ", 1)
        command = command.strip("`")
        matches = [c for c in full if c.startswith(command)]
        assert matches and does in full[matches[0]], row
    for name in ("watch", "doctor", "report", "ui", "suspect", "proxy", "os-sysmon"):
        assert any(row.startswith("| `raqib %s" % name) for row in short), name


def test_e1_more_links_every_heading_of_the_guide():
    more = section("More")
    targets = [t for t in links(more) if t.startswith("docs/GUIDE.md#")]
    assert targets == ["docs/GUIDE.md#" + slug(t) for t in headings(GUIDE)]
    assert "docs/GUIDE.md" in links(more)


def test_e2_the_sample_report_is_the_codes_own(monkeypatch):
    """The README's block is what `raqib report` prints for tests/fixtures/docs/alarm-sample.log, rendered by
    the same path (cli.main -> cmd_report -> report.render_text). The trace is given as the relative path the
    README shows, from the checkout's root; on Windows the catalog's relative path is printed with
    backslashes, so that one path is read with forward slashes before the comparison."""
    recs = [json.loads(line) for line in (DOCS / "alarm-sample.log").read_text(encoding="ascii").splitlines()]
    fixture = ROOT / "tests" / "fixtures" / "silence" / "empty-start-alone-at-end-negative.json"
    assert recs == json.loads(fixture.read_text(encoding="utf-8"))   # an existing fixture, one record per line
    monkeypatch.chdir(ROOT)
    monkeypatch.delenv("RAQIB_GAP_SECONDS", raising=False)
    out = io.StringIO()
    with contextlib.redirect_stderr(io.StringIO()):
        code = cli.main(["report", "tests/fixtures/docs/alarm-sample.log"], out=out)
    text = out.getvalue()
    text = text.replace("(catalog %s)" % os.path.join("raqib", "rules", "catalog"), "(catalog raqib/rules/catalog)")
    assert code == 1 and text.endswith("RESULT: ALARM (exit 1)\n")
    block = section("What an alarm looks like").split("```text\n", 1)[1].split("```", 1)[0]
    assert block == text
    assert "[high] SILENCE-OPEN" in block and "ALARMS (A3, A5): 0" in block


def test_e3_every_old_heading_is_a_heading_of_the_readme_or_the_guide():
    old = before()
    assert hashlib.sha256(old.encode("utf-8")).hexdigest() == BEFORE_SHA256
    assert headings(old) == OLD_HEADINGS
    for title in OLD_HEADINGS:
        assert title in headings(README) or title in headings(GUIDE), title
    assert [t for t in headings(GUIDE)] == [t for t in OLD_HEADINGS if t in headings(GUIDE)]   # the README's order
    assert "Licence" not in headings(GUIDE)


def test_e3_every_sentence_of_the_old_readme_is_in_the_readme_or_the_guide_word_for_word():
    readme = flat(root_links(README, ""))
    guide = flat(root_links(GUIDE, "docs"))
    readme_lines, guide_lines = set(README.split("\n")), set(root_links(GUIDE, "docs").split("\n"))
    lost = []
    found = 0
    for kind, piece in pieces(before()):
        piece = CHANGED.get(piece, piece)
        if kind == "line":
            ok = piece in readme_lines or piece in guide_lines
        else:
            ok = piece in readme or piece in guide
        found += 1
        if not ok:
            lost.append(piece)
    assert lost == [] and found == 395   # the fixture is fixed (its sha256 above), so is the count


def test_e3_the_guide_is_wrapped_at_100_but_its_tables_and_code():
    fence = False
    for line in GUIDE.split("\n"):
        if line.startswith("```"):
            fence = not fence
        elif not fence and not line.startswith("|"):
            assert len(line) <= 100, line
    assert GUIDE.startswith("# The Raqib guide\n")


def test_e3_every_relative_link_names_a_file_that_exists_and_a_guide_heading():
    for path, text in ((README_PATH, README), (GUIDE_PATH, GUIDE)):
        for target in links(text):
            if re.match(r"^[a-z]+:", target):
                continue
            name, _, anchor = target.partition("#")
            where = (path.parent / name) if name else path
            assert where.is_file(), (path.name, target)
            if anchor and where.resolve() == GUIDE_PATH.resolve():
                assert anchor in [slug(t) for t in headings(GUIDE)], target
    assert "](specs/ADR-0010-a-strangers-first-run.md)" in GUIDE and "](docs/" not in GUIDE
    assert "[CC0 1.0 Universal](LICENSE)" in README


# E5: the help cites the README by what it holds; each citation still names a section that holds it.
CITED = {"README's Windows loop": ("Find the agents on a host (discover)", "```powershell\n$N = 6; $T = 10\n")}


def test_e5_the_helps_readme_citations_name_a_section_that_exists():
    source = (ROOT / "raqib" / "cli.py").read_text(encoding="ascii")
    found = set(re.findall(r"README's \w+ \w+", " ".join(source.split())))
    assert found == set(CITED), found
    assert source.count("README") == 2
    for title, holds in CITED.values():
        assert title in headings(README) or title in headings(GUIDE), title
        text = README if title in headings(README) else GUIDE
        assert holds in section(title, text), title
        assert "docs/GUIDE.md#" + slug(title) in links(section("More"))   # and the README links to it
