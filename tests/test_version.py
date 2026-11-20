"""M17.1 (ADR-0015 V-1 to V-4 and its Amendment A): a number for every Raqib.

E1: the number is raqib.__version__ alone, of the form 0.MINOR.PATCH (VA-2: the form and the changelog's first
heading are held, not the literal number), and `raqib --version` says it. E2: the first line a watch prints and
the first line of its report end with "; raqib <number>", read when said; the window's title bar says
"Raqib <number>". E3: CHANGELOG.md is held by the checks below, each broken in turn by a made-up changelog. E4
(VA-3): tools/event_examples.py checks and writes docs/specs/EVENT.md's examples. E5: the documents say it."""
import ast
import datetime
import importlib.util
import io
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import raqib  # noqa: E402
from raqib import app, cli, host, watch  # noqa: E402
from readme_text import GUIDE, README, flat, section  # noqa: E402
from hostthreads import raqib_threads_end  # noqa: E402,F401  (V-5: every HostWatch ended, no thread leaked)
from test_host import CATALOG, RULES, inv  # noqa: E402
from test_watch import run_watch  # noqa: E402

CHANGELOG = ROOT / "CHANGELOG.md"
DOC = ROOT / "docs" / "specs" / "EVENT.md"
PROTOCOL = ROOT / "docs" / "SESSION_PROTOCOL.md"
TOOL = ROOT / "tools" / "event_examples.py"
_spec = importlib.util.spec_from_file_location("event_examples", TOOL)
event_examples = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(event_examples)

FAKE = "9.8.7"   # a number no copy says: a line that ends with it read raqib.__version__ when it was said


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    path = tmp_path / "home"
    path.mkdir()
    monkeypatch.setenv("HOME", str(path))
    monkeypatch.setenv("USERPROFILE", str(path))
    monkeypatch.delenv("RAQIB_GAP_SECONDS", raising=False)
    return path


# --- E1 (V-1): the one number ------------------------------------------------------------------------------------

LITERAL = re.compile(r"""["']v?\d+\.\d+\.\d+["']""")   # a version written as a string: "1.2.3", 'v1.2.3'
ASSIGNED = re.compile(r"__version__\s*=")


def version_literals(text, number):
    """What in text holds a version as a literal: a quoted X.Y.Z, an assignment of __version__, or the number
    itself (not as a part of a longer dotted run such as an address)."""
    return (LITERAL.findall(text) + ASSIGNED.findall(text) +
            re.findall(r"(?<![\d.])%s(?![\d.])" % re.escape(number), text))


def test_e1_the_number_is_of_the_form_0_minor_patch_and_the_package_reads_it():
    assert re.fullmatch(r"0\.(0|[1-9]\d*)\.(0|[1-9]\d*)", raqib.__version__), raqib.__version__
    assert 'version = { attr = "raqib.__version__" }' in (ROOT / "pyproject.toml").read_text(encoding="utf-8")


def test_e1_nothing_else_in_raqib_holds_a_version_as_a_literal():
    held = {}
    for path in sorted((ROOT / "raqib").rglob("*")):
        if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
            got = version_literals(path.read_bytes().decode("latin-1"), raqib.__version__)
            if got:
                held[path.relative_to(ROOT).as_posix()] = got
    number = raqib.__version__
    assert held == {"raqib/__init__.py": ['"%s"' % number, "__version__ =", number]}, held


def test_e1_the_grep_finds_a_literal_and_passes_what_is_none():
    for line in ('VERSION = "1.2.3"', "tag = 'v0.3.1'", "__version__ = make()", 'say("raqib 0.2.0")'):
        assert version_literals(line, "0.2.0"), line
    for line in ('HOST = "127.0.0.1"', "# RFC 5424 6.2.1: the facilities", "seen in 10.0.2.0.1", "raqib %s"):
        assert version_literals(line, "0.2.0") == [], line


def test_e1_raqib_version_prints_raqib_and_the_number(monkeypatch):
    out = io.StringIO()
    assert cli.main(["--version"], out=out) == 0 and out.getvalue() == "raqib %s\n" % raqib.__version__
    monkeypatch.setattr(raqib, "__version__", FAKE)
    out = io.StringIO()
    assert cli.main(["--version"], out=out) == 0 and out.getvalue() == "raqib %s\n" % FAKE


# --- E2 (V-2, VA-1): where a person looks -----------------------------------------------------------------------

HOST_FIRST = ("raqib watch --host: the host, not a name (ADR-0007); nothing is installed, no project is touched (no"
              " --attach-hooks); raqib %s")
HOST_REPORT_FIRST = "Raqib watch --host (ADR-0007): the host, not a name; raqib %s"


def test_e2_the_word_is_raqib_and_the_number_read_when_said(monkeypatch):
    assert watch.version_word() == "raqib %s" % raqib.__version__
    monkeypatch.setattr(raqib, "__version__", FAKE)
    assert watch.version_word() == "raqib " + FAKE


def test_e2_the_host_watch_s_first_line_and_its_report_s_first_line_end_with_the_number(_home, monkeypatch):
    monkeypatch.setattr(raqib, "__version__", FAKE)
    out = io.StringIO()
    running = host.start(CATALOG, RULES, every=10, no_open=True, no_notify=True, port=0, out=out,
                         err=io.StringIO(), environ={}, home=str(_home), reader=lambda: inv("linux"),
                         platform="test", no_page=True)
    try:
        stop = watch.Stop()
        stop.set("the window's Stop")
        crash = host.loop(running, stop)
        text, code = host.conclude(running, crash)
    finally:
        host.close(running)
    assert crash is None and code == 0
    assert out.getvalue().split("\n", 1)[0] == HOST_FIRST % FAKE
    report = text.split("\n")
    assert report[0] == HOST_REPORT_FIRST % FAKE
    assert report[1].startswith("host: test; a round every 10 s")   # nothing else in the report moves


def test_e2_the_project_watch_s_first_line_and_its_report_s_first_line_end_with_the_number(tmp_path, monkeypatch):
    monkeypatch.setattr(raqib, "__version__", FAKE)
    proj = tmp_path / "proj"
    proj.mkdir()
    code, out = run_watch(monkeypatch, ["watch", proj, "--no-open", "--no-notify", "--port", "0"])
    lines = out.split("\n")
    own = [x for x in lines if x.startswith("raqib watch: ")]
    assert own[0].startswith("raqib watch: project ") and own[0].endswith("proj; raqib " + FAKE), own[0]
    assert "raqib watch: project " not in "\n".join(own[1:])
    assert lines.count("Raqib watch; raqib " + FAKE) == 1 and "Raqib watch" not in lines
    after = lines[lines.index("Raqib watch; raqib " + FAKE) + 1]
    assert after.startswith("project: ") and code in (0, 1, 3)   # nothing else in the report moves


def test_e2_the_window_s_title_is_raqib_and_the_number(monkeypatch):
    assert app.window_title() == "Raqib %s" % raqib.__version__
    monkeypatch.setattr(raqib, "__version__", FAKE)
    assert app.window_title() == "Raqib " + FAKE and app.TITLE == "Raqib"


def test_tk_the_window_s_title_bar_says_raqib_and_the_number(tmp_path, monkeypatch):
    import test_app as ta
    tkinter, root = ta.tk_or_skip()
    monkeypatch.setattr(raqib, "__version__", FAKE)
    window = None
    try:
        c = app.Controller(None, tray=None, make_session=ta.TkSession)
        doctor = app.DoctorJob(str(tmp_path), checks=lambda p: (p, [("python", (True, "3.12"))], []))
        window = app.Window(tkinter, root, c, str(tmp_path), doctor_job=lambda p: doctor)
        root.withdraw()
        assert ta.until(lambda: doctor.result() is not None, 10)
        assert root.title() == "Raqib " + FAKE
    finally:
        root.destroy()


# --- E3 (V-3): the changelog ------------------------------------------------------------------------------------

PARTS = ("What is new:", "To update:", "Not measured:")
FIRST = re.compile(r"(\d+\.\d+\.\d+) - (\d{4}-\d{2}-\d{2})\Z")


def entries(text):
    """[(heading without its `## `, the entry's lines)] in the page's order."""
    return [(b.split("\n", 1)[0], b.split("\n")[1:]) for b in re.split(r"(?m)^## ", text)[1:]]


def number(heading):
    """The heading's number as numbers ((0, 10, 0) > (0, 9, 0)), None where it does not start with one."""
    m = re.match(r"(\d+)\.(\d+)\.(\d+)(?=\s|\Z)", heading)
    return tuple(int(x) for x in m.groups()) if m else None


def parts(lines):
    """{part: its lines that are not blank} of one entry."""
    out, at = {}, None
    for line in lines:
        if line.strip() in PARTS:
            at = line.strip()
            out.setdefault(at, [])
        elif at and line.strip():
            out[at].append(line)
    return out


def real_date(text):
    try:
        datetime.date.fromisoformat(text)
    except ValueError:
        return False
    return True


def problems(text, version):
    """[(check, what)]: each way text breaks V-3 ([]: none). The checks: first (its first heading is
    `## <version> - <YYYY-MM-DD>`), number (every heading starts with its number), order (the numbers strictly go
    down the page, as numbers), parts (every entry but the oldest has the three parts, each with a line), ascii."""
    out = []
    if not text.isascii():
        out.append(("ascii", "a character that is not ASCII"))
    es = entries(text)
    if not es:
        return out + [("first", "no `## ` heading")]
    m = FIRST.match(es[0][0])
    if not (m and m.group(1) == version and real_date(m.group(2))):
        out.append(("first", "%r is not `%s - <YYYY-MM-DD>`" % (es[0][0], version)))
    nums = [number(h) for h, _ in es]
    out += [("number", h) for (h, _), n in zip(es, nums) if n is None]
    for (h1, _), n1, (h2, _), n2 in zip(es, nums, es[1:], nums[1:]):
        if n1 is not None and n2 is not None and not n2 < n1:
            out.append(("order", "%r then %r" % (h1, h2)))
    for h, lines in es[:-1]:
        got = parts(lines)
        out += [("parts", "%r: %s %s" % (h, p, "has no line" if p in got else "is missing"))
                for p in PARTS if not got.get(p)]
    return out


def entry(num, date="2026-11-20", have=PARTS, lines=1):
    body = []
    for p in have:
        body += ["", p] + ["- a line"] * lines
    return "\n".join(["## %s - %s" % (num, date)] + body) + "\n"


OLDEST = "## 0.1.0 - before 2026-11-20\n\nEvery copy before this file said 0.1.0.\n"


def changelog(*made):
    return "# Changelog\n\nThe newest first.\n\n" + "\n".join(made)


def checks(found):
    return [k for k, _ in found]


def test_e3_the_changelog_holds_every_check():
    data = CHANGELOG.read_bytes()
    assert data.isascii()
    assert problems(data.decode("ascii"), raqib.__version__) == []
    assert entries(data.decode("ascii"))[0][0].startswith(raqib.__version__ + " - ")


def test_e3_a_made_up_changelog_that_keeps_every_check_has_no_problem():
    assert problems(changelog(entry("0.10.0"), entry("0.9.2"), entry("0.9.0"), OLDEST), "0.10.0") == []


def test_e3_the_first_heading_must_be_the_number_and_a_date():
    assert checks(problems(changelog(entry("0.3.0"), OLDEST), "0.4.0")) == ["first"]   # not raqib's number
    assert checks(problems(changelog(entry("0.3.0", date="before 2026-11-20"), OLDEST), "0.3.0")) == ["first"]
    assert checks(problems(changelog(entry("0.3.0", date="2026-13-40"), OLDEST), "0.3.0")) == ["first"]
    assert checks(problems(changelog(entry("0.3.0").replace(" - 2026-11-20", ""), OLDEST), "0.3.0")) == ["first"]
    assert checks(problems("# Changelog\n\nnone yet\n", "0.3.0")) == ["first"]


def test_e3_every_heading_starts_with_a_number():
    made = changelog(entry("0.3.0"), entry("0.2.0").replace("## 0.2.0", "## the second"), OLDEST)
    assert checks(problems(made, "0.3.0")) == ["number"]


def test_e3_the_numbers_strictly_go_down_the_page_as_numbers_not_text():
    assert checks(problems(changelog(entry("0.2.0"), entry("0.3.0"), OLDEST), "0.2.0")) == ["order"]
    assert checks(problems(changelog(entry("0.2.0"), entry("0.2.0"), OLDEST), "0.2.0")) == ["order"]
    assert checks(problems(changelog(entry("0.9.0"), entry("0.10.0"), OLDEST), "0.9.0")) == ["order"]
    assert "0.9.0" > "0.10.0" and problems(changelog(entry("0.10.0"), entry("0.9.0"), OLDEST), "0.10.0") == []


def test_e3_every_entry_but_the_oldest_has_the_three_parts_each_with_a_line():
    for p in PARTS:
        gone = tuple(x for x in PARTS if x != p)
        found = problems(changelog(entry("0.3.0"), entry("0.2.0", have=gone), OLDEST), "0.3.0")
        assert checks(found) == ["parts"] and p in found[0][1] and "is missing" in found[0][1]
        empty = changelog(entry("0.3.0"), entry("0.2.0").replace(p + "\n- a line\n", p + "\n\n"), OLDEST)
        found = problems(empty, "0.3.0")
        assert checks(found) == ["parts"] and p in found[0][1] and "has no line" in found[0][1]
    assert problems(changelog(entry("0.3.0"), entry("0.2.0", have=())), "0.3.0") == []   # the oldest: free


def test_e3_the_changelog_is_ascii():
    assert checks(problems(changelog(entry("0.3.0").replace("a line", "a line " + chr(0x2014) + " a dash"), OLDEST),
                           "0.3.0")) == ["ascii"]


# --- E4 (VA-3): the examples' tool -------------------------------------------------------------------------------

@pytest.fixture(scope="module")
def built():
    return event_examples.build()


def test_e4_the_tool_checks_and_writes_the_examples_from_the_code(tmp_path, built):
    real = DOC.read_text(encoding="utf-8")
    out = io.StringIO()
    assert event_examples.main(["--check"], out=out, built=built) == 0, out.getvalue()
    doc = tmp_path / "EVENT.md"
    number, examples = '"version":"%s"' % raqib.__version__, len(event_examples.found(real))
    assert real.count(number) == examples > 0   # every example holds the number once
    doc.write_text(real.replace(number, '"version":"0.0.1"'), encoding="utf-8")   # a number that moved
    out = io.StringIO()
    assert event_examples.main(["--check", "--doc", str(doc)], out=out, built=built) == 1
    assert out.getvalue().count("is not the code's own") == examples
    assert event_examples.main(["--write", "--doc", str(doc)], out=io.StringIO(), built=built) == 0
    assert doc.read_text(encoding="utf-8") == real
    assert event_examples.main(["--check", "--doc", str(doc)], out=io.StringIO(), built=built) == 0


def test_e4_an_example_lost_or_of_no_event_is_named_and_exits_1(tmp_path, built):
    real = DOC.read_text(encoding="utf-8")
    doc = tmp_path / "EVENT.md"
    doc.write_text(real.replace("### example: knock\n", "### example: a knock no run makes\n"), encoding="utf-8")
    for how in ("--check", "--write"):
        out = io.StringIO()
        assert event_examples.main([how, "--doc", str(doc)], out=out, built=built) == 1
        assert "no example of knock in the document" in out.getvalue()
        assert "the example a knock no run makes is of no built event" in out.getvalue()


def test_vb3_an_example_whose_fence_is_missing_is_named_and_never_takes_the_next_ones_line(tmp_path, built):
    real = DOC.read_text(encoding="utf-8")
    labels = list(event_examples.found(real))
    first = labels[0]
    at = real.index("### example: %s\n" % first)
    fence = real.index("```json\n", at)
    broken = real[:fence] + real[fence:].replace("```json\n", "```\n", 1)   # the first example's fence is lost
    doc = tmp_path / "EVENT.md"
    for how in ("--check", "--write"):
        doc.write_text(broken, encoding="utf-8")
        out = io.StringIO()
        assert event_examples.main([how, "--doc", str(doc)], out=out, built=built) == 1
        said = out.getvalue()
        assert said.count("no example of") == 1 and "no example of %s in the document" % first in said
        assert doc.read_text(encoding="utf-8") == broken   # nothing written under a wrong label
    assert list(event_examples.found(broken)) == labels[1:]


def test_e4_the_tool_is_ascii_and_imports_the_standard_library_raqib_and_the_events_test():
    data = TOOL.read_bytes()
    assert data.isascii()
    names = set()
    for node in ast.walk(ast.parse(data.decode("ascii"))):
        if isinstance(node, ast.Import):
            names |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            names.add(node.module.split(".")[0])
    # test_event: the fixture runs whose builder the tool and tests/test_event.py share (VA-3)
    assert names - set(sys.stdlib_module_names) == {"raqib", "test_event"}, names


# --- E5: the documents ---------------------------------------------------------------------------------------------

def test_e5_the_guide_says_where_the_number_is_read_what_a_move_means_and_how_to_update():
    guide = flat(section("Install and watch", GUIDE))
    for words in ("`raqib --version` prints `raqib` and the number",
                  "the first line a watch prints and the first line of its report end with it",
                  "the window's title bar says `Raqib` and the number", "every event holds it as `watch.version`",
                  "MINOR moves with every merge into `main` that changes what Raqib does for a person",
                  "PATCH with a merge that only repairs", "a merge of documents or tests alone moves nothing",
                  "The number is not a promise of stability",
                  "[CHANGELOG.md](../CHANGELOG.md) says, the newest first, what each number brought, how to update",
                  "First stop a running watch, window or service: a running one keeps the number it started with.",
                  "- Installed with pipx, on Linux or Windows: `pipx install --force .`",
                  "- Installed with pip: `pip install --upgrade .` in the same venv; with Windows' launcher,"
                  " `py -m pip install --upgrade .`",
                  "`sudo DIR/bin/raqib service install` again (it writes the unit again and restarts it)",
                  "These steps were not run on a machine yet.",
                  "- Then `raqib --version` says the number at the top of CHANGELOG.md."):
        assert words in guide, words
    # the steps as CHANGELOG.md's newest entry gives them: each of its commands is the guide's
    steps = parts(entries(CHANGELOG.read_text(encoding="ascii"))[0][1])["To update:"]
    commands = re.findall(r"`([^`]+)`", "\n".join(steps))
    assert commands and all("`%s`" % c in guide for c in commands), commands


def test_e5_the_protocol_s_line_and_the_readme_s_pointer():
    protocol = flat(PROTOCOL.read_text(encoding="utf-8"))
    assert ("A merge into `main` that changes what Raqib does moves the number (`raqib/__init__.py`) and writes its"
            " entry at the top of `CHANGELOG.md`, in the merge itself (ADR-0015)") in protocol
    assert "`python3 tools/event_examples.py --write` then makes the events' examples again" in protocol
    assert ("What each version of Raqib brought, and how to update to it, is in [CHANGELOG.md](CHANGELOG.md)."
            in flat(section("More", README)))
