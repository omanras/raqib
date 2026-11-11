"""M9.2 (ADR-0010 decision 7): the README's top is one screen. README.md says what Raqib is, how to install
and start it, what an alarm looks like, where it runs and the commands; docs/GUIDE.md holds everything else
the README said, under the README's own headings, word for word. No sentence is lost: the README as it was
before (c13b9ad) is kept as a fixture and every sentence of it is found in one of the two files.
REDO (ADR-0010 Amendment E): "Where it runs" is written fresh, each fact pinned by the code or the guide (E-1);
one sentence names what prints the sample (E-2); the Commands table is for a person, every row checked against
the parser (E-3); raqib/ cites docs/GUIDE.md, not the README, for what moved there (E-4); the nothing-lost test
counts, reads under each heading and runs both ways (E-6); a split section of the guide links its start (E-7)."""
import argparse
import collections
import contextlib
import hashlib
import io
import itertools
import json
import os
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from raqib import cli, discover, doctor, notify, report, watch  # noqa: E402
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
# Sentences deliberately changed on the way (old -> new). E-7: "this quickstart" names where the quickstart is
# (ADR-0010 decision 6: the README's install block). Link targets are not words: a guide link is relative to
# docs/, and the comparisons below read every link as the repository path it names.
CHANGED = {
    "The last exit criterion of the plan (M3.3) is still open: one person outside the project runs this quickstart"
    " and files one issue.":
    "The last exit criterion of the plan (M3.3) is still open: one person outside the project runs the quickstart"
    " in the README ([Install and watch](README.md#install-and-watch)) and files one issue.",
}
# The README's own two sentences that "Where it runs" keeps from the old Install and watch (ADR-0010 E-5: the
# Windows install line is in "Where it runs"); the old split rule cuts the first at its colon.
WINDOWS_INSTALL = ("On Windows: `pipx install C:\\path\\to\\raqib` (or `py -m pip install C:\\path\\to\\raqib`), then"
                   " `raqib watch C:\\path\\to\\project`.")
WSL = "Install on the side that runs the agent (Windows or WSL), not both."
MOVED = {"On Windows:": "Where it runs",
         "`pipx install C:\\path\\to\\raqib` (or `py -m pip install C:\\path\\to\\raqib`), then `raqib watch"
         " C:\\path\\to\\project`.": "Where it runs",
         WSL: "Where it runs"}
# E-7: the sections whose beginning stayed in the README; the guide's part begins with this line.
SPLIT = ["Install and watch", "Watch a project", "Doctor"]
LINK_LINE = "This section begins in the README, under [%s](%sREADME.md#%s)."
# E-3: the rows the guide's Commands table gained, as in README's table.
NEW_ROWS = ["| `raqib app [PROJECT]` | open Raqib as a desktop window: the host first, Watch this host, or a project |",
            "| `raqib rules [--set ID on\\|off]` | list every rule; turn a rule on or off; `--new ID`, `--add FILE`,"
            " `--remove NAME` |",
            "| `raqib discover` | find AI agents on a host by what they do |",
            "| `raqib --version` | print raqib <version> and exit 0 |"]
# The pieces of the guide that are not the old README's (E-6): its title, E-7's lines, E-3's rows (and CHANGED).
GUIDE_NEW = ["# The Raqib guide"] + [LINK_LINE % (t, "", t.lower().replace(" ", "-")) for t in SPLIT] + NEW_ROWS
# The two sentences the first build copied from the guide into "Where it runs" (Q-4); the guide's again (E-1).
TKINTER_SENTENCE = ("It needs tkinter: python.org Python ships it; on Debian or Ubuntu `sudo apt install python3-tk`;"
                    " without it, or without a display, `raqib app` exits 2 and says so")
BETWEEN_SENTENCE = ("On Linux, and on Windows without Sysmon, a tree that lives between two rounds is not seen, and"
                    " the watch says so once")


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


def cut(text):
    """The text cut into what must survive, each with the heading it stands under (None: before the first
    `## `): each heading line, each line of a code block or a table, and each sentence of a paragraph or list
    item (flattened)."""
    out, para, fence, heading = [], [], False, None

    def flush():
        if para:
            for s in re.split(r"(?<=[.!?:;])\s+(?=[A-Z`\"*(\[])", flat(" ".join(para))):
                out.append(("sentence", s, heading))
            del para[:]
    for line in text.split("\n"):
        if line.startswith("```"):
            flush()
            fence = not fence
            out.append(("line", line, heading))
        elif fence or line.startswith("|") or line.startswith("#"):
            flush()
            if not fence and line.startswith("## "):
                heading = line[3:]
            if line.strip():
                out.append(("line", line, heading))
        elif not line.strip() or re.match(r"^(- |\d+\. )", line):
            flush()
            if line.strip():
                para.append(line)
        else:
            para.append(line)
    flush()
    return out


def pieces(text):
    return [(kind, piece) for kind, piece, _ in cut(text)]


def part(text, title):
    """The text under a heading (None: before the first heading); "" when the text has no such heading."""
    if title is None:
        return text.split("\n## ", 1)[0]
    return section(title, text) if title in headings(text) else ""


def parser_parts():
    """The parser, its subcommands {name: parser}, and every help text it holds (the module's docstring, the
    subcommands' and every option's), flattened."""
    p = cli._parser()
    sub = next(a for a in p._actions if isinstance(a, argparse._SubParsersAction))
    texts = [cli.__doc__] + [a.help or "" for a in p._actions] + [c.help or "" for c in sub._choices_actions]
    texts += [a.help or "" for sp in sub.choices.values() for a in sp._actions]
    return p, sub.choices, flat(" ".join(texts))


def parse(argv):
    """argv as `raqib` parses it: the namespace, or "--version"; a usage error fails with argv."""
    err = io.StringIO()
    try:
        with contextlib.redirect_stderr(err):
            return cli._parser().parse_args(argv)
    except cli._VersionAsked:
        return "--version"
    except SystemExit as exc:
        raise AssertionError("raqib %s: usage error %s: %s" % (" ".join(argv), exc.code, err.getvalue()))


def cells(row):
    return [c.strip() for c in re.split(r"(?<!\\)\|", row)[1:-1]]


def table_rows(text):
    return [row for row in text.splitlines() if row.startswith("| ") and not row.startswith("| Command ")]


# A capital word of a row, typed with a real value.
VALUES = {"PROJECT": "my-project", "TRACE": "trace.jsonl", "ID": "NET-TOOL", "FILE": "rule.yaml", "NAME": "MY-TF"}


def argvs(code):
    """Every argv a row's command shows: each [optional | alternative] group absent or each alternative, each
    a|b word each way, each capital word a real value."""
    words = code.replace("\\|", "|")
    assert words.startswith("raqib "), code
    choices = []
    for chunk in re.split(r"(\[[^\]]*\])", words[len("raqib "):]):
        if chunk.startswith("["):
            choices.append([[]] + [alt.split() for alt in chunk[1:-1].split(" | ")])
        else:
            choices.append([chunk.split()])
    out = []
    for combo in itertools.product(*choices):
        shown = [w for seq in combo for w in seq]
        for filled in itertools.product(*[w.split("|") for w in shown]):
            out.append([VALUES.get(w, w) for w in filled])
    return out


def test_e1_readme_is_one_screen_then_the_alarm_where_it_runs_the_commands_more_and_the_licence():
    lines = README.split("\n")
    assert lines[-1] == "" and len(lines) - 1 <= 120, len(lines)
    # Q-10, ruled by the Table: only the sample's fence is exempt, up to the report's own cap (a cited line is
    # what the code prints and is not cut); every other line keeps 120.
    sample = sample_fence()
    assert max(len(line) for line in lines[:sample[0]] + lines[sample[1]:]) <= 120
    assert max(len(line) for line in lines[sample[0]:sample[1]]) <= report.LINE_TEXT_MAX
    assert lines[sample[0] - 1] == "```text" and lines[sample[1]] == "```" and lines.count("```text") == 1
    assert headings(README) == NEW_HEADINGS
    assert lines[0] == before().split("\n")[0] and lines[2:5] == before().split("\n")[2:5]   # the name, three lines
    assert len(README.split("\n## Doctor\n", 1)[0].splitlines()) <= 25
    assert section("Licence") == section("Licence", before())   # as it is


def test_e1_where_it_runs_is_written_fresh_and_each_fact_is_pinned_by_the_code_or_the_guide():
    """ADR-0010 E-1: at most eight lines of plain words, each fact true of the tree. This test replaces the first
    build's "built from sentences the README had": its two README sentences stay pinned here, its two copies of
    the guide's sentences are pinned in the guide again (the last block), and Python 3.11 in Install and watch."""
    where = section("Where it runs")
    said = flat(where)
    text_lines = [line for line in where.split("\n") if line.strip()]
    assert len(text_lines) <= 8 and all(len(line) <= 120 for line in text_lines), text_lines
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    gate = (ROOT / ".github" / "workflows" / "gate.yml").read_text(encoding="utf-8")
    p, commands, helps = parser_parts()
    # Linux and Windows: both CI jobs run on exactly these two; no job runs on macOS.
    assert "Raqib runs on Linux and Windows" in said and "the tests run on both" in said
    assert re.findall(r"^\s+os: \[(.*)\]$", gate, re.M) == ["ubuntu-latest, windows-latest"] * 2
    assert "macos" not in gate.lower() and gate.count("runs-on: ${{ matrix.os }}") == 2
    # Python's floor (pyproject.toml, doctor's check) and the standard library only (no dependency).
    assert "on Python 3.11 or newer and its standard library only" in said
    assert re.search(r'^requires-python = ">=3\.11"$', pyproject, re.M) and doctor.MIN_PYTHON == (3, 11)
    assert re.search(r"^dependencies = \[\]$", pyproject, re.M)
    # The Windows install and WSL: the README's own sentences, word for word (ADR-0010 E-5).
    for sentence in (WINDOWS_INSTALL, WSL):
        assert sentence in said and sentence in flat(before()), sentence
    for words in ("On Windows: `pipx install", "(Windows or WSL)"):   # the first build's pins, kept
        assert words in said, words
    # Claude Code for `raqib watch PROJECT`: the hooks it installs are Claude Code's.
    assert "`raqib watch PROJECT` needs Claude Code, whose hooks it installs." in said
    assert doctor.check_claude({}, False, shutil.which, None) == (
        False, "not on PATH (install Claude Code; the hooks are Claude Code hooks)")
    assert parse(["watch", "my-project"]).project == "my-project" and "install the hooks" in helps
    # `raqib watch --host` names no agent; on Windows it reads Sysmon where it is; what it misses is the guide's.
    assert "`raqib watch --host` needs no agent named: it finds the agents by what they do" in said
    args = parse(["watch", "--host"])
    assert args.host and args.project is None
    assert "find AI agents on a host by what they do" in helps and "watch this host, not a project" in helps
    assert "where Sysmon is, each round also reads the channel since the previous round" in helps
    assert ("and on Windows it also reads Sysmon where it is installed ([what it misses without"
            " it](docs/GUIDE.md#watch-the-host)).") in said
    assert links(where) == ["docs/GUIDE.md#watch-the-host"] and "Watch the host" in headings(GUIDE)
    assert BETWEEN_SENTENCE in flat(section("Watch the host", GUIDE))
    # The window needs tkinter and `raqib watch` does not: doctor's line is UNSURE and never fails its exit.
    # ADR-0010 F-1 (J2): python3-tk is Debian's and Ubuntu's package; python.org's Python has tkinter (the guide's words)
    assert ("The window, `raqib app`, needs tkinter (python.org's Python has it; on Debian or Ubuntu install"
            " `python3-tk`); `raqib watch` does not.") in said
    assert "python.org Python ships it; on Debian or Ubuntu `sudo apt install python3-tk`" in TKINTER_SENTENCE

    def no_tkinter(name):
        raise ImportError("No module named %r" % name)
    verdict, line = doctor.check_tkinter({}, "linux", no_tkinter)
    assert verdict == doctor.UNSURE and doctor.TK_UNSURE == "the window needs it (python3-tk); watch does not"
    assert line.startswith(doctor.TK_UNSURE) and doctor.summary([("tkinter", (verdict, line))])[1] == 0
    assert "app" in commands
    # macOS, as the tree stands: osascript and the page opener are written; no live reader; no CI job (above).
    # ADR-0010 F-1 (J1): the hooks and doctor are written for it too (the guide's sentences, the old README's);
    # discover has no live reader there either (collect_live below is discover's own reader); nothing is tested
    assert ("On macOS the hooks, doctor, the notifications and the page opener are written for it, but `raqib watch"
            " --host` and `raqib discover` have no live reader there and no CI job runs on macOS: none of it is"
            " tested.") in said
    assert "on Linux and macOS `python3` on PATH, which the hooks run" in flat(section("Doctor", GUIDE))
    assert "Linux, macOS; Windows: capture and installer" in flat(GUIDE)
    knocks = notify.Notifier("p", environ={}, platform="darwin", isfile=lambda path: True)
    assert (knocks.backend, knocks.program) == ("osascript", notify.OSASCRIPT)
    opened = []
    watch.open_page("http://127.0.0.1:8765/", environ={}, platform="darwin", isfile=lambda path: True,
                    runner=lambda argv, env, cwd, wait=False: (opened.append(argv), (0, None))[1])
    assert opened == [[watch.MAC_OPENER, "http://127.0.0.1:8765/"]]
    texts, holes, _ = discover.collect_live(discover.load_catalog(), platform="darwin", homes=[])
    assert set(texts) == {"footprints"} and holes[0].startswith("no live process or connection reader on darwin")
    assert doctor.check_host("darwin") == (doctor.UNSURE, "homes only; no live reader")
    # The two sentences the first build copied from the guide left the README; the guide keeps them (Q-4).
    assert TKINTER_SENTENCE not in flat(README) and TKINTER_SENTENCE in flat(section("The window", GUIDE))
    assert BETWEEN_SENTENCE not in flat(README) and "on Windows without Sysmon" in flat(section("Watch the host", GUIDE))
    assert "It needs tkinter" in flat(section("The window", GUIDE)) and "It needs tkinter" not in said
    assert "Python 3.11 or newer and Claude Code" in flat(section("Install and watch"))


def test_e3_the_commands_table_is_cut_from_the_guides_and_in_the_ruled_order():
    """ADR-0010 E-3: `raqib app` first, then watch, watch --host, doctor, report, rules, discover, --version, and
    one row for the rest that points at the guide. Each command row is a guide row (its command the row's or a
    prefix of it, its words a part of the row's): the guide's table gained E-3's new rows (NEW_ROWS)."""
    full = {}
    for row in table_rows(section("Commands", GUIDE)):
        command, does = cells(row)
        full[command.split("`")[1]] = does
    rows = table_rows(section("Commands"))
    assert len(rows) >= 8 and all(len(row) <= 120 for row in rows)
    short = [row for row in rows if row.startswith("| `raqib ")]
    rest = [row for row in rows if not row.startswith("| `raqib ")]
    assert rows == short + rest and len(rest) == 1
    for row in short:
        command, does = cells(row)
        command = command.strip("`")
        matches = [command] if command in full else [c for c in full if c.startswith(command)]
        assert matches and does in full[matches[0]], row
    keys = [cells(row)[0].strip("`").split()[1] for row in short]
    keys = [k + " --host" if k == "watch" and "--host" in row else k for k, row in zip(keys, short)]
    assert keys == ["app", "watch", "watch --host", "doctor", "report", "rules", "discover", "--version"], keys
    for row in NEW_ROWS:
        assert row in rows and row in table_rows(section("Commands", GUIDE)), row
    named = set(keys) | set(re.findall(r"`([a-z-]+)`", cells(rest[0])[0]))
    for name in ("watch", "doctor", "report", "ui", "suspect", "proxy", "os-sysmon"):   # the first build's names
        assert name in named, name
    assert cells(rest[0])[0].startswith("the rest: ") and links(rest[0]) == ["docs/GUIDE.md#commands"]


def test_e3_every_command_in_the_table_is_the_parsers_and_parses_as_shown():
    """Every subcommand of the parser is named in the table, and nothing else is; a row's command, typed as shown
    with real values for its capital words, parses; each option it shows is that command's, with the metavar it
    shows; a new row's words are the help's own."""
    p, commands, helps = parser_parts()
    rows = table_rows(section("Commands"))
    short = [row for row in rows if row.startswith("| `raqib ")]
    rest = cells([row for row in rows if not row.startswith("| `raqib ")][0])[0]
    named = [cells(row)[0].strip("`").split()[1] for row in short]
    assert set(n for n in named if not n.startswith("-")) | set(re.findall(r"`([a-z-]+)`", rest)) == set(commands)
    for row in short:
        command, does = cells(row)
        word = command.strip("`").split()[1]
        shapes = argvs(command.strip("`"))
        assert shapes, row
        for argv in shapes:
            got = parse(argv)
            assert got == "--version" if word == "--version" else got.command == word, (argv, got)
            for value, attr in (("my-project", "project"), ("trace.jsonl", "trace")):
                if value in argv:
                    assert getattr(got, attr) == value, argv
        owner = p if word.startswith("-") else commands[word]
        options = {o: a for a in owner._actions for o in a.option_strings}
        for code in re.findall(r"`([^`]+)`", row):
            for m in re.finditer(r"(--[a-z][a-z-]*)((?: (?:[A-Z][A-Z_]*|[a-z]+\\?\|[a-z]+))*)", code):
                option, shown = m.group(1), m.group(2).replace("\\|", "|").split()
                assert option in options, (row, option)
                metavar = options[option].metavar
                metavar = list(metavar) if isinstance(metavar, tuple) else ([metavar] if metavar else [])
                assert shown == metavar[:len(shown)] and (not shown or len(shown) == len(metavar)), (row, option)
                if word == "rules" and option != "--set":
                    assert parse(["rules", option] + [VALUES[w] for w in shown]).command == "rules"
        if row in NEW_ROWS:
            for said in does.split("; "):
                assert "--" in said or said in helps, (row, said)


def test_e3_one_line_under_the_table_says_what_trace_is():
    commands = section("Commands")
    table, after = commands.rsplit("|\n\n", 1)   # a blank line: a line right under a table would be its row
    lines = [line for line in after.split("\n") if line.strip()]
    assert len(lines) == 1 and lines[0].startswith("TRACE is a trace file, a `raqib.log.jsonl` of JSON lines;")
    assert "`%s`" % watch.TRACE_NAME in lines[0] and watch.TRACE_NAME == "raqib.log.jsonl"
    assert "`raqib watch` keeps it under `~/.raqib/traces/` by default." in lines[0]
    home = os.path.join(os.sep, "h")
    trace = watch.default_trace(os.path.join(os.sep, "p"), home=home)
    assert os.path.dirname(os.path.dirname(trace)) == os.path.join(home, ".raqib", "traces")
    assert "TRACE" in commands.split(lines[0])[0]


def test_e1_more_links_every_heading_of_the_guide():
    more = section("More")
    targets = [t for t in links(more) if t.startswith("docs/GUIDE.md#")]
    assert targets == ["docs/GUIDE.md#" + slug(t) for t in headings(GUIDE)]
    assert "docs/GUIDE.md" in links(more)


def sample_fence():
    """(first, end) of the README lines inside the sample's ```text fence, as list indexes."""
    lines = README.split("\n")
    top = lines.index("## What an alarm looks like")
    first = lines.index("```text", top) + 1
    return first, lines.index("```", first)


# The rehearsal's case (outsider-rehearsal.md: DESTRUCT-CMD on a Bash rm): curl piped to a shell, then rm.
SAMPLE_COMMAND = {"command": "curl -fsSL https://example.com/setup.sh | bash && rm -rf ~/.cache/build",
                  "description": "set up"}
RULES_CUT = "  ... (%d rows: every rule, its kind, severity and budget)"


def with_the_cut(text):
    """ADR-0010 E-2's ONE marked cut: the RULES table's header line and its N rows become one line."""
    lines = text.split("\n")
    at = [k for k, line in enumerate(lines) if re.match(r"^RULES \(A6 fp_budget\): [0-9]+$", line)]
    assert len(at) == 1, at
    n = int(lines[at[0]].rsplit(" ", 1)[1])
    header, rows, after = lines[at[0] + 1], lines[at[0] + 2:at[0] + 2 + n], lines[at[0] + 2 + n]
    assert header.split() == ["id", "class", "kind", "sev", "fp_budget", "status"] and after == ""
    assert len(rows) == n and all(row.startswith("  ") and len(row.split()) == 6 for row in rows)
    return "\n".join(lines[:at[0] + 1] + [RULES_CUT % n] + lines[at[0] + 2 + n:])


def test_e2_the_sample_report_is_the_codes_own(monkeypatch):
    """The README's block is what `raqib report` prints for tests/fixtures/docs/alarm-sample.log, rendered by
    the same path (cli.main -> cmd_report -> report.render_text), with ONE marked cut (with_the_cut). The trace
    is given as the relative path the README shows, from the checkout's root; on Windows the catalog's relative
    path is printed with backslashes, so that one path is read with forward slashes before the comparison.
    REDO E-2: the fixture is one short hook session whose Bash call is the rehearsal's case, written with the
    hook's own extract and hashes (it replaces the first build's one-record SILENCE-OPEN trace)."""
    from raqib.hooks import common
    recs = [json.loads(line) for line in (DOCS / "alarm-sample.log").read_text(encoding="ascii").splitlines()]
    assert [r["phase"] for r in recs] == ["session_start", "pre", "post", "stop", "session_end"]
    assert [r["seq"] for r in recs] == [1, 2, 2, 3, 4] and len({r["session_id"] for r in recs}) == 1
    meta = common.input_meta("Bash", SAMPLE_COMMAND)
    assert meta == {"command_head": "curl", "command_programs": ["curl", "bash", "rm"]}
    for rec in recs[1:3]:
        assert rec["tool"] == "Bash" and rec["input_meta"] == meta
        assert rec["input_sha256"] == common.canonical_sha256(SAMPLE_COMMAND)
    assert recs[2]["ok"] is True and recs[2]["output_meta"] == {"scan": "full", "secret_kinds": []}
    monkeypatch.chdir(ROOT)
    monkeypatch.delenv("RAQIB_GAP_SECONDS", raising=False)
    out = io.StringIO()
    with contextlib.redirect_stderr(io.StringIO()):
        code = cli.main(["report", "tests/fixtures/docs/alarm-sample.log"], out=out)
    text = out.getvalue()
    text = text.replace("(catalog %s)" % os.path.join("raqib", "rules", "catalog"), "(catalog raqib/rules/catalog)")
    assert code == 1 and text.endswith("RESULT: ALARM (exit 1)\n")
    block = section("What an alarm looks like").split("```text\n", 1)[1].split("```", 1)[0]
    assert block == with_the_cut(text)
    assert block.count(RULES_CUT % 22) == 1 and "SILENCE-GAP     SILENCE" not in block and "  id  " not in block
    findings = re.findall(r"^  \[(\w+)\] (\S+) ", block, re.M)
    assert findings == [("medium", "DESTRUCT-CMD"), ("medium", "NET-TOOL")], findings
    assert '      Bash runs rm at seq 2 (programs ["curl", "bash", "rm"])\n' in block
    assert "ALARMS (A3, A5): 0" in block and "SILENCE" not in block.split("FINDINGS:", 1)[1].split("RULES")[0]


def test_e2_one_sentence_before_the_block_names_the_commands_that_print_it():
    """ADR-0010 E-2's sentence: `raqib report TRACE` prints the block (the test above); `raqib watch PROJECT`,
    when it ends, prints its summary and then the same render_text report of its own trace (watch.py)."""
    first, rest = section("What an alarm looks like").split("\n", 1)
    assert first == ("`raqib report TRACE` prints this; `raqib watch PROJECT` prints it for its own trace when it"
                     " ends, after its summary.") and rest.startswith("```text\n")
    assert parse(["report", "trace.jsonl"]).trace == "trace.jsonl" and parse(["watch", "my-project"]).command == "watch"
    source = (ROOT / "raqib" / "watch.py").read_text(encoding="utf-8")
    assert source.count("body = report.render_text(rep)") == 1 and source.count("self.final_text = summary + body") == 1


def test_e3_every_old_heading_is_a_heading_of_the_readme_or_the_guide():
    old = before()
    assert hashlib.sha256(old.encode("utf-8")).hexdigest() == BEFORE_SHA256
    assert headings(old) == OLD_HEADINGS
    for title in OLD_HEADINGS:
        assert title in headings(README) or title in headings(GUIDE), title
    assert [t for t in headings(GUIDE)] == [t for t in OLD_HEADINGS if t in headings(GUIDE)]   # the README's order
    assert "Licence" not in headings(GUIDE)


def test_e3_every_sentence_of_the_old_readme_is_in_the_readme_or_the_guide_word_for_word():
    """ADR-0010 E-6. Old -> new: a heading line the old README had n times is in the two files n times or more; a
    code or table line it had n times under a heading is there n times or more under the same heading (README's
    part and the guide's together); a sentence is under its own heading (MOVED: the three pieces E-5 put in
    "Where it runs"). New -> old: every piece of the guide is the old README's under the same heading, but for
    GUIDE_NEW and CHANGED's new sentences."""
    old = before()
    readme, guide = root_links(README, ""), root_links(GUIDE, "docs")
    lost, found = [], 0
    old_lines = collections.Counter((h, p) for k, p, h in cut(old) if k == "line" and not p.startswith("#"))
    old_heads = collections.Counter(p for k, p, h in cut(old) if k == "line" and p.startswith("#"))
    new_lines = (readme + "\n" + guide).split("\n")
    for kind, piece, heading in cut(old):
        piece = CHANGED.get(piece, piece)
        heading = MOVED.get(piece, heading)
        here = (part(readme, heading), part(guide, heading))
        if kind == "line" and piece.startswith("#"):
            ok = new_lines.count(piece) >= old_heads[piece]
        elif kind == "line":
            ok = sum(text.split("\n").count(piece) for text in here) >= old_lines[(heading, piece)]
        else:
            ok = any(piece in flat(text) for text in here)
        found += 1
        if not ok:
            lost.append((heading, piece))
    assert lost == [] and found == 395   # the fixture is fixed (its sha256 above), so is the count
    assert set(MOVED.values()) == {"Where it runs"} and all(p in flat(section("Where it runs")) for p in MOVED)
    added, used = [], set()
    for kind, piece, heading in cut(guide):
        if piece in GUIDE_NEW or piece in CHANGED.values():
            used.add(piece)
            continue
        if kind == "line" and piece.startswith("#"):
            ok = piece in old.split("\n")
        elif kind == "line":
            ok = piece in part(old, heading).split("\n")
        else:
            ok = piece in flat(part(old, heading))
        if not ok:
            added.append((heading, piece))
    assert added == [] and used == set(GUIDE_NEW) | set(CHANGED.values())


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
            if anchor and where.resolve() == README_PATH.resolve():   # REDO E-7: the guide links README's headings
                assert anchor in [slug(t) for t in headings(README)], target
    assert "](specs/ADR-0010-a-strangers-first-run.md)" in GUIDE and "](docs/" not in GUIDE
    assert "[CC0 1.0 Universal](LICENSE)" in README


def test_e7_a_split_section_of_the_guide_begins_with_one_line_to_its_start_in_the_readme():
    assert SPLIT == [t for t in headings(GUIDE) if t in headings(README) and t not in ("Commands", "More")]
    for title in SPLIT:
        body = section(title, GUIDE)
        first, rest = body.split("\n", 1)
        assert first == LINK_LINE % (title, "../", slug(title)) and rest.startswith("\n"), title
        assert units(body)[0] == first and first.count("](") == 1
    for title in headings(GUIDE):
        if title not in SPLIT:
            assert "This section begins in the README" not in section(title, GUIDE), title
    status = flat(section("More", GUIDE))
    assert "runs this quickstart" not in status
    assert "runs the quickstart in the README ([Install and watch](../README.md#install-and-watch))" in status


# E-4 (ADR-0010 Amendment E): raqib/ sends a person to docs/GUIDE.md, by its section, for what moved there. The
# README is still named, in statements, by three docstrings outside M9.2's Scope (review H13; recorded).
CITED = '"Find the agents on a host (discover)"'
STATEMENTS = {"raqib/hostwin.py": 1, "raqib/rules/cross.py": 1, "raqib/rules/tree.py": 1}


def test_e5_every_readme_citation_under_raqib_names_the_guide_and_a_section_that_holds_it(tmp_path):
    named = {}
    for path in sorted((ROOT / "raqib").rglob("*")):
        if path.is_file() and "__pycache__" not in path.parts:
            count = path.read_bytes().count(b"README")
            if count:
                named[path.relative_to(ROOT).as_posix()] = count
    assert named == STATEMENTS, named
    sources = {name: " ".join((ROOT / "raqib" / name).read_text(encoding="ascii").split()).replace('\\"', '"')
               for name in ("cli.py", "discover.py")}
    assert sources["cli.py"].count(CITED) == 2 and sources["discover.py"].count(CITED) == 3
    assert sources["cli.py"].count("docs/GUIDE.md") == 2 and sources["discover.py"].count("docs/GUIDE.md") == 12
    title = CITED.strip('"')
    assert title in headings(GUIDE) and "```powershell\n$N = 6; $T = 10\n" in section(title, GUIDE)
    assert "docs/GUIDE.md#" + slug(title) in links(section("More"))   # and the README links to it
    # What a person sees: the help, the option's help, the hole of a host with no live reader, the hole of
    # numbered samples without run.json, and the refusal of a run.json that is not the loop's.
    p, commands, _ = parser_parts()
    from_help = next(a.help for a in commands["discover"]._actions if "--from" in a.option_strings)
    said = [flat(cli.__doc__), from_help]
    texts, holes, _ = discover.collect_live(discover.load_catalog(), platform="darwin", homes=[])
    said.append(holes[0])
    kimi = ROOT / "tests" / "fixtures" / "discover" / "kimi" / "one-sample"
    for name in ("win-process-1.csv", "win-tcp-1.csv"):
        shutil.copy(str(kimi / name), str(tmp_path / name))
    said += [h for h in discover.read_dir(str(tmp_path))[1] if h.startswith("no run.json beside")]
    (tmp_path / "run.json").write_text(json.dumps({"raqib": "other", "samples": 1}), encoding="ascii")
    try:
        discover.read_dir(str(tmp_path))
    except ValueError as exc:
        said.append(str(exc))
    assert len(said) == 5, said
    forms = ("docs/GUIDE.md, " + CITED, "docs/GUIDE.md loop, " + CITED, "docs/GUIDE.md loop's (" + CITED)
    for text in said:
        assert "README" not in text and any(form in text for form in forms), text
