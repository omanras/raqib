"""M17.2a (ADR-0007 Amendment CG-1, CG-2): the helper's word, taken by Raqib's entry before anything else.

A packed Raqib's helper is the packed program with one fixed word (raqib/procevents.py WORD); raqib/cli.py main
takes it before it reads anything else of its arguments. The word is no command of a person's: it is in no help
text, no usage line and not in the guide's table of commands."""
import io
import signal
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from raqib import cli, procevents  # noqa: E402

WORD = procevents.WORD


def test_cg1_the_entry_given_the_word_alone_serves_before_it_reads_anything_else(monkeypatch):
    served = []
    monkeypatch.setattr(procevents, "serve", lambda *a, **k: served.append((a, k)) or 0)
    monkeypatch.setattr(cli, "_parser", lambda: pytest.fail("the parser was asked for the helper's word"))

    class Out(io.StringIO):
        def reconfigure(self, **kw):
            pytest.fail("the output was set up for the helper's word")
    monkeypatch.setattr(sys, "stdout", Out())
    before = signal.getsignal(signal.SIGINT)
    try:
        assert cli.main([WORD]) == 0 and served == [((), {})]
        assert signal.getsignal(signal.SIGINT) == signal.SIG_IGN
        monkeypatch.setattr(sys, "argv", ["/opt/raqib.example/raqib", WORD])   # the packed program's own argv
        assert cli.main() == 0 and len(served) == 2
    finally:
        signal.signal(signal.SIGINT, before)
    assert sys.stdout.getvalue() == ""


def test_cg1_the_word_with_anything_after_it_is_a_usage_error_exit_2(monkeypatch, capsys):
    monkeypatch.setattr(procevents, "serve", lambda *a, **k: pytest.fail("served with more arguments"))
    for more in ([WORD, "watch"], [WORD, "--help"], [WORD, WORD], [WORD, ""]):
        assert cli.main(more, out=io.StringIO()) == 2
        got = capsys.readouterr()
        assert got.out == "" and got.err == "raqib: %s\n" % procevents.WORD_USAGE and WORD not in got.err


def test_cg1_any_other_first_argument_goes_on_as_it_always_did(monkeypatch, capsys):
    monkeypatch.setattr(procevents, "serve", lambda *a, **k: pytest.fail("served without the word"))
    out = io.StringIO()
    assert cli.main(["--version"], out=out) == 0 and out.getvalue() == cli.version_line() + "\n"
    assert cli.main(["watch", WORD], out=io.StringIO()) == 2   # the word after a command is no word of the entry's
    capsys.readouterr()


def _helps():
    """Every help text of the parser: the top's and each command's."""
    parser = cli._parser()
    out = [parser.format_help(), parser.format_usage()]
    for action in parser._actions:
        for sub in (getattr(action, "choices", None) or {}).values():
            if hasattr(sub, "format_help"):
                out += [sub.format_help(), sub.format_usage()]
    return out


def test_cg2_the_word_is_in_no_help_text_no_usage_line_and_not_in_the_guides_table(capsys):
    assert cli.main(["--help"], out=io.StringIO()) == 0
    got = capsys.readouterr()
    assert got.out.startswith("usage: raqib ") and WORD not in got.out + got.err
    assert cli.main([], out=io.StringIO()) == 2   # `raqib` alone: its usage, exit 2
    got = capsys.readouterr()
    assert "usage: raqib " in got.err and WORD not in got.out + got.err
    helps = _helps()
    assert len(helps) > 20 and not [h for h in helps if WORD in h]
    assert WORD not in (cli.__doc__ or "") and WORD not in procevents.WORD_USAGE
    guide = (ROOT / "docs" / "GUIDE.md").read_text(encoding="utf-8")
    table = guide[guide.index("## Commands"):]
    assert "| Command | Does |" in table and WORD not in guide


def test_cg2_procevents_spec_says_the_packed_road_the_word_and_that_by_hand_it_serves_until_its_input_ends():
    spec = " ".join((ROOT / "docs" / "specs" / "PROC-EVENTS.md").read_text(encoding="utf-8").split())
    assert "`%s`" % WORD in spec and "sys.frozen" in spec
    assert "run by hand it serves until its input ends" in spec.lower()


def test_cg1_the_test_is_ascii():
    assert (ROOT / "tests" / "test_cli_word.py").read_text(encoding="utf-8").isascii()
