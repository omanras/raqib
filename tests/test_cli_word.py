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

from raqib import cli, own, procevents  # noqa: E402

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


# --- M17.2b E4 (ADR-0007 CI-3): packed and on Windows, the entry puts the folder searched first back ---------------
class Log(list):
    pass


def _entry_with(monkeypatch, result, frozen, platform):
    """cli.main's call of own.library_folder, run for real with a stand-in of SetDllDirectoryW and a made-up
    frozen state and system; [what was called, in order]."""
    monkeypatch.setattr(own, "LIBRARY_FOLDER", None)
    log = Log()
    real = own.library_folder

    def call(folder):
        log.append(("SetDllDirectoryW", folder))
        if isinstance(result, BaseException):
            raise result
        return result
    def entry_call(given):   # main gives the system's call; a stand-in takes its place here
        log.append("library_folder")
        entry_call.given = given
        return real(call, frozen=frozen, platform=platform)
    monkeypatch.setattr(own, "library_folder", entry_call)
    log.entry, log.real = entry_call, real
    parser = cli._parser
    monkeypatch.setattr(cli, "_parser", lambda: log.append("parser") or parser())
    return log


@pytest.mark.parametrize("result", [1, 0, OSError(5, "Access is denied"), RuntimeError("a stand-in that raises")])
def test_ci3_packed_on_windows_main_calls_it_once_after_the_word_before_anything_else(result, monkeypatch):
    log = _entry_with(monkeypatch, result, True, "win32")
    out = io.StringIO()
    assert cli.main(["--version"], out=out) == 0 and out.getvalue() == cli.version_line() + "\n"
    assert log == ["library_folder", ("SetDllDirectoryW", None), "parser"]   # before the parser and the output
    assert callable(log.entry.given)
    if result == 1:
        assert own.LIBRARY_FOLDER is True and own.library_folder_hole() is None
    else:   # 0 or what it raised: a result, kept for the watch to say, never an exception out of main
        assert isinstance(own.LIBRARY_FOLDER, str) and own.library_folder_hole().startswith(
            "what the watch starts searches the packed program's folder first for its libraries")


@pytest.mark.parametrize("frozen,platform", [(False, "win32"), (True, "linux"), (True, "darwin"), (False, "linux")])
def test_ci3_not_called_where_plain_where_linux_where_macos(frozen, platform, monkeypatch):
    log = _entry_with(monkeypatch, 1, frozen, platform)
    assert cli.main(["--version"], out=io.StringIO()) == 0
    assert log == ["library_folder", "parser"] and own.LIBRARY_FOLDER is None


def test_ci3_the_helpers_word_is_taken_first_and_the_call_is_not_made_for_it(monkeypatch):
    log = _entry_with(monkeypatch, 1, True, "win32")
    monkeypatch.setattr(procevents, "serve", lambda *a, **k: 0)
    before = signal.getsignal(signal.SIGINT)
    try:
        assert cli.main([WORD]) == 0
    finally:
        signal.signal(signal.SIGINT, before)
    assert log == [] and own.LIBRARY_FOLDER is None


@pytest.mark.skipif(sys.platform == "win32", reason="off Windows the system's call cannot be reached: a result")
def test_ci3_the_call_main_gives_reached_off_windows_is_a_result_never_an_exception(monkeypatch):
    log = _entry_with(monkeypatch, 1, False, "win32")
    assert cli.main(["--version"], out=io.StringIO()) == 0 and own.LIBRARY_FOLDER is None
    said = log.real(log.entry.given, frozen=True, platform="win32")   # main's own call, given for real
    assert isinstance(said, str) and said.startswith("SetDllDirectoryW(NULL) failed: ") and said.isascii()
