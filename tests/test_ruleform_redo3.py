"""M8.2 REDO 3 (ADR-0009 Amendment G, G-1..G-8): each ruling's case FOR and the case it MUST NOT TOUCH (Z-9).
A test that depends on the system that runs it asks that system first and skips, with the reason, before it
makes anything the system cannot make (G-1); the Tk tests (test_tk*) end what they start (conftest), and a key
reaches a widget only through app.KEYS."""
import io
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from raqib import app, cli, overlay, ruleform  # noqa: E402
from raqib.rules import fixtures  # noqa: E402
import test_ruleform_redo2 as redo2  # noqa: E402

FIX = ROOT / "tests" / "fixtures" / "rules"
BOUNDS = "the newest 20 files, at most 20,000 lines in all and 4 MB of each"
NEVER = "information only, never a gate"


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    path = tmp_path / "home"
    path.mkdir()
    monkeypatch.setenv("HOME", str(path))
    monkeypatch.setenv("USERPROFILE", str(path))
    overlay._MEASURED.clear()
    yield path
    overlay._MEASURED.clear()


def ans(when="program", rid="MY-X", values="terraform", fires="terraform", quiet="ls", **kw):
    a = {"id": rid, "when": when, "values": values, "severity": "medium", "fires": fires, "quiet": quiet}
    a.update(kw)
    return a


def rules_d(home):
    d = Path(overlay.user_dir(str(home)))
    return sorted(p.name for p in d.iterdir()) if d.is_dir() else []


def files_under(path):
    return sorted(str(p.relative_to(path)) for p in Path(path).rglob("*"))


def run_cli(argv, capsys):
    out = io.StringIO()
    code = cli.main(argv, out=out)
    return code, out.getvalue(), capsys.readouterr().err


def junction(target, link):
    """G-5: on Windows a real junction (_winapi.CreateJunction, what mklink /J makes; it needs no privilege),
    whether or not this job can make symlinks; elsewhere a symlink. None, or why it could not be made (the
    test skips with it, before anything else is made)."""
    if os.name == "nt":
        try:
            import _winapi
            _winapi.CreateJunction(str(target), str(link))
            return None
        except Exception as exc:   # noqa: BLE001 - said in the skip
            return "no junction can be made here (%s)" % exc
    try:
        os.symlink(str(target), str(link), target_is_directory=True)
        return None
    except (OSError, NotImplementedError) as exc:
        return "no symlink can be made here (%s)" % exc


def keeps_both(directory, made, other):
    """G-1: asks the file system - with `made` already in directory, is `other` (the same name a case apart)
    a second name here? Nothing is made by asking."""
    return not os.path.lexists(os.path.join(str(directory), other))


def entry_of(home):
    doc, _, _ = overlay.read(overlay.overlay_path(str(home)))
    return doc["rules"]


# --- G-1: a test of two names a case apart asks the file system first -----------------------------------------

def test_redo3_g1_for_a_file_system_that_folds_case_the_test_skips_before_it_makes_the_second(home, monkeypatch):
    made, real_mkdir, real_lexists = [], Path.mkdir, os.path.lexists

    def mkdir(self, *a, **k):
        made.append(self.name)
        return real_mkdir(self, *a, **k)

    def folds(path):   # a file system that folds case, as NTFS does: my-tf is the folder MY-TF
        p = str(path)
        if os.path.basename(p) == "my-tf":
            return real_lexists(os.path.join(os.path.dirname(p), "MY-TF"))
        return real_lexists(p)
    monkeypatch.setattr(Path, "mkdir", mkdir)
    monkeypatch.setattr(os.path, "lexists", folds)
    with pytest.raises(pytest.skip.Exception, match="this file system folds case"):
        redo2.test_redo2_f3_for_two_folders_a_case_apart(home)
    assert "my-tf" not in made and rules_d(home) == ["MY-TF"]   # skipped before it made anything more


def test_redo3_g1_must_not_touch_a_file_system_that_keeps_both_runs_the_test(home):
    assert ruleform.add(ans(rid="MY-PROBE"), str(home)).ok
    if not keeps_both(overlay.user_dir(str(home)), "MY-PROBE", "my-probe"):
        pytest.skip("this file system folds case: the case-apart test skips here (its FOR case above)")
    for name in rules_d(home):   # a fresh rules.d for the test itself
        overlay.remove_rule(name, home=str(home), place=name)
    redo2.test_redo2_f3_for_two_folders_a_case_apart(home)   # runs whole: no skip
    assert rules_d(home) == ["MY-TF"]


# --- G-2: the terminal removes what was named, never a neighbour of it ----------------------------------------

def test_redo3_g2_for_a_file_name_with_no_such_file_removes_nothing(home, capsys):
    assert ruleform.add(ans(rid="MY-TF"), str(home)).ok
    overlay.set_status("MY-TF", "off", home=str(home))
    before = files_under(overlay.user_dir(str(home)))
    for name in ("MY-TF.yaml", "my-tf.yaml", "MY-TF.yml"):   # a file is named: a folder is never taken for it
        code, _, err = run_cli(["rules", "--remove", name], capsys)
        assert code == 2 and "no loose rule file %s in %s: nothing removed" % (name, overlay.user_dir(str(home))) \
            in err, err
    assert files_under(overlay.user_dir(str(home))) == before and entry_of(home)["MY-TF"]["status"] == "off"


def test_redo3_g2_for_a_stem_is_never_matched_across_kinds(home, capsys):
    d = Path(overlay.user_dir(str(home)))
    d.mkdir(parents=True)
    loose = d / "MY-LOOSE.yaml"
    loose.write_text("id: MY-LOOSE\n")
    code, _, err = run_cli(["rules", "--remove", "MY-LOOSE"], capsys)   # a folder is named: the file stays
    assert code == 2 and "no rule folder MY-LOOSE in" in err and loose.exists()
    code, out, _ = run_cli(["rules", "--remove", "my-loose.YAML"], capsys)   # a file, in any case: that file
    assert code == 0 and "MY-LOOSE.yaml removed" in out and not loose.exists()


def test_redo3_g2_for_several_of_one_kind_are_refused_all_listed_none_suggested(home, capsys):
    d = Path(overlay.user_dir(str(home)))
    d.mkdir(parents=True)
    (d / "MY-A.yaml").write_text("id: MY-A\n")
    if not keeps_both(d, "MY-A.yaml", "my-a.yaml"):
        pytest.skip("this file system folds case: MY-A.yaml and my-a.yaml cannot both be kept here")
    (d / "my-a.yaml").write_text("id: MY-A\n")
    code, _, err = run_cli(["rules", "--remove", "My-A.yaml"], capsys)
    assert code == 2 and "My-A.yaml matches 2 loose rule files of" in err and "MY-A.yaml, my-a.yaml" in err
    assert "raqib rules --remove " not in err and rules_d(home) == ["MY-A.yaml", "my-a.yaml"]   # none suggested


def test_redo3_g2_for_q10_a_folder_named_as_a_package_rule_is_removed_the_package_rule_untouched(home, capsys):
    overlay.set_status("NET-TOOL", "off", home=str(home))
    folder = Path(overlay.user_dir(str(home))) / "NET-TOOL"
    folder.mkdir(parents=True)
    (folder / "NET-TOOL.yaml").write_text("id: NET-TOOL\n")
    code, _, err = run_cli(["rules", "--remove", "NET-TOOL.yaml"], capsys)   # a file is named: the folder stays
    assert code == 2 and "no loose rule file NET-TOOL.yaml" in err and folder.is_dir()
    code, out, _ = run_cli(["rules", "--remove", "NET-TOOL"], capsys)   # exactly that name: that folder
    assert code == 0 and "NET-TOOL removed: no rule loaded from it" in out
    assert "the package rule NET-TOOL is untouched" in out and not folder.exists()
    assert entry_of(home)["NET-TOOL"]["status"] == "off"   # the package rule's own setting is never dropped
    assert next(r for r in overlay.load(str(home)) if r.id == "NET-TOOL").status == "disabled"


def test_redo3_g2_must_not_touch_one_loaded_rule_and_a_package_id_with_no_entry(home, capsys):
    assert ruleform.add(ans(), str(home)).ok
    code, out, _ = run_cli(["rules", "--remove", "MY-X"], capsys)
    target = os.path.join(overlay.user_dir(str(home)), "MY-X")
    assert code == 0 and out.startswith("raqib rules: MY-X removed: it had no entry in %s; %s deleted (7 file(s));"
                                        " %s\n" % (overlay.overlay_path(str(home)), target, overlay.NEXT_WATCH))
    code, _, err = run_cli(["rules", "--remove", "NET-TOOL"], capsys)   # refused as before
    assert code == 2 and overlay.REMOVE_PACKAGE % ("NET-TOOL", "NET-TOOL") in err


# --- G-3: "on your records" never says more than it read ------------------------------------------------------

def _write(path, records, mtime=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r) + "\n" for r in records))
    if mtime is not None:
        os.utime(str(path), (mtime, mtime))


def _bash(head, seq=1):
    return redo2.line("Bash", {"command_head": head}, seq=seq)


def test_redo3_g3_for_a_linked_folder_beside_a_readable_trace_is_not_every_file(home, tmp_path):
    traces = Path(overlay.raqib_dir(str(home))) / "traces"
    _write(traces / "demo" / "raqib.log.jsonl", [_bash("ls")])
    outside = tmp_path / "outside"
    _write(outside / "x.jsonl", [_bash("terraform")])
    why = junction(outside, traces / "x")
    if why:
        pytest.skip(why)
    text = ruleform.records_text(ruleform.test(ans(), str(home)).records)
    assert text == ("on your records: would have fired on 0 of 1 line in 1 file; read: not every file (%s); 1 folder"
                    " not read: a link; %s" % (BOUNDS, NEVER)), text


def test_redo3_g3_for_the_file_bound_is_said_when_no_file_was_judged(home):
    traces = Path(overlay.raqib_dir(str(home))) / "traces"
    host_lines, _, _ = fixtures.load_fixture(FIX / "NET-TOOL" / "positive-host-child.json")
    for i in range(5):   # the older five: traces a path rule would read
        _write(traces / ("old-%d" % i) / "raqib.log.jsonl", [_bash("ls")], mtime=1000000000 + i)
    for i in range(20):   # the newest twenty hold host lines (under traces/: called by what they hold)
        _write(traces / ("host-%02d" % i) / "raqib.log.jsonl", host_lines, mtime=1100000000 + i)
    fires, quiet = ruleform.examples("path", "/srv/data", redo2.POSIX)
    res = ruleform.test(ans(when="path", values="/srv/data", fires=fires, quiet=quiet), str(home), where=redo2.POSIX)
    text = ruleform.records_text(res.records)
    assert text == ("on your records: no file was judged (it would read %s); 20 files of host lines not judged: a watch"
                    " gives host lines only to a rule that reads HostChild lines; 5 older files not read (the newest"
                    " 20 only); %s" % (BOUNDS, NEVER)), text


def test_redo3_g3_for_a_linked_traces_folder_is_one_folder_not_read(home, tmp_path):
    outside = tmp_path / "outside"
    _write(outside / "demo" / "raqib.log.jsonl", [_bash("terraform")])
    Path(overlay.raqib_dir(str(home))).mkdir(parents=True)
    why = junction(outside, Path(overlay.raqib_dir(str(home))) / "traces")
    if why:
        pytest.skip(why)
    text = ruleform.records_text(ruleform.test(ans(), str(home)).records)
    assert text == "on your records: no file was judged (it would read %s); 1 folder not read: a link; %s" % (
        BOUNDS, NEVER), text


def test_redo3_g3_for_each_bound_met_is_said(home):
    traces = Path(overlay.raqib_dir(str(home))) / "traces"
    _write(traces / "a" / "raqib.log.jsonl", [_bash("terraform", 1), _bash("ls", 2)], mtime=1100000000)
    _write(traces / "b" / "raqib.log.jsonl", [_bash("ls", 1)], mtime=1000000000)
    rule = ruleform.test(ans(), str(home)).rule
    capped = ruleform.records_text(ruleform.on_records(rule, str(home), max_lines=1))
    assert "read: not every file (" in capped and "2 files read in part or not at all: the cap of 1 line was met" \
        in capped, capped
    big = ruleform.records_text(ruleform.on_records(rule, str(home), max_bytes=40))
    assert "read: not every file (" in big and "2 files read only in their last 4e-05 MB" in big, big


def test_redo3_g3_must_not_touch_nothing_refused_and_no_bound_met(home):
    traces = Path(overlay.raqib_dir(str(home))) / "traces"
    assert ruleform.records_text(ruleform.test(ans(), str(home)).records) == (
        "on your records: no trace or host source file under ~/.raqib this rule would read yet, nothing to run it on"
        " (it would read %s)" % BOUNDS)
    _write(traces / "demo" / "raqib.log.jsonl", [_bash("terraform", 1), _bash("ls", 2)])
    text = ruleform.records_text(ruleform.test(ans(), str(home)).records)
    assert text == "on your records: would have fired on 1 of 2 lines in 1 file; read: every file (%s); %s" % (
        BOUNDS, NEVER), text


# --- G-5: Remove never walks into a link; whatever fails is a refusal with words ------------------------------

def _rule_with_sub(home):
    assert ruleform.add(ans(), str(home)).ok
    folder = Path(overlay.user_dir(str(home))) / "MY-X"
    (folder / "sub" / "deeper").mkdir(parents=True)
    (folder / "sub" / "deeper" / "note.txt").write_text("x")
    return folder


def record_listing(monkeypatch):
    """Every directory listed (os.listdir, os.scandir - what os.walk calls) while a removal is planned."""
    listed, real_listdir, real_scandir = [], os.listdir, os.scandir

    def listdir(path="."):
        listed.append(str(path))
        return real_listdir(path)

    def scandir(path="."):
        listed.append(str(path))
        return real_scandir(path)
    monkeypatch.setattr(os, "listdir", listdir)
    monkeypatch.setattr(os, "scandir", scandir)
    return listed


def test_redo3_g5_for_a_reparse_point_os_walk_does_not_see_as_a_link_is_never_entered(home, monkeypatch):
    """On every system: a directory only the reparse check knows as a link (as os.walk(followlinks=False) does
    not know a junction) is refused before the walk enters it."""
    folder = _rule_with_sub(home)
    fake = folder / "sub" / "reparse"
    (fake / "inner").mkdir(parents=True)
    (fake / "inner" / "precious.txt").write_text("x")
    real_is_link = overlay._is_link
    before = files_under(folder)
    with monkeypatch.context() as m:   # S13: the autouse HOME stays patched; only these are undone
        m.setattr(overlay, "_is_link", lambda path: os.path.normcase(str(path)) == os.path.normcase(
            str(fake)) or real_is_link(path))
        listed = record_listing(m)
        with pytest.raises(overlay.OverlayError) as err:
            overlay.remove_rule("MY-X", home=str(home))
    assert str(err.value) == "%s is a link: nothing removed (remove it by hand)" % fake
    assert not [p for p in listed if os.path.normcase(p).startswith(os.path.normcase(str(fake)))], listed
    assert files_under(folder) == before


def test_redo3_g5_for_a_junction_inside_a_rule_folder_is_refused_by_its_own_name(home, tmp_path, capsys,
                                                                                  monkeypatch):
    outside = tmp_path / "outside"
    (outside / "inner").mkdir(parents=True)
    (outside / "precious.txt").write_text("x")
    folder = _rule_with_sub(home)
    link = folder / "sub" / "linked"
    why = junction(outside, link)
    if why:
        pytest.skip(why)
    before = files_under(folder)
    listed = record_listing(monkeypatch)
    words = "%s is a link: nothing removed (remove it by hand)" % link
    with pytest.raises(overlay.OverlayError) as err:
        overlay.remove_rule("MY-X", home=str(home))
    assert str(err.value) == words and "precious" not in str(err.value)
    assert not [p for p in listed if p.startswith(str(link))]   # looked at before it was entered: never entered
    code, _, err = run_cli(["rules", "--remove", "MY-X"], capsys)
    assert code == 2 and words in err and "Traceback" not in err
    panel = app.RulesPanel(home=str(home))
    assert panel.remove_rule("MY-X", place="MY-X") == "REFUSED: " + words and panel.level == "alarm"
    assert files_under(folder) == before and (outside / "precious.txt").read_text() == "x"   # nothing deleted


def test_redo3_g5_for_a_path_on_another_drive_is_a_refusal(home, capsys, monkeypatch):
    folder = _rule_with_sub(home)
    before = files_under(folder)

    def other_drive(paths):
        raise ValueError("Paths don't have the same drive")
    assert overlay._inside("/a", "/a/b") is True
    monkeypatch.setattr(overlay.os.path, "commonpath", other_drive)
    assert overlay._inside("C:\\x", "D:\\x") is False   # never the exception
    with pytest.raises(overlay.OverlayError, match="resolves outside .*: nothing removed"):   # the walk's own check
        overlay._tree_plan(str(folder), overlay.user_dir(str(home)))
    with pytest.raises(overlay.OverlayError, match="nothing removed"):
        overlay.remove_rule("MY-X", home=str(home))
    code, _, err = run_cli(["rules", "--remove", "MY-X"], capsys)
    assert code == 2 and err.startswith("raqib: refused: ") and "nothing removed" in err and "Traceback" not in err
    panel = app.RulesPanel(home=str(home))
    assert panel.remove_rule("MY-X", place="MY-X").startswith("REFUSED: ") and panel.level == "alarm"
    assert files_under(folder) == before


def test_redo3_g5_for_an_entry_that_cannot_be_read_is_a_refusal_in_remove_and_in_the_rows(home, capsys,
                                                                                         monkeypatch):
    folder = _rule_with_sub(home)
    (Path(overlay.user_dir(str(home))) / "MY-OLD.yaml").write_text("id: MY-OLD\n")   # a refused row
    before = files_under(folder)
    real_listdir = os.listdir

    def denied(path="."):
        if os.path.basename(str(path)) == "sub":
            raise PermissionError(13, "Permission denied", str(path))
        return real_listdir(path)
    with monkeypatch.context() as m:   # S13: the autouse HOME stays patched; only this is undone
        m.setattr(overlay.os, "listdir", denied)
        with pytest.raises(overlay.OverlayError) as err:
            overlay.remove_rule("MY-X", home=str(home))
        assert str(err.value) == "nothing removed: the removal could not be checked: %s cannot be read or" \
            " changed (Permission denied)" % (folder / "sub")
        code, _, err = run_cli(["rules", "--remove", "MY-X", "--dry-run"], capsys)
        assert code == 2 and "dry run: the removal would be refused: nothing removed: the removal could not" in err
    assert files_under(folder) == before
    panel = app.RulesPanel(home=str(home))

    def unlistable(rules_d):
        raise PermissionError(13, "Permission denied", rules_d)
    monkeypatch.setattr(overlay, "user_entries", unlistable)
    rows = panel.refused_rows()   # drawing the rows: words, never a crash
    (item,) = [i for i in app.rule_items(rows) if i["id"] == "MY-OLD"]
    assert item["removable"] is False and "could not be listed (PermissionError" in item["no_remove"]

    def broken(*a, **k):
        raise RuntimeError("disk on fire")
    monkeypatch.setattr(overlay, "remove_rule", broken)
    assert panel.remove_rule("MY-X", place="MY-X") == \
        "REFUSED: the change could not be made: RuntimeError: disk on fire"


def test_redo3_g5_for_a_failure_while_deleting_that_is_no_oserror_is_said(home, monkeypatch):
    folder = _rule_with_sub(home)
    real_rmdir = os.rmdir

    def odd(path):
        raise ValueError("another drive")
    monkeypatch.setattr(overlay.os, "rmdir", odd)
    with pytest.raises(overlay.OverlayError) as err:
        overlay.remove_rule("MY-X", home=str(home))
    monkeypatch.setattr(overlay.os, "rmdir", real_rmdir)
    assert str(err.value).startswith("MY-X was not removed whole: stopped midway: ValueError: another drive; gone: ")
    assert "what remains: " in str(err.value) and folder.is_dir()


def test_redo3_g5_must_not_touch_a_folder_with_ordinary_sub_folders_is_removed_as_now(home):
    _rule_with_sub(home)
    said = overlay.remove_rule("MY-X", home=str(home))
    target = os.path.join(overlay.user_dir(str(home)), "MY-X")
    assert said == "MY-X removed: it had no entry in %s; %s deleted (8 file(s)); %s" % (
        overlay.overlay_path(str(home)), target, overlay.NEXT_WATCH)
    assert rules_d(home) == []


# --- G-6: the words of a Remove fit its case ---------------------------------------------------------------------

def test_redo3_g6_for_a_loose_file_that_cannot_be_deleted_is_not_a_folder(home, monkeypatch):
    d = Path(overlay.user_dir(str(home)))
    d.mkdir(parents=True)
    loose = d / "MY-OLD.yaml"
    loose.write_text("id: MY-OLD\n")

    def fails(path, *a, **k):
        raise OSError(13, "Permission denied")
    monkeypatch.setattr(overlay.os, "remove", fails)
    with pytest.raises(overlay.OverlayError) as err:
        overlay.remove_rule("MY-OLD.yaml", home=str(home))
    assert str(err.value) == "nothing was removed: %s could not be deleted (%s: Permission denied); the file is" \
        " as it was" % (loose, loose)
    assert "folder" not in str(err.value) and "overlay entry" not in str(err.value) and loose.exists()


def test_redo3_g6_for_a_folder_with_no_rule_file_is_never_said_to_no_longer_load(home, monkeypatch):
    old = Path(overlay.user_dir(str(home))) / "MY-OLD"
    old.mkdir(parents=True)
    for name in ("a.json", "b.json"):
        (old / name).write_text("{}")
    real, calls = os.remove, []

    def second_fails(path, *a, **k):
        calls.append(path)
        if len(calls) == 2:
            raise OSError(13, "Permission denied")
        return real(path, *a, **k)
    monkeypatch.setattr(overlay.os, "remove", second_fails)
    with pytest.raises(overlay.OverlayError) as err:
        overlay.remove_rule("MY-OLD", home=str(home))
    text = str(err.value)
    assert text.startswith("MY-OLD was not removed whole: stopped midway: ") and "removed:" not in text
    assert "no longer loads" not in text and "rule file" not in text and "what remains: %s" % calls[1] in text


def test_redo3_g6_for_an_overlay_entry_that_could_not_be_dropped_is_listed_with_what_remains(home, monkeypatch):
    assert ruleform.add(ans(), str(home)).ok
    overlay.set_status("MY-X", "off", home=str(home))

    def cannot(doc, home=None):
        raise overlay.OverlayError("cannot write %s: Read-only file system" % overlay.overlay_path(home))
    monkeypatch.setattr(overlay, "write", cannot)
    panel = app.RulesPanel(home=str(home))   # the window's Remove: under REFUSED, never "MY-X removed"
    said = panel.remove_rule("MY-X", place="MY-X")
    assert panel.level == "alarm" and said.startswith("REFUSED: MY-X was not removed whole: ") and \
        "REFUSED: MY-X removed" not in said
    text = said[len("REFUSED: "):]
    rule_file = os.path.join(overlay.user_dir(str(home)), "MY-X", "MY-X.yaml")
    assert text.startswith("MY-X was not removed whole: stopped midway: cannot write ") and "gone: %s;" % rule_file \
        in text
    assert "its entry MY-X in %s (its rule file is gone: it no longer loads)" % overlay.overlay_path(str(home)) in text
    assert entry_of(home)["MY-X"]["status"] == "off"   # the entry stays, and is said to remain


def test_redo3_g6_for_a_link_named_as_a_rule_is_said_as_a_link(home, tmp_path, capsys):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "keep.txt").write_text("x")
    d = Path(overlay.user_dir(str(home)))
    d.mkdir(parents=True)
    why = junction(elsewhere, d / "MY-LINK")
    if why:
        pytest.skip(why)
    words = "%s is a link, not a rule folder: nothing removed; remove the link by hand" % (d / "MY-LINK")
    code, _, err = run_cli(["rules", "--remove", "MY-LINK"], capsys)
    assert code == 2 and words in err
    panel = app.RulesPanel(home=str(home))
    (item,) = [i for i in app.rule_items(panel.rows + panel.refused_rows()) if i["id"] == "MY-LINK"]
    assert item["removable"] is False and item["no_remove"] == app.BY_HAND_LINK
    with pytest.raises(overlay.OverlayError) as err:
        overlay.remove_rule("MY-LINK", home=str(home), place="MY-LINK")
    assert str(err.value).startswith("%s is a link, not a rule folder or a rule file: nothing removed" % (
        d / "MY-LINK"))
    assert (elsewhere / "keep.txt").read_text() == "x"


def test_redo3_g6_for_the_header_names_a_refused_loose_file_by_its_file_name(home):
    redo2._loaded_and_loose(home)
    text = overlay.off_text(overlay.describe(overlay.load(str(home))))
    assert "MY-TF.yaml (refused: " in text and "MY-TF (refused" not in text
    assert text.startswith("2 rules off: MY-TF, MY-TF.yaml (refused: ")   # the loaded one off by the overlay


def test_redo3_g6_for_q15_the_real_place_is_said_where_a_linked_home_leads(tmp_path, monkeypatch):
    real_home = tmp_path / "real-home"
    real_home.mkdir()
    why = junction(real_home, tmp_path / "linked-home")
    if why:
        pytest.skip(why)
    home = tmp_path / "linked-home"
    assert ruleform.add(ans(), str(home)).ok
    said = overlay.remove_rule("MY-X", home=str(home))
    assert "(in %s, where %s leads)" % (os.path.realpath(overlay.user_dir(str(home))), overlay.user_dir(str(home))) \
        in said and not (real_home / ".raqib" / "rules.d" / "MY-X").exists()


def test_redo3_g6_must_not_touch_a_removal_that_succeeds(home):
    assert ruleform.add(ans(), str(home)).ok
    overlay.set_status("MY-X", "off", home=str(home))
    said = overlay.remove_rule("MY-X", home=str(home))
    target = os.path.join(overlay.user_dir(str(home)), "MY-X")
    assert said == "MY-X removed: its entry dropped from %s; %s deleted (7 file(s)); %s" % (
        overlay.overlay_path(str(home)), target, overlay.NEXT_WATCH)


# --- G-8: how a person's rule was measured (Q-9) -------------------------------------------------------------------

def test_redo3_g8_q9_the_count_is_named_by_its_unit(home):
    assert ruleform.add(ans(), str(home)).ok
    fires, quiet = ruleform.examples("path", "/srv/data", redo2.POSIX)
    assert ruleform.add(ans(rid="MY-P", when="path", values="/srv/data", fires=fires, quiet=quiet), str(home),
                        where=redo2.POSIX).ok
    lines = overlay.start_lines(overlay.describe(overlay.load(str(home))))
    assert [x for x in lines if x.startswith("rules: user rule MY-X") and
            x.endswith("measured on its own fixture files only (6), not on a corpus")]
    assert [x for x in lines if x.startswith("rules: user rule MY-P") and
            x.endswith("measured on its own fixture files only (2), not on a corpus")]
    assert not [x for x in lines if "own examples" in x]


# --- G-7: the window -----------------------------------------------------------------------------------------------

from test_app_redo import _window, tk_or_skip  # noqa: E402


def _text(widget):
    return widget.get("1.0", "end-1c")


def test_tk_redo3_g7_after_a_change_the_preview_is_marked_as_the_last_tests(home, tmp_path):
    tkinter, root = tk_or_skip()
    window = None
    try:
        window, c = _window(tkinter, root, home, tmp_path)
        root.deiconify()
        root.geometry("900x600")
        window.rules_new()
        window.form_vars["id"].set("MY-TF")
        window.form_vars["values"].set("terraform")
        redo2._press(root, window.rules_form_test_button)
        passed = _text(window.form_text)
        assert passed.startswith("on your records: ") and 'id: "MY-TF"' in passed
        window.form_vars["severity"].set("high")   # a field changed after the passed Test
        root.update()
        stale = _text(window.form_text)
        assert stale.startswith("THE LAST TEST'S, NOT THESE ANSWERS: ") and stale.endswith(passed)
        assert 'severity: "medium"' in stale or "severity: medium" in stale   # what the last test gave, said so
        window.form_vars["severity"].set("medium")   # the same answers again: the passed Test's preview, unmarked
        root.update()
        assert _text(window.form_text) == passed
    finally:
        if window is not None:
            window.destroy()
        else:
            root.destroy()


def test_tk_redo3_g7_a_delete_by_hand_row_is_reached_by_tab_and_its_path_can_be_selected(home, tmp_path):
    tkinter, root = tk_or_skip()
    window = None
    try:
        backup = Path(overlay.user_dir(str(home))) / "backup"
        backup.mkdir(parents=True)
        window, c = _window(tkinter, root, home, tmp_path)
        root.deiconify()
        root.geometry("900x600")
        window.show_rules()
        window.tick()
        root.update()
        path = window.rule_widgets[("backup", "path")]
        assert path.winfo_class() == "TEntry" and path.instate(["readonly"]) and path.get() == str(backup)
        chain, w = [], window.rule_filter_entry
        for _ in range(2000):   # the Tab order (tk_focusNext is what Tab follows)
            w = w.tk_focusNext()
            if w is None or w in chain:
                break
            chain.append(w)
        assert path in chain, "the path is not in the Tab order"
        before = chain[chain.index(path) - 1]
        redo2._press(root, before, "next")   # Tab, through KEYS
        assert root.focus_get() is path
        path.selection_range(0, "end")
        assert path.selection_present() and (path.index("sel.first"), path.index("sel.last")) == (0, len(str(backup)))
        assert root.bind_class("TEntry", "<<Copy>>")   # the entry's own Copy (Ctrl-C) is there for it
        root.update()
        right = path.winfo_rootx() + path.winfo_width()   # must not touch: it fits at 900x600
        assert right <= root.winfo_rootx() + root.winfo_width()
    finally:
        if window is not None:
            window.destroy()
        else:
            root.destroy()


# --- the Table's commit on review 2026-11-11-M8.2-redo3.md (ADR-0009 Amendment H: H-1..H-3) ---------------------

def _records_with_a_file_of_host_lines(home, **bounds):
    root = Path(overlay.raqib_dir(str(home)))
    host_lines, _, _ = fixtures.load_fixture(FIX / "NET-TOOL" / "positive-host-child.json")
    _write(root / "traces" / "a" / "raqib.log.jsonl", [_bash("ls")], mtime=1000000000)
    _write(root / "host" / "sources" / "x.jsonl", host_lines * 4, mtime=1100000000)
    fires, quiet = ruleform.examples("path", "/srv/data", redo2.POSIX)
    rule = ruleform.test(ans(when="path", values="/srv/data", fires=fires, quiet=quiet), str(home),
                         where=redo2.POSIX).rule
    return ruleform.records_text(ruleform.on_records(rule, str(home), **bounds))


def test_table_h1_for_a_file_of_host_lines_read_in_part_and_not_judged_is_not_every_file(home):
    """T1: the bounded file is one the rule is not given; "read: every file" may not stand beside it."""
    text = _records_with_a_file_of_host_lines(home, max_bytes=600)
    assert "read: not every file (" in text and "read: every file" not in text, text
    assert "1 file of host lines not judged" in text and "read only in" in text, text


def test_table_h1_must_not_touch_a_file_of_host_lines_read_whole_and_not_judged(home):
    """Q-16 as built: read whole, not judged, said as not judged: "read: every file" stands."""
    text = _records_with_a_file_of_host_lines(home)
    assert text.startswith("on your records: would have fired on 0 of 1 line in 1 file; read: every file (%s); 1 file"
                           " of host lines not judged: " % BOUNDS) and "read only in" not in text, text


def test_table_h2_the_package_refusal_reads_exactly_as_before(home, capsys):
    """T2: G-2's MUST NOT TOUCH, by its exact words: nothing is appended to the package refusal."""
    with pytest.raises(overlay.OverlayError) as err:
        overlay.remove_rule("NET-TOOL", home=str(home))
    assert str(err.value) == overlay.REMOVE_PACKAGE % ("NET-TOOL", "NET-TOOL")
    code, _, said = run_cli(["rules", "--remove", "NET-TOOL"], capsys)
    assert code == 2 and said.rstrip().endswith(overlay.REMOVE_PACKAGE % ("NET-TOOL", "NET-TOOL")), said
    with pytest.raises(overlay.OverlayError, match="nothing removed"):   # another check's refusal still says it
        overlay.remove_rule("MY-NONE", home=str(home))


def test_table_h3_one_rows_failure_is_that_rows_and_not_the_next_rows(home, monkeypatch):
    """T4: an entry that cannot be looked at loses its own Remove; the rows after it keep theirs."""
    d = Path(overlay.user_dir(str(home)))
    d.mkdir(parents=True)
    for name in ("MY-A.yaml", "MY-B.yaml"):
        (d / name).write_text("id: %s\n" % name[:-5])
    panel = app.RulesPanel(home=str(home))
    real_entries = overlay.user_entries
    monkeypatch.setattr(overlay, "user_entries", lambda rules_d: [
        (n, "other" if n == "MY-A.yaml" else k) for n, k in real_entries(rules_d)])

    def cannot(path):
        raise PermissionError(13, "Permission denied", path)
    monkeypatch.setattr(overlay, "is_link", cannot)
    rows = {i["id"]: i for i in app.rule_items(panel.refused_rows())}
    a = next(v for k, v in rows.items() if "MY-A" in k)
    b = next(v for k, v in rows.items() if "MY-B" in k)
    assert a["removable"] is False and "cannot be read (PermissionError" in a["no_remove"]
    assert b["removable"] is True and "cannot be read" not in (b.get("no_remove") or ""), b
