"""M8.2 REDO 2 (ADR-0009 Amendment F, F-1..F-11): each ruling's case FOR and the case it MUST NOT TOUCH (Z-9).
No test here depends on the system that runs it unless it skips and says why; the Tk tests (test_tk*) end what
they start (conftest), and a key reaches a widget only through app.KEYS."""
import io
import json
import os
import re
import sys
import warnings
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from raqib import app, cli, overlay, ruleform  # noqa: E402
from raqib.hooks import common  # noqa: E402
from raqib.rules import engine, fixtures  # noqa: E402
from hostthreads import raqib_threads_end  # noqa: E402,F401  (every HostWatch a test starts is ended)
import test_acts_judged as acts  # noqa: E402

CATALOG = ROOT / "raqib" / "rules" / "catalog"
FIX = ROOT / "tests" / "fixtures" / "rules"
POSIX = ("/home/user", "posix")
WINDOWS = ("C:\\Users\\user", "windows")


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


def run_cli(argv):
    out = io.StringIO()
    return cli.main(argv, out=out), out.getvalue()


def line(tool, meta, **kw):
    rec = {"ts": "2026-11-11T08:00:01.000Z", "seq": 1, "session_id": "s", "phase": "pre", "tool": tool,
           "cwd": "/work/example", "input_sha256": "0" * 64, "input_meta": meta}
    rec.update(kw)
    return rec


def link_dir(target, link):
    """A directory link: a symlink, else on Windows a junction (it needs no privilege: _winapi.CreateJunction,
    what mklink /J makes). None, or why neither could be made (the test skips with it)."""
    try:
        os.symlink(str(target), str(link), target_is_directory=True)
        return None
    except (OSError, NotImplementedError) as exc:
        why = "no symlink can be made here (%s)" % exc
    if os.name == "nt":
        try:
            import _winapi
            _winapi.CreateJunction(str(target), str(link))
            return None
        except Exception as exc:   # noqa: BLE001 - said in the skip
            why += "; no junction either (%s)" % exc
    else:
        why += "; a junction is a Windows thing"
    return why


def under_any(rule_or_doc):
    doc = getattr(rule_or_doc, "doc", rule_or_doc)
    return doc["match"]["all"][3]["any"][0]["under_any"]


# --- F-1: a ~ place on Windows is one path ---------------------------------------------------------------------

def test_redo2_f1_for_a_home_place_with_a_windows_home_is_one_windows_path(home):
    assert ruleform.home_of("~/.aws", "C:\\Users\\user", "windows") == "C:\\Users\\user\\.aws"
    assert ruleform.home_of("~\\.aws/c", "C:\\Users\\user\\", "windows") == "C:\\Users\\user\\.aws\\c"
    assert ruleform.home_of("~/.aws", "C:/Users/user", "windows") == "C:/Users/user/.aws"   # the home's separator
    names, note, why = ruleform.check_place("~/.aws", where=WINDOWS)
    assert why is None and names == ["~/.aws", "C:\\Users\\user\\.aws"] and "C:\\Users\\user\\.aws" in note
    fires, quiet = ruleform.examples("path", "~/.aws", WINDOWS)   # the examples are of the place's system
    assert (fires, quiet) == ("C:\\Users\\user\\.aws\\example.txt", "C:\\work\\example\\notes.txt")
    res = ruleform.test(ans(when="path", values="~/.aws", fires=fires, quiet=quiet), str(home), where=WINDOWS)
    assert res.ok, res.refusals
    assert under_any(res.rule) == ["~/.aws", "C:\\Users\\user\\.aws"]
    for path in ("C:\\Users\\user\\.aws\\credentials", "c:/users/USER/.aws/config"):   # folded A-Z, either slash
        assert engine.judge(res.rule, [line("Read", {"path": path}, cwd="C:\\work\\example")], {})[0], path


def test_redo2_f1_must_not_touch_posix_exactly_as_before(home):
    assert ruleform.home_of("~/.aws", "/home/user", "posix") == "/home/user/.aws"
    assert ruleform.home_of("~/.aws", "/home/user/", "posix") == "/home/user/.aws"
    assert ruleform.home_of("~", "/home/user", "posix") == "/home/user"
    assert ruleform.home_of("/srv/data", "/home/user", "posix") is None
    assert ruleform.examples("path", "~/.aws", POSIX) == ("/home/user/.aws/example.txt", "/work/example/notes.txt")
    res = ruleform.test(ans(when="path", values="~/.aws", fires="/home/user/.aws/example.txt",
                            quiet="/work/example/notes.txt"), str(home), where=POSIX)
    assert res.ok and under_any(res.rule) == ["~/.aws", "/home/user/.aws"]
    # where defaults to this machine's home and system, whichever system runs the test
    here, system = ruleform.this_home()
    assert system == ("windows" if os.name == "nt" else "posix")
    assert ruleform.check_place("~/.aws")[0] == ["~/.aws", ruleform.home_of("~/.aws", here, system)]


# --- F-2: as typed, as typed in lower case, as an image is named ----------------------------------------------

def test_redo2_f2_for_curl_exe_passes_its_own_test_and_fires_on_each_line(home):
    assert ruleform.check_program("curl.exe")[0] == ["curl", "curl.exe"]
    fires, quiet = ruleform.examples("program", "curl.exe")
    assert (fires, quiet) == ("curl.exe", "ls")
    res = ruleform.test(ans(values="curl.exe", fires=fires, quiet=quiet), str(home))
    assert res.ok, res.refusals
    cmd = "curl.exe https://example.com/x"
    programs = common.command_programs(cmd)
    bash = line("Bash", dict({"command_head": common.command_head(cmd)},
                             **({"command_programs": programs} if programs is not None else {})))
    os_line = line("process", {"image": "curl", "parent_image": "explorer", "depth": 1}, source="os",
                   cwd="C:\\work\\example")
    host_line = line("HostChild", {"command_programs": ["curl"], "pid": 1, "round": 1, "run": "r",
                                   "children": [{"image": "curl", "pid": 2, "started": None}]}, source="host",
                     cwd="host")
    for rec in (bash, os_line, host_line):
        assert engine.judge(res.rule, [rec], {})[0], rec["tool"]


def test_redo2_f2_must_not_touch_terraform_and_r(home):
    assert ruleform.check_program("terraform") == (["terraform"], None, None)
    assert ruleform.check_program("R") == (["r", "R"], "R is also matched as r (an os or host line's image is lower"
                                                       " case)", None)
    names = ruleform.build(ans()).doc["match"]["all"][1]["any"][0]["all"][2]["in"]
    assert names == ["terraform"]


# --- F-3: Remove acts on the row's own place -------------------------------------------------------------------

def _loaded_and_loose(home):
    assert ruleform.add(ans(rid="MY-TF"), str(home)).ok
    overlay.set_status("MY-TF", "off", home=str(home))
    loose = Path(overlay.user_dir(str(home))) / "MY-TF.yaml"
    loose.write_text("id: MY-TF\n")
    return loose


def test_redo2_f3_for_a_refused_loose_file_beside_the_loaded_rule(home):
    loose = _loaded_and_loose(home)
    panel = app.RulesPanel(home=str(home))
    items = app.rule_items(panel.rows + panel.refused_rows())
    mine = [(i["key"], i["place"], i["refused"], i["removable"]) for i in items if i["id"] == "MY-TF"]
    assert mine == [("MY-TF", "MY-TF", False, True), ("MY-TF.yaml", "MY-TF.yaml", True, True)]   # two rows
    said = panel.remove_rule("MY-TF", place="MY-TF.yaml")
    assert panel.level == "clean" and said.startswith("MY-TF.yaml removed: no rule loaded from it"), said
    assert not loose.exists() and rules_d(home) == ["MY-TF"]
    doc, _, _ = overlay.read(overlay.overlay_path(str(home)))
    assert doc["rules"]["MY-TF"]["status"] == "off"   # the loaded rule, its folder and its entry stay
    assert next(r for r in overlay.load(str(home)) if r.id == "MY-TF").status == "disabled"


def test_redo2_f3_for_two_folders_a_case_apart(home):
    assert ruleform.add(ans(rid="MY-TF"), str(home)).ok
    other = Path(overlay.user_dir(str(home))) / "my-tf"
    if os.path.lexists(str(other)):   # REDO 3 G-1: the file system is asked first, before the second is made
        pytest.skip("this file system folds case: my-tf is the folder MY-TF here, so the two cannot both be kept")
    other.mkdir()
    (other / "my-tf.yaml").write_text("id: broken\n")
    code, _ = run_cli(["rules", "--remove", "My-Tf"])   # several without regard to case: refused, each listed
    assert code == 2 and rules_d(home) == ["MY-TF", "my-tf"]
    panel = app.RulesPanel(home=str(home))
    keys = [i["key"] for i in app.rule_items(panel.rows + panel.refused_rows()) if i["id"].upper() == "MY-TF"]
    assert sorted(keys) == ["MY-TF", "my-tf"]
    assert panel.remove_rule("my-tf", place="my-tf").startswith("my-tf removed")
    assert rules_d(home) == ["MY-TF"] and any(r.id == "MY-TF" for r in overlay.load(str(home)))


def test_redo2_f3_the_terminal_takes_the_exact_name_then_one_without_regard_to_case(home, capsys):
    loose = _loaded_and_loose(home)
    # REDO 3 G-2: a NAME without a suffix is a folder: the one folder MY-TF matches my-tf; a stem never matches
    # across kinds (the folder beside the loose file is no second match): test_ruleform_redo3
    code, out = run_cli(["rules", "--remove", "my-tf", "--dry-run"])
    assert code == 0 and "would delete %s" % os.path.join(overlay.user_dir(str(home)), "MY-TF") in out
    code, out = run_cli(["rules", "--remove", "MY-TF.yaml"])   # the exact name: the loose file
    assert code == 0 and not loose.exists() and rules_d(home) == ["MY-TF"]
    old = Path(overlay.user_dir(str(home))) / "my-old"
    old.mkdir()
    code, out = run_cli(["rules", "--remove", "MY-OLD"])   # no exact name: the one that matches in any case
    assert code == 0 and "my-old removed" in out and not old.exists()


def test_redo2_f3_taken_ids_count_loose_files_and_fold_ascii_only(home):
    d = Path(overlay.user_dir(str(home)))
    d.mkdir(parents=True)
    (d / "my-loose.yaml").write_text("id: x\n")
    assert "my-loose" in ruleform.taken_ids(str(home))
    res = ruleform.test(ans(rid="MY-LOOSE"), str(home))
    assert res.refusals[0][0] == "id" and "taken" in res.refusals[0][1]
    assert overlay.fold_id("my-tf") == "MY-TF" and overlay.fold_id("my-\u00df") == "MY-\u00df"   # C-11: ASCII only


def test_redo2_f3_a_place_raqib_could_not_have_written_has_no_remove(home):
    d = Path(overlay.user_dir(str(home))) / "backup"
    d.mkdir(parents=True)
    (d / "keep.txt").write_text("x")
    panel = app.RulesPanel(home=str(home))
    (item,) = [i for i in app.rule_items(panel.rows + panel.refused_rows()) if i["id"] == "backup"]
    assert item["removable"] is False and item["path"] == str(d)
    with pytest.raises(overlay.OverlayError, match="delete it by hand"):
        overlay.remove_rule("backup", home=str(home), place="backup")
    assert (d / "keep.txt").read_text() == "x"


def test_redo2_f3_must_not_touch_one_rule_one_row_removed_as_before(home):
    assert ruleform.add(ans(), str(home)).ok
    panel = app.RulesPanel(home=str(home))
    (item,) = [i for i in app.rule_items(panel.rows + panel.refused_rows()) if i["id"] == "MY-X"]
    assert (item["key"], item["place"], item["removable"]) == ("MY-X", "MY-X", True)
    said = overlay.remove_rule("MY-X", home=str(home))
    target = os.path.join(overlay.user_dir(str(home)), "MY-X")
    assert said == "MY-X removed: it had no entry in %s; %s deleted (7 file(s)); %s" % (
        overlay.overlay_path(str(home)), target, overlay.NEXT_WATCH)
    assert rules_d(home) == []


# --- F-4: a Remove that deletes nothing changes nothing --------------------------------------------------------

def test_redo2_f4_for_nothing_deleted_nothing_changed(home, monkeypatch):
    assert ruleform.add(ans(), str(home)).ok
    overlay.set_status("MY-X", "off", home=str(home))
    calls = []

    def fails(path, *a, **k):
        calls.append(path)
        raise OSError(13, "Permission denied")
    with monkeypatch.context() as m:   # REDO 3 (S13): the autouse HOME stays patched
        m.setattr(overlay.os, "remove", fails)
        with pytest.raises(overlay.OverlayError) as err:
            overlay.remove_rule("MY-X", home=str(home))
    assert str(err.value).startswith("nothing was removed: ") and len(calls) == 1 and calls[0].endswith("MY-X.yaml")
    doc, _, _ = overlay.read(overlay.overlay_path(str(home)))
    assert doc["rules"]["MY-X"]["status"] == "off" and len(list((Path(overlay.user_dir(str(home))) / "MY-X")
                                                                .iterdir())) == 7


def test_redo2_f4_for_a_removal_stopped_midway_says_what_is_gone_and_what_remains(home, monkeypatch):
    assert ruleform.add(ans(), str(home)).ok
    overlay.set_status("MY-X", "off", home=str(home))
    real, calls = os.remove, []

    def second_fails(path, *a, **k):
        calls.append(path)
        if len(calls) == 2:
            raise OSError(13, "Permission denied")
        return real(path, *a, **k)
    with monkeypatch.context() as m:   # REDO 3 (S13): the autouse HOME stays patched
        m.setattr(overlay.os, "remove", second_fails)
        with pytest.raises(overlay.OverlayError) as err:
            overlay.remove_rule("MY-X", home=str(home))
    text = str(err.value)
    assert calls[0].endswith("MY-X.yaml")   # the rule file first: the rule can no longer load
    assert "stopped midway" in text and "gone: %s" % calls[0] in text and "what remains:" in text
    assert "it no longer loads" in text and "gone: %s, its entry MY-X in " % calls[0] in text   # G-6
    assert text.startswith("MY-X was not removed whole: stopped midway: ")   # G-6: never "MY-X removed"
    rules = overlay.load(str(home))
    assert "MY-X" not in [r.id for r in rules]
    assert "MY-X" in [u["rule_id"] for u in overlay.describe(rules)["user_refused_ids"]]
    doc, _, _ = overlay.read(overlay.overlay_path(str(home)))
    assert "MY-X" not in doc["rules"]   # dropped once the rule file was gone


def test_redo2_f4_the_dry_run_says_what_the_real_run_would_do_a_refusal_included(home, tmp_path, capsys):
    assert ruleform.add(ans(), str(home)).ok
    code, out = run_cli(["rules", "--remove", "MY-X", "--dry-run"])
    assert code == 0 and "dry run: would delete" in out and rules_d(home) == ["MY-X"]
    outside = tmp_path / "outside"
    outside.mkdir()
    why = link_dir(outside, Path(overlay.user_dir(str(home))) / "MY-X" / "linked")
    if why:
        pytest.skip(why)
    code, _ = run_cli(["rules", "--remove", "MY-X", "--dry-run"])
    err = capsys.readouterr().err
    assert code == 2 and "dry run: the removal would be refused" in err and "is a link" in err
    code, _ = run_cli(["rules", "--remove", "MY-X"])   # the real run refuses the same, nothing deleted
    assert code == 2 and "is a link: nothing removed" in capsys.readouterr().err and outside.is_dir()
    assert len(list((Path(overlay.user_dir(str(home))) / "MY-X").iterdir())) == 8


def test_redo2_f4_must_not_touch_a_removal_that_succeeds(home):
    assert ruleform.add(ans(), str(home)).ok
    overlay.set_status("MY-X", "off", home=str(home))
    said = overlay.remove_rule("MY-X", home=str(home))
    assert re.match(r"MY-X removed: its entry dropped from .+; .+ deleted \(7 file\(s\)\); ", said), said
    assert said.endswith(overlay.NEXT_WATCH) and " where " not in said and rules_d(home) == []


# --- F-5: Remove follows what Add follows ----------------------------------------------------------------------

def test_redo2_f5_for_a_linked_raqib_folder_the_form_adds_and_remove_removes(home, tmp_path):
    disk = tmp_path / "disk" / "raqib"
    disk.mkdir(parents=True)
    why = link_dir(disk, overlay.raqib_dir(str(home)))
    if why:
        pytest.skip(why)
    assert ruleform.add(ans(), str(home)).ok
    assert (disk / "rules.d" / "MY-X" / "MY-X.yaml").is_file()
    said = overlay.remove_rule("MY-X", home=str(home))
    assert "MY-X removed" in said and "where %s leads" % overlay.user_dir(str(home)) in said
    assert os.path.realpath(str(disk / "rules.d")) in said   # the real place it deleted in, named
    assert not (disk / "rules.d" / "MY-X").exists()


def test_redo2_f5_must_not_touch_the_checks_below_the_rules_folder(home, tmp_path):
    assert ruleform.add(ans(), str(home)).ok
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "precious.txt").write_text("x")
    why = link_dir(outside, Path(overlay.user_dir(str(home))) / "MY-X" / "linked")
    if why:
        pytest.skip(why)
    with pytest.raises(overlay.OverlayError, match="is a link: nothing removed"):
        overlay.remove_rule("MY-X", home=str(home))
    assert (outside / "precious.txt").read_text() == "x" and rules_d(home) == ["MY-X"]
    assert (Path(overlay.user_dir(str(home))) / "MY-X" / "MY-X.yaml").is_file()   # nothing deleted, not even first


# --- F-6: the pre-M7.8 note hides only the notes of the rules it names ------------------------------------------

def _persons_rule(tmp_path):
    built = ruleform.build(ans(values="plink", fires="plink"))
    stage = tmp_path / "rule"
    stage.mkdir()
    for rel, text in list(built.files.items()) + [("MY-X.yaml", built.yaml)]:
        (stage / rel).write_text(text)
    return overlay.validate_rule(str(stage / "MY-X.yaml"), str(stage), user=True)


def test_redo2_f6_for_a_persons_rule_keeps_its_could_not_judge(tmp_path, monkeypatch):
    monkeypatch.setattr(acts, "RULES", acts.RULES + [_persons_rule(tmp_path)])
    follow = acts.CountingFollow(acts.after_start(acts.old_shape(acts.os_lines("net-windows.sysmon.xml", 4700))))
    w = acts.watch_rounds(tmp_path, ["defender/before", "quiet/talking", "quiet/talking"], follow=follow)
    assert [n for n in w.notes if "rule MY-X partial: could not judge 6 line(s)" in n]
    # must not touch: NET-TOOL's and DESTRUCT-CMD's same-cause notes stay folded into the one note
    assert [n for n in w.notes if "carry no input_meta.image" in n]
    assert not [n for n in w.notes if "NET-TOOL partial" in n or "DESTRUCT-CMD partial" in n]


# --- F-7: "on your records" says what it read and what it did not ----------------------------------------------

def _write(path, records):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r) + "\n" for r in records))


def test_redo2_f7_for_an_os_source_file_is_judged_by_its_lines_not_its_folder(home):
    sources = Path(overlay.raqib_dir(str(home))) / "host" / "sources"
    _write(sources / "run-1-os.jsonl", [line("WebSearch", {}, source="os", seq=i) for i in (1, 2, 3)])
    lines, _, _ = fixtures.load_fixture(FIX / "NET-TOOL" / "positive-host-child.json")
    _write(sources / "run-1-host.jsonl", lines)
    res = ruleform.test(ans(when="tool", values="WebSearch", fires="WebSearch", quiet="Read"), str(home))
    r = res.records
    assert (r["files"], r["lines"], r["not_host"]) == (1, 3, 1)   # the os file judged and counted; host lines not
    text = ruleform.records_text(r)
    assert "on 0 of 3 lines in 1 file;" in text and "1 file of host lines not judged" in text   # REDO 3 G-3


def test_redo2_f7_for_links_and_unreadable_files_are_counted_and_said(home, tmp_path, monkeypatch):
    traces = Path(overlay.raqib_dir(str(home))) / "traces"
    traces.mkdir(parents=True)
    outside = tmp_path / "outside"
    _write(outside / "x.jsonl", [line("Bash", {"command_head": "terraform"})])
    why = link_dir(outside, traces / "linked")
    if why:
        pytest.skip(why)
    res = ruleform.test(ans(), str(home))
    text = ruleform.records_text(res.records)
    assert res.ok and "1 folder not read: a link" in text and "no file was judged" in text   # G-3: a folder
    assert "this rule would read yet" not in text   # never "no file yet" when files were refused
    _write(traces / "demo" / "raqib.log.jsonl", [line("Bash", {"command_head": "ls"})])

    def unreadable(path, limit):
        raise OSError(13, "Permission denied")
    monkeypatch.setattr(ruleform, "_tail", unreadable)
    text = ruleform.records_text(ruleform.test(ans(), str(home)).records)
    assert "1 file not read: cannot be read (Permission denied)" in text and "1 folder not read: a link" in text


def test_redo2_f7_for_a_failure_reading_the_records_never_undoes_a_passed_test(home, monkeypatch):
    def broken(*a, **k):
        raise RuntimeError("disk on fire")
    monkeypatch.setattr(ruleform, "on_records", broken)
    res = ruleform.test(ans(), str(home))
    assert res.ok and not res.refusals
    assert ruleform.records_text(res.records).startswith(
        "on your records: your records could not be read: RuntimeError: disk on fire")


def test_redo2_f7_for_the_sweep_leaves_a_young_folder_and_says_what_it_could_not_remove(home, monkeypatch):
    base = Path(ruleform.staging_dir(str(home)))
    for name in ("form-old", "form-stuck", "form-young", "kept-other"):
        (base / name).mkdir(parents=True)
    for name in ("form-old", "form-stuck", "kept-other"):
        os.utime(str(base / name), (1000000000, 1000000000))
    real = ruleform._unstage

    def stuck(stage, home=None):
        return "the staging folder %s could not be removed (in use)" % stage if stage.endswith("form-stuck") else \
            real(stage, home)
    monkeypatch.setattr(ruleform, "_unstage", stuck)
    res = ruleform.test(ans(), str(home))
    notes = [w for f, w in res.notes if f == "rule"]
    assert "1 staging folder an earlier Test left was removed" in notes
    assert "1 staging folder younger than ten minutes left alone (another Test may be using it)" in notes
    assert any("was not removed" in w and "form-stuck" in w for w in notes)
    # must not touch: a folder not named form-*, however old
    assert sorted(p.name for p in base.iterdir()) == ["form-stuck", "form-young", "kept-other"]


def test_redo2_f7_must_not_touch_the_bounds():
    assert (ruleform.RECORD_FILES, ruleform.RECORD_LINES, ruleform.RECORD_BYTES, ruleform.RECORD_ENTRIES) == (
        20, 20000, 4000000, 10000)


# --- F-8: how a person's rule was measured, at the start and in the report -------------------------------------

def test_redo2_f8_for_every_user_rule_line_says_how_it_was_measured(home):
    assert ruleform.add(ans(), str(home)).ok
    info = overlay.describe(overlay.load(str(home)))
    words = "measured on its own fixture files only (6), not on a corpus"   # REDO 3 G-8 (Q-9)
    assert [x for x in overlay.start_lines(info) if x.startswith("rules: user rule MY-X") and x.endswith(words)]
    assert [x for x in overlay.report_lines(info, {}) if x.startswith("  - user rule MY-X") and x.endswith(words)]


def test_redo2_f8_must_not_touch_a_package_rules_line(home):
    overlay.set_status("NET-TOOL", "off", home=str(home))
    info = overlay.describe(overlay.load(str(home)))
    lines = overlay.start_lines(info) + overlay.report_lines(info, {})
    assert not [x for x in lines if "measured on its own" in x]
    assert [x for x in lines if x.startswith("  - NET-TOOL [medium] off by the overlay")]


# --- F-9: a person's home does not travel in a title --------------------------------------------------------------

@pytest.mark.parametrize("where", [POSIX, WINDOWS])
def test_redo2_f9_for_no_default_title_or_description_holds_the_home(home, where):
    fires, quiet = ruleform.examples("path", "~/.aws, /srv/data", where)
    built = ruleform.build(ans(when="path", values="~/.aws, /srv/data", fires=fires, quiet=quiet), (), where)
    for text in (built.doc["title"], built.doc["description"]):
        assert where[0].lower() not in text.lower(), text
    assert built.doc["title"] == "A file under a place is touched: ~/.aws, /srv/data"
    assert "~/.aws, /srv/data" in built.doc["description"] and "example.txt" in built.doc["description"]
    assert where[0] in under_any(built.doc)[1]   # the home is in the match only


def test_redo2_f9_must_not_touch_a_title_the_person_typed(home):
    title = "Keys under /home/user/.aws"
    built = ruleform.build(ans(when="path", values="~/.aws", fires="/home/user/.aws/a", quiet="/work/a",
                               title=title), (), POSIX)
    assert built.doc["title"] == title


# --- F-10: the words are true --------------------------------------------------------------------------------------

@pytest.mark.parametrize("name", ["HostChild", "HostConnection", "HostGone", "process", "net", "file"])
def test_redo2_f10_the_tool_form_refuses_the_sources_own_tool_names(home, name):
    res = ruleform.test(ans(when="tool", values=name, fires=name, quiet="Read"), str(home))
    assert any(f == "values" and "the host source or the os source writes" in w for f, w in res.refusals)
    assert ruleform.test(ans(when="tool", values="WebSearch", fires="WebSearch", quiet="Read"), str(home)).ok


def test_redo2_f10_another_users_home_and_a_home_that_cannot_be_written_are_said():
    assert "another user's home" in ruleform.check_place("~user/.aws")[2]
    for where, words in ((("~", "posix"), "this machine's home is not known"),
                         (("/home/us\ter", "posix"), "cannot be written in the rule file"),
                         (("/" + "h" * 300, "posix"), "longer than 260 characters")):
        names, note, why = ruleform.check_place("~/.aws", where=where)
        assert why is None and names == ["~/.aws"] and "matched as typed only" in note and words in note, note


def test_redo2_f10_the_help_the_docstring_and_the_evasion_follow_the_code(home):
    doc = cli.__doc__
    assert "its two fixtures" not in doc and "--remove NAME [--dry-run]" in doc
    assert "judged by NET-TOOL and DESTRUCT-CMD, as the" not in doc and "names the\n      tool HostChild" in doc
    assert "lower-cased as discover.image_name does" not in ruleform.__doc__
    path = ruleform.EVASIONS["path"][0]
    assert "never /home/me" not in path and "another user's home" in path and "relative to the" in path
    with warnings.catch_warnings():   # no call deprecated in Python 3.12 (shutil.rmtree's onerror)
        warnings.simplefilter("error", DeprecationWarning)
        assert ruleform.test(ans(), str(home)).ok


# --- F-11: the tests the review named ------------------------------------------------------------------------------

def test_redo2_f11_a_failure_after_staging_began_is_a_refusal_and_unstages(home, monkeypatch):
    stages = []
    real = ruleform._new_stage

    def staged(home=None, now=None):
        out = real(home, now)
        stages.append(out[0])
        return out

    def broken(*a, **k):
        assert os.path.isdir(stages[-1])   # staging began: the files are written
        raise RuntimeError("after staging")
    monkeypatch.setattr(ruleform, "_new_stage", staged)
    monkeypatch.setattr(overlay, "validate_rule", broken)
    for res in (ruleform.test(ans(), str(home)), ruleform.add(ans(), str(home))):
        assert res.refusals == [("rule", "the form could not write this rule: RuntimeError: after staging")]
    assert len(stages) == 2 and not any(os.path.exists(s) for s in stages)
    assert not os.path.exists(ruleform.staging_dir(str(home))) and rules_d(home) == []


def test_redo2_f11_no_catalog_rule_declares_class_user():
    assert "USER" in engine.CLASSES
    assert [r.id for r in engine.load_catalog(CATALOG) if r.cls == "USER"] == []
    for path in sorted(CATALOG.glob("*.yaml")):
        assert not re.search(r"^class:\s*\"?USER\"?\s*$", path.read_text(encoding="utf-8"), re.M), path.name


# --- the window --------------------------------------------------------------------------------------------------

from test_app_redo import _window, tk_or_skip  # noqa: E402


def _press(root, widget, key="act"):
    widget.focus_force()
    root.update()
    widget.event_generate(app.KEYS[key][0])
    root.update()


def test_tk_redo2_f3_each_row_removes_its_own_place(home, tmp_path):
    tkinter, root = tk_or_skip()
    window = None
    try:
        loose = _loaded_and_loose(home)
        backup = Path(overlay.user_dir(str(home))) / "backup"
        backup.mkdir()
        window, c = _window(tkinter, root, home, tmp_path)
        root.deiconify()
        root.geometry("900x600")
        window.show_rules()
        window.tick()
        keys = {i["key"] for i, _ in window.rule_rows}
        assert {"MY-TF", "MY-TF.yaml", "backup"} <= keys
        assert ("MY-TF", "remove") in window.rule_widgets and ("MY-TF.yaml", "remove") in window.rule_widgets
        assert ("backup", "remove") not in window.rule_widgets   # not a place Raqib could have written
        frame = next(f for i, f in window.rule_rows if i["key"] == "backup")
        texts, todo = [], [frame]
        while todo:   # every label of the row
            w = todo.pop()
            todo += w.winfo_children()
            texts += [w.cget("text")] if w.winfo_class() == "TLabel" else []
        assert any("delete it by hand" in t for t in texts), texts
        assert window.rule_widgets[("backup", "path")].get() == str(backup)   # REDO 3 G-7: its path, selectable
        _press(root, window.rule_widgets[("MY-TF.yaml", "remove")])
        assert root.focus_get() is window.rule_widgets[("MY-TF.yaml", "keep")]
        assert ("MY-TF", "confirm") not in window.rule_widgets   # only that row asks
        _press(root, window.rule_widgets[("MY-TF.yaml", "confirm")])
        assert not loose.exists() and (Path(overlay.user_dir(str(home))) / "MY-TF" / "MY-TF.yaml").is_file()
        assert "MY-TF.yaml removed" in window.detail.cget("text")
        doc, _, _ = overlay.read(overlay.overlay_path(str(home)))
        assert doc["rules"]["MY-TF"]["status"] == "off"
    finally:
        if window is not None:
            window.destroy()
        else:
            root.destroy()


def test_tk_redo2_f10_f11_the_header_says_changed_and_testing_is_shown_first(home, tmp_path):
    tkinter, root = tk_or_skip()
    window = None
    try:
        window, c = _window(tkinter, root, home, tmp_path)
        root.deiconify()
        root.geometry("900x600")
        window.rules_new()
        window.form_vars["id"].set("MY-TF")
        window.form_vars["values"].set("terraform")
        seen = []
        real = window.rules_panel.test_form

        def watched(answers):
            seen.append(window.form_status.cget("text"))   # what the window says while it reads
            return real(answers)
        window.rules_panel.test_form = watched
        _press(root, window.rules_form_test_button)
        assert seen and seen[0].startswith("testing...")
        assert window.verdict.cget("text") == "The test passed: the rule can be added"
        window.form_vars["severity"].set("high")   # a field edited after a passed Test
        root.update()
        assert window.verdict.cget("text") == "Changed since the test: test again"
        assert window.pill.cget("text") == "changed" and window.rules_form_add_button.instate(["disabled"])
        assert window.form_status.cget("text") == "changed since the test: test again"
        window.form_vars["severity"].set("medium")   # the same answers again: passed again
        assert window.verdict.cget("text") == "The test passed: the rule can be added"
        assert window.form_status.cget("text").startswith("test passed")
        assert window.rules_form_add_button.instate(["!disabled"])
    finally:
        if window is not None:
            window.destroy()
        else:
            root.destroy()


def test_tk_redo2_f11_with_a_watch_running_add_and_remove_say_it_keeps_its_rules(home, tmp_path):
    tkinter, root = tk_or_skip()
    window = None
    try:
        window, c = _window(tkinter, root, home, tmp_path)
        assert c.start_host() is None and c.watching()   # a host watch runs (the window's fake host session)
        root.withdraw()
        window.rules_new()
        window.form_vars["id"].set("MY-TF")
        window.form_vars["values"].set("terraform")
        window.rules_form_test()
        window.rules_form_add()
        assert window.screen == "rules" and "MY-TF added as" in window.detail.cget("text")
        assert "a watch is running: it keeps the rules it started with" in window.detail.cget("text")
        window.rules_remove("MY-TF")
        window.rules_remove("MY-TF", confirmed=True)
        assert "MY-TF removed" in window.detail.cget("text") and rules_d(home) == []
        assert "a watch is running: it keeps the rules it started with" in window.detail.cget("text")
    finally:
        if window is not None:
            window.destroy()
        else:
            root.destroy()
