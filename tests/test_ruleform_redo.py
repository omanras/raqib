"""M8.2 REDO (ADR-0009 Amendment E, E-1..E-10): each ruling's case FOR, and the case it must NOT TOUCH (E-11)."""
import io
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from raqib import cli, host, overlay, ruleform  # noqa: E402
from raqib.rules import engine, fixtures  # noqa: E402

CATALOG = ROOT / "raqib" / "rules" / "catalog"
FIX = ROOT / "tests" / "fixtures" / "rules"
EMOJI = "\U0001F600"


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


# --- E-1: nothing typed ends the form in anything but an answer --------------------------------------------------

@pytest.mark.parametrize("field, a", [
    ("title", ans(title="Agent runs ssh " + EMOJI)),
    ("values", ans(when="path", values="/srv/" + EMOJI, fires="/srv/x/a", quiet="/tmp/a")),
    ("values", ans(values="terraform" + EMOJI)),
    ("fires", ans(when="host", values="example.com", fires="example.com" + EMOJI, quiet="example.org")),
    ("quiet", ans(when="path", values="/srv/data", fires="/srv/data/a", quiet="/tmp/" + EMOJI)),
])
def test_redo_e1_a_character_the_file_cannot_hold_is_refused_beside_its_field(home, field, a):
    for res in (ruleform.test(a, str(home)), ruleform.add(a, str(home))):
        assert not res.ok and any(f == field and "a character this file cannot hold: U+1F600" in w
                                  for f, w in res.refusals), res.refusals
    assert rules_d(home) == []


def test_redo_e1_must_not_touch_text_the_file_can_carry(home):
    a = ans(when="path", values="/srv/\u062f\u0644\u064a\u0644", fires="/srv/\u062f\u0644\u064a\u0644/a.txt",
            quiet="/tmp/a.txt", title="Les donn\u00e9es \u062f\u0644\u064a\u0644")
    res = ruleform.add(a, str(home))
    assert res.ok, res.refusals
    rule = next(r for r in overlay.load(str(home)) if r.id == "MY-X")
    assert rule.title == a["title"] and rule.doc["match"]["all"][3]["any"][0]["under_any"] == [a["values"]]


def test_redo_e1_any_failure_inside_is_a_refusal_never_a_traceback(home, monkeypatch, capsys):
    def broken(*args, **kw):
        raise RuntimeError("disk on fire")
    monkeypatch.setattr(ruleform, "dumps", broken)
    for res in (ruleform.test(ans(), str(home)), ruleform.add(ans(), str(home))):
        assert res.refusals == [("rule", "the form could not write this rule: RuntimeError: disk on fire")]
    code, _ = run_cli(["rules", "--new", "MY-X", "--when", "program", "--values", "terraform", "--severity", "low",
                       "--fires", "terraform", "--quiet", "ls"])
    assert code == 2 and "the form could not write this rule: RuntimeError" in capsys.readouterr().err
    monkeypatch.undo()
    code, _ = run_cli(["rules", "--new", "MY-X", "--when", "program", "--values", "terraform", "--severity", "low",
                       "--fires", "terraform", "--quiet", "ls", "--title", "x " + EMOJI])
    assert code == 2 and "U+1F600" in capsys.readouterr().err and rules_d(home) == []
    assert not Path(ruleform.staging_dir(str(home))).exists()


# --- E-2: a rule judges the lines it says it reads ------------------------------------------------------------------

def test_redo_e2_host_lines_go_to_the_rules_that_name_hostchild(home):
    package = engine.load_catalog(CATALOG)
    chosen = host.source_rules(package, host_lines=True)
    assert sorted(r.id for r in chosen) == sorted(host.HOST_LINE_RULES) == ["DESTRUCT-CMD", "NET-TOOL"]
    assert ruleform.add(ans(), str(home)).ok and ruleform.add(ans(when="tool", rid="MY-T", values="WebSearch",
                                                                  fires="WebSearch", quiet="Read"), str(home)).ok
    rules = overlay.load(str(home))
    ids = sorted(r.id for r in host.source_rules(rules, host_lines=True))
    assert ids == ["DESTRUCT-CMD", "MY-X", "NET-TOOL"]   # the program rule; the tool rule names no HostChild
    assert "MY-T" in [r.id for r in host.source_rules(rules)]   # must not touch: the other sources keep every rule


# REDO 2 F-11 (R13): the package's findings on its shipped host fixtures, pinned (rule, session, cited seq)
PINNED = {
    ("NET-TOOL", "positive-host-child.json"): [("NET-TOOL", "host-1600", (1,))],
    ("NET-TOOL", "negative-host-child.json"): [("DESTRUCT-CMD", "host-1600", (1,))],
    ("DESTRUCT-CMD", "positive-host-child.json"): [("DESTRUCT-CMD", "host-1600", (1,))],
    ("DESTRUCT-CMD", "negative-host-child.json"): [("NET-TOOL", "host-1600", (1,))],
}


def test_redo_e2_the_package_findings_on_the_shipped_host_fixtures_are_unchanged():
    package = engine.load_catalog(CATALOG)
    for (rid, name), expected in PINNED.items():
        lines, _, _ = fixtures.load_fixture(FIX / rid / name)
        found, notes = host.judge_source(host.source_rules(package, host_lines=True), lines)
        assert sorted((f["rule_id"], f["session_id"], tuple(f["cited_seq"])) for f in found) == expected, (rid, name)
        assert not [n for n in notes if n.get("rule_id") in host.HOST_LINE_RULES], notes


def test_redo_e2_a_persons_program_rule_fires_on_a_real_hostchild_line(home):
    assert ruleform.add(ans(values="curl", fires="curl"), str(home)).ok
    rule = next(r for r in overlay.load(str(home)) if r.id == "MY-X")
    lines, _, _ = fixtures.load_fixture(FIX / "NET-TOOL" / "positive-host-child.json")
    found, _ = host.judge_source(host.source_rules([rule], host_lines=True), lines)
    assert [f["rule_id"] for f in found if f["rule_id"] == "MY-X"]


def test_redo_e2_the_tool_form_says_the_lines_it_reads(home):
    built = ruleform.build(ans(when="tool", values="WebSearch", fires="WebSearch", quiet="Read"))
    assert "a hook or a proxy writes" in built.doc["description"] and "every tool line" not in built.yaml


# --- E-3, E-4: as typed and as capture writes it ----------------------------------------------------------------------

def test_redo_e3_a_program_is_matched_as_typed_and_as_lower_cased(home):
    res = ruleform.test(ans(values="R", fires="R", quiet="ls"), str(home))
    assert res.ok and ("values", "R is also matched as r (an os or host line's image is lower case)") in res.notes
    rule = res.rule
    bash = [{"ts": "2026-11-11T08:00:01.000Z", "seq": 1, "session_id": "s", "phase": "pre", "tool": "Bash",
             "cwd": "/w", "input_sha256": "0" * 64, "input_meta": {"command_head": "R", "command_programs": ["R"]}}]
    assert engine.judge(rule, bash, {})[0]
    # must not touch: a name typed in lower case makes the rule it made before
    assert ruleform.build(ans()).doc["match"]["all"][1]["any"][0]["all"][2]["in"] == ["terraform"]
    # REDO 2 F-2: curl.exe is matched as an image is named and as typed
    assert ruleform.check_program("curl.exe") == (["curl", "curl.exe"], "curl.exe is also matched as curl (an os or"
                                                  " host line names its image curl)", None)


def test_redo_e4_a_home_place_is_also_written_with_the_home(home):
    where = ("/home/user", "posix")   # REDO 2 F-1: pure in the home and its system (F-1's own tests: test_ruleform_redo2)
    res = ruleform.test(ans(when="path", values="~/.aws", fires="~/.aws/x", quiet="/tmp/x"), str(home), where=where)
    assert res.ok and any("also matched as /home/user/.aws" in w for f, w in res.notes if f == "values")
    under = res.rule.doc["match"]["all"][3]["any"][0]["under_any"]
    assert under == ["~/.aws", "/home/user/.aws"]
    read = [{"ts": "2026-11-11T08:00:01.000Z", "seq": 1, "session_id": "s", "phase": "pre", "tool": "Read",
             "cwd": "/w", "input_sha256": "0" * 64, "input_meta": {"path": "/home/user/.aws/c"}}]
    assert engine.judge(res.rule, read, {})[0]   # fires where a tool is aimed
    plain = ruleform.build(ans(when="path", values="/srv/data", fires="/srv/data/a", quiet="/tmp/a"))
    assert plain.doc["match"]["all"][3]["any"][0]["under_any"] == ["/srv/data"]   # must not touch
    assert ruleform.VALUE_HINTS["path"].startswith("Whole places, separated by commas (/srv/data")


# --- E-6: Remove ------------------------------------------------------------------------------------------------------

def test_redo_e6_a_rule_refused_at_load_is_removed_and_ids_ignore_case(home):
    d = Path(overlay.user_dir(str(home))) / "my-old"
    d.mkdir(parents=True)
    (d / "my-old.yaml").write_text("id: broken\n")
    rules = overlay.load(str(home))
    assert [u["rule_id"] for u in overlay.describe(rules)["user_refused_ids"]] == ["my-old"]
    res = ruleform.test(ans(rid="MY-OLD"), str(home))
    assert res.refusals[0][0] == "id" and "taken" in res.refusals[0][1]   # compared without regard to case
    assert "removed" in overlay.remove_rule("my-old", home=str(home)) and rules_d(home) == []
    with pytest.raises(overlay.OverlayError, match="switch it off instead"):
        overlay.remove_rule("net-tool", home=str(home))


def test_redo_e6_a_removal_that_deletes_nothing_changes_nothing(home, monkeypatch):
    """Superseded by REDO 2 F-4 (the Table ledger: E-6's "overlay entry first" made a failed Remove switch a rule
    back on): every check first, the rule file first, the entry only once the rule file is gone."""
    assert ruleform.add(ans(), str(home)).ok
    overlay.set_status("MY-X", "off", home=str(home))
    real = os.remove

    def fails(path, *a, **k):
        raise OSError(13, "Permission denied")
    monkeypatch.setattr(overlay.os, "remove", fails)
    with pytest.raises(overlay.OverlayError) as err:
        overlay.remove_rule("MY-X", home=str(home))
    monkeypatch.setattr(overlay.os, "remove", real)
    text = str(err.value)
    assert text.startswith("nothing was removed: ") and "Permission denied" in text and "MY-X.yaml" in text
    doc, _, _ = overlay.read(overlay.overlay_path(str(home)))
    assert doc["rules"]["MY-X"]["status"] == "off" and rules_d(home) == ["MY-X"]
    assert next(r for r in overlay.load(str(home)) if r.id == "MY-X").status == "disabled"   # it stays off


def test_redo_e6_a_link_below_rules_d_is_refused(home, tmp_path):
    """REDO 2 F-5 supersedes E-6's refusal of a linked rules.d (followed by Add and Remove alike:
    test_ruleform_redo2); a link BELOW rules.d is refused, nothing deleted."""
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "keep.txt").write_text("x")
    Path(overlay.user_dir(str(home))).mkdir(parents=True)
    try:
        os.symlink(str(elsewhere), os.path.join(overlay.user_dir(str(home)), "MY-X"), target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("no symlink here (the junction case: test_ruleform_redo3)")
    # REDO 3 G-6 (S7): the refusal's own words, never a word the tmp path holds ("link" is in this test's name)
    words = "%s is a link, not a rule folder: nothing removed" % os.path.join(overlay.user_dir(str(home)), "MY-X")
    with pytest.raises(overlay.OverlayError) as err:
        overlay.remove_rule("MY-X", home=str(home))
    assert str(err.value).startswith(words), str(err.value)
    assert (elsewhere / "keep.txt").read_text() == "x"


def test_redo_e10_remove_dry_run_says_what_it_would_delete(home):
    assert ruleform.add(ans(), str(home)).ok
    code, out = run_cli(["rules", "--remove", "MY-X", "--dry-run"])
    assert code == 0 and "dry run: would delete" in out and "MY-X.yaml" in out and rules_d(home) == ["MY-X"]
    code, out = run_cli(["rules", "--remove", "MY-X"])
    assert code == 0 and rules_d(home) == []


# --- E-8: what a person's fixtures can measure -------------------------------------------------------------------

def test_redo_e8_a_quiet_example_the_rule_could_never_fire_on_is_refused(home):
    res = ruleform.test(ans(when="path", values="/srv/data", fires="/srv/data/a", quiet="C:\\work\\a.txt"), str(home))
    assert [f for f, _ in res.refusals] == ["quiet"] and "could never fire on" in res.refusals[0][1]
    # must not touch: a quiet example of the same system, or any with a pattern among the places
    assert ruleform.test(ans(when="path", values="/srv/data", fires="/srv/data/a", quiet="/tmp/a"), str(home)).ok
    assert ruleform.test(ans(when="path", values="/srv/*.pem", fires="/srv/a.pem", quiet="C:\\a.txt"), str(home)).ok


def test_redo_e8_fp_budget_zero_and_said(home):
    res = ruleform.test(ans(), str(home))
    assert res.ok and res.rule.fp_budget == 0 and ruleform.MEASURED in res.said
    assert "measured on the examples you gave, not on a corpus" == ruleform.MEASURED


# --- E-9: staging leftovers, the walk ------------------------------------------------------------------------------

def test_redo_e9_leftover_staging_folders_are_swept_and_counted(home):
    base = Path(ruleform.staging_dir(str(home)))
    (base / "form-crashed1").mkdir(parents=True)
    (base / "form-crashed1" / "MY-X.yaml").write_text("x")
    (base / "form-crashed2").mkdir()
    (base / "kept-other").mkdir()   # must not touch: only the form's own folders
    old = 1000000000   # REDO 2 F-7: older than ten minutes (a younger one may be another Test's)
    for name in ("form-crashed1", "form-crashed2", "kept-other"):
        os.utime(str(base / name), (old, old))
    res = ruleform.test(ans(), str(home))
    assert res.ok and ("rule", "2 staging folders an earlier Test left were removed") in res.notes
    assert sorted(p.name for p in base.iterdir()) == ["kept-other"]


def test_redo_e9_record_files_follow_no_link(home, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "x.jsonl").write_text("{}\n")
    traces = Path(overlay.raqib_dir(str(home))) / "traces"
    traces.mkdir(parents=True)
    try:
        os.symlink(str(outside), str(traces / "linked"), target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("no symlink here")
    assert ruleform.record_files(str(home)) == ([], False, [("traces/linked", "a link", "folder")])   # F-7, G-3


# --- E-10: the words and the terminal -----------------------------------------------------------------------------

def test_redo_e10_json_with_new_is_refused_and_the_dry_run_counts_records(home, capsys):
    code, _ = run_cli(["rules", "--new", "MY-X", "--when", "program", "--values", "curl", "--severity", "low",
                       "--fires", "curl", "--quiet", "ls", "--json"])
    assert code == 2 and "--json does not apply" in capsys.readouterr().err
    base = Path(overlay.raqib_dir(str(home))) / "host" / "sources"
    base.mkdir(parents=True)
    lines, _, _ = fixtures.load_fixture(FIX / "NET-TOOL" / "positive-host-child.json")
    (base / "run-1.jsonl").write_text("".join(json.dumps(r) + "\n" for r in lines))
    code, out = run_cli(["rules", "--new", "MY-X", "--when", "program", "--values", "curl", "--severity", "low",
                         "--fires", "curl", "--quiet", "ls", "--dry-run"])
    assert code == 0 and "would have fired on 1 of %d lines in 1 file;" % len(lines) in out
    assert "host/sources/run-1.jsonl, seq 1" in out and rules_d(home) == []
