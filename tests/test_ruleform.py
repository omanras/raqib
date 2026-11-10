"""M8.2 (ADR-0009 decisions 4-5): a rule made from a form (raqib/ruleform.py), Remove, `raqib rules --new`
and `--remove`. The generated rule is judged by the engine's loader and the fixture runner (A6), never by
the form; nothing is written in rules.d when anything is refused (E2); the staging place is emptied."""
import ast
import io
import json
import os
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from raqib import app, cli, overlay, ruleform  # noqa: E402
from raqib.rules import engine, fixtures, trace, yamlite  # noqa: E402

FORMS = {
    "program": ("terraform, tofu", "terraform", "ls"),
    "path": ("~/.aws, C:\\Users\\me\\secrets, /srv/keys/*.pem", "~/.aws/example.txt", "/work/example/notes.txt"),
    "host": ("paste.example.com", "paste.example.com", "example.org"),
    "tool": ("WebSearch, mcp__notes__write", "WebSearch", "Read"),
}


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    path = tmp_path / "home"
    path.mkdir()
    monkeypatch.setenv("HOME", str(path))
    monkeypatch.setenv("USERPROFILE", str(path))
    overlay._MEASURED.clear()
    yield path
    overlay._MEASURED.clear()


def answers(form, rid=None, **kw):
    values, fires, quiet = FORMS[form]
    a = {"id": rid or "MY-%s" % form.upper(), "when": form, "values": values, "severity": "high",
         "fires": fires, "quiet": quiet}
    a.update(kw)
    return a


def rules_d(home):
    d = Path(overlay.user_dir(str(home)))
    return sorted(p.name for p in d.iterdir()) if d.is_dir() else []


def staged(home):
    return Path(ruleform.staging_dir(str(home))).exists()


def run_cli(argv):
    out = io.StringIO()
    return cli.main(argv, out=out), out.getvalue()


# --- E1, E2, E7: per form the rule loads, its fixtures pass, the positive fires, the negative does not --------

@pytest.mark.parametrize("when", sorted(FORMS))
def test_e1_e7_each_form_makes_a_rule_the_engine_accepts(home, when):
    a = answers(when)
    assert ruleform.examples(when, a["values"]) == (a["fires"], a["quiet"])   # E5: prefilled from the first name
    built = ruleform.build(a, ruleform.taken_ids(str(home)))
    assert built.yaml.isascii() and yamlite.loads(built.yaml) == built.doc   # written in what the loader reads
    doc = built.doc
    assert doc["kind"] == "signature" and doc["evasion"] == list(ruleform.EVASIONS[when]) and doc["evasion"]
    assert doc["class"] not in ("HOST", engine.CODE_CLASS) and doc["class"] in engine.CLASSES
    assert ruleform.READS[when] in doc["description"]   # which lines it reads, said
    tested = ruleform.test(a, str(home))
    assert tested.ok, tested.refusals
    assert rules_d(home) == [] and not staged(home)   # Test writes nothing in rules.d; staging emptied
    added = ruleform.add(a, str(home))
    assert added.ok, added.refusals
    assert "added as" in added.said and "origin: user" in added.said
    assert rules_d(home) == [a["id"]] and not staged(home)
    rule = next(r for r in overlay.load(str(home)) if r.id == a["id"])
    assert rule.origin == "user" and rule.kind == "signature" and rule.severity == "high"
    result = fixtures.check_rule(rule, rule.fixture_root)
    assert result["verdict"] == "ok" and all(p["fired"] for p in result["positives"])
    assert result["negatives"] and all(n["measured"] and not n["fired"] for n in result["negatives"])
    for rel in rule.fixtures["positive"]:
        assert fixtures.fires(rule, os.path.join(rule.fixture_root, rel))
    for rel in rule.fixtures["negative"]:
        assert not fixtures.fires(rule, os.path.join(rule.fixture_root, rel))
    if when == "program":   # the three lines NET-TOOL reads: Bash, the host's HostChild, the os process image
        assert sorted(rule.fixtures["positive"]) == ["positive-bash.json", "positive-host.json", "positive-os.json"]


def test_e1_the_path_form_reads_places_and_patterns(home):
    a = answers("path", values="/srv/keys/*.pem", fires="/srv/keys/a.pem", quiet="/srv/keys/a.txt")
    assert ruleform.test(a, str(home)).ok
    built = ruleform.build(a)
    assert {"field": "input_meta.path", "glob": "/srv/keys/*.pem"} in built.doc["match"]["all"][3]["any"]
    a = answers("path", values="C:\\Users\\me\\secrets", fires="c:/users/ME/secrets/a.txt", quiet="C:\\work\\a.txt")
    assert ruleform.test(a, str(home)).ok   # placed by the engine's own path rule (Windows folded A-Z)


@pytest.mark.parametrize("answers_kw, field, words", [
    ({"id": ""}, "id", "empty"),
    ({"id": "my-rule"}, "id", "upper-case"),
    ({"id": "MYRULE"}, "id", "dashes"),
    ({"id": "../../X-1"}, "id", "upper-case"),
    ({"id": "NET-TOOL"}, "id", "taken"),
    ({"id": "A-" + "B" * 60}, "id", "at most"),
    ({"when": "file"}, "when", "choose one"),
    ({"severity": "urgent"}, "severity", "low, medium, high"),
    ({"values": " , "}, "values", "empty"),
    ({"values": "/usr/bin/curl"}, "values", "a path"),
    ({"values": "cu rl"}, "values", "not a program name"),
    ({"values": ",".join("p%d" % i for i in range(40))}, "values", "at most"),
    ({"fires": ""}, "fires", "empty"),
    ({"quiet": "C:\\x\\ls.exe"}, "quiet", "a path"),
    ({"title": "a {seq} title"}, "title", "no { or }"),
    ({"title": "x" * 90}, "title", "at most"),
])
def test_e1_each_refusal_names_its_field(home, answers_kw, field, words):
    res = ruleform.test(answers("program", **answers_kw), str(home))
    assert not res.ok and field in [f for f, _ in res.refusals], res.refusals
    assert any(words in why for f, why in res.refusals if f == field), res.refusals
    assert rules_d(home) == [] and not staged(home)   # nothing written when anything is refused


@pytest.mark.parametrize("when, kw, field, words", [
    ("host", {"values": "https://example.com/x"}, "values", "a URL"),
    ("host", {"values": "*.example.com"}, "values", "sub-domain"),
    ("host", {"values": "exa_mple.com"}, "values", "not a host name"),
    ("tool", {"values": "1Read"}, "values", "not a tool name"),
    ("path", {"values": "src/secrets"}, "values", "not a whole path"),
    ("path", {"values": "/srv/../etc"}, "values", ".. part"),
    ("path", {"values": "/srv/da\tta"}, "values", "control"),
    ("path", {"values": "/srv/[ab]"}, "values", "[ ] sets"),
    ("path", {"fires": "/srv/*.pem"}, "fires", "no * or ?"),
])
def test_e1_names_and_places_pass_the_capture_rules(home, when, kw, field, words):
    res = ruleform.test(answers(when, **kw), str(home))
    assert any(f == field and words in why for f, why in res.refusals), res.refusals
    assert rules_d(home) == []


def test_e1_program_names_are_lower_cased_as_discover_names_images():
    assert ruleform.check_program("Curl.EXE") == ("curl", None)
    assert ruleform.check_host("Paste.Example.COM") == ("paste.example.com", None)


def test_e2_the_examples_are_judged_by_the_engine_not_the_form(home):
    res = ruleform.test(answers("program", fires="wget"), str(home))   # wget is not watched: the engine says so
    assert [f for f, _ in res.refusals] == ["fires"] and "positive-missed" in res.refusals[0][1]
    res = ruleform.test(answers("program", quiet="tofu"), str(home))   # tofu is watched: the negative fires
    assert [f for f, _ in res.refusals] == ["quiet"] and "over-budget" in res.refusals[0][1]
    assert rules_d(home) == [] and not staged(home)
    calls = []
    real = overlay.validate_rule
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(overlay, "validate_rule", lambda *a, **k: calls.append(k) or real(*a, **k))
        assert ruleform.test(answers("tool"), str(home)).ok
        assert ruleform.add(answers("tool"), str(home)).ok   # add_rule validates again
    assert calls and all(c.get("user") for c in calls)


def test_e2_class_host_is_refused_by_the_overlays_check(home, monkeypatch):
    monkeypatch.setitem(ruleform.CLASS_OF, "tool", "HOST")
    res = ruleform.add(answers("tool"), str(home))
    assert not res.ok and overlay.HOST_FIXED in res.refusals[0][1]
    assert rules_d(home) == [] and not staged(home)


def test_e2_an_id_taken_by_a_user_rule_or_its_folder_is_refused(home):
    assert ruleform.add(answers("tool"), str(home)).ok
    res = ruleform.test(answers("host", rid="MY-TOOL"), str(home))
    assert res.refusals[0][0] == "id" and "taken" in res.refusals[0][1]
    (Path(overlay.user_dir(str(home))) / "MY-OLD").mkdir()   # a folder refused at load still holds its id
    assert ruleform.test(answers("host", rid="MY-OLD"), str(home)).refusals[0][0] == "id"


def test_e2_a1_every_generated_file_passes_the_fixture_path_checks(home):
    for when in FORMS:
        built = ruleform.build(answers(when))
        for rel in list(built.files) + [built.rid + ".yaml"]:
            assert engine.fixture_path_problem(rel) is None and "/" not in rel and "\\" not in rel
            assert overlay.fixture_file(str(home), rel)
        for rel, text in built.files.items():
            body = json.loads(text)
            assert set(body) <= fixtures.OBJECT_KEYS and body.get("expect_seq", [1]) == [1]
            assert all(trace.strict_problem(r) is None for r in body["lines"])   # in the shape capture writes
            assert text.isascii()


def test_e2_a_staging_place_that_is_a_link_is_refused(home, tmp_path):
    raqib_dir = Path(overlay.raqib_dir(str(home)))
    raqib_dir.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    try:
        os.symlink(str(elsewhere), str(raqib_dir / ruleform.STAGING_NAME), target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("no symlink here")
    res = ruleform.test(answers("tool"), str(home))
    assert not res.ok and "link" in res.refusals[0][1]
    assert list(elsewhere.iterdir()) == []


# --- E3: on your records -------------------------------------------------------------------------------------------

def _trace_lines(heads, sid="s-1"):
    out = []
    for i, head in enumerate(heads, start=1):
        out.append({"ts": "2026-11-11T08:00:%02d.000Z" % i, "seq": i, "session_id": sid, "phase": "pre",
                    "tool": "Bash", "cwd": "/work/demo", "input_sha256": "0" * 64,
                    "input_meta": {"command_head": head, "command_programs": [head]}})
    return out


def _write_records(home):
    base = Path(overlay.raqib_dir(str(home)))
    t = base / "traces" / "demo-1" / "raqib.log.jsonl"
    t.parent.mkdir(parents=True)
    t.write_text("".join(json.dumps(r) + "\n" for r in _trace_lines(["ls", "terraform", "make", "tofu"])))
    s = base / "host" / "sources" / "run-1-tree.jsonl"
    s.parent.mkdir(parents=True)
    s.write_text("".join(json.dumps(r) + "\n" for r in _trace_lines(["terraform", "git"], sid="s-2")))
    os.utime(str(t), (1000000000, 1000000000))   # the trace is the older file
    return t, s


def test_e3_on_your_records_counts_the_lines_it_would_have_fired_on(home):
    _write_records(home)
    before = {p: p.stat().st_mtime for p in Path(overlay.raqib_dir(str(home))).rglob("*.jsonl")}
    res = ruleform.test(answers("program"), str(home))
    r = res.records
    assert (r["files"], r["lines"], r["fired"], r["fired_files"]) == (2, 6, 3, 2)
    assert r["cited"] == [("host/sources/run-1-tree.jsonl", 1), ("traces/demo-1/raqib.log.jsonl", 2),
                          ("traces/demo-1/raqib.log.jsonl", 4)]   # newest file first; up to three
    text = ruleform.records_text(r)
    assert text.startswith("on your records: would have fired on 3 of 6 lines in 2 files")
    assert "never a gate" in text and "the newest 20 files" in text
    assert ruleform.cited_text(r)[0] == "host/sources/run-1-tree.jsonl, seq 1"
    assert {p: p.stat().st_mtime for p in before} == before   # read-only
    bounded = ruleform.on_records(res.rule, str(home), max_files=1, max_lines=1)
    assert (bounded["files"], bounded["lines"], bounded["more_files"]) == (1, 1, 1)
    assert "1 older files not read" in ruleform.records_text(bounded)
    quiet = ruleform.test(answers("tool"), str(home)).records
    assert quiet["fired"] == 0 and "would have fired on 0 of 6 lines" in ruleform.records_text(quiet)


def test_e3_no_records_is_said_and_never_gates(home):
    res = ruleform.test(answers("host"), str(home))
    assert res.ok and res.records["files"] == 0
    assert "no trace or host source file under ~/.raqib yet" in ruleform.records_text(res.records)


# --- E4: Remove --------------------------------------------------------------------------------------------------------

def test_e4_remove_a_user_rule_deletes_its_folder_and_its_overlay_lines(home):
    assert ruleform.add(answers("tool"), str(home)).ok
    assert ruleform.add(answers("host"), str(home)).ok
    overlay.set_status("MY-TOOL", "off", home=str(home))
    keep = Path(overlay.raqib_dir(str(home))) / "keep.txt"
    keep.write_text("x")
    said = overlay.remove_rule("MY-TOOL", home=str(home))
    assert "MY-TOOL removed" in said and "entry dropped" in said and overlay.NEXT_WATCH in said
    assert rules_d(home) == ["MY-HOST"] and keep.read_text() == "x"
    doc, state, _ = overlay.read(overlay.overlay_path(str(home)))
    assert state == "read" and "MY-TOOL" not in doc["rules"]
    assert "it had no entry" in overlay.remove_rule("MY-HOST", home=str(home))
    assert rules_d(home) == []


def test_e4_a_package_rule_is_refused_switch_it_off_instead(home):
    with pytest.raises(overlay.OverlayError, match="switch it off instead"):
        overlay.remove_rule("NET-TOOL", home=str(home))
    for bad in ("../x", "..\\MY-X", "MY-NONE", ""):
        with pytest.raises(overlay.OverlayError):
            overlay.remove_rule(bad, home=str(home))


def test_e4_remove_follows_no_link(home, tmp_path):
    assert ruleform.add(answers("tool"), str(home)).ok
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "precious.txt").write_text("x")
    target = Path(overlay.user_dir(str(home))) / "MY-TOOL" / "link"
    try:
        os.symlink(str(outside), str(target), target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("no symlink here")
    with pytest.raises(overlay.OverlayError, match="link"):
        overlay.remove_rule("MY-TOOL", home=str(home))
    assert (outside / "precious.txt").read_text() == "x" and rules_d(home) == ["MY-TOOL"]


def test_e4_a_malformed_overlay_refuses_the_whole_removal(home):
    assert ruleform.add(answers("tool"), str(home)).ok
    Path(overlay.overlay_path(str(home))).write_text("rules: [\n")
    with pytest.raises(overlay.OverlayError):
        overlay.remove_rule("MY-TOOL", home=str(home))
    assert rules_d(home) == ["MY-TOOL"]


def test_e4_the_panel_says_a_running_watch_keeps_its_rules(home):
    assert ruleform.add(answers("tool"), str(home)).ok
    panel = app.RulesPanel(home=str(home))
    said = panel.remove_rule("MY-TOOL", running=True)
    assert panel.level == "clean" and "MY-TOOL removed" in said and "keeps the rules it started with" in said
    assert "MY-TOOL" not in [r["id"] for r in panel.rows]
    assert panel.remove_rule("NET-TOOL").startswith("REFUSED: ") and panel.level == "alarm"


def test_e4_the_panel_runs_the_form_through_ruleform(home):
    panel = app.RulesPanel(home=str(home))
    res = panel.test_form(answers("program"))
    assert res.ok and panel.form_passed == ruleform.fingerprint(answers("program"))
    assert not panel.can_add(answers("program", severity="low"))   # Add only after a Test of the same answers
    assert panel.can_add(answers("program"))
    res = panel.add_form(answers("program"))
    assert res.ok and "MY-PROGRAM" in [r["id"] for r in panel.rows] and panel.form_passed is None
    assert [r["origin"] for r in panel.rows if r["id"] == "MY-PROGRAM"] == ["user"]


# --- E6: the terminal -------------------------------------------------------------------------------------------

def _new(rid, *extra):
    return ["rules", "--new", rid, "--when", "program", "--values", "terraform,tofu", "--severity", "medium",
            "--fires", "terraform", "--quiet", "ls"] + list(extra)


def test_e6_rules_new_and_remove_in_the_terminal(home, capsys):
    code, out = run_cli(_new("MY-TF", "--dry-run"))
    assert code == 0 and 'id: "MY-TF"' in out and "dry run: nothing written" in out and rules_d(home) == []
    assert "test passed" in out and "on your records:" in out
    code, out = run_cli(_new("MY-TF"))
    assert code == 0 and "MY-TF added as" in out and rules_d(home) == ["MY-TF"] and not staged(home)
    code, out = run_cli(_new("MY-TF"))
    assert code == 2 and "taken" in capsys.readouterr().err
    code, out = run_cli(["rules", "--remove", "MY-TF"])
    assert code == 0 and "MY-TF removed" in out and rules_d(home) == []
    code, _ = run_cli(["rules", "--remove", "NET-TOOL"])
    assert code == 2 and "switch it off instead" in capsys.readouterr().err


def test_e6_the_terminal_refuses_with_the_forms_words(home, capsys):
    code, _ = run_cli(["rules", "--new", "MY-TF", "--when", "program", "--values", "/bin/curl", "--severity", "low",
                       "--fires", "curl", "--quiet", "ls"])
    err = capsys.readouterr().err
    assert code == 2 and "Names or places:" in err and "is a path" in err
    code, _ = run_cli(_new("MY-TF")[:-2] + ["--quiet", "tofu"])
    assert code == 2 and "Must stay quiet on" in capsys.readouterr().err and rules_d(home) == []
    code, _ = run_cli(["rules", "--when", "tool"])
    assert code == 2 and "apply to `raqib rules --new ID`" in capsys.readouterr().err


# --- A4: the guards ----------------------------------------------------------------------------------------------

def test_a4_ruleform_writes_only_in_its_staging_place_and_starts_nothing():
    tree = ast.parse((ROOT / "raqib" / "ruleform.py").read_text(encoding="ascii"))
    imported = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))
                for a in n.names} | {n.module.split(".")[0] for n in ast.walk(tree)
                                     if isinstance(n, ast.ImportFrom) and n.module}
    assert not imported & {"subprocess", "socket", "urllib", "http", "ctypes", "multiprocessing"}, imported
    funcs = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
    writers = {}
    for name, fn in funcs.items():
        for sub in ast.walk(fn):
            if not isinstance(sub, ast.Call):
                continue
            f = sub.func
            called = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", None)
            owner = getattr(f.value, "id", None) if isinstance(f, ast.Attribute) else None
            if owner in ("os", "shutil"):
                assert called not in ("system", "kill", "startfile", "replace", "rename", "remove", "unlink",
                                      "copy", "copyfile", "move", "symlink", "link"), (name, called)
            if called in ("makedirs", "mkdtemp", "rmtree", "rmdir", "mkdir"):
                writers.setdefault(name, set()).add(called)
            if called == "open":
                modes = [a.value for a in sub.args[1:] if isinstance(a, ast.Constant)]
                if modes and modes[0] != "rb":
                    writers.setdefault(name, set()).add("open-" + modes[0])
    assert writers == {"_stage": {"makedirs", "mkdtemp", "open-w"}, "_unstage": {"rmtree", "rmdir"}}
    stage = ast.get_source_segment((ROOT / "raqib" / "ruleform.py").read_text(encoding="ascii"), funcs["_stage"])
    assert "base = staging_dir(home)" in stage and "overlay.fixture_file(stage, rel)" in stage
    unstage = ast.get_source_segment((ROOT / "raqib" / "ruleform.py").read_text(encoding="ascii"),
                                     funcs["_unstage"])
    assert "os.path.realpath(staging_dir(home))" in unstage and "os.path.dirname(stage) == base" in unstage
    # Add reaches rules.d through overlay.add_rule only (the --add path)
    calls = {c.func.attr for c in ast.walk(funcs["add"]) if isinstance(c, ast.Call)
             and isinstance(c.func, ast.Attribute) and getattr(c.func.value, "id", None) == "overlay"}
    assert calls == {"add_rule"}
    assert staging_under_raqib()


def staging_under_raqib():
    return os.path.dirname(ruleform.staging_dir("/h")) == overlay.raqib_dir("/h")
