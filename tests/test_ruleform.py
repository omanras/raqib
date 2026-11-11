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

from raqib import app, cli, host, overlay, ruleform  # noqa: E402
from raqib.rules import engine, fixtures, trace, yamlite  # noqa: E402

FORMS = {
    "program": ("terraform, tofu", "terraform", "ls"),
    "path": ("~/.aws, C:\\Users\\user\\secrets, /srv/keys/*.pem", "~/.aws/example.txt", "/work/example/notes.txt"),
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

# REDO 2 F-1: the home a ~ place stands for and its system are arguments: both shapes run on every system
WHERE = {"posix": ("/home/user", "posix"), "windows": ("C:\\Users\\user", "windows")}
PATH_EXAMPLES = {"posix": ("/home/user/.aws/example.txt", "/work/example/notes.txt"),
                 "windows": ("C:\\Users\\user\\.aws\\example.txt", "C:\\work\\example\\notes.txt")}


@pytest.mark.parametrize("when, system", [(w, "posix") for w in sorted(FORMS)] + [("path", "windows")])
def test_e1_e7_each_form_makes_a_rule_the_engine_accepts(home, when, system):
    where = WHERE[system]
    a = answers(when)
    expected = PATH_EXAMPLES[system] if when == "path" else (a["fires"], a["quiet"])   # REDO E-4, REDO 2 F-1
    assert ruleform.examples(when, a["values"], where) == expected   # E5: prefilled from the first name
    a["fires"], a["quiet"] = expected   # the form's own prefilled examples pass its Test
    built = ruleform.build(a, ruleform.taken_ids(str(home)), where)
    assert built.yaml.isascii() and yamlite.loads(built.yaml) == built.doc   # written in what the loader reads
    doc = built.doc
    assert doc["kind"] == "signature" and doc["evasion"] == list(ruleform.EVASIONS[when]) and doc["evasion"]
    assert doc["class"] == "USER" and "USER" in engine.CLASSES and engine.CLASSES[-1] == "HOST"   # REDO E-7
    assert doc["fp_budget"] == 0 and ruleform.MEASURED in doc["description"]   # REDO E-8
    assert ruleform.READS[when] in doc["description"]   # which lines it reads, said
    tested = ruleform.test(a, str(home), where=where)
    assert tested.ok, tested.refusals
    assert rules_d(home) == [] and not staged(home)   # Test writes nothing in rules.d; staging emptied
    added = ruleform.add(a, str(home), where=where)
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
    if when == "path":   # F-1: one path of the home's system, held beside the place as typed
        held = rule.doc["match"]["all"][3]["any"][0]["under_any"]
        assert held[:2] == ["~/.aws", WHERE[system][0] + ("\\.aws" if system == "windows" else "/.aws")]


def test_e1_the_path_form_reads_places_and_patterns(home):
    a = answers("path", values="/srv/keys/*.pem", fires="/srv/keys/a.pem", quiet="/srv/keys/a.txt")
    assert ruleform.test(a, str(home)).ok
    built = ruleform.build(a)
    assert {"field": "input_meta.path", "glob": "/srv/keys/*.pem"} in built.doc["match"]["all"][3]["any"]
    a = answers("path", values="C:\\Users\\user\\secrets", fires="c:/users/USER/secrets/a.txt", quiet="C:\\work\\a.txt")
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
    assert ruleform.check_program("Curl.EXE") == (["curl", "curl.exe", "Curl.EXE"], "Curl.EXE is also matched as curl"
                                                  " and curl.exe (an os or host line names its image curl; curl.exe:"
                                                  " as typed in lower case)", None)   # REDO 2 F-2
    assert ruleform.check_host("Paste.Example.COM") == (["paste.example.com"], None, None)


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


def _host_child_lines():
    """REDO E-10 (P15): the host source's own lines, as the host watch writes them (NET-TOOL's fixture)."""
    body = json.loads((ROOT / "tests" / "fixtures" / "rules" / "NET-TOOL" / "positive-host-child.json").read_text())
    return body["lines"]


def _write_records(home):
    base = Path(overlay.raqib_dir(str(home)))
    t = base / "traces" / "demo-1" / "raqib.log.jsonl"
    t.parent.mkdir(parents=True)
    t.write_text("".join(json.dumps(r) + "\n" for r in _trace_lines(["ls", "curl", "make", "terraform"])))
    s = base / "host" / "sources" / "run-1-tree.jsonl"
    s.parent.mkdir(parents=True)
    lines = _host_child_lines()
    assert lines and all(r.get("source") == "host" for r in lines)
    s.write_text("".join(json.dumps(r) + "\n" for r in lines))
    os.utime(str(t), (1000000000, 1000000000))   # the trace is the older file
    return t, s, len(lines)


def test_e3_on_your_records_counts_the_lines_it_would_have_fired_on(home):
    _, _, host_n = _write_records(home)
    before = {p: p.stat().st_mtime for p in Path(overlay.raqib_dir(str(home))).rglob("*.jsonl")}
    a = answers("program", values="curl", fires="curl", quiet="ls")
    res = ruleform.test(a, str(home))
    r = res.records
    # REDO E-2: the host watch gives host lines to a rule that names HostChild: the program rule reads them
    assert host.reads_host_lines(res.rule) and r["not_host"] == 0
    # REDO 2 F-11: exact - the trace's curl (seq 2) and the host source's one HostChild line that starts curl
    assert (r["files"], r["lines"]) == (2, 4 + host_n) and r["fired"] == 2 and r["fired_files"] == 2
    assert r["cited"][0] == ("host/sources/run-1-tree.jsonl", 1)   # newest file first; up to three
    assert ("traces/demo-1/raqib.log.jsonl", 2) in r["cited"]
    text = ruleform.records_text(r)
    assert text.startswith("on your records: would have fired on %d of %d lines in 2 files (in 2 of them)"
                           % (r["fired"], 4 + host_n))
    assert "never a gate" in text and "the newest 20 files" in text
    assert {p: p.stat().st_mtime for p in before} == before   # read-only
    bounded = ruleform.on_records(res.rule, str(home), max_files=1, max_lines=1)
    assert (bounded["files"], bounded["lines"], bounded["more_files"]) == (1, 1, 1)
    assert "1 older file not read" in ruleform.records_text(bounded)
    # E-2, must not touch: a rule that does not name HostChild is not given host lines (said, not judged)
    tool = ruleform.test(answers("tool"), str(home)).records
    assert tool["not_host"] == 1 and (tool["files"], tool["lines"], tool["fired"]) == (1, 4, 0)
    assert "would have fired on 0 of 4 lines in 1 file;" in ruleform.records_text(tool)
    assert "1 host source file not judged" in ruleform.records_text(tool)
    walked = ruleform.on_records(res.rule, str(home), max_entries=1)
    assert walked["walk_cut"] and "the walk stopped at 1 entries" in ruleform.records_text(walked)


def test_e3_no_records_is_said_and_never_gates(home):
    res = ruleform.test(answers("host"), str(home))
    assert res.ok and res.records["files"] == 0
    assert "no trace or host source file under ~/.raqib this rule would read yet" in ruleform.records_text(
        res.records)


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

# REDO E-10 (P15): an allow-list - every call ruleform makes on a module, and every open's mode, is named here;
# REDO 2 F-11: names bound by an import are resolved (import os as o is os), a module's function is only called
# (never bound to a name), and every entry is used
ALLOWED_MODULE_CALLS = {
    ("os", "makedirs"), ("os", "listdir"), ("os", "rmdir"), ("os", "lstat"), ("os", "walk"),
    ("shutil", "rmtree"), ("tempfile", "mkdtemp"), ("hashlib", "sha256"), ("json", "dumps"), ("re", "split"),
    ("re", "compile"), ("os.path", "join"), ("os.path", "dirname"), ("os.path", "basename"),
    ("os.path", "realpath"), ("os.path", "islink"), ("os.path", "isdir"), ("os.path", "getmtime"),
    ("os.path", "relpath"), ("os.path", "expanduser"), ("os.path", "lexists"), ("time", "time"),
}
ALLOWED_MODULE_VALUES = {("os", "SEEK_END"), ("os", "name"), ("os", "path"), ("sys", "version_info")}
STDLIB = ("os", "os.path", "shutil", "tempfile", "hashlib", "json", "re", "sys", "time", "subprocess")
WRITERS = {"_new_stage": {"makedirs", "mkdtemp"}, "_write_stage": {"open-w"}, "_unstage": {"rmtree", "rmdir"}}


def _bound_modules(tree):
    """{name bound in the module: the module it stands for} of every import (an alias resolved)."""
    out = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                out[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
        elif isinstance(n, ast.ImportFrom) and n.module in STDLIB:
            for a in n.names:
                out[a.asname or a.name] = "%s.%s" % (n.module, a.name)
    return out


def _owner(node, bound):
    """The module an expression stands for (os, os.path), resolved through the import names, or None."""
    if isinstance(node, ast.Name):
        return bound.get(node.id)
    if isinstance(node, ast.Attribute):
        base = _owner(node.value, bound)
        return "%s.%s" % (base, node.attr) if base else None
    return None


def test_a4_ruleform_writes_only_in_its_staging_place_and_starts_nothing():
    src = (ROOT / "raqib" / "ruleform.py").read_text(encoding="ascii")
    tree = ast.parse(src)
    bound = _bound_modules(tree)
    imported = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    assert imported == {"hashlib", "json", "os", "re", "shutil", "sys", "tempfile", "time"}, imported
    froms = {(n.module, a.name) for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) for a in n.names}
    assert froms == {("__future__", "annotations"), ("raqib", "discover"), ("raqib", "host"), ("raqib", "overlay"),
                     ("raqib.hooks", "common"), ("raqib.rules", "engine"), ("raqib.rules", "trace"),
                     ("raqib.rules", "yamlite")}, froms
    called = {id(c.func) for c in ast.walk(tree) if isinstance(c, ast.Call)}
    used = set()
    for node in ast.walk(tree):   # every use of a module's attribute: a call in the list, or a listed value
        if isinstance(node, ast.Attribute) and _owner(node.value, bound) in STDLIB:
            pair = (_owner(node.value, bound), node.attr)
            if id(node) in called:
                assert pair in ALLOWED_MODULE_CALLS, pair
                used.add(pair)
            else:
                assert pair in ALLOWED_MODULE_VALUES or "%s.%s" % pair in STDLIB, pair   # never f = shutil.rmtree
    assert used == ALLOWED_MODULE_CALLS, ALLOWED_MODULE_CALLS - used   # no entry the module does not use
    funcs = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
    writers = {}
    for name, fn in funcs.items():
        for sub in ast.walk(fn):
            if not isinstance(sub, ast.Call):
                continue
            f = sub.func
            if isinstance(f, ast.Name):
                assert f.id not in ("exec", "eval", "compile", "__import__", "setattr", "globals"), (name, f.id)
                assert f.id not in bound or bound[f.id] not in STDLIB, (name, f.id)   # no module called by a bare name
                if f.id == "getattr":   # only a named attribute (st_file_attributes, isjunction), never a computed one
                    assert isinstance(sub.args[1], ast.Constant) and sub.args[1].value in (
                        "st_file_attributes", "isjunction", "doc"), (name, ast.dump(sub)[:80])
            owner = _owner(f.value, bound) if isinstance(f, ast.Attribute) else None
            if owner in STDLIB and f.attr in ("makedirs", "mkdtemp", "rmtree", "rmdir"):
                writers.setdefault(name, set()).add(f.attr)
            if isinstance(f, ast.Name) and f.id == "open":
                modes = [a.value for a in sub.args[1:2] if isinstance(a, ast.Constant)] + \
                        [k.value.value for k in sub.keywords if k.arg == "mode" and isinstance(k.value, ast.Constant)]
                assert modes and all(m in ("rb", "w") for m in modes), (name, modes)
                if modes != ["rb"]:
                    writers.setdefault(name, set()).add("open-" + modes[0])
    assert writers == WRITERS
    stage = ast.get_source_segment(src, funcs["_new_stage"])
    assert "base = staging_dir(home)" in stage and "overlay.fixture_file(overlay.raqib_dir(home), STAGING_NAME)" in stage
    assert "overlay.fixture_file(stage, rel)" in ast.get_source_segment(src, funcs["_write_stage"])
    unstage = ast.get_source_segment(src, funcs["_unstage"])
    assert "os.path.realpath(staging_dir(home))" in unstage and "os.path.dirname(real) != base" in unstage
    # Add reaches rules.d through overlay.add_rule only (the --add path)
    calls = {c.func.attr for c in ast.walk(funcs["add"]) if isinstance(c, ast.Call)
             and isinstance(c.func, ast.Attribute) and getattr(c.func.value, "id", None) == "overlay"}
    assert calls == {"add_rule"}
    assert os.path.dirname(ruleform.staging_dir("/h")) == overlay.raqib_dir("/h")

