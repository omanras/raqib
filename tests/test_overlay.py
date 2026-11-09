"""M7.6 the rules panel (HANDOFF.md, ADR-0008 decisions 1-5): the overlay
~/.raqib/rules.yaml (raqib/overlay.py), the person's rules in
~/.raqib/rules.d, `raqib rules`, "rules off" said in every watch output, and
the window's Rules screen. Every test runs under a temporary HOME."""
import ast
import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from raqib import app, cli, discover, host, overlay, ui, watch  # noqa: E402
from raqib.rules import engine, fixtures, yamlite  # noqa: E402

CATALOG_DIR = ROOT / "raqib" / "rules" / "catalog"
QUESTIONS = ROOT / "docs" / "review" / "2026-11-09-M7.6-questions.md"
WINDOWS = os.name == "nt"


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    path = tmp_path / "home"
    path.mkdir()
    monkeypatch.setenv("HOME", str(path))
    monkeypatch.setenv("USERPROFILE", str(path))
    monkeypatch.delenv("RAQIB_GAP_SECONDS", raising=False)
    return path


def write_overlay(home, text):
    p = Path(overlay.overlay_path(str(home)))
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="ascii")
    return p


def by_id(rules, rid):
    return next(r for r in rules if r.id == rid)


# --- a person's rule, with its fixtures -----------------------------------------------------------

def line(seq, head, phase="pre"):
    rec = {"ts": "2026-11-09T10:00:%02d.000Z" % seq, "seq": seq, "session_id": "s-user", "phase": phase,
           "tool": "Bash", "cwd": "/work/demo", "input_sha256": "0" * 64, "input_meta": {"command_head": head}}
    if phase == "post":
        rec.update(output_sha256="1" * 64, ok=True, output_meta={"scan": "full", "secret_kinds": []})
    return rec


USER_RULE = """id: USER-SHRED
title: A Bash call runs shred
class: DESTRUCT
kind: signature
evasion:
  - "shred behind a wrapper (sudo, env) is the wrapper's call"
severity: low
fp_budget: 0.5
match:
  all:
    - {field: tool, eq: Bash}
    - {field: phase, eq: pre}
    - {field: input_meta.command_head, eq: shred}
fixtures:
  positive:
    - fx/USER-SHRED/positive.json
  negative:
    - fx/USER-SHRED/negative.json
"""


def user_rule(folder, text=USER_RULE, positive_head="shred", name="USER-SHRED"):
    folder = Path(folder)
    (folder / "fx" / "USER-SHRED").mkdir(parents=True, exist_ok=True)
    (folder / ("%s.yaml" % name)).write_text(text, encoding="ascii")
    (folder / "fx" / "USER-SHRED" / "positive.json").write_text(json.dumps([line(1, positive_head)]),
                                                                encoding="ascii")
    (folder / "fx" / "USER-SHRED" / "negative.json").write_text(json.dumps([line(1, "ls")]), encoding="ascii")
    return folder / ("%s.yaml" % name)


# --- E1: read, validate, apply, write ---------------------------------------------------------------

def test_e1_overlay_round_trip_and_atomic_write(home):
    doc = {"rules": {"HOST-RHYTHM": {"status": "off", "since": "2026-11-09T10:00:00Z", "thresholds": {"k": 5, "w": 60}},
                     "NET-TOOL": {"status": "on"}}}
    text = overlay.dumps(doc)
    assert text.isascii() and '"off"' in text and overlay.parse(text) == doc
    assert yamlite.loads(text)["raqib_overlay"] == 1
    path = overlay.write(doc, str(home))
    assert path == str(home / ".raqib" / "rules.yaml")
    assert overlay.read(path) == (doc, "read", None)
    assert sorted(os.listdir(home / ".raqib")) == ["rules.yaml"]   # no temp file left
    assert overlay.read(str(home / "none.yaml")) == ({"rules": {}}, "absent", None)
    assert overlay.parse("") == {"rules": {}} and overlay.dumps({"rules": {}}).endswith("rules: {}\n")


@pytest.mark.parametrize("text, word", [
    ("rules:\n  HOST-RHYTHM:\n    status: off\n", "quote it"),            # yamlite: plain off is ambiguous
    ("rules: [a, b]\n", "rules: must be a mapping"),
    ("other: 1\n", "unknown top-level key"),
    ("raqib_overlay: 2\nrules: {}\n", "raqib_overlay must be 1"),
    ("rules:\n  HOST-RHYTHM:\n    status: \"maybe\"\n", "must be \"on\" or \"off\""),
    ("rules:\n  HOST-RHYTHM:\n    thresholds: {k: \"5\"}\n", "whole number"),
    ("rules:\n  HOST-RHYTHM:\n    color: \"red\"\n", "unknown key"),
    ("rules:\n  HOST-RHYTHM: {}\n", "must be a mapping with status"),
    ("rules:\n  HOST-RHYTHM:\n    since: \"x\"\n", "says nothing"),
])
def test_e1_a_malformed_overlay_is_one_hole_and_nothing_is_applied(home, text, word):
    # a sound entry beside the bad one: nothing of the file applies
    write_overlay(home, "rules:\n  NET-TOOL:\n    status: \"off\"\n" + text.replace("rules:\n", "", 1)
                  if text.startswith("rules:\n  ") else text)
    rules = overlay.load(str(home))
    info = overlay.describe(rules)
    assert info["file"] == "malformed" and word in info["hole"] and "nothing of it is applied" in info["hole"]
    assert info["off"] == [] and info["applied"] == [] and all(r.status == "active" for r in rules)
    assert overlay.start_lines(info)[0].startswith("rules overlay: HOLE: ")
    with pytest.raises(overlay.OverlayError, match="never overwritten while malformed"):
        overlay.set_status("NET-TOOL", "off", str(home))


@pytest.mark.parametrize("entry, word", [
    ("NO-SUCH-RULE:\n    status: \"off\"", "no such rule"),
    ("HOST-RHYTHM:\n    thresholds: {q: 5}", "has no field 'q'"),
    ("HOST-RHYTHM:\n    thresholds: {cycles: 5}", "has no field"),
    ("HOST-RHYTHM:\n    thresholds: {k: 0}", "outside its bounds 1..100"),
    ("HOST-RHYTHM:\n    thresholds: {k: 101}", "outside its bounds 1..100"),
    ("HOST-RHYTHM:\n    thresholds: {w: 3601}", "outside its bounds 1..3600"),
    ("HOST-RHYTHM:\n    thresholds: {r: 1001}", "outside its bounds 1..1000"),
    ("AGENT-DARK-LIVE:\n    thresholds: {streak: 101}", "outside its bounds 1..100"),
    ("AGENT-DARK-LIVE:\n    thresholds: {live_window: 2}", "below its streak (3)"),
    ("AGENT-DARK-LIVE:\n    thresholds: {streak: 10}", "above its live_window (9)"),
    ("HOST-RHYTHM:\n    thresholds: {tool: 5}", "not a declared threshold"),           # an eq of the gate
    ("HOST-RHYTHM:\n    thresholds: {class: 5}", "not a declared threshold"),
    ("NET-TOOL:\n    thresholds: {command_head: 5}", "not an eq value"),
    ("NET-TOOL:\n    thresholds: {source: 5}", "not a declared threshold"),
    ("SCOPE-PATH:\n    thresholds: {path: 5}", "not an eq value"),                    # a non-eq field
])
def test_e1_every_refusal_names_its_reason_and_the_rest_applies(home, entry, word):
    write_overlay(home, "rules:\n  %s\n  SECRET-OUTPUT:\n    status: \"off\"\n" % entry)
    info = overlay.describe(overlay.load(str(home)))
    assert info["file"] == "read" and len(info["refused"]) == 1 and word in info["refused"][0], info["refused"]
    assert [o["rule_id"] for o in info["off"]] == ["SECRET-OUTPUT"]   # the sound entry applies
    assert any("REFUSED (not applied): " in s and word in s for s in overlay.start_lines(info))


def test_e1_the_overlay_cannot_turn_on_a_rule_its_yaml_disables(home, tmp_path):
    folder = tmp_path / "cat"
    folder.mkdir()
    for p in CATALOG_DIR.glob("*.yaml"):
        text = p.read_text(encoding="utf-8")
        if p.stem == "NET-TOOL":
            text = text.replace("fp_budget: 0.25\n", "fp_budget: 0.25\nstatus: disabled\n")
        (folder / p.name).write_text(text, encoding="utf-8")
    write_overlay(home, "rules:\n  NET-TOOL:\n    status: \"on\"\n")
    rules = engine.load_catalog(folder, overlay=overlay.overlay_path(str(home)), user_rules=overlay.user_dir(str(home)))
    info = overlay.describe(rules)
    assert "A6" in info["refused"][0] and by_id(rules, "NET-TOOL").status == "disabled"
    assert info["off"] == [{"rule_id": "NET-TOOL", "by": "its YAML (status: disabled, A6)", "since": None,
                            "severity": "medium", "kind": "signature"}]


def test_e1_apply_changes_only_status_and_declared_eq_values(home):
    write_overlay(home, 'rules:\n  HOST-RHYTHM:\n    status: "off"\n    since: "2026-11-09T10:00:00Z"\n'
                        '    thresholds: {k: 5, input_meta.rhythm.w: 60, r: 20}\n'
                        '  AGENT-DARK-LIVE:\n    thresholds: {streak: 4, live_window: 12}\n')
    base = engine.load_catalog(CATALOG_DIR)
    rules = overlay.load(str(home))
    assert [r.id for r in rules] == [r.id for r in base]
    for r, b in zip(rules, base):
        for attr in ("kind", "cls", "severity", "fp_budget", "fixtures", "title"):
            assert getattr(r, attr) == getattr(b, attr), (r.id, attr)
    rhythm = by_id(rules, "HOST-RHYTHM")
    assert rhythm.status == "disabled" and rhythm.off_by == overlay.overlay_path(str(home))
    assert rhythm.off_since == "2026-11-09T10:00:00Z" and "the overlay" in rhythm.source
    assert host.rhythm_params(rhythm) == (5, 60, 20) and host.rhythm_params(by_id(base, "HOST-RHYTHM")) == (3, 30, 10)
    dark = by_id(rules, "AGENT-DARK-LIVE")
    assert dark.status == "active" and host.rule_eq(dark, "input_meta.streak") == 4
    assert host.rule_eq(dark, host.LIVE_WINDOW_FIELD) == 12
    info = overlay.describe(rules)
    assert {(t["rule_id"], t["name"], t["value"], t["yaml"]) for t in info["thresholds"]} == {
        ("HOST-RHYTHM", "k", 5, 3), ("HOST-RHYTHM", "w", 60, 30), ("HOST-RHYTHM", "r", 20, 10),
        ("AGENT-DARK-LIVE", "streak", 4, 3), ("AGENT-DARK-LIVE", "live_window", 12, 9)}
    # the engine's existing switch: the note of a rule off names the overlay
    _, notes = engine.evaluate(rules, [])
    assert {"rule_id": "HOST-RHYTHM", "status": "disabled",
            "detail": "status: disabled in %s (A6)" % rhythm.source} in notes
    # the package catalog is unchanged on disk, and read as before without the overlay
    assert host.rhythm_params(by_id(engine.load_catalog(CATALOG_DIR), "HOST-RHYTHM")) == (3, 30, 10)


def test_e1_the_matcher_follows_the_changed_threshold(home):
    """A HostTree line computed with k=5 fires the overlaid rule; one with k=3 does not."""
    write_overlay(home, "rules:\n  HOST-RHYTHM:\n    thresholds: {k: 5}\n")
    rule = by_id(overlay.load(str(home)), "HOST-RHYTHM")
    positive = ROOT / rule.fixtures["positive"][0]
    lines = fixtures.load_fixture(positive)[0]
    assert engine.run_rule(by_id(engine.load_catalog(CATALOG_DIR), "HOST-RHYTHM"), lines)
    assert not engine.run_rule(rule, lines)   # the fixture's lines carry k=3
    for rec in lines:
        if isinstance(rec.get("input_meta", {}).get("rhythm"), dict):
            rec["input_meta"]["rhythm"]["k"] = 5
    assert engine.run_rule(rule, lines)


def test_e1_host_reads_the_changed_k_w_r_streak_and_window(home, tmp_path):
    write_overlay(home, 'rules:\n  HOST-RHYTHM:\n    thresholds: {k: 4, w: 45, r: 12}\n'
                        '  AGENT-DARK-LIVE:\n    thresholds: {streak: 5, live_window: 15}\n')
    from test_watch import FakeRunner, make_notifier
    notifier = make_notifier(FakeRunner())
    notifier.host = True
    w = host.HostWatch(lambda: {}, discover.load_catalog(discover.CATALOG), overlay.load(str(home)), notifier,
                       out=io.StringIO(), err=io.StringIO(), home=str(home), platform="test")
    assert (w.rhythm_k, w.rhythm_w, w.rhythm_r, w.dark_rounds, w.dark_window) == (4, 45, 12, 5, 15)
    assert w.state(w.clock())["host"]["rhythm"] == {"k": 4, "w": 45, "r": 12}
    assert w.state(w.clock())["rules_overlay"]["thresholds"]
    plain = host.HostWatch(lambda: {}, discover.load_catalog(discover.CATALOG), engine.load_catalog(CATALOG_DIR),
                           notifier, out=io.StringIO(), err=io.StringIO(), home=str(tmp_path / "other"),
                           platform="test")
    assert (plain.rhythm_k, plain.rhythm_w, plain.rhythm_r, plain.dark_rounds, plain.dark_window) == (3, 30, 10, 3, 9)


# --- A6: the person's rules under rules.d -------------------------------------------------------------

def test_a6_add_validates_with_the_loader_and_the_fixture_runner_and_copies(home, tmp_path):
    src = user_rule(tmp_path / "mine")
    said = overlay.add_rule(str(src), str(home))
    assert "USER-SHRED added" in said and "2 fixture file(s) copied" in said and overlay.NEXT_WATCH in said
    d = Path(overlay.user_dir(str(home)))
    assert (d / "USER-SHRED.yaml").read_text() == src.read_text()
    assert (d / "fx" / "USER-SHRED" / "positive.json").is_file()
    rules = overlay.load(str(home))
    rule = by_id(rules, "USER-SHRED")
    assert rule.origin == "user" and all(r.origin == "package" for r in rules if r.id != "USER-SHRED")
    info = overlay.describe(rules)
    assert info["user"] == [{"rule_id": "USER-SHRED", "source": str(d / "USER-SHRED.yaml")}]
    assert any("user rule USER-SHRED (origin: user)" in s for s in overlay.start_lines(info))
    row = next(r for r in overlay.listing(rules) if r["id"] == "USER-SHRED")
    assert row["origin"] == "user" and row["status"] == "on"
    # a user rule can be turned off like any other
    overlay.set_status("USER-SHRED", "off", str(home))
    assert by_id(overlay.load(str(home)), "USER-SHRED").status == "disabled"
    with pytest.raises(overlay.OverlayError, match="already in the catalog or rules.d"):
        overlay.add_rule(str(src), str(home))


def test_a6_a_rule_the_loader_or_the_runner_refuses_is_not_copied(home, tmp_path):
    missed = user_rule(tmp_path / "missed", positive_head="ls")      # the positive does not fire
    with pytest.raises(overlay.OverlayError, match="refused by the fixture runner: positive-missed"):
        overlay.add_rule(str(missed), str(home))
    broken = user_rule(tmp_path / "broken", text=USER_RULE.replace("kind: signature\n", ""))
    with pytest.raises(overlay.OverlayError, match="refused by the loader: .*kind"):
        overlay.add_rule(str(broken), str(home))
    over = user_rule(tmp_path / "over", text=USER_RULE.replace("fp_budget: 0.5", "fp_budget: 0.0").replace(
        "eq: shred}", "in: [shred, ls]}"))
    with pytest.raises(overlay.OverlayError, match="over-budget"):
        overlay.add_rule(str(over), str(home))
    clash = user_rule(tmp_path / "clash", text=USER_RULE.replace("USER-SHRED", "NET-TOOL", 1), name="NET-TOOL")
    with pytest.raises(overlay.OverlayError, match="already in the catalog"):
        overlay.add_rule(str(clash), str(home))
    assert not Path(overlay.user_dir(str(home))).exists()


def test_a6_a_bad_file_put_in_rules_d_by_hand_is_refused_at_load_and_said(home):
    d = Path(overlay.user_dir(str(home)))
    user_rule(d, positive_head="ls")
    (d / "STRAY.yml").write_text("x: 1\n", encoding="ascii")
    rules = overlay.load(str(home))
    info = overlay.describe(rules)
    assert "USER-SHRED" not in {r.id for r in rules}
    assert len(info["user_refused"]) == 2 and any("positive-missed" in r for r in info["user_refused"])
    assert any("must end in .yaml" in r for r in info["user_refused"])
    assert sum("user rule REFUSED" in s for s in overlay.start_lines(info)) == 2


# --- E2: raqib rules -------------------------------------------------------------------------------------

def run_cli(argv):
    out = io.StringIO()
    return cli.main(argv, out=out), out.getvalue()


def test_e2_raqib_rules_lists_every_rule_with_its_columns(home):
    code, text = run_cli(["rules"])
    assert code == 0
    head = text.splitlines()[0].split()
    assert head == ["ID", "KIND", "CLASS", "SEVERITY", "BUDGET", "STATUS", "ORIGIN", "THRESHOLDS"]
    for r in engine.load_catalog(CATALOG_DIR):
        assert any(l.split()[:2] == [r.id, r.kind] for l in text.splitlines()), r.id
    assert "k=3 [1..100], w=30 [1..3600], r=10 [1..1000]" in text
    assert "streak=3 [1..100], live_window=9 [1..1000]" in text
    assert "raqib rules: rules: no rule off" in text
    code, text = run_cli(["rules", "--json"])
    data = json.loads(text)
    assert code == 0 and {r["id"] for r in data["rules"]} >= {"HOST-RHYTHM", "NET-TOOL"}
    assert data["overlay"]["file"] == "absent"


def test_e2_set_threshold_reset_add_and_exit_2_on_refusal(home, tmp_path, capsys):
    code, text = run_cli(["rules", "--set", "SECRET-OUTPUT", "off"])
    assert code == 0 and "raqib rules: SECRET-OUTPUT off in" in text and "1 rule off: SECRET-OUTPUT" in text
    code, text = run_cli(["rules", "--threshold", "HOST-RHYTHM", "k", "7"])
    assert code == 0 and "k=7* [1..100]" in text
    code, _ = run_cli(["rules", "--threshold", "HOST-RHYTHM", "k", "700"])
    assert code == 2 and "refused: HOST-RHYTHM: HOST-RHYTHM k = 700 is outside its bounds" in capsys.readouterr().err
    for argv, word in ((["rules", "--set", "NOPE-X", "off"], "no rule 'NOPE-X'"),
                       (["rules", "--set", "NET-TOOL", "maybe"], "on or off"),
                       (["rules", "--threshold", "HOST-RHYTHM", "tool", "3"], "not a declared threshold"),
                       (["rules", "--threshold", "HOST-RHYTHM", "k", "x"], "whole number"),
                       (["rules", "--add", str(tmp_path / "none.yaml")], "cannot read"),
                       (["rules", "trace.jsonl", "--set", "NET-TOOL", "off"], "apply to `raqib rules` with no TRACE"),
                       (["rules", "--set", "NET-TOOL", "off", "--json", "-o", "x"], "apply to `raqib rules TRACE`")):
        code, _ = run_cli(argv)
        assert code == 2 and word in capsys.readouterr().err, argv
    code, text = run_cli(["rules", "--add", str(user_rule(tmp_path / "mine"))])
    assert code == 0 and "USER-SHRED added" in text and "user rule USER-SHRED (origin: user)" in text
    code, text = run_cli(["rules", "--reset", "SECRET-OUTPUT"])
    assert code == 0 and "SECRET-OUTPUT reset" in text and "rules: no rule off" in text
    code, text = run_cli(["rules", "--reset", "SECRET-OUTPUT"])
    assert code == 0 and "has no entry" in text
    assert overlay.read(overlay.overlay_path(str(home)))[0] == {"rules": {"HOST-RHYTHM": {
        "since": overlay.read(overlay.overlay_path(str(home)))[0]["rules"]["HOST-RHYTHM"]["since"],
        "thresholds": {"k": 7}}}}


def test_e2_the_ci_pair_raqib_rules_then_set_and_reset_in_a_child_process(home):
    """CI: `raqib rules` + a --set / --reset pair, as a person runs them (python -m raqib)."""
    env = dict(os.environ, HOME=str(home), USERPROFILE=str(home))
    env.pop("PYTHONPATH", None)

    def run(*argv):
        return subprocess.run([sys.executable, "-m", "raqib", "rules"] + list(argv), cwd=str(ROOT), env=env,
                              capture_output=True, text=True, timeout=120)
    listed = run()
    assert listed.returncode == 0 and "HOST-RHYTHM" in listed.stdout, listed.stderr
    off = run("--set", "NET-TOOL", "off")
    assert off.returncode == 0 and "1 rule off: NET-TOOL" in off.stdout, off.stderr
    back = run("--reset", "NET-TOOL")
    assert back.returncode == 0 and "rules: no rule off" in back.stdout, back.stderr
    refused = run("--set", "NET-TOOL", "sometimes")
    assert refused.returncode == 2 and "refused" in refused.stderr


def test_e2_the_trace_commands_judge_the_catalog_as_declared(home, tmp_path):
    """Q-2: `raqib rules TRACE`, report, ui, suspect, eval and check-rules read the package's catalog."""
    overlay.set_status("SECRET-OUTPUT", "off", str(home))
    trace = tmp_path / "t.jsonl"
    src = ROOT / "tests" / "fixtures" / "rules" / "SECRET-OUTPUT" / "positive-aws-key-in-cat.json"
    trace.write_text("".join(json.dumps(r) + "\n" for r in fixtures.load_fixture(src)[0]), encoding="ascii")
    code, text = run_cli(["rules", str(trace)])
    assert code == 1 and "SECRET-OUTPUT" in text


# --- E3: said, not silent ----------------------------------------------------------------------------------

def secret_lines():
    src = ROOT / "tests" / "fixtures" / "rules" / "SECRET-OUTPUT" / "positive-aws-key-in-cat.json"
    return fixtures.load_fixture(src)[0]


def test_e3_a_high_rule_off_is_listed_not_judged_with_what_it_would_have_found(home):
    """ADR-0008 CI: an overlay turning a high rule off still lists what that
    rule would have found as "not judged (off)" on the fixtures."""
    overlay.set_status("SECRET-OUTPUT", "off", str(home))
    rules = overlay.load(str(home))
    rule = by_id(rules, "SECRET-OUTPUT")
    assert rule.severity == "high" and rule.status == "disabled"
    for p in rule.fixtures["positive"]:
        lines = fixtures.load_fixture(ROOT / p)[0]
        found, notes = engine.evaluate(rules, lines)
        assert not any(f["rule_id"] == "SECRET-OUTPUT" for f in found)   # off: no finding
        counts = overlay.count_not_judged(rules, lines, {}, {})
        assert counts["SECRET-OUTPUT"]["fired"] >= 1 and counts["SECRET-OUTPUT"]["lines"] >= 1
        report = "\n".join(overlay.report_lines(overlay.describe(rules), counts))
        assert "not judged by SECRET-OUTPUT (off): %d lines; it would have fired %d time(s)" % (
            counts["SECRET-OUTPUT"]["lines"], counts["SECRET-OUTPUT"]["fired"]) in report
        assert "SECRET-OUTPUT [high] off by the overlay %s since " % overlay.overlay_path(str(home)) in report


def test_e3_a_project_watch_says_the_overlay_at_start_in_watch_json_and_the_final_report(home, tmp_path):
    overlay.set_status("SECRET-OUTPUT", "off", str(home))
    rules, gap, evaluator = cli._watch_setup()
    assert isinstance(rules, overlay.Catalog) and by_id(rules, "SECRET-OUTPUT").status == "disabled"
    from test_watch import Clock, START, make_notifier
    evaluate, _ = evaluator(str(tmp_path))
    path = tmp_path / "traces" / "raqib.log.jsonl"
    path.parent.mkdir(parents=True)
    path.write_text("")
    clock = Clock()
    w = watch.Watch(str(tmp_path), str(path), evaluate, rules, gap, make_notifier(), out=io.StringIO(),
                    err=io.StringIO(), clock=clock, started=START, wall=lambda: START.timestamp() + clock.t - 1000.0)
    with open(path, "a") as f:
        f.write("".join(json.dumps(r) + "\n" for r in secret_lines()))
    w.step()
    state = json.loads(Path(w.state_path).read_text(encoding="ascii"))
    ro = state["rules_overlay"]
    assert [o["rule_id"] for o in ro["off"]] == ["SECRET-OUTPUT"] and ro["not_judged"]["SECRET-OUTPUT"]["fired"] >= 1
    assert ("incomplete", "1 rule off: SECRET-OUTPUT") in ui.band_items(state)
    assert not any(e["rule_id"] == "SECRET-OUTPUT" for e in state["findings"])
    rep = w.finish()
    assert "RULES OFF (ADR-0008" in w.final_text and "not judged by SECRET-OUTPUT (off): " in w.final_text
    assert w.final_exit == rep["exit"]                      # the exit code is the report's, as without an overlay
    assert not any(n["status"] != "disabled" and n["rule_id"] == "SECRET-OUTPUT" for n in rep["notes"]
                   if "status" in n)


def test_e3_watch_start_prints_the_applied_overlay(home, tmp_path, monkeypatch):
    overlay.set_threshold("HOST-RHYTHM", "k", "4", str(home))
    overlay.set_status("NET-TOOL", "off", str(home))
    info = overlay.describe(overlay.load(str(home)))
    lines = overlay.start_lines(info)
    assert lines[0] == "rules overlay %s: 2 applied, 0 refused" % overlay.overlay_path(str(home))
    assert "rules overlay: applied: HOST-RHYTHM k = 4 (its YAML: 3)" in lines
    assert any(l.startswith("rules overlay: applied: NET-TOOL off (since ") for l in lines)
    assert "rules: 1 rule off: NET-TOOL (not judged; each is listed in the final report)" in lines
    src = (ROOT / "raqib" / "watch.py").read_text(encoding="utf-8")
    assert "overlay.start_lines(watcher.rules_overlay)" in src     # watch.start prints them
    assert "overlay.start_lines(watcher.rules_overlay)" in (ROOT / "raqib" / "host.py").read_text(encoding="utf-8")


def test_e3_every_rule_of_a_kind_off_is_said_in_words(home):
    for r in engine.load_catalog(CATALOG_DIR):
        if r.kind == "signature":
            overlay.set_status(r.id, "off", str(home))
    info = overlay.describe(overlay.load(str(home)))
    assert info["kinds_off"] == ["signature"]
    assert ("rules: every catalog rule of kind signature is off: nothing is judged as a signature by the catalog"
            in overlay.start_lines(info))


def test_e3_a_host_watch_with_a_rule_off_has_no_hole_for_it_and_counts_it(home, tmp_path):
    overlay.set_status("NEW-AGENT", "off", str(home))
    import test_host
    w, clock = test_host.make_host(tmp_path, ["linux", "linux"])
    w2 = host.HostWatch(lambda: test_host.inv("linux"), test_host.CATALOG, overlay.load(str(home)), w.notifier,
                        out=io.StringIO(), err=io.StringIO(), clock=clock, home=str(home), platform="test")
    assert not any(h["kind"] == "host-rule" for h in w2.holes)   # an overlay-off rule is not a hole (exit unchanged)
    test_host.run_rounds(w2, clock, 2)
    st = w2.state(clock())
    assert [o["rule_id"] for o in st["rules_overlay"]["off"]] == ["NEW-AGENT"]
    assert st["rules_overlay"]["not_judged"]["NEW-AGENT"]["lines"] >= 1
    assert ("incomplete", "1 rule off: NEW-AGENT") in ui.host_band(st)
    text, code = w2.finish()
    assert "not judged by NEW-AGENT (off): " in text and "RULES OFF (ADR-0008" in text
    # a rule disabled in its YAML stays a hole of the host watch, as before (A6)
    rules = engine.load_catalog(CATALOG_DIR)
    by_id(rules, "NEW-AGENT").status = "disabled"
    w3 = host.HostWatch(lambda: {}, test_host.CATALOG, rules, w.notifier, out=io.StringIO(), err=io.StringIO(),
                        home=str(tmp_path / "h3"), platform="test")
    assert any(h["kind"] == "host-rule" and "NEW-AGENT has status disabled" in h["detail"] for h in w3.holes)


def test_e3_the_band_item_and_rules_off_text():
    assert ui.rules_off_text({}) is None
    state = {"rules_overlay": {"off": [{"rule_id": "A-B"}, {"rule_id": "C-D"}]}}
    assert ui.rules_off_text(state) == "2 rules off: A-B, C-D"
    assert overlay.off_text(state["rules_overlay"]) == "2 rules off: A-B, C-D"


# --- E4: the panel (state -> text; A4) --------------------------------------------------------------------------

def test_e4_the_rules_panel_state_to_text_and_changes(home, tmp_path):
    p = app.RulesPanel(home=str(home))
    text = p.text()
    assert text.startswith(app.RULES_INTRO) and "HOST-RHYTHM" in text and "rules: no rule off" in text
    assert p.header() == "no rule off"
    p.set("SECRET-OUTPUT", False)
    assert p.level == "clean" and "SECRET-OUTPUT off" in p.message and overlay.NEXT_WATCH in p.message
    assert p.header() == "1 rule off: SECRET-OUTPUT" and "1 rule off: SECRET-OUTPUT" in p.text()
    p.threshold("HOST-RHYTHM", "w", "120", running=True)
    assert "a watch is running: it keeps the rules it started with" in p.message and "w=120*" in p.text()
    p.threshold("HOST-RHYTHM", "w", "9999")
    assert p.level == "alarm" and p.message.startswith("REFUSED: ") and "outside its bounds 1..3600" in p.message
    p.add(str(user_rule(tmp_path / "mine")))
    assert p.level == "clean" and "USER-SHRED added" in p.message and "user" in p.text()
    p.add(None)
    assert p.level == "incomplete" and p.message == "no file chosen: nothing added"
    p.reset("SECRET-OUTPUT")
    assert p.header() == "no rule off"
    write_overlay(home, "rules: [x]\n")
    p.reload()
    assert "rules overlay: HOLE: " in p.text()


def test_e4_the_next_watch_takes_the_overlay_as_it_is_then(home):
    calls = []

    def setup():
        calls.append(1)
        return overlay.load(str(home)), 60, (lambda project: (None, None))
    o = app.Options(None, engine.load_catalog(CATALOG_DIR), 60, setup=setup)
    overlay.set_status("NET-TOOL", "off", str(home))
    assert by_id(o.rules_now(), "NET-TOOL").status == "disabled" and calls == [1]

    def broken():
        raise engine.RuleError("bad catalog")
    with pytest.raises(watch.WatchError, match="the rules could not be loaded: bad catalog"):
        app.Options(None, [], 60, setup=broken).rules_now()
    assert app.Options(None, ["kept"], 60).rules_now() == ["kept"]


PANEL_CALLS = {"set_status", "set_threshold", "reset", "add_rule", "load", "listing", "describe", "off_text",
               "table_text", "start_lines", "OverlayError"}


def test_e4_a4_the_panel_writes_the_overlay_only_and_copies_into_rules_d_only():
    """A4 (ADR-0008 decision 5): the Rules panel's code calls raqib/overlay.py
    and nothing that writes, starts or signals; overlay.py writes in one
    function (_atomic_write), which only write() (overlay_path) and
    add_rule() (under user_dir) call."""
    tree = ast.parse((ROOT / "raqib" / "app.py").read_text(encoding="utf-8"))
    panel = [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.name == "RulesPanel"]
    window = next(n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.name == "Window")
    panel += [f for f in window.body if isinstance(f, ast.FunctionDef) and f.name.startswith(("rules_", "show_rules",
                                                                                              "_rules"))]
    assert len(panel) == 7
    for node in panel:
        for sub in ast.walk(node):
            if isinstance(sub, ast.Attribute) and isinstance(sub.value, ast.Name) and sub.value.id == "overlay":
                assert sub.attr in PANEL_CALLS | {"NEXT_WATCH"}, sub.attr
            if isinstance(sub, ast.Call):
                f = sub.func
                name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", None)
                assert name not in ("open", "write", "replace", "remove", "unlink", "rename", "makedirs", "mkstemp",
                                    "copy", "copyfile", "rmtree", "system", "Popen", "run", "kill"), name
    tree = ast.parse((ROOT / "raqib" / "overlay.py").read_text(encoding="utf-8"))
    funcs = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
    writers = set()
    for name, fn in funcs.items():
        for sub in ast.walk(fn):
            if not isinstance(sub, ast.Call):
                continue
            f = sub.func
            called = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", None)
            if called in ("replace", "rename", "remove", "unlink", "makedirs", "mkstemp", "fdopen", "rmtree"):
                writers.add(name)
            if called == "open":
                modes = [a.value for a in sub.args[1:] if isinstance(a, ast.Constant)]
                assert all(m in ("rb", "r") for m in modes), (name, modes)   # every open reads
            if called == "_atomic_write":
                assert name in ("write", "add_rule"), name
    assert writers == {"_atomic_write"}
    src = ast.get_source_segment((ROOT / "raqib" / "overlay.py").read_text(encoding="utf-8"), funcs["write"])
    assert "path = overlay_path(home)" in src
    src = ast.get_source_segment((ROOT / "raqib" / "overlay.py").read_text(encoding="utf-8"), funcs["add_rule"])
    assert "target_dir = user_dir(home)" in src and "os.path.join(target_dir," in src
    assert "subprocess" not in (ROOT / "raqib" / "overlay.py").read_text(encoding="utf-8")


def test_e4_a_running_add_or_change_never_touches_a_project(home, tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    before = sorted(os.listdir(project))
    p = app.RulesPanel(home=str(home))
    p.set("NET-TOOL", False, running=True)
    p.add(str(user_rule(tmp_path / "mine")), running=True)
    assert sorted(os.listdir(project)) == before
    assert sorted(os.listdir(home / ".raqib")) == ["rules.d", "rules.yaml"]


# --- E5: files, README, questions ------------------------------------------------------------------------------

def test_e5_new_and_changed_code_is_ascii():
    for name in ("raqib/overlay.py", "raqib/app.py", "raqib/cli.py", "raqib/watch.py", "raqib/host.py", "raqib/ui.py",
                 "raqib/rules/engine.py", "tests/test_overlay.py"):
        (ROOT / name).read_bytes().decode("ascii")


def test_e5_readme_says_the_rules_in_four_lines():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    section = text.split("## Choose the rules\n", 1)[1].split("\n## ", 1)[0]
    lines = [l for l in section.split("\n") if l.strip()]
    assert len(lines) == 4 and "raqib rules" in lines[0] and "~/.raqib/rules.yaml" in " ".join(lines)
    assert "not judged by" in " ".join(lines) and "rules.d" in " ".join(lines)


def test_e5_the_questions_file_has_the_gate_numbers_and_the_tests():
    text = QUESTIONS.read_text(encoding="utf-8")
    for q in ("Q-1", "Q-2", "Q-3", "Q-4", "Q-5", "Q-6", "Q-7", "Q-8"):
        assert q in text
    assert "2758 passed, 19 skipped" in text and "test_overlay.py" in text


# --- the Tk Rules screen: only with tkinter and a display ----------------------------------------------------------

def test_tk_the_rules_screen_from_the_header(home, tmp_path):
    try:
        import tkinter
    except ImportError:
        pytest.skip("no tkinter in this Python")
    if not WINDOWS and sys.platform != "darwin" and not os.environ.get("DISPLAY"):
        pytest.skip("no display (DISPLAY is not set)")
    try:
        root = tkinter.Tk()
    except tkinter.TclError as exc:
        pytest.skip("no window: %s" % exc)
    import test_host
    window = None
    try:
        c = app.Controller(app.Options(None, None, 60, environ={}), tray=None)
        doctor = app.DoctorJob(str(tmp_path), checks=lambda x: (x, [("python", (True, "3"))], []))
        window = app.Window(tkinter, root, c, str(tmp_path), doctor_job=lambda x: doctor, probe=lambda: app.HostProbe(
            lambda: test_host.inv("linux"), test_host.CATALOG, 20.0, home=str(home)),
                            home=str(home))
        root.withdraw()
        window.rules_tab.invoke()
        window.tick()
        assert window.screen == "rules" and window.band.cget("text") == "RULES"
        assert "HOST-RHYTHM" in window.rules_text.get("1.0", "end")
        window.rule_id.set("NET-TOOL")
        window.rules_set(False)
        window.tick()
        assert "1 rule off: NET-TOOL" in window.head_note.cget("text")
        assert "1 rule off: NET-TOOL" in window.rules_text.get("1.0", "end")
        window.rule_field.set("k")
        window.rule_value.set("0")
        window.rule_id.set("HOST-RHYTHM")
        window.rules_threshold()
        assert window.band.cget("text") == "RULES: REFUSED"
        window.rule_id.set("NET-TOOL")
        window.rules_reset()
        window.tick()
        assert "no rule off" in window.head_note.cget("text")
        window.show_host()
        assert window.screen == "host"
    finally:
        if window is not None:
            window.destroy()
        else:
            root.destroy()

