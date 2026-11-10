"""M7.5 after the first field run (HANDOFF.md E1-E4; ADR-0007 Amendment M).

No live host, no Sysmon channel, no real notification: every HostWatch gets
a reader of discover-fixture inventories (or fake ones in their shape), and
every notifier a fake runner (tests/test_watch.py's).
"""
import io
import json
import os
import re
import shutil
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from raqib import app, cli, discover, host, notify, ui  # noqa: E402
from raqib.rules import engine, fixtures  # noqa: E402
from hostthreads import raqib_threads_end  # noqa: E402,F401  (V-5: every HostWatch ended, no thread leaked)

sys.path.insert(0, str(ROOT / "tests"))
from test_watch import FakeRunner, make_notifier  # noqa: E402

sys.path.insert(0, str(ROOT / "tests" / "fixtures" / "host"))
import make as host_fixtures  # noqa: E402

CATALOG = discover.load_catalog(discover.CATALOG)
CATALOG_DIR = ROOT / "raqib" / "rules" / "catalog"
RULES = engine.load_catalog(CATALOG_DIR)
RULE_FIXTURES = ROOT / "tests" / "fixtures" / "rules"
QUESTIONS = ROOT / "docs" / "review" / "2026-11-09-M7.5-questions.md"
NOTES = ROOT / "tests" / "fixtures" / "host" / "notes"   # N-2: host.py's note fixtures, not a rule's
KIMI_FP = "C:\\Users\\user\\.kimi"
# The field run's order (ADR-0007 Amendment M): AGENT-DARK-LIVE at round 3, kimi new at round 10, dark again to 13
FIELD = ["kimi-gone"] * 9 + ["kimi/two-samples"] + ["kimi-gone"] * 3


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    path = tmp_path / "home"
    path.mkdir()
    monkeypatch.setenv("HOME", str(path))
    monkeypatch.setenv("USERPROFILE", str(path))
    return path


def inv(name):
    return host_fixtures.inventory(name, CATALOG)


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


def make_host(tmp_path, names, runner=None, rules=None, every=10, **kw):
    feed = iter([inv(n) if isinstance(n, str) else n for n in names])
    clock = Clock()
    notifier = make_notifier(runner or FakeRunner())
    notifier.host = True
    w = host.HostWatch(lambda: next(feed), CATALOG, rules or RULES, notifier, every=every, out=io.StringIO(),
                       err=io.StringIO(), clock=clock, wall=lambda: 1793700000.0 + clock.t - 1000.0,
                       home=str(tmp_path / "home"), platform="test", sysmon=lambda: (False, "test: no Sysmon"), **kw)
    return w, clock


def run_rounds(w, clock, n):
    for _ in range(n):
        w.tick(wait=30)
        clock.t += w.every


def main_rules(tmp_path):
    """The catalog as it was on main before M7.5 (AGENT-DARK-LIVE without its was_live clause): the
    field run's rules, to replay its order exactly."""
    d = tmp_path / "catalog-main"
    shutil.copytree(CATALOG_DIR, d)
    p = d / "AGENT-DARK-LIVE.yaml"
    text = p.read_text(encoding="ascii")
    p.write_text(text.replace("    - {field: input_meta.was_live, eq: false}\n", ""), encoding="ascii")
    rules = engine.load_catalog(d)
    assert "was_live" not in json.dumps(next(r for r in rules if r.id == "AGENT-DARK-LIVE").doc["match"])
    return rules


def footprint_lines(w, path=KIMI_FP):
    out = []
    for r in w.round_lines:
        out += [l for l in r["lines"] if l["tool"] == host.FOOTPRINT_TOOL and l["input_meta"]["path"] == path]
    return out


# --- E1: dark after a live tree is a note -----------------------------------------------------------------

def test_e1_a_footprint_dark_after_its_live_tree_is_a_note_not_a_knock(tmp_path):
    runner = FakeRunner()
    w, clock = make_host(tmp_path, FIELD, runner=runner)
    run_rounds(w, clock, len(FIELD))
    assert [(f["rule_id"], f["round"]) for f in w.findings] == [("AGENT-DARK-LIVE", 3), ("NEW-AGENT", 10)]
    assert len(runner.calls) == 2
    (note,) = w.dark_notes
    assert note["round"] == 13 and note["path"] == KIMI_FP and note["live_round"] == 10 and note["streak"] == 3
    assert host.DARK_NOTE in note["text"] and "not a knock, not an alarm" in note["text"]
    # A5: the note cites its HostFootprint line (run, seq) and the inventory's record lines
    line = footprint_lines(w)[-1]
    assert note["cited_seq"] == [line["seq"]] and note["run"] == w.run and note["cites"]
    assert line["input_meta"]["was_live"] is True and line["input_meta"]["streak"] == 3
    # A3: said and listed, never dropped
    assert note["text"] in w.notes and ("NOTE " + note["text"]) in w.out.getvalue()
    assert w.round_lines[-1]["dark_notes"] == [KIMI_FP]


def test_e1_a_footprint_never_live_knocks_as_today(tmp_path):
    runner = FakeRunner()
    w, clock = make_host(tmp_path, ["kimi-gone"] * 3, runner=runner)
    run_rounds(w, clock, 3)
    assert [f["rule_id"] for f in w.findings] == ["AGENT-DARK-LIVE"] and w.dark_notes == []
    assert footprint_lines(w)[-1]["input_meta"]["was_live"] is False
    assert runner.titles() == ["Raqib: AGENT-DARK-LIVE"]


def test_e1_linked_again_and_dark_again_stays_a_note_once_per_streak(tmp_path):
    names = ["kimi-gone", "kimi/two-samples", "kimi-gone", "kimi-gone", "kimi-gone", "kimi-gone",
             "kimi/two-samples", "kimi-gone", "kimi-gone", "kimi-gone"]
    w, clock = make_host(tmp_path, names)
    run_rounds(w, clock, len(names))
    assert [f["rule_id"] for f in w.findings] == ["NEW-AGENT"]   # kimi new once; never AGENT-DARK-LIVE
    assert [d["round"] for d in w.dark_notes] == [5, 10]          # streak 3 each time, round 6 (streak 4) is not again
    assert [d["live_round"] for d in w.dark_notes] == [2, 7]


def test_e1_a_link_to_an_act_root_only_does_not_make_the_footprint_live(tmp_path):
    w, clock = make_host(tmp_path, ["kimi/one-sample"] + ["kimi-gone"] * 3)
    run_rounds(w, clock, 4)
    first = footprint_lines(w)[0]["input_meta"]
    assert first["state"] == "linked" and first["was_live"] is False   # kimi is an act-root in one-sample
    assert [f["rule_id"] for f in w.findings] == ["AGENT-DARK-LIVE"] and w.dark_notes == []


def test_e1_a_note_is_never_an_alarm(tmp_path):
    w, clock = make_host(tmp_path, ["kimi-gone", "kimi/two-samples"] + ["kimi-gone"] * 3)
    run_rounds(w, clock, 5)
    text, code = w.finish()
    assert [f["rule_id"] for f in w.findings] == ["NEW-AGENT"] and len(w.dark_notes) == 1
    result, reasons = w.result()
    assert result == "alarm" and reasons[0] == "1 finding(s): NEW-AGENT"   # the finding's alarm, not the note's
    assert "DARK AFTER A LIVE TREE (notes, not alarms, not knocked): 1" in text


# --- REDO N-1: the live window; history never makes a footprint live ------------------------------------------

def test_redo_n1_the_reviewers_case_a_history_candidate_then_dark_alarms_as_on_main(tmp_path):
    """A candidate there at the start (history), then an agent that runs only between rounds: ALARM."""
    runner = FakeRunner()
    w, clock = make_host(tmp_path, ["kimi/two-samples"] + ["kimi-gone"] * 3, runner=runner)
    run_rounds(w, clock, 4)
    text, code = w.finish()
    assert [(f["rule_id"], f["round"]) for f in w.findings] == [("AGENT-DARK-LIVE", 4)] and w.dark_notes == []
    assert all(l["input_meta"]["was_live"] is False for l in footprint_lines(w))
    assert code == 1 and runner.titles() == ["Raqib: AGENT-DARK-LIVE"]


def test_redo_n1_kimis_case_is_a_note_within_the_window_and_a_knock_after_it(tmp_path):
    names = FIELD + ["kimi-gone"] * 8   # rounds 14..21
    runner = FakeRunner()
    w, clock = make_host(tmp_path, names, runner=runner)
    run_rounds(w, clock, len(names))
    assert w.dark_window == host.DARK_WINDOW == 9
    assert [(f["rule_id"], f["round"]) for f in w.findings] == [
        ("AGENT-DARK-LIVE", 3), ("NEW-AGENT", 10), ("AGENT-DARK-LIVE", 21)]
    assert [d["round"] for d in w.dark_notes] == [13]
    live = {l["input_meta"]["round"]: (l["input_meta"]["was_live"], l["input_meta"]["streak"])
            for l in footprint_lines(w)}
    assert live[18] == (True, 8) and live[19] == (False, 1) and live[21] == (False, 3)   # live round 10 + 9
    assert any("left the live window" in n and "round 19" in n for n in w.notes)
    assert runner.titles()[-1] == "Raqib: AGENT-DARK-LIVE"


def test_redo_n1_the_window_is_the_yamls_eq_and_on_every_line(tmp_path):
    rule = next(r for r in RULES if r.id == "AGENT-DARK-LIVE")
    assert host.rule_eq(rule, host.LIVE_WINDOW_FIELD) == 9 == 3 * host.DARK_ROUNDS
    assert {"field": "input_meta.live_window", "eq": 9} in rule.doc["match"]["all"]
    assert any("live window" in h and "A history candidate never makes the footprint live" in h for h in rule.holes)
    assert not any("for the rest of the watch" in h for h in rule.holes)
    w, clock = make_host(tmp_path, ["kimi-gone"])
    run_rounds(w, clock, 1)
    assert footprint_lines(w)[0]["input_meta"]["live_window"] == 9
    rules = main_rules(tmp_path)   # a catalog whose rule declares no window: a hole, and the default
    for r in rules:
        if r.id == "AGENT-DARK-LIVE":
            r.doc["match"]["all"] = [x for x in r.doc["match"]["all"] if x.get("field") != "input_meta.live_window"]
    w, clock = make_host(tmp_path / "b", ["kimi-gone"], rules=rules)
    assert w.dark_window == 9 and any("live window" in h["detail"] for h in w.holes)


def test_redo_n1_an_unjudged_round_at_the_windows_end_does_not_keep_a_stale_streak(tmp_path):
    unjudged = inv("kimi-gone")
    unjudged["agent_dark"] = []   # the footprint listed, no dark verdict: neither counts nor clears
    names = FIELD + ["kimi-gone"] * 5 + [unjudged] + ["kimi-gone"] * 3   # rounds 14-18 dark, 19 unjudged, 20-22
    w, clock = make_host(tmp_path, names)
    run_rounds(w, clock, len(names))
    assert [(f["rule_id"], f["round"]) for f in w.findings][-1] == ("AGENT-DARK-LIVE", 22)


def test_e1_the_yaml_excludes_was_live_and_lists_the_three_fixtures():
    rule = next(r for r in RULES if r.id == "AGENT-DARK-LIVE")
    assert {"field": "input_meta.was_live", "eq": False} in rule.doc["match"]["all"]
    assert "tests/fixtures/rules/AGENT-DARK-LIVE/positive-never-live.json" in rule.fixtures["positive"]
    for name in ("negative-live-then-gone.json", "negative-linked-again.json"):   # N-2: not measured negatives
        assert not any(name in p for p in rule.fixtures["negative"])
        assert not (RULE_FIXTURES / "AGENT-DARK-LIVE" / name).exists()
        assert (NOTES / name).exists()
    assert "0 of 2 fire" in (CATALOG_DIR / "AGENT-DARK-LIVE.yaml").read_text(encoding="ascii")
    assert "dark after a live tree" in rule.doc["description"] and "was_live" in rule.doc["description"]
    assert any("act-root" in h for h in rule.holes) and rule.fp_budget == 0.0
    for name in ("positive-never-live", "negative-live-then-gone", "negative-linked-again"):
        where = RULE_FIXTURES / "AGENT-DARK-LIVE" if name.startswith("positive") else NOTES
        doc = json.loads((where / (name + ".json")).read_text(encoding="ascii"))
        (fp,) = [l for l in doc["lines"] if l["tool"] == host.FOOTPRINT_TOOL]
        assert fp["input_meta"]["streak"] == 3 and fp["input_meta"]["was_live"] is (not name.startswith("positive"))
        found, _ = engine.evaluate([rule], doc["lines"])
        assert bool(found) is name.startswith("positive"), name


def test_e1_e2_check_rules_counts_are_in_the_questions_file():
    reports = {r["rule_id"]: r for r in fixtures.check_catalog(RULES, ROOT, cli.benign_default(ROOT))}
    text = QUESTIONS.read_text(encoding="utf-8") + (ROOT / "docs" / "review" / "2026-11-09-M7.6c-questions.md").read_text(encoding="utf-8")
    # N-2: 2, not 4; M7.6c REDO E-2: each gains its edge negatives (live window: 1; W and R: 2)
    for rule_id, (m, u) in (("AGENT-DARK-LIVE", (3, 10)), ("HOST-RHYTHM", (7, 8))):
        r = reports[rule_id]
        assert (r["measured"], r["unmeasured"]) == (m, u) and r["verdict"] == "ok" and r["fp_rate"] == 0.0
        assert re.search(r"%s +ok .* %d measured, %d unmeasured" % (re.escape(rule_id), m, u), text), rule_id


# --- E2: rhythm takes beats from every source --------------------------------------------------------------

def test_e2_an_os_source_tree_with_three_cycles_fires_and_two_do_not(tmp_path):
    rules = RULES
    for name, fires in (("HOST-RHYTHM/positive-os-three-cycles.json", True),
                        ("HOST-RHYTHM/negative-os-two-cycles.json", False)):
        w = host_fixtures.rounds_of(host_fixtures.OS_SCENARIOS[name], CATALOG, rules,
                                    str(tmp_path / name.replace("/", "-")), os_rounds=host_fixtures.OS_ROUNDS[name])
        found = [f for f in w.findings if f["rule_id"] == host.RHYTHM]
        assert bool(found) is fires, name
        (tree,) = [l for l in w.round_lines[-1]["lines"] if l["tool"] == host.TREE_TOOL]
        rh = tree["input_meta"]["rhythm"]
        assert rh["destination"].startswith("os:") and rh["cycles"] == (3 if fires else 2)
        assert tree["input_meta"]["source"] == "os"
        if fires:   # A5: each beat cites the os source file's lines (act and talk), with round and seq
            (f,) = found
            for b in f["beats"]:
                assert [a["basis"] for a in b["acts"]] == ["os"]
                assert all(c["src"].endswith(".jsonl") and isinstance(c["line"], int) for c in b["talk_cites"])
                assert all(c["src"].endswith(".jsonl") for a in b["acts"] for c in a["cites"])


def test_e2_a_tree_whose_talks_are_os_and_acts_are_host_fires(tmp_path):
    name = "HOST-RHYTHM/positive-os-talks-host-acts.json"
    w = host_fixtures.rounds_of(host_fixtures.OS_SCENARIOS[name], CATALOG, RULES, str(tmp_path / "h"),
                                os_rounds=host_fixtures.OS_ROUNDS[name])
    (f,) = [f for f in w.findings if f["rule_id"] == host.RHYTHM]
    assert f["destination"].startswith("os:")
    assert {a["basis"] for b in f["beats"] for a in b["acts"]} == {"started"}   # host children, their start times
    doc = json.loads((RULE_FIXTURES / name).read_text(encoding="ascii"))
    assert doc["expect_seq"] and engine.evaluate([r for r in RULES if r.id == host.RHYTHM], doc["lines"])[0]


def test_e2_the_os_fixtures_are_what_make_py_makes():
    built = host_fixtures.build()
    for name in host_fixtures.OS_SCENARIOS:
        assert (RULE_FIXTURES / name).read_text(encoding="ascii") == built[name], name


def _watch_with_feed(tmp_path, kind, records, history=False):
    w, clock = make_host(tmp_path, ["linux"])
    run_rounds(w, clock, 1)
    key = next(iter(w.trees))
    path = tmp_path / ("%s.jsonl" % kind)
    path.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="ascii")
    feed = host.Feed(str(path), [], path.stat().st_size if history else 0)
    feed.poll()
    w.sources[key] = host.TreeSource(kind, kind, path=str(path), feeds=[feed])
    return w, key


def test_e2_act_beats_reads_os_process_lines_and_hooks_bash_calls_with_their_own_times(tmp_path):
    os_recs = [{"ts": "2026-11-03T10:00:05.000Z", "seq": 2, "session_id": "os-1", "phase": "pre", "tool": "process",
                "source": "os", "input_meta": {"command_head": "pwsh", "command_programs": ["pwsh"], "depth": 1}},
               {"ts": "2026-11-03T10:00:05.000Z", "seq": 2, "session_id": "os-1", "phase": "post", "tool": "process",
                "source": "os", "input_meta": {"depth": 1}},
               {"ts": "2026-11-03T10:00:01.000Z", "seq": 1, "session_id": "os-1", "phase": "pre", "tool": "process",
                "source": "os", "input_meta": {"command_head": "kimi", "depth": 0}},
               {"ts": "2026-11-03T10:00:03.000Z", "seq": 3, "session_id": "os-1", "phase": "pre", "tool": "net",
                "source": "os", "input_sha256": "ab" * 32, "input_meta": {"dest_port": 443}}]
    w, key = _watch_with_feed(tmp_path, "os", os_recs)
    fresh = w._source_beats(key)
    acts = [b for k, b in fresh if k == "act"]
    talks = [b for k, b in fresh if k == "talk"]
    assert [(a["image"], a["basis"], a["started"]) for a in acts] == [("pwsh", "os", "2026-11-03T10:00:05.000Z")]
    assert [(t["dest"], t["at"].second) for t in talks] == [("os:" + "ab" * 6, 3)]
    assert w._source_beats(key) == []   # read once
    hooks = [{"ts": "2026-11-03T10:00:07.000Z", "seq": 1, "session_id": "s", "phase": "pre", "tool": "Bash"},
             {"ts": "2026-11-03T10:00:08.000Z", "seq": 1, "session_id": "s", "phase": "post", "tool": "Bash"},
             {"ts": "2026-11-03T10:00:09.000Z", "seq": 2, "session_id": "s", "phase": "pre", "tool": "Read"}]
    w2, key2 = _watch_with_feed(tmp_path / "h", "hooks", hooks)
    t = w2.trees[key2]
    acts = w2.act_beats(0.0, 2, key2, dict(t, children=[]), None, {})
    assert [(a["image"], a["basis"]) for a in acts] == [("Bash", "hooks")]


def test_e2_history_lines_of_a_source_are_not_beats(tmp_path):
    recs = [{"ts": "2026-11-03T10:00:05.000Z", "seq": 2, "session_id": "os-1", "phase": "pre", "tool": "process",
             "source": "os", "input_meta": {"command_head": "pwsh", "depth": 1}}]
    w, key = _watch_with_feed(tmp_path, "os", recs, history=True)
    assert w._source_beats(key) == []


def test_e2_a_source_beat_goes_to_the_round_whose_interval_holds_its_time():
    import datetime
    t0 = datetime.datetime(2026, 11, 3, 10, 0, 0, tzinfo=datetime.timezone.utc)
    sec = datetime.timedelta(seconds=1)
    ring = [{"round": k, "from": t0 + (k - 2) * 10 * sec, "at": t0 + (k - 1) * 10 * sec} for k in (1, 2, 3)]
    assert host._bin(ring, None)["round"] == 3
    assert host._bin(ring, t0 + 5 * sec)["round"] == 2
    assert host._bin(ring, t0 + 10 * sec)["round"] == 2     # (from, at]
    assert host._bin(ring, t0 + 11 * sec)["round"] == 3
    assert host._bin(ring, t0 - 60 * sec)["round"] == 1     # older than the ring: its oldest round


def test_e2_rhythm_of_pairs_an_act_with_a_source_talks_own_time():
    import datetime
    t0 = datetime.datetime(2026, 11, 3, 10, 0, 0, tzinfo=datetime.timezone.utc)
    sec = datetime.timedelta(seconds=1)
    act = {"pid": None, "image": "bash", "at": t0 + 9 * sec, "basis": "os", "cites": []}
    ring = [{"round": 1, "at": t0 + 10 * sec, "talks": {"os:x": []}, "talk_at": {"os:x": [t0 + 2 * sec]},
             "acts": [act], "seq": 1}]
    assert host.rhythm_of(ring, 1, 30, 10, 1)["cycles"] == 1   # the round's own time (10 s) is after the act
    ring[0]["talk_at"] = {}
    assert host.rhythm_of(ring, 1, 30, 10, 1)["cycles"] == 0


def test_e2_the_yaml_names_the_sources():
    text = (CATALOG_DIR / "HOST-RHYTHM.yaml").read_text(encoding="ascii")
    rule = next(r for r in RULES if r.id == host.RHYTHM)
    for word in ("Sysmon event 1", "Sysmon event 3", "Bash calls", "act_beats", "talk_beats"):
        assert word in text, word
    assert "Sysmon event 1" in rule.doc["description"] and "Sysmon event 3" in rule.doc["description"]
    assert any("hash of (hostname, ip, port, protocol)" in h for h in rule.holes)
    assert set(host.SOURCE_BASES) == {"os", "hooks"}


# --- E3: the missing knock ------------------------------------------------------------------------------

def test_e3_the_field_runs_order_gives_three_deliveries_in_three_toasts(tmp_path):
    """The field run's rules (main, before E1) and order: three knocks, each under its own id, three toasts."""
    runner = FakeRunner()
    w, clock = make_host(tmp_path, FIELD, runner=runner, rules=main_rules(tmp_path))
    run_rounds(w, clock, len(FIELD))
    assert [(f["rule_id"], f["round"], f["notice"]) for f in w.findings] == [
        ("AGENT-DARK-LIVE", 3, "sent"), ("NEW-AGENT", 10, "sent"), ("AGENT-DARK-LIVE", 13, "sent")]
    assert [c["text"] for c in runner.calls] == [
        "Raqib: AGENT-DARK-LIVE\nhost, kimi footprint, 3 rounds (round 3)\n",
        "Raqib: NEW-AGENT kimi\nhost, kimi pid 10728 (named)\n",
        "Raqib: AGENT-DARK-LIVE\nhost, kimi footprint, 3 rounds (round 13)\n"]
    assert w.notifier.counts["sent"] == 3 and w.notifier.counts["folded"] == 0
    assert [k["limit_id"] for k in w.knock_rows()] == [
        "AGENT-DARK-LIVE " + KIMI_FP, "NEW-AGENT pid 10728", "AGENT-DARK-LIVE " + KIMI_FP]
    # FIRST-FINDING never took NEW-AGENT's knock: a host-line finding does not pass through it
    assert all(t.get("first_knock") is None for t in w.trees.values())


@pytest.mark.parametrize("at", [25.0, 90.0])   # the same minute as round 3's knock, and the next one
def test_e3_the_notifier_keeps_new_agent_on_its_own_id_in_the_same_or_the_next_minute(at):
    runner = FakeRunner()
    n = make_notifier(runner)
    n.host = True
    got = [n.notify("AGENT-DARK-LIVE", "kimi footprint, 3 rounds (round 3)", 20.0,
                    limit_id="AGENT-DARK-LIVE " + KIMI_FP),
           n.notify("NEW-AGENT", "kimi pid 9176 (named)", at, limit_id="NEW-AGENT pid 9176", subject="kimi"),
           n.notify("AGENT-DARK-LIVE", "kimi footprint, 3 rounds (round 13)", 120.0,
                    limit_id="AGENT-DARK-LIVE " + KIMI_FP)]
    assert got == ["sent", "sent", "sent"] and len(runner.calls) == 3
    assert len(set(runner.titles())) == 2 and runner.titles()[1] == "Raqib: NEW-AGENT kimi"


def test_e3_with_e1_the_field_run_knocks_twice_and_notes_the_third(tmp_path):
    runner = FakeRunner()
    w, clock = make_host(tmp_path, FIELD, runner=runner)
    run_rounds(w, clock, len(FIELD))
    text, code = w.finish()
    assert runner.titles() == ["Raqib: AGENT-DARK-LIVE", "Raqib: NEW-AGENT kimi"] and code == 1
    assert "KNOCKS: 2 (each: round, event, title / body, rate-limit id: status)" in text
    assert ('round 10 at 2026-11-03T10:01:30.000Z: NEW-AGENT, "Raqib: NEW-AGENT kimi" / "host, kimi pid 10728'
            ' (named)", id NEW-AGENT pid 10728: sent') in text
    assert "NEW-AGENT sent" in text   # on the tree, as before


def test_e3_a_folded_source_knock_never_writes_the_trees_new_agent_status(tmp_path):
    w, clock = make_host(tmp_path, ["benign/windows-desktop", "windows"])
    run_rounds(w, clock, 2)
    (f,) = [f for f in w.findings if f["rule_id"] == "NEW-AGENT" and f["pid"] == 2100]
    tree = w.trees[tuple(f["tree_key"])]
    assert tree["knocked"] == "sent"
    source_entry = {"rule_id": "NET-TOOL", "tree_key": list(f["tree_key"]), "fkey": ["x"], "notice": "folded"}
    w._folds([(source_entry, "notice")], "sent", 1)
    assert source_entry["notice"] == "folded: sent as 1 more" and tree["knocked"] == "sent"
    w._folds([(f, "notice")], "sent", 2)   # the NEW-AGENT entry's own fold does write it
    assert tree["knocked"] == "folded: sent as 2 more"
    rhythm = {"rule_id": host.RHYTHM, "tree_key": list(f["tree_key"]), "notice": "folded"}
    w._folds([(rhythm, "notice")], "sent", 1)
    assert tree["rhythm"] == "folded: sent as 1 more" and tree["knocked"] == "folded: sent as 2 more"


def test_e3_the_ledger_says_what_became_of_a_folded_knock(tmp_path):
    w, clock = make_host(tmp_path, ["linux"], rounds_max=1)
    run_rounds(w, clock, 1)
    holes = [w._hole(clock.t, "test", "x", knock="round 1, test %d" % i) for i in range(2)]
    assert [h["notice"] for h in holes] == ["sent", "folded"]
    clock.t += 61
    w.tick()
    rows = w.knock_rows()[-2:]
    assert [r["status"] for r in rows] == ["sent", "folded: sent as 1 more"]
    assert rows[1]["called"] == "folded" and rows[1]["limit_id"] == host.HOLE_EVENT
    text, _ = w.finish()
    assert "folded: sent as 1 more (at the call: folded)" in text


def test_e3_the_title_subject_is_cleaned_and_bounded():
    n = make_notifier(FakeRunner())
    n.host = True
    title, body = n.texts("NEW-AGENT", "x pid 1 (named)", subject="evil;rm -rf /" + "y" * 200)
    assert not re.search(r"[^A-Za-z0-9 ._,:+()-]", title) and len(title) <= notify.TEXT_MAX
    assert title.startswith("Raqib: NEW-AGENT evil_rm -rf _")
    assert n.texts("NEW-AGENT", "x")[0] == "Raqib: NEW-AGENT"   # no subject: the A-4 title as before
    runner = FakeRunner()
    n = make_notifier(runner, limit_seconds=60)
    n.host = True
    n.notify("NEW-AGENT", "a pid 1 (named)", 0.0, limit_id="x", subject="a")
    n.notify("NEW-AGENT", "b pid 2 (named)", 1.0, limit_id="x", subject="b")
    n.tick(61.0)   # a fold delivered by tick keeps the subject of the first folded knock
    assert runner.titles() == ["Raqib: NEW-AGENT a", "Raqib: NEW-AGENT b"]


def test_e3_the_root_cause_is_recorded_before_the_fix():
    text = QUESTIONS.read_text(encoding="utf-8")
    head = text.split("## E3")[1]
    for word in ("Shared limit id: no", "FIRST-FINDING \"by the rule\": no", "A fold token: no",
                 "Title collision: no", "Root cause"):
        assert word in head, word


# --- E4: notes apart from findings, on the report, the page and the window ----------------------------------

def test_e4_page_and_window_show_the_note_apart_from_the_findings(tmp_path):
    w, clock = make_host(tmp_path, FIELD)
    run_rounds(w, clock, len(FIELD))
    state = w.state(clock.t)
    page = ui.host_page(state)
    assert "<h3>Dark after a live tree (1 notes, not alarms)</h3>" in page
    assert "dark after a live tree (note)" in page and "<script" not in page.lower()
    head, findings = page.split("<h3>Host findings (2)</h3>")
    assert "Dark after a live tree" in findings and "Dark after a live tree" not in head
    view = app.host_watch_view(state)
    assert len(view["findings"]) == 2 and len(view["notes"]) == 1
    items = app.host_finding_items(state, view)   # M8.1 REDO A-9: what the window draws, the notes after
    assert [i[2] for i in items].count("NOTE") == 1 and [i[2] for i in items][-1] == "NOTE"
    assert [i[1] for i in items if i[2] == "NOTE"] == ["note"]
    assert all(host.DARK_NOTE not in f for f in view["findings"])
    assert view["level"] != "alarm" or w.findings   # the alarm is the findings', never the note's


def test_e4_readme_has_the_two_lines():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "dark after a live tree (note)" in text and "never knocked and never an alarm" in text
    assert "HOST-RHYTHM takes its beats from every source" in text and "(KNOCKS)" in text
    section = text.split("## Watch the host\n", 1)[1].split("\n## ", 1)[0]
    lines = [l for l in section.split("\n") if l.strip()]
    # the two lines, at its end until M7.8, whose three lines follow them (test_acts_judged.py)
    assert "dark after a live tree (note)" in lines[-5] and "(KNOCKS)" in lines[-4]


def test_e4_kinds_stay_4_7_11():
    """No rule is added or changes kind: the catalog's share of the gate's 4 : 7 : 11 stays 4 : 2 : 8 (the
    silence, cross-source and tree rules, untouched here, make the rest)."""
    kinds = [r.kind for r in RULES]
    assert (kinds.count("signature"), kinds.count("demand"), kinds.count("anchor")) == (4, 2, 8)
    assert {r.id: r.kind for r in RULES}["AGENT-DARK-LIVE"] == "anchor" == {r.id: r.kind for r in RULES}[host.RHYTHM]


# --- REDO N-3..N-9 ---------------------------------------------------------------------------------------

def test_redo_n3_the_field_runs_shape_host_talks_and_os_acts_fires_at_three_cycles(tmp_path):
    name = "HOST-RHYTHM/positive-host-talks-os-acts.json"
    rule = next(r for r in RULES if r.id == host.RHYTHM)
    assert "tests/fixtures/rules/" + name in rule.fixtures["positive"]
    w = host_fixtures.rounds_of(host_fixtures.OS_SCENARIOS[name], CATALOG, RULES, str(tmp_path / "h"),
                                os_rounds=host_fixtures.OS_ROUNDS[name])
    (f,) = [f for f in w.findings if f["rule_id"] == host.RHYTHM]
    assert f["destination"] == "192.0.2.10:443" and len(f["beats"]) == 3          # the host's talk
    assert {a["basis"] for b in f["beats"] for a in b["acts"]} == {"os"}           # the os source's acts
    doc = json.loads((RULE_FIXTURES / name).read_text(encoding="ascii"))
    (tree,) = [l for l in doc["lines"] if l["tool"] == host.TREE_TOOL]
    assert tree["input_meta"]["rhythm"]["cycles"] == 3 and tree["input_meta"]["rhythm"]["fires"] is True


def test_redo_n4_beats_of_the_final_poll_are_counted_never_dropped(tmp_path):
    name = "HOST-RHYTHM/negative-os-two-cycles.json"
    names = host_fixtures.OS_SCENARIOS[name][:3]
    calls = {}
    orig = host_fixtures.rounds_of

    w = orig(names, CATALOG, RULES, str(tmp_path / "h"), os_rounds=(2,))
    # rounds_of finished the watch; a fresh one whose last os lines arrive after its last round:
    clock = Clock(0.0)
    feed = iter([host_fixtures.inventory(n, CATALOG) for n in names])
    notifier = notify.Notifier(host.HOST, enabled=False, reason="test", host=True)
    w = host.HostWatch(lambda: next(feed), CATALOG, RULES, notifier, every=10, err=io.StringIO(), clock=clock,
                       wall=lambda: host_fixtures.WALL0 + clock.t, home=str(tmp_path / "h2"), platform="fixture",
                       run="fixture-run", sysmon=lambda: (True, "test"), os_follow=host_fixtures._Follow())
    for _ in names:
        w.tick(wait=30)
        clock.t += 10
    (key,) = [k for k in w.trees if k[0] == host_fixtures.RHYTHM_PID]
    w.sources[key].first_pass.wait(5)
    lines, _ = host_fixtures.os_lines(4, "oscycle", 0)
    with open(w.sources[key].path, "a", encoding="ascii", newline="\n") as f:
        f.write("".join(json.dumps(x) + "\n" for x in lines))
    text, _ = w.finish()
    assert w.late_beats == {host.tree_word(key): 2}   # one talk and one act, read by the final poll only
    assert "RHYTHM BEATS: beats after the last round: 2 (" in text and "not judged by HOST-RHYTHM" in text


def test_redo_n5_the_state_keeps_the_newest_200_knocks_and_the_report_all(tmp_path):
    w, clock = make_host(tmp_path, ["linux"], rounds_max=1)
    run_rounds(w, clock, 1)
    for i in range(205):
        w._hole(clock.t + i, "test", "x %d" % i, knock="test %d" % i)
    st = w.state(clock.t + 300)
    assert len(st["host"]["knocks"]) == host.KNOCKS_KEPT == 200 and st["host"]["knocks_older"] == 5
    assert st["host"]["knocks"][-1]["body"].endswith("test 204") and st["host"]["knocks"][0]["body"].endswith("test 5")
    text, _ = w.finish()
    assert "KNOCKS: 205 " in text and "test 0\\\"" not in text and '"host, test 0"' in text


class OsFollow:
    """N-6: the os source of the field run: kimi's tree gains six process events (depth 1) and one
    connection when it is attached; every other tree's follow writes nothing."""

    def __init__(self, root=10728):
        self.root = root

    def __call__(self, root, log, stop, every=None, out=None, err=None, on_pass=None, after_record=None,
                 helpers=None):
        if root == self.root:
            from raqib.hooks import common
            sid = "os-%d" % root
            recs = [{"ts": "2026-11-03T10:01:20.000Z", "seq": 1, "session_id": sid, "phase": "session_start",
                     "tool": "session", "source": "os"}]
            for i in range(6):
                base = {"ts": "2026-11-03T10:01:2%d.000Z" % (i + 1), "seq": i + 2, "session_id": sid, "tool": "process",
                        "source": "os", "input_sha256": common.canonical_sha256({"command_line": "cmd %d" % i}),
                        "input_meta": {"command_head": "cmd", "command_programs": ["cmd"], "depth": 1}}
                recs += [dict(base, phase="pre"), dict(base, phase="post", output_meta={}, ok=True)]
            recs.append({"ts": "2026-11-03T10:01:29.000Z", "seq": 8, "session_id": sid, "phase": "session_end",
                         "tool": "session", "source": "os"})
            with open(log, "a", encoding="ascii", newline="\n") as f:
                f.write("".join(json.dumps(r) + "\n" for r in recs))
        if on_pass:
            on_pass(1, None)
        stop.wait()   # V-5: only the stop it is given ends it
        return 1


def field_inventories():
    """The field run's rounds with its history terminal: powershell pid 5888, unknown, a candidate there from
    round 1 (history: listed, never knocked, as Amendment M records it)."""
    import copy
    out = []
    talk = [{"remote": "198.51.100.7:443", "state": "ESTABLISHED", "basis": "ports", "lines": 1, "names": [],
             "endpoint": [], "cites": [{"src": "win-tcp", "line": 2, "text": "fake terminal connection (N-6)"}]}]
    for name in FIELD:
        i = copy.deepcopy(inv(name))
        i["candidates"].append({"pid": 5888, "image": "powershell", "id": "C9", "talks": talk,
                               "exe": "C:\\Users\\user\\AppData\\Local\\term\\powershell.exe", "exe_from": "record",
                               "started": "2026-11-03T09:00:00.000Z", "cwd": None, "acts": [],
                               "cites": [{"src": "win-process", "line": 2, "text": "fake terminal row (N-6)"}]})
        out.append(i)
    return out


def test_redo_n6_the_replay_with_the_history_terminal_and_an_os_source(tmp_path):
    runner = FakeRunner()
    feed = iter(field_inventories())
    clock = Clock()
    notifier = make_notifier(runner)
    notifier.host = True
    w = host.HostWatch(lambda: next(feed), CATALOG, main_rules(tmp_path), notifier, every=10, out=io.StringIO(),
                       err=io.StringIO(), clock=clock, wall=lambda: 1793700000.0 + clock.t - 1000.0,
                       home=str(tmp_path / "home"), platform="test", sysmon=lambda: (True, "test: Sysmon"),
                       os_follow=OsFollow())
    for k in range(len(FIELD)):
        w.tick(wait=30)
        for src in list(w.sources.values()):
            src.first_pass.wait(5)
        clock.t += w.every
    text, code = w.finish()
    (term,) = [t for t in w.trees.values() if t["pid"] == 5888]
    assert term["history"] is True and not term.get("knocked") and term["source"] == "os"
    (kimi,) = [t for t in w.trees.values() if t["pid"] == 10728]
    assert kimi["source"] == "os" and kimi["knocked"] == "sent"
    assert [(f["rule_id"], f["round"], f["notice"]) for f in w.findings] == [
        ("AGENT-DARK-LIVE", 3, "sent"), ("NEW-AGENT", 10, "sent"), ("AGENT-DARK-LIVE", 13, "sent")]
    # the os source's findings of kimi's tree, if any, knock on their own ids, never NEW-AGENT's
    kimi_ids = [k["limit_id"] for k in w.knock_rows() if "10728" in k["limit_id"]]
    assert kimi_ids[0] == "NEW-AGENT pid 10728" and all(not i.startswith("NEW-AGENT") for i in kimi_ids[1:])
    assert [k["status"] for k in w.knock_rows() if k["limit_id"] == "NEW-AGENT pid 10728"] == ["sent"]
    assert "Raqib: NEW-AGENT kimi\nhost, kimi pid 10728 (named)\n" in [c["text"] for c in runner.calls]
    assert w.source_findings == [] and len(runner.calls) == 3   # as the field's report: three findings, no source one
    assert code == 1


def test_redo_n6_n8_the_questions_file_keeps_to_the_record():
    text = QUESTIONS.read_text(encoding="utf-8")
    assert "10:09" not in text and "18:10:30Z" in text
    redo = text.split("## REDO (Amendment N)")[1]
    assert "AppUserModelID" in redo and "struck" in redo
    head = text.split("## E3")[1].split("## Design points")[0]
    assert "Kimi ran in a PowerShell terminal at that moment" not in head


def test_redo_n9_one_child_seen_by_the_host_and_by_os_is_one_act(tmp_path):
    import datetime
    w, clock = make_host(tmp_path, ["linux"])
    run_rounds(w, clock, 1)
    key = next(iter(w.trees))
    at = datetime.datetime(2026, 11, 3, 10, 0, 5, 200000, tzinfo=datetime.timezone.utc)
    host_act = {"pid": 4401, "image": "bash", "started": "2026-11-03T10:00:05.200Z", "at": at, "basis": "started",
                "cites": []}
    os_act = {"pid": None, "image": "BASH.exe", "started": "2026-11-03T10:00:05.000Z",
              "at": at - datetime.timedelta(seconds=0.2), "basis": "os", "cites": []}
    other = dict(os_act, image="python")
    later = dict(os_act, at=at + datetime.timedelta(seconds=5))
    hooks = {"pid": None, "image": "Bash", "started": "x", "at": at + datetime.timedelta(seconds=0.5),
             "basis": "hooks", "cites": []}
    assert w._once(key, [host_act]) == [host_act]
    assert w._once(key, [os_act, other, later, hooks]) == [other, later]
    assert w.act_twins == 2
    assert w._once(key, [dict(host_act)]) == []   # the same pid and start time again
    text, _ = w.finish()
    assert "3 act(s) seen by a second source, counted once" in text


def test_redo_n2_the_note_fixtures_are_what_make_py_makes_and_each_holds_its_note():
    built = host_fixtures.build_notes()
    assert sorted(built) == sorted(p.name for p in NOTES.glob("*.json"))
    for name, text in built.items():
        assert (NOTES / name).read_text(encoding="ascii") == text, name
        doc = json.loads(text)
        assert doc["dark_notes"] and doc["dark_notes"][-1] == doc["lines"][0]["input_meta"]["round"]
