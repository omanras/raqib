"""Where M8.1 meets M7.8 (the Table, 2026-11-11; ADR-0009 Amendment C, ADR-0007 Amendment W): the window was
rebuilt beside M7.8 and had not seen its state. It counts a source's finding as the watch's own rule does (not
history, not a copy judged on another tree, not a note on a benign tree), lists a benign tree's notes apart,
and knows the words a tree's findings cell now carries."""
import json
from pathlib import Path

from raqib import app, host, ui

import test_acts_judged as aj
from hostthreads import raqib_threads_end   # noqa: F401  (autouse: ends every HostWatch, fails a leaked thread)


def entry(**kw):
    base = {"rule_id": "NET-TOOL", "severity": "medium", "summary": "process may reach the network", "history": False,
            "judged_on": None, "tree": "6200:agent:-", "trace": "x.jsonl", "cited_seq": [3], "notice": "sent"}
    base.update(kw)
    return base


def test_the_window_counts_a_source_finding_as_the_watchs_own_rule_does():
    live, old = entry(), entry(history=True)
    copy, note = entry(judged_on=6200, tree="5100:outer:-"), entry(benign_note=True, tree="5100:explorer:-")
    state = {"host": {"findings": [], "source_findings": [live, old, copy, note], "suspicions": []}}
    assert [app.source_alarm(f) for f in (live, old, copy, note)] == [True, False, False, False]
    assert [app.source_note(f) for f in (live, old, copy, note)] == [False, False, False, True]
    assert not app.source_note(entry(benign_note=True, judged_on=6200))   # a copy of a note is neither
    assert app.host_counts(state) == (1, 0)
    items = app.host_finding_items(state)
    assert [(i[0], i[1]) for i in items] == [("medium", "alarm"), ("noted", "note")]
    assert "on a benign tree: noted, not knocked" in items[1][4] and "x.jsonl" in items[1][4]   # its cite (A5)
    assert "6200" in items[0][4] and "x.jsonl" in items[0][4]


def test_the_findings_cell_knows_the_new_words_and_only_an_alarm_is_red():
    words = ("high", "medium", "low", "history", "pending at exit", "pending", "judged on another tree",
             "noted (benign)", "not settled")   # what ui.severity_counts gives a tree
    assert set(words) == set(app.SEVERITY_RANK)
    cell = ui.severity_counts({"noted (benign)": 3, "judged on another tree": 1})
    assert cell == "judged on another tree 1, noted (benign) 3"
    row = ["explorer", "5100", "benign", "-", "0", "os", cell, "-", "-"]
    assert app.row_level(row) is None                                   # a note is not an alarm
    assert app.row_level(row[:6] + ["not settled 1"] + row[7:]) == "alarm"   # V-1: an alarm of its tree
    assert app.row_level(row[:6] + ["medium 1, noted (benign) 2"] + row[7:]) == "alarm"
    order = sorted(["none", "noted (benign) 3", "not settled 1", "medium 1", "history 2", "high 1"],
                   key=lambda c: app.sort_key("severity", c))
    assert order == ["high 1", "medium 1", "not settled 1", "history 2", "noted (benign) 3", "none"]


def test_a_real_watch_with_notes_on_a_benign_tree_reads_clean_in_the_window(tmp_path):
    """The person's own ssh and curl under explorer (ADR-0007 T-2): the watch ends 0, and the window says so."""
    follow = aj.CountingFollow(by_root={5100: aj.after_start(aj.built(aj.person_and_agent_export(), 5100))})
    w = aj.watch_rounds(tmp_path, ["benign-person/before", "benign-person/before"], follow=follow)
    assert w.source_alarms() == [] and len([f for f in w.source_findings if f.get("benign_note")]) == 3
    state = json.loads(Path(w.state_path).read_text(encoding="ascii"))
    assert state["code_so_far"] == 0                                   # M8.1 B-4, on M7.8's watch
    assert app.host_counts(state) == (0, 0)                            # the verdict, the rail, the card, the tray
    items = app.host_finding_items(state)
    assert [(i[0], i[1], i[2]) for i in items] == [("noted", "note", "NET-TOOL")] * 3
    assert app.live_level(state["code_so_far"], "WATCHING") == "clean"
    (row,) = app.host_rows(state["host"]["trees"])
    assert row[2].startswith("benign") and row[6] == "%s 3" % host.BENIGN_COUNT and app.row_level(row) is None
    _, code = w.finish()
    assert code == 0
