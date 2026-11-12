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
    assert w.source_alarms() == [] and len([f for f in w.source_findings if f.get("benign_note")]) == 4
    state = json.loads(Path(w.state_path).read_text(encoding="ascii"))
    assert state["code_so_far"] == 0                                   # M8.1 B-4, on M7.8's watch
    assert app.host_counts(state) == (0, 0)                            # the verdict, the rail, the card, the tray
    items = app.host_finding_items(state)
    assert [(i[0], i[1], i[2]) for i in items] == [("noted", "note", "NET-TOOL")] * 4
    assert app.live_level(state["code_so_far"], "WATCHING") == "clean"
    (row,) = app.host_rows(state["host"]["trees"])
    assert row[2].startswith("benign") and row[6] == "%s 3" % host.BENIGN_COUNT and app.row_level(row) is None
    _, code = w.finish()
    assert code == 0


# --- where the window meets M7.9 (the Table at the merge: ADR-0007 AB-2, AB-9 / Q-21, AB-11) ---------------------

def test_m79_a_tree_listed_by_the_channel_says_so_in_its_kind_and_a_knocked_one_does_not():
    assert app.tree_kind({"by_channel": True}) == "unknown (%s)" % host.BY_CHANNEL
    assert host.BY_CHANNEL not in app.tree_kind({"by_channel": True, "knocked": 3})   # AB-1: knocked, never tagged
    assert app.tree_kind({}) == "unknown" and app.tree_kind({"named": True, "knocked": 2}) == "named (new)"


def test_m79_a_clean_host_watch_says_the_trees_it_listed_by_the_channel_and_never_a_path():
    state = {"host": {"by_channel_count": 2, "by_channel_sentence": "2 unknown tree(s) ...: C:\\Users\\user\\x.exe (2)"}}
    said = app.by_channel_cause(state)
    assert said == "2 unknown trees seen only %s, listed, not knocked" % host.BY_CHANNEL and "\\" not in said
    assert app.by_channel_cause({"host": {"by_channel_count": 1}}).startswith("1 unknown tree seen only ")
    for none in ({"host": {"by_channel_count": 0}}, {"host": {}}, {}, None, {"host": {"by_channel_count": True}}):
        assert app.by_channel_cause(none) == ""   # must not touch: M = 0 reads as before
    # only where the watch's own causes say nothing: an alarm or a hole keeps its words
    assert app.live_cause(3, 0, 0, app.host_causes({"holes": [{"kind": "x"}]})) == "1 hole"


def _look(reader):
    probe = app.HostProbe(reader, catalog=None, deadline=60.0).start()
    probe.worker.thread.join(10)
    assert probe.done()
    return probe


def test_m79_the_look_closes_the_channel_its_reader_opened_once_its_one_read_is_back():
    calls = []

    def reader():
        calls.append("read")
        return {"holes": [], "candidates": [], "act_roots": []}

    def close(why):
        calls.append(("close", why))
        return []
    reader.close = close
    probe = _look(reader)
    assert calls == ["read", ("close", "the look ended")] and probe.closed == []


def test_m79_what_the_looks_close_had_to_end_is_a_hole_of_the_look_and_a_reader_without_close_is_as_before():
    def reader():
        return {"holes": [], "candidates": [], "act_roots": []}
    assert _look(reader).closed == []   # must not touch: a test's reader, a stand-in: nothing to close

    def failing():
        raise RuntimeError("no sample")
    failing.close = lambda why: ["wevtutil ended: %s" % why]
    probe = _look(failing)   # the reader failed: its channel is closed all the same
    assert probe.closed == ["the look's channel: wevtutil ended: the look ended"]
    assert probe.closed[0] in probe.view()["holes"]

    def broken():
        return {"holes": [], "candidates": [], "act_roots": []}

    def bad_close(why):
        raise OSError("gone")
    broken.close = bad_close
    assert _look(broken).closed == ["the look's channel was not closed: OSError: gone"]
