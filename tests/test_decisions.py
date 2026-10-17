"""M1.2: decisions (ADR-0001 section 7): DECISION-DUE, closes must name a
kill policy, and a backdated closing decision does not close a kill."""

import datetime
from pathlib import Path

from qayd import cli, decisions, rules

FIX = Path(__file__).parent / "fixtures"
DEC = FIX / "decisions"
RUL = FIX / "rules"


def D(text):
    return datetime.date.fromisoformat(text)


# ----------------------------------------------------------------- the loader


def test_closes_must_name_a_kill_policy_when_kill_ids_are_given():
    ds, problems = decisions.load(RUL / "decisions" / "decisions.yml", ("K1", "CAP-HOLD"), kill_ids=("K1",))
    assert [d.id for d in ds] == ["D-due", "D-open", "D-today", "D-close", "D-done"]
    assert [(p["line"], p["code"], p["field"]) for p in problems] == [(28, "BAD-CLOSES", "decisions[4].closes")]
    assert "not of type kill" in problems[0]["reason"] and problems[0]["class"] == "invalid"


def test_closes_is_not_type_checked_without_kill_ids():
    ds, problems = decisions.load(RUL / "decisions" / "decisions.yml", ("K1", "CAP-HOLD"))
    assert problems == [] and len(ds) == 6
    ds, problems = decisions.load(RUL / "decisions" / "decisions.yml", ("K1", "CAP-HOLD"), kill_ids=())
    assert [p["code"] for p in problems] == ["BAD-CLOSES", "BAD-CLOSES"]       # nothing is a kill
    assert [d.id for d in ds] == ["D-due", "D-open", "D-today", "D-done"]


def test_unknown_closes_is_reported_as_unknown_policy_not_bad_closes():
    ds, problems = decisions.load(DEC / "unknown_policy.yml", ("WLT-05",), kill_ids=("WLT-05",))
    assert [p["code"] for p in problems] == ["UNKNOWN-POLICY", "UNKNOWN-POLICY"]


def test_days_until_review_and_is_due():
    ds, _ = decisions.load(RUL / "decisions" / "decisions.yml", ("K1", "CAP-HOLD"), kill_ids=("K1",))
    by_id = {d.id: d for d in ds}
    due = by_id["D-due"]
    assert due.days_until_review(D("2026-09-30")) == -15 and due.is_due(D("2026-09-30"))
    assert due.days_until_review(D("2026-09-15")) == 0 and not due.is_due(D("2026-09-15"))
    assert not due.is_due(D("2026-09-14")) and due.is_due(D("2026-09-16"))
    assert by_id["D-open"].days_until_review(D("2026-09-30")) == 93
    closed = by_id["D-close"]
    assert not closed.is_due(D("2030-01-01"))                      # closed decisions are never due


# ------------------------------------------------------------- DECISION-DUE


def test_decision_findings():
    ds, _ = decisions.load(RUL / "decisions" / "decisions.yml", ("K1", "CAP-HOLD"), kill_ids=("K1",))
    found = rules.decision_findings(ds, D("2026-09-30"))
    assert len(found) == 1
    f = found[0]
    assert f.code == "DECISION-DUE" and f.cls == "red" and f.policy == "CAP-HOLD"
    assert f.date == "2026-09-15" and f.cites == ("decisions.yml:1",)
    assert f.reason == "decision D-due is open and its review date 2026-09-15 is 15 days past"
    found = rules.decision_findings(ds, D("2026-10-01"))
    assert [f.policy for f in found] == ["CAP-HOLD", None]        # D-today has no policy
    assert "1 day past" in found[1].reason
    assert rules.decision_findings(ds, D("2026-09-15")) == ()
    assert rules.decision_findings((), D("2026-09-30")) == ()


def test_check_is_not_green_with_a_due_decision():
    h = cli.load_household(str(RUL / "decisions"), D("2026-09-30"))
    rep = cli.build_check(h, D("2026-09-30"))
    assert rep.green is False and [f.code for f in rep.findings] == ["DECISION-DUE", "BAD-CLOSES"]
    assert all(v.verdict == "hold" for v in rep.verdicts)


# ------------------------------------------------------- kill and its closer


def test_kill_closed_by_a_backdated_decision_stays_kill():
    h = cli.load_household(str(RUL / "kill_backdated"), D("2026-09-30"))
    assert [d.id for d in h.decisions] == ["D-early"]
    v = rules.verdict(h.config.policy("K1"), h.ctx, D("2026-09-30"))
    assert v.verdict == "kill" and v.findings[0].date == "2026-08-31"


def test_kill_closed_by_a_decision_after_the_crossing_holds():
    h = cli.load_household(str(RUL / "kill"), D("2026-09-30"))
    v = rules.verdict(h.config.policy("K1"), h.ctx, D("2026-09-30"))
    assert v.verdict == "hold" and "closed by D-close" in v.reason
    # a decision that was dropped for naming a non-kill policy closes nothing
    h = cli.load_household(str(RUL / "decisions"), D("2026-09-30"))
    assert "D-bad-closes" not in [d.id for d in h.decisions]
    v = rules.verdict(h.config.policy("K1"), h.ctx, D("2026-09-30"))
    assert v.verdict == "hold" and "closed by D-close" in v.reason


def test_load_household_passes_kill_ids():
    h = cli.load_household(str(RUL / "decisions"), D("2026-09-30"))
    assert [p["code"] for p in h.problems["decisions.yml"]] == ["BAD-CLOSES"]
    assert h.fatal == ()                                            # a row-level problem, not fatal
