"""M1.1: verdicts (ADR-0001 section 6) over the households in
tests/fixtures/rules: a holding and a breaching case for every rule type,
the kill-persists-until-closed sequence, and both silence findings."""

import datetime
from decimal import Decimal
from pathlib import Path

from qayd import cli, rules
from qayd.measures import Stale, Unknown, Value

FIX = Path(__file__).parent / "fixtures" / "rules"


def D(text):
    return datetime.date.fromisoformat(text)


def household(name, as_of="2026-09-30"):
    h = cli.load_household(str(FIX / name), D(as_of))
    assert h.fatal == (), h.fatal
    return h


def verdicts(name, as_of="2026-09-30"):
    h = household(name, as_of)
    vs, findings = rules.check(h.ctx, D(as_of))
    return {v.id: v for v in vs}, findings


def verdict_of(name, pid, as_of="2026-09-30"):
    h = household(name, as_of)
    return rules.verdict(h.config.policy(pid), h.ctx, D(as_of))


# ------------------------------------------------------------------ cap / floor


def test_cap_holds_and_breaches():
    v = verdict_of("household", "CAP-HOLD")
    assert v.verdict == "hold" and v.findings == () and not v.red
    assert v.measure.amount == Decimal("40") and v.limit.amount == Decimal("100")
    assert v.period.label == "2026-09" and v.cites == ("ledger.csv:22",)
    v = verdict_of("household", "CAP-BREACH")
    assert v.verdict == "breach" and v.red
    assert v.measure.amount == Decimal("15") and v.limit.amount == Decimal("10")   # 1% of 1000
    assert v.cites == ("ledger.csv:23", "ledger.csv:19")                         # measure rows, then income rows
    assert [f.code for f in v.findings] == ["BREACH"]
    f = v.findings[0]
    assert f.cls == "red" and f.policy == "CAP-BREACH" and f.period == "2026-09"
    assert f.cites == ("ledger.csv:23", "ledger.csv:19")
    assert "exceeds" in f.reason


def test_cap_equal_to_limit_holds():
    v = verdict_of("household", "CAP-HOLD", "2026-05-31")   # May: food 40 vs 100 -> hold
    assert v.verdict == "hold"
    h = household("household")
    policy = h.config.policy("CAP-HOLD")._replace(limit={"kind": "value", "value": Decimal("40")})
    assert rules.verdict(policy, h.ctx, D("2026-09-30")).verdict == "hold"
    policy = policy._replace(limit={"kind": "value", "value": Decimal("39.999")})
    assert rules.verdict(policy, h.ctx, D("2026-09-30")).verdict == "breach"


def test_floor_holds_and_breaches():
    v = verdict_of("household", "FLOOR-HOLD")
    assert v.verdict == "hold" and v.measure.amount == Decimal("1900")
    assert v.cites == ("holdings.csv:10",)
    v = verdict_of("household", "FLOOR-BREACH")
    assert v.verdict == "breach" and v.measure.amount == Decimal("1000") and v.limit.amount == Decimal("2000")
    assert "below" in v.reason and v.findings[0].code == "BREACH"


# ------------------------------------------------------------------ allocation


def test_allocation_within_and_outside_the_band():
    v = verdict_of("household", "ALLOC-HOLD")
    assert v.verdict == "hold"
    assert v.measure.amount == Decimal("1900") / Decimal("2450") * 100
    v = verdict_of("household", "ALLOC-BREACH")
    assert v.verdict == "breach"
    assert v.measure.amount == Decimal("100") / Decimal("2450") * 100
    assert "outside 20%..50%" in v.reason
    assert set(v.cites) == {"holdings.csv:10", "holdings.csv:11", "holdings.csv:12"}


# -------------------------------------------------------------------- red line


def test_red_line_holds_when_no_row_ever_matches():
    v = verdict_of("household", "RED-HOLD")
    assert v.verdict == "hold" and v.period is None and v.rows == ()
    assert isinstance(v.measure, Value) and v.measure.amount == 0


def test_red_line_breaches_citing_every_matching_row_ever():
    v = verdict_of("household", "RED-BREACH")
    assert v.verdict == "breach" and v.cites == ("ledger.csv:6",)        # May 2026, long before as_of
    assert v.findings[0].code == "BREACH" and v.findings[0].cites == ("ledger.csv:6",)
    assert v.findings[0].period is None
    # before the row existed: hold
    assert verdict_of("household", "RED-BREACH", "2026-05-09").verdict == "hold"
    assert verdict_of("household", "RED-BREACH", "2026-05-10").verdict == "breach"


def test_match_rows_semantics():
    h = household("household")
    rows = h.ctx.ledger
    m, u = rules.match_rows({"tags": ("transfer",), "account": "savings"}, rows, h.ctx)
    assert len(m) == 5 and all(r.account == "savings" for r in m) and u == ()
    m, _ = rules.match_rows({"tags": ("transfer",), "account": "savings", "min_amount": Decimal("300.001")}, rows, h.ctx)
    assert m == ()
    m, _ = rules.match_rows({"category": "discretionary", "min_amount": Decimal("200")}, rows, h.ctx)
    assert [r.line for r in m] == [6]                                       # abs(-250) >= 200
    m, _ = rules.match_rows({"tags_any": ("margin", "transfer")}, rows, h.ctx)
    assert len(m) == 10
    m, _ = rules.match_rows({"tags": ("transfer", "margin")}, rows, h.ctx)   # all tags required
    assert m == ()


# --------------------------------------------------------------------- routine


def test_routine_holds_with_a_matching_row_and_is_missing_without():
    v = verdict_of("household", "ROUT-HOLD")
    assert v.verdict == "hold" and v.cites == ("ledger.csv:21",) and v.period.label == "2026-09"
    v = verdict_of("household", "ROUT-MISS")
    assert v.verdict == "missing" and v.period.label == "2026-Q3"
    assert [f.code for f in v.findings] == ["ROUTINE-MISSING"]
    assert v.findings[0].period == "2026-Q3" and v.findings[0].cites == ()
    # as_of before the transfer of the month: missing (silence is red)
    v = verdict_of("household", "ROUT-HOLD", "2026-09-02")
    assert v.verdict == "missing"


# ------------------------------------------------------------------------ kill


def test_kill_crosses_and_persists_until_closed():
    # 2026-08-31: 6% drawdown vs 5% -> kill, citing the crossing and its peak
    v = verdict_of("kill", "K1", "2026-08-31")
    assert v.verdict == "kill"
    assert set(v.cites) == {"holdings.csv:8", "holdings.csv:9", "holdings.csv:5", "holdings.csv:6"}
    assert v.findings[0].code == "KILL" and v.findings[0].date == "2026-08-31"
    assert "crossed 5%" in v.reason and "peak 500 OMR on 2026-07-31" in v.reason
    # the day before the closing decision: still kill
    assert verdict_of("kill", "K1", "2026-09-04").verdict == "kill"
    # on the decision date: closed -> hold, with the closing noted
    v = verdict_of("kill", "K1", "2026-09-05")
    assert v.verdict == "hold" and v.findings == ()
    assert v.reason == "kill of 2026-08-31 closed by D-close (2026-09-05)"
    assert verdict_of("kill", "K1", "2026-09-30").verdict == "hold"
    # a new crossing after the decision: kill again
    v = verdict_of("kill", "K1", "2026-10-31")
    assert v.verdict == "kill" and v.findings[0].date == "2026-10-31"
    assert v.measure.amount == Decimal("100") / Decimal("550") * 100
    # before any crossing: hold with no note
    v = verdict_of("kill", "K1", "2026-07-31")
    assert v.verdict == "hold" and v.reason is None


def test_kill_closed_by_a_decision_dated_before_the_crossing_stays_kill():
    v = verdict_of("kill_backdated", "K1", "2026-09-30")
    assert v.verdict == "kill" and v.findings[0].date == "2026-08-31"


def test_kill_hold_when_threshold_never_crossed():
    v = verdict_of("household", "KILL-HOLD")
    assert v.verdict == "hold" and v.measure.amount == Decimal("0") and v.limit.amount == Decimal("50")
    v = verdict_of("household", "KILL-BREACH")
    assert v.verdict == "kill"


# --------------------------------------------------------------- silence (A3)


def test_empty_period_makes_ledger_based_policies_missing():
    vs, findings = verdicts("empty_period")
    assert vs["CAP-M"].verdict == "missing" and vs["CAP-M"].findings[0].code == "EMPTY-PERIOD"
    assert vs["CAP-M"].findings[0].period == "2026-09" and vs["CAP-M"].findings[0].cites == ()
    assert vs["ROUT-M"].verdict == "missing" and vs["ROUT-M"].findings[0].code == "EMPTY-PERIOD"
    assert vs["CAP-Q"].verdict == "hold" and vs["CAP-Q"].measure.amount == Decimal("80")   # Q3 has July and August
    assert vs["FLOOR-H"].verdict == "hold"                                                 # holdings do not care
    assert [f.code for f in findings] == ["EMPTY-PERIOD", "EMPTY-PERIOD"]
    assert not rules.is_green(tuple(vs.values()), findings)
    # in August the same policies hold
    vs, findings = verdicts("empty_period", "2026-08-31")
    assert {v.verdict for v in vs.values()} == {"hold"} and findings == ()


def test_stale_snapshot_for_holdings_based_policies():
    vs, findings = verdicts("stale")
    for pid in ("FLOOR-H", "ALLOC", "K1"):
        v = vs[pid]
        assert v.verdict == "stale", pid
        assert v.findings[0].code == "STALE-SNAPSHOT" and v.findings[0].date == "2026-07-31"
        assert "61 days old; 45 allowed" in v.reason
    assert isinstance(vs["FLOOR-H"].measure, Stale) and vs["FLOOR-H"].measure.amount == Decimal("1300")
    assert vs["CAP-M"].verdict == "hold"                               # ledger-based: unaffected
    assert vs["K1"].findings[0].cites == ("holdings.csv:5",)
    # exactly at the allowed age: not stale
    vs, findings = verdicts("stale", "2026-09-14")
    assert {v.verdict for v in vs.values()} == {"hold"}


# ------------------------------------------------------- unknown and invalid


def test_invalid_row_makes_touched_policies_invalid_and_is_a_red_finding():
    vs, findings = verdicts("invalid_rows")
    assert vs["CAP-SEP"].verdict == "invalid" and vs["CAP-SEP"].findings[0].code == "INVALID"
    assert vs["CAP-SEP"].findings[0].cites == ("ledger.csv:14",)
    assert vs["CAP-Q"].verdict == "invalid"                     # the quarter contains September
    assert vs["RED"].verdict == "invalid"                       # the bad row may be the margin trade
    assert vs["ROUT"].verdict == "hold"                         # the routine row itself is fine
    assert isinstance(vs["CAP-SEP"].measure, Unknown) and vs["CAP-SEP"].measure.cause == "invalid"
    loose = [f for f in findings if f.policy is None]
    assert [(f.code, f.cls, f.cites) for f in loose] == [
        ("BAD-AMOUNT", "red", ("ledger.csv:14",)),
        ("DUP-ROW", "warn", ("ledger.csv:16",)),
    ]
    # in August the bad row (dated 2026-09-16) is after as_of: nothing is invalid
    vs, findings = verdicts("invalid_rows", "2026-08-31")
    assert vs["CAP-SEP"].verdict == "hold" and vs["RED"].verdict == "hold"
    assert [f.code for f in findings if f.policy is None] == ["BAD-AMOUNT", "DUP-ROW"]   # still reported


def test_red_line_ignores_invalid_rows_dated_after_as_of():
    v = verdict_of("invalid_rows", "RED", "2026-08-31")
    assert v.verdict == "hold"
    v = verdict_of("invalid_rows", "RED", "2026-09-16")
    assert v.verdict == "invalid"


def test_foreign_row_without_rates_table_is_unknown():
    v = verdict_of("invalid_rows", "CAP-FX", "2026-08-31")
    assert v.verdict == "unknown" and isinstance(v.measure, Unknown)
    assert v.measure.cause == "unknown" and v.findings[0].code == "UNKNOWN"
    assert v.cites == () and v.findings[0].cites == ("ledger.csv:17",)


def test_undeclared_policy_shape_is_unknown():
    v = verdict_of("invalid_rows", "SHAPE")
    assert v.verdict == "unknown" and v.measure is None
    assert v.findings[0].code == "UNKNOWN" and v.findings[0].cites == ("policies.yml:21",)
    assert "not declared" in v.reason


# ---------------------------------------------------------- check and green


def test_check_orders_reds_first_and_green_is_strict():
    vs, findings = verdicts("household")
    ordered = rules.order(tuple(vs.values()))
    assert [v.verdict for v in ordered][:6] == ["breach", "breach", "missing", "breach", "kill", "breach"]
    assert all(v.verdict == "hold" for v in ordered[6:])
    assert not rules.is_green(tuple(vs.values()), findings)
    vs, findings = verdicts("green")
    assert rules.is_green(tuple(vs.values()), findings) and findings == ()
    # a warning alone does not break green
    warn = rules.Finding("DUP-ROW", "warn", None, None, None, ("ledger.csv:3",), "dup")
    assert rules.is_green(tuple(vs.values()), (warn,))
    red = warn._replace(cls="red", code="BAD-AMOUNT")
    assert not rules.is_green(tuple(vs.values()), (red,))


def test_money_and_pct_display():
    assert rules.money(Decimal("248.180000"), "OMR") == "248.18 OMR"
    assert rules.money(Decimal("1900.000"), "OMR") == "1900 OMR"
    assert rules.money(Decimal("0.1")) == "0.1"
    assert rules.money(Decimal("-0.000")) == "0"
    assert rules.money(Decimal("1E+3")) == "1000"
    assert rules.pct(Decimal("4.545454545")) == "4.55%"
    assert rules.pct(Decimal("77.5")) == "77.5%"
    assert rules.pct(Decimal("0")) == "0%"
