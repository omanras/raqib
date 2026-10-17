"""M0.3: measures, limits and rates (ADR-0001 section 5, A5).

The household in tests/fixtures/measures is small enough to compute by
hand; every expected Decimal below was computed from the CSV rows:

  rates: USD 0.385 from 2026-07-01, 0.384 from 2026-07-14, 0.386 from
  2026-09-01; no EUR or GBP rate.
  2026-07 income 1000; expense housing 200 + food 50.5 - refund 10
          + discretionary 20 USD * 0.384 = 7.68  -> 248.18
  2026-08 income 1000 + 100 side = 1100; expense 200 + 60 = 260
  2026-09 income 1000 (a +50 row tagged transfer is not income);
          expense has a 25 EUR row -> Unknown (no rate)
  holdings 2026-08-31: cash 1600; broker 800 USD + 250 USD at 0.384
          = 307.2 + 96 = 403.2; debt 500 (excluded from share totals)
  holdings 2026-09-30: cash 1900; broker (950 + 300) * 0.386 = 482.5;
          debt 400; gold 100 GBP -> Unknown
  broker by snapshot: 07-31 (900+200)*0.384 = 422.4; 08-31 403.2;
          09-30 482.5 -> drawdown on 08-31 = 19.2/422.4 = 4.5454..%
"""

import datetime
from decimal import Decimal
from pathlib import Path

from qayd import ledger, measures, periods, policies, rates
from qayd.measures import Context, Stale, Unknown, Value

FIX = Path(__file__).parent / "fixtures"
RAT = FIX / "rates"
MEA = FIX / "measures"


def D(text):
    return datetime.date.fromisoformat(text)


def P(text):
    return periods.parse(text)


def q4(value):
    return value.quantize(Decimal("0.0001"))


# ----------------------------------------------------------------- the household


def household():
    cfg, problems = policies.load(MEA / "policies.yml")
    assert problems == []
    led = ledger.load_ledger(MEA / "ledger.csv", cfg.accounts, cfg.categories)
    hol = ledger.load_holdings(MEA / "holdings.csv", cfg.accounts, cfg.classes)
    rt = rates.load(MEA / "rates.csv", cfg.base_currency)
    assert led.problems == [] and hol.problems == [] and rt.problems == []
    return cfg, led.rows, hol.rows, rt.table


def ctx(as_of="2026-09-30", **kw):
    cfg, led, hol, table = household()
    return Context(cfg, led, hol, table, D(as_of), **kw)


def measure_of(pid):
    cfg, _, _, _ = household()
    return cfg.policy(pid).measure


def limit_of(pid):
    cfg, _, _, _ = household()
    return cfg.policy(pid).limit


SUM_DISC = {"kind": "sum", "group": "expense", "category": "discretionary", "period": "month"}
SUM_FOOD = {"kind": "sum", "group": "expense", "category": "food", "period": "month"}
HOLD_CASH = {"kind": "holdings", "by": "class", "name": "cash"}
HOLD_BROKER = {"kind": "holdings", "by": "account", "name": "broker"}
SHARE_EQUITY = {"kind": "share", "by": "class", "name": "equity"}


def dd(name, days):
    return {"kind": "drawdown", "by": "account", "name": name, "window_days": days}


# ----------------------------------------------------------------------- rates


def test_rates_valid_table_and_convert():
    table, problems = rates.load(RAT / "valid.csv", "OMR")
    assert problems == []
    assert table.base == "OMR" and table.currencies == ("EUR", "USD")
    assert len(table.rows) == 4
    c = table.convert(Decimal("10"), "OMR", D("2026-07-14"))
    assert c == rates.Conversion(Decimal("10"), None)
    c = table.convert(Decimal("20.000"), "USD", D("2026-07-14"))   # exactly on a rate date
    assert c.amount == Decimal("7.680000") and c.rate.cite == "valid.csv:3"
    assert isinstance(c.amount, Decimal)
    c = table.convert(Decimal("20"), "USD", D("2026-07-13"))       # the day before
    assert c.amount == Decimal("7.700") and c.rate.line == 2
    c = table.convert(Decimal("1"), "USD", D("2030-01-01"))        # far later: latest rate
    assert c.amount == Decimal("0.386") and c.rate.line == 4
    c = table.convert(Decimal("100"), "EUR", D("2026-01-01"))
    assert c.amount == Decimal("42.00") and c.rate.line == 5


def test_rates_unknown_cases():
    table, _ = rates.load(RAT / "valid.csv", "OMR")
    u = table.convert(Decimal("1"), "USD", D("2026-06-30"))
    assert isinstance(u, Unknown) and "on or before 2026-06-30" in u.reason
    u = table.convert(Decimal("1"), "GBP", D("2026-07-14"))
    assert isinstance(u, Unknown) and "GBP" in u.reason
    u = rates.Table((), None).convert(Decimal("1"), "USD", D("2026-07-14"))
    assert isinstance(u, Unknown) and "base currency" in u.reason
    assert rates.empty("OMR").convert(Decimal("3"), "OMR", D("2026-01-01")).amount == Decimal("3")


def test_rates_bad_rows_are_problems():
    table, problems = rates.load(RAT / "bad_rows.csv", "OMR")
    assert [(p["line"], p["code"]) for p in problems] == [
        (3, "BAD-DATE"), (4, "BAD-CURRENCY"), (5, "BAD-RATE"), (6, "BAD-RATE"),
        (7, "BAD-RATE"), (8, "BAD-RATE"), (9, "BASE-RATE"), (10, "COLUMN-COUNT"),
    ]
    assert [r.line for r in table.rows] == [2]


def test_rates_conflict_is_a_problem_and_unknown_on_that_date():
    table, problems = rates.load(RAT / "conflict.csv", "OMR")
    assert [(p["line"], p["code"]) for p in problems] == [(3, "CONFLICT-RATE")]
    assert "line 2" in problems[0]["reason"]
    u = table.convert(Decimal("1"), "USD", D("2026-07-15"))
    assert isinstance(u, Unknown) and u.cites == ("conflict.csv:2", "conflict.csv:3")
    assert table.convert(Decimal("1"), "USD", D("2026-08-01")).amount == Decimal("0.390")


def test_rates_exact_duplicate_is_a_warning_not_a_conflict():
    table, problems = rates.load(RAT / "dup.csv", "OMR")
    assert [(p["line"], p["code"], p["class"]) for p in problems] == [(3, "DUP-ROW", "warn")]
    assert table.convert(Decimal("2"), "USD", D("2026-07-01")).amount == Decimal("0.770")


def test_rates_file_level():
    table, problems = rates.load(RAT / "bad_header.csv", "OMR")
    assert table.rows == () and [p["code"] for p in problems] == ["BAD-HEADER"]
    table, problems = rates.load(RAT / "nope.csv", "OMR")
    assert table.rows == () and [p["code"] for p in problems] == ["FILE-MISSING"]
    table, problems = rates.load_optional(RAT / "nope.csv", "OMR")
    assert table.rows == () and problems == [] and table.base == "OMR"
    table, problems = rates.load_optional(RAT / "valid.csv", "OMR")
    assert len(table.rows) == 4 and problems == []
    table, problems = rates.load_optional(RAT, "OMR")
    assert [p["code"] for p in problems] == ["FILE-UNREADABLE"]


# ------------------------------------------------------------------------ sums


def test_income_excludes_transfers_and_cites_rows():
    c = ctx()
    v = measures.income(c, P("2026-07"))
    assert isinstance(v, Value)
    assert v.amount == Decimal("1000.000") and isinstance(v.amount, Decimal)
    assert v.cites == ("ledger.csv:2",)
    v = measures.income(c, P("2026-08"))
    assert v.amount == Decimal("1100") and v.cites == ("ledger.csv:9", "ledger.csv:14")
    v = measures.income(c, P("2026-09"))                 # +50 tagged transfer is not income
    assert v.amount == Decimal("1000") and v.cites == ("ledger.csv:15",)
    v = measures.income(c, P("2026-Q3"))
    assert v.amount == Decimal("3100") and len(v.rows) == 4


def test_expense_is_positive_with_refund_and_foreign_row_converted():
    v = measures.expense(ctx(), P("2026-07"))
    assert v.amount == Decimal("248.18")
    assert v.cites == ("ledger.csv:5", "ledger.csv:6", "ledger.csv:7", "ledger.csv:8", "rates.csv:3")
    v = measures.expense(ctx(), P("2026-08"))
    assert v.amount == Decimal("260") and v.cites == ("ledger.csv:12", "ledger.csv:13")


def test_sum_category_and_group():
    c = ctx()
    v = measures.evaluate(SUM_FOOD, c, P("2026-07"))
    assert v.amount == Decimal("40.5") and v.cites == ("ledger.csv:6", "ledger.csv:8")
    v = measures.evaluate(SUM_DISC, c, P("2026-07"))
    assert v.amount == Decimal("7.68") and v.cites == ("ledger.csv:7", "rates.csv:3")
    v = measures.evaluate(measure_of("M-07"), c, P("2026-08"))      # sum: expense
    assert v.amount == Decimal("260")
    v = measures.evaluate(measure_of("M-06"), c, P("2026-Q3"))      # sum: income per quarter
    assert v.amount == Decimal("3100")
    v = measures.evaluate({"kind": "sum", "group": "invest", "category": None, "period": "month"}, c, P("2026-07"))
    assert v.amount == Decimal("0") and v.rows == ()


def test_missing_rate_makes_the_measure_unknown_never_partial():
    c = ctx()
    u = measures.evaluate(SUM_DISC, c, P("2026-09"))
    assert isinstance(u, Unknown)
    assert "EUR" in u.reason and u.cites == ("ledger.csv:18",)
    assert isinstance(measures.expense(c, P("2026-Q3")), Unknown)
    assert isinstance(measures.expense(c, P("2026-09")), Unknown)


def test_as_of_cuts_the_period():
    v = measures.evaluate(SUM_DISC, ctx("2026-09-10"), P("2026-09"))
    assert v.amount == Decimal("0") and v.rows == ()          # the EUR row (09-15) is not seen
    v = measures.evaluate(SUM_DISC, ctx("2026-09-28"), P("2026-09"))
    assert isinstance(v, Unknown)                               # 09-15 EUR row is seen again
    v = measures.income(ctx("2026-08-10"), P("2026-08"))
    assert v.amount == Decimal("1000")                          # the 08-20 side income is not seen
    assert measures.rows_in(ctx("2026-08-10"), P("2026-08")) == tuple(
        r for r in ctx().ledger if D("2026-08-01") <= r.date <= D("2026-08-10"))
    assert measures.end_of(ctx("2026-08-10"), P("2026-08")) == D("2026-08-10")
    assert measures.end_of(ctx("2026-09-30"), P("2026-08")) == D("2026-08-31")
    assert measures.end_of(Context(None, as_of=None), P("2026-08")) == D("2026-08-31")


def test_invalid_ledger_row_poisons_its_period():
    dated = [{"file": "ledger.csv", "line": 99, "code": "BAD-AMOUNT", "class": "invalid",
              "reason": "x", "date": "2026-07-03"}]
    u = measures.income(ctx(ledger_problems=dated), P("2026-07"))
    assert isinstance(u, Unknown) and u.cites == ("ledger.csv:99",) and "BAD-AMOUNT" in u.reason
    assert measures.income(ctx(ledger_problems=dated), P("2026-08")).amount == Decimal("1100")
    assert isinstance(measures.income(ctx(ledger_problems=dated), P("2026-Q3")), Unknown)
    undated = [{"file": "ledger.csv", "line": 5, "code": "COLUMN-COUNT", "class": "invalid", "reason": "x"}]
    assert isinstance(measures.income(ctx(ledger_problems=undated), P("2026-08")), Unknown)
    warn = [{"file": "ledger.csv", "line": 5, "code": "DUP-ROW", "class": "warn", "reason": "x",
             "date": "2026-08-03"}]
    assert measures.income(ctx(ledger_problems=warn), P("2026-08")).amount == Decimal("1100")
    assert measures.invalid_in(dated + undated, D("2026-08-01"), D("2026-08-31")) == undated


# ---------------------------------------------------------------------- limits


def test_limit_value_absolute_and_pct():
    c = ctx()
    v = measures.limit_value({"kind": "value", "value": Decimal("2000")}, c, P("2026-08"))
    assert v == Value(Decimal("2000"))
    v = measures.limit_value(limit_of("M-03"), c, P("2026-09"))          # {pct: 15}
    assert v.amount == Decimal("15") and v.rows == ()


def test_limit_pct_of_income_cites_the_income_rows():
    c = ctx()
    v = measures.limit_value(limit_of("M-01"), c, P("2026-07"))          # 10% of 1000
    assert v.amount == Decimal("100") and v.cites == ("ledger.csv:2",)
    v = measures.limit_value(limit_of("M-01"), c, P("2026-08"))          # 10% of 1100
    assert v.amount == Decimal("110")
    v = measures.limit_value({"kind": "pct_of", "of": "income", "value": Decimal("12.5")}, c, P("2026-08"))
    assert v.amount == Decimal("137.5")


def test_limit_months_of_expense_uses_complete_months_with_rows():
    c = ctx()
    v = measures.limit_value(limit_of("M-02"), c, P("2026-08"))          # 6 x avg(248.18, 260)
    assert v.amount == Decimal("1524.54")
    assert v.detail == ("2026-07", "2026-08")
    assert set(v.cites) == {"ledger.csv:5", "ledger.csv:6", "ledger.csv:7", "ledger.csv:8",
                            "rates.csv:3", "ledger.csv:12", "ledger.csv:13"}
    avg = measures.average_monthly_expense(c, P("2026-08"))
    assert avg.amount == Decimal("254.09")
    # a month with an Unknown expense (EUR row) makes the limit Unknown
    assert isinstance(measures.limit_value(limit_of("M-02"), c, P("2026-09")), Unknown)
    # as_of mid-month: September is incomplete and does not count
    v = measures.limit_value(limit_of("M-02"), ctx("2026-09-10"), P("2026-09"))
    assert v.amount == Decimal("1524.54") and v.detail == ("2026-07", "2026-08")
    # before any ledger row: no month available
    u = measures.limit_value(limit_of("M-02"), ctx("2026-06-30"), P("2026-06"))
    assert isinstance(u, Unknown) and "no complete month" in u.reason
    # an invalid row in one of the months poisons the average
    bad = [{"file": "ledger.csv", "line": 4, "code": "BAD-DATE", "class": "invalid", "reason": "x",
            "date": "2026-07-09"}]
    assert isinstance(measures.limit_value(limit_of("M-02"), ctx(ledger_problems=bad), P("2026-08")), Unknown)


def test_limit_and_measure_unknown_kinds():
    c = ctx()
    assert isinstance(measures.limit_value({"kind": "ratio", "value": 1}, c, P("2026-08")), Unknown)
    assert isinstance(measures.limit_value(None, c, P("2026-08")), Unknown)
    assert isinstance(measures.evaluate({"kind": "median"}, c, P("2026-08")), Unknown)
    assert isinstance(measures.evaluate(None, c, P("2026-08")), Unknown)


# -------------------------------------------------------------------- holdings


def test_holdings_as_of_period_end():
    c = ctx()
    v = measures.evaluate(HOLD_CASH, c, P("2026-09"))
    assert v.amount == Decimal("1900") and v.cites == ("holdings.csv:11",)
    v = measures.evaluate(HOLD_BROKER, c, P("2026-09"))
    assert v.amount == Decimal("482.5")
    assert v.cites == ("holdings.csv:12", "holdings.csv:13", "rates.csv:4")
    v = measures.evaluate(HOLD_CASH, c, P("2026-08"))            # an earlier period, same ctx
    assert v.amount == Decimal("1600") and v.cites == ("holdings.csv:7",)
    v = measures.evaluate(HOLD_CASH, ctx("2026-09-15"), P("2026-09"))   # as_of before the 09-30 snapshot
    assert v.amount == Decimal("1600")
    v = measures.evaluate(measure_of("M-09"), c, P("2026-09"))   # gold in GBP: no rate
    assert isinstance(v, Unknown) and v.cites == ("holdings.csv:15",)
    v = measures.evaluate(HOLD_BROKER, ctx("2026-06-30"), P("2026-06"))
    assert isinstance(v, Unknown) and "on or before 2026-06-30" in v.reason
    v = measures.evaluate(HOLD_CASH, ctx("2026-06-30"), P("2026-06"))   # the OMR row needs no rate
    assert v.amount == Decimal("1000")


def test_no_snapshot_is_unknown():
    u = measures.evaluate(HOLD_CASH, ctx("2026-05-31"), P("2026-05"))
    assert isinstance(u, Unknown) and "no holdings snapshot on or before 2026-05-31" == u.reason
    assert isinstance(measures.evaluate(SHARE_EQUITY, ctx("2026-05-31"), P("2026-05")), Unknown)
    assert isinstance(measures.evaluate(dd("broker", 90), ctx("2026-05-31"), P("2026-05")), Unknown)


def test_stale_snapshot_carries_age_and_value():
    s = measures.evaluate(HOLD_CASH, ctx("2026-11-30"), P("2026-11"))
    assert isinstance(s, Stale)
    assert s.age_days == 61 and s.date == D("2026-09-30")
    assert s.amount == Decimal("1900") and s.cites == ("holdings.csv:11",)
    v = measures.evaluate(HOLD_CASH, ctx("2026-11-14"), P("2026-11"))      # age 45 = allowed
    assert isinstance(v, Value) and v.amount == Decimal("1900")
    s = measures.evaluate(HOLD_CASH, ctx("2026-11-15"), P("2026-11"))      # age 46 = stale
    assert isinstance(s, Stale) and s.age_days == 46
    s = measures.evaluate(SHARE_EQUITY, ctx("2026-10-20"), P("2026-10"))  # 20 days: fine, but GBP
    assert isinstance(s, Unknown)
    s = measures.evaluate(dd("broker", 90), ctx("2026-11-30"), P("2026-11"))
    assert isinstance(s, Stale) and s.age_days == 61 and s.amount is None


def test_stale_without_declared_max_age_is_unknown():
    cfg, led, hol, table = household()
    cfg = cfg._replace(snapshot_max_age_days=None)
    u = measures.evaluate(HOLD_CASH, Context(cfg, led, hol, table, D("2026-09-30")), P("2026-09"))
    assert isinstance(u, Unknown) and "snapshot_max_age_days" in u.reason


def test_invalid_holdings_row_poisons_the_snapshot():
    bad = [{"file": "holdings.csv", "line": 7, "code": "BAD-VALUE", "class": "invalid", "reason": "x",
            "date": "2026-08-31"}]
    u = measures.evaluate(HOLD_CASH, ctx("2026-08-31", holdings_problems=bad), P("2026-08"))
    assert isinstance(u, Unknown) and u.cites == ("holdings.csv:7",)
    # a later valid snapshot is unaffected; an earlier one too
    assert measures.evaluate(HOLD_CASH, ctx("2026-09-30", holdings_problems=bad), P("2026-09")).amount == Decimal("1900")
    assert measures.evaluate(HOLD_CASH, ctx("2026-07-31", holdings_problems=bad), P("2026-07")).amount == Decimal("1300")
    # as_of between the bad snapshot and the next one: the bad one is the latest -> Unknown
    assert isinstance(measures.evaluate(HOLD_CASH, ctx("2026-09-15", holdings_problems=bad), P("2026-09")), Unknown)
    undated = [{"file": "holdings.csv", "line": 3, "code": "COLUMN-COUNT", "class": "invalid", "reason": "x"}]
    assert isinstance(measures.evaluate(HOLD_CASH, ctx(holdings_problems=undated), P("2026-09")), Unknown)
    assert isinstance(measures.evaluate(HOLD_CASH, ctx("2026-05-31", holdings_problems=undated), P("2026-05")), Unknown)


# ----------------------------------------------------------------------- share


def test_share_excludes_debt_from_the_total():
    v = measures.evaluate(SHARE_EQUITY, ctx("2026-08-31"), P("2026-08"))
    assert isinstance(v, Value)
    expected = Decimal("96") / Decimal("2003.2") * Decimal(100)      # equity / (cash + fund + equity)
    assert v.amount == expected and q4(v.amount) == Decimal("4.7923")
    assert set(v.cites) == {"holdings.csv:7", "holdings.csv:8", "holdings.csv:9", "rates.csv:3"}
    assert "holdings.csv:10" not in v.cites                           # the debt row is not in the total
    v = measures.evaluate({"kind": "share", "by": "class", "name": "cash"}, ctx("2026-08-31"), P("2026-08"))
    assert q4(v.amount) == q4(Decimal("1600") / Decimal("2003.2") * 100)
    v = measures.evaluate({"kind": "share", "by": "class", "name": "property"}, ctx("2026-08-31"), P("2026-08"))
    assert v.amount == Decimal("0")
    assert isinstance(measures.evaluate(SHARE_EQUITY, ctx(), P("2026-09")), Unknown)   # GBP row


def test_share_with_zero_total_is_unknown():
    cfg, led, hol, table = household()
    only_debt = tuple(r for r in hol if r.asset_class == "debt")
    u = measures.evaluate(SHARE_EQUITY, Context(cfg, led, only_debt, table, D("2026-09-30")), P("2026-09"))
    assert isinstance(u, Unknown) and "zero" in u.reason


# -------------------------------------------------------------------- drawdown


def test_drawdown_series_running_peak_and_window():
    v = measures.evaluate(dd("broker", 90), ctx(), P("2026-09"))      # window 2026-07-03..09-30
    assert isinstance(v, Value) and v.amount == Decimal("0")
    dates = [d for d, _, _ in v.detail]
    assert dates == [D("2026-07-31"), D("2026-08-31"), D("2026-09-30")]
    values = [x for _, x, _ in v.detail]
    assert values == [Decimal("422.4"), Decimal("403.2"), Decimal("482.5")]
    dds = [x for _, _, x in v.detail]
    assert dds[0] == Decimal("0") and dds[2] == Decimal("0")
    assert dds[1] == Decimal("19.2") / Decimal("422.4") * 100 and q4(dds[1]) == Decimal("4.5455")
    assert "rates.csv:3" in v.cites and "rates.csv:4" in v.cites and "holdings.csv:5" in v.cites
    v = measures.evaluate(dd("broker", 40), ctx("2026-08-31"), P("2026-08"))   # window 07-23..08-31
    assert q4(v.amount) == Decimal("4.5455") and len(v.detail) == 2
    v = measures.evaluate(dd("broker", 10), ctx(), P("2026-09"))      # only 09-30 in the window
    assert v.amount == Decimal("0") and len(v.detail) == 1


def test_drawdown_unknown_cases():
    u = measures.evaluate(dd("broker", 90), ctx("2026-08-31"), P("2026-08"))   # 06-30 USD has no rate
    assert isinstance(u, Unknown) and u.cites == ("holdings.csv:3",)
    u = measures.evaluate(dd("salary", 60), ctx(), P("2026-09"))               # no rows for the account
    assert isinstance(u, Unknown) and "not positive" in u.reason
    u = measures.evaluate(dd("broker", 20), ctx("2026-10-30"), P("2026-10"))   # latest is 30 days old
    assert isinstance(u, Unknown) and "within 20 days" in u.reason
    u = measures.evaluate(dd("cash", 60), ctx(), P("2026-09"))                 # gold GBP row in 'cash'
    assert isinstance(u, Unknown) and u.cites == ("holdings.csv:15",)
    bad = [{"file": "holdings.csv", "line": 5, "code": "BAD-VALUE", "class": "invalid", "reason": "x",
            "date": "2026-07-31"}]
    assert isinstance(measures.evaluate(dd("broker", 90), ctx(holdings_problems=bad), P("2026-09")), Unknown)
    assert measures.evaluate(dd("broker", 40), ctx(holdings_problems=bad), P("2026-09")).amount == Decimal("0")


def test_drawdown_counts_every_position_of_the_account():
    cfg, led, hol, table = household()
    no_gold = tuple(r for r in hol if r.asset_class != "gold")
    v = measures.evaluate(dd("cash", 60), Context(cfg, led, no_gold, table, D("2026-09-30")), P("2026-09"))
    assert v.amount == Decimal("20")                                   # loan 500 -> 400
    assert [x for _, x, _ in v.detail] == [Decimal("500"), Decimal("400")]
