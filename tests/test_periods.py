"""M0.2: period math, tested at year and quarter boundaries and on leap days."""

import datetime

import pytest

from qayd import periods
from qayd.periods import Period


def D(text):
    return datetime.date.fromisoformat(text)


def P(a, b):
    return Period(D(a), D(b))


# ------------------------------------------------------------------- period_of


def test_period_of_month_boundaries_and_leap_day():
    assert periods.period_of(D("2026-10-17"), "month") == P("2026-10-01", "2026-10-31")
    assert periods.period_of(D("2026-02-01"), "month") == P("2026-02-01", "2026-02-28")
    assert periods.period_of(D("2024-02-29"), "month") == P("2024-02-01", "2024-02-29")
    assert periods.period_of(D("2100-02-10"), "month") == P("2100-02-01", "2100-02-28")  # not a leap year
    assert periods.period_of(D("2000-02-10"), "month") == P("2000-02-01", "2000-02-29")  # a leap year
    assert periods.period_of(D("2025-12-31"), "month") == P("2025-12-01", "2025-12-31")
    assert periods.period_of(D("2026-01-01"), "month") == P("2026-01-01", "2026-01-31")


def test_period_of_quarter():
    assert periods.period_of(D("2026-01-01"), "quarter") == P("2026-01-01", "2026-03-31")
    assert periods.period_of(D("2026-03-31"), "quarter") == P("2026-01-01", "2026-03-31")
    assert periods.period_of(D("2026-04-01"), "quarter") == P("2026-04-01", "2026-06-30")
    assert periods.period_of(D("2026-08-15"), "quarter") == P("2026-07-01", "2026-09-30")
    assert periods.period_of(D("2025-12-31"), "quarter") == P("2025-10-01", "2025-12-31")
    assert periods.period_of(D("2024-02-29"), "quarter") == P("2024-01-01", "2024-03-31")


def test_period_of_year():
    assert periods.period_of(D("2026-07-04"), "year") == P("2026-01-01", "2026-12-31")
    assert periods.period_of(D("2025-12-31"), "year") == P("2025-01-01", "2025-12-31")
    assert periods.period_of(D("2026-01-01"), "year") == P("2026-01-01", "2026-12-31")


def test_period_of_unknown_kind_raises():
    with pytest.raises(ValueError):
        periods.period_of(D("2026-01-01"), "week")


# ------------------------------------------------------------ kind and label


def test_kind_and_label_are_derived_from_bounds():
    assert P("2026-10-01", "2026-10-31").kind == "month"
    assert P("2026-10-01", "2026-10-31").label == "2026-10"
    assert P("2026-07-01", "2026-09-30").kind == "quarter"
    assert P("2026-07-01", "2026-09-30").label == "2026-Q3"
    assert P("2026-01-01", "2026-12-31").kind == "year"
    assert P("2026-01-01", "2026-12-31").label == "2026"
    assert P("2026-02-01", "2026-04-30").kind == "window"       # three months, not a quarter
    assert P("2025-10-01", "2026-09-30").kind == "window"       # twelve months, not a year
    assert P("2025-10-01", "2026-09-30").label == "2025-10-01..2026-09-30"
    assert P("2026-10-01", "2026-10-17").kind == "window"
    assert P("2026-10-02", "2026-10-31").kind == "window"
    assert P("2024-02-01", "2024-02-29").kind == "month"
    assert P("2024-02-01", "2024-02-28").kind == "window"       # leap year: 28 is not the end


def test_days_contains_and_months():
    q = P("2026-07-01", "2026-09-30")
    assert q.days == 92
    assert q.contains(D("2026-07-01")) and q.contains(D("2026-09-30"))
    assert not q.contains(D("2026-10-01")) and not q.contains(D("2026-06-30"))
    assert [m.label for m in q.months()] == ["2026-07", "2026-08", "2026-09"]
    assert P("2024-02-01", "2024-02-29").days == 29
    w = P("2025-11-15", "2026-02-10")
    assert [m.label for m in w.months()] == ["2025-11", "2025-12", "2026-01", "2026-02"]


# ----------------------------------------------------------------------- parse


def test_parse_valid():
    assert periods.parse("2026-10") == P("2026-10-01", "2026-10-31")
    assert periods.parse("2026-02") == P("2026-02-01", "2026-02-28")
    assert periods.parse("2024-02") == P("2024-02-01", "2024-02-29")
    assert periods.parse("2026-Q3") == P("2026-07-01", "2026-09-30")
    assert periods.parse("2026-Q1") == P("2026-01-01", "2026-03-31")
    assert periods.parse("2026-Q4") == P("2026-10-01", "2026-12-31")
    assert periods.parse("2026") == P("2026-01-01", "2026-12-31")


@pytest.mark.parametrize("text", [
    "2026-13", "2026-00", "2026-1", "2026-Q5", "2026-Q0", "2026-q3", "26",
    "2026-10-01", " 2026-10", "2026-10 ", "", "Q3-2026", "2026/10", None, 2026,
])
def test_parse_invalid_is_none(text):
    assert periods.parse(text) is None


# -------------------------------------------------------------------- trailing


def test_trailing_window():
    assert periods.trailing(D("2026-09-30"), 12) == P("2025-10-01", "2026-09-30")
    assert periods.trailing(D("2026-09-15"), 12) == P("2025-10-01", "2026-09-15")
    assert periods.trailing(D("2026-01-31"), 1) == P("2026-01-01", "2026-01-31")
    assert periods.trailing(D("2026-01-15"), 12) == P("2025-02-01", "2026-01-15")
    assert periods.trailing(D("2026-01-15"), 2) == P("2025-12-01", "2026-01-15")   # year boundary
    assert periods.trailing(D("2024-02-29"), 12) == P("2023-03-01", "2024-02-29")  # leap day
    assert periods.trailing(D("2025-02-28"), 12) == P("2024-03-01", "2025-02-28")
    assert periods.trailing(D("2026-03-31"), 24) == P("2024-04-01", "2026-03-31")
    assert periods.trailing(D("2026-09-30"), 12).kind == "window"


@pytest.mark.parametrize("months", [0, -1, True, "12", None])
def test_trailing_rejects_bad_months(months):
    with pytest.raises(ValueError):
        periods.trailing(D("2026-09-30"), months)


# ------------------------------------------------------------- periods_between


def test_periods_between_months_across_year_and_leap():
    got = periods.periods_between(D("2025-11-15"), D("2026-02-01"), "month")
    assert [p.label for p in got] == ["2025-11", "2025-12", "2026-01", "2026-02"]
    got = periods.periods_between(D("2024-01-31"), D("2024-03-01"), "month")
    assert [p.label for p in got] == ["2024-01", "2024-02", "2024-03"]
    assert got[1] == P("2024-02-01", "2024-02-29")
    got = periods.periods_between(D("2024-10-01"), D("2026-09-30"), "month")
    assert len(got) == 24 and got[0].label == "2024-10" and got[-1].label == "2026-09"


def test_periods_between_quarters_and_years():
    got = periods.periods_between(D("2025-12-31"), D("2026-07-01"), "quarter")
    assert [p.label for p in got] == ["2025-Q4", "2026-Q1", "2026-Q2", "2026-Q3"]
    got = periods.periods_between(D("2024-06-01"), D("2026-01-01"), "year")
    assert [p.label for p in got] == ["2024", "2025", "2026"]


def test_periods_between_same_period_and_reversed():
    got = periods.periods_between(D("2026-10-01"), D("2026-10-31"), "month")
    assert [p.label for p in got] == ["2026-10"]
    got = periods.periods_between(D("2026-10-17"), D("2026-10-17"), "quarter")
    assert [p.label for p in got] == ["2026-Q4"]
    assert periods.periods_between(D("2026-10-17"), D("2026-10-16"), "month") == ()


# ------------------------------------------------------------- next / previous


def test_next_and_previous_period():
    assert periods.next_period(P("2025-12-01", "2025-12-31")) == P("2026-01-01", "2026-01-31")
    assert periods.previous_period(P("2026-01-01", "2026-01-31")) == P("2025-12-01", "2025-12-31")
    assert periods.next_period(P("2025-10-01", "2025-12-31")) == P("2026-01-01", "2026-03-31")
    assert periods.previous_period(P("2026-01-01", "2026-12-31")) == P("2025-01-01", "2025-12-31")
    assert periods.next_period(P("2024-01-01", "2024-01-31")) == P("2024-02-01", "2024-02-29")
    with pytest.raises(ValueError):
        periods.next_period(P("2026-01-02", "2026-01-31"))


# -------------------------------------------------------------------- helpers


def test_add_months_clamps_the_day():
    assert periods.add_months(D("2026-01-31"), 1) == D("2026-02-28")
    assert periods.add_months(D("2024-01-31"), 1) == D("2024-02-29")
    assert periods.add_months(D("2026-03-31"), -1) == D("2026-02-28")
    assert periods.add_months(D("2026-12-15"), 1) == D("2027-01-15")
    assert periods.add_months(D("2026-01-15"), -1) == D("2025-12-15")
    assert periods.add_months(D("2026-01-15"), -13) == D("2024-12-15")
    assert periods.add_months(D("2026-01-15"), 0) == D("2026-01-15")


def test_last_day():
    assert periods.last_day(2026, 12) == D("2026-12-31")
    assert periods.last_day(2024, 2) == D("2024-02-29")
    assert periods.last_day(2026, 2) == D("2026-02-28")
    assert periods.last_day(2026, 4) == D("2026-04-30")
