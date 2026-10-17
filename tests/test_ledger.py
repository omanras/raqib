"""M0.1: ledger and holdings loaders (ADR-0001 sections 3-4).

One test per fixture in tests/fixtures/{ledger,holdings}; the size limits
are exercised on files generated in tmp_path (a 1 MiB line and a 64 MiB
file do not belong in the repository).
"""

import datetime
import os
from decimal import Decimal
from pathlib import Path

from qayd import ledger

FIX = Path(__file__).parent / "fixtures"
LED = FIX / "ledger"
HOL = FIX / "holdings"

ACCOUNTS = ["salary", "savings", "broker", "cash"]
CATEGORIES = {
    "income": ["salary", "bonus", "side"],
    "expense": ["housing", "food", "transport", "family", "discretionary", "fees"],
    "transfer": ["transfer"],
    "invest": ["buy", "sell", "dividend"],
}
CLASSES = ["cash", "equity", "fund", "property", "gold", "debt", "other"]


def D(text):
    return datetime.date.fromisoformat(text)


def load(name):
    return ledger.load_ledger(LED / name, ACCOUNTS, CATEGORIES)


def load_h(name):
    return ledger.load_holdings(HOL / name, ACCOUNTS, CLASSES)


def codes(problems):
    return [(p["line"], p["code"]) for p in problems]


# ---------------------------------------------------------------- ledger: valid


def test_valid_ledger_rows_and_types():
    rows, problems = load("valid.csv")
    assert problems == []
    assert len(rows) == 7
    r = rows[0]
    assert r.date == D("2026-01-05")
    assert isinstance(r.amount, Decimal) and r.amount == Decimal("1200.000")
    assert r.currency == "OMR" and r.account == "salary" and r.category == "salary"
    assert r.tags == () and r.note == "January salary"
    assert r.line == 2 and r.file == "valid.csv" and r.cite == "valid.csv:2"
    for row in rows:
        assert isinstance(row.amount, Decimal)
        assert isinstance(row.date, datetime.date)
        assert isinstance(row.tags, tuple)


def test_valid_ledger_quoting_tags_and_order():
    rows, _ = load("valid.csv")
    assert rows[3].tags == ("grocery", "weekly")
    assert rows[3].note == "milk, bread"            # quoted comma
    assert rows[3].amount == Decimal("-12.345")     # exact, three places
    assert rows[4].note == 'he said "ok"'           # doubled quote
    assert rows[4].currency == "USD"
    assert rows[5].amount == Decimal("0")
    assert rows[6].date == D("2025-12-31")          # file order kept, not sorted
    assert [r.line for r in rows] == [2, 3, 4, 5, 6, 7, 8]


def test_valid_ledger_accepts_flat_category_iterable():
    flat = [c for group in CATEGORIES.values() for c in group]
    rows, problems = ledger.load_ledger(LED / "valid.csv", set(ACCOUNTS), flat)
    assert problems == [] and len(rows) == 7


def test_bom_and_crlf_tolerated_with_utf8_note():
    rows, problems = load("valid_bom_crlf.csv")
    plain, _ = load("valid.csv")
    assert problems == []
    assert len(rows) == 7
    assert rows[0].date == D("2026-01-05")          # BOM did not poison the header
    assert rows[3].note == "caf\u00e9, bread"
    assert rows[0].note == "January salary"         # no trailing \r
    for a, b in zip(rows, plain):
        assert a._replace(note="", file="") == b._replace(note="", file="")


def test_header_only_is_zero_rows_no_loader_problem():
    rows, problems = load("header_only.csv")
    assert rows == () and problems == []


# ------------------------------------------------------------- ledger: file level


def test_empty_file_is_a_problem():
    rows, problems = load("empty.csv")
    assert rows == ()
    assert codes(problems) == [(0, "FILE-EMPTY")]
    assert problems[0]["class"] == "invalid" and problems[0]["file"] == "empty.csv"


def test_missing_file_never_raises():
    rows, problems = load("does_not_exist.csv")
    assert rows == ()
    assert codes(problems) == [(0, "FILE-MISSING")]
    assert "does_not_exist.csv" in problems[0]["reason"]


def test_directory_and_none_never_raise():
    rows, problems = ledger.load_ledger(LED, ACCOUNTS, CATEGORIES)
    assert rows == () and codes(problems) == [(0, "FILE-UNREADABLE")]
    rows, problems = ledger.load_ledger(None, ACCOUNTS, CATEGORIES)
    assert rows == () and len(problems) == 1 and problems[0]["line"] == 0


def test_bad_header_stops_with_one_problem():
    rows, problems = load("bad_header.csv")
    assert rows == ()
    assert codes(problems) == [(1, "BAD-HEADER")]
    assert ledger.LEDGER_HEADER in problems[0]["reason"]


def test_header_must_match_exactly_even_a_space():
    rows, problems = load("bad_header_space.csv")
    assert rows == () and codes(problems) == [(1, "BAD-HEADER")]


# -------------------------------------------------------------- ledger: row level


def test_bad_date_names_each_line_and_continues():
    rows, problems = load("bad_date.csv")
    assert codes(problems) == [(3, "BAD-DATE"), (4, "BAD-DATE"), (5, "BAD-DATE"),
                               (6, "BAD-DATE"), (7, "BAD-DATE")]
    assert [r.line for r in rows] == [2, 8]
    assert all(p["class"] == "invalid" for p in problems)
    assert "2026-13-01" in problems[0]["reason"]
    assert all("date" not in p for p in problems)


def test_bad_amount_rejects_everything_but_plain_decimal_text():
    rows, problems = load("bad_amount.csv")
    assert [p["line"] for p in problems] == list(range(2, 11))
    assert {p["code"] for p in problems} == {"BAD-AMOUNT"}
    assert [r.line for r in rows] == [11]
    assert rows[0].amount == Decimal("-7.25")
    assert all(p["date"] == "2026-01-05" for p in problems)


def test_bad_currency():
    rows, problems = load("bad_currency.csv")
    assert codes(problems) == [(2, "BAD-CURRENCY"), (3, "BAD-CURRENCY"),
                               (4, "BAD-CURRENCY"), (5, "BAD-CURRENCY")]
    assert [r.line for r in rows] == [6]


def test_unknown_account_is_exact_match():
    rows, problems = load("unknown_account.csv")
    assert codes(problems) == [(3, "UNKNOWN-ACCOUNT"), (4, "UNKNOWN-ACCOUNT"), (5, "UNKNOWN-ACCOUNT")]
    assert "wallet" in problems[0]["reason"]
    assert "Salary" in problems[1]["reason"]
    assert [r.line for r in rows] == [2]


def test_unknown_category_and_group_name_is_not_a_category():
    rows, problems = load("unknown_category.csv")
    assert codes(problems) == [(3, "UNKNOWN-CATEGORY"), (4, "UNKNOWN-CATEGORY")]
    assert "expense" in problems[1]["reason"]
    assert [r.line for r in rows] == [2]


def test_column_count():
    rows, problems = load("column_count.csv")
    assert codes(problems) == [(3, "COLUMN-COUNT"), (4, "COLUMN-COUNT"), (5, "COLUMN-COUNT")]
    assert "expected 7 columns, got 6" in problems[0]["reason"]
    assert "got 8" in problems[1]["reason"]
    assert "got 1" in problems[2]["reason"]
    assert [r.line for r in rows] == [2, 6]


def test_bad_tags():
    rows, problems = load("bad_tags.csv")
    assert codes(problems) == [(2, "BAD-TAGS"), (3, "BAD-TAGS"), (4, "BAD-TAGS"), (5, "BAD-TAGS")]
    assert [r.line for r in rows] == [6]
    assert rows[0].tags == ("a", "b", "a")


def test_empty_line_is_a_problem_but_final_newline_is_not():
    rows, problems = load("empty_line.csv")
    assert codes(problems) == [(3, "EMPTY-LINE"), (5, "EMPTY-LINE")]
    assert [r.line for r in rows] == [2, 4]


def test_bad_csv_quoting():
    rows, problems = load("bad_csv.csv")
    assert codes(problems) == [(2, "BAD-CSV"), (3, "BAD-CSV")]
    assert [r.line for r in rows] == [4]


def test_bad_encoding_names_the_line_and_continues():
    rows, problems = load("bad_encoding.csv")
    assert codes(problems) == [(3, "BAD-ENCODING")]
    assert "UTF-8" in problems[0]["reason"]
    assert [r.line for r in rows] == [2, 4]


def test_multi_problem_row_reports_every_problem_once_per_field():
    rows, problems = load("multi_problem.csv")
    assert rows == ()
    line2 = [p["code"] for p in problems if p["line"] == 2]
    assert line2 == ["BAD-DATE", "BAD-AMOUNT", "BAD-CURRENCY", "UNKNOWN-ACCOUNT",
                     "UNKNOWN-CATEGORY", "BAD-TAGS"]
    line3 = [p for p in problems if p["line"] == 3]
    assert [p["code"] for p in line3] == ["BAD-AMOUNT", "UNKNOWN-ACCOUNT"]
    assert all(p["date"] == "2026-01-05" for p in line3)   # period hint survives
    assert all("date" not in p for p in problems if p["line"] == 2)


def test_dup_row_is_a_warning_and_no_row_is_dropped():
    rows, problems = load("dup_row.csv")
    assert len(rows) == 4
    assert [r.line for r in rows] == [2, 3, 4, 5]
    assert codes(problems) == [(3, "DUP-ROW"), (5, "DUP-ROW")]
    for p in problems:
        assert p["class"] == "warn"
        assert p["dup_of"] == 2
        assert "line 2" in p["reason"]
    # a near-duplicate (different note) is not flagged
    assert rows[2].note == "coffee again"


# ------------------------------------------------------------------- size limits


def _ledger_with_note(path, note_bytes):
    head = b"date,amount,currency,account,category,tags,note\n"
    good = b"2026-01-05,1,OMR,salary,salary,,ok\n"
    good2 = b"2026-01-07,-2,OMR,cash,food,,ok too\n"
    with open(path, "wb") as fh:
        fh.write(head + good + b"2026-01-06,-1,OMR,cash,food,," + note_bytes + b"\n" + good2)


def test_line_of_one_mib_is_a_problem(tmp_path):
    p = tmp_path / "long.csv"
    prefix = b"2026-01-06,-1,OMR,cash,food,,"
    _ledger_with_note(p, b"x" * (ledger.MAX_LINE_BYTES - len(prefix)))
    rows, problems = ledger.load_ledger(p, ACCOUNTS, CATEGORIES)
    assert codes(problems) == [(3, "LINE-TOO-LONG")]
    assert [r.line for r in rows] == [2, 4]


def test_line_just_under_one_mib_is_fine(tmp_path):
    p = tmp_path / "almost.csv"
    prefix = b"2026-01-06,-1,OMR,cash,food,,"
    _ledger_with_note(p, b"x" * (ledger.MAX_LINE_BYTES - len(prefix) - 1))
    rows, problems = ledger.load_ledger(p, ACCOUNTS, CATEGORIES)
    assert problems == [] and len(rows) == 3


def test_file_of_64_mib_is_a_problem_without_reading_it(tmp_path):
    p = tmp_path / "huge.csv"
    with open(p, "wb") as fh:
        fh.write(b"date,amount,currency,account,category,tags,note\n")
        fh.truncate(ledger.MAX_FILE_BYTES)   # sparse: the size is what counts
    assert os.stat(p).st_size == ledger.MAX_FILE_BYTES
    rows, problems = ledger.load_ledger(p, ACCOUNTS, CATEGORIES)
    assert rows == () and codes(problems) == [(0, "FILE-TOO-LARGE")]


# ---------------------------------------------------------------------- holdings


def test_valid_holdings():
    rows, problems = load_h("valid.csv")
    assert problems == []
    assert len(rows) == 6
    r = rows[1]
    assert r.date == D("2026-01-31") and r.account == "broker" and r.asset == "VWRA"
    assert r.asset_class == "fund"
    assert isinstance(r.quantity, Decimal) and r.quantity == Decimal("10.5")
    assert isinstance(r.value, Decimal) and r.value == Decimal("1234.56")
    assert r.currency == "USD" and r.line == 3 and r.file == "valid.csv"
    assert rows[4].value == Decimal("-200.00") and rows[4].asset_class == "debt"


def test_latest_snapshot():
    rows, _ = load_h("valid.csv")
    assert ledger.snapshot_dates(rows) == (D("2025-12-31"), D("2026-01-31"), D("2026-02-28"))
    snap = ledger.latest_snapshot(rows, D("2026-02-10"))
    assert snap.date == D("2026-01-31")
    assert [r.line for r in snap.rows] == [2, 3]
    snap_rows, snap_date = ledger.latest_snapshot(rows, D("2026-02-28"))   # on the date itself
    assert snap_date == D("2026-02-28") and [r.line for r in snap_rows] == [4, 5, 6]
    assert ledger.latest_snapshot(rows, D("2030-01-01")).date == D("2026-02-28")
    assert ledger.latest_snapshot(rows, D("2025-12-31")).date == D("2025-12-31")
    before = ledger.latest_snapshot(rows, D("2025-01-01"))
    assert before.rows == () and before.date is None
    assert ledger.latest_snapshot((), D("2026-01-01")) == ledger.Snapshot((), None)


def test_holdings_bad_header():
    rows, problems = load_h("bad_header.csv")
    assert rows == () and codes(problems) == [(1, "BAD-HEADER")]


def test_holdings_bad_date():
    rows, problems = load_h("bad_date.csv")
    assert codes(problems) == [(2, "BAD-DATE")] and [r.line for r in rows] == [3]


def test_holdings_unknown_account():
    rows, problems = load_h("unknown_account.csv")
    assert codes(problems) == [(2, "UNKNOWN-ACCOUNT")] and [r.line for r in rows] == [3]


def test_holdings_unknown_class_is_exact_match():
    rows, problems = load_h("unknown_class.csv")
    assert codes(problems) == [(2, "UNKNOWN-CLASS"), (3, "UNKNOWN-CLASS")]
    assert [r.line for r in rows] == [4]


def test_holdings_bad_asset():
    rows, problems = load_h("bad_asset.csv")
    assert codes(problems) == [(2, "BAD-ASSET")] and [r.line for r in rows] == [3]


def test_holdings_bad_quantity():
    rows, problems = load_h("bad_quantity.csv")
    assert codes(problems) == [(2, "BAD-QUANTITY"), (3, "BAD-QUANTITY")]
    assert [r.line for r in rows] == [4]


def test_holdings_bad_value():
    rows, problems = load_h("bad_value.csv")
    assert codes(problems) == [(2, "BAD-VALUE"), (3, "BAD-VALUE")]
    assert [r.line for r in rows] == [4]


def test_holdings_bad_currency():
    rows, problems = load_h("bad_currency.csv")
    assert codes(problems) == [(2, "BAD-CURRENCY")] and [r.line for r in rows] == [3]


def test_holdings_column_count():
    rows, problems = load_h("column_count.csv")
    assert codes(problems) == [(2, "COLUMN-COUNT"), (3, "COLUMN-COUNT")]
    assert [r.line for r in rows] == [4]


def test_holdings_dup_row():
    rows, problems = load_h("dup_row.csv")
    assert len(rows) == 3
    assert codes(problems) == [(3, "DUP-ROW")]
    assert problems[0]["class"] == "warn" and problems[0]["dup_of"] == 2


def test_holdings_missing_file_never_raises():
    rows, problems = load_h("nope.csv")
    assert rows == () and codes(problems) == [(0, "FILE-MISSING")]
