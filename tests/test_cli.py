"""M1.1: the check command (ADR-0001 section 8) through qayd.cli.main,
called directly with StringIO streams; no subprocess."""

import io
import json
from pathlib import Path

from qayd import cli

FIX = Path(__file__).parent / "fixtures" / "rules"


def run(*args):
    out, err = io.StringIO(), io.StringIO()
    code = cli.main(list(args), out, err)
    return code, out.getvalue(), err.getvalue()


def check(name, *extra):
    return run("check", "--dir", str(FIX / name), "--as-of", "2026-09-30", *extra)


# ------------------------------------------------------------------- exit codes


def test_green_household_exits_0():
    code, out, err = check("green")
    assert code == 0 and err == ""
    assert out.splitlines()[-1].startswith("GREEN as of 2026-09-30: 3 of 3 policies hold")


def test_red_household_exits_1():
    code, out, err = check("household")
    assert code == 1 and err == ""
    assert out.splitlines()[-1].startswith("RED as of 2026-09-30: 6 of 12 policies hold, 6 red findings")


def test_unparseable_policies_exits_3():
    code, out, err = check("broken_policies")
    assert code == 3 and out == ""
    assert "policies.yml:4 BAD-YAML" in err


def test_missing_ledger_exits_3():
    code, out, err = check("missing_ledger")
    assert code == 3 and "ledger.csv FILE-MISSING" in err


def test_invalid_config_exits_3():
    code, out, err = check("bad_config")
    assert code == 3 and "MISSING-FIELD: base_currency is missing" in err


def test_invalid_rows_exit_1_and_are_listed():
    code, out, err = check("invalid_rows")
    assert code == 1
    assert "findings:" in out
    assert "red   BAD-AMOUNT       ledger.csv:14" in out
    assert "warn  DUP-ROW          ledger.csv:16" in out
    assert out.splitlines()[-1].endswith("6 red findings, 1 warning")


# ------------------------------------------------------------------------ usage


def test_no_command_is_usage():
    code, out, err = run()
    assert code == 2 and out == "" and err.startswith("usage:")


def test_help_is_fine():
    code, out, err = run("--help")
    assert code == 0 and out.startswith("usage:") and err == ""
    code, out, err = run("check", "-h")
    assert code == 0


def test_bad_options_are_usage_errors():
    assert run("check", "--bogus")[0] == 2
    assert run("bogus")[0] == 2
    assert run("check", "--as-of")[0] == 2
    assert run("check", "--as-of", "2026-13-01")[0] == 2
    assert run("check", "--as-of", "20260101")[0] == 2
    assert run("check", "--dir")[0] == 2
    assert run("check", "extra")[0] == 2
    code, out, err = run("check", "--as-of", "yesterday")
    assert code == 2 and "--as-of must be YYYY-MM-DD" in err and out == ""


def test_main_never_raises(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("boom")
    monkeypatch.setattr(cli, "load_household", boom)
    code, out, err = check("green")
    assert code == 3 and "internal error: RuntimeError: boom" in err


def test_default_streams_and_today(monkeypatch, capsys):
    import datetime as dt
    monkeypatch.setattr(cli, "parse_args", lambda argv: cli.Options("check", str(FIX / "green"), None, None, False, None, False))

    class Today(dt.date):
        @classmethod
        def today(cls):
            return dt.date(2026, 9, 30)
    monkeypatch.setattr(cli.datetime, "date", Today)
    code = cli.main([])
    captured = capsys.readouterr()
    assert code == 0 and "GREEN as of 2026-09-30" in captured.out


# ----------------------------------------------------------------- text format


def test_text_lines_are_verdict_id_title_measure_vs_limit_then_citations():
    code, out, err = check("household")
    lines = out.splitlines()
    assert lines[0] == ("breach   CAP-BREACH discretionary per month  15 OMR vs 10 OMR (1% of income) [2026-09]"
                        "  -- sum expense.discretionary per month = 15 OMR exceeds 10 OMR")
    assert lines[1] == "         ledger.csv:23 ledger.csv:19"
    verdict_lines = [l for l in lines if l and not l.startswith(" ") and l[0].islower()]
    assert [l.split()[0] for l in verdict_lines] == [
        "breach", "breach", "missing", "breach", "kill", "breach",
        "hold", "hold", "hold", "hold", "hold", "hold"]
    assert [l.split()[1] for l in verdict_lines] == [
        "CAP-BREACH", "FLOOR-BREACH", "ROUT-MISS", "RED-BREACH", "KILL-BREACH", "ALLOC-BREACH",
        "CAP-HOLD", "FLOOR-HOLD", "ROUT-HOLD", "RED-HOLD", "KILL-HOLD", "ALLOC-HOLD"]
    assert "kill     KILL-BREACH broker drawdown, tight  0% vs 5% [as of 2026-09-30]  -- drawdown 6% on 2026-08-31 crossed 5% (peak 500 OMR on 2026-07-31)" in lines
    assert "hold     RED-HOLD   no margin, no options  no row vs none (any tag of margin,options) [ever]" in lines
    assert "hold     ALLOC-HOLD cash share  77.55% vs 50%..100% [as of 2026-09-30]" in lines
    assert "missing  ROUT-MISS  quarterly dividend booked  no row vs 1 row required (category dividend) [2026-Q3]  -- no row matching category dividend in 2026-Q3" in lines


def test_text_silence_and_stale_lines():
    code, out, err = check("empty_period")
    assert "missing  CAP-M      food per month  - vs 100 OMR [2026-09]  -- no ledger rows in 2026-09" in out
    code, out, err = check("stale")
    assert ("stale    FLOOR-H    cash floor  stale 1300 OMR as of 2026-07-31 (61 days) vs 1000 OMR [as of 2026-09-30]"
            "  -- holdings snapshot 2026-07-31 is 61 days old; 45 allowed") in out


def test_kill_closed_shows_in_text():
    code, out, err = check("kill")
    assert code == 0
    assert "hold     K1         broker drawdown  0% vs 5% [as of 2026-09-30]  -- kill of 2026-08-31 closed by D-close (2026-09-05)" in out


# ----------------------------------------------------------------------- JSON


def test_json_shape_and_decimal_text():
    code, out, err = check("household", "--json")
    assert code == 1 and err == ""
    doc = json.loads(out)
    assert doc["version"] == 1 and doc["command"] == "check" and doc["as_of"] == "2026-09-30"
    assert doc["green"] is False and doc["base_currency"] == "OMR"
    assert set(doc) >= {"version", "as_of", "green", "policies", "findings"}
    assert [p["id"] for p in doc["policies"]][:2] == ["CAP-BREACH", "FLOOR-BREACH"]
    cap = doc["policies"][0]
    assert cap["verdict"] == "breach" and cap["period"] == "2026-09"
    assert cap["measure"] == {"status": "ok", "amount": "15", "cites": ["ledger.csv:23"], "text": "15 OMR"}
    assert cap["limit"]["amount"] == "10" and cap["limit"]["cites"] == ["ledger.csv:19"]
    assert isinstance(cap["measure"]["amount"], str)             # never a JSON number
    assert cap["declared"]["limit"] == "1% of income"
    assert cap["findings"] == ["BREACH"] and cap["cites"] == ["ledger.csv:23", "ledger.csv:19"]
    kill = [p for p in doc["policies"] if p["id"] == "KILL-BREACH"][0]
    assert kill["verdict"] == "kill" and kill["measure"]["amount"] == "0"
    red = [p for p in doc["policies"] if p["id"] == "RED-HOLD"][0]
    assert red["period"] is None and red["scope"] == "ever" and red["measure"]["amount"] == "0"
    alloc = [p for p in doc["policies"] if p["id"] == "ALLOC-HOLD"][0]
    assert alloc["measure"]["amount"].startswith("77.55102040816326530612244")
    assert alloc["declared"]["band"] == "50%..100%"
    findings = doc["findings"]
    assert len(findings) == 6
    assert findings[0] == {"code": "BREACH", "class": "red", "policy": "CAP-BREACH", "period": "2026-09",
                           "date": None, "cites": ["ledger.csv:23", "ledger.csv:19"],
                           "reason": "sum expense.discretionary per month = 15 OMR exceeds 10 OMR"}
    assert doc["files"] == {"policies.yml": 12, "ledger.csv": 22, "holdings.csv": 11,
                            "decisions.yml": 0, "rates.csv": None}
    assert doc["problems"] == []
    assert "." not in json.dumps(doc["policies"][0]["measure"]["amount"]).strip('"')


def test_json_green_and_problems():
    code, out, err = check("green", "--json")
    doc = json.loads(out)
    assert code == 0 and doc["green"] is True and doc["findings"] == []
    code, out, err = check("invalid_rows", "--json")
    doc = json.loads(out)
    assert code == 1
    codes = [(f["code"], f["class"]) for f in doc["findings"]]
    assert ("BAD-AMOUNT", "red") in codes and ("DUP-ROW", "warn") in codes
    assert [p["code"] for p in doc["problems"]] == ["BAD-AMOUNT", "DUP-ROW"]
    unknown = [p for p in doc["policies"] if p["id"] == "CAP-SEP"][0]
    assert unknown["verdict"] == "invalid" and unknown["measure"]["status"] == "invalid"
    stale_doc = json.loads(check("stale", "--json")[1])
    s = [p for p in stale_doc["policies"] if p["id"] == "FLOOR-H"][0]
    assert s["measure"] == {"status": "stale", "amount": "1300", "age_days": 61, "date": "2026-07-31",
                            "cites": ["holdings.csv:4"], "text": "stale 1300 OMR as of 2026-07-31 (61 days)"}
    empty_doc = json.loads(check("empty_period", "--json")[1])
    e = [p for p in empty_doc["policies"] if p["id"] == "CAP-M"][0]
    assert e["verdict"] == "missing" and e["measure"] is None and e["findings"] == ["EMPTY-PERIOD"]


# ------------------------------------------------------------ load_household


def test_load_household_reports_files_and_problems():
    import datetime
    h = cli.load_household(str(FIX / "household"), datetime.date(2026, 9, 30))
    assert h.fatal == () and h.files["rates.csv"] is None and h.files["ledger.csv"] == 22
    assert h.decisions == () and h.ctx.as_of == datetime.date(2026, 9, 30)
    h = cli.load_household(str(FIX / "kill"), datetime.date(2026, 9, 30))
    assert [d.id for d in h.decisions] == ["D-close"] and h.ctx.decisions == h.decisions
    h = cli.load_household(str(FIX / "nowhere"), datetime.date(2026, 9, 30))
    assert h.config is None and [p["code"] for p in h.fatal] == ["FILE-MISSING"]


# ========================================================================= M1.2
# routine and decisions commands; DECISION-DUE in check.


def routine(name, *extra):
    return run("routine", "--dir", str(FIX / name), *extra)


def decisions(name, *extra):
    return run("decisions", "--dir", str(FIX / name), *extra)


def test_routine_month_done_and_missing():
    code, out, err = routine("household", "--period", "2026-09", "--as-of", "2026-09-30")
    assert code == 1 and err == ""
    lines = out.splitlines()
    assert lines[0] == "done     ROUT-HOLD  monthly transfer to savings [2026-09]"
    assert lines[1] == "         ledger.csv:21"
    assert lines[2].startswith("missing  ROUT-MISS  quarterly dividend booked [2026-Q3]  -- no row matching category dividend")
    assert lines[-1] == "MISSING routine 2026-09 as of 2026-09-30: 1 of 2 done"


def test_routine_exit_0_only_when_all_done():
    code, out, err = routine("green", "--period", "2026-09", "--as-of", "2026-09-30")
    assert code == 0 and out.splitlines()[-1] == "ALL DONE routine 2026-09 as of 2026-09-30: 1 of 1 done"
    code, out, err = routine("green", "--period", "2026-09", "--as-of", "2026-09-02")   # before the transfer
    assert code == 1 and out.splitlines()[0].startswith("missing  ROUT-HOLD")


def test_routine_quarter_lists_each_month_of_a_monthly_routine():
    code, out, err = routine("household", "--period", "2026-Q3", "--as-of", "2026-09-30")
    labels = [l.split("[")[1].split("]")[0] for l in out.splitlines() if l.startswith("done") or l.startswith("missing")]
    assert labels == ["2026-07", "2026-08", "2026-09", "2026-Q3"]
    assert out.splitlines()[-1] == "MISSING routine 2026-Q3 as of 2026-09-30: 3 of 4 done"


def test_routine_month_for_a_quarterly_routine_uses_its_quarter():
    code, out, err = routine("household", "--period", "2026-08", "--as-of", "2026-09-30")
    assert "missing  ROUT-MISS  quarterly dividend booked [2026-Q3]" in out
    assert "done     ROUT-HOLD  monthly transfer to savings [2026-08]" in out


def test_routine_empty_period_and_future_period():
    code, out, err = routine("empty_period", "--period", "2026-09", "--as-of", "2026-09-30")
    assert code == 1 and "missing  ROUT-M     monthly transfer to savings [2026-09]  -- no ledger rows in 2026-09" in out
    code, out, err = routine("household", "--period", "2026-12", "--as-of", "2026-09-30")
    assert code == 1 and "[2026-12]  -- period 2026-12 starts after 2026-09-30" in out


def test_routine_default_period_is_the_month_of_as_of():
    code, out, err = routine("green", "--as-of", "2026-08-31")
    assert code == 0 and "[2026-08]" in out and out.splitlines()[-1].startswith("ALL DONE routine 2026-08")


def test_routine_usage_and_file_errors():
    assert routine("household", "--period", "2026-13")[0] == 2
    assert routine("household", "--period", "Q3")[0] == 2
    code, out, err = routine("broken_policies", "--period", "2026-09")
    assert code == 3 and out == ""


def test_routine_json():
    code, out, err = routine("household", "--period", "2026-Q3", "--as-of", "2026-09-30", "--json")
    doc = json.loads(out)
    assert doc["version"] == 1 and doc["command"] == "routine"
    assert doc["period"] == "2026-Q3" and doc["as_of"] == "2026-09-30" and doc["all_done"] is False
    assert [(r["id"], r["period"], r["status"]) for r in doc["routines"]] == [
        ("ROUT-HOLD", "2026-07", "done"), ("ROUT-HOLD", "2026-08", "done"),
        ("ROUT-HOLD", "2026-09", "done"), ("ROUT-MISS", "2026-Q3", "missing")]
    assert doc["routines"][0]["cites"] == ["ledger.csv:13"]
    assert doc["routines"][3]["match"] == "category dividend" and doc["routines"][3]["cites"] == []
    assert doc["findings"] == [] and doc["files"]["ledger.csv"] == 22
    code, out, err = routine("green", "--period", "2026-09", "--as-of", "2026-09-30", "--json")
    assert json.loads(out)["all_done"] is True and code == 0


def test_decisions_text_due_open_closed():
    code, out, err = decisions("decisions", "--as-of", "2026-09-30")
    assert code == 1 and err == ""
    lines = out.splitlines()
    assert lines[0] == "due      D-due          review the food cap  review by 2026-09-15 (15 days overdue)  policy CAP-HOLD"
    assert lines[1] == "         decisions.yml:1"
    assert lines[2] == "open     D-open         keep the broker pilot  review by 2027-01-01 (93 days left)  policy K1"
    assert lines[4] == "open     D-today        review on the as-of day itself  review by 2026-09-30 (0 days left)"
    assert "closed   D-close        end the broker pilot after the August drawdown  decided 2026-09-05  closes K1" in lines
    assert "closed   D-done         an old closed decision without a policy  decided 2026-05-01" in lines
    assert "  red   BAD-CLOSES       decisions.yml:28  closes 'CAP-HOLD' names a policy that is not of type kill" in lines
    assert lines[-1] == "DUE decisions as of 2026-09-30: 3 open, 1 due, 2 closed"


def test_decisions_due_is_strictly_before_as_of():
    code, out, err = decisions("decisions", "--as-of", "2026-09-30")
    assert "open     D-today" in out
    code, out, err = decisions("decisions", "--as-of", "2026-10-01")
    assert code == 1 and "due      D-today        review on the as-of day itself  review by 2026-09-30 (1 day overdue)" in out
    assert out.splitlines()[-1] == "DUE decisions as of 2026-10-01: 3 open, 2 due, 2 closed"
    code, out, err = decisions("decisions", "--as-of", "2026-09-15")
    assert code == 0 and out.splitlines()[-1] == "NONE DUE decisions as of 2026-09-15: 3 open, 0 due, 2 closed"


def test_decisions_exit_codes():
    assert decisions("green", "--as-of", "2026-09-30")[0] == 0
    code, out, err = decisions("green", "--as-of", "2026-09-30")
    assert out == "NONE DUE decisions as of 2026-09-30: 0 open, 0 due, 0 closed\n"
    assert decisions("broken_policies")[0] == 3
    assert decisions("missing_ledger")[0] == 3


def test_decisions_json():
    code, out, err = decisions("decisions", "--as-of", "2026-09-30", "--json")
    doc = json.loads(out)
    assert doc["version"] == 1 and doc["command"] == "decisions" and doc["due"] is True
    by_id = {d["id"]: d for d in doc["decisions"]}
    assert by_id["D-due"]["days_until_review"] == -15 and by_id["D-due"]["due"] is True
    assert by_id["D-open"]["days_until_review"] == 93 and by_id["D-open"]["due"] is False
    assert by_id["D-today"]["days_until_review"] == 0 and by_id["D-today"]["due"] is False
    assert by_id["D-close"]["closes"] == "K1" and by_id["D-close"]["days_until_review"] is None
    assert by_id["D-close"]["cite"] == "decisions.yml:20"
    assert "D-bad-closes" not in by_id
    assert [(f["code"], f["policy"], f["date"]) for f in doc["findings"]] == [
        ("DECISION-DUE", "CAP-HOLD", "2026-09-15"), ("BAD-CLOSES", None, None)]


def test_check_includes_decision_due_in_findings_and_green():
    code, out, err = check("decisions")
    assert code == 1
    assert "  red   DECISION-DUE     decisions.yml:1  decision D-due is open and its review date 2026-09-15 is 15 days past" in out
    assert out.splitlines()[-1] == "RED as of 2026-09-30: 2 of 2 policies hold, 2 red findings, 0 warnings"
    doc = json.loads(check("decisions", "--json")[1])
    assert doc["green"] is False
    assert [f["code"] for f in doc["findings"]] == ["DECISION-DUE", "BAD-CLOSES"]
    code, out, err = run("check", "--dir", str(FIX / "decisions"), "--as-of", "2026-09-15", "--json")
    doc = json.loads(out)
    assert [f["code"] for f in doc["findings"]] == ["BAD-CLOSES"] and doc["green"] is False
