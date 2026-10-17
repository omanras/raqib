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


def test_commands_not_yet_available_are_usage_errors():
    for command in ("routine", "decisions", "review", "init"):
        code, out, err = run(command, "--dir", str(FIX / "green"))
        assert code == 2 and "not available yet" in err, command


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
