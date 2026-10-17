"""M1.3: the example household. The generator is rerun into a temp
directory and compared byte for byte with examples/; then the planned
verdict set is asserted through qayd.cli.main; then init."""

import io
import json
import os
import runpy
import sys
from pathlib import Path

import pytest

from qayd import cli

ROOT = Path(__file__).parent.parent
EXAMPLES = ROOT / "examples"
SCRIPT = ROOT / "tools" / "make_example.py"
FILES = ("policies.yml", "ledger.csv", "holdings.csv", "decisions.yml", "rates.csv", "README.md")


def run(*args):
    out, err = io.StringIO(), io.StringIO()
    code = cli.main(list(args), out, err)
    return code, out.getvalue(), err.getvalue()


def check(as_of, *extra):
    return run("check", "--dir", str(EXAMPLES), "--as-of", as_of, *extra)


def verdicts(as_of):
    code, out, err = check(as_of, "--json")
    assert err == ""
    doc = json.loads(out)
    return code, dict((p["id"], p) for p in doc["policies"]), doc


# ------------------------------------------------------------- reproducible


def test_generator_reproduces_examples_byte_for_byte(tmp_path, capsys):
    out_dir = tmp_path / "regen"
    saved = sys.argv
    try:
        sys.argv = [str(SCRIPT), "--out", str(out_dir)]
        with pytest.raises(SystemExit) as info:
            runpy.run_path(str(SCRIPT), run_name="__main__")
        assert info.value.code == 0
    finally:
        sys.argv = saved
    assert sorted(os.listdir(out_dir)) == sorted(FILES)
    assert sorted(os.listdir(EXAMPLES)) == sorted(FILES)
    for name in FILES:
        assert (out_dir / name).read_bytes() == (EXAMPLES / name).read_bytes(), name
    assert "verified the planted facts" in capsys.readouterr().out


def test_examples_are_ascii_and_synthetic():
    for name in FILES:
        data = (EXAMPLES / name).read_bytes()
        assert all(b < 128 for b in data), name
    text = (EXAMPLES / "ledger.csv").read_text()
    assert text.count("\n") == 272 and text.startswith("date,amount,currency,account,category,tags,note\n")
    assert (EXAMPLES / "holdings.csv").read_text().count("\n") == 73       # 24 snapshots x 3 + header
    assert (EXAMPLES / "rates.csv").read_text().count("\n") == 25          # 24 months + header


# ------------------------------------------------------------- planned verdicts


def test_as_of_2026_09_30_everything_holds_but_one_decision_is_due():
    code, by_id, doc = verdicts("2026-09-30")
    assert code == 1
    assert sorted(by_id) == ["WLT-%02d" % i for i in range(1, 9)]
    assert all(p["verdict"] == "hold" for p in by_id.values())
    assert [f["code"] for f in doc["findings"]] == ["DECISION-DUE"]
    assert doc["findings"][0]["cites"] == ["decisions.yml:26"]
    assert doc["green"] is False and doc["problems"] == []
    assert doc["files"] == {"policies.yml": 8, "ledger.csv": 271, "holdings.csv": 72,
                            "decisions.yml": 4, "rates.csv": 24}
    assert by_id["WLT-05"]["reason"] == "kill of 2025-11-30 closed by D-2025-12-05 (2025-12-05)"
    code, out, err = check("2026-09-30")
    assert out.splitlines()[-1] == "RED as of 2026-09-30: 8 of 8 policies hold, 1 red finding, 0 warnings"
    assert "  red   DECISION-DUE     decisions.yml:26  decision D-2026-06-01 is open" in out


def test_as_of_2026_09_14_is_green():
    code, by_id, doc = verdicts("2026-09-14")
    assert code == 0 and doc["green"] is True and doc["findings"] == []


def test_planted_breach_only_in_2026_07():
    code, by_id, doc = verdicts("2026-07-31")
    assert by_id["WLT-01"]["verdict"] == "breach"
    assert by_id["WLT-01"]["limit"]["amount"] == "120"                     # 10% of 1200
    assert all(p["verdict"] == "hold" for k, p in by_id.items() if k != "WLT-01")
    assert [f["code"] for f in doc["findings"]] == ["BREACH"]
    assert code == 1
    assert verdicts("2026-06-30")[1]["WLT-01"]["verdict"] == "hold"
    assert verdicts("2026-08-31")[1]["WLT-01"]["verdict"] == "hold"


def test_planted_missing_routine_only_in_2026_03():
    code, by_id, doc = verdicts("2026-03-31")
    assert by_id["WLT-03"]["verdict"] == "missing" and by_id["WLT-03"]["findings"] == ["ROUTINE-MISSING"]
    assert all(p["verdict"] == "hold" for k, p in by_id.items() if k != "WLT-03")
    assert verdicts("2026-02-28")[1]["WLT-03"]["verdict"] == "hold"
    assert verdicts("2026-04-30")[1]["WLT-03"]["verdict"] == "hold"
    code, out, err = run("routine", "--dir", str(EXAMPLES), "--period", "2026-03", "--as-of", "2026-03-31")
    assert code == 1 and out.splitlines()[0].startswith("missing  WLT-03")
    assert out.splitlines()[-1] == "MISSING routine 2026-03 as of 2026-03-31: 1 of 2 done"


def test_planted_kill_crossed_in_2025_11_and_closed_on_2025_12_05():
    code, by_id, doc = verdicts("2025-11-30")
    assert by_id["WLT-05"]["verdict"] == "kill"
    assert all(p["verdict"] == "hold" for k, p in by_id.items() if k != "WLT-05")
    kill = [f for f in doc["findings"] if f["code"] == "KILL"][0]
    assert kill["date"] == "2025-11-30" and "crossed 15%" in kill["reason"]
    assert verdicts("2025-12-04")[1]["WLT-05"]["verdict"] == "kill"
    code, by_id, doc = verdicts("2025-12-05")
    assert by_id["WLT-05"]["verdict"] == "hold" and "closed by D-2025-12-05" in by_id["WLT-05"]["reason"]
    assert verdicts("2025-10-31")[1]["WLT-05"]["verdict"] == "hold"
    assert verdicts("2025-10-31")[1]["WLT-05"]["reason"] is None
    code, out, err = check("2025-12-31")
    assert "hold     WLT-05     broker pilot drawdown" in out and "closed by D-2025-12-05 (2025-12-05)" in out


def test_other_months_are_green():
    for as_of in ("2024-10-31", "2025-01-31", "2025-06-30", "2025-10-31", "2026-01-31", "2026-05-31", "2026-08-31"):
        code, by_id, doc = verdicts(as_of)
        assert code == 0 and doc["green"] is True, (as_of, doc["findings"])


def test_decisions_command_on_the_example():
    code, out, err = run("decisions", "--dir", str(EXAMPLES), "--as-of", "2026-09-30")
    assert code == 1
    assert out.splitlines()[0].startswith("due      D-2026-06-01   review the family support amount")
    assert out.splitlines()[-1] == "DUE decisions as of 2026-09-30: 2 open, 1 due, 2 closed"


# ------------------------------------------------------------------------ init


def test_init_copies_the_example_and_refuses_to_overwrite(tmp_path):
    target = tmp_path / "money"
    code, out, err = run("init", "--dir", str(target))
    assert code == 0 and err == ""
    assert out.startswith("wrote 6 files to %s: README.md, decisions.yml, holdings.csv, ledger.csv, policies.yml, rates.csv" % target)
    for name in FILES:
        assert (target / name).read_bytes() == (EXAMPLES / name).read_bytes()
    code, out, err = run("check", "--dir", str(target), "--as-of", "2026-09-14")
    assert code == 0
    # a second init refuses and changes nothing
    (target / "ledger.csv").write_text("date,amount,currency,account,category,tags,note\n")
    code, out, err = run("init", "--dir", str(target))
    assert code == 2 and out == ""
    assert "refusing to overwrite existing files" in err and "ledger.csv" in err
    assert (target / "ledger.csv").read_text() == "date,amount,currency,account,category,tags,note\n"
    assert (target / "policies.yml").read_bytes() == (EXAMPLES / "policies.yml").read_bytes()


def test_init_refuses_when_one_file_exists(tmp_path):
    target = tmp_path / "partial"
    target.mkdir()
    (target / "policies.yml").write_text("version: 1\n")
    code, out, err = run("init", "--dir", str(target))
    assert code == 2 and "policies.yml" in err
    assert sorted(os.listdir(target)) == ["policies.yml"]


def test_init_without_examples_dir(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "examples_dir", lambda: str(tmp_path / "nowhere"))
    code, out, err = run("init", "--dir", str(tmp_path / "x"))
    assert code == 3 and "not available" in err
