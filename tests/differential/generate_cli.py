"""Generate the CLI expectations in tests/differential/cli/ from the
reference engine (branch qayd, read-only). Not part of the gate: the JSON it
writes is committed, and cli.test.ts replays every run through the port.

    git archive origin/qayd qayd tests examples | tar -x -C /some/dir
    python3 -I tests/differential/generate_cli.py /some/dir tests/differential/cli

Each output file: {"name", "files": {name: text or null (absent)},
"runs": [{"args": [...], "exit": n, "stdout": s, "stderr": s}]}. Households:
the CLI's rules fixtures and the example household with one change each.
"""
import io, json, os, sys, tempfile, shutil
QAYD = sys.argv[1]
OUT = sys.argv[2]
sys.path.insert(0, QAYD)
from qayd import cli

FILES = ("policies.yml", "ledger.csv", "holdings.csv", "decisions.yml", "rates.csv")

def read_dir(d):
    out = {}
    for f in FILES:
        p = os.path.join(d, f)
        out[f] = open(p, encoding="utf-8", newline="").read() if os.path.exists(p) else None
    return out

def run_case(name, files, runs):
    tmp = tempfile.mkdtemp()
    try:
        for f, text in files.items():
            if text is not None:
                with open(os.path.join(tmp, f), "w", encoding="utf-8", newline="") as fh:
                    fh.write(text)
        results = []
        for args in runs:
            out, err = io.StringIO(), io.StringIO()
            code = cli.main([args[0], "--dir", tmp] + list(args[1:]), out, err)
            results.append({"args": list(args), "exit": code, "stdout": out.getvalue(), "stderr": err.getvalue().replace(tmp + "/", "")})
        with open(os.path.join(OUT, name + ".json"), "w", encoding="utf-8") as fh:
            json.dump({"name": name, "files": files, "runs": results}, fh, separators=(",", ":"), ensure_ascii=True)
            fh.write("\n")
        return len(results)
    finally:
        shutil.rmtree(tmp)

def std_runs(dates, periods, ddates, json_dates=None):
    runs = []
    for d in dates:
        if json_dates is None or d in json_dates:
            runs.append(("check", "--as-of", d, "--json"))
        runs.append(("check", "--as-of", d))
    for p, d in periods:
        runs.append(("routine", "--period", p, "--as-of", d, "--json"))
        runs.append(("routine", "--period", p, "--as-of", d))
    for d in ddates:
        runs.append(("decisions", "--as-of", d, "--json"))
        runs.append(("decisions", "--as-of", d))
    return runs

FIX_DATES = ["2026-05-09", "2026-05-10", "2026-05-31", "2026-06-30", "2026-07-31", "2026-08-31", "2026-09-02", "2026-09-04",
             "2026-09-05", "2026-09-14", "2026-09-15", "2026-09-16", "2026-09-30", "2026-10-01", "2026-10-31", "2026-11-30", "2026-12-31"]
FIX_PERIODS = [("2026-09", "2026-09-30"), ("2026-09", "2026-09-02"), ("2026-Q3", "2026-09-30"), ("2026-08", "2026-09-30"),
               ("2026-12", "2026-09-30"), ("2026", "2026-09-30"), ("2026-Q4", "2026-12-31")]
FIX_DDATES = ["2026-09-14", "2026-09-15", "2026-09-30", "2026-10-01"]

total = 0
rules = os.path.join(QAYD, "tests", "fixtures", "rules")
for d in sorted(os.listdir(rules)):
    total += run_case("rules-" + d, read_dir(os.path.join(rules, d)), std_runs(FIX_DATES, FIX_PERIODS, FIX_DDATES, ("2026-05-31", "2026-08-31", "2026-09-30", "2026-11-30")))

EX = read_dir(os.path.join(QAYD, "examples"))
EX_DATES = []
for y, m, last in [(2024, 10, 31), (2024, 11, 30), (2024, 12, 31)] + [(2025, i, 0) for i in range(1, 13)] + [(2026, i, 0) for i in range(1, 13)] + [(2027, 1, 31)]:
    import calendar
    last = calendar.monthrange(y, m)[1]
    EX_DATES.append("%04d-%02d-%02d" % (y, m, last))
EX_DATES += ["2024-10-01", "2025-12-04", "2025-12-05", "2025-12-15", "2026-03-02", "2026-09-14", "2026-09-15", "2026-09-16", "2026-10-17"]
EX_PERIODS = [("2026-03", "2026-10-17"), ("2026-Q1", "2026-10-17"), ("2026", "2026-10-17"), ("2026-09", "2026-09-30"),
              ("2025-11", "2026-10-17"), ("2026-12", "2026-10-17"), ("2026-10", "2026-10-17"), ("2024", "2026-10-17")]
EX_DDATES = ["2025-10-01", "2025-10-02", "2026-09-14", "2026-09-30", "2026-12-31", "2027-01-01"]
EX_JSON_DATES = ("2024-10-01", "2024-10-31", "2024-12-31", "2025-03-31", "2025-06-30", "2025-09-30", "2025-12-04", "2025-12-05",
                 "2025-12-31", "2026-06-30", "2026-09-14", "2026-10-31", "2026-11-30", "2027-01-31")

def mut(name, change, dates=None, periods=None, ddates=None):
    files = dict(EX)
    change(files)
    # JSON at a few dates (the text output carries the rest, much smaller)
    json_dates = EX_JSON_DATES if dates is None else ("2025-11-30", "2026-09-30")
    return run_case(name, files, std_runs(dates or EX_DATES, periods or EX_PERIODS, ddates or EX_DDATES, json_dates))

total += mut("example", lambda f: None)
SHORT = ["2025-11-30", "2025-12-31", "2026-03-31", "2026-07-31", "2026-08-31", "2026-09-30", "2026-10-31", "2026-12-31"]
SP = [("2026-03", "2026-10-17"), ("2026-09", "2026-09-30"), ("2026-Q3", "2026-09-30")]
SD = ["2026-09-30"]
def app(file, line):
    def f(files):
        files[file] = files[file] + line
    return f
def rep(file, old, new):
    def f(files):
        assert old in files[file], (file, old)
        files[file] = files[file].replace(old, new)
    return f
def setf(file, text):
    def f(files):
        files[file] = text
    return f
def chain(*fs):
    def f(files):
        for g in fs: g(files)
    return f
BREACH = "2026-09-28,-200,OMR,cash,discretionary,,new tablet\n"
total += mut("ex-breach", app("ledger.csv", BREACH), SHORT, SP, SD)
total += mut("ex-breach-reversed", app("ledger.csv", BREACH + "2026-09-28,200,OMR,cash,discretionary,reversal,reverses ledger.csv:273\n"), SHORT, SP, SD)
total += mut("ex-dup-row", app("ledger.csv", "2026-09-15,-17.507,OMR,cash,discretionary,,gift\n"), SHORT, SP, SD)
total += mut("ex-bad-amount", app("ledger.csv", "2026-09-10,1.000.00,OMR,cash,food,,typo\n"), SHORT, SP, SD)
total += mut("ex-column-count", app("ledger.csv", "2026-09-10,-1,OMR,cash,food\n"), SHORT, SP, SD)
total += mut("ex-bad-csv", app("ledger.csv", '2026-09-10,-1,OMR,cash,food,,"unclosed\n'), SHORT, SP, SD)
total += mut("ex-unknown-category", app("ledger.csv", "2026-08-10,-1,OMR,cash,coffee,,x\n"), SHORT, SP, SD)
total += mut("ex-eur-no-rate", app("ledger.csv", "2026-09-20,-10,EUR,cash,discretionary,,in euro\n"), SHORT, SP, SD)
total += mut("ex-no-rates", lambda f: f.__setitem__("rates.csv", None), SHORT, SP, SD)
total += mut("ex-rate-conflict", app("rates.csv", "2026-09-01,USD,0.3900\n"), SHORT, SP, SD)
total += mut("ex-margin", app("ledger.csv", "2026-02-10,-50,OMR,broker,buy,margin;pilot,bought on margin\n"), SHORT, SP, SD)
total += mut("ex-decision-closed", rep("decisions.yml", "  review_by: 2026-09-15\n  status: open", "  review_by: 2026-09-15\n  status: closed"), SHORT, SP, ["2026-09-30", "2026-12-31"])
total += mut("ex-backdated-close", rep("decisions.yml", "- id: D-2025-12-05\n  date: 2025-12-05", "- id: D-2025-12-05\n  date: 2025-11-30"), SHORT + ["2025-12-05"], SP, SD)
total += mut("ex-closes-non-kill", rep("decisions.yml", "closes: WLT-05", "closes: WLT-01"), SHORT, SP, SD)
total += mut("ex-unknown-type", rep("policies.yml", "    type: allocation\n", "    type: band\n"), SHORT, SP, SD)
total += mut("ex-decimals", chain(rep("policies.yml", "limit: {pct_of: income, value: 10}", "limit: {pct_of: income, value: 12.50}"),
                                   rep("policies.yml", "limit: {value: 2400}", "limit: {value: 2400.50}"),
                                   rep("policies.yml", "band: {min_pct: 2, max_pct: 30}", "band: {min_pct: 2.5, max_pct: 30.0}"),
                                   rep("policies.yml", "min_amount: 300}", "min_amount: 300.000}")), SHORT, SP, SD)
total += mut("ex-tight-age", rep("policies.yml", "snapshot_max_age_days: 45", "snapshot_max_age_days: 20"), SHORT + ["2026-09-20", "2026-09-21"], SP, SD)
total += mut("ex-bad-holding", rep("holdings.csv", "2026-09-30,cash,gold coin,gold,1,150.000,OMR", "2026-09-30,cash,gold coin,gold,1,150.000.0,OMR"), SHORT, SP, SD)
total += mut("ex-header-only-ledger", setf("ledger.csv", "date,amount,currency,account,category,tags,note\n"), SHORT, SP, SD)
total += mut("ex-broken-policies", app("policies.yml", "  - id: [unclosed\n"), SHORT[:2], SP[:1], SD)
total += mut("ex-blank-line", rep("ledger.csv", "2026-09-01,1200.000", "\n2026-09-01,1200.000"), SHORT, SP, SD)
total += mut("ex-crlf-bom", lambda f: [f.__setitem__(k, chr(0xfeff) + v.replace("\n", "\r\n")) for k, v in list(f.items()) if v is not None and k.endswith(".csv")], SHORT, SP, SD)
total += mut("ex-quoted-note", app("ledger.csv", '2026-09-11,-3.250,OMR,cash,food,"weekly;market","fish, bread"\n'), SHORT, SP, SD)
total += mut("ex-two-tags", rep("policies.yml", "match: {tags: transfer, account: savings, min_amount: 300}", "match: {tags: [transfer, monthly], account: savings, min_amount: 300}"), SHORT, SP, SD)
total += mut("ex-undeclared-account", rep("policies.yml", "match: {tags: transfer, account: savings, min_amount: 300}", "match: {tags: transfer, account: vault, min_amount: 300}"), SHORT[:2], SP[:1], SD)
total += mut("ex-cap-on-share", rep("policies.yml", "    type: allocation\n    title: equities band\n    measure: {share: class.equity}\n    band: {min_pct: 2, max_pct: 30}\n",
                                     "    type: cap\n    title: equities as a cap\n    measure: {share: class.equity}\n    limit: {value: 5}\n"), SHORT, SP, SD)
total += mut("ex-future-rows", app("ledger.csv", "2026-10-03,-300.000,OMR,salary,transfer,transfer,to savings\n2026-10-03,300.000,OMR,savings,transfer,transfer,from salary\n"), SHORT + ["2026-10-02", "2026-10-03"], SP + [("2026-10", "2026-10-03"), ("2026-10", "2026-10-02")], SD)
BAD_DECISIONS = ("- id: D-x1\n  date: 2026-02-30\n  title: bad date\n  policy: null\n  criteria: c\n  review_by: 2026-06-01\n  status: open\n  closes: null\n"
                 "- id: D-x2\n  date: 2026-01-01\n  title: unknown policy\n  policy: WLT-99\n  criteria: c\n  review_by: 2026-06-01\n  status: open\n  closes: null\n"
                 "- id: D-x3\n  date: 2026-01-01\n  title: 5\n  review_by: 2026-06-01\n  status: pending\n  owner: me\n"
                 "- id: D-2026-06-01\n  date: 2026-06-01\n  title: dup id\n  review_by: 2026-07-01\n  status: open\n")
total += mut("ex-decision-problems", app("decisions.yml", BAD_DECISIONS), SHORT, SP, ["2026-09-30", "2026-07-02"])
total += mut("ex-rate-problems", app("rates.csv", "2026-09-02,OMR,1\n2026-09-03,USD,-0.38\n2026-09-04,usd,0.38\n2026-9-05,USD,0.38\n2026-09-06,USD\n"), SHORT, SP, SD)
total += mut("ex-holdings-dup", app("holdings.csv", "2026-09-30,cash,gold coin,gold,1,150.000,OMR\n"), SHORT, SP, SD)
total += mut("ex-yaml11", chain(rep("policies.yml", "min_amount: 300}", "min_amount: 0x12C}"),
                                rep("policies.yml", "limit: {pct: 15}", "limit: {pct: 1_5}"),
                                rep("policies.yml", "window_days: 90}", "window_days: 0132}"),
                                rep("policies.yml", "limit: {value: 2400}", "limit: {value: 0o12}"),
                                rep("policies.yml", "min_amount: 250}", "min_amount: '250.00'}")), SHORT, SP, SD)
total += mut("ex-quoted-age", rep("policies.yml", "snapshot_max_age_days: 45", "snapshot_max_age_days: '45'"), SHORT[:1], SP[:1], SD)
total += mut("ex-unknown-shapes", chain(rep("policies.yml", "measure: {sum: expense, period: quarter}", "measure: {sum: expense, period: week}"),
                                        rep("policies.yml", "    match: {category: housing, min_amount: 250}\n    period: month\n", "    match: {category: housing, min_amount: 250}\n    period: month\n    owner: me\n"),
                                        rep("policies.yml", "band: {min_pct: 2, max_pct: 30}", "band: {min_pct: 40, max_pct: 30}"),
                                        rep("policies.yml", "limit: {pct_of: income, value: 10}", "limit: {pct_of: income, value: yes}")), SHORT, SP, SD)
total += mut("ex-no-version", rep("policies.yml", "version: 1\n", ""), SHORT[:1], SP[:1], SD)
total += mut("ex-empty-decisions", setf("decisions.yml", "[]\n"), SHORT, SP, SD)
total += mut("ex-missing-decisions", lambda f: f.__setitem__("decisions.yml", None), SHORT[:1], SP[:1], SD)
total += mut("ex-empty-rates-file", setf("rates.csv", ""), SHORT[:1], SP[:1], SD)
total += mut("ex-no-snapshots", setf("holdings.csv", "date,account,asset,class,quantity,value,currency\n"), SHORT, SP, SD)
total += mut("ex-refund", app("ledger.csv", "2026-07-25,40,OMR,cash,discretionary,,refund of the phone case\n"), SHORT, SP, SD)
total += mut("ex-transfer-as-expense", rep("ledger.csv", "2026-09-03,-300.000,OMR,salary,transfer,transfer,to savings", "2026-09-03,-300.000,OMR,salary,housing,,to savings"), SHORT, SP, SD)
print("runs:", total)

# ---- the loaders on their own fixtures: tests/differential/loaders.json ----
from qayd import ledger as L, policies as P, decisions as DD, rates as R

def dec(x):
    return None if x is None else str(x)

def policy_json(p):
    return {"id": p.id, "type": p.type, "title": p.title, "status": p.status, "reason": p.reason, "line": p.line,
            "measure": P.measure_text(p.measure) if p.measure else None,
            "limit": P.limit_text(p.limit, "OMR") if p.limit else None,
            "match": P.match_text(p.match) if p.match else None,
            "band": P.band_text(p.band) if p.band else None, "period": p.period}

ACC = ["salary", "savings", "broker", "cash"]
CATS = {"income": ["salary", "bonus", "side"], "expense": ["housing", "food", "transport", "family", "discretionary", "fees"],
        "transfer": ["transfer"], "invest": ["buy", "sell", "dividend"]}
CLASSES = ["cash", "equity", "fund", "property", "gold", "debt", "other"]
FX = os.path.join(QAYD, "tests", "fixtures")
loaders = []
for kind in ("ledger", "holdings", "rates", "policies", "decisions"):
    for name in sorted(os.listdir(os.path.join(FX, kind))):
        if name.startswith("bad_encoding"):
            continue
        path = os.path.join(FX, kind, name)
        entry = {"kind": kind, "name": name}
        if kind == "ledger":
            got = L.load_ledger(path, ACC, CATS)
            entry["rows"] = [[r.line, r.date.isoformat(), dec(r.amount), r.currency, r.account, r.category, list(r.tags), r.note] for r in got.rows]
        elif kind == "holdings":
            got = L.load_holdings(path, ACC, CLASSES)
            entry["rows"] = [[r.line, r.date.isoformat(), r.account, r.asset, r.asset_class, dec(r.quantity), dec(r.value), r.currency] for r in got.rows]
        elif kind == "rates":
            got = R.load(path, "OMR")
            entry["rows"] = [[r.line, r.date.isoformat(), r.currency, dec(r.rate)] for r in got.table.rows]
        elif kind == "policies":
            cfg, problems = P.load(path)
            got = L.Loaded((), problems)
            entry["config"] = None if cfg is None else {
                "version": cfg.version, "base_currency": cfg.base_currency, "accounts": list(cfg.accounts),
                "categories": {k: list(v) for k, v in cfg.categories.items()}, "classes": list(cfg.classes),
                "snapshot_max_age_days": cfg.snapshot_max_age_days, "policies": [policy_json(p) for p in cfg.policies]}
        else:
            ds, problems = DD.load(path, ("WLT-01", "WLT-05"), ("WLT-05",))
            got = L.Loaded((), problems)
            entry["decisions"] = [[d.id, d.date.isoformat(), d.title, d.policy, d.criteria, d.review_by.isoformat(), d.status, d.closes, d.line] for d in ds]
        entry["problems"] = got.problems
        loaders.append(entry)
with open(os.path.join(os.path.dirname(OUT.rstrip("/")), "loaders.json"), "w", encoding="utf-8") as fh:
    json.dump(loaders, fh, indent=1, ensure_ascii=True)
    fh.write("\n")
print("loader fixtures:", len(loaders))
