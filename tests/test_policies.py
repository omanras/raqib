"""M0.2: policies.yml and decisions.yml loaders (ADR-0001 sections 5 and 7).

One test per fixture in tests/fixtures/policies and tests/fixtures/decisions.
"""

import datetime
from decimal import Decimal
from pathlib import Path

from qayd import decisions, policies

FIX = Path(__file__).parent / "fixtures"
POL = FIX / "policies"
DEC = FIX / "decisions"


def D(text):
    return datetime.date.fromisoformat(text)


def load(name):
    return policies.load(POL / name)


def codes(problems):
    return [(p["line"], p["code"], p.get("field")) for p in problems]


def by_id(cfg):
    return {p.id: p for p in cfg.policies}


# ----------------------------------------------------------------- policies: valid


def test_valid_config_fields():
    cfg, problems = load("valid.yml")
    assert problems == []
    assert cfg.version == 1
    assert cfg.base_currency == "OMR"
    assert cfg.accounts == ("salary", "savings", "broker", "cash")
    assert cfg.categories == {
        "income": ("salary", "bonus", "side"),
        "expense": ("housing", "food", "transport", "family", "discretionary", "fees"),
        "transfer": ("transfer",),
        "invest": ("buy", "sell", "dividend"),
    }
    assert cfg.classes == policies.DEFAULT_CLASSES
    assert cfg.snapshot_max_age_days == 45
    assert cfg.file == "valid.yml"
    assert cfg.group_of("food") == "expense" and cfg.group_of("coffee") is None
    assert "dividend" in cfg.all_categories
    assert cfg.policy_ids == tuple("WLT-%02d" % i for i in range(1, 12))
    assert cfg.policy("WLT-05").type == "kill" and cfg.policy("nope") is None
    assert all(p.status == "ok" and p.reason is None for p in cfg.policies)


def test_valid_policies_normalized():
    cfg, _ = load("valid.yml")
    p = by_id(cfg)
    assert p["WLT-01"].type == "cap" and p["WLT-01"].title == "discretionary spending per month"
    assert p["WLT-01"].measure == {"kind": "sum", "group": "expense", "category": "discretionary", "period": "month"}
    assert p["WLT-01"].limit == {"kind": "pct_of", "of": "income", "value": Decimal(10)}
    assert p["WLT-01"].line == 11 and p["WLT-01"].cite == "valid.yml:11"
    assert p["WLT-02"].measure == {"kind": "holdings", "by": "class", "name": "cash"}
    assert p["WLT-02"].limit == {"kind": "months_of", "of": "expense", "value": Decimal(6)}
    assert p["WLT-03"].match == {"tags": ("transfer",), "account": "savings", "min_amount": Decimal(300)}
    assert p["WLT-03"].period == "month"
    assert p["WLT-04"].match == {"tags_any": ("margin", "options")}
    assert p["WLT-05"].measure == {"kind": "drawdown", "by": "account", "name": "broker", "window_days": 90}
    assert p["WLT-05"].limit == {"kind": "pct", "value": Decimal(15)}
    assert p["WLT-06"].measure == {"kind": "share", "by": "class", "name": "equity"}
    assert p["WLT-06"].band == {"min_pct": Decimal(20), "max_pct": Decimal(50)}
    assert p["WLT-07"].measure == {"kind": "sum", "group": "expense", "category": None, "period": "quarter"}
    assert p["WLT-07"].limit == {"kind": "value", "value": Decimal("4500.50")}
    assert p["WLT-08"].measure == {"kind": "sum", "group": "income", "category": None, "period": "year"}
    assert p["WLT-09"].measure == {"kind": "holdings", "by": "account", "name": "broker"}
    assert p["WLT-10"].match == {"category": "discretionary", "min_amount": Decimal(200)}
    assert p["WLT-11"].match == {"category": "dividend"} and p["WLT-11"].period == "quarter"
    assert p["WLT-04"].measure is None and p["WLT-04"].limit is None and p["WLT-04"].band is None


def test_rendering_helpers():
    cfg, _ = load("valid.yml")
    p = by_id(cfg)
    assert policies.measure_text(p["WLT-01"].measure) == "sum expense.discretionary per month"
    assert policies.measure_text(p["WLT-07"].measure) == "sum expense per quarter"
    assert policies.measure_text(p["WLT-02"].measure) == "holdings class.cash"
    assert policies.measure_text(p["WLT-05"].measure) == "drawdown account.broker over 90 days"
    assert policies.limit_text(p["WLT-01"].limit) == "10% of income"
    assert policies.limit_text(p["WLT-02"].limit) == "6 months of expense"
    assert policies.limit_text(p["WLT-07"].limit, "OMR") == "4500.50 OMR"
    assert policies.limit_text(p["WLT-05"].limit) == "15%"
    assert policies.band_text(p["WLT-06"].band) == "20%..50%"
    assert policies.match_text(p["WLT-03"].match) == "tags transfer, account savings, amount >= 300"
    assert policies.match_text(p["WLT-04"].match) == "any tag of margin,options"
    assert policies.measure_text(None) == "?" and policies.limit_text(None) == "?"


def test_decimals_never_float():
    cfg, problems = load("decimals.yml")
    assert problems == []
    p = by_id(cfg)
    assert p["P-01"].limit["value"] == Decimal("0.1") and str(p["P-01"].limit["value"]) == "0.1"
    assert isinstance(p["P-01"].limit["value"], Decimal)
    assert p["P-02"].band == {"min_pct": Decimal("12.5"), "max_pct": Decimal("37.75")}
    assert p["P-03"].limit["value"] == Decimal("1234.5678")
    assert p["P-04"].limit["value"] == Decimal("10.5")
    for policy in cfg.policies:
        for d in (policy.limit, policy.band):
            for v in (d or {}).values():
                assert not isinstance(v, float)


def test_custom_classes_replace_the_default():
    cfg, problems = load("classes_custom.yml")
    assert cfg.classes == ("cash", "stocks", "gold")
    p = by_id(cfg)
    assert p["P-01"].status == "ok"
    assert p["P-02"].status == "unknown" and "equity" in p["P-02"].reason
    assert codes(problems) == [(20, "UNDECLARED-CLASS", "policies[1].measure.share")]


# --------------------------------------------------------- policies: unknown shapes


def test_unknown_shapes_are_kept_as_unknown_and_the_file_is_not_rejected():
    cfg, problems = load("unknown_shapes.yml")
    assert problems == []                       # none of these is a file problem
    assert cfg is not None
    p = by_id(cfg)
    assert len(cfg.policies) == 21
    assert p["OK-01"].status == "ok"
    unknown = {k: v for k, v in p.items() if k.startswith("U-")}
    assert all(v.status == "unknown" and v.reason for v in unknown.values())
    assert all(v.measure is None and v.limit is None and v.match is None and v.band is None
               for v in unknown.values())
    assert "ceiling" in p["U-01"].reason and p["U-01"].type == "ceiling"
    assert "period" in p["U-02"].reason
    assert "average" in p["U-03"].reason
    assert "max" in p["U-04"].reason
    assert "pct" in p["U-05"].reason                 # {pct} is not a cap limit
    assert "drawdown" in p["U-06"].reason
    assert "window_days" in p["U-07"].reason
    assert "min_pct <= max_pct" in p["U-08"].reason
    assert "share" in p["U-09"].reason
    assert "period" in p["U-10"].reason
    assert "week" in p["U-11"].reason
    assert "at least one" in p["U-12"].reason
    assert "merchant" in p["U-13"].reason
    assert "needs measure and limit" in p["U-14"].reason
    assert "number" in p["U-15"].reason
    assert "income" in p["U-16"].reason
    assert "band" in p["U-17"].reason
    assert "period" in p["U-18"].reason
    assert "number" in p["U-19"].reason              # true is not a number
    assert "number" in p["U-20"].reason              # .inf is not a number
    assert p["U-01"].raw["title"] == "unknown type"  # the raw mapping is kept
    assert p["U-01"].line == 11


# ------------------------------------------------------------ policies: problems


def test_duplicate_policy_id_is_a_problem_and_the_second_is_dropped():
    cfg, problems = load("dup_id.yml")
    assert codes(problems) == [(20, "DUP-ID", "policies[2].id")]
    assert "line 11" in problems[0]["reason"]
    assert cfg.policy_ids == ("WLT-01", "WLT-02")
    assert cfg.policy("WLT-01").limit["value"] == Decimal(100)   # the first one stands


def test_undeclared_names_are_problems_and_unknown_policies():
    cfg, problems = load("undeclared.yml")
    assert codes(problems) == [
        (14, "UNDECLARED-CATEGORY", "policies[0].measure.sum"),
        (19, "UNDECLARED-CATEGORY", "policies[1].measure.sum"),
        (24, "UNDECLARED-CLASS", "policies[2].measure.holdings"),
        (29, "UNDECLARED-ACCOUNT", "policies[3].measure.drawdown"),
        (34, "UNDECLARED-ACCOUNT", "policies[4].match.account"),
        (39, "UNDECLARED-CATEGORY", "policies[5].match.category"),
        (43, "UNDECLARED-CATEGORY", "policies[6].measure.sum"),
    ]
    assert all(p["class"] == "invalid" for p in problems)
    assert all(p.status == "unknown" for p in cfg.policies)
    assert "food" in problems[6]["reason"] and "income" in problems[6]["reason"]


def test_empty_policies_list_is_a_problem():
    cfg, problems = load("empty_policies.yml")
    assert codes(problems) == [(1, "EMPTY-POLICIES", "policies")]
    assert cfg is not None and cfg.policies == ()


def test_missing_policies_key_is_a_problem():
    cfg, problems = load("no_policies_key.yml")
    assert codes(problems) == [(1, "EMPTY-POLICIES", "policies")]


def test_missing_base_currency_names_the_field():
    cfg, problems = load("missing_base_currency.yml")
    assert codes(problems) == [(1, "MISSING-FIELD", "base_currency")]
    assert cfg.base_currency is None and len(cfg.policies) == 1


def test_missing_snapshot_max_age_names_the_field():
    cfg, problems = load("missing_snapshot_age.yml")
    assert codes(problems) == [(1, "MISSING-FIELD", "snapshot_max_age_days")]
    assert cfg.snapshot_max_age_days is None


def test_categories_must_declare_income_and_expense():
    cfg, problems = load("categories_missing_group.yml")
    assert codes(problems) == [(5, "MISSING-FIELD", "categories.expense")]
    assert "expense" not in cfg.categories


def test_bad_fields_each_named():
    cfg, problems = load("bad_fields.yml")
    got = [(p["code"], p["field"]) for p in problems]
    assert got == [
        ("BAD-FIELD", "colour"),
        ("BAD-FIELD", "version"),
        ("BAD-FIELD", "base_currency"),
        ("DUP-ID", "accounts"),
        ("BAD-FIELD", "accounts"),
        ("DUP-ID", "categories.expense"),
        ("BAD-FIELD", "categories.transfer"),
        ("BAD-FIELD", "snapshot_max_age_days"),
        ("BAD-FIELD", "policies[1].id"),
        ("BAD-FIELD", "policies[2]"),
    ]
    assert cfg.version is None and cfg.base_currency is None
    assert cfg.accounts == ("salary",)
    assert cfg.categories == {"income": ("salary",), "expense": ("food",), "transfer": ()}
    assert cfg.snapshot_max_age_days is None
    assert cfg.policy_ids == ("P-01",)


# ---------------------------------------------------------- policies: file level


def test_bad_yaml_names_the_line():
    cfg, problems = load("bad_yaml.yml")
    assert cfg is None
    assert [(p["line"], p["code"]) for p in problems] == [(5, "BAD-YAML")]


def test_duplicate_key_is_a_parse_problem():
    cfg, problems = load("dup_key.yml")
    assert cfg is None
    assert [(p["line"], p["code"]) for p in problems] == [(16, "BAD-YAML")]
    assert "duplicate key 'limit'" in problems[0]["reason"]


def test_not_a_mapping():
    cfg, problems = load("not_a_mapping.yml")
    assert cfg is None and [(p["line"], p["code"]) for p in problems] == [(1, "BAD-SHAPE")]


def test_empty_and_comment_only_files():
    for name in ("empty.yml", "comment_only.yml"):
        cfg, problems = load(name)
        assert cfg is None and [(p["line"], p["code"]) for p in problems] == [(0, "FILE-EMPTY")]


def test_unsafe_tag_is_rejected():
    cfg, problems = load("unsafe_tag.yml")
    assert cfg is None and [p["code"] for p in problems] == ["BAD-YAML"]


def test_multi_document_is_rejected():
    cfg, problems = load("multi_doc.yml")
    assert cfg is None and [p["code"] for p in problems] == ["BAD-YAML"]


def test_bad_encoding_names_the_line():
    cfg, problems = load("bad_encoding.yml")
    assert cfg is None and [(p["line"], p["code"]) for p in problems] == [(13, "BAD-ENCODING")]


def test_missing_file_and_directory_never_raise():
    cfg, problems = load("nope.yml")
    assert cfg is None and [(p["line"], p["code"]) for p in problems] == [(0, "FILE-MISSING")]
    cfg, problems = policies.load(POL)
    assert cfg is None and [(p["line"], p["code"]) for p in problems] == [(0, "FILE-UNREADABLE")]
    cfg, problems = policies.load(None)
    assert cfg is None and len(problems) == 1


# ------------------------------------------------------------------- decisions


IDS = ("WLT-01", "WLT-05")


def load_d(name, ids=IDS):
    return decisions.load(DEC / name, ids)


def test_valid_decisions():
    ds, problems = load_d("valid.yml")
    assert problems == []
    assert [d.id for d in ds] == ["D-2026-10-01", "D-2025-12-05", "D-min"]
    d = ds[0]
    assert d.date == D("2026-10-01") and d.review_by == D("2027-01-01")
    assert d.title == "start broker pilot with 500 OMR"
    assert d.policy == "WLT-05" and d.closes is None
    assert d.criteria.startswith("stop if drawdown")
    assert d.status == "open" and d.is_open
    assert d.line == 1 and d.file == "valid.yml" and d.cite == "valid.yml:1"
    assert ds[1].status == "closed" and not ds[1].is_open and ds[1].closes == "WLT-05"
    assert ds[1].date == D("2025-12-05")          # quoted date text also works
    assert ds[2].title == "" and ds[2].criteria == "" and ds[2].policy is None


def test_decisions_bad_dates_name_the_field():
    ds, problems = load_d("bad_date.yml")
    assert [d.id for d in ds] == ["D-5"]
    assert codes(problems) == [
        (1, "BAD-DATE", "decisions[0].date"),
        (6, "BAD-DATE", "decisions[1].review_by"),
        (11, "BAD-DATE", "decisions[2].date"),
        (16, "BAD-DATE", "decisions[3].review_by"),
    ]
    assert "before" in problems[3]["reason"]


def test_decisions_unknown_policy():
    ds, problems = load_d("unknown_policy.yml")
    assert [d.id for d in ds] == ["D-3"]
    assert codes(problems) == [
        (1, "UNKNOWN-POLICY", "decisions[0].policy"),
        (7, "UNKNOWN-POLICY", "decisions[1].closes"),
    ]


def test_decisions_bad_status():
    ds, problems = load_d("bad_status.yml")
    assert [d.id for d in ds] == ["D-4"]
    assert codes(problems) == [
        (1, "BAD-STATUS", "decisions[0].status"),
        (6, "BAD-STATUS", "decisions[1].status"),
        (10, "BAD-STATUS", "decisions[2].status"),
    ]


def test_decisions_duplicate_id():
    ds, problems = load_d("dup_id.yml")
    assert [d.id for d in ds] == ["D-1"] and ds[0].title == "first"
    assert codes(problems) == [(6, "DUP-ID", "decisions[1].id")]


def test_decisions_missing_fields():
    ds, problems = load_d("missing_fields.yml")
    assert ds == ()
    assert codes(problems) == [
        (1, "BAD-FIELD", "decisions[0].id"),
        (5, "MISSING-FIELD", "decisions[1].date"),
        (5, "MISSING-FIELD", "decisions[1].review_by"),
        (8, "BAD-FIELD", "decisions[2].owner"),
        (14, "BAD-FIELD", "decisions[3].title"),
        (1, "BAD-FIELD", "decisions[4]"),
    ]


def test_decisions_not_a_list_and_empty():
    ds, problems = load_d("not_a_list.yml")
    assert ds == () and [(p["line"], p["code"]) for p in problems] == [(1, "BAD-SHAPE")]
    ds, problems = load_d("empty_list.yml")
    assert ds == () and problems == []
    ds, problems = load_d("empty.yml")
    assert ds == () and [(p["line"], p["code"]) for p in problems] == [(0, "FILE-EMPTY")]
    ds, problems = load_d("nope.yml")
    assert ds == () and [(p["line"], p["code"]) for p in problems] == [(0, "FILE-MISSING")]


def test_decisions_policy_ids_may_be_any_iterable():
    ds, problems = decisions.load(DEC / "valid.yml", iter(["WLT-05"]))
    assert problems == [] and len(ds) == 3
    ds, problems = decisions.load(DEC / "valid.yml", ())
    assert [p["code"] for p in problems] == ["UNKNOWN-POLICY", "UNKNOWN-POLICY", "UNKNOWN-POLICY"]
    assert [d.id for d in ds] == ["D-min"]
