"""Tests for mizan.condition (HANDOFF M0.3, ADR-0001 section 5).

Every grammar form, precedence, every Unknown cause, the full three-valued
table, and evaluate_rule over loader + matcher.
"""

import itertools
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from mizan import condition, loader  # noqa: E402
from mizan.condition import Unknown, evaluate, evaluate_rule, parse, references  # noqa: E402

NAMES = ("selection", "filter_admin", "filter_system", "keywords")
U = Unknown("test")


def ident(name):
    return ("id", name)


def unknown(text, names=NAMES, *parts):
    result = parse(text, names)
    assert isinstance(result, Unknown), "%r parsed to %r" % (text, result)
    for part in parts:
        assert part in result.reason, "reason %r lacks %r" % (result.reason, part)
    return result


# --- E1: grammar forms --------------------------------------------------------------

def test_identifier():
    assert parse("selection", NAMES) == ident("selection")
    assert parse("  selection  ", NAMES) == ident("selection")


def test_and_or_not():
    assert parse("selection and keywords", NAMES) == ("and", (ident("selection"), ident("keywords")))
    assert parse("selection or keywords", NAMES) == ("or", (ident("selection"), ident("keywords")))
    assert parse("not selection", NAMES) == ("not", ident("selection"))
    assert parse("not not selection", NAMES) == ("not", ("not", ident("selection")))


def test_chains_are_flattened():
    assert parse("selection and keywords and filter_admin", NAMES) == (
        "and", (ident("selection"), ident("keywords"), ident("filter_admin")))
    assert parse("selection or keywords or filter_admin", NAMES) == (
        "or", (ident("selection"), ident("keywords"), ident("filter_admin")))


def test_parentheses():
    assert parse("(selection)", NAMES) == ident("selection")
    assert parse("((selection))", NAMES) == ident("selection")
    assert parse("(selection or keywords) and not filter_admin", NAMES) == (
        "and", (("or", (ident("selection"), ident("keywords"))), ("not", ident("filter_admin"))))
    assert parse("selection and (keywords or filter_admin)", NAMES) == (
        "and", (ident("selection"), ("or", (ident("keywords"), ident("filter_admin")))))


def test_precedence_not_over_and_over_or():
    assert parse("selection or keywords and filter_admin", NAMES) == (
        "or", (ident("selection"), ("and", (ident("keywords"), ident("filter_admin")))))
    assert parse("selection and keywords or filter_admin", NAMES) == (
        "or", (("and", (ident("selection"), ident("keywords"))), ident("filter_admin")))
    assert parse("not selection and keywords", NAMES) == (
        "and", (("not", ident("selection")), ident("keywords")))
    assert parse("not selection or keywords", NAMES) == (
        "or", (("not", ident("selection")), ident("keywords")))
    assert parse("selection and not keywords or filter_admin and not filter_system", NAMES) == (
        "or", (("and", (ident("selection"), ("not", ident("keywords")))),
               ("and", (ident("filter_admin"), ("not", ident("filter_system"))))))


def test_one_of_pattern_is_or():
    assert parse("1 of filter_*", NAMES) == ("or", (ident("filter_admin"), ident("filter_system")))
    assert parse("selection and not 1 of filter_*", NAMES) == (
        "and", (ident("selection"), ("not", ("or", (ident("filter_admin"), ident("filter_system"))))))


def test_all_of_pattern_is_and():
    assert parse("all of filter_*", NAMES) == ("and", (ident("filter_admin"), ident("filter_system")))


def test_one_of_them_and_all_of_them():
    assert parse("1 of them", NAMES) == ("or", tuple(ident(n) for n in NAMES))
    assert parse("all of them", NAMES) == ("and", tuple(ident(n) for n in NAMES))
    assert parse("1 of them", ("only",)) == ident("only")


def test_pattern_matching_one_selection_or_an_exact_name():
    assert parse("1 of sel*", NAMES) == ident("selection")
    assert parse("all of selection", NAMES) == ident("selection")
    assert parse("1 of *", NAMES) == ("or", tuple(ident(n) for n in NAMES))


def test_identifier_characters():
    names = ("sel-1", "sel.2", "Sel_3")
    assert parse("sel-1 and sel.2 and Sel_3", names) == (
        "and", (ident("sel-1"), ident("sel.2"), ident("Sel_3")))
    assert parse("selection and(keywords)", NAMES) == ("and", (ident("selection"), ident("keywords")))


# --- E2: Unknown causes -----------------------------------------------------------------

def test_identifier_not_a_selection():
    unknown("selection and nothing", NAMES, "'nothing'", "not a selection")
    unknown("nothing", NAMES, "'nothing'", "not a selection")


def test_operators_are_lowercase_only():
    unknown("selection AND keywords", NAMES, "'AND'", "lowercase")
    unknown("selection Or keywords", NAMES, "'Or'", "lowercase")
    unknown("NOT selection", NAMES, "'NOT'", "lowercase")
    unknown("1 OF them", NAMES, "'OF'", "expected 'of'")
    unknown("ALL of them", NAMES, "'ALL'", "lowercase")
    # A selection that happens to be named like an uppercase keyword still works.
    assert parse("selection and AND", NAMES + ("AND",)) == ("and", (ident("selection"), ident("AND")))


def test_pattern_matching_no_selection():
    unknown("1 of nothing_*", NAMES, "'nothing_*'", "matches no selection")
    unknown("all of nothing", NAMES, "'nothing'", "matches no selection")


def test_pattern_with_non_trailing_wildcard():
    unknown("1 of *_admin", NAMES, "'*_admin'", "only a trailing '*'")
    unknown("1 of fil*er_*", NAMES, "only a trailing '*'")


def test_pattern_outside_quantifier():
    unknown("filter_*", NAMES, "'filter_*'", "only valid after")
    unknown("selection and filter_*", NAMES, "only valid after")


def test_unbalanced_parentheses():
    unknown("(selection", NAMES, "unbalanced", "missing ')'")
    unknown("selection)", NAMES, "unbalanced", "unexpected ')'")
    unknown("((selection)", NAMES, "unbalanced")
    unknown("(selection))", NAMES, "unbalanced")
    unknown(")", NAMES, "unbalanced")
    unknown("()", NAMES)


def test_trailing_tokens():
    unknown("selection keywords", NAMES, "trailing tokens", "'keywords'")
    unknown("selection not keywords", NAMES, "trailing tokens")
    unknown("1 of them selection", NAMES, "trailing tokens")


def test_aggregations_are_unknown():
    unknown("selection | count() > 5", NAMES, "aggregation", "count()")
    unknown("selection | count(User) by Computer > 3", NAMES, "aggregation")
    unknown("selection|count() > 1", NAMES, "aggregation")
    unknown("selection | near keywords", NAMES, "aggregation")


def test_near_is_unknown():
    unknown("selection near keywords", NAMES, "'near'")
    unknown("near", NAMES, "'near'")


def test_other_quantifiers_are_unknown():
    unknown("2 of them", NAMES, "only '1 of' and 'all of'", "'2 of'")
    unknown("0 of filter_*", NAMES, "only '1 of' and 'all of'")


def test_malformed_quantifiers():
    unknown("1 selection", NAMES, "expected 'of'")
    unknown("all selection", NAMES, "expected 'of'")
    unknown("1 of", NAMES, "unexpected end")
    unknown("1 of and", NAMES)
    unknown("all of (selection)", NAMES)
    unknown("them", NAMES, "unexpected keyword")
    unknown("of selection", NAMES, "unexpected keyword")


def test_empty_and_dangling_conditions():
    unknown("", NAMES, "empty condition")
    unknown("   ", NAMES, "empty condition")
    unknown("selection and", NAMES, "unexpected end")
    unknown("and selection", NAMES, "unexpected keyword")
    unknown("not", NAMES, "unexpected end")
    unknown("selection or ()", NAMES)


def test_unexpected_tokens():
    unknown("selection & keywords", NAMES, "trailing tokens", "'& keywords'")
    unknown("& keywords", NAMES, "unexpected token", "'&'")
    unknown("selection and 'keywords'", NAMES, "unexpected token")
    unknown("selection and =", NAMES, "unexpected token", "'='")


def test_them_without_selections():
    unknown("1 of them", (), "no selection")


def test_bad_inputs_never_raise():
    assert isinstance(parse(None, NAMES), Unknown)
    assert isinstance(parse(["selection"], NAMES), Unknown)
    assert isinstance(parse("selection", None), Unknown)
    assert isinstance(parse("selection", [1, 2]), Unknown)
    deep = "(" * 5000 + "selection" + ")" * 5000
    result = parse(deep, NAMES)
    assert result == ident("selection") or isinstance(result, Unknown)


# --- references --------------------------------------------------------------------------

def test_references():
    assert references(parse("selection and not 1 of filter_*", NAMES)) == {
        "selection", "filter_admin", "filter_system"}
    assert references(parse("keywords", NAMES)) == {"keywords"}
    assert references(parse("all of them", NAMES)) == set(NAMES)
    assert references(Unknown("x")) == frozenset()


# --- E3: three-valued logic -----------------------------------------------------------------

VALUES = (True, False, U)


def expected_and(values):
    if any(v is False for v in values):
        return False
    if any(isinstance(v, Unknown) for v in values):
        return U
    return True


def expected_or(values):
    if any(v is True for v in values):
        return True
    if any(isinstance(v, Unknown) for v in values):
        return U
    return False


def same(actual, expected):
    if isinstance(expected, Unknown):
        return isinstance(actual, Unknown)
    return actual is expected


@pytest.mark.parametrize("a,b", list(itertools.product(VALUES, VALUES)))
def test_binary_truth_table(a, b):
    results = {"a": a, "b": b}
    assert same(evaluate(parse("a and b", ("a", "b")), results), expected_and((a, b)))
    assert same(evaluate(parse("a or b", ("a", "b")), results), expected_or((a, b)))


@pytest.mark.parametrize("a", VALUES)
def test_not_truth_table(a):
    result = evaluate(parse("not a", ("a",)), {"a": a})
    if isinstance(a, Unknown):
        assert isinstance(result, Unknown)
    else:
        assert result is (not a)


@pytest.mark.parametrize("a,b,c", list(itertools.product(VALUES, VALUES, VALUES)))
def test_ternary_chains(a, b, c):
    names = ("a", "b", "c")
    results = {"a": a, "b": b, "c": c}
    assert same(evaluate(parse("a and b and c", names), results), expected_and((a, b, c)))
    assert same(evaluate(parse("a or b or c", names), results), expected_or((a, b, c)))
    assert same(evaluate(parse("all of them", names), results), expected_and((a, b, c)))
    assert same(evaluate(parse("1 of them", names), results), expected_or((a, b, c)))
    # a or (b and c)
    assert same(evaluate(parse("a or b and c", names), results), expected_or((a, expected_and((b, c)))))


def test_unknown_reason_propagates():
    result = evaluate(parse("a and b", ("a", "b")), {"a": True, "b": Unknown("why")})
    assert result == Unknown("why")
    result = evaluate(parse("not (a or b)", ("a", "b")), {"a": False, "b": Unknown("why")})
    assert result == Unknown("why")


def test_missing_or_malformed_results_are_unknown():
    ast = parse("a and b", ("a", "b"))
    result = evaluate(ast, {"a": True})
    assert isinstance(result, Unknown) and "no result" in result.reason
    result = evaluate(ast, {"a": True, "b": 1})
    assert isinstance(result, Unknown) and "not True, False or Unknown" in result.reason
    result = evaluate(ast, {"a": True, "b": None})
    assert isinstance(result, Unknown)
    assert isinstance(evaluate(ast, None), Unknown)
    assert isinstance(evaluate(Unknown("parse failed"), {}), Unknown)
    assert isinstance(evaluate(("bogus", 1), {}), Unknown)
    assert isinstance(evaluate("not an ast", {}), Unknown)


def test_evaluate_a_false_beats_a_missing_result():
    # Unknown and False = False, so a missing result need not be fetched.
    ast = parse("a and b", ("a", "b"))
    assert evaluate(ast, {"a": False}) is False


# --- E4: evaluate_rule over loader + matcher ------------------------------------------------

def rule_from(detection, path="inline.yml"):
    raw = {
        "title": "Inline rule",
        "id": "6f1d2c3e-4b5a-4c6d-8e7f-9a0b1c2d3e4f",
        "logsource": {"product": "windows"},
        "detection": detection,
        "level": "low",
        "x-mizan": {"fp_budget": 1},
    }
    return loader.Rule(
        title=raw["title"], id=raw["id"], logsource=raw["logsource"],
        detection=detection, condition=detection["condition"], level="low",
        fp_budget=1.0, corpus=None, raw=raw, path=path)


EVENT = {"Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd.exe /c whoami",
         "User": "EXAMPLE\\alice", "EventID": 4688}


def test_evaluate_rule_from_fixture_file():
    rule = loader.load(str(ROOT / "tests" / "fixtures" / "rules" / "valid.yml"))
    assert isinstance(rule, loader.Rule)
    matching = {"Image": "C:\\Tools\\powershell.exe", "CommandLine": "powershell -enc AAAA",
                "User": "EXAMPLE\\bob"}
    assert evaluate_rule(rule, matching) is True
    filtered = dict(matching, User="EXAMPLE\\svc-deploy")
    assert evaluate_rule(rule, filtered) is False
    other = dict(matching, Image="C:\\Windows\\cmd.exe")
    assert evaluate_rule(rule, other) is False


def test_evaluate_rule_true_false():
    rule = rule_from({
        "selection": {"Image|endswith": "\\cmd.exe"},
        "filter": {"User|endswith": "\\svc-deploy"},
        "condition": "selection and not filter",
    })
    assert evaluate_rule(rule, EVENT) is True
    assert evaluate_rule(rule, dict(EVENT, User="EXAMPLE\\svc-deploy")) is False
    assert evaluate_rule(rule, dict(EVENT, Image="x.exe")) is False


def test_evaluate_rule_with_quantifiers_and_keywords():
    rule = rule_from({
        "selection": {"EventID": 4688},
        "filter_a": {"User|contains": "svc-"},
        "filter_b": {"CommandLine|contains": "hostname"},
        "keywords": ["whoami"],
        "condition": "selection and keywords and not 1 of filter_*",
    })
    assert evaluate_rule(rule, EVENT) is True
    assert evaluate_rule(rule, dict(EVENT, CommandLine="cmd.exe /c hostname")) is False
    assert evaluate_rule(rule, dict(EVENT, User="svc-x")) is False
    assert evaluate_rule(rule, dict(EVENT, EventID=1)) is False


def test_unreferenced_selections_are_not_evaluated(monkeypatch):
    calls = []
    original = condition.matcher.compile_selection

    def spy(selection):
        calls.append(selection)
        return original(selection)

    monkeypatch.setattr(condition.matcher, "compile_selection", spy)
    rule = rule_from({
        "selection": {"EventID": 4688},
        "unused_bad": {"Image|base64": "x"},  # unsupported, but never referenced
        "unused_ok": {"Image": "y"},
        "condition": "selection",
    })
    assert evaluate_rule(rule, EVENT) is True
    assert calls == [{"EventID": 4688}]


def test_referenced_unsupported_selection_makes_the_rule_unknown():
    # Even when short-circuit logic would never need it (A4).
    rule = rule_from({
        "selection": {"EventID": 1},
        "filter": {"Image|base64": "x"},
        "condition": "selection and filter",
    })
    result = evaluate_rule(rule, EVENT)
    assert isinstance(result, Unknown)
    assert "filter" in result.reason and "base64" in result.reason


def test_unsupported_condition_makes_the_rule_unknown():
    rule = rule_from({"selection": {"EventID": 4688}, "condition": "selection | count() > 3"})
    result = evaluate_rule(rule, EVENT)
    assert isinstance(result, Unknown) and "aggregation" in result.reason
    rule = rule_from({"selection": {"EventID": 4688}, "condition": "selection and missing"})
    result = evaluate_rule(rule, EVENT)
    assert isinstance(result, Unknown) and "'missing'" in result.reason


def test_evaluate_rule_on_bad_event_and_bad_rule():
    rule = rule_from({"selection": {"EventID": 4688}, "condition": "selection"})
    assert isinstance(evaluate_rule(rule, "not an event"), Unknown)
    assert isinstance(evaluate_rule(rule, None), Unknown)
    problems = loader.load(str(ROOT / "tests" / "fixtures" / "rules" / "missing_title.yml"))
    result = evaluate_rule(problems, EVENT)
    assert isinstance(result, Unknown) and "invalid" in result.reason and "title" in result.reason
    assert isinstance(evaluate_rule(None, EVENT), Unknown)
    assert isinstance(evaluate_rule(object(), EVENT), Unknown)


def test_compile_rule_reuse():
    rule = rule_from({
        "selection": {"Image|endswith": "\\cmd.exe"},
        "keywords": ["whoami"],
        "condition": "selection and keywords",
    })
    compiled = condition.compile_rule(rule)
    assert isinstance(compiled, condition.CompiledRule)
    assert compiled.referenced == {"selection", "keywords"}
    assert compiled.evaluate(EVENT) is True
    assert compiled.evaluate({"Image": "a\\cmd.exe", "CommandLine": "x"}) is False
    assert compiled.evaluate({}) is False
    assert isinstance(compiled.evaluate([]), Unknown)
    unknown_rule = condition.compile_rule(rule_from({"s": {"a|base64": 1}, "condition": "s"}))
    assert isinstance(unknown_rule, Unknown)
