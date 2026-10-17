"""Tests for mizan.matcher (HANDOFF M0.2, ADR-0001 sections 4-5).

Every modifier has a positive and a negative event; wildcards and their
escapes, nested paths, JSON-text comparison, null, keyword selections and
every Unknown cause are covered.  ``match_selection`` never raises.
"""

import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from mizan import matcher  # noqa: E402
from mizan.matcher import Unknown, match_selection  # noqa: E402

EVENT = {
    "Image": "C:\\Windows\\System32\\cmd.exe",
    "CommandLine": "cmd.exe /c whoami -all",
    "EventID": 4688,
    "Size": "2048",
    "Ratio": 0.5,
    "SourceIp": "10.1.2.3",
    "SourceIp6": "2001:db8::10",
    "Enabled": True,
    "Nothing": None,
    "Tags": ["alpha", "Beta"],
    "process": {"parent": {"name": "explorer.exe", "pid": 7}},
    "a.b": "flat",
}


def is_unknown(result, *parts):
    assert isinstance(result, Unknown), "expected Unknown, got %r" % (result,)
    for part in parts:
        assert part in result.reason, "reason %r lacks %r" % (result.reason, part)
    return True


def yes(selection, event=EVENT):
    result = match_selection(selection, event)
    assert result is True, "%r -> %r, expected True" % (selection, result)


def no(selection, event=EVENT):
    result = match_selection(selection, event)
    assert result is False, "%r -> %r, expected False" % (selection, result)


# --- Unknown value ----------------------------------------------------------------

def test_unknown_has_reason_equality_and_no_truth_value():
    u = Unknown("because")
    assert u.reason == "because"
    assert u == Unknown("because")
    assert u != Unknown("other")
    assert u != True and u != False  # noqa: E712
    assert repr(u) == "Unknown('because')"
    assert hash(u) == hash(Unknown("because"))
    with pytest.raises(TypeError):
        bool(u)


# --- E2: mapping selections -------------------------------------------------------

def test_mapping_is_and_across_fields():
    yes({"Image|endswith": "\\cmd.exe", "EventID": 4688})
    no({"Image|endswith": "\\cmd.exe", "EventID": 1})
    no({"Image|endswith": "\\powershell.exe", "EventID": 4688})


def test_value_list_is_or():
    yes({"CommandLine|contains": ["nothing", "whoami"]})
    no({"CommandLine|contains": ["nothing", "nobody"]})


def test_all_modifier_turns_list_into_and():
    yes({"CommandLine|contains|all": ["whoami", "-all"]})
    no({"CommandLine|contains|all": ["whoami", "-none"]})
    yes({"CommandLine|all|contains": ["whoami", "cmd"]})
    yes({"EventID|all": 4688})  # all on a single value is the value itself


# --- E2: keyword selections -------------------------------------------------------

def test_keyword_matches_any_string_value_anywhere():
    yes(["whoami"])
    yes(["WHOAMI"])
    yes(["explorer.exe"])  # nested object
    yes(["beta"])  # inside an array
    yes(["nothing-here", "cmd.exe"])  # OR across keywords
    no(["nothing-here"])


def test_keyword_search_is_contains_with_wildcards():
    yes(["who*all"])
    yes(["wh?ami"])
    no(["who\\*all"])


def test_keyword_search_looks_at_string_values_only():
    no(["4688"])  # EventID is a number, not a string value
    no(["true"])
    no(["Image"])  # keys are not values


def test_keyword_list_with_non_string_is_unknown():
    is_unknown(match_selection(["cmd", 4688], EVENT), "keyword 2", "string")
    is_unknown(match_selection([{"Image": "x"}], EVENT), "list of mappings")
    is_unknown(match_selection([None], EVENT), "keyword 1")


# --- E3: comparison rules ---------------------------------------------------------

def test_comparison_is_case_insensitive():
    yes({"Image": "c:\\windows\\system32\\CMD.EXE"})
    yes({"Image|contains": "SYSTEM32"})
    yes({"Image|startswith": "c:\\WIN"})
    yes({"Image|endswith": "\\Cmd.Exe"})


def test_plain_value_is_a_full_match():
    no({"Image": "cmd.exe"})
    no({"Image": "C:\\Windows\\System32\\cmd.ex"})
    yes({"Image": "C:\\Windows\\System32\\cmd.exe"})


def test_wildcards():
    yes({"Image": "*\\cmd.exe"})
    # In Sigma, "\*" is a literal star; a backslash before a wildcard is
    # written "\\*" (escaped backslash, then the wildcard).
    yes({"Image": "C:\\\\*\\cmd.exe"})
    no({"Image": "C:\\*\\cmd.exe"})
    yes({"Image": "C:\\Windows\\System32\\cmd.ex?"})
    no({"Image": "C:\\Windows\\System32\\cmd.ex??"})
    yes({"Image": "*"})
    yes({"CommandLine": "cmd.exe*whoami*"})
    yes({"CommandLine": "*whoami -all"})


def test_wildcard_star_matches_across_newlines():
    yes({"Text": "a*b"}, {"Text": "a\n\nb"})


def test_backslash_escapes_star_question_and_backslash():
    event = {"s": "a*b", "q": "a?b", "b": "a\\b", "bb": "a\\\\b", "x": "aXb"}
    yes({"s": "a\\*b"}, event)
    no({"q": "a\\*b"}, event)
    yes({"q": "a\\?b"}, event)
    no({"x": "a\\?b"}, event)
    yes({"x": "a?b"}, event)
    yes({"b": "a\\\\b"}, event)
    no({"bb": "a\\\\b"}, event)
    yes({"bb": "a\\\\\\\\b"}, event)


def test_backslash_before_other_character_is_literal():
    event = {"p": "C:\\Temp\\x", "d": "a-b", "e": "a\\-b"}
    yes({"p": "C:\\Temp\\x"}, event)
    no({"p": "C:\\Temp\\*"}, event)  # "\*" is a literal star
    yes({"p": "C:\\Temp\\\\*"}, event)  # "\\*" is a backslash then a wildcard
    no({"d": "a\\-b"}, event)  # "\-" is a backslash followed by a dash
    yes({"e": "a\\-b"}, event)


def test_non_string_event_values_compare_as_json_text():
    yes({"EventID": 4688})
    yes({"EventID": "4688"})
    yes({"EventID|startswith": "46"})
    yes({"EventID|contains": 68})
    yes({"Enabled": True})
    yes({"Enabled": "true"})
    yes({"Enabled": "TRUE"})
    no({"Enabled": "1"})
    yes({"Ratio": 0.5})
    yes({"Ratio": "0.5"})
    yes({"Nothing": "null"})
    yes({"Tags|contains": "alpha"})
    yes({"Tags": '["alpha","Beta"]'})
    no({"Tags": "alpha"})
    yes({"process|contains": '"pid":7'})


def test_null_matches_absent_or_null():
    yes({"Nothing": None})
    yes({"Absent": None})
    yes({"process.parent.missing": None})
    no({"Image": None})
    yes({"Image": [None, "*cmd.exe"]})
    yes({"Absent": [None, "x"]})


def test_null_with_a_modifier_is_unknown():
    is_unknown(match_selection({"Image|contains": None}, EVENT), "null")
    is_unknown(match_selection({"Image|windash": None}, EVENT), "null")


def test_nested_field_by_dotted_path():
    yes({"process.parent.name": "explorer.exe"})
    yes({"process.parent.pid": 7})
    yes({"process.parent.pid|gt": 6})
    no({"process.parent.name": "cmd.exe"})
    no({"process.child.name": "explorer.exe"})
    no({"process.parent.name.deeper": "x"})


def test_exact_key_wins_over_dotted_path():
    yes({"a.b": "flat"})
    event = {"a.b": "flat", "a": {"b": "nested"}}
    yes({"a.b": "flat"}, event)
    no({"a.b": "nested"}, event)


def test_lookup_field_helper():
    assert matcher.lookup_field(EVENT, "EventID") == 4688
    assert matcher.lookup_field(EVENT, "process.parent.pid") == 7
    assert matcher.lookup_field(EVENT, "process.parent.x") is matcher.MISSING
    assert matcher.lookup_field(EVENT, "Missing") is matcher.MISSING
    assert matcher.lookup_field(EVENT, "Nothing") is None


# --- E4: every modifier, positive and negative --------------------------------------

def test_contains():
    yes({"CommandLine|contains": "whoami"})
    no({"CommandLine|contains": "hostname"})


def test_startswith():
    yes({"CommandLine|startswith": "cmd.exe"})
    no({"CommandLine|startswith": "whoami"})


def test_endswith():
    yes({"CommandLine|endswith": "-all"})
    no({"CommandLine|endswith": "cmd.exe"})


def test_all():
    yes({"Tags|contains|all": ["alpha", "beta"]})
    no({"Tags|contains|all": ["alpha", "gamma"]})


def test_re_is_case_sensitive_search():
    yes({"Image|re": "cmd\\.exe$"})
    no({"Image|re": "CMD\\.exe$"})
    yes({"Image|re": "System32"})
    no({"Image|re": "^cmd"})
    yes({"EventID|re": "^46"})


def test_re_with_i_is_case_insensitive():
    yes({"Image|re|i": "CMD\\.EXE$"})
    no({"Image|re|i": "^CMD"})


def test_re_invalid_pattern_is_unknown():
    is_unknown(match_selection({"Image|re": "("}, EVENT), "invalid regular expression", "Image")
    is_unknown(match_selection({"Image|re": ["ok", "(bad"]}, EVENT), "invalid regular expression")
    is_unknown(match_selection({"Image|re": 7}, EVENT), "pattern string")


def test_exists():
    yes({"Image|exists": True})
    no({"Image|exists": False})
    yes({"Missing|exists": False})
    no({"Missing|exists": True})
    yes({"Nothing|exists": True})  # present with a null value exists
    yes({"process.parent.pid|exists": True})
    no({"process.parent.nope|exists": True})


def test_exists_needs_a_single_boolean():
    is_unknown(match_selection({"Image|exists": "yes"}, EVENT), "exists")
    is_unknown(match_selection({"Image|exists": [True]}, EVENT), "exists")
    is_unknown(match_selection({"Image|exists|all": True}, EVENT), "exists")


def test_gt_gte_lt_lte_on_numbers():
    yes({"EventID|gt": 4687})
    no({"EventID|gt": 4688})
    yes({"EventID|gte": 4688})
    no({"EventID|gte": 4689})
    yes({"EventID|lt": 4689})
    no({"EventID|lt": 4688})
    yes({"EventID|lte": 4688})
    no({"EventID|lte": 4687})
    yes({"Ratio|gt": 0.25})
    no({"Ratio|gt": 0.75})
    yes({"EventID|gt": [9000, 4000]})
    no({"EventID|gt|all": [9000, 4000]})


def test_numeric_modifiers_on_numeric_strings_and_non_numbers():
    yes({"Size|gt": 1024})  # "2048" is a JSON number literal in a string
    no({"Size|gt": 4096})
    no({"Image|gt": 1})  # not a number at all
    no({"Enabled|gt": 0})  # booleans are not numbers
    no({"Nothing|gt": 0})
    no({"Missing|gt": 0})
    no({"Tags|gt": 0})


def test_numeric_modifiers_need_a_number_in_the_rule():
    is_unknown(match_selection({"EventID|gt": "4000"}, EVENT), "gt", "number")
    is_unknown(match_selection({"EventID|lt": True}, EVENT), "lt", "number")
    is_unknown(match_selection({"EventID|gte": float("nan")}, EVENT), "gte")
    is_unknown(match_selection({"EventID|lte": None}, EVENT), "lte")


def test_cidr_v4_and_v6():
    yes({"SourceIp|cidr": "10.0.0.0/8"})
    no({"SourceIp|cidr": "192.168.0.0/16"})
    yes({"SourceIp|cidr": "10.1.2.3/32"})
    yes({"SourceIp|cidr": ["192.168.0.0/16", "10.0.0.0/8"]})
    yes({"SourceIp6|cidr": "2001:db8::/32"})
    no({"SourceIp6|cidr": "2001:db9::/32"})
    no({"SourceIp6|cidr": "10.0.0.0/8"})  # version mismatch
    no({"Image|cidr": "10.0.0.0/8"})  # not an address
    no({"EventID|cidr": "10.0.0.0/8"})
    no({"Missing|cidr": "10.0.0.0/8"})


def test_cidr_invalid_network_is_unknown():
    is_unknown(match_selection({"SourceIp|cidr": "10.0.0.0/33"}, EVENT), "invalid CIDR")
    is_unknown(match_selection({"SourceIp|cidr": "not a network"}, EVENT), "invalid CIDR")
    is_unknown(match_selection({"SourceIp|cidr": 10}, EVENT), "cidr")


def test_windash():
    yes({"CommandLine|contains|windash": "-all"})
    yes({"CommandLine|contains|windash": "/c"})
    no({"CommandLine|contains": "/all"})
    yes({"CommandLine|contains|windash": "-c whoami -all"})
    yes({"CommandLine|windash": "cmd.exe -c whoami -all"})
    # Only a dash in the rule value is widened; a slash stays a slash.
    no({"CommandLine|windash": "cmd.exe -c whoami /all"})
    no({"CommandLine|contains|windash": "-x"})
    no({"CommandLine|contains|windash": "-all -now"})
    yes({"CommandLine|endswith|windash": "-all"})
    no({"CommandLine|endswith|windash": "/all"})
    yes({"CommandLine|startswith|windash": "cmd.exe -c"})


def test_windash_combinations_that_are_unknown():
    is_unknown(match_selection({"Image|re|windash": "x"}, EVENT), "windash")
    is_unknown(match_selection({"EventID|gt|windash": 1}, EVENT), "windash")
    is_unknown(match_selection({"SourceIp|cidr|windash": "10.0.0.0/8"}, EVENT), "windash")


# --- E4: Unknown causes ----------------------------------------------------------------

@pytest.mark.parametrize("modifier", [
    "base64", "base64offset", "utf16le", "utf16be", "utf16", "wide", "expand",
    "fieldref", "cased", "m", "s", "minute", "hour", "contains_all", "CONTAINS",
])
def test_unsupported_modifier_is_unknown_and_named(modifier):
    result = match_selection({"Image|%s" % modifier: "x"}, EVENT)
    is_unknown(result, "unsupported modifier", repr(modifier), "Image")


def test_unsupported_modifier_dominates_the_selection():
    # The other field is False, but the selection is still unknown (A4).
    result = match_selection({"EventID": 1, "Image|base64": "x"}, EVENT)
    is_unknown(result, "base64")
    result = match_selection({"EventID": 4688, "Image|base64": "x"}, EVENT)
    is_unknown(result, "base64")


def test_modifier_combinations_that_are_unknown():
    is_unknown(match_selection({"Image|contains|startswith": "x"}, EVENT), "cannot be combined")
    is_unknown(match_selection({"Image|contains|contains": "x"}, EVENT), "repeated")
    is_unknown(match_selection({"Image|i": "x"}, EVENT), "'i'", "re")
    is_unknown(match_selection({"Image|exists|contains": True}, EVENT), "cannot be combined")
    is_unknown(match_selection({"Image|gt|lt": 1}, EVENT), "cannot be combined")


def test_bad_field_specs_are_unknown():
    is_unknown(match_selection({"|contains": "x"}, EVENT), "empty field name")
    is_unknown(match_selection({7: "x"}, EVENT), "field name must be a string")
    is_unknown(match_selection({"Image": []}, EVENT), "empty value list")
    is_unknown(match_selection({"Image": {"nested": "map"}}, EVENT), "unsupported value type")
    is_unknown(match_selection({"Image": [["nested"]]}, EVENT), "unsupported value type")


def test_bad_selection_shapes_are_unknown():
    is_unknown(match_selection({}, EVENT), "empty selection")
    is_unknown(match_selection([], EVENT), "empty keyword list")
    is_unknown(match_selection("selection", EVENT), "mapping or a list")
    is_unknown(match_selection(42, EVENT), "mapping or a list")
    is_unknown(match_selection(None, EVENT), "mapping or a list")


def test_bad_event_is_unknown_not_an_exception():
    is_unknown(match_selection({"Image": "x"}, None), "not a JSON object")
    is_unknown(match_selection({"Image": "x"}, "text"), "not a JSON object")
    is_unknown(match_selection({"Image": "x"}, ["list"]), "not a JSON object")
    is_unknown(match_selection(["kw"], 5), "not a JSON object")


def test_never_raises_on_odd_data():
    class Odd:
        def __repr__(self):
            return "<odd>"
    odd = Odd()
    for selection in ({"Image": odd}, {"Image|re": odd}, {odd: "x"}, [odd], odd):
        result = match_selection(selection, EVENT)
        assert isinstance(result, Unknown)
    result = match_selection({"Image|contains": "x"}, {"Image": odd})
    assert result is False
    result = match_selection({"Image": "<odd>"}, {"Image": odd})
    assert result is True


def test_empty_event_and_deep_nesting():
    no({"Image": "x"}, {})
    yes({"Image": None}, {})
    no(["x"], {})
    deep = {"k": "v"}
    for _ in range(3000):
        deep = {"n": deep}
    yes(["v"], deep)
    no(["w"], deep)


# --- compile_selection ---------------------------------------------------------------------

def test_compile_selection_reuses_across_events():
    compiled = matcher.compile_selection({"Image|endswith": "\\cmd.exe", "EventID|gte": 4000})
    assert isinstance(compiled, matcher.CompiledSelection)
    assert compiled.match(EVENT) is True
    assert compiled.match({"Image": "x\\cmd.exe", "EventID": 3999}) is False
    assert compiled.match({"Image": "x\\cmd.exe", "EventID": "4001"}) is True
    assert isinstance(compiled.match("not an event"), Unknown)
    assert isinstance(matcher.compile_selection({"Image|base64": "x"}), Unknown)
    keywords = matcher.compile_selection(["whoami"])
    assert keywords.match(EVENT) is True
    assert keywords.match({"x": {"y": ["nope"]}}) is False


def test_cache_does_not_change_answers_for_non_json_selections():
    import datetime
    result = match_selection({"Image": datetime.date(2026, 10, 17)}, EVENT)
    is_unknown(result, "unsupported value type")
    result = match_selection({1: "x"}, EVENT)
    is_unknown(result, "field name must be a string")
    result = match_selection({"Image": ("tuple",)}, EVENT)
    is_unknown(result, "unsupported value type")


def test_known_modifiers_set():
    assert matcher.KNOWN_MODIFIERS == {
        "contains", "startswith", "endswith", "all", "re", "i", "exists",
        "gt", "gte", "lt", "lte", "cidr", "windash",
    }
