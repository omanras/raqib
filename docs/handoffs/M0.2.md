# HANDOFF — M0.2  (phase 0: matcher)

Task: implement `mizan/matcher.py`: evaluate one Sigma selection against one
event per docs/specs/ADR-0001 §4-§5.

Scope:
  mizan/matcher.py
  tests/test_matcher.py
  tests/fixtures/
  docs/review/

Exit criteria:
- E1 `matcher.match_selection(selection, event)` returns True, False, or an
     `Unknown(reason)` value (never raises on bad data).
- E2 Mapping selections: AND across fields, OR across a value list, `all`
     modifier turns the list into AND; keyword list selections: any string
     value anywhere in the event (nested too) contains the keyword.
- E3 Case-insensitive comparison; `*` and `?` wildcards; backslash escapes;
     a value that is not a string compares as its JSON text; `null` matches
     absent or null; nested field by dotted path when the exact key is absent.
- E4 Modifiers contains, startswith, endswith, all, re, exists, gt, gte, lt,
     lte, cidr, windash behave as in ADR §5; any other modifier -> Unknown
     naming it; `re` with an invalid pattern -> Unknown.
- E5 Tests cover every modifier with a positive and a negative event, the
     wildcard escapes, nested paths, Unknown cases; gate green.

Not in scope: the condition grammar (M0.3), fixtures, CLI.
Commit: `landed: M0.2 matcher` or `STOP: M0.2 <reason>`.
Read HANDOFF.md and do only the task it specifies.
