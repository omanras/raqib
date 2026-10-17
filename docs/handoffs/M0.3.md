# HANDOFF — M0.3  (phase 0: condition)

Task: implement `mizan/condition.py`: parse a Sigma `condition` string and
evaluate it over per-selection results per docs/specs/ADR-0001 §5.

Scope:
  mizan/condition.py
  tests/test_condition.py
  docs/review/

Exit criteria:
- E1 `condition.parse(text, selection_names)` returns an AST or
     `Unknown(reason)`: identifiers, and/or/not, parentheses, `1 of X*`,
     `all of X*`, `1 of them`, `all of them`; precedence not > and > or.
- E2 An identifier not in selection_names, a pattern matching no selection,
     unbalanced parentheses, trailing tokens, `| count` or any aggregation,
     and `near` -> Unknown naming the cause.
- E3 `condition.evaluate(ast, results)` where results maps selection name ->
     True | False | Unknown: three-valued logic (Unknown and False = False;
     Unknown or True = True; otherwise Unknown propagates).
- E4 `condition.evaluate_rule(rule, event)` ties loader + matcher + condition:
     runs every selection the condition references, returns True, False or
     Unknown; selections not referenced are not evaluated.
- E5 Tests for every grammar form, precedence, each Unknown cause, and the
     three-valued table; gate green.

Not in scope: fixtures, corpus, CLI.
Commit: `landed: M0.3 condition` or `STOP: M0.3 <reason>`.
Read HANDOFF.md and do only the task it specifies.
