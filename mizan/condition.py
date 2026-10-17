"""Parse and evaluate a Sigma ``condition`` (ADR-0001 section 5).

Grammar (precedence ``not`` > ``and`` > ``or``)::

    expr      := and_expr ( 'or' and_expr )*
    and_expr  := not_expr ( 'and' not_expr )*
    not_expr  := 'not' not_expr | primary
    primary   := '(' expr ')' | quantified | IDENT
    quantified:= ( '1' | 'all' ) 'of' ( 'them' | PATTERN )
    PATTERN   := IDENT with an optional trailing '*'

``parse(text, selection_names)`` returns an AST or ``Unknown(reason)``.
The AST is made of tuples: ``('id', name)``, ``('not', node)``,
``('and', (nodes...))``, ``('or', (nodes...))``; ``1 of`` / ``all of`` are
desugared into ``or`` / ``and`` over the selections they match.

Everything outside the grammar is ``Unknown`` naming the cause: an
identifier that is not a selection, a pattern matching no selection,
unbalanced parentheses, trailing tokens, aggregations (``| count() ...``),
``near``, other quantifiers (``2 of``), keywords in another case.

``evaluate(ast, results)`` applies three-valued logic over per-selection
results (True, False or Unknown): Unknown and False = False, Unknown or
True = True, otherwise Unknown propagates.

``evaluate_rule(rule, event)`` ties loader, matcher and condition together.
Every selection the condition references is compiled first; if any is
unsupported the rule is Unknown whatever the event says (A4).  Selections
the condition does not reference are never evaluated.
"""

import re
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Tuple

from mizan import matcher
from mizan.matcher import Unknown

__all__ = ["Unknown", "parse", "references", "evaluate", "compile_rule",
           "evaluate_rule", "CompiledRule"]

_TOKEN_RE = re.compile(r"\s*(\(|\)|\||[^\s()|]+)")
_KEYWORDS = frozenset(("and", "or", "not", "of", "them", "all", "1"))
_IDENT_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_PATTERN_RE = re.compile(r"^[A-Za-z0-9_.-]*\*$")
_OTHER_QUANTIFIER_RE = re.compile(r"^[0-9]+$")


# --- tokens --------------------------------------------------------------------------

def _tokenize(text: str):
    """A list of tokens, or Unknown.  Operators are matched case-sensitively:
    ``AND`` is an identifier and will be reported as not a selection."""
    tokens: List[str] = []
    pos = 0
    length = len(text)
    while pos < length:
        match = _TOKEN_RE.match(text, pos)
        if match is None:
            break  # only trailing whitespace remains
        tokens.append(match.group(1))
        pos = match.end()
    if "|" in tokens:
        tail = text[text.index("|"):].strip()
        return Unknown("aggregation expressions are not supported: %r" % tail)
    if "near" in tokens:
        return Unknown("'near' is not supported")
    return tokens


# --- parser -----------------------------------------------------------------------------

class _Parser:
    def __init__(self, tokens: List[str], names: Tuple[str, ...]):
        self.tokens = tokens
        self.names = names
        self.pos = 0

    # helpers
    def peek(self) -> Optional[str]:
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return None

    def take(self) -> Optional[str]:
        token = self.peek()
        if token is not None:
            self.pos += 1
        return token

    # grammar
    def parse_or(self):
        left = self.parse_and()
        if isinstance(left, Unknown):
            return left
        parts = [left]
        while self.peek() == "or":
            self.take()
            right = self.parse_and()
            if isinstance(right, Unknown):
                return right
            parts.append(right)
        if len(parts) == 1:
            return left
        return ("or", tuple(parts))

    def parse_and(self):
        left = self.parse_not()
        if isinstance(left, Unknown):
            return left
        parts = [left]
        while self.peek() == "and":
            self.take()
            right = self.parse_not()
            if isinstance(right, Unknown):
                return right
            parts.append(right)
        if len(parts) == 1:
            return left
        return ("and", tuple(parts))

    def parse_not(self):
        if self.peek() == "not":
            self.take()
            operand = self.parse_not()
            if isinstance(operand, Unknown):
                return operand
            return ("not", operand)
        return self.parse_primary()

    def parse_primary(self):
        token = self.take()
        if token is None:
            return Unknown("unexpected end of condition: an expression is missing")
        if token == "(":
            inner = self.parse_or()
            if isinstance(inner, Unknown):
                return inner
            if self.take() != ")":
                return Unknown("unbalanced parentheses: missing ')'")
            return inner
        if token == ")":
            return Unknown("unbalanced parentheses: unexpected ')'")
        if token in ("1", "all"):
            return self.parse_quantified(token)
        if _OTHER_QUANTIFIER_RE.match(token) and self.peek() == "of":
            return Unknown("only '1 of' and 'all of' are supported, got %r" % ("%s of" % token))
        if token in _KEYWORDS:
            return Unknown("unexpected keyword %r" % token)
        if token.lower() in _KEYWORDS and token not in self.names:
            return Unknown("keyword %r must be lowercase (%r)" % (token, token.lower()))
        if "*" in token:
            return Unknown("pattern %r is only valid after '1 of' or 'all of'" % token)
        if not _IDENT_RE.match(token):
            return Unknown("unexpected token %r" % token)
        if token not in self.names:
            return Unknown("identifier %r is not a selection of this rule" % token)
        return ("id", token)

    def parse_quantified(self, quantifier: str):
        token = self.take()
        if token != "of":
            if token is None:
                return Unknown("expected 'of' after %r, got the end of the condition" % quantifier)
            return Unknown("expected 'of' after %r, got %r" % (quantifier, token))
        target = self.take()
        if target is None:
            return Unknown("unexpected end of condition after '%s of'" % quantifier)
        if target == "them":
            matched = list(self.names)
            if not matched:
                return Unknown("'%s of them' but the rule has no selection" % quantifier)
        elif _PATTERN_RE.match(target):
            prefix = target[:-1]
            matched = [name for name in self.names if name.startswith(prefix)]
            if not matched:
                return Unknown("pattern %r matches no selection of this rule" % target)
        elif "*" in target:
            return Unknown("pattern %r is not supported: only a trailing '*' is" % target)
        elif _IDENT_RE.match(target):
            if target not in self.names:
                return Unknown("pattern %r matches no selection of this rule" % target)
            matched = [target]
        else:
            return Unknown("unexpected token %r after '%s of'" % (target, quantifier))
        nodes = tuple(("id", name) for name in matched)
        if len(nodes) == 1:
            return nodes[0]
        return ("or" if quantifier == "1" else "and", nodes)


def parse(text: Any, selection_names: Iterable[str]):
    """Parse ``text`` over ``selection_names``; an AST tuple or Unknown."""
    if not isinstance(text, str):
        return Unknown("condition must be a string (got %s)" % type(text).__name__)
    try:
        names = tuple(selection_names)
    except TypeError:
        return Unknown("selection names must be an iterable of strings")
    if not all(isinstance(name, str) for name in names):
        return Unknown("selection names must be strings")
    tokens = _tokenize(text)
    if isinstance(tokens, Unknown):
        return tokens
    if not tokens:
        return Unknown("empty condition")
    parser = _Parser(tokens, names)
    try:
        ast = parser.parse_or()
    except RecursionError:
        return Unknown("condition is nested too deeply")
    if isinstance(ast, Unknown):
        return ast
    if parser.pos < len(tokens):
        first = tokens[parser.pos]
        rest = " ".join(tokens[parser.pos:])
        if first == ")":
            return Unknown("unbalanced parentheses: unexpected ')'")
        if first.lower() in ("and", "or", "not") and first != first.lower() and first not in names:
            return Unknown("keyword %r must be lowercase (%r)" % (first, first.lower()))
        return Unknown("trailing tokens after the expression: %r" % rest)
    return ast


def references(ast: Any) -> FrozenSet[str]:
    """The selection names an AST refers to."""
    names = set()
    stack = [ast]
    while stack:
        node = stack.pop()
        if not isinstance(node, tuple) or not node:
            continue
        kind = node[0]
        if kind == "id":
            names.add(node[1])
        elif kind == "not":
            stack.append(node[1])
        elif kind in ("and", "or"):
            stack.extend(node[1])
    return frozenset(names)


# --- evaluation -----------------------------------------------------------------------------

def _result_of(results, name: str):
    try:
        value = results[name]
    except (KeyError, TypeError):
        return Unknown("no result for selection %r" % name)
    if value is True or value is False or isinstance(value, Unknown):
        return value
    return Unknown("result for selection %r is not True, False or Unknown (got %r)" % (name, value))


def evaluate(ast: Any, results):
    """Three-valued evaluation of ``ast`` over ``results`` (name -> True |
    False | Unknown).  Returns True, False or Unknown; never raises."""
    try:
        return _evaluate(ast, results)
    except RecursionError:
        return Unknown("condition is nested too deeply")
    except Exception as exc:  # never raise
        return Unknown("condition error: %s: %s" % (type(exc).__name__, exc))


def _evaluate(node: Any, results):
    if isinstance(node, Unknown):
        return node
    if not isinstance(node, tuple) or len(node) != 2:
        return Unknown("malformed condition AST node %r" % (node,))
    kind, payload = node
    if kind == "id":
        return _result_of(results, payload)
    if kind == "not":
        value = _evaluate(payload, results)
        if isinstance(value, Unknown):
            return value
        return not value
    if kind == "and":
        unknown = None
        for child in payload:
            value = _evaluate(child, results)
            if value is False:
                return False
            if isinstance(value, Unknown) and unknown is None:
                unknown = value
        return unknown if unknown is not None else True
    if kind == "or":
        unknown = None
        for child in payload:
            value = _evaluate(child, results)
            if value is True:
                return True
            if isinstance(value, Unknown) and unknown is None:
                unknown = value
        return unknown if unknown is not None else False
    return Unknown("malformed condition AST node %r" % (node,))


# --- rules ------------------------------------------------------------------------------------

class _LazyResults:
    """Evaluates referenced selections on demand, once per event."""

    __slots__ = ("compiled", "event", "cache")

    def __init__(self, compiled: Dict[str, Any], event: Any):
        self.compiled = compiled
        self.event = event
        self.cache: Dict[str, Any] = {}

    def __getitem__(self, name: str):
        if name not in self.cache:
            self.cache[name] = self.compiled[name].match(self.event)
        return self.cache[name]


class CompiledRule:
    """A rule whose condition is parsed and whose referenced selections are
    compiled; ``evaluate(event)`` many times."""

    __slots__ = ("ast", "compiled", "referenced")

    def __init__(self, ast, compiled: Dict[str, Any]):
        self.ast = ast
        self.compiled = compiled
        self.referenced = frozenset(compiled)

    def evaluate(self, event: Any):
        if not isinstance(event, dict):
            return Unknown("event is not a JSON object (got %s)" % type(event).__name__)
        return evaluate(self.ast, _LazyResults(self.compiled, event))


def compile_rule(rule: Any):
    """Parse the rule's condition and compile every referenced selection.
    A ``CompiledRule``, or Unknown naming the first unsupported feature."""
    try:
        if isinstance(rule, list):  # loader.Problems
            return Unknown("rule is invalid: %s" % "; ".join(
                "%s: %s" % (getattr(p, "field", "?"), getattr(p, "reason", p)) for p in rule))
        detection = getattr(rule, "detection", None)
        condition = getattr(rule, "condition", None)
        if not isinstance(detection, dict):
            return Unknown("rule has no detection mapping")
        selections = {k: v for k, v in detection.items() if k != "condition"}
        ast = parse(condition, selections.keys())
        if isinstance(ast, Unknown):
            return Unknown("condition: %s" % ast.reason)
        compiled = {}
        for name in sorted(references(ast)):
            selection = matcher.compile_selection(selections[name])
            if isinstance(selection, Unknown):
                return Unknown("selection %r: %s" % (name, selection.reason))
            compiled[name] = selection
        return CompiledRule(ast, compiled)
    except Exception as exc:  # never raise
        return Unknown("rule error: %s: %s" % (type(exc).__name__, exc))


def evaluate_rule(rule: Any, event: Any):
    """True, False or Unknown for one rule on one event.  Only the selections
    the condition references are evaluated."""
    compiled = compile_rule(rule)
    if isinstance(compiled, Unknown):
        return compiled
    return compiled.evaluate(event)
