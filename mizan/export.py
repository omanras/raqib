"""Export a Sigma rule to a target query language through pySigma
(ADR-0001 sections 2, 9; A6).

This is the only module of Mizan allowed to import ``sigma`` (pySigma), and
it does so lazily, inside ``load_adapter``: ``check``, ``test``, ``match``
and ``corpus`` never touch it, and Mizan works without pySigma installed.
Export makes no network call; pySigma backends are pure converters.

    python3 -m mizan export RULE.yml --target splunk|elastic [--json]

A missing package is reported as ``MissingDependency`` with the exact
``pip install`` line; the CLI turns it into exit code 3 and one line.
"""

import importlib
from typing import Any, Callable, Dict, Optional

from mizan.loader import Problems, Rule

PYSIGMA_PACKAGE = "pysigma"
PYSIGMA_MODULE = "sigma"

#: target -> (pip package, module, backend class)
TARGETS: Dict[str, Dict[str, str]] = {
    "splunk": {"package": "pysigma-backend-splunk", "module": "sigma.backends.splunk",
               "backend": "SplunkBackend"},
    "elastic": {"package": "pysigma-backend-elasticsearch", "module": "sigma.backends.elasticsearch",
                "backend": "LuceneBackend"},
}

#: Keys that belong to Mizan, not to Sigma; they are removed before export.
MIZAN_KEYS = ("x-mizan",)


class ExportError(Exception):
    """The rule could not be converted; the message is for the user."""


class MissingDependency(ExportError):
    """pySigma or a backend package is not installed."""

    def __init__(self, target: str, packages):
        self.target = target
        self.packages = list(packages)
        self.pip = "pip install %s" % " ".join(self.packages)
        super().__init__("export to %s needs pySigma: %s" % (target, self.pip))


class UnknownTarget(ExportError):
    def __init__(self, target: str):
        self.target = target
        super().__init__("unknown target %r (known: %s)" % (target, ", ".join(sorted(TARGETS))))


def _import_module(name: str):
    """Indirection so tests can simulate an absent package."""
    return importlib.import_module(name)


def _distribution_version(package: str) -> str:
    try:
        from importlib import metadata
        return metadata.version(package)
    except Exception:  # not installed as a distribution (vendored, editable...)
        return "unknown"


class PySigmaAdapter:
    """Converts a rule mapping with a pySigma backend.

    ``convert(rule_dict)`` returns the query string; ``version`` is the
    backend package version.  Constructing it imports pySigma.
    """

    def __init__(self, target: str):
        spec = TARGETS.get(target)
        if spec is None:
            raise UnknownTarget(target)
        self.target = target
        self.spec = spec
        try:
            self._sigma_rule = _import_module("sigma.rule")
            self._sigma_collection = _import_module("sigma.collection")
        except ImportError:
            raise MissingDependency(target, [PYSIGMA_PACKAGE, spec["package"]])
        try:
            module = _import_module(spec["module"])
        except ImportError:
            raise MissingDependency(target, [spec["package"]])
        try:
            self._backend_class = getattr(module, spec["backend"])
        except AttributeError:
            raise ExportError("backend module %s has no %s" % (spec["module"], spec["backend"]))
        self.version = _distribution_version(spec["package"])
        self.pysigma_version = _distribution_version(PYSIGMA_PACKAGE)

    def convert(self, rule_dict: Dict[str, Any]) -> str:
        try:
            sigma_rule = self._sigma_rule.SigmaRule.from_dict(rule_dict)
            collection = self._sigma_collection.SigmaCollection([sigma_rule])
            backend = self._backend_class()
            queries = backend.convert(collection)
        except Exception as exc:  # pySigma raises many SigmaError subclasses
            raise ExportError("%s: %s" % (type(exc).__name__, exc))
        if not queries:
            raise ExportError("the backend returned no query")
        return "\n".join(str(q) for q in queries)


def load_adapter(target: str) -> PySigmaAdapter:
    """The adapter for ``target``; raises UnknownTarget or MissingDependency."""
    return PySigmaAdapter(target)


def sigma_mapping(rule: Rule) -> Dict[str, Any]:
    """The rule as pySigma should see it: without the x-mizan extension."""
    return {k: v for k, v in rule.raw.items() if k not in MIZAN_KEYS}


def export_rule(rule, target: str,
                adapter_factory: Optional[Callable[[str], Any]] = None) -> Dict[str, Any]:
    """Convert ``rule`` for ``target``.

    Returns ``{"target", "query", "backend_version"}``.  Raises
    ``ExportError`` (``UnknownTarget``, ``MissingDependency`` or a
    conversion failure); an invalid rule (``Problems``) is an ExportError
    naming each problem.
    """
    if target not in TARGETS:
        raise UnknownTarget(target)
    if isinstance(rule, Problems):
        raise ExportError("rule is invalid: " + "; ".join(
            "%s: %s" % (p.field, p.reason) for p in rule))
    if not isinstance(rule, Rule):
        raise ExportError("not a loaded rule")
    factory = adapter_factory if adapter_factory is not None else load_adapter
    adapter = factory(target)
    query = adapter.convert(sigma_mapping(rule))
    return {"target": target, "query": query, "backend_version": str(getattr(adapter, "version", "unknown"))}
