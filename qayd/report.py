"""Text and JSON rendering of a check (ADR-0001 section 8).

Text: one line per policy ``<verdict> <id> <title> <measure> vs <limit>``
then indented citations, reds first; then the findings that belong to no
policy (invalid rows, duplicates); then one summary line GREEN / RED.
JSON: ``{"version": 1, "command", "as_of", "green", "policies": [...],
"findings": [...], "files": {...}, "problems": [...]}``. Every amount is
decimal text, never a JSON number (A5).
"""

import json
from decimal import Decimal
from typing import NamedTuple, Optional

from .measures import Stale, Unknown, Value
from .policies import band_text, limit_text, match_text, measure_text
from .rules import money, order, pct

VERSION = 1


class Report(NamedTuple):
    command: str
    as_of: object                 # datetime.date
    config: object                # policies.Config
    verdicts: tuple
    findings: tuple
    files: dict                   # file name -> row count (None: absent)
    problems: tuple               # every loader problem, in file order
    green: bool
    extra: Optional[dict] = None  # command-specific payload (M1.2)


# ------------------------------------------------------------------ measures


def _is_pct(policy):
    kind = policy.measure.get("kind") if policy.measure else None
    return kind in ("share", "drawdown")


def measure_display(v, base):
    """Short text for the measure side of a verdict line."""
    policy, m = v.policy, v.measure
    if m is None:
        return "-"
    if isinstance(m, Unknown):
        return "unknown"
    if policy.type in ("routine", "red_line"):
        n = len(m.rows)
        return "no row" if n == 0 else "%d row%s" % (n, "" if n == 1 else "s")
    if isinstance(m, Stale):
        if m.amount is None:
            return "stale (%d days)" % m.age_days
        shown = pct(m.amount) if _is_pct(policy) else money(m.amount, base)
        return "stale %s as of %s (%d days)" % (shown, m.date.isoformat(), m.age_days)
    return pct(m.amount) if _is_pct(policy) else money(m.amount, base)


def limit_display(v, base):
    policy, lim = v.policy, v.limit
    if policy.type == "routine":
        return "1 row required (%s)" % match_text(policy.match)
    if policy.type == "red_line":
        return "none (%s)" % match_text(policy.match)
    if policy.type == "allocation":
        return band_text(policy.band) if policy.band else "?"
    if policy.type == "kill":
        return limit_text(policy.limit) if policy.limit else "?"
    if policy.limit is None:
        return "?"
    declared = limit_text(policy.limit, base)
    if lim is None or isinstance(lim, Unknown):
        return declared if policy.limit["kind"] == "value" else "unknown (%s)" % declared
    if policy.limit["kind"] == "value":
        return declared
    return "%s (%s)" % (money(lim.amount, base), limit_text(policy.limit))


def scope_display(v, as_of):
    """What the verdict is about: a period label, 'as of <date>' for
    holdings-based policies, 'ever' for a red line."""
    if v.policy.type == "red_line":
        return "ever"
    if v.period is None:
        return ""
    if v.policy.measure and v.policy.measure.get("kind") != "sum" and v.policy.type != "routine":
        cut = v.period.end if as_of is None or as_of >= v.period.end else as_of
        return "as of %s" % cut.isoformat()
    return v.period.label


def amount_text(x):
    """Decimal -> plain text; None stays None."""
    if x is None:
        return None
    return money(x) if isinstance(x, Decimal) else str(x)


# ---------------------------------------------------------------------- text


def render_text(report):
    base = report.config.base_currency if report.config else ""
    lines = []
    for v in order(report.verdicts):
        scope = scope_display(v, report.as_of)
        line = "%-8s %-10s %s  %s vs %s" % (v.verdict, v.id, v.policy.title,
                                              measure_display(v, base), limit_display(v, base))
        if scope:
            line += " [%s]" % scope
        if v.reason:
            line += "  -- " + v.reason
        lines.append(line)
        cites = v.cites
        if not cites:
            cites = tuple(c for f in v.findings for c in f.cites)
        if cites:
            lines.append("         " + " ".join(cites))
    loose = [f for f in report.findings if f.policy is None]
    if loose:
        lines.append("findings:")
        for f in loose:
            lines.append("  %-5s %-16s %s  %s" % (f.cls, f.code, " ".join(f.cites), f.reason))
    holds = sum(1 for v in report.verdicts if v.verdict == "hold")
    reds = sum(1 for f in report.findings if f.cls == "red")
    warns = sum(1 for f in report.findings if f.cls == "warn")
    summary = "%s as of %s: %d of %d policies hold, %d red finding%s, %d warning%s" % (
        "GREEN" if report.green else "RED", report.as_of.isoformat(), holds, len(report.verdicts),
        reds, "" if reds == 1 else "s", warns, "" if warns == 1 else "s")
    lines.append(summary)
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------- JSON


def _value_json(x, text):
    if x is None:
        return None
    if isinstance(x, Unknown):
        return {"status": "unknown" if x.cause != "invalid" else "invalid", "reason": x.reason,
                "cites": list(x.cites), "text": text}
    if isinstance(x, Stale):
        return {"status": "stale", "amount": amount_text(x.amount), "age_days": x.age_days,
                "date": x.date.isoformat(), "cites": list(x.cites), "text": text}
    if isinstance(x, Value):
        return {"status": "ok", "amount": amount_text(x.amount), "cites": list(x.cites), "text": text}
    return {"status": "ok", "amount": amount_text(x), "text": text}


def verdict_json(v, base, as_of):
    return {
        "id": v.id,
        "type": v.policy.type,
        "title": v.policy.title,
        "verdict": v.verdict,
        "period": v.period.label if v.period is not None else None,
        "scope": scope_display(v, as_of),
        "measure": _value_json(v.measure, measure_display(v, base)),
        "limit": _value_json(v.limit, limit_display(v, base)),
        "declared": {
            "measure": measure_text(v.policy.measure) if v.policy.measure else None,
            "limit": limit_text(v.policy.limit, base) if v.policy.limit else None,
            "match": match_text(v.policy.match) if v.policy.match else None,
            "band": band_text(v.policy.band) if v.policy.band else None,
            "period": v.policy.period,
        },
        "cites": list(v.cites),
        "reason": v.reason,
        "findings": [f.code for f in v.findings],
    }


def finding_json(f):
    return {"code": f.code, "class": f.cls, "policy": f.policy, "period": f.period,
            "date": f.date, "cites": list(f.cites), "reason": f.reason}


def to_dict(report):
    base = report.config.base_currency if report.config else None
    out = {
        "version": VERSION,
        "command": report.command,
        "as_of": report.as_of.isoformat(),
        "green": report.green,
        "base_currency": base,
        "policies": [verdict_json(v, base, report.as_of) for v in order(report.verdicts)],
        "findings": [finding_json(f) for f in report.findings],
        "files": dict(report.files),
        "problems": [dict(p) for p in report.problems],
    }
    if report.extra:
        out.update(report.extra)
    return out


def render_json(report):
    return json.dumps(to_dict(report), indent=2, sort_keys=False, default=str) + "\n"
