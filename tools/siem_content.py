"""The files of siem/ that are made from the rules (ADR-0017 S-3, Amendment A SA-8 and B SB-8, M16.1 E4, REDO R5):
siem/attack/rules.md, a table of every rule the report lists - raqib/report.py's own rule_table: the silence rules,
the cross-source rule and the drift anchors the code holds, and the rules of raqib/rules/catalog - with its class,
kind, severity and ATT&CK techniques, and siem/attack/raqib-layer.json, a layer for the ATT&CK Navigator of the
same techniques (never loaded into a Navigator yet, siem/README.md).

    python3 tools/siem_content.py --write   writes both from the catalog
    python3 tools/siem_content.py --check   exit 0 when both are what --write would write; else exit 1 and each
                                            difference named (the gate calls it: a rule added or changed fails
                                            the gate until --write is run)

Standard library and raqib only (it imports raqib.report and raqib.rules.engine to read the rules as the report
does; nothing under raqib/ is changed). It writes under siem/attack; raqib never imports it."""
import difflib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from raqib import report  # noqa: E402
from raqib.rules import engine  # noqa: E402

CATALOG = os.path.join(ROOT, "raqib", "rules", "catalog")
TABLE = os.path.join("siem", "attack", "rules.md")
LAYER = os.path.join("siem", "attack", "raqib-layer.json")


def catalog(path=CATALOG):
    """Every rule the report lists (report.rule_table over the catalog, as the watch loads it), sorted by id:
    {id, title, class, kind, severity, attack}; a kind the code does not declare is "none"."""
    rules = [{"id": r["id"], "title": r["title"], "class": r["class"], "kind": r["kind"] or "none",
              "severity": r["severity"], "attack": list(r["attack"] or [])}
             for r in report.rule_table(engine.load_catalog(path))]
    return sorted(rules, key=lambda r: r["id"])


def techniques(rules):
    """technique id -> the ids of the rules that declare it, both sorted."""
    out = {}
    for rule in rules:
        for tech in rule["attack"]:
            out.setdefault(tech, []).append(rule["id"])
    return {t: sorted(out[t]) for t in sorted(out)}


def table(rules):
    techs = techniques(rules)
    lines = [
        "# Every rule the report lists and its ATT&CK techniques",
        "",
        "Made by `python3 tools/siem_content.py --write` from every rule the report lists (`raqib/report.py`,",
        "`rule_table`: the silence rules, the cross-source rule and the drift anchors of the code, and the rules of",
        "`raqib/rules/catalog`); `--check` holds it in the gate.",
        "Do not edit it by hand. A technique is what a finding is consistent with, never that it happened",
        "(docs/specs/EVENT.md, `rule.attack`); a finding carries its rule's in `threat.technique.id` (siem/README.md).",
        "The same techniques, for the ATT&CK Navigator: `raqib-layer.json` beside this file (never loaded into a",
        "Navigator yet).",
        "",
        "| rule | title | class | kind | severity | ATT&CK techniques |",
        "|---|---|---|---|---|---|",
    ]
    for rule in rules:
        lines.append("| %s | %s | %s | %s | %s | %s |" % (
            rule["id"], rule["title"].replace("|", "/"), rule["class"], rule["kind"], rule["severity"],
            ", ".join(rule["attack"]) or "none"))
    lines += ["", "%d rules; %d of them declare a technique; %d techniques: %s." % (
        len(rules), sum(1 for r in rules if r["attack"]), len(techs), ", ".join(techs))]
    return "\n".join(lines) + "\n"


def layer(rules):
    by_id = {r["id"]: r for r in rules}
    techs = techniques(rules)
    body = {
        "name": "Raqib - the techniques of every rule the report lists",
        "versions": {"layer": "4.5"},
        "domain": "enterprise-attack",
        "description": ("Made by python3 tools/siem_content.py --write from every rule the report lists "
                        "(raqib/report.py rule_table). A technique is what a "
                        "finding of the rule is consistent with, never that it happened. The score is the number "
                        "of rules that declare the technique."),
        "sorting": 0,
        "hideDisabled": False,
        "techniques": [{"techniqueID": tech, "score": len(ids), "enabled": True, "showSubtechniques": False,
                        "comment": "; ".join("%s (%s, %s, %s)" % (i, by_id[i]["class"], by_id[i]["kind"],
                                                                  by_id[i]["severity"]) for i in ids)}
                       for tech, ids in techs.items()],
        "gradient": {"colors": ["#ffe0b2", "#e65100"], "minValue": 0,
                     "maxValue": max([len(ids) for ids in techs.values()] or [1])},
        "legendItems": [],
        "metadata": [{"name": "rules", "value": str(len(rules))}],
    }
    return json.dumps(body, indent=2, ensure_ascii=True) + "\n"


def made(rules=None):
    rules = catalog() if rules is None else rules
    return {TABLE: table(rules), LAYER: layer(rules)}


def differences(root=ROOT, rules=None):
    """Each difference between the files under root and what --write would write, one line each."""
    out = []
    for rel, want in made(rules).items():
        path = os.path.join(root, rel)
        if not os.path.exists(path):
            out.append("%s: missing (run python3 tools/siem_content.py --write)" % rel)
            continue
        with open(path, encoding="utf-8", newline="") as f:
            have = f.read()
        if have == want:
            continue
        for line in difflib.unified_diff(have.splitlines(), want.splitlines(), lineterm="", n=0):
            if line.startswith(("---", "+++", "@@")):
                continue
            out.append("%s: %s %s" % (rel, "the rules give" if line[0] == "+" else "the file has", line[1:]))
    return out


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv == ["--write"]:
        for rel, text in made().items():
            path = os.path.join(ROOT, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="ascii", newline="\n") as f:
                f.write(text)
            print("wrote %s" % rel)
        return 0
    if argv == ["--check"]:
        diffs = differences()
        for line in diffs:
            print(line)
        if diffs:
            print("siem/attack is not the rules': run python3 tools/siem_content.py --write")
            return 1
        print("siem/attack is the rules' (%d rules)" % len(catalog()))
        return 0
    print("usage: python3 tools/siem_content.py --write | --check", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
