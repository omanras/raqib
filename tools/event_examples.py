#!/usr/bin/env python3
"""VA-3 (ADR-0015 Amendment A): the examples of docs/specs/EVENT.md, made from the code.

    python3 tools/event_examples.py --check   exit 0 where every example is the code's own, else 1 (each named)
    python3 tools/event_examples.py --write   rewrite every example line from the code, exit 0 (1: an example
                                              the code does not make, or one it makes that the document lacks)

The events are built by the fixture runs of tests/test_event.py (build_runs, example_events): the same builder
that test compares with, through differences() below, so the tool and the test cannot disagree. A move of the
number (ADR-0015 V-1) is then one command, never eighteen lines edited by hand. This file imports the standard
library, raqib and tests/test_event.py (VB-2: the fixture runs are that test's own, and it needs pytest, as the
gate does; without pytest the tool ends with an ImportError and writes nothing).
Run D's two os follows list their source findings in either order (EVENT.md says so): for the labels given as
`varies`, an example's id, n, about and prev (ADR-0016: the line before it differs as its number does) are the
document's, and the rest is compared and written."""
import argparse
import json
import re
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "docs" / "specs" / "EVENT.md"
# VB-3: the lines between an example's heading and its fence hold no heading and no fence (an example whose fence
# is missing is then no example of the document, and is named; it never takes the next one's line)
EXAMPLE = re.compile(r"^(### example: (.+?)\n(?:(?!#|```).*\n)*?```json\n)(.+?)(\n```)", re.M)
VARIES = ("id", "n", "about", "prev")   # what a run of `varies` may number differently from the document


def _event():
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from raqib import event
    return event


def found(text):
    """{label: the example's JSON line} of the document's text, in its order."""
    return {m.group(2): m.group(3) for m in EXAMPLE.finditer(text)}


def _kept(built, doc_line):
    """The built event with the document's id, n and about where the document's line holds them."""
    try:
        doc = json.loads(doc_line)
    except ValueError:
        return built
    return dict(built, **{k: doc[k] for k in VARIES if isinstance(doc, dict) and k in doc})


def differences(text, built, varies=()):
    """Each way the document's examples are not the code's own, as a sentence ([]: every one is). built:
    {label: the event as the document writes it}. A label of `varies` is compared but for id, n and about."""
    event = _event()
    doc = found(text)
    out = ["no example of %s in the document" % label for label in built if label not in doc]
    out += ["the example %s is of no built event" % label for label in doc if label not in built]
    for label, line in doc.items():
        if label not in built:
            continue
        if label in varies:
            try:
                same = {k: v for k, v in json.loads(line).items() if k not in VARIES} == {
                    k: v for k, v in built[label].items() if k not in VARIES}
            except (ValueError, AttributeError):
                same = False
        else:
            same = line == event.line(built[label])
        if not same:
            out.append("the example %s is not the code's own" % label)
    return out


def rewrite(text, built, varies=()):
    """The document's text with each example's line made from built (the labels of `varies` keep the
    document's id, n and about); an example of no built event is left as it is."""
    event = _event()

    def one(m):
        label = m.group(2)
        if label not in built:
            return m.group(0)
        ev = _kept(built[label], m.group(3)) if label in varies else built[label]
        return m.group(1) + event.line(ev) + m.group(4)
    return EXAMPLE.sub(one, text)


def build():
    """(built, varies): the examples' events from tests/test_event.py's fixture runs, each run in a temporary
    directory of its own that is removed after."""
    for path in (ROOT, ROOT / "tests"):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))
    import test_event
    base = tempfile.mkdtemp(prefix="raqib-event-examples-")
    try:
        runs = test_event.build_runs(lambda name: Path(tempfile.mkdtemp(prefix=name + "-", dir=base)))
        return test_event.example_events(runs), tuple(test_event.RUN_D)
    finally:
        shutil.rmtree(base, ignore_errors=True)


def main(argv=None, out=None, doc=None, built=None):
    out = out or sys.stdout
    p = argparse.ArgumentParser(prog="event_examples.py", description="docs/specs/EVENT.md's examples, from the code")
    how = p.add_mutually_exclusive_group(required=True)
    how.add_argument("--check", action="store_true", help="exit 1 where an example is not the code's own")
    how.add_argument("--write", action="store_true", help="rewrite the examples from the code")
    p.add_argument("--doc", default=None, help="the document (default docs/specs/EVENT.md)")
    args = p.parse_args(argv)
    path = Path(args.doc or doc or DOC)
    raw = path.read_bytes().decode("utf-8")
    text = raw.replace("\r\n", "\n")
    made, varies = built if built is not None else build()
    if args.write:
        new = rewrite(text, made, varies)
        if new != text:
            path.write_bytes((new.replace("\n", "\r\n") if "\r\n" in raw else new).encode("utf-8"))
        problems = differences(new, made, varies)
        out.write("%s: %s\n" % (path.name, "the examples rewritten from the code" if new != text else
                                "the examples were the code's own already"))
    else:
        problems = differences(text, made, varies)
        if not problems:
            out.write("%s: every example is the code's own\n" % path.name)
    for problem in problems:
        out.write("%s: %s\n" % (path.name, problem))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
