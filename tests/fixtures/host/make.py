"""Make the rule fixtures of NEW-AGENT and AGENT-DARK-LIVE (M7.2), under
tests/fixtures/rules/<RULE>/ as every catalog rule's, from the
discover fixtures: each is a sequence of rounds, each round the inventory
`raqib discover --from DIR` gives for one discover fixture directory, run
through raqib/host.py's HostWatch with a fake clock. The fixture holds the
host lines of the LAST round only (the round judged); the earlier rounds
are its history, written into each line by HostWatch (history,
candidate_before, streak). A test (tests/test_host.py) runs this again and
holds the files to it.

    python3 tests/fixtures/host/make.py

The inventories are of the SYNTHETIC and REAL-redacted discover fixtures
under tests/fixtures/discover (see their headers); "kimi-gone" is
kimi/one-sample with the rows of kimi.exe's tree (pid 10728 and below)
left out of its process file: the agent exited, its footprint stays.
"""
import io
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
sys.path.insert(0, ROOT)
from raqib import discover, host, notify  # noqa: E402
from raqib.rules import engine  # noqa: E402

DISCOVER = os.path.join(ROOT, "tests", "fixtures", "discover")
KIMI_TREE = ("10728", "7768", "10476", "5796", "8496", "8500")

# file (under tests/fixtures/rules/) -> the discover fixtures read as rounds, in order
SCENARIOS = {
    "NEW-AGENT/positive-new-unknown.json": ["benign/windows-desktop", "windows"],
    "NEW-AGENT/positive-new-named.json": ["benign/linux-desktop", "linux"],
    "NEW-AGENT/positive-act-root-becomes-candidate.json": ["kimi/one-sample", "kimi/two-samples"],
    "NEW-AGENT/negative-history-only.json": ["linux", "linux"],
    "NEW-AGENT/negative-gone-and-back.json": ["benign/windows-desktop", "windows", "benign/windows-desktop",
                                              "windows"],
    "NEW-AGENT/negative-act-root-only.json": ["benign/linux-desktop", "linux-agent"],
    "AGENT-DARK-LIVE/positive-dark-three-rounds.json": ["windows", "windows", "windows"],
    "AGENT-DARK-LIVE/negative-dark-two-rounds.json": ["windows", "windows"],
    "AGENT-DARK-LIVE/negative-dark-then-linked.json": ["kimi-gone", "kimi-gone", "kimi-gone", "kimi/one-sample"],
}
OUT = os.path.join(ROOT, "tests", "fixtures", "rules")


def inventory(name, catalog):
    if name == "kimi-gone":
        texts, holes = discover.read_dir(os.path.join(DISCOVER, "kimi", "one-sample"))
        label, text, error = texts["win-process-1"]
        kept = [line for line in text.splitlines(True)
                if not any(line.startswith('"%s",' % pid) for pid in KIMI_TREE)]
        texts["win-process-1"] = (label + " (kimi.exe's tree left out: make.py)", "".join(kept), error)
    else:
        texts, holes = discover.read_dir(os.path.join(DISCOVER, *name.split("/")))
    return discover.run(texts, catalog, holes=holes)


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def rounds_of(names, catalog, rules, home):
    """The round records of a HostWatch fed these inventories in order."""
    invs = [inventory(n, catalog) for n in names]
    feed = iter(invs)
    clock = Clock()
    notifier = notify.Notifier(host.HOST, enabled=False, reason="fixture", host=True)
    watch = host.HostWatch(lambda: next(feed), catalog, rules, notifier, every=10, out=None, err=io.StringIO(),
                           clock=clock, wall=lambda: 1793700000.0 + clock.t, home=home, platform="fixture")
    for _ in names:
        watch.tick(wait=30)
        clock.t += 10
    return watch


def build():
    catalog = discover.load_catalog(discover.CATALOG)
    rules = engine.load_catalog(os.path.join(ROOT, "raqib", "rules", "catalog"))
    out = {}
    with tempfile.TemporaryDirectory() as home:
        for name, names in SCENARIOS.items():
            watch = rounds_of(names, catalog, rules, os.path.join(home, name.replace("/", "-")))
            last = watch.round_lines[-1]
            lines = last["lines"]
            found, _ = engine.evaluate(watch.rules, lines)
            doc = {"lines": lines}
            if found:
                doc["expect_seq"] = sorted({s for f in found for s in f["cited_seq"]})
            out[name] = json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=True) + "\n"
    return out


def main():
    for name, text in build().items():
        path = os.path.join(OUT, *name.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="ascii", newline="\n") as f:
            f.write(text)


if __name__ == "__main__":
    main()
