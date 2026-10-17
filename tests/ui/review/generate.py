"""Record the reference CLI's review pages for tests/ui/review.test.ts.

Not part of the gate: the JSON it writes is committed and the test renders
the same reviews with the port and compares byte for byte. Needs the
reference engine (branch qayd, read-only):

    git archive origin/qayd qayd examples | tar -x -C /some/dir
    python3 -I tests/ui/review/generate.py /some/dir tests/ui/review/cli-reviews.json
"""
import io
import json
import os
import shutil
import sys
import tempfile

QAYD, OUT = sys.argv[1], sys.argv[2]
sys.path.insert(0, QAYD)
from qayd import cli  # noqa: E402

FILES = ("policies.yml", "ledger.csv", "holdings.csv", "decisions.yml", "rates.csv")


def example():
    out = {}
    for f in FILES:
        with open(os.path.join(QAYD, "examples", f), encoding="utf-8", newline="") as fh:
            out[f] = fh.read()
    return out


def page(files, period, as_of):
    tmp = tempfile.mkdtemp()
    try:
        for f, text in files.items():
            if text is not None:
                with open(os.path.join(tmp, f), "w", encoding="utf-8", newline="") as fh:
                    fh.write(text)
        out, err = io.StringIO(), io.StringIO()
        code = cli.main(["review", "--dir", tmp, "--period", period, "--as-of", as_of, "-o", "-"], out, err)
        assert code == 0 and err.getvalue() == "", err.getvalue()
        return out.getvalue()
    finally:
        shutil.rmtree(tmp)


def variant(name, change):
    files = example()
    change(files)
    return name, files


def append(file, text):
    return lambda f: f.__setitem__(file, f[file] + text)


def replace(file, old, new):
    def change(f):
        assert old in f[file]
        f[file] = f[file].replace(old, new)
    return change


HOUSEHOLDS = [
    variant("example", lambda f: None),
    variant("breach", append("ledger.csv", "2026-09-28,-200,OMR,cash,discretionary,,new tablet\n")),
    variant("eur-no-rate", append("ledger.csv", "2026-09-20,-10,EUR,cash,discretionary,,in euro\n")),
    variant("no-rates", lambda f: f.__setitem__("rates.csv", None)),
    variant("tight-age", replace("policies.yml", "snapshot_max_age_days: 45", "snapshot_max_age_days: 20")),
    variant("html-note", append("ledger.csv", '2026-09-11,-3.250,OMR,cash,food,"weekly;market","fish <b>& bread</b> \'x\'"\n')),
    variant("no-snapshots", lambda f: f.__setitem__("holdings.csv", "date,account,asset,class,quantity,value,currency\n")),
    variant("refund", append("ledger.csv", "2026-07-25,40,OMR,cash,discretionary,,refund of the phone case\n")),
]
REVIEWS = {
    "example": [("2026-Q3", "2026-10-17"), ("2026-07", "2026-10-17"), ("2026", "2026-10-17"), ("2025-Q4", "2026-10-17"),
                ("2026-03", "2026-10-17"), ("2026-Q4", "2026-10-17"), ("2026-09", "2026-09-14"), ("2024-10", "2024-10-01"),
                ("2027", "2027-01-31")],
    "breach": [("2026-Q3", "2026-10-17")],
    "eur-no-rate": [("2026-Q3", "2026-10-17"), ("2026-09", "2026-09-30")],
    "no-rates": [("2026-Q3", "2026-10-17")],
    "tight-age": [("2026-Q4", "2026-12-31")],
    "html-note": [("2026-09", "2026-09-30")],
    "no-snapshots": [("2026-Q3", "2026-10-17")],
    "refund": [("2026-07", "2026-10-17")],
}

cases = []
for name, files in HOUSEHOLDS:
    cases.append({"name": name, "files": files,
                  "reviews": [{"period": p, "as_of": d, "page": page(files, p, d)} for p, d in REVIEWS[name]]})
with open(OUT, "w", encoding="utf-8") as fh:
    json.dump(cases, fh, separators=(",", ":"), ensure_ascii=True)
    fh.write("\n")
print("pages:", sum(len(c["reviews"]) for c in cases))
