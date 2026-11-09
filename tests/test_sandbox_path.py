"""M7.6d: the sandbox path redacted (HANDOFF.md E1, E2; resume note of
2026-11-09; ADR-0008 Amendment E, E-1).

The M7.1 live capture tests/fixtures/discover/linux named the build
sandbox's home directory; capture.py's redact_home() wrote it as the
placeholder home /home/user. The export is REAL data (A8): these tests hold
that nothing else of it moved, by rebuilding the export as it was (the note
taken out, the placeholder written back as the sandbox home) and matching it
byte for byte to the sha256 of the files before (dc7ac20); then they rebuild
the five rule fixtures made from it, before and after, with make.py, and
hold that the two differ only in that path.
"""
import hashlib
import json
import os
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
LINUX = ROOT / "tests" / "fixtures" / "discover" / "linux"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(LINUX))
sys.path.insert(0, str(ROOT / "tests" / "fixtures" / "host"))
import capture  # noqa: E402
import make as host_fixtures  # noqa: E402
from raqib import discover  # noqa: E402

SANDBOX_HOME = "/home/claude"   # the build sandbox's home in the capture of 2026-11-02 (a sandbox user, not a person)
NOTE = "redacted 2026-11-09: home -> /home/user"
# sha256 of the files as they were before M7.6d (dc7ac20)
BEFORE = {
    "discover/linux/proc.txt": "c6f7f57e10c0f7abd504912725522406cff8e7192fd44bc049fa93aa2302a99a",
    "discover/linux/footprints.txt": "1edd6fae0d2581cefffe8a34bfa20d3622c0814b821547d2d86bec6b8a32a032",
    "rules/NEW-AGENT/positive-new-named.json": "e3f05a0aa3e313b5533097fb41bf20a91a6d08a7525f03a1bb2c7c67291a6bb0",
    "rules/NEW-AGENT/negative-history-only.json": "5e9cee7c8d24907a58269dbe31f350076e7aea038dcf8d80404f5dd2713fb37f",
    "rules/HOST-UNWATCHED/positive-no-source-two-rounds.json":
        "07e81cd948299cff5caf7a2248b0fea641a96b83c69297d767a44fd283e47a2c",
    "rules/HOST-UNWATCHED/negative-one-round.json": "c6dd11cd8dc9711116abd746a33f609408715f7cdf0155522e7d2bd8eb08a69b",
    "rules/HOST-UNWATCHED/negative-host-source.json": "5e9cee7c8d24907a58269dbe31f350076e7aea038dcf8d80404f5dd2713fb37f",
}
FIVE = [k[len("rules/"):] for k in BEFORE if k.startswith("rules/")]
UNCHANGED = ("proc-net.txt", "ss.txt")


def sha(text):
    return hashlib.sha256(text.encode("ascii")).hexdigest()


def read(path):
    with open(path, encoding="ascii", newline="") as f:
        return f.read()


def unredacted(name, text):
    """The text of the export file `name` as it was before M7.6d: the note
    taken out, the placeholder home written back as the sandbox's."""
    lines = text.split("\n")
    if name == "proc.txt":
        i = next(n for n, x in enumerate(lines) if x.startswith("{"))
        meta = json.loads(lines[i])
        assert meta["note"].endswith("; " + NOTE)
        meta["note"] = meta["note"][:-len("; " + NOTE)]
        lines[i] = json.dumps(meta, sort_keys=True, ensure_ascii=True)
    else:
        assert lines[0].endswith(" " + NOTE)
        lines[0] = lines[0][:-len(" " + NOTE)]
    return "\n".join(lines).replace(capture.HOME_PLACEHOLDER, SANDBOX_HOME)


@pytest.fixture(scope="module")
def before_dir(tmp_path_factory):
    """A copy of tests/fixtures/discover with the linux export as it was (checked by sha256)."""
    where = tmp_path_factory.mktemp("before") / "discover"
    shutil.copytree(str(ROOT / "tests" / "fixtures" / "discover"), str(where))
    for name in ("proc.txt", "footprints.txt"):
        old = unredacted(name, read(LINUX / name))
        assert sha(old) == BEFORE["discover/linux/" + name], name
        with open(where / "linux" / name, "w", encoding="ascii", newline="") as f:
            f.write(old)
    return where


def test_e1_the_export_is_byte_identical_but_for_the_home_and_the_note(before_dir):
    """E1: the redacted texts are redact_home() over the texts before plus the note, nothing else; the
    sandbox home is gone from the export, and the files that never held it are untouched."""
    for name in ("proc.txt", "footprints.txt"):
        old, new = read(before_dir / "linux" / name), read(LINUX / name)
        assert SANDBOX_HOME in old and SANDBOX_HOME not in new and capture.HOME_PLACEHOLDER not in old
        assert capture.noted(name, capture.redact_home(old, SANDBOX_HOME)) == new
        assert len(old.split("\n")) == len(new.split("\n"))   # cites keep their line numbers
        assert NOTE in new
    for name in UNCHANGED:
        assert SANDBOX_HOME not in read(LINUX / name)
    assert capture.REDACTED_NOTE == NOTE
    assert json.loads(read(LINUX / "proc.txt").split("\n")[2])["note"].endswith("; " + NOTE)


def test_e1_the_helper_is_one_deterministic_substitution_of_whole_path_parts():
    r = capture.redact_home
    assert r('"cwd": "/home/sbx", "/home/sbx/raqib", /home/sbx: 10', "/home/sbx/") == (
        '"cwd": "/home/user", "/home/user/raqib", /home/user: 10')
    assert r("/home/sbxx/a /home/sbx.d /home/sbx-2 /root/home/sbx", "/home/sbx") == (
        "/home/sbxx/a /home/sbx.d /home/sbx-2 /root/home/user")
    with pytest.raises(ValueError):
        r("x", "/root")
    with pytest.raises(ValueError):
        r("x", "/home/a/b")


def _built(discover_dir, monkeypatch):
    """make.py's build() of the five fixtures over the exports in discover_dir."""
    monkeypatch.setattr(host_fixtures, "DISCOVER", str(discover_dir))
    monkeypatch.setattr(host_fixtures, "SCENARIOS", {k: host_fixtures.SCENARIOS[k] for k in FIVE})
    monkeypatch.setattr(host_fixtures, "SOURCE_SCENARIOS", {})
    made = host_fixtures.build()
    assert sorted(made) == sorted(FIVE)
    return made


def _same_but_the_path(old, new, elided):
    """old and new (JSON values) are equal once the sandbox home is the placeholder; a cited line long
    enough to be bounded (its middle cut to "...") is compared as the redacted line bounded (the cut moves
    by the length the path lost: elided maps bounded(line before) -> bounded(line after))."""
    if isinstance(old, dict):
        assert isinstance(new, dict) and sorted(old) == sorted(new)
        for k in old:
            _same_but_the_path(old[k], new[k], elided)
    elif isinstance(old, list):
        assert isinstance(new, list) and len(old) == len(new)
        for a, b in zip(old, new):
            _same_but_the_path(a, b, elided)
    elif isinstance(old, str):
        want = elided.get(old, old.replace(SANDBOX_HOME, capture.HOME_PLACEHOLDER))
        assert want == new, (old, new)
    else:
        assert old == new


def test_e2_the_five_fixtures_are_regenerated_and_differ_only_in_the_path(before_dir, monkeypatch):
    made_before = _built(before_dir, monkeypatch)
    for name, text in made_before.items():
        assert sha(text) == BEFORE["rules/" + name], name   # make.py over the export before: the files before
    made_after = _built(ROOT / "tests" / "fixtures" / "discover", monkeypatch)
    rules_dir = ROOT / "tests" / "fixtures" / "rules"
    elided = {}
    for name in ("proc.txt", "footprints.txt"):
        for a, b in zip(read(before_dir / "linux" / name).split("\n"), read(LINUX / name).split("\n")):
            if a != b and len(discover._safe(a)) > discover.LINE_TEXT_MAX:
                elided[discover.bounded(a)] = discover.bounded(b)
    assert elided   # the long process lines are the ones whose cut moved
    for name in FIVE:
        new = read(rules_dir / name)
        assert made_after[name] == new, name   # the shipped file is make.py's output
        assert SANDBOX_HOME not in new and capture.HOME_PLACEHOLDER in new
        _same_but_the_path(json.loads(made_before[name]), json.loads(new), elided)


def test_e2_no_other_shipped_fixture_held_the_sandbox_home():
    for p in sorted((ROOT / "tests" / "fixtures").rglob("*")):
        if p.is_file() and p.suffix in (".json", ".txt", ".csv", ".xml", ".jsonl", ".yaml"):
            assert SANDBOX_HOME not in p.read_text(encoding="utf-8"), p
    assert os.path.isfile(str(LINUX / "capture.py"))
