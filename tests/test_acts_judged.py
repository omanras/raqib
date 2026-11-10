"""M7.8 (ADR-0007 Amendment P, rulings P-1, P-2, P-3): the second field run's
lessons. On a host with Sysmon a tree's acts are judged (E1-E3), a living
tree is quiet, not gone (E4), and Windows Defender's engine in its own
directory is benign (E5); THREAT_MODEL says what the host watch sees (E6).
Every round here is a text fixture (tests/fixtures/host/quiet, defender;
tests/fixtures/os/*.sysmon.xml, SYNTHETIC); no live host, no Windows."""
import io
import json
import os
import re
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from raqib import discover, host, notify, ui  # noqa: E402
from raqib.hooks import common, os_sysmon  # noqa: E402
from raqib.rules import engine, fixtures  # noqa: E402

FIX = ROOT / "tests" / "fixtures"
RULES_DIR = ROOT / "raqib" / "rules" / "catalog"
HOSTFIX = FIX / "host"
CATALOG = discover.load_catalog(discover.CATALOG)
RULES = engine.load_catalog(RULES_DIR)


def rule(rule_id):
    return next(r for r in RULES if r.id == rule_id)


def os_lines(name, root, cwd="C:\\work\\proj"):
    text = (FIX / "os" / name).read_text(encoding="ascii")
    lines, _ = os_sysmon.build(text, root, cwd=cwd)
    return [json.loads(x) for x in lines]


def pre_processes(recs):
    return [r for r in recs if r["phase"] == "pre" and r["tool"] == "process"]


# --- E1: the image name on an os process line --------------------------------------------------------------

@pytest.mark.parametrize("image", [
    "C:\\Windows\\System32\\curl.exe", "C:\\Program Files\\Git\\usr\\bin\\RM.EXE", "C:\\Windows\\System32\\format.com",
    "C:\\tools\\build.cmd", "C:\\tools\\setup.bat", "C:/Program Files/PuTTY/plink.exe", "C:\\x\\mkfs.ext4",
])
def test_e1_the_image_is_discovers_one_normalised_form(image):
    """The os line's image is discover.image_name of what Sysmon logged, the function discover names a tree's
    image with; command_head keeps Sysmon's own basename; the command line is only hashed."""
    text = (FIX / "os" / "sysmon-synthetic.xml").read_text(encoding="ascii").replace(
        "<Data Name='Image'>C:\\Windows\\System32\\curl.exe</Data>", "<Data Name='Image'>%s</Data>" % image, 1)
    (curl,) = [r for r in pre_processes([json.loads(x) for x in os_sysmon.build(text, 4100)[0]])
               if r["ts"] == "2026-11-03T09:00:40.000Z"]
    assert curl["input_meta"]["image"] == discover.image_name(image)
    assert curl["input_meta"]["command_head"] == os_sysmon.program_name(image)   # as Sysmon logged it
    assert curl["input_sha256"] == common.canonical_sha256({"command_line": "curl -s https://198.51.100.20/x"})
    assert "198.51.100.20" not in json.dumps(curl) and "-s" not in json.dumps(curl["input_meta"])


def test_e1_one_function_not_a_second_normaliser():
    import inspect
    src = (ROOT / "raqib" / "hooks" / "os_sysmon.py").read_text(encoding="ascii")
    fields = inspect.getsource(os_sysmon._event_fields)
    assert src.count("discover.image_name(") == 1 and "discover.image_name(" in fields
    assert ".lower()" not in fields and ".exe" not in fields
    for word in ("bash.exe", "Bash", "CURL.EXE", "x.cmd", "-sh", None, ""):
        assert host._image_word(word) == (discover.image_name(word or "") or "")   # N-9 compares with it too


def test_e1_every_process_line_of_the_exports_has_the_field_and_no_argument():
    for name, root in (("sysmon-synthetic.xml", 4100), ("net-windows.sysmon.xml", 4700),
                       ("destruct-windows.sysmon.xml", 4600), ("benign-windows-desktop.sysmon.xml", 5100)):
        recs = os_lines(name, root)
        procs = [r for r in recs if r["tool"] == "process"]
        assert procs and all("image" in r["input_meta"] for r in procs), name
        flat = json.dumps(recs)
        assert "/transfer" not in flat and "delete shadows" not in flat and "-rf" not in flat, name


def old_shape(recs):
    """The lines as os-sysmon wrote them before M7.8: no image key."""
    out = []
    for r in recs:
        r = json.loads(json.dumps(r))
        if isinstance(r.get("input_meta"), dict):
            r["input_meta"].pop("image", None)
        out.append(r)
    return out


def test_e1_a_line_before_m78_is_not_guessed_and_the_engine_says_it():
    recs = old_shape(os_lines("net-windows.sysmon.xml", 4700))
    found, notes = engine.evaluate([rule("NET-TOOL"), rule("DESTRUCT-CMD")], recs)
    assert found == []   # never guessed from command_head (bitsadmin.exe, plink.exe)
    assert sorted((n["rule_id"], n["status"]) for n in notes) == [("DESTRUCT-CMD", "partial"), ("NET-TOOL", "partial")]
    assert all("could not judge 4 line(s)" in n["detail"] for n in notes)


# --- the host watch over text rounds ------------------------------------------------------------------------

def inventory(rel):
    d = HOSTFIX / rel
    texts, holes = discover.read_dir(str(d))
    return discover.run(texts, CATALOG, holes=holes, run={"system_drive": "c"}, processes=True)


class CountingFollow:
    """A fake os follow: each attach is counted; its first pass appends `lines` (os-sysmon's), then it waits."""

    def __init__(self, lines=()):
        self.lines = list(lines)
        self.attaches = []

    def __call__(self, root, log, stop, every=None, out=None, err=None, on_pass=None, after_record=None, helpers=None):
        self.attaches.append(root)
        if self.lines and len(self.attaches) == 1:
            os_sysmon.append(log, [json.dumps(x, separators=(",", ":")) for x in self.lines])
        if on_pass:
            on_pass(1, None)
        stop.wait(60)
        return 1


def watch_rounds(tmp_path, names, sysmon=True, follow=None, inv=inventory):
    invs = iter([inv(n) for n in names])
    clock = host.FixtureClock()
    notifier = notify.Notifier(host.HOST, enabled=False, reason="fixture", host=True)
    kw = {"os_follow": follow} if follow is not None else {}
    w = host.HostWatch(lambda: next(invs), CATALOG, RULES, notifier, every=10, out=None, err=io.StringIO(),
                       clock=clock, wall=lambda: 1793700000.0 + clock.t, home=str(tmp_path), platform="fixture",
                       run="fixture-run", sysmon=(lambda: (True, "fixture: Sysmon")) if sysmon
                       else (lambda: (False, "fixture: no Sysmon")), **kw)
    for _ in names:
        w.tick(wait=30)
        for src in list(w.sources.values()):
            src.first_pass.wait(5)
        w.tick()   # the poll after the pass: the source's lines are read and judged
        clock.t += 10
    return w


SHELL = "5888:powershell:2026-11-10T07:50:00.000Z"


# --- E4 (P-2): quiet is not gone ----------------------------------------------------------------------------

def test_e4_the_field_alternation_is_one_attach_and_no_hole(tmp_path):
    """Amendment P: the shell (pid 5888, alive the whole watch) talked in alternate rounds; 13 times it was
    "gone", its os source ended, and "back", attached again after a hole. Now: quiet, one attach, no hole."""
    follow = CountingFollow()
    names = ["quiet/talking", "quiet/quiet"] * 14
    w = watch_rounds(tmp_path, names, follow=follow)
    assert follow.attaches == [5888]   # one attach
    rounds = w.round_lines
    assert all(r["gone"] == [] and r["back"] == [] for r in rounds)
    assert [r["quiet"] for r in rounds] == [[], [SHELL]] * 14
    assert not [h for h in w.holes if h["kind"].startswith("source")]
    (key,) = list(w.sources)
    src = w.sources[key]
    assert src.ended is None and src.error is None and src.thread.is_alive() and not src.stop.is_set()
    tree = w.trees[key]
    assert tree["quiet"] and not tree["present"] and tree["quiet_round"] == 28
    assert "quiet: %s" % SHELL in w.round_text(rounds[-1])
    text, _ = w.finish()
    assert "TREES SEEN: 1 (0 now, 1 quiet)" in text
    assert "[candidate] pid 5888 powershell (unknown): quiet (its root alive in round 28, no talk; source kept)" in text
    assert "attached again" not in text and "the tree is gone" not in text
    st = json.loads(Path(w.state_path).read_text(encoding="ascii"))
    assert st["host"]["quiet"] == 1 and st["host"]["trees"][0]["quiet"] is True   # the state carries the word
    page = "\n".join(ui.host_section(st))
    assert '<span class="tag">quiet</span>' in page and "(1 trees seen, 0 now, 1 quiet)" in page


def test_e4_gone_is_the_root_not_in_the_sample(tmp_path):
    follow = CountingFollow()
    w = watch_rounds(tmp_path, ["quiet/talking", "quiet/quiet", "quiet/ended"], follow=follow)
    assert [r["quiet"] for r in w.round_lines] == [[], [SHELL], []]
    assert [r["gone"] for r in w.round_lines] == [[], [], [SHELL]]
    (src,) = w.sources.values()
    assert src.stop.is_set() and src.ended == "the tree is gone (round 3)"
    assert follow.attaches == [5888]


def test_e4_the_host_source_keeps_its_file_and_writes_no_gone_line_while_quiet(tmp_path):
    w = watch_rounds(tmp_path, ["quiet/talking", "quiet/quiet", "quiet/talking", "quiet/quiet", "quiet/ended"],
                     sysmon=False)
    (src,) = w.sources.values()
    recs = [json.loads(x) for x in Path(src.path).read_text(encoding="ascii").splitlines()]
    assert [r["tool"] for r in recs].count("HostGone") == 1 and recs[-1]["tool"] == "HostGone"
    assert recs[-1]["input_meta"]["round"] == 5
    assert all(r["back"] == [] for r in w.round_lines)
    assert len(os.listdir(w.sources_dir)) == 1


def test_e4_a_quiet_tree_that_talks_again_is_neither_back_nor_new(tmp_path):
    w = watch_rounds(tmp_path, ["defender/before", "quiet/talking", "quiet/quiet", "quiet/talking"],
                     follow=CountingFollow())
    news = [f for f in w.findings if f["rule_id"] in host.NEW_RULES]
    assert [(f["rule_id"], f["round"]) for f in news] == [("NEW-AGENT-UNKNOWN", 2)]   # the field's round-2 knock
    assert w.round_lines[3]["back"] == [] and w.round_lines[3]["lines"][0]["input_meta"]["was"] == host.QUIET


def test_e4_without_a_process_sample_a_tree_that_left_is_gone_and_that_is_said_once(tmp_path):
    def bare(rel):
        inv = inventory(rel)
        inv.pop("processes")
        return inv
    follow = CountingFollow()
    w = watch_rounds(tmp_path, ["quiet/talking", "quiet/quiet", "quiet/talking", "quiet/quiet"], follow=follow,
                     inv=bare)
    assert [r["gone"] for r in w.round_lines] == [[], [SHELL], [], [SHELL]]
    assert [r["back"] for r in w.round_lines] == [[], [], [SHELL], []]
    assert follow.attaches == [5888, 5888]
    assert sum(1 for n in w.notes if host.NO_SAMPLE_NOTE in n) == 1


def test_e4_the_live_reader_asks_discover_for_the_sample_and_discover_json_is_unchanged(monkeypatch):
    texts, holes = discover.read_dir(str(HOSTFIX / "quiet" / "quiet"))
    monkeypatch.setattr(discover, "collect_live", lambda *a, **k: (texts, holes, None))
    inv = host.live_reader(CATALOG, platform="win32")()
    assert (5888, "powershell", "2026-11-10T07:50:00.000Z") in {(p["pid"], p["image"], p["started"])
                                                                 for p in inv["processes"]}
    assert "processes" not in discover.run(texts, CATALOG, holes=holes)   # raqib discover --json: no new key
    # derived processes (a Sysmon event's Image) are not in the sample: only a process list is
    t2, h2 = discover.read_dir(str(FIX / "discover" / "windows"))
    inv2 = discover.run(t2, CATALOG, holes=h2, processes=True)
    listed = {p["pid"] for p in inv2["processes"]}
    procs = discover._merge_procs([r for s in [discover.parse_win_process(t2["win-process"][1])] for r in s[0]])
    assert listed == set(procs)


# --- E5 (P-3): Windows Defender's engine ------------------------------------------------------------------------

@pytest.mark.parametrize("exe, benign", [
    ("C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.25000.1-0\\MsMpEng.exe", True),
    ("C:\\Program Files\\Windows Defender\\MsMpEng.exe", True),
    ("C:\\Users\\user\\AppData\\Local\\Temp\\x\\MsMpEng.exe", False),
    ("D:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.1\\MsMpEng.exe", False),   # another drive
    ("C:\\Program Files\\Other\\MsMpEng.exe", False),        # pinned: not under the block's other directories
    ("C:\\Windows\\System32\\MsMpEng.exe", False),
    ("C:\\ProgramData\\Microsoft\\Windows Defender\\explorer.exe", False),   # its directory is msmpeng's only
    ("C:\\ProgramData\\Other\\MsMpEng.exe", False),
])
def test_e5_benign_by_image_and_directory(exe, benign):
    got, _ = discover.benign_check(discover.image_name(exe), exe, "record", CATALOG, "c")
    assert (got is not None) == benign, (exe, got)
    assert discover.benign_check("msmpeng", exe, "argv", CATALOG, "c")[0] is None   # a path the process wrote


def test_e5_the_catalog_pins_it_with_its_evasion_line():
    spec = CATALOG["benign_images"]
    assert "msmpeng" not in spec["names"] and spec["pinned"] == {"msmpeng": [
        "%systemdrive%/programdata/microsoft/windows defender/*", "%systemdrive%/program files/windows defender/*"]}
    (line,) = [e for e in spec["evasion"] if e.startswith("P-3 (M7.8) msmpeng")]
    assert "copied there is listed as benign" in line and "administrator rights" in line and "anywhere else" in line


@pytest.mark.parametrize("where, knocks", [("programdata", False), ("programfiles", False), ("copy", True)])
def test_e5_the_engine_is_listed_benign_and_a_copy_elsewhere_still_knocks(tmp_path, where, knocks):
    w = watch_rounds(tmp_path, ["defender/before", "defender/" + where], sysmon=False)
    news = [(f["rule_id"], f["image"]) for f in w.findings if f["rule_id"] in host.NEW_RULES]
    assert news == ([("NEW-AGENT-UNKNOWN", "msmpeng")] if knocks else [])
    assert w.round_lines[1]["benign"] == ([] if knocks else ["4400:msmpeng:2026-11-10T07:52:00.000Z"])
    (tree,) = w.trees.values()
    assert tree["benign"] is (not knocks)


def test_e5_the_catalog_still_loads_a_block_without_pinned():
    text = Path(discover.CATALOG).read_text(encoding="utf-8")
    lines = text.splitlines(True)
    i = next(n for n, x in enumerate(lines) if x.strip() == "pinned:")
    trimmed = "".join(lines[:i] + lines[i + 2:])
    path = ROOT / "tests" / ".tmp-endpoints-m78.yaml"
    try:
        path.write_text(trimmed, encoding="utf-8")
        cat = discover.load_catalog(str(path))
    finally:
        path.unlink()
    assert cat["benign_images"]["pinned"] == {}
    assert discover.benign_check("msmpeng", "C:\\Program Files\\Windows Defender\\MsMpEng.exe", "record", cat,
                                 "c")[0] is None


@pytest.mark.parametrize("pin, why", [
    ({"name": "explorer", "dirs": ["%systemdrive%/x/*"]}, "not in names"),
    ({"name": "x", "dirs": ["/usr/*"]}, "system drive"),
    ({"name": "X", "dirs": ["%systemdrive%/x/*"]}, "lower-case image name"),
    ({"name": "x"}, "must be {name, dirs}"),
])
def test_e5_a_bad_pin_is_a_catalog_error(pin, why):
    spec = {"kind": "signature", "names": ["explorer"], "dirs": ["%systemdrive%/windows/*"],
            "exclude": ["%systemdrive%/windows/temp/*"], "evasion": ["x"], "pinned": [pin]}

    def bad(field, msg):
        raise discover.CatalogError("%s: %s" % (field, msg))
    with pytest.raises(discover.CatalogError, match=re.escape(why)):
        discover._benign_spec(spec, bad)


# --- E2 (P-1): the two rules judge os process lines ----------------------------------------------------------

NET_WINDOWS = ("bitsadmin", "tftp", "finger", "plink", "pscp", "psftp", "winscp")
DESTRUCT_WINDOWS = ("format", "diskpart", "cipher", "sdelete", "sdelete64", "vssadmin", "wbadmin")
NOT_LISTED = ("git", "ping", "powershell", "pwsh", "cmd", "certutil", "mshta", "wmic", "robocopy", "node", "python",
              "msedge", "code", "explorer", "nslookup", "net", "fsutil", "wevtutil")


def osline(image, tool="process", seq=1):
    meta = {"command_head": "%s.exe" % image, "command_programs": ["%s.exe" % image], "image": image, "depth": 1}
    if tool != "process":
        meta = {"dest_port": 443, "dest_private": False}
    return {"ts": "2026-11-10T08:00:00.000Z", "seq": seq, "session_id": "os-5888", "phase": "pre", "tool": tool,
            "input_sha256": "0" * 64, "input_meta": meta, "cwd": "C:\\w", "source": "os"}


@pytest.mark.parametrize("rule_id, names", [("NET-TOOL", NET_WINDOWS + ("curl", "wget", "ssh", "scp", "ftp")),
                                            ("DESTRUCT-CMD", DESTRUCT_WINDOWS + ("rm", "dd", "shred", "rmdir"))])
def test_e2_every_listed_program_fires_on_an_os_line_a_host_line_and_a_bash_line(rule_id, names):
    r = rule(rule_id)
    for name in names:
        assert len(engine.run_rule(r, [osline(name)])) == 1, name
        child = {"ts": "2026-11-10T08:00:00.000Z", "seq": 1, "session_id": "host-5888", "phase": "pre",
                 "tool": "HostChild", "cwd": "host", "source": "host", "input_sha256": "0" * 64,
                 "input_meta": {"command_programs": [name]}}
        assert len(engine.run_rule(r, [child])) == 1, name
        bash = {"ts": "2026-11-10T08:00:00.000Z", "seq": 1, "session_id": "s", "phase": "pre", "tool": "Bash",
                "cwd": "/w", "input_sha256": "0" * 64, "input_meta": {"command_head": name, "command_programs": [name]}}
        assert len(engine.run_rule(r, [bash])) == 1, name


@pytest.mark.parametrize("rule_id", ["NET-TOOL", "DESTRUCT-CMD"])
def test_e2_what_is_not_listed_and_the_other_os_lines_do_not_fire(rule_id):
    r = rule(rule_id)
    for name in NOT_LISTED:
        assert engine.judge(r, [osline(name)]) == ([], []), name
    assert engine.judge(r, [osline("curl", tool="net"), osline("rm", tool="file")]) == ([], [])
    unread = osline("curl")
    unread["input_meta"] = {"command_unread": True, "image": None, "depth": 1}
    assert engine.judge(r, [unread]) == ([], [])   # judged: the name was not read, nothing to match
    post = dict(osline("curl" if rule_id == "NET-TOOL" else "rm"), phase="post", ok=True, output_meta={})
    assert engine.judge(r, [post]) == ([], [])


@pytest.mark.parametrize("rule_id, cite", [("NET-TOOL", ("curl", "bitsadmin", "plink")),
                                           ("DESTRUCT-CMD", ("rm", "vssadmin"))])
def test_e2_the_os_fixtures_positive_and_negative_and_the_budget_measured(rule_id, cite):
    r = rule(rule_id)
    pos = "tests/fixtures/rules/%s/positive-os-process.json" % rule_id
    neg = "tests/fixtures/rules/%s/negative-os-process.json" % rule_id
    assert pos in r.fixtures["positive"] and neg in r.fixtures["negative"]
    lines, _, expect = fixtures.load_fixture(ROOT / pos)
    found, unknown = engine.judge(r, lines)
    assert unknown == [] and sorted({s for f in found for s in f["cited_seq"]}) == expect
    cited = {(f["session_id"], s) for f in found for s in f["cited_seq"]}
    assert sorted(l["input_meta"]["image"] for l in lines if (l["session_id"], l["seq"]) in cited
                  and l["phase"] == "pre") == sorted(cite)   # each listed program's own line, and nothing else
    assert fixtures.outcome(r, ROOT / neg) == (False, set(), True)   # measured, clean
    neg_lines = fixtures.load_fixture(ROOT / neg)[0]
    sessions = {l["session_id"] for l in neg_lines}
    assert {"os-5100", "os-6050", "os-10728"} <= sessions   # the benign Windows desktop and Kimi's tree, as os lines
    report = fixtures.check_rule(r, ROOT, [str(p) for p in fixtures.benign_corpus(FIX / "rules" / "benign")]
                                 + sorted(str(p) for p in FIX.glob("*.log")))
    assert report["verdict"] == "ok" and (report["measured"], report["unmeasured"]) == (12, 0)
    assert round(report["fp_rate"], 3) == 0.083 and report["fp_rate"] <= r.fp_budget   # 1 of 12


@pytest.mark.parametrize("rule_id", ["NET-TOOL", "DESTRUCT-CMD"])
def test_e2_the_evasions_say_what_is_still_unseen(rule_id):
    (line,) = [e for e in rule(rule_id).evasion if e.startswith("os source (M7.8")]
    for words in ("shell builtin", "cmdlet", "renamed copy", "argument", "written before M7.8"):
        assert words in line, words


# --- E3: a finding of an os line, on its tree ------------------------------------------------------------------

def test_e3_an_os_finding_shows_on_its_tree_cites_its_line_and_knocks_as_a_source_finding(tmp_path):
    lines = os_lines("net-windows.sysmon.xml", 4700)
    follow = CountingFollow(lines)
    w = watch_rounds(tmp_path, ["defender/before", "quiet/talking", "quiet/talking"], follow=follow)
    found = [f for f in w.source_findings if f["rule_id"] == "NET-TOOL"]
    assert len(found) == 2 and {f["source"] for f in found} == {"os"} and {f["pid"] for f in found} == {5888}
    (src,) = w.sources.values()
    file_lines = Path(src.path).read_text(encoding="ascii").splitlines()
    for f in found:   # A5: the trace and its line, which is the os process line of the program
        assert f["trace"] == src.path and f["lines"]
        rec = json.loads(file_lines[f["lines"][0] - 1])
        assert rec["tool"] == "process" and rec["input_meta"]["image"] in ("bitsadmin", "plink")
        assert rec["seq"] in f["cited_seq"]
    tree = w.trees[next(iter(w.sources))]
    assert tree["source_findings"] == {"medium": 2}
    # I-6: medium, so no rule knock; the first finding of the tree knocks once as FIRST-FINDING
    events = [k["event"] for k in w.knocks]
    assert events.count(notify.FIRST_EVENT) == 1 and "NET-TOOL" not in events
    assert sorted(f["notice"] for f in found) == ["not notified: severity medium", "off"]   # off: a fixture notifier
    text, code = w.finish()
    assert code == 1 and "findings medium 2" in text and "SOURCE FINDINGS: 2 (2 live" in text
    assert "] NET-TOOL on powershell pid 5888 via os: process may reach the network" in text
    st = json.loads(Path(w.state_path).read_text(encoding="ascii"))
    assert {f["rule_id"] for f in st["host"]["source_findings"]} == {"NET-TOOL"}
    assert [t["source_findings"] for t in st["host"]["trees"]] == [{"medium": 2}]
    page = "\n".join(ui.host_section(st))
    assert "<span class=\"tag\">NET-TOOL</span>" in page and "medium 2" in page and src.path in page


def test_e3_a_source_of_lines_before_m78_is_said_once_and_not_guessed(tmp_path):
    follow = CountingFollow(old_shape(os_lines("net-windows.sysmon.xml", 4700)))
    w = watch_rounds(tmp_path, ["defender/before", "quiet/talking", "quiet/talking"], follow=follow)
    assert w.source_findings == []
    said = [n for n in w.notes if "carry no input_meta.image" in n]
    assert said == ["tree %s, its os source: %s" % (SHELL, host.PRE_M78_NOTE % 4)]
    assert not [n for n in w.notes if "NET-TOOL partial" in n or "DESTRUCT-CMD partial" in n]


# --- E6: THREAT_MODEL's host watch -------------------------------------------------------------------------

def test_e6_threat_model_says_what_the_host_watch_sees():
    text = (ROOT / "docs" / "THREAT_MODEL.md").read_text(encoding="utf-8")
    assert "### The host watch" in text
    section = " ".join(text.split("### The host watch", 1)[1].split("\n## ", 1)[0].split())
    for words in ("between two rounds", "ADR-0007 P-4", "quiet", "person's hands", "There is no timing rule",
                  "clipboard's text is never read", "stops nothing", "A4", "MsMpEng", "cmdlet", "builtin"):
        assert words in section, words


def test_e7_readme_says_it():
    text = " ".join((ROOT / "README.md").read_text(encoding="utf-8").split())
    assert "quiet" in text and "input_meta.image" in text and "bitsadmin" in text and "vssadmin" in text
    assert "SECRET-OUTPUT and NET-TOOL do not judge os lines" not in text
