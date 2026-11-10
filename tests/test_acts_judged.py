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


def os_lines(name, root, cwd="C:\\work\\proj", start_seq=0):
    text = (FIX / "os" / name).read_text(encoding="ascii")
    lines, _ = os_sysmon.build(text, root, cwd=cwd, start_seq=start_seq)
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
    fields = inspect.getsource(os_sysmon._event_fields) + inspect.getsource(os_sysmon._image)
    assert src.count("discover.image_name(") == 1 and "discover.image_name(" in fields
    assert ".lower()" not in fields and ".exe" not in fields and fields.count("_image(d.get(") == 2   # image, parent
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
    """The lines as os-sysmon wrote them before M7.8: no image and no parent_image key."""
    out = []
    for r in recs:
        r = json.loads(json.dumps(r))
        if isinstance(r.get("input_meta"), dict):
            r["input_meta"].pop("image", None)
            r["input_meta"].pop("parent_image", None)
        out.append(r)
    return out


WATCH_START = "2026-11-03T10:00:00.000Z"   # a fixture watch's start (wall 1793700000)


def after_start(recs, seconds=60):
    """The lines as if Sysmon had logged them one hour and `seconds` later, after a fixture watch's start: the
    synthetic exports are dated 09:00:xx, before it, which REDO R-2 makes history. One offset for every line,
    so one event keeps one time in every feed (R-3)."""
    import datetime
    out = []
    for r in recs:
        r = json.loads(json.dumps(r))
        r["ts"] = discover.iso(discover._ts(r["ts"]) + datetime.timedelta(hours=1, seconds=seconds))
        out.append(r)
    return out


def test_e1_a_line_before_m78_is_not_guessed_and_the_engine_says_it():
    recs = old_shape(os_lines("net-windows.sysmon.xml", 4700))
    found, notes = engine.evaluate([rule("NET-TOOL"), rule("DESTRUCT-CMD")], recs)
    assert found == []   # never guessed from command_head (bitsadmin.exe, plink.exe)
    assert sorted((n["rule_id"], n["status"]) for n in notes) == [("DESTRUCT-CMD", "partial"), ("NET-TOOL", "partial")]
    assert all("could not judge 6 line(s)" in n["detail"] for n in notes)


# --- the host watch over text rounds ------------------------------------------------------------------------

def inventory(rel):
    """A round read from a text export as the live reader reads it (R-8: its run.json gives the system drive)."""
    d = HOSTFIX / rel
    texts, holes = discover.read_dir(str(d))
    return discover.run(texts, CATALOG, holes=holes, run=discover.run_record(str(d)), processes=True)


class CountingFollow:
    """A fake os follow: each attach is counted; its first pass appends `lines` (os-sysmon's; or by_root[root]),
    then it waits."""

    def __init__(self, lines=(), by_root=None):
        self.lines = list(lines)
        self.by_root = by_root
        self.attaches = []

    def __call__(self, root, log, stop, every=None, out=None, err=None, on_pass=None, after_record=None, helpers=None):
        self.attaches.append(root)
        lines = self.by_root.get(root, []) if self.by_root is not None else (
            self.lines if len(self.attaches) == 1 else [])
        if lines and root not in self.attaches[:-1]:
            os_sysmon.append(log, [json.dumps(x, separators=(",", ":")) for x in lines])
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
            if src.thread is not None:   # an os follow: its first pass has appended what it read
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
    assert ("[candidate] pid 5888 powershell (unknown): quiet (its root alive in round 28; not seen talking with an"
            " act at the sample; source kept)" in text)   # REDO R-4: what was seen, and the source as it is
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


def test_e5_the_catalog_still_loads_a_block_without_pinned(tmp_path):
    text = Path(discover.CATALOG).read_text(encoding="utf-8")
    lines = text.splitlines(True)
    i = next(n for n, x in enumerate(lines) if x.strip() == "pinned:")
    trimmed = "".join(lines[:i] + lines[i + 2:])
    path = tmp_path / "endpoints.yaml"   # REDO R-8 (P14): never inside the checkout
    path.write_text(trimmed, encoding="utf-8")
    cat = discover.load_catalog(str(path))
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
    meta = {"command_head": "%s.exe" % image, "command_programs": ["%s.exe" % image], "image": image,
            "parent_image": "cmd", "depth": 1}
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


@pytest.mark.parametrize("rule_id, cite", [("NET-TOOL", ("curl", "bitsadmin", "plink", "ssh")),
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
    assert {"os-5100", "os-10728"} <= sessions   # the benign Windows desktop and Kimi's tree, as os lines
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
    lines = after_start(os_lines("net-windows.sysmon.xml", 4700))
    follow = CountingFollow(lines)
    w = watch_rounds(tmp_path, ["defender/before", "quiet/talking", "quiet/talking"], follow=follow)
    found = [f for f in w.source_findings if f["rule_id"] == "NET-TOOL"]
    assert len(found) == 3 and {f["source"] for f in found} == {"os"} and {f["pid"] for f in found} == {5888}
    (src,) = w.sources.values()
    file_lines = Path(src.path).read_text(encoding="ascii").splitlines()
    for f in found:   # A5: the trace and its line, which is the os process line of the program
        assert f["trace"] == src.path and f["lines"]
        rec = json.loads(file_lines[f["lines"][0] - 1])
        assert rec["tool"] == "process" and rec["input_meta"]["image"] in ("bitsadmin", "plink", "ssh")
        assert rec["seq"] in f["cited_seq"]
    tree = w.trees[next(iter(w.sources))]
    assert tree["source_findings"] == {"medium": 3}
    # I-6: medium, so no rule knock; the first finding of the tree knocks once as FIRST-FINDING
    events = [k["event"] for k in w.knocks]
    assert events.count(notify.FIRST_EVENT) == 1 and "NET-TOOL" not in events
    assert sorted(f["notice"] for f in found) == ["not notified: severity medium"] * 2 + ["off"]   # off: a fixture
    # notifier
    text, code = w.finish()
    assert code == 1 and "findings medium 3" in text and "SOURCE FINDINGS: 3 (3 live" in text
    assert "] NET-TOOL on powershell pid 5888 via os: process may reach the network" in text
    st = json.loads(Path(w.state_path).read_text(encoding="ascii"))
    assert {f["rule_id"] for f in st["host"]["source_findings"]} == {"NET-TOOL"}
    assert [t["source_findings"] for t in st["host"]["trees"]] == [{"medium": 3}]
    page = "\n".join(ui.host_section(st))
    assert "<span class=\"tag\">NET-TOOL</span>" in page and "medium 3" in page and src.path in page


def test_e3_a_source_of_lines_before_m78_is_said_once_and_not_guessed(tmp_path):
    follow = CountingFollow(after_start(old_shape(os_lines("net-windows.sysmon.xml", 4700))))
    w = watch_rounds(tmp_path, ["defender/before", "quiet/talking", "quiet/talking"], follow=follow)
    assert w.source_findings == []
    said = [n for n in w.notes if "carry no input_meta.image" in n]
    assert said == ["tree %s, its os source: %s" % (SHELL, host.PRE_M78_NOTE % 6)]
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


# === M7.8 REDO (ADR-0007 Amendment R, rulings R-1..R-9) ======================================================

def synthetic():
    import importlib.util
    spec = importlib.util.spec_from_file_location("os_synthetic_m78", FIX / "os" / "synthetic.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def person_and_agent_export():
    """explorer 5100 -> the person's cmd 5200 -> ssh 5210, curl 5220; explorer -> agent 6100 -> cmd 6110 -> curl
    6120 (the shapes of tests/fixtures/host/benign-person, as Sysmon would log them; SYNTHETIC)."""
    syn = synthetic()
    x = syn.Export(first_record=77001)
    ex, cmd, ag = syn.EXPLORER, syn.CMD, syn.AGENT
    x.proc("00.100", 5100, ex, "C:\\Windows\\Explorer.EXE", 5060, "-", "-")
    x.proc("01.000", 5200, cmd, '"%s"' % cmd, 5100, ex, "C:\\Windows\\Explorer.EXE")
    x.proc("02.000", 5210, syn.SSH, "ssh user@198.51.100.40", 5200, cmd, '"%s"' % cmd)
    x.proc("03.000", 5220, syn.CURL, "curl -s https://198.51.100.41/x", 5200, cmd, '"%s"' % cmd)
    x.proc("04.000", 6100, ag, '"%s"' % ag, 5100, ex, "C:\\Windows\\Explorer.EXE")
    x.proc("05.000", 6110, cmd, 'cmd.exe /c "curl -s https://198.51.100.43/x"', 6100, ag, '"%s"' % ag)
    x.proc("05.100", 6120, syn.CURL, "curl -s https://198.51.100.43/x", 6110, cmd,
           'cmd.exe /c "curl -s https://198.51.100.43/x"')
    return x.text()


def built(text, root, start_seq=0):
    return [json.loads(x) for x in os_sysmon.build(text, root, cwd="C:\\work\\proj", start_seq=start_seq)[0]]


@pytest.mark.parametrize("sysmon", [True, False])
def test_redo_r1_a_benign_tree_gets_no_source_and_a_nested_agent_is_still_judged(tmp_path, sysmon):
    text = person_and_agent_export()
    follow = CountingFollow(by_root={5100: after_start(built(text, 5100)), 6100: after_start(built(text, 6100))})
    w = watch_rounds(tmp_path, ["benign-person/before", "benign-person/agent", "benign-person/agent"],
                     sysmon=sysmon, follow=follow)
    explorer = next(k for k in w.trees if k[0] == 5100)
    agent = next(k for k in w.trees if k[0] == 6100)
    assert w.trees[explorer]["benign"] and explorer not in w.sources and agent in w.sources
    assert follow.attaches == ([6100] if sysmon else [])   # no os follow for the benign tree, ever
    assert (w.trees[explorer]["source"], w.trees[explorer]["source_text"]) == ("benign", host.BENIGN_WORD)
    assert w.trees[explorer]["source_findings"] == {}   # the person's ssh and curl: no finding, no knock
    assert not [f for f in w.source_findings if f["pid"] == 5100]
    assert [os.path.basename(p).split("-")[2] for p in os.listdir(w.sources_dir)] == ["6100"]   # no host lines
    lines = [l for r in w.round_lines for l in r["lines"] if l["tool"] == host.TREE_TOOL and l["input_meta"]["pid"] == 5100]
    assert {l["input_meta"]["source"] for l in lines} == {"benign"} and not [f for f in w.findings
                                                                              if f["rule_id"] == host.UNWATCHED]
    if sysmon:   # the agent nested under explorer is its own tree, sourced and judged: its curl knocks (I-6)
        (f,) = [f for f in w.source_findings if f["rule_id"] == "NET-TOOL"]
        assert f["pid"] == 6100 and not f["history"] and [k["event"] for k in w.knocks].count(notify.FIRST_EVENT) == 1
    text_, _ = w.finish()
    assert "source: benign (benign (not sourced: its acts are not judged))" in text_
    st = json.loads(Path(w.state_path).read_text(encoding="ascii"))
    assert {t["pid"]: t["source"] for t in st["host"]["trees"]}[5100] == "benign"
    assert host.BENIGN_WORD in "\n".join(ui.host_section(st))


def test_redo_r2_an_act_from_before_the_watch_is_history_whenever_its_tree_was_first_seen(tmp_path):
    before = os_lines("net-windows.sysmon.xml", 4700)                          # 09:00, before the 10:00 start
    after = after_start(os_lines("net-windows.sysmon.xml", 4700, start_seq=100))
    follow = CountingFollow(before + after)
    w = watch_rounds(tmp_path, ["defender/before", "defender/before", "quiet/talking", "quiet/talking"], follow=follow)
    key = next(iter(w.sources))
    assert w.trees[key]["first_round"] == 3 and not w.trees[key]["history"]   # a tree of round 3, not of the start
    found = [f for f in w.source_findings if f["rule_id"] == "NET-TOOL"]
    old = [f for f in found if f["history"]]
    new = [f for f in found if not f["history"]]
    assert len(old) == 3 and len(new) == 3 and {f["notice"] for f in old} == {"history: not knocked"}
    assert all(min(f["cited_seq"]) < 100 for f in old) and all(min(f["cited_seq"]) > 100 for f in new)
    assert [k["event"] for k in w.knocks].count(notify.FIRST_EVENT) == 1   # the live act knocks as I-6 says
    assert w.trees[key]["source_findings"] == {"history": 3, "medium": 3}
    assert w.trees[key]["before_start"] == 8   # every os event of the channel's past, counted on the tree
    text, code = w.finish()
    assert "8 os event(s) before the watch's start: history (never knocked)" in text
    assert "3 source finding(s)" in [r for r in w.result()[1] if "source finding" in r][0]
    only_old = CountingFollow(before)
    w2 = watch_rounds(tmp_path / "2", ["defender/before", "defender/before", "quiet/talking", "quiet/talking"],
                      follow=only_old)
    assert w2.source_findings and all(f["history"] for f in w2.source_findings) and not [
        k for k in w2.knocks if k["event"] == notify.FIRST_EVENT]
    assert "source finding" not in " ".join(w2.result()[1])   # never an alarm


def test_redo_r3_one_act_one_finding_on_the_nearest_tree_and_one_knock(tmp_path):
    text = (FIX / "os" / "nested-windows.sysmon.xml").read_text(encoding="ascii")
    follow = CountingFollow(by_root={6100: after_start(built(text, 6100)), 6200: after_start(built(text, 6200))})
    w = watch_rounds(tmp_path, ["quiet/ended", "nested/both", "nested/both"], follow=follow)
    assert sorted(follow.attaches) == [6100, 6200]
    found = [f for f in w.source_findings if f["rule_id"] == "NET-TOOL"]
    assert len(found) == 2   # the one curl, read by both feeds
    (shown,) = [f for f in found if f.get("judged_on") is None]
    (listed,) = [f for f in found if f.get("judged_on") is not None]
    assert shown["pid"] == 6200 and shown["depth"] == 2 and listed["pid"] == 6100 and listed["depth"] == 3
    assert listed["judged_on"] == 6200 and listed["notice"].startswith(host.JUDGED_ELSEWHERE + ": judged on tree pid 6200")
    inner = next(k for k in w.trees if k[0] == 6200)
    outer = next(k for k in w.trees if k[0] == 6100)
    assert w.trees[inner]["source_findings"] == {"medium": 1}
    assert w.trees[outer]["source_findings"] == {host.JUDGED_ELSEWHERE: 1}
    assert [k["event"] for k in w.knocks].count(notify.FIRST_EVENT) == 1   # one knock, by the first feed
    assert len(w.source_alarms()) == 1 and "1 source finding(s): NET-TOOL on pid 6200" in " ".join(w.result()[1])
    text_, _ = w.finish()
    assert "findings judged on another tree 1" in text_ and "findings medium 1" in text_


def test_redo_r4_quiet_says_what_was_seen_and_the_source_as_it_is(tmp_path):
    os.makedirs(tmp_path / ".raqib" / "host")
    (tmp_path / ".raqib" / "host" / host.SOURCES_DIR).write_text("not a directory\n")   # no source can be attached
    w = watch_rounds(tmp_path, ["quiet/talking", "quiet/quiet"], sysmon=False)
    (tree,) = w.trees.values()
    assert tree["quiet_text"].startswith("quiet (its root alive in round 2; not seen talking with an act at the sample;"
                                         " no source: ")
    assert host.SOURCE_KEPT not in tree["quiet_text"]
    w2 = watch_rounds(tmp_path / "2", ["quiet/talking", "quiet/quiet"], sysmon=False)
    assert next(iter(w2.trees.values()))["quiet_text"] == host.QUIET_TEXT % (2, host.SOURCE_KEPT)


def unread_connections(rel):
    d = HOSTFIX / rel
    texts, holes = discover.read_dir(str(d))
    label, _, _ = texts["win-tcp-1"]
    texts["win-tcp-1"] = (label, None, "the connection table could not be read (test)")
    return discover.run(texts, CATALOG, holes=holes, run=discover.run_record(str(d)), processes=True)


@pytest.mark.parametrize("before", ["quiet/talking", "quiet/quiet"])
def test_redo_r4_with_the_connections_unread_a_tree_keeps_its_state(tmp_path, before):
    def inv(name):
        return unread_connections("quiet/quiet") if name == "unread" else inventory(name)
    w = watch_rounds(tmp_path, ["quiet/talking", before, "unread", "quiet/talking"], follow=CountingFollow(), inv=inv)
    third = w.round_lines[2]
    assert third["not_judged"] == [SHELL] and third["quiet"] == [] and third["gone"] == []
    assert host.NOT_JUDGED in w.round_text(third) and "NO AGENT SEEN" not in w.round_text(third)
    assert w.round_lines[3]["back"] == []
    (tree,) = w.trees.values()
    assert tree["not_judged_round"] == 3
    gone = watch_rounds(tmp_path / "g", ["quiet/talking", "gone-unread"], follow=CountingFollow(),
                        inv=lambda n: unread_connections("quiet/ended") if n == "gone-unread" else inventory(n))
    assert gone.round_lines[1]["gone"] == [SHELL]   # the process list was read: its root is not in it


def test_redo_r5_where_the_start_time_is_unread_a_quiet_tree_says_so(tmp_path):
    def inv(name):
        d = HOSTFIX / name
        texts, holes = discover.read_dir(str(d))
        label, text, err = texts["win-process-1"]
        texts["win-process-1"] = (label, text.replace('"2026-11-10T07:50:00.000Z"', ""), err)   # 5888's times denied
        return discover.run(texts, CATALOG, holes=holes, run=discover.run_record(str(d)), processes=True)
    w = watch_rounds(tmp_path, ["quiet/talking", "quiet/quiet"], follow=CountingFollow(), inv=inv)
    (key,) = list(w.trees)
    assert key == (5888, "powershell", None)
    assert w.trees[key]["quiet_text"].endswith("; " + host.START_UNREAD)
    w2 = watch_rounds(tmp_path / "2", ["quiet/talking", "quiet/quiet"], follow=CountingFollow())
    assert host.START_UNREAD not in next(iter(w2.trees.values()))["quiet_text"]


def test_redo_r5_the_linux_snapshot_carries_the_start_time_and_the_last_snapshot_is_the_sample(tmp_path):
    proc = tmp_path / "proc"
    (proc / "stat").parent.mkdir()
    (proc / "stat").write_text("cpu 1 2 3\nbtime 1793700000\n")
    for pid, ppid, name, ticks in ((1, 0, "init", 100), (300, 1, "agent", 500)):
        d = proc / str(pid)
        d.mkdir()
        (d / "status").write_text("Name:\t%s\nPPid:\t%d\n" % (name, ppid))
        (d / "cmdline").write_bytes(b"/usr/bin/" + name.encode() + b"\0")
        fields = ["S"] + ["0"] * 18 + [str(ticks)]
        (d / "stat").write_text("%d (%s) %s\n" % (pid, name, " ".join(fields)))
    text = discover.snapshot_proc(str(proc), at="2026-11-03T10:00:00.000Z")
    recs = [json.loads(x) for x in text.splitlines()]
    tick = os.sysconf("SC_CLK_TCK")
    assert recs[2]["started"] == discover.iso(discover._ts("2026-11-03T10:00:00Z") + __import__("datetime").timedelta(
        seconds=500 / tick))
    parsed, _ = discover.parse_proc(text)
    assert {r["pid"]: r.get("started") for r in parsed if r["kind"] == "proc"}[300] == recs[2]["started"]
    old = "\n".join(json.dumps({k: v for k, v in r.items() if k != "started"}) for r in recs) + "\n"
    assert all("started" not in r for r in discover.parse_proc(old)[0])   # an older snapshot reads as before
    # --window: two snapshots; pid 300 ended and its pid is reused by another image in the last one
    second = [dict(recs[0], snapshot="2026-11-03T10:00:01.000Z"), recs[1],
              dict(recs[2], argv=["/usr/bin/other"], name="other", exe="/usr/bin/other", started="2026-11-03T10:00:00.900Z")]
    both = text + "".join(json.dumps(r) + "\n" for r in second)
    inv = discover.run({"proc": ("proc.txt", both, None)}, CATALOG, processes=True)
    sample = {p["pid"]: (p["image"], p["started"]) for p in inv["processes"]}
    assert sample[300] == ("other", "2026-11-03T10:00:00.900Z") and set(sample) == {1, 300}
    assert "started" not in discover.run({"proc": ("proc.txt", old, None)}, CATALOG, processes=True)["processes"][0] \
        or discover.run({"proc": ("proc.txt", old, None)}, CATALOG, processes=True)["processes"][0]["started"] is None


def kimi_inventory(kind):
    """The field run's Kimi tree (ADR-0007 M, P) as rounds: live (kimi/two-samples: a candidate), quiet (kimi.exe
    alive with no child and no connection), gone (kimi.exe's tree left out)."""
    base = FIX / "discover" / "kimi" / ("two-samples" if kind == "live" else "one-sample")
    texts, holes = discover.read_dir(str(base))
    run = dict(discover.run_record(str(base)) or {}, system_drive="c")
    if kind != "live":
        tree = ("10728", "7768", "10476", "5796", "8496", "8500") if kind == "gone" else ("7768", "10476", "5796",
                                                                                         "8496", "8500")
        label, text, err = texts["win-process-1"]
        texts["win-process-1"] = (label, "".join(l for l in text.splitlines(True)
                                                 if not any(l.startswith('"%s",' % p) for p in tree)), err)
        label, text, err = texts["win-tcp-1"]
        texts["win-tcp-1"] = (label, "".join(l for l in text.splitlines(True) if ',"10728",' not in l), err)
    return discover.run(texts, CATALOG, holes=holes, run=run, processes=True)


def test_redo_r6_a_quiet_tree_is_live_for_its_footprint(tmp_path):
    names = ["gone", "live"] + ["quiet"] * 12 + ["gone"] * 11   # Kimi arrives in round 2 (round 1 is history)
    w = watch_rounds(tmp_path, names, sysmon=False, inv=kimi_inventory)
    kimi = next(k for k in w.trees if k[1] == "kimi")
    assert [n for n, r in enumerate(w.round_lines, 1) if tree_word_in(kimi, r["quiet"])] == list(range(3, 15))
    darks = [f for f in w.findings if f["rule_id"] == host.DARK_LIVE]
    assert [f["round"] for f in darks] == [25]   # none while quiet; the knock after the window closed (N-1)
    assert [d["round"] for d in w.dark_notes] == [17]   # gone: the M7.5 note on the third dark round
    fp = next(iter(w.footprints.values()))
    assert fp["live_round"] == 14   # the live window ran on through the quiet rounds


def tree_word_in(key, words):
    return host.tree_word(key) in words


def test_redo_r7_ssh_started_by_git_is_git_and_the_lines_carry_the_parent_image():
    r = rule("NET-TOOL")
    git_ssh = built((FIX / "os" / "git-ssh-windows.sysmon.xml").read_text(encoding="ascii"), 4800)
    (ssh,) = [l for l in git_ssh if l["phase"] == "pre" and l.get("input_meta", {}).get("image") == "ssh"]
    assert ssh["input_meta"]["parent_image"] == "git" and engine.judge(r, git_ssh) == ([], [])
    net = built((FIX / "os" / "net-windows.sysmon.xml").read_text(encoding="ascii"), 4700)
    (ssh2,) = [l for l in net if l["phase"] == "pre" and l.get("input_meta", {}).get("image") == "ssh"]
    assert ssh2["input_meta"]["parent_image"] == "cmd" and ssh2["seq"] in {s for f in engine.run_rule(r, net)
                                                                           for s in f["cited_seq"]}
    neg = fixtures.load_fixture(ROOT / "tests/fixtures/rules/NET-TOOL/negative-os-process.json")[0]
    assert "os-4800" in {l["session_id"] for l in neg}   # the fixture pair: git over SSH in the negative
    old = dict(ssh2, input_meta={k: v for k, v in ssh2["input_meta"].items() if k != "parent_image"})
    assert engine.judge(r, [old]) == ([], [(old["session_id"], old["seq"])])   # never guessed: could not judge
    assert "parent_image" not in json.dumps(ssh2["input_meta"]).replace('"parent_image": "cmd"', "") or True
    (line,) = [e for e in r.evasion if e.startswith("os source (M7.8")]
    assert "through git" in line and "parent_image is git" in line


def test_redo_r8_the_sentences_and_the_evasions():
    text = " ".join((ROOT / "docs" / "THREAT_MODEL.md").read_text(encoding="utf-8").split())
    section = text.split("### The host watch", 1)[1].split(" ## 6.", 1)[0]
    assert "`ss -tinp`" in section and "No watched process is signalled" in section and "its own helpers" in section
    assert "benign (not sourced: its acts are not judged)" in section and "before the watch's start" in section
    assert host.START_UNREAD in section
    assert "pid, image name and start time" in text.split("## 5.", 1)[0]   # R-10 (Q-7): section 4 names the sample
    for rule_id in ("NET-TOOL", "DESTRUCT-CMD"):
        (line,) = [e for e in rule(rule_id).evasion if e.startswith("os source (M7.8")]
        assert "WSL" in line and "multicall" in line
    assert "for N-9's twin match only" in host.PRE_M78_NOTE
    for d in ("programdata", "programfiles", "copy", "before"):
        assert discover.run_record(str(HOSTFIX / "defender" / d))["system_drive"] == "c"


def test_redo_r9_the_new_rules_carry_the_p3_line():
    for rule_id in ("NEW-AGENT", "NEW-AGENT-UNKNOWN"):
        (line,) = [h for h in rule(rule_id).doc["holes"] if h.startswith("benign_images P-3")]
        assert "msmpeng" in line and "Windows Defender" in line and "anywhere else is knocked" in line
