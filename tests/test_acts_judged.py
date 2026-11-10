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
from hostthreads import raqib_threads_end  # noqa: E402,F401  (V-5: every HostWatch ended, no thread leaked)

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


WATCHES = []   # the watches a test of this file built through watch_rounds (the fixture finds them all itself)


# REDO 2 T-6 / REDO 3 V-5: the fixture is tests/hostthreads.py's raqib_threads_end (imported above), which ends every
# HostWatch a test of this file builds and fails a test that leaves a raqib- thread alive.


class CountingFollow:
    """A fake os follow: each attach is counted; its first pass appends `lines` (os-sysmon's; or by_root[root]),
    then it waits on the stop it is given, with no time limit (T-6)."""

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
        stop.wait()
        return 1


def watch_rounds(tmp_path, names, sysmon=True, follow=None, inv=inventory, between=None, wall=None):
    """The HostWatch fed these rounds (fixture clock). between(w, k): called after round k's first tick and
    before the poll that judges what the sources gained (T-1: to append lines or reorder the feeds). wall(t):
    the wall clock at fixture time t (T-3), default the fixture's start plus t."""
    invs = iter([inv(n) for n in names])
    clock = host.FixtureClock()
    notifier = notify.Notifier(host.HOST, enabled=False, reason="fixture", host=True)
    kw = {"os_follow": follow} if follow is not None else {}
    wall = wall or (lambda t: 1793700000.0 + t)
    w = host.HostWatch(lambda: next(invs), CATALOG, RULES, notifier, every=10, out=None, err=io.StringIO(),
                       clock=clock, wall=lambda: wall(clock.t), home=str(tmp_path), platform="fixture",
                       run="fixture-run", sysmon=(lambda: (True, "fixture: Sysmon")) if sysmon
                       else (lambda: (False, "fixture: no Sysmon")), **kw)
    WATCHES.append(w)   # T-6: ended by the fixture if the test does not
    for k, _ in enumerate(names, start=1):
        w.tick(wait=30)
        for src in list(w.sources.values()):
            if src.thread is not None:   # an os follow: its first pass has appended what it read
                src.first_pass.wait(5)
        if between is not None:
            between(w, k)
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
    assert sorted(f["notice"] for f in found) == ["not notified: severity medium"] * 2 + [
        "off (knocked on tree pid 5888)"]   # off: a fixture notifier; V-1: the act says which tree knocked
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
    # V-3 (U7): said once, and its count is the final one (the first judge may have seen part of an append)
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


def test_redo2_t2_the_persons_ssh_under_explorer_is_a_note_exit_0_no_knock(tmp_path):
    """T-2 (R-1 amended): a benign tree is sourced like any other; what its acts match is a note."""
    text = person_and_agent_export()
    follow = CountingFollow(by_root={5100: after_start(built(text, 5100))})
    w = watch_rounds(tmp_path, ["benign-person/before", "benign-person/before"], follow=follow)
    (explorer,) = list(w.trees)
    tree = w.trees[explorer]
    assert tree["benign"] and explorer in w.sources and follow.attaches == [5100]   # sourced again
    assert tree["benign_word"] == host.BENIGN_WORD == "benign (its acts are noted, not knocked; its rhythm is judged)"
    notes = [f for f in w.source_findings if f["rule_id"] == "NET-TOOL"]
    # ssh and curl of the person's cmd, and a curl below explorer that no tree of its own holds in these rounds
    assert len(notes) == 3 and all(f["benign_note"] and f["notice"].startswith(host.BENIGN_NOTE) for f in notes)
    assert tree["source_findings"] == {host.BENIGN_COUNT: 3} and tree.get("first_knock") is None   # FIRST not spent
    assert w.knocks == [] and w.source_alarms() == []
    text_, code = w.finish()
    assert code == 0 and "RESULT: CLEAN" in text_   # not an alarm: the exit code is unchanged
    assert "ON BENIGN TREES (noted, not knocked): 3" in text_ and "0 live" in text_
    assert "SOURCE FINDINGS: 3 (0 live, of them 0 pending at exit; 0 history; 0 judged on another tree; 3 on benign" \
           " trees, noted)" in text_
    lines = [l for r in w.round_lines for l in r["lines"] if l["tool"] == host.TREE_TOOL]
    assert {l["input_meta"]["source"] for l in lines} == {"os"}   # the HostTree line as before R-1
    st = json.loads(Path(w.state_path).read_text(encoding="ascii"))
    page = "\n".join(ui.host_section(st))
    assert host.BENIGN_WORD in page and host.BENIGN_COUNT + " 3" in page   # on the tree, on the page


def editor_export():
    """code.exe (benign: under the system drive's Program Files) -> its own extension host (code.exe) -> cmd ->
    curl: an agent inside the editor's own process (SYNTHETIC)."""
    syn = synthetic()
    code = "C:\\Program Files\\Microsoft VS Code\\Code.exe"
    x = syn.Export(first_record=78001)
    x.proc("00.100", 7100, code, '"%s"' % code, 5100, syn.EXPLORER, "C:\\Windows\\Explorer.EXE")
    x.proc("00.500", 7110, code, '"%s" --type=extensionHost' % code, 7100, code, '"%s"' % code)
    x.proc("05.000", 7120, syn.CMD, 'cmd.exe /c "curl -s https://198.51.100.47/x"', 7110, code,
           '"%s" --type=extensionHost' % code)
    x.proc("05.100", 7130, syn.CURL, "curl -s https://198.51.100.47/x", 7120, syn.CMD,
           'cmd.exe /c "curl -s https://198.51.100.47/x"')
    return x.text(), code


def test_redo2_t2_an_agents_curl_under_an_editors_own_process_is_a_note_on_that_tree(tmp_path):
    text, code = editor_export()

    def inv(name):
        i = inventory("quiet/ended")
        if name == "editor":
            i["candidates"] = [{"pid": 7100, "image": "code", "exe": code, "exe_from": "record",
                                "started": "2026-11-10T07:46:00.000Z", "cwd": None, "id": "C1",
                                "cites": [{"src": "win-process-1", "line": 9, "text": "code 7100 (test)"}],
                                "acts": [{"how": "process", "pid": 7110, "image": "code", "started": None,
                                          "cites": []}],
                                "talks": [{"remote": "203.0.113.48:443", "endpoint": [], "cites": []}]}]
        return i
    follow = CountingFollow(by_root={7100: after_start(built(text, 7100))})
    w = watch_rounds(tmp_path, ["none", "editor", "editor"], follow=follow, inv=inv)
    (key,) = [k for k in w.trees if k[0] == 7100]
    assert w.trees[key]["benign"] and follow.attaches == [7100]   # an editor's tree is sourced (S2)
    (f,) = [f for f in w.source_findings if f["rule_id"] == "NET-TOOL"]
    assert f["pid"] == 7100 and f["benign_note"] and not f["history"]   # the agent's curl: a note on that tree
    assert w.trees[key]["source_findings"] == {host.BENIGN_COUNT: 1}
    assert not [k for k in w.knocks if k["event"] in (notify.FIRST_EVENT, "NET-TOOL")]


def test_redo2_t2_rhythm_on_a_benign_tree_still_knocks(tmp_path):
    from raqib.rules import fixturegen

    def inv(name):
        i = fixturegen.rhythm_inventory("cycle", int(name))
        tree = i["candidates"][0]
        tree.update(image="explorer", exe="C:\\Windows\\explorer.exe")   # benign: a listed image and directory
        return i
    w = watch_rounds(tmp_path, [str(k) for k in range(1, 5)], sysmon=False, inv=inv)
    (tree,) = w.trees.values()
    rhythm = [f for f in w.findings if f["rule_id"] == host.RHYTHM]
    assert len(rhythm) == 1 and [k["event"] for k in w.knocks].count(host.RHYTHM) == 1   # K-10: judged, and knocks
    text, code = w.finish()
    assert code == 1 and tree["benign"]
    # V-3 (U8): the benign word says what happened to the tree, never "not knocked" beside a knock
    assert tree["benign_word"] == "benign (its acts are noted; knocked here: HOST-RHYTHM; its rhythm is judged)"
    assert "(benign: c:/windows/*, knocked: HOST-RHYTHM)" in text and "c:/windows/*, not knocked" not in text


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


def nested_copies():
    """The curl of tests/fixtures/os/nested-windows as each tree's os source writes it (after the start): its
    pre and post lines under the outer root (depth 3) and under the inner one (depth 2), seqs apart."""
    text = (FIX / "os" / "nested-windows.sysmon.xml").read_text(encoding="ascii")
    out = {}
    for root in (6100, 6200):
        lines = after_start(built(text, root, start_seq=50))
        out[root] = [l for l in lines if l.get("input_meta", {}).get("image") == "curl"]
    return out


def own_act(root, seq, image):
    """An act of one tree only (a child of its root), after the start: a pre and a post line of its os source."""
    meta = {"command_head": image + ".exe", "command_programs": [image + ".exe"], "image": image,
            "parent_image": "outer" if root == 6100 else "inner", "depth": 1}
    base = {"ts": "2026-11-03T10:00:30.000Z", "seq": seq, "session_id": "os-%d" % root, "tool": "process",
            "input_sha256": common.canonical_sha256({"command_line": "%s %d" % (image, root)}), "input_meta": meta,
            "cwd": "C:\\work\\proj", "source": "os"}
    return [dict(base, phase="pre"), dict(base, phase="post", output_meta={}, ok=True)]


def append_to(w, pid, lines):
    key = next(k for k in w.sources if k[0] == pid)
    os_sysmon.append(w.sources[key].path, [json.dumps(x, separators=(",", ":")) for x in lines])


def nested_watch(tmp_path, steps, order=None):
    """quiet/ended, then nested/both for len(steps) rounds; steps[k] is a list of (pid, lines) appended before
    round k's poll; order: "inner-first" polls the inner tree's feed first."""
    def between(w, k):
        for pid, lines in steps[k - 2] if k >= 2 else ():
            append_to(w, pid, lines)
        if order == "inner-first" and k >= 2:
            w.sources = dict(sorted(w.sources.items(), key=lambda kv: -kv[0][0]))
    return watch_rounds(tmp_path, ["quiet/ended"] + ["nested/both"] * len(steps), follow=CountingFollow(),
                        between=between)


def standing_and_copies(w):
    found = [f for f in w.source_findings if f["rule_id"] == "NET-TOOL" and f["image"] in ("outer", "inner")
             and any(c in f["summary"] for c in ("curl",))]
    return [f for f in found if f.get("judged_on") is None], [f for f in found if f.get("judged_on") is not None]


@pytest.mark.parametrize("order", ["outer-first", "inner-first"])
def test_redo2_t1_the_outer_trees_first_finding_spent_the_nested_trees_not(tmp_path, order):
    """S1 (a): A has spent its FIRST-FINDING; nested B acts: the act knocks as B's FIRST-FINDING, in either poll
    order (T-1: merged first, then I-6 on the tree it is shown on)."""
    copies = nested_copies()
    w = nested_watch(tmp_path, [[(6100, own_act(6100, 1, "plink"))], [(6100, copies[6100]), (6200, copies[6200])]],
                     order=order)
    (shown,), (listed,) = standing_and_copies(w)
    assert shown["pid"] == 6200 and listed["pid"] == 6100 and listed["judged_on"] == 6200
    firsts = [k for k in w.knocks if k["event"] == notify.FIRST_EVENT]
    assert [k["limit_id"] for k in firsts] == ["FIRST-FINDING pid 6100", "FIRST-FINDING pid 6200"]
    assert "pid 6200" in firsts[1]["body"]   # the KNOCKS row names the tree the finding is shown on
    inner = next(k for k in w.trees if k[0] == 6200)
    assert w.trees[inner]["first_knock"]["rule_id"] == "NET-TOOL" and shown["notice"] == "off (knocked on tree pid 6200)"
    assert w.trees[inner]["source_findings"] == {"medium": 1}


@pytest.mark.parametrize("order", ["outer-first", "inner-first"])
def test_redo2_t1_copies_agree_on_history_and_the_standing_one_knocks_once(tmp_path, order):
    """S1 (b), (c): for os lines history is the event's time only, so the two copies agree; the act knocks once,
    on the nearest tree, whichever feed is read first."""
    copies = nested_copies()
    w = nested_watch(tmp_path, [[(6100, copies[6100]), (6200, copies[6200])]], order=order)
    (shown,), (listed,) = standing_and_copies(w)
    assert shown["history"] is listed["history"] is False and shown["pid"] == 6200
    assert [k["limit_id"] for k in w.knocks if k["event"] == notify.FIRST_EVENT] == ["FIRST-FINDING pid 6200"]
    assert w.source_alarms() == [shown]
    old = {r: [dict(l, ts="2026-11-03T09:00:05.300Z") for l in v] for r, v in copies.items()}   # before the start
    w2 = nested_watch(tmp_path / "h", [[(6100, old[6100]), (6200, old[6200])]], order=order)
    (shown2,), (listed2,) = standing_and_copies(w2)
    assert shown2["history"] and listed2["history"] and w2.source_alarms() == []
    assert not [k for k in w2.knocks if k["event"] in (notify.FIRST_EVENT, "NET-TOOL")]


def test_redo2_t1_a_copy_arriving_after_the_knock_moves_the_finding_and_never_knocks_twice(tmp_path):
    copies = nested_copies()
    w = nested_watch(tmp_path, [[(6100, copies[6100])], [(6200, copies[6200])]])
    (shown,), (listed,) = standing_and_copies(w)
    assert shown["pid"] == 6200 and listed["pid"] == 6100 and listed["notice"].startswith(host.JUDGED_ELSEWHERE)
    # V-1: read from the act: the knock was sent on 6100's tree (its FIRST unspent) before the nearer copy came
    assert shown["notice"] == "off (knocked on tree pid 6100)"
    (row,) = [k for k in w.knock_rows() if k["event"] == notify.FIRST_EVENT]
    assert row["limit_id"] == "FIRST-FINDING pid 6100" and row["shown_on"] == "tree pid 6200"
    assert row["knocked_on"] == "tree pid 6100"
    inner, outer = (next(k for k in w.trees if k[0] == p) for p in (6200, 6100))
    assert w.trees[inner]["source_findings"] == {"medium": 1}
    assert w.trees[outer]["source_findings"] == {host.JUDGED_ELSEWHERE: 1}
    text, _ = w.finish()
    assert "the finding is shown on tree pid 6200, knocked on tree pid 6100 (V-1)" in text
    assert "SOURCE FINDINGS: 2 (1 live, of them 0 pending at exit; 0 history; 1 judged on another tree; 0 on benign" \
           " trees, noted)" in text   # T-8: the counts add up


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
    # T-4: the key is the kernel's own number (ticks since boot), on every platform; the time is for display only,
    # where the clock tick rate is known (no os.sysconf on Windows: no display time there, the key all the same)
    assert [r.get("start_ticks") for r in recs[1:]] == [100, 500] and recs[0]["start_unread"] == 0
    if hasattr(os, "sysconf"):
        tick = os.sysconf("SC_CLK_TCK")
        assert recs[2]["started"] == discover.iso(discover._ts("2026-11-03T10:00:00Z")
                                                  + __import__("datetime").timedelta(seconds=500 / tick))
    parsed, _ = discover.parse_proc(text)
    assert {r["pid"]: r.get("started") for r in parsed if r["kind"] == "proc"}[300] == "boot+500"
    stepped = "".join(json.dumps(dict(r, started="2026-11-03T11:00:00.000Z") if "start_ticks" in r else r) + "\n"
                      for r in recs)   # a stepped wall clock moves the display time (btime); the key does not
    assert {r["pid"]: r.get("started") for r in discover.parse_proc(stepped)[0] if r["kind"] == "proc"}[300] == "boot+500"
    old = "\n".join(json.dumps({k: v for k, v in r.items() if k not in ("started", "start_ticks")})
                    for r in recs) + "\n"
    assert all("started" not in r for r in discover.parse_proc(old)[0])   # an older snapshot reads as before
    # --window: two snapshots; pid 300 ended and its pid is reused by another image in the last one
    second = [dict(recs[0], snapshot="2026-11-03T10:00:01.000Z"), recs[1],
              dict(recs[2], argv=["/usr/bin/other"], name="other", exe="/usr/bin/other", start_ticks=590)]
    both = text + "".join(json.dumps(r) + "\n" for r in second)
    inv = discover.run({"proc": ("proc.txt", both, None)}, CATALOG, processes=True)
    sample = {p["pid"]: (p["image"], p["started"]) for p in inv["processes"]}
    assert sample[300] == ("other", "boot+590") and set(sample) == {1, 300}
    assert discover.run({"proc": ("proc.txt", old, None)}, CATALOG, processes=True)["processes"][0]["started"] is None
    # T-8 (S14): the pids whose start was unread are counted and said once per round
    (proc / "300" / "stat").unlink()
    text2 = discover.snapshot_proc(str(proc), at="2026-11-03T10:00:00.000Z")
    assert json.loads(text2.splitlines()[0])["start_unread"] == 1
    holes = discover.run({"proc": ("proc.txt", text2, None)}, CATALOG)["holes"]
    assert sum(1 for h in holes if "whose start could not be read" in h) == 1 and any(
        h.startswith("1 process(es) whose start could not be read") for h in holes)


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
    assert set(ssh2["input_meta"]) == {"command_head", "command_programs", "image", "parent_image", "depth",
                                       "parent_seq"}   # T-8 (S15): names only, no argument
    (line,) = [e for e in r.evasion if e.startswith("os source (M7.8")]
    assert "through git" in line and "parent_image is git" in line


def test_redo_r8_the_sentences_and_the_evasions():
    text = " ".join((ROOT / "docs" / "THREAT_MODEL.md").read_text(encoding="utf-8").split())
    section = text.split("### The host watch", 1)[1].split(" ## 6.", 1)[0]
    assert "`ss -tinp`" in section and "No watched process is signalled" in section and "its own helpers" in section
    assert host.BENIGN_WORD in section and "before the watch's start" in section   # T-2 amends R-1's word
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


# === M7.8 REDO 2 (ADR-0007 Amendment T) =====================================================================

def test_redo2_t2_an_act_under_a_benign_tree_and_a_nearer_agent_is_the_agents_finding(tmp_path):
    text = person_and_agent_export()
    follow = CountingFollow(by_root={5100: after_start(built(text, 5100)), 6100: after_start(built(text, 6100))})
    w = watch_rounds(tmp_path, ["benign-person/before", "benign-person/agent", "benign-person/agent"], follow=follow)
    agent_curl = [f for f in w.source_findings if f["rule_id"] == "NET-TOOL" and f.get("judged_on") is None
                  and f["pid"] == 6100]
    assert len(agent_curl) == 1 and not agent_curl[0].get("benign_note")   # the nearer, non-benign tree's finding
    assert [k["limit_id"] for k in w.knocks if k["event"] == notify.FIRST_EVENT] == ["FIRST-FINDING pid 6100"]
    explorer = next(k for k in w.trees if k[0] == 5100)
    assert w.trees[explorer]["source_findings"] == {host.BENIGN_COUNT: 2, host.JUDGED_ELSEWHERE: 1}


def test_redo2_t3_a_clock_that_steps_back_does_not_make_acts_history(tmp_path):
    lines = os_lines("net-windows.sysmon.xml", 4700)   # 09:00:00-09:00:11, an hour before the watch's start
    def between(w, k):
        if k == 3:
            append_to(w, 5888, lines)
    stepped = watch_rounds(tmp_path, ["defender/before", "quiet/talking", "quiet/talking"], between=between,
                           wall=lambda t: 1793700000.0 + t - (3600 if t >= 20 else 0))   # back one hour at t=20
    live = [f for f in stepped.source_findings if f["rule_id"] == "NET-TOOL"]
    assert len(live) == 3 and not any(f["history"] for f in live)   # after the step they are acts of the watch
    (hole,) = [h for h in stepped.holes if h["kind"] == "clock-step"]
    assert "stepped back 3600 s" in hole["detail"]
    steady = watch_rounds(tmp_path / "s", ["defender/before", "quiet/talking", "quiet/talking"], between=between)
    assert all(f["history"] for f in steady.source_findings if f["rule_id"] == "NET-TOOL")   # no step: before it
    assert not [h for h in steady.holes if h["kind"] == "clock-step"]


def test_redo2_t5_a_silence_finding_keeps_i3s_rule_not_the_events_time(tmp_path):
    lines = [l for l in os_lines("net-windows.sysmon.xml", 4700) if l["phase"] != "session_end"]   # before the start
    lines = [l for l in lines if not (l["phase"] == "post" and l["seq"] == lines[-1]["seq"])]       # a call left open
    w = watch_rounds(tmp_path, ["defender/before", "quiet/talking", "quiet/talking"], follow=CountingFollow(lines))
    w.finish()
    silence = [f for f in w.source_findings if f["class"] == "SILENCE"]
    assert silence and not any(f["history"] for f in silence) and any(f["pending"] for f in silence)
    assert all(f["history"] for f in w.source_findings if f["rule_id"] == "NET-TOOL")   # the catalog's: history
    assert w.result()[0] == "alarm"   # pending for good is silence (I-3, B-1)


def test_redo2_t7_the_act_key_names_the_image_and_the_parent_and_the_evasion_says_the_name_only():
    rec = os_lines("net-windows.sysmon.xml", 4700)[5]
    key = host.act_key(rec)
    assert key[:3] == (rec["ts"], rec["tool"], rec["input_sha256"]) and key[3:] == (
        rec["input_meta"]["image"], rec["input_meta"]["parent_image"])
    other = dict(rec, input_meta=dict(rec["input_meta"], image="renamed"))
    assert host.act_key(other) != key   # the same command line in the same millisecond, another image: two acts
    (line,) = [e for e in rule("NET-TOOL").evasion if e.startswith("os source (M7.8")]
    assert "known by its name only" in line and "GIT_SSH_COMMAND" in line and "core.sshCommand" in line


def test_redo2_t8_the_help_text_and_threat_model_say_what_the_code_does():
    from raqib import cli
    helptext = " ".join(cli.USAGE.split()) if hasattr(cli, "USAGE") else " ".join(
        (ROOT / "raqib" / "cli.py").read_text(encoding="ascii").split())
    for words in ("its root alive in round N; not seen talking with an act at the sample; source kept",
                  "not judged this round (connections unread)", "on a benign tree they are notes"):
        assert words in helptext, words
    text = " ".join((ROOT / "docs" / "THREAT_MODEL.md").read_text(encoding="utf-8").split())
    section = text.split("### The host watch", 1)[1].split(" ## 6.", 1)[0]
    for words in ("unread in both the tree's key and the sample", "or keeps it, when the round's connections were not"
                  " read either", "an `ss` that has not returned in 30 s", "process list was not read has an empty"
                  " sample", "counted once per round", "benign (its acts are noted, not knocked; its rhythm is judged)",
                  "The silence rules keep I-3's rule", "a clock that steps back"):
        assert words in section, words
    assert "or kept when the round's connections were not read either" in host.NO_SAMPLE_NOTE


def test_redo2_t6_the_fakes_wait_on_their_stop_and_finish_ends_every_thread(tmp_path):
    import inspect
    assert "stop.wait()" in inspect.getsource(CountingFollow.__call__)   # no time: only the stop ends it
    before = {t for t in threading.enumerate() if t.name.startswith("raqib-")}
    w = watch_rounds(tmp_path, ["quiet/talking", "quiet/quiet", "quiet/talking"], follow=CountingFollow())
    mine = [t for t in threading.enumerate() if t.name.startswith("raqib-") and t not in before]
    assert [t.name for t in mine if t.is_alive()] == ["raqib-host-os-5888"]   # alive while the watch runs
    w.finish()
    for t in mine:
        t.join(10)
    assert not [t.name for t in mine if t.is_alive()]   # the fixture checks this after every test of this file


# === M7.8 REDO 3 (ADR-0007 Amendment V): the act, in every order of arrival ===================================

import itertools  # noqa: E402

PERM_START = "2026-11-10T07:50:00.000Z"


def nested_inventory(spec):
    """One round's inventory of len(spec) nested trees, outermost first: spec[i] is True when tree i is benign
    (explorer under the system drive's Windows) and False when it is an agent (a user directory). Each talks and
    has the next as its child (SYNTHETIC; the trees only: what they read is appended to their files)."""
    trees = []
    for i, benign in enumerate(spec):
        pid = 9100 + 100 * i
        exe = "C:\\Windows\\explorer.exe" if benign else "C:\\Users\\user\\AppData\\Local\\Programs\\a%d\\a%d.exe" % (i, i)
        trees.append({"pid": pid, "image": "explorer" if benign else "a%d" % i, "exe": exe, "exe_from": "record",
                      "started": PERM_START, "cwd": None, "id": "C%d" % (i + 1),
                      "cites": [{"src": "win-process-1", "line": 3 + i, "text": "tree %d (test)" % pid}],
                      "acts": [{"how": "process", "pid": pid + 100, "image": "child", "started": PERM_START,
                                "cites": []}],
                      "talks": [{"remote": "203.0.113.%d:443" % (60 + i), "endpoint": [], "cites": []}]})
    return {"records": 20, "holes": [], "incomplete": [], "alarms": [], "problems": [], "result": "alarm",
            "sources": [], "footprints": [], "agent_dark": [], "system_drive": "c", "live": False,
            "candidates": trees, "act_roots": [], "processes": [{"pid": t["pid"], "image": t["image"],
                                                                 "started": PERM_START} for t in trees],
            "window": {"start": None, "end": None, "snapshots": 0, "samples_read": [1]}}


def copy_lines(pid, depth, half=False):
    """The one curl (the act) as tree pid's source writes it, at depth below its root; half: its pre only."""
    meta = {"command_head": "curl.exe", "command_programs": ["curl.exe"], "image": "curl", "parent_image": "cmd",
            "depth": depth}
    base = {"ts": "2026-11-03T10:00:30.000Z", "seq": 7, "session_id": "os-%d" % pid, "tool": "process",
            "input_sha256": common.canonical_sha256({"command_line": "curl -s https://198.51.100.70/x"}),
            "input_meta": meta, "cwd": "C:\\work\\proj", "source": "os"}
    lines = [dict(base, phase="pre")]
    return lines if half else lines + [dict(base, phase="post", output_meta={}, ok=True)]


def run_order(tmp_path, spec, spent, order, half=frozenset()):
    """A watch of the nested trees of spec; trees whose index is in spent have their FIRST-FINDING spent; each
    tree's copy of the act arrives in its own poll, in `order` (indices). The act logic is the same whatever
    source wrote the lines; the trees' host sources (no Sysmon, no thread) keep the case fast."""
    inv = nested_inventory(spec)
    clock = host.FixtureClock()
    notifier = notify.Notifier(host.HOST, enabled=False, reason="fixture", host=True)
    w = host.HostWatch(lambda: json.loads(json.dumps(inv)), CATALOG, RULES, notifier, every=10, out=None,
                       err=io.StringIO(), clock=clock, wall=lambda: 1793700000.0 + clock.t, home=str(tmp_path),
                       platform="fixture", run="fixture-run", sysmon=lambda: (False, "fixture: no Sysmon"))
    WATCHES.append(w)
    w.tick(wait=30)   # round 1: the trees and their sources
    keys = sorted(w.trees, key=lambda k: k[0])
    for i in spent:
        w.trees[keys[i]]["first_knock"] = {"rule_id": "EARLIER", "severity": "medium", "where": "-",
                                           "status": "off", "at": "-"}
    n = len(spec)
    for i in order:
        os_sysmon.append(w.sources[keys[i]].path, [json.dumps(x, separators=(",", ":"))
                                                   for x in copy_lines(keys[i][0], n - i, half=i in half)])
        clock.t += 1
        w.tick()   # a poll of its own
    for i in sorted(half):   # U6: the post of a copy read half, in a later poll
        os_sysmon.append(w.sources[keys[i]].path, [json.dumps(copy_lines(keys[i][0], n - i)[1], separators=(",", ":"))])
        clock.t += 1
        w.tick()
    text, code = w.finish()
    acts = [f for f in w.source_findings if f["rule_id"] == "NET-TOOL"]
    shown = [f["pid"] for f in acts if f.get("judged_on") is None]
    knocks = [k for k in w.knocks if k["event"] in (notify.FIRST_EVENT, "NET-TOOL")]
    counts = {k[0]: dict(w.trees[k].get("source_findings") or {}) for k in keys}
    return {"shown": shown, "code": code, "counts": counts, "knocks": len(knocks)}


def every_order(tmp_path, n):
    results = {}
    for spec in itertools.product((False, True), repeat=n):
        for spent in itertools.product((False, True), repeat=n):
            spent_idx = frozenset(i for i, s in enumerate(spent) if s)
            outs = [run_order(tmp_path / ("%d-%s-%s-%s" % (n, spec, spent, order)).replace(" ", ""), spec, spent_idx,
                              order) for order in itertools.permutations(range(n))]
            results[(spec, spent)] = outs
    return results


@pytest.mark.parametrize("n", [2, 3])
def test_redo3_v1_every_order_of_arrival_gives_one_answer(tmp_path, n):
    """V-1, the test that matters: for two and three nested trees, each benign or not, its FIRST-FINDING spent
    or not, EVERY order of arrival over separate polls gives the same standing tree, the same exit code, the
    same counts, at most one knock, and a knock in every order whenever some order gives one (2 x 4 x 4 x 2 = 32
    runs for two trees, 8 x 8 x 6 = 384 for three)."""
    bad = []
    for (spec, spent), outs in every_order(tmp_path, n).items():
        first = outs[0]
        same = all(o["shown"] == first["shown"] and o["code"] == first["code"] and o["counts"] == first["counts"]
                   for o in outs)
        once = all(o["knocks"] <= 1 for o in outs)
        agree = len({o["knocks"] > 0 for o in outs}) == 1
        if not (same and once and agree and len(first["shown"]) == 1):
            bad.append((spec, spent, [(o["shown"], o["code"], o["knocks"]) for o in outs]))
        # V-2: an act is a note only when every tree above it is benign; else it stands on the nearest agent's tree
        agents = [i for i, b in enumerate(spec) if not b]
        want = 9100 + 100 * max(agents) if agents else 9100 + 100 * (n - 1)
        if first["shown"] != [want] or (first["code"] == 1) != bool(agents):
            bad.append(("standing", spec, spent, first["shown"], first["code"]))
    assert not bad, bad[:6]


def test_redo3_v1_a_half_read_copy_is_the_same_act(tmp_path):
    """U6: a feed read in the middle of an append judges the pre alone; its key is the event's, as its twin's."""
    whole = run_order(tmp_path / "w", (False, False), frozenset(), (0, 1))
    half = run_order(tmp_path / "h", (False, False), frozenset(), (0, 1), half=frozenset({0}))
    assert half["shown"] == whole["shown"] == [9200] and half["knocks"] == whole["knocks"] == 1
    assert half["counts"] == whole["counts"]


def test_redo3_v1_a_folds_outcome_is_read_from_the_act_by_the_finding_and_its_knocks_row(tmp_path):
    """U3: the finding's status and its KNOCKS row are one thing (the act's), also after a fold."""
    w = watch_rounds(tmp_path, ["quiet/ended"], sysmon=False)
    out = run_order(tmp_path / "f", (False, False), frozenset(), (1, 0))
    assert out["knocks"] == 1
    inv = nested_inventory((False, False))
    clock = host.FixtureClock()
    notifier = notify.Notifier(host.HOST, enabled=False, reason="fixture", host=True)
    w = host.HostWatch(lambda: json.loads(json.dumps(inv)), CATALOG, RULES, notifier, every=10, out=None,
                       err=io.StringIO(), clock=clock, wall=lambda: 1793700000.0 + clock.t, home=str(tmp_path / "w"),
                       platform="fixture", run="fixture-run", sysmon=lambda: (False, "fixture: no Sysmon"))
    w.tick(wait=30)
    keys = sorted(w.trees, key=lambda k: k[0])
    for i in (0, 1):
        os_sysmon.append(w.sources[keys[i]].path, [json.dumps(x) for x in copy_lines(keys[i][0], 2 - i)])
    clock.t += 1
    w.tick()
    (row,) = [k for k in w.knocks if k["event"] == notify.FIRST_EVENT]
    w._folds([row["ref"]], "sent", 2)   # what the notifier writes back when a fold is delivered (C-5)
    w._refresh()
    (shown,) = [f for f in w.source_findings if f["rule_id"] == "NET-TOOL" and f.get("judged_on") is None]
    (krow,) = [k for k in w.knock_rows() if k["event"] == notify.FIRST_EVENT]
    assert shown["notice"].startswith("folded: sent as 2 more") and krow["status"] == "folded: sent as 2 more"
    w.finish()


def test_redo3_v1_a_poll_cut_short_is_settled_and_what_finish_cannot_settle_is_said(tmp_path, monkeypatch):
    """U2: a judge that raises mid-poll leaves no finding without a word: the poll's `finally` settles what was
    judged; an act that cannot be settled at all is in the report's NOT SETTLED, an alarm of its tree."""
    inv = nested_inventory((False, False))
    clock = host.FixtureClock()
    notifier = notify.Notifier(host.HOST, enabled=False, reason="fixture", host=True)
    w = host.HostWatch(lambda: json.loads(json.dumps(inv)), CATALOG, RULES, notifier, every=10, out=None,
                       err=io.StringIO(), clock=clock, wall=lambda: 1793700000.0 + clock.t, home=str(tmp_path),
                       platform="fixture", run="fixture-run", sysmon=lambda: (False, "fixture: no Sysmon"))
    w.tick(wait=30)
    keys = sorted(w.trees, key=lambda k: k[0])
    for i in (0, 1):
        os_sysmon.append(w.sources[keys[i]].path, [json.dumps(x) for x in copy_lines(keys[i][0], 2 - i)])
    real = host.HostWatch._judge_feed
    calls = []

    def judge(self, now, key, src, feed, final):
        calls.append(key)
        if len(calls) == 2:
            raise RuntimeError("the second feed's judge failed (test)")
        return real(self, now, key, src, feed, final)
    monkeypatch.setattr(host.HostWatch, "_judge_feed", judge)
    clock.t += 1
    with pytest.raises(RuntimeError):
        w.tick()
    (first,) = [f for f in w.source_findings if f["rule_id"] == "NET-TOOL"]
    assert first["settled"] and first["notice"] and first["notice"] != "None"   # settled by the poll's finally
    assert [k["event"] for k in w.knocks].count(notify.FIRST_EVENT) == 1
    monkeypatch.setattr(host.HostWatch, "_judge_feed", real)
    monkeypatch.setattr(host.HostWatch, "_decide", lambda self, now, act: (_ for _ in ()).throw(
        RuntimeError("cannot decide (test)")))
    for act in w.acts.values():
        act["dirty"] = True
    text, code = w.finish()
    assert "NOT SETTLED (A3; a finding no settle could decide, an alarm of its tree): 1" in text
    assert "RuntimeError: cannot decide (test)" in text and code == 1


def test_redo3_v1_three_trees_over_three_polls_name_the_tree_that_knocked(tmp_path):
    """U5: the knock and the finding are named from the act: which tree knocked, where it is shown."""
    inv = nested_inventory((False, False, False))
    clock = host.FixtureClock()
    notifier = notify.Notifier(host.HOST, enabled=False, reason="fixture", host=True)
    w = host.HostWatch(lambda: json.loads(json.dumps(inv)), CATALOG, RULES, notifier, every=10, out=None,
                       err=io.StringIO(), clock=clock, wall=lambda: 1793700000.0 + clock.t, home=str(tmp_path),
                       platform="fixture", run="fixture-run", sysmon=lambda: (False, "fixture: no Sysmon"))
    w.tick(wait=30)
    keys = sorted(w.trees, key=lambda k: k[0])
    w.trees[keys[1]]["first_knock"] = {"rule_id": "EARLIER"}
    for i in (0, 1, 2):
        os_sysmon.append(w.sources[keys[i]].path, [json.dumps(x) for x in copy_lines(keys[i][0], 3 - i)])
        clock.t += 1
        w.tick()
    (shown,) = [f for f in w.source_findings if f["rule_id"] == "NET-TOOL" and f.get("judged_on") is None]
    assert shown["pid"] == 9300 and shown["notice"] == "off (knocked on tree pid 9100)"
    others = sorted(f["notice"] for f in w.source_findings if f.get("judged_on") is not None)
    assert others == ["%s: judged on tree pid 9300 (one act, one finding)" % host.JUDGED_ELSEWHERE] * 2
    # M7.9 REDO X-9: the trees' start (PERM_START) is read and after this watch's start, so they are not history and
    # knock NEW-AGENT-UNKNOWN in round 1; the act's knock is the one row with a tree it was shown on
    (row,) = [r for r in w.knock_rows() if r.get("shown_on")]
    assert (row["knocked_on"], row["shown_on"]) == ("tree pid 9100", "tree pid 9300")
    w.finish()


def test_redo3_v3_the_page_lists_notes_apart_and_rules_off_count_acts(tmp_path):
    off = []
    for r in RULES:
        if r.id == "NET-TOOL":
            doc = dict(r.doc, status="disabled")
            r2 = engine.compile_rule(doc, r.source)
            r2.off_by = "test"
            off.append(r2)
        else:
            off.append(r)

    def run(spec):
        inv = nested_inventory(spec)
        clock = host.FixtureClock()
        notifier = notify.Notifier(host.HOST, enabled=False, reason="fixture", host=True)
        w = host.HostWatch(lambda: json.loads(json.dumps(inv)), CATALOG, off, notifier, every=10, out=None,
                           err=io.StringIO(), clock=clock, wall=lambda: 1793700000.0 + clock.t,
                           home=str(tmp_path / str(spec)), platform="fixture", run="fixture-run",
                           sysmon=lambda: (False, "fixture: no Sysmon"))
        w.tick(wait=30)
        keys = sorted(w.trees, key=lambda k: k[0])
        for i, k in enumerate(keys):
            os_sysmon.append(w.sources[k].path, [json.dumps(x) for x in copy_lines(k[0], len(keys) - i)])
        clock.t += 1
        w.tick()
        return w
    nested = run((False, False))
    assert nested.all_not_judged()["NET-TOOL"]["fired"] == 1   # one act read by two trees: once, not twice
    text, code = nested.finish()
    assert "it would have fired 1 time(s)" in text
    benign = run((True,))
    assert benign.all_not_judged()["NET-TOOL"]["fired"] == 0 and benign.off_notes() == {"NET-TOOL": 1}
    text, code = benign.finish()
    assert "(and NET-TOOL 1 would-be finding(s) on benign trees, which would have been notes: not counted above)" in text
    # the page: notes under their own heading, never among the source findings
    w = run_order(tmp_path / "p", (True,), frozenset(), (0,))
    assert w["code"] == 0
    inv = nested_inventory((True,))
    clock = host.FixtureClock()
    notifier = notify.Notifier(host.HOST, enabled=False, reason="fixture", host=True)
    w2 = host.HostWatch(lambda: json.loads(json.dumps(inv)), CATALOG, RULES, notifier, every=10, out=None,
                        err=io.StringIO(), clock=clock, wall=lambda: 1793700000.0 + clock.t, home=str(tmp_path / "pg"),
                        platform="fixture", run="fixture-run", sysmon=lambda: (False, "fixture: no Sysmon"))
    w2.tick(wait=30)
    (k,) = list(w2.trees)
    os_sysmon.append(w2.sources[k].path, [json.dumps(x) for x in copy_lines(k[0], 1)])
    clock.t += 1
    w2.tick()
    page = "\n".join(ui.host_section(w2.state(clock())))
    assert "<h3>Source findings (0)</h3>" in page and "<h3>On benign trees (noted, not knocked) (1)</h3>" in page
    w2.finish()


def test_redo3_v4_the_linux_tree_shows_its_start_as_a_time_beside_the_key(tmp_path):
    d = FIX / "discover" / "linux-agent"
    texts, holes = discover.read_dir(str(d))
    label, text, err = texts["proc"]
    lines = []
    for line in text.splitlines(True):
        if line.startswith("{") and '"pid"' in line:
            rec = json.loads(line)
            rec.update(start_ticks=1000 + rec["pid"], started="2026-11-03T09:%02d:00.000Z" % (rec["pid"] % 60))
            line = json.dumps(rec) + "\n"
        lines.append(line)
    texts["proc"] = (label, "".join(lines), err)
    inv = discover.run(texts, CATALOG, holes=holes, processes=True)
    (c,) = inv["candidates"] + inv["act_roots"]
    assert c["started"] == "boot+%d" % (1000 + c["pid"])
    assert c["started_at"] == "2026-11-03T09:%02d:00.000Z" % (c["pid"] % 60)
    plain = discover.run(discover.read_dir(str(d))[0], CATALOG, holes=holes)   # a shipped snapshot: no key added
    assert all("started_at" not in t for t in plain["candidates"] + plain["act_roots"])
    w = watch_rounds(tmp_path, ["one", "one"], sysmon=False, inv=lambda n: json.loads(json.dumps(inv)))
    text_, _ = w.finish()
    assert "started %s (key %s)" % (c["started_at"], c["started"]) in text_
    for rule_id in ("NEW-AGENT", "NEW-AGENT-UNKNOWN"):
        assert any(h.startswith("Linux: a tree is keyed by (pid, image, its start in clock ticks since boot")
                   for h in rule(rule_id).doc["holes"])
        assert not any("gives no creation time" in h for h in rule(rule_id).doc["holes"])
    assert "shown as a time where the clock tick rate is known" in " ".join(
        (ROOT / "docs" / "THREAT_MODEL.md").read_text(encoding="utf-8").split())


def test_redo3_v5_the_helper_serves_the_four_files_and_a_finish_that_raises_still_stops_the_rest(tmp_path):
    import hostthreads
    for name in ("test_acts_judged.py", "test_host_sources.py", "test_rhythm.py", "test_field_run.py"):
        text = (ROOT / "tests" / name).read_text(encoding="ascii")
        timed = re.findall(r"(?:stop|release|gate)\.wait\(\d", text)   # a fake waiting on a time
        assert "from hostthreads import raqib_threads_end" in text and not timed, name
    assert not re.findall(r"stop\.wait\(\d", (ROOT / "raqib" / "host.py").read_text(encoding="ascii"))
    # (the Table, 2026-11-11: tests/conftest.py exists from here on - it collects Tk garbage on the main thread,
    # ADR-0009 A-16 - and the helper stays its own module, imported by the four files that start a HostWatch)
    assert "raqib_threads_end" not in (ROOT / "tests" / "conftest.py").read_text(encoding="ascii")
    w = watch_rounds(tmp_path, ["quiet/talking"], follow=CountingFollow())
    (src,) = w.sources.values()
    w.finish = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("finish raised (test)"))
    hostthreads._stop_sources(w)   # what the teardown does after a finish that raised
    src.thread.join(5)
    assert not src.thread.is_alive()
    del w.finish


def test_redo3_v6_a_later_larger_step_is_said_again(tmp_path):
    steps = {20: 3600, 30: 3600, 40: 7200}
    w = watch_rounds(tmp_path, ["defender/before"] * 5, sysmon=False,
                     wall=lambda t: 1793700000.0 + t - max([v for k, v in steps.items() if t >= k] or [0]))
    holes = [h["detail"] for h in w.holes if h["kind"] == "clock-step"]
    assert len(holes) == 2 and "stepped back 3600 s" in holes[0] and "stepped back 7200 s" in holes[1]
