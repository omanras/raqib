"""ADR-0007 Amendments AU and AW: one server, one os destination.

AU-1: an os net line's input_meta carries dest_sha256, the hash of the
address (canonical), the port and the protocol alone, so one server is one
hash whether or not Sysmon named the host; its input_sha256 is what it was.
AW-2: the key is written only where the caller asks (the host watch's os
follow asks; every other caller does not). AU-2: the rhythm's destination of
an os talk is made from it; a line without it keeps the destination it had,
said once per source object with its count (AW-3). AW-1 (AU-3 withdrawn): a
host talk and an os talk to one server are two destinations, so one
connection both sources saw is never two cycles on one. Every run here is
synthetic (raqib/rules/fixturegen.py), on a fake clock; every address is a
documentation one (RFC 5737, RFC 3849).
"""
import copy
import io
import json
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from raqib import discover, host, notify  # noqa: E402
from raqib.hooks import common, os_sysmon  # noqa: E402
from raqib.rules import engine, fixturegen  # noqa: E402
from hostthreads import raqib_threads_end  # noqa: E402,F401  (V-5: every HostWatch ended, no thread leaked)

CATALOG = discover.load_catalog(discover.CATALOG)
RULES = engine.load_catalog(ROOT / "raqib" / "rules" / "catalog")
RHYTHM = next(r for r in RULES if r.id == "HOST-RHYTHM")
PID = fixturegen.RHYTHM_PID
OTHER = PID + 1000   # a second tree (its children pid+1, pid+2 never meet the first's)
K = engine.declared_thresholds(RHYTHM.doc)["k"]["value"]
FIX = ROOT / "tests" / "fixtures" / "rules" / "HOST-RHYTHM"
SERVER = "79782a401441049982377a170ce40fc684bdd4079e17e633de22dce7a25011fc"   # 192.0.2.20, 443, tcp (literal)
OS_NAME = "os:%s" % SERVER[:12]
HOST_NAME = "192.0.2.20:443"   # the same server as the host's sample names it


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    path = tmp_path / "home"
    path.mkdir()
    monkeypatch.setenv("HOME", str(path))
    monkeypatch.setenv("USERPROFILE", str(path))
    return path


def net_event(**data):
    d = {"DestinationIp": "192.0.2.20", "DestinationPort": "443", "Protocol": "tcp"}
    d.update(data)
    return {"event": 3, "data": {k: v for k, v in d.items() if v is not None}}


# --- AU-1: the os line says which server (where asked) ------------------------------------------------------------

def test_e1_one_server_named_and_not_is_one_dest_sha256_and_two_input_sha256():
    named, meta_named = os_sysmon._event_fields(net_event(DestinationHostname="model.example"), None, True)
    plain, meta_plain = os_sysmon._event_fields(net_event(), None, True)
    assert meta_named["dest_sha256"] == meta_plain["dest_sha256"] == SERVER
    assert named != plain
    # the line's identity is byte for byte what it was: the hash of the whole destination, the name included
    for digest, hostname in ((named, "model.example"), (plain, None)):
        assert digest == common.canonical_sha256({"destination": {"hostname": hostname, "ip": "192.0.2.20",
                                                                   "port": "443", "protocol": "tcp"}})
    assert set(meta_plain) == {"dest_port", "dest_private", "dest_sha256"}
    assert meta_plain["dest_port"] == 443 and meta_plain["dest_private"] is False


@pytest.mark.parametrize("ip, port, proto, same", [
    ("192.0.2.20", 443, "tcp", "192.0.2.20"),
    ("::ffff:192.0.2.20", "443", "TCP", "192.0.2.20"),     # an IPv4-mapped address is its IPv4
    (" 192.0.2.20 ", " 443 ", " Tcp ", "192.0.2.20"),
    ("2001:DB8:0:0::5", "443", "tcp", "2001:db8::5"),      # the ipaddress module's canonical form
])
def test_e1_the_address_is_canonical_the_port_an_integer_the_protocol_lower(ip, port, proto, same):
    assert os_sysmon.dest_sha256(ip, port, proto) == common.canonical_sha256(
        {"server": {"ip": same, "port": 443, "protocol": "tcp"}})
    literal = {"192.0.2.20": SERVER, "2001:db8::5": "13aaacd11f14e4b7d7fab2209378711c3b51716c7a96d718a65ce9322751159f"}
    assert os_sysmon.dest_sha256(ip, port, proto) == literal[same]


def test_e1_another_protocol_or_port_is_another_server():
    assert os_sysmon.dest_sha256("192.0.2.20", 443, "udp") == \
        "cf83974f2a1a02b23a05de379660a3276d5730f817b15f167c75af7ed91dce15" != SERVER
    assert os_sysmon.dest_sha256("192.0.2.20", 8443, "tcp") != SERVER
    assert os_sysmon.dest_sha256("198.51.100.7", 443, "tcp") != SERVER


@pytest.mark.parametrize("data", [
    {"DestinationIp": "model.example"}, {"DestinationIp": ""}, {"DestinationIp": None}, {"DestinationIp": "192.0.2"},
    {"DestinationPort": "https"}, {"DestinationPort": "70000"}, {"DestinationPort": None}, {"Protocol": None},
])
def test_e1_what_does_not_parse_has_no_dest_sha256_never_a_guess(data):
    digest, meta = os_sysmon._event_fields(net_event(**data), None, True)
    assert "dest_sha256" not in meta
    assert isinstance(digest, str) and len(digest) == 64   # the line is still written, its identity as before


# --- AW-2: written only where the caller asks ---------------------------------------------------------------------

def export():
    return (ROOT / "tests" / "fixtures" / "os" / "net-windows.sysmon.xml").read_text(encoding="ascii")


def strip_key(line):
    rec = json.loads(line)
    if rec.get("tool") == "net":
        rec["input_meta"].pop("dest_sha256")
    return rec


def test_e2_a_build_that_asks_differs_from_one_that_does_not_only_by_the_key_on_net_lines():
    plain, plain_silences = os_sysmon.build(export(), 4700, cwd="C:\\work\\proj")
    asked, asked_silences = os_sysmon.build(export(), 4700, cwd="C:\\work\\proj", server_hash=True)
    assert plain == os_sysmon.build(export(), 4700, cwd="C:\\work\\proj", server_hash=False)[0]   # the default
    assert plain_silences == asked_silences and len(plain) == len(asked)
    nets = [i for i, x in enumerate(asked) if json.loads(x).get("tool") == "net"]
    assert nets and all("dest_sha256" not in x for x in plain)
    for i, (p, a) in enumerate(zip(plain, asked)):
        if i in nets:   # the key, and nothing else: every other key and the line's identity as they were
            assert p != a and "dest_sha256" in json.loads(a)["input_meta"] and json.loads(p) == strip_key(a)
        else:
            assert p == a   # byte for byte


def follow_once(tmp_path, **kw):
    log, stop = tmp_path / "os.jsonl", threading.Event()
    os_sysmon.follow("4700", str(log), stop, every=0.0, out=io.StringIO(), err=io.StringIO(),
                     live=lambda: (export(), None), on_pass=lambda n, top: stop.set(), **kw)
    return [json.loads(x) for x in log.read_text(encoding="ascii").splitlines() if x.startswith("{")]


def test_e2_the_follow_writes_the_key_only_when_asked(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    plain, asked = follow_once(tmp_path / "a"), follow_once(tmp_path / "b", server_hash=True)
    nets = [r for r in asked if r.get("tool") == "net"]
    assert nets and all(len(r["input_meta"].get("dest_sha256", "")) == 64 for r in nets)
    assert not [r for r in plain if "dest_sha256" in (r.get("input_meta") or {})]


class AskedFollow:
    """The host watch's os follow (host.FixtureFollow's one pass, then its Stop), recording the server_hash it is
    given; its first call also returns when `end` is set (a follow that ended: ADR-0007 AS-6, attached again)."""

    def __init__(self):
        self.asked, self.end = [], threading.Event()

    def __call__(self, root, log, stop, **kw):
        self.asked.append(kw.get("server_hash"))
        if kw.get("on_pass"):
            kw["on_pass"](1, None)
        first = len(self.asked) == 1
        while not stop.is_set() and not (first and self.end.is_set()):
            stop.wait(0.01)
        return 1


# --- the rounds (a fake os follow, as host.fixture_rounds) -----------------------------------------------------

def run(home, invs, os_at, old=False, follow=None, pids=(PID,), at_round=None):
    """The HostWatch fed invs with a fake os follow; os_at {round: [(k, scenario)]}: fixturegen.os_lines for
    round k appended to each tree's (pids) os source before that round ("net": "oscycle" without its child;
    old: with no dest_sha256, as a line written before the key or by a caller that did not ask).
    at_round {round: f(watch)}: called before that round's lines and tick.
    (watch, the first tree's HostTree lines in round order)."""
    feed = iter(invs)
    clock = host.FixtureClock()
    notifier = notify.Notifier(host.HOST, enabled=False, reason="test", host=True)
    watch = host.HostWatch(lambda: next(feed), CATALOG, RULES, notifier, every=fixturegen.EVERY, out=None,
                           err=io.StringIO(), clock=clock, wall=lambda: fixturegen.WALL0 + clock.t, home=str(home),
                           platform="fixture", run="test-run", sysmon=lambda: (True, "test: a synthetic os source"),
                           os_follow=follow or host.FixtureFollow())
    seq, lines = {p: 0 for p in pids}, []
    for n in range(1, len(invs) + 1):
        if at_round and n in at_round:
            at_round[n](watch)
        for k, scenario in os_at.get(n, ()):
            for pid in pids:
                (key,) = [x for x in watch.trees if x[0] == pid]
                src = watch.sources[key]
                src.first_pass.wait(5)
                recs, seq[pid] = fixturegen.os_lines(k, "oscycle" if scenario == "net" else scenario, seq[pid],
                                                     sid="os-%d" % pid)
                if scenario == "net":
                    recs = [r for r in recs if r.get("tool") != "process"]
                if old:
                    for rec in recs:
                        rec["input_meta"].pop("dest_sha256", None)
                with open(src.path, "a", encoding="ascii", newline="\n") as f:
                    f.write("".join(json.dumps(x, separators=(",", ":")) + "\n" for x in recs))
        before = watch.round_lines[-1] if watch.round_lines else None
        watch.tick(wait=30)
        if watch.round_lines and watch.round_lines[-1] is not before:
            lines += [ln for ln in watch.round_lines[-1]["lines"]
                      if ln.get("tool") == host.TREE_TOOL and ln["input_meta"]["pid"] == PID]
        clock.t += watch.every
    watch.finish()
    return watch, lines


def between(n, pids=(PID,)):
    """Rounds 1..n of fixturegen's os scenarios: no host cycle; every cycle is the os source's (one tree per pid)."""
    out = []
    for i in range(1, n + 1):
        inv = fixturegen.synthetic_inventory("rhythm-os:oscycle:%d" % i)
        for pid in pids[1:]:
            inv["candidates"] += fixturegen.rhythm_inventory("between", i, pid=pid, bytes_moved=False)["candidates"]
        out.append(inv)
    return out


def fired(lines):
    return [ln for ln in lines if ln["input_meta"]["rhythm"]["fires"]]


def fires_on_the_third(lines):
    """The one firing line is the first whose rhythm counts K cycles (the round that reads the K-th)."""
    (fire,) = fired(lines)
    first = next(ln for ln in lines if ln["input_meta"]["rhythm"]["cycles"] >= K)
    assert fire is first
    assert all(ln["input_meta"]["rhythm"]["cycles"] < K for ln in lines[:lines.index(fire)])
    return fire


def said(watch):
    return [x for x in watch.notes if "carry no input_meta.dest_sha256" in x]


# --- AU-2, AW-2, AW-3: the rhythm's destination of an os talk, and the note -------------------------------------

def test_e2_the_host_watch_asks_its_os_follow_for_the_key(home):
    follow = AskedFollow()
    run(home, between(2), {}, follow=follow)
    assert follow.asked == [True]


def test_e2_an_os_talk_is_named_by_its_server_hash_and_no_note(home):
    watch, lines = run(home, between(K + 2), {n: [(n, "oscycle")] for n in range(2, K + 2)})
    fire = fires_on_the_third(lines)
    assert fire["input_meta"]["rhythm"]["destination"] == OS_NAME
    assert not said(watch)


def test_e3_a_line_without_the_key_keeps_its_destination_and_is_said_once_with_its_count(home):
    watch, lines = run(home, between(K + 2), {n: [(n, "oscycle")] for n in range(2, K + 2)}, old=True)
    fire = fires_on_the_third(lines)
    old = "os:%s" % common.canonical_sha256({"destination": fixturegen.OS_DEST})[:12]
    assert fire["input_meta"]["rhythm"]["destination"] == old != OS_NAME
    (note,) = said(watch)
    assert note.endswith(host.PRE_DEST_NOTE % K) and "its os source" in note   # the final count: K net lines


def test_e3_the_note_names_both_causes_and_that_old_and_new_lines_are_two_destinations():
    words = host.PRE_DEST_NOTE
    for cause in ("written before the key", "did not ask for it", "address, port or protocol did not parse",
                  "a line with the key to one server are two destinations"):
        assert cause in words, cause


def test_e3_two_trees_each_say_it_once_for_their_own_source(home):
    watch, _ = run(home, between(K + 2, pids=(PID, OTHER)), {n: [(n, "net")] for n in range(2, K + 1)},
                   old=True, pids=(PID, OTHER))
    notes = said(watch)
    assert len(notes) == 2 and all(n.endswith(host.PRE_DEST_NOTE % (K - 1)) for n in notes)
    assert len({n.split(", its os source")[0] for n in notes}) == 2   # one per tree


def test_e3_a_source_attached_again_says_it_once_for_itself(home):
    follow, paths = AskedFollow(), []

    def end_the_follow(watch):   # before round K+1: the first follow returns; the round attaches the tree again
        (src,) = watch.sources.values()
        paths.append(src.path)
        follow.end.set()
        src.thread.join(5)
    watch, _ = run(home, between(K + 4), {n: [(n, "net")] for n in list(range(2, K + 1)) + [K + 2, K + 3]},
                   old=True, follow=follow, at_round={K + 1: end_the_follow})
    (src,) = watch.sources.values()
    assert len(follow.asked) == 2 and set(follow.asked) == {True}   # attached again, and it asks again
    assert paths == [src.path]   # the same trace, read again by the new source object
    # once per source object, with its count, as PRE_M78_NOTE: the first said its K-1 lines; the one attached again
    # reads the whole trace (the K-1 and the 2 after it) and says it once, with that count
    word = host.tree_word(next(iter(watch.sources)))
    assert said(watch) == ["tree %s, its os source: %s" % (word, host.PRE_DEST_NOTE % c) for c in (K - 1, K + 1)]


def test_e3_old_lines_named_on_some_events_stay_two_destinations(home):
    # the hole that stays: a line without the key has only the hash of the name too
    watch, lines = run(home, between(K + 2), {n: [(n, "osnamed")] for n in range(2, K + 2)}, old=True)
    assert not fired(lines)
    assert len(said(watch)) == 1


def test_e2_named_on_some_events_and_not_on_others_k_fire_k_minus_1_do_not(home):
    _, lines = run(home, between(K + 2), {n: [(n, "osnamed")] for n in range(2, K + 2)})
    assert fires_on_the_third(lines)["input_meta"]["rhythm"]["destination"] == OS_NAME
    _, lines = run(home, between(K + 2), {n: [(n, "osnamed")] for n in range(2, K + 1)})
    assert not fired(lines)
    assert max(ln["input_meta"]["rhythm"]["cycles"] for ln in lines) == K - 1


# --- AW-1, AW-4: one connection both sources saw, through the rounds ---------------------------------------------

@pytest.mark.parametrize("act_rounds", [(5,), (4, 5)])
def test_e4_one_connection_the_os_source_places_in_round_m_and_the_sample_first_sees_in_m_plus_1(home, act_rounds):
    """Round m = 3: Sysmon's event 3 at t=12 (round 3's interval); the sample first sees 192.0.2.20:443 in round 4
    (t=30). One act at t=35 (round 5), within W of both talks; or one turn whose children run over rounds 4 and 5
    (t=25, t=35). One talk on each of two destinations, and never two cycles on one (as AU-3's merge counted)."""
    invs = between(K + 4)
    for inv in invs[3:]:   # rounds 4.. hold the connection
        (tree,) = inv["candidates"]
        talk = copy.deepcopy(tree["talks"][0])
        talk["remote"] = HOST_NAME
        tree["talks"] = tree["talks"] + [talk]
    os_at = {3: [(3, "net")]}
    for r in act_rounds:
        os_at.setdefault(r, []).append((r, "osact"))
    watch, lines = run(home, invs, os_at)
    assert not fired(lines) and max(ln["input_meta"]["rhythm"]["cycles"] for ln in lines) == 1
    (key,) = [x for x in watch.trees if x[0] == PID]
    ring = watch.rings[key]
    talks = {d: [e["round"] for e in ring if d in e["talks"]] for e in ring for d in e["talks"]}
    assert talks[OS_NAME] == [3] and talks[HOST_NAME] == [4]   # one talk on each destination
    n = ring[-1]["round"]
    for dest in (OS_NAME, HOST_NAME):   # each destination alone: one cycle
        alone = [dict(e, talks={d: c for d, c in e["talks"].items() if d == dest}) for e in ring]
        assert host.rhythm_of(alone, K, 30, 10, n)["cycles"] == 1, dest
    assert host.rhythm_of(ring, K, 30, 10, n)["cycles"] == 1


# --- AU-4: the shipped fixtures ----------------------------------------------------------------------------------

@pytest.mark.parametrize("name, cycles", [("positive-os-named-some", K), ("negative-os-named-some", K - 1)])
def test_e4_the_new_fixtures_are_listed_and_say_one_destination(name, cycles):
    path = "tests/fixtures/rules/HOST-RHYTHM/%s.json" % name
    assert path in RHYTHM.fixtures[name.split("-")[0]]
    doc = json.loads((FIX / ("%s.json" % name)).read_text(encoding="ascii"))
    (line,) = [ln for ln in doc["lines"] if ln.get("tool") == host.TREE_TOOL and ln["input_meta"]["pid"] == PID]
    rhythm = line["input_meta"]["rhythm"]
    assert rhythm["cycles"] == cycles and rhythm["destination"] == OS_NAME
    found, _ = engine.judge(RHYTHM, doc["lines"], {})
    assert bool(found) is name.startswith("positive-")


def test_e4_no_split_sources_fixture_is_shipped_or_listed():
    assert not list(FIX.glob("*split-sources*"))
    assert not [p for v in RHYTHM.fixtures.values() for p in v if "split" in p]
    assert not hasattr(host, "one_server") and not hasattr(host, "server_of")
