"""ADR-0007 Amendment AU: one server, one destination.

AU-1: an os net line's input_meta carries dest_sha256, the hash of the
address (canonical), the port and the protocol alone, so one server is one
hash whether or not Sysmon named the host; its input_sha256 is what it was.
AU-2: the rhythm's destination of an os talk is made from it; a line written
before it keeps the destination it had, said once per source. AU-3: a host
talk to address:port and an os talk to that server (tcp) are one destination,
named as the host's sample names it where the ring holds it. Every run here
is synthetic (raqib/rules/fixturegen.py), on a fake clock; every address is a
documentation one (RFC 5737, RFC 3849).
"""
import datetime
import io
import json
import sys
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
K = engine.declared_thresholds(RHYTHM.doc)["k"]["value"]
FIX = ROOT / "tests" / "fixtures" / "rules" / "HOST-RHYTHM"
SERVER = os_sysmon.dest_sha256("192.0.2.20", 443, "tcp")
OS_NAME = "os:%s" % SERVER[:12]


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


# --- AU-1: the os line says which server ---------------------------------------------------------------------

def test_e1_one_server_named_and_not_is_one_dest_sha256_and_two_input_sha256():
    named, meta_named = os_sysmon._event_fields(net_event(DestinationHostname="model.example"), None)
    plain, meta_plain = os_sysmon._event_fields(net_event(), None)
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


def test_e1_another_protocol_or_port_is_another_server():
    assert os_sysmon.dest_sha256("192.0.2.20", 443, "udp") != SERVER
    assert os_sysmon.dest_sha256("192.0.2.20", 8443, "tcp") != SERVER
    assert os_sysmon.dest_sha256("198.51.100.7", 443, "tcp") != SERVER


@pytest.mark.parametrize("data", [
    {"DestinationIp": "model.example"}, {"DestinationIp": ""}, {"DestinationIp": None}, {"DestinationIp": "192.0.2"},
    {"DestinationPort": "https"}, {"DestinationPort": "70000"}, {"DestinationPort": None}, {"Protocol": None},
])
def test_e1_what_does_not_parse_has_no_dest_sha256_never_a_guess(data):
    digest, meta = os_sysmon._event_fields(net_event(**data), None)
    assert "dest_sha256" not in meta
    assert isinstance(digest, str) and len(digest) == 64   # the line is still written, its identity as before


# --- the rounds (a fake os follow, as host.fixture_rounds) -----------------------------------------------------

def run(home, invs, os_at, old=False):
    """The HostWatch fed invs with a fake os follow; os_at {round: [(k, scenario)]}: fixturegen.os_lines for
    round k appended before that round (old: with no dest_sha256, as a line written before AU-1).
    (watch, the tree's HostTree lines in round order)."""
    feed = iter(invs)
    clock = host.FixtureClock()
    notifier = notify.Notifier(host.HOST, enabled=False, reason="test", host=True)
    watch = host.HostWatch(lambda: next(feed), CATALOG, RULES, notifier, every=fixturegen.EVERY, out=None,
                           err=io.StringIO(), clock=clock, wall=lambda: fixturegen.WALL0 + clock.t, home=str(home),
                           platform="fixture", run="test-run", sysmon=lambda: (True, "test: a synthetic os source"),
                           os_follow=host.FixtureFollow())
    seq, lines = 0, []
    for n in range(1, len(invs) + 1):
        for k, scenario in os_at.get(n, ()):
            (key,) = [x for x in watch.trees if x[0] == PID]
            src = watch.sources[key]
            src.first_pass.wait(5)
            recs, seq = fixturegen.os_lines(k, scenario, seq)
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


def mixed(n):
    """Rounds 1..n of fixturegen's "mixed": the host's sample sees the tree talk to 192.0.2.20:443 in round 1
    and its child new in round 2 (one host cycle); the os lines given are the other cycles."""
    return [fixturegen.synthetic_inventory("rhythm-os:mixed:%d" % i) for i in range(1, n + 1)]


def between(n):
    """Rounds 1..n of fixturegen's os scenarios: no host cycle; every cycle is the os source's."""
    return [fixturegen.synthetic_inventory("rhythm-os:oscycle:%d" % i) for i in range(1, n + 1)]


def fired(lines):
    return [ln for ln in lines if ln["input_meta"]["rhythm"]["fires"]]


def fires_on_the_third(lines):
    """The one firing line is the first whose rhythm counts K cycles (the round that reads the K-th)."""
    (fire,) = fired(lines)
    first = next(ln for ln in lines if ln["input_meta"]["rhythm"]["cycles"] >= K)
    assert fire is first
    assert all(ln["input_meta"]["rhythm"]["cycles"] < K for ln in lines[:lines.index(fire)])
    return fire


# --- AU-2: the rhythm's destination of an os talk ----------------------------------------------------------------

def test_e2_an_os_talk_is_named_by_its_server_hash_and_no_note(home):
    watch, lines = run(home, between(K + 2), {n: [(n, "oscycle")] for n in range(2, K + 2)})
    fire = fires_on_the_third(lines)
    assert fire["input_meta"]["rhythm"]["destination"] == OS_NAME
    assert not [x for x in watch.notes if host.PRE_DEST_NOTE in x]


def test_e2_a_line_without_the_key_keeps_its_destination_and_is_said_once_per_source(home):
    watch, lines = run(home, between(K + 2), {n: [(n, "oscycle")] for n in range(2, K + 2)}, old=True)
    fire = fires_on_the_third(lines)
    old = "os:%s" % common.canonical_sha256({"destination": fixturegen.OS_DEST})[:12]
    assert fire["input_meta"]["rhythm"]["destination"] == old != OS_NAME
    said = [x for x in watch.notes if host.PRE_DEST_NOTE in x]
    assert len(said) == 1 and "its os source" in said[0]


def test_e2_old_lines_named_on_some_events_stay_two_destinations(home):
    # the hole that stays: a line written before AU-1 has only the hash of the name too
    watch, lines = run(home, between(K + 2), {n: [(n, "osnamed")] for n in range(2, K + 2)}, old=True)
    assert not fired(lines)
    assert len([x for x in watch.notes if host.PRE_DEST_NOTE in x]) == 1


def test_e2_named_on_some_events_and_not_on_others_k_fire_k_minus_1_do_not(home):
    _, lines = run(home, between(K + 2), {n: [(n, "osnamed")] for n in range(2, K + 2)})
    assert fires_on_the_third(lines)["input_meta"]["rhythm"]["destination"] == OS_NAME
    _, lines = run(home, between(K + 2), {n: [(n, "osnamed")] for n in range(2, K + 1)})
    assert not fired(lines)
    assert max(ln["input_meta"]["rhythm"]["cycles"] for ln in lines) == K - 1


# --- AU-3: the two sources, one destination --------------------------------------------------------------------

def test_e3_one_host_cycle_and_two_os_cycles_fire_in_the_round_that_reads_the_third(home):
    _, lines = run(home, mixed(K + 2), {n: [(n, "mixed")] for n in range(3, K + 2)})
    fire = fires_on_the_third(lines)
    rhythm = fire["input_meta"]["rhythm"]
    assert rhythm["cycles"] == K and rhythm["destination"] == fixturegen.OS_REMOTE
    assert rhythm["beats"][0]["talk_round"] == 1   # the host's own talk is the first cycle's
    (finding,) = engine.judge(RHYTHM, [fire], {})[0]
    assert "cycles to %s " % fixturegen.OS_REMOTE in finding["summary"]


def test_e3_the_same_with_the_os_events_named_on_some_and_not_on_others(home):
    _, lines = run(home, mixed(K + 2), {n: [(n, "osnamed")] for n in range(3, K + 2)})
    assert fires_on_the_third(lines)["input_meta"]["rhythm"]["destination"] == fixturegen.OS_REMOTE


@pytest.mark.parametrize("scenario", ["mixed", "osnamed"])
def test_e3_k_minus_1_cycles_split_between_the_sources_do_not_fire(home, scenario):
    _, lines = run(home, mixed(K + 2), {n: [(n, scenario)] for n in range(3, K + 1)})
    assert not fired(lines)
    assert max(ln["input_meta"]["rhythm"]["cycles"] for ln in lines) == K - 1


def at(s):
    return datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(seconds=s)


def entry(n, talks=(), talk_at=None, acts=()):
    return {"round": n, "at": at(10 * n), "from": at(10 * n - 10), "seq": n,
            "talks": {d: [{"src": "t", "line": n, "text": d}] for d in talks}, "talk_at": dict(talk_at or {}),
            "acts": [{"pid": None, "image": "bash", "at": at(a), "basis": "os", "cites": []} for a in acts]}


def test_e3_rhythm_of_counts_one_server_whichever_source_saw_it_first():
    host_name = "192.0.2.20:443"
    ring = [entry(1, [OS_NAME], {OS_NAME: [at(12)]}, [15]),     # the os source first
            entry(2, [OS_NAME], {OS_NAME: [at(22)]}, [25]),
            entry(3, [host_name]), entry(4, acts=[43])]          # the sample sees it later
    got = host.rhythm_of(ring, K, 30, 10, 4)
    assert got["cycles"] == 3 and got["destination"] == host_name   # one count; named as the sample names it
    assert host.rhythm_of(ring[:2], K, 30, 10, 2)["destination"] == OS_NAME   # before it: as the os talk names it
    merged = host.one_server(ring)
    assert all(OS_NAME not in e["talks"] for e in merged)
    assert merged[0]["talk_at"] == {host_name: [at(12)]}
    assert host.rhythm_of(merged, K, 30, 10, 4) == got


def test_e3_one_round_with_both_talks_is_one_talk_and_keeps_both_times():
    ring = [entry(1, ["192.0.2.20:443", OS_NAME], {OS_NAME: [at(13)]})]
    (e,) = host.one_server(ring)
    assert list(e["talks"]) == ["192.0.2.20:443"] and len(e["talks"]["192.0.2.20:443"]) == 2
    assert e["talk_at"]["192.0.2.20:443"] == [at(10), at(13)]   # the host's at the round's time


def test_e3_what_only_one_source_saw_is_named_as_before():
    other = "os:%s" % os_sysmon.dest_sha256("192.0.2.20", 443, "udp")[:12]   # another protocol: another server
    ring = [entry(1, ["198.51.100.7:443", other], {other: [at(12)]}, [15])]
    assert host.one_server(ring) == ring
    assert host.server_of("[2001:db8::5]:443") == host.server_of("2001:db8::5:443") == "os:%s" % (
        os_sysmon.dest_sha256("2001:db8::5", 443, "tcp")[:12])
    assert host.server_of(OS_NAME) is None and host.server_of("model.example:443") is None
    assert host.server_of("192.0.2.20:https") is None


# --- AU-4: the shipped fixtures ----------------------------------------------------------------------------------

@pytest.mark.parametrize("name, cycles, dest", [
    ("positive-os-named-some", K, OS_NAME), ("negative-os-named-some", K - 1, OS_NAME),
    ("positive-split-sources", K, fixturegen.OS_REMOTE), ("negative-split-sources", K - 1, fixturegen.OS_REMOTE)])
def test_e4_the_new_fixtures_are_listed_and_say_one_destination(name, cycles, dest):
    path = "tests/fixtures/rules/HOST-RHYTHM/%s.json" % name
    assert path in RHYTHM.fixtures[name.split("-")[0]]
    doc = json.loads((FIX / ("%s.json" % name)).read_text(encoding="ascii"))
    (line,) = [ln for ln in doc["lines"] if ln.get("tool") == host.TREE_TOOL and ln["input_meta"]["pid"] == PID]
    assert line["input_meta"]["rhythm"]["cycles"] == cycles and line["input_meta"]["rhythm"]["destination"] == dest
    found, _ = engine.judge(RHYTHM, doc["lines"], {})
    assert bool(found) is name.startswith("positive-")
