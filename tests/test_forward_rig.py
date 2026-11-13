"""M10.3 E7 and the REDO's E7 (ADR-0011 J-14, L-10): the rig's stand-in collector (tools/rig/collector.py), its
forwarder run (tools/rig/forward_run.py) and X19 to X22 in tools/rig/check.py, offline: a made-up events file,
loopback only. No verdict here waits for a time to pass: the collector's own counts and the states say it."""
import http.client
import importlib.util
import json
import os
import re
import socket
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


collector = load("rig_collector", ROOT / "tools" / "rig" / "collector.py")
forward_run = load("rig_forward_run", ROOT / "tools" / "rig" / "forward_run.py")
check = load("rig_check_forward", ROOT / "tools" / "rig" / "check.py")
rig = load("rig_check_tests", ROOT / "tests" / "test_rig_check.py")
TOKEN = "made-up-rig-token-not-a-secret-89ab"


def secret(path, value=TOKEN):
    fd = os.open(str(path), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(value + "\n")
    return str(path)


def ask(port, body, token=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    headers = {"Authorization": "Splunk " + token} if token else {}
    conn.request("POST", "/services/collector/event", body=body, headers=headers)
    r = conn.getresponse()
    out = r.status, json.loads(r.read().decode("ascii"))
    conn.close()
    return out


def envelope(n):
    ev = {"id": "r1:%d" % n, "watch": {"host": "host.example"}}
    return json.dumps({"time": 1.0, "host": "host.example", "source": "raqib", "sourcetype": "raqib:event",
                       "event": ev}).encode("ascii")


def test_e7_the_collector_is_loopback_checks_the_token_and_can_refuse_fail_and_be_late(tmp_path):
    c = collector.Collector(secret(tmp_path / "t"), refuse={"r1:2"}, late=0.0)
    port = c.start()
    try:
        assert c.server.server_address[0] == "127.0.0.1" == collector.HOST
        assert ask(port, envelope(1)) == (401, {"text": "Token is required", "code": 2})
        assert ask(port, envelope(1), "made-up-wrong")[0] == 403
        assert ask(port, envelope(1) + b"\n" + envelope(3), TOKEN) == (200, {"text": "Success", "code": 0})
        assert ask(port, envelope(1) + b"\n" + envelope(2), TOKEN)[0] == 400          # told to refuse r1:2
        assert ask(port, b"{not an envelope", TOKEN)[0] == 400
        secret(tmp_path / "t", "made-up-other")                                       # read at every request
        assert ask(port, envelope(1), TOKEN)[0] == 403
        c.fail, c.fail_status = 1, 503                                                # told to fail
        assert ask(port, envelope(1), "made-up-other")[0] == 503
        c.late = 30.0                                                                 # told to be late
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=0.2)
        conn.request("POST", "/services/collector/event", body=envelope(4), headers={"Authorization": "Splunk x"})
        with pytest.raises(socket.timeout):
            conn.getresponse()   # it holds the answer (30 s, or until it stops): no answer comes in 0.2 s
        conn.close()
        assert [json.loads(x)["id"] for x in c.events] == ["r1:1", "r1:3"]
    finally:
        c.stop()


def test_redo_e7_the_collector_is_down_on_a_port_it_bound_comes_up_on_it_and_holds_a_request_by_its_count(tmp_path):
    c = collector.Collector(secret(tmp_path / "t"), down=True, hold=1)
    port = c.start()
    try:
        probe = socket.socket()
        with pytest.raises(OSError):   # bound, and nothing listening: refused
            probe.connect(("127.0.0.1", port))
        probe.close()
        c.up()
        assert ask(port, envelope(1), TOKEN)[0] == 200
        done = []
        t = threading.Thread(target=_held, args=(port, done))
        t.start()
        assert c.held.wait(30) and c.arrived == 2 and done == []
        c.release.set()   # the held request is dropped: never taken
        t.join(30)
        assert done == ["no answer"] and [json.loads(x)["id"] for x in c.events] == ["r1:1"]
        assert ask(port, envelope(3), TOKEN)[0] == 200   # only that count is held
    finally:
        c.stop()


def _held(port, done):
    try:
        ask(port, envelope(2), TOKEN)
        done.append("answered")
    except (OSError, http.client.HTTPException):
        done.append("no answer")


def made_up_file(tmp_path, count=23):
    text = rig.made_up_events()
    first = text.splitlines()
    import sys
    sys.path.insert(0, str(ROOT))
    from raqib import event
    facts = json.loads(first[0])["watch"]
    more = [event.line(event.note({"text": "note %d" % n}, facts, "2026-11-03T07:51:%02d.000Z" % n, len(first) + n,
                                  "note:%d" % n)) for n in range(1, count)]
    path = tmp_path / "events.jsonl"
    path.write_bytes(("\n".join(first[:-1] + more + first[-1:]) + "\n").encode("ascii"))
    return path


@pytest.fixture(scope="module")
def ran(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("forward-rig")
    events = made_up_file(tmp)
    out = tmp / "facts.json"
    assert forward_run.main(["--events", str(events), "--out", str(out), "--home", str(tmp / "home")]) == 0
    return events, json.loads(out.read_text(encoding="ascii"))


def states(facts, events):
    return {r[0].split(" ", 1)[0]: (r[1], r[2]) for r in check.read_forward(facts, events.read_text(encoding="ascii"))}


def test_e7_x19_to_x22_are_met_by_the_forwarder_over_a_made_up_events_file(ran):
    events, facts = ran
    got = states(facts, events)
    assert {k: s for k, (s, _) in got.items()} == {"X19": check.MET, "X20": check.MET, "X21": check.MET,
                                                   "X22": check.MET}, got
    assert facts["x20"]["failing"]["error"] == "connect" and facts["x21"]["batch"] == 5
    assert 0 < facts["x21"]["killed"]["offset"] < facts["x21"]["size"]
    assert facts["x21"]["held"] and facts["x21"]["before"] == 5 and facts["x21"]["requests_at_kill"] == 2
    assert [p["how"] for p in facts["x22"]["listed"]] and all("--token-file" in p["text"]
                                                             for p in facts["x22"]["listed"])


def test_e7_each_of_x19_to_x22_is_missed_when_its_part_is_broken(ran):
    events, facts = ran

    def broken(change):
        f = json.loads(json.dumps(facts))
        change(f)
        return {k: s for k, (s, _) in states(f, events).items()}
    assert broken(lambda f: f["x19"]["events"].pop(3))["X19"] == check.MISSED                     # a line lost
    assert broken(lambda f: f["x19"]["events"].reverse())["X19"] == check.MISSED                  # not in order
    assert broken(lambda f: f["x19"].update(exit=1))["X19"] == check.MISSED
    assert broken(lambda f: f["x20"].update(failing=None))["X20"] == check.MISSED                 # never said failing
    assert broken(lambda f: f["x20"]["events"].pop())["X20"] == check.MISSED                      # lost when it came up
    assert broken(lambda f: f["x21"].update(killed={"offset": 0}))["X21"] == check.MISSED         # not between batches
    assert broken(lambda f: f["x21"]["events"].pop(7))["X21"] == check.MISSED                     # a gap
    assert broken(lambda f: f["x21"]["events"].append(f["x21"]["events"][0]))["X21"] == check.MISSED   # sent again
    assert broken(lambda f: f["x21"].update(before=0))["X21"] == check.MISSED                     # killed too soon
    token = open(facts["token_file"], encoding="ascii").read().strip()
    wrong = open(facts["wrong_file"], encoding="ascii").read().strip()
    assert broken(lambda f: f["x22"]["texts"].append({"where": "x", "text": "a " + token}))["X22"] == check.MISSED
    assert broken(lambda f: f["x22"]["texts"].append({"where": "x", "text": "a " + wrong}))["X22"] == check.MISSED
    assert broken(lambda f: f["x22"]["argv"].append(["--token", token]))["X22"] == check.MISSED
    assert broken(lambda f: f["x22"]["listed"][0].update(text="raqib --token-file f " + wrong))["X22"] == check.MISSED
    assert broken(lambda f: f["x22"].update(listed=[]))["X22"] == check.MISSED                    # never read
    assert broken(lambda f: f["x22"]["listed"][0].update(text=""))["X22"] == check.MISSED
    assert broken(lambda f: f.update(wrong_file=str(Path(f["wrong_file"]).with_name("gone"))))["X22"] == check.MISSED
    assert set(states(None, events).values()) == {(check.MISSED, "the forwarder's run left no facts (silence is a"
                                                                 " finding)")}


def test_e7_main_reads_the_facts_beside_the_events_and_a_missing_file_is_missed(ran, tmp_path, capsys):
    events, facts = ran
    (tmp_path / "w.out").write_text(rig.REPORT, encoding="utf-8")
    (tmp_path / "l.out").write_text(rig.WORKLOAD, encoding="utf-8")
    (tmp_path / "f.json").write_text(json.dumps(facts), encoding="ascii")
    base = ["--report", str(tmp_path / "w.out"), "--workload", str(tmp_path / "l.out"), "--exit-code", "1",
            "--platform", "win32", "--sysmon", "--events", str(events)]
    assert check.main(base + ["--forward", str(tmp_path / "f.json")]) == 0
    out = capsys.readouterr().out
    assert all(re.search(r"^MET +X%d " % i, out, re.M) for i in (19, 20, 21, 22)), out
    assert check.main(base + ["--forward", str(tmp_path / "none.json"), "--strict"]) == 1
    assert "::warning title=rig MISSED::X19" in capsys.readouterr().out
    check.main(base)
    assert "X19" not in capsys.readouterr().out   # no --forward: the rig did not run it, and says nothing of it


def test_e7_rig_yml_runs_the_forwarder_on_both_machines_against_the_watchs_events_file():
    text = (ROOT / ".github" / "workflows" / "rig.yml").read_text(encoding="ascii")
    jobs = text.split("\n  linux:\n")
    assert len(jobs) == 2
    for job, events, facts in ((jobs[0], r"$HOME\.raqib\host\events.jsonl", r"$env:RUNNER_TEMP\forward.json"),
                               (jobs[1], '"$HOME/.raqib/host/events.jsonl"', '"$RUNNER_TEMP/forward.json"')):
        run = next(line for line in job.splitlines() if "run: python tools/rig/forward_run.py" in line.replace("\\", "/"))
        assert "--events " + events in run and "--out " + facts in run, run
        reads = next(line for line in job.splitlines() if "run: python tools/rig/check.py" in line.replace("\\", "/"))
        assert "--forward " + facts in reads and job.index(run) < job.index(reads), reads
        assert job.index("watch the host while the stand-in agent works") < job.index(run)
        for step in (run, reads):   # L-10: each runs always, whatever a step before it did
            head = job[:job.index(step)].rstrip().splitlines()
            assert "if: always()" in head[-1] or "if: always()" in head[-2], step


def test_e7_the_rigs_new_files_are_ascii_stdlib_and_no_part_of_raqib():
    for name in ("collector.py", "forward_run.py"):
        text = (ROOT / "tools" / "rig" / name).read_bytes().decode("ascii")
        assert "import requests" not in text and "urllib.request" not in text
    assert not [p for p in (ROOT / "raqib").rglob("*.py") if "collector" in p.read_text(encoding="utf-8") and
                "tools" in p.read_text(encoding="utf-8") and "rig/collector" in p.read_text(encoding="utf-8")]
    assert threading.current_thread() is threading.main_thread()


def test_redo_e7_forward_run_with_no_events_file_exits_0_writes_facts_and_the_table_stands(tmp_path, capsys):
    out = tmp_path / "facts.json"
    missing = tmp_path / "none" / "events.jsonl"
    assert forward_run.main(["--events", str(missing), "--out", str(out), "--home", str(tmp_path / "home")]) == 0
    facts = json.loads(out.read_text(encoding="ascii"))
    assert facts["events_missing"] is True
    got = check.read_forward(facts, "")
    assert [r[1] for r in got] == [check.SKIP] * 4 and all("no events file" in r[2] for r in got)
    (tmp_path / "w.out").write_text(rig.REPORT, encoding="utf-8")
    (tmp_path / "l.out").write_text(rig.WORKLOAD, encoding="utf-8")
    capsys.readouterr()
    assert check.main(["--report", str(tmp_path / "w.out"), "--workload", str(tmp_path / "l.out"), "--exit-code", "1",
                       "--platform", "linux", "--events", str(missing), "--forward", str(out)]) == 0
    table = capsys.readouterr().out
    assert re.search(r"^MISSED +X16 ", table, re.M) and re.search(r"^MET +X1 ", table, re.M), table
    assert all(re.search(r"^n/a +X%d .*no events file" % i, table, re.M) for i in (19, 20, 21, 22)), table


def test_redo_e7_forward_run_with_a_forwarder_that_cannot_start_exits_0_and_check_says_missed(tmp_path, capsys,
                                                                                             monkeypatch):
    events = made_up_file(tmp_path, count=5)
    monkeypatch.setattr(forward_run, "FORWARD", [str(tmp_path / "no-such-program")])
    out = tmp_path / "facts.json"
    assert forward_run.main(["--events", str(events), "--out", str(out), "--home", str(tmp_path / "home")]) == 0
    facts = json.loads(out.read_text(encoding="ascii"))
    got = {r[0].split(" ", 1)[0]: (r[1], r[2]) for r in check.read_forward(facts, events.read_text(encoding="ascii"))}
    assert {k: v[0] for k, v in got.items()} == {"X19": check.MISSED, "X20": check.MISSED, "X21": check.MISSED,
                                                 "X22": check.MISSED}, got
    assert "FileNotFoundError" in got["X20"][1] and "process list" in got["X22"][1]
    assert [t["text"] for t in facts["x22"]["texts"] if t["where"] == "x19 start"] == ["cannot start: FileNotFoundError"]
    (tmp_path / "w.out").write_text(rig.REPORT, encoding="utf-8")
    (tmp_path / "l.out").write_text(rig.WORKLOAD, encoding="utf-8")
    capsys.readouterr()
    assert check.main(["--report", str(tmp_path / "w.out"), "--workload", str(tmp_path / "l.out"), "--exit-code", "1",
                       "--platform", "linux", "--events", str(events), "--forward", str(out)]) == 0
    assert re.search(r"^MET +X1 ", capsys.readouterr().out, re.M)


# --- M10.3b E5 (ADR-0011 J-6, J-14): the syslog stand-in and X23 to X25 ----------------------------------------
syslog_collector = load("rig_syslog_collector", ROOT / "tools" / "rig" / "syslog_collector.py")


def syslog_states(facts, events):
    return {r[0].split(" ", 1)[0]: (r[1], r[2]) for r in check.read_syslog(facts, events.read_text(encoding="ascii"))}


def test_m103b_e5_the_syslog_stand_in_is_loopback_over_udp_and_tcp_and_holds_each_message_to_j6(tmp_path):
    """The stand-in reads octet-counted and newline frames over tcp and one message a datagram over udp, keeps
    the event lines in order per transport, and a problem for each message that is not J-6's shape (it takes the
    severity map as J-6 writes it, not from raqib); it can be down on a port it bound, then up."""
    import sys
    sys.path.insert(0, str(ROOT))
    from raqib import event, forward
    raw = made_up_file(tmp_path, count=3).read_bytes().splitlines(True)
    objs = [json.loads(r) for r in raw]
    msgs = [forward.syslog_message(r, o) for r, o in zip(raw, objs)]
    c = syslog_collector.SyslogCollector(down=True)
    tcp, udp = c.start()
    try:
        assert c.tcp.getsockname()[0] == c.udp.getsockname()[0] == "127.0.0.1" == syslog_collector.HOST
        probe = socket.socket()
        with pytest.raises(OSError):   # bound, and nothing listening: refused
            probe.connect(("127.0.0.1", tcp))
        probe.close()
        c.up()
        s = socket.create_connection(("127.0.0.1", tcp), timeout=10)
        s.sendall(b"".join(forward.syslog_frame(m, "syslog+tcp") for m in msgs[:2]) +
                  b"".join(forward.syslog_frame(m, "syslog+tcp", "newline") for m in msgs[2:]))
        s.sendall(b"<13>1 - - x - - - not json\n" +   # then a facility 0 where the stand-in takes 13
                  forward.syslog_frame(forward.syslog_message(raw[0], objs[0], 0), "syslog+tcp"))
        s.close()
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for m in msgs:
            u.sendto(m, ("127.0.0.1", udp))
        u.close()
    finally:
        c.stop()   # drains what was sent before it
    want = [json.dumps(o, sort_keys=True, separators=(",", ":")) for o in objs]
    assert c.events["tcp"] == want + want[:1] and c.events["udp"] == want
    assert c.framings == {"octet", "newline", "datagram"} and c.connections == 1 and c.messages == 2 * len(msgs) + 2
    assert len(c.problems) == 2 and "the MSG is not one JSON line" in c.problems[0] and "PRI of" in c.problems[1]
    assert event.check(objs[0]) == []


def test_m103b_e5_x23_to_x25_are_met_by_the_forwarder_over_syslog_over_a_made_up_events_file(ran):
    events, facts = ran
    got = syslog_states(facts, events)
    assert {k: s for k, (s, _) in got.items()} == {"X23": check.MET, "X24": check.MET, "X25": check.MET}, got
    assert facts["x23"]["framings"] == ["octet"] and facts["x25"]["framings"] == ["newline"]
    assert facts["x24"]["framings"] == ["datagram"] and facts["x24"]["connections"] == 0
    assert facts["x23"]["delivery"] == facts["x25"]["delivery"] == "written" and facts["x24"]["delivery"] == "sent"
    whole = len(events.read_bytes().splitlines())
    assert all(facts[k]["messages"] == whole == len(facts[k]["events"]) for k in ("x23", "x24", "x25"))


def test_m103b_e5_each_of_x23_to_x25_is_missed_when_its_part_is_broken_and_the_check_never_raises(ran):
    events, facts = ran

    def broken(change):
        f = json.loads(json.dumps(facts))
        change(f)
        return {k: s for k, (s, _) in syslog_states(f, events).items()}
    for key, ident in (("x23", "X23"), ("x24", "X24"), ("x25", "X25")):
        assert broken(lambda f: f[key]["events"].pop(3))[ident] == check.MISSED                  # a line lost
        assert broken(lambda f: f[key]["events"].reverse())[ident] == check.MISSED               # not in order
        assert broken(lambda f: f[key].update(exit=1))[ident] == check.MISSED
        assert broken(lambda f: f[key]["problems"].append("tcp: PRI of r1:1"))[ident] == check.MISSED
        assert broken(lambda f: f[key].update(delivery="acknowledged"))[ident] == check.MISSED
        assert broken(lambda f: f[key].update(framings=["octet", "newline"]))[ident] == check.MISSED
        assert broken(lambda f: f[key].update(refused=1))[ident] == check.MISSED
        assert broken(lambda f: f.pop(key))[ident] == check.MISSED                               # never ran
        assert broken(lambda f: f.update({key: {"error": "OSError: x"}}))[ident] == check.MISSED
        assert broken(lambda f: f[key].update(events=5))[ident] == check.MISSED                 # never raises
    assert set(v[0] for v in syslog_states(None, events).values()) == {check.MISSED}
    assert set(v[0] for v in syslog_states({"error": "boom"}, events).values()) == {check.MISSED}
    assert [r[1] for r in check.read_syslog({"events_missing": True}, "")] == [check.SKIP] * 3
    assert [r[1] for r in check.read_syslog(facts, None)] == [check.MISSED] * 3   # no events: nothing to compare


def test_m103b_e5_check_main_says_x23_to_x25_and_rig_yml_runs_them_on_both_machines(ran, tmp_path, capsys):
    events, facts = ran
    (tmp_path / "w.out").write_text(rig.REPORT, encoding="utf-8")
    (tmp_path / "l.out").write_text(rig.WORKLOAD, encoding="utf-8")
    (tmp_path / "f.json").write_text(json.dumps(facts), encoding="ascii")
    base = ["--report", str(tmp_path / "w.out"), "--workload", str(tmp_path / "l.out"), "--exit-code", "1",
            "--platform", "linux"]
    assert check.main(base + ["--events", str(events), "--forward", str(tmp_path / "f.json")]) == 0
    out = capsys.readouterr().out
    assert all(re.search(r"^MET +X%d " % i, out, re.M) for i in (23, 24, 25)), out
    assert check.main(base + ["--events", str(tmp_path / "none.jsonl"), "--forward", str(tmp_path / "f.json")]) == 0
    out = capsys.readouterr().out   # facts of lines, and no events file to hold them to: nothing is MET
    assert all(re.search(r"^MISSED +X%d .*holds no whole event" % i, out, re.M) for i in (23, 24, 25)), out
    gone = tmp_path / "g.json"
    gone.write_text(json.dumps({"events_missing": True}), encoding="ascii")
    check.main(base + ["--events", str(tmp_path / "none.jsonl"), "--forward", str(gone)])
    table = capsys.readouterr().out
    assert all(re.search(r"^n/a +X%d .*no events file" % i, table, re.M) for i in (23, 24, 25)), table
    assert forward_run.SYSLOG_CASES == ("x23", "x24", "x25") and all(k in facts for k in forward_run.SYSLOG_CASES)
    text = (ROOT / ".github" / "workflows" / "rig.yml").read_text(encoding="ascii")
    jobs = text.split("\n  linux:\n")
    for job in jobs:
        lines = job.splitlines()
        run = next(i for i, line in enumerate(lines) if "run: python tools/rig/forward_run.py" in line.replace("\\", "/"))
        assert "syslog" in lines[run - 2] + lines[run - 3] and "X25" in lines[run - 2] + lines[run - 3]
        assert any("if: always()" in x for x in lines[run - 2:run])
    assert "tools/rig/syslog_collector.py" in text


def test_m103b_e5_the_syslog_stand_in_and_the_new_rig_code_are_ascii_stdlib_and_no_part_of_raqib():
    text = (ROOT / "tools" / "rig" / "syslog_collector.py").read_bytes().decode("ascii")
    assert "import requests" not in text and "raqib import" not in text and "import raqib" not in text
    for name in ("forward_run.py", "check.py"):
        (ROOT / "tools" / "rig" / name).read_bytes().decode("ascii")
    assert not [p for p in (ROOT / "raqib").rglob("*.py") if "syslog_collector" in p.read_text(encoding="utf-8")]
