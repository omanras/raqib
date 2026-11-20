"""M15.1 (ADR-0014 A-3, A-4, A-5, A-8): the first two rules of behaviour,
PERSIST-AUTOSTART and NET-ADMIN-PORT, and the four keys an os net line
carries for the second (initiated, dest_scope, image, parent_image).

Every export here is SYNTHETIC (synthetic.py's Export: host `host`, user
`user`, private example and documentation addresses); the lines are
os-sysmon's own (os_sysmon.build)."""
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from raqib import cli, host  # noqa: E402
from raqib.hooks import os_sysmon  # noqa: E402
from raqib.rules import engine, fixtures  # noqa: E402

CATALOG = ROOT / "raqib" / "rules" / "catalog"
RULES = engine.load_catalog(CATALOG)
FX = ROOT / "tests" / "fixtures" / "rules"
FOUR = ("initiated", "dest_scope", "image", "parent_image")
PWSH = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
SSH = "C:\\Windows\\System32\\OpenSSH\\ssh.exe"
STARTUP = "C:\\Users\\user\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"
_spec = importlib.util.spec_from_file_location("os_synthetic_m151", ROOT / "tests" / "fixtures" / "os" / "synthetic.py")
SYN = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(SYN)


def rule(rule_id):
    return next(r for r in RULES if r.id == rule_id)


def export(root=4950, start_root=True, acts=(), first=79001):
    """A SYNTHETIC export: the root agent (its event 1 when start_root), then acts as generate.py's os_export
    writes them: ("proc", at, pid, image, ppid, pimage), ("file", at, pid, image, path), ("net", at, pid, image, ip,
    port[, initiated]); initiated "-" drops the field."""
    x = SYN.Export(first_record=first)
    if start_root:
        x.proc("00.100", root, SYN.AGENT, '"%s"' % SYN.AGENT, 900, SYN.EXPLORER, "C:\\Windows\\Explorer.EXE")
    for act in acts:
        if act[0] == "proc":
            _, at, pid, image, ppid, pimage = act
            x.proc(at, pid, image, '"%s"' % image, ppid, pimage, '"%s"' % pimage)
        elif act[0] == "file":
            x.file(*act[1:])
        else:
            _, at, pid, image, ip, port = act[:6]
            x.net(at, pid, image, ip, port)
            said = act[6] if len(act) > 6 else "true"
            x.lines[-1] = x.lines[-1].replace("<Data Name='Initiated'>true</Data>",
                                              "" if said == "-" else "<Data Name='Initiated'>%s</Data>" % said)
    return x.text()


def records(text, root=4950, **kw):
    lines, _ = os_sysmon.build(text, root, cwd="C:\\work\\proj", **kw)
    return [json.loads(line) for line in lines]


def nets(recs):
    return [r["input_meta"] for r in recs if r["tool"] == "net" and r["phase"] == "pre"]


# --- E1 (A-5): the four keys -----------------------------------------------------------------------------------------

@pytest.mark.parametrize("ip, scope", [
    ("127.0.0.1", "loopback"), ("127.20.0.1", "loopback"), ("::1", "loopback"), ("::ffff:127.0.0.1", "loopback"),
    ("169.254.10.20", "link-local"), ("fe80::1", "link-local"), ("fe80::1%12", "link-local"),
    ("::ffff:169.254.0.9", "link-local"),
    ("10.0.0.5", "private"), ("172.16.4.8", "private"), ("172.31.255.1", "private"), ("192.168.1.20", "private"),
    ("100.64.0.9", "private"), ("fd00::25", "private"), ("fc00::1", "private"), ("::ffff:192.168.1.21", "private"),
    ("203.0.113.7", "public"), ("198.51.100.20", "public"), ("192.0.2.20", "public"), ("172.32.0.1", "public"),
    ("2001:db8::1", "public"), ("::ffff:203.0.113.1", "public"),
    ("model.example", None), ("", None), (None, None), ("192.0.2", None), ("fe80::zz", None),
])
def test_e1_each_scope_in_ipv4_and_ipv6_and_one_with_dest_private(ip, scope):
    assert os_sysmon.dest_scope(ip) == scope
    private = os_sysmon.dest_private(ip)   # where dest_private is true the scope is one of three, false public
    assert {None: None, True: True, False: False}[private] == (None if scope is None else scope != "public")


def test_e1_a_connection_made_one_accepted_and_one_whose_initiated_is_unread():
    recs = records(export(acts=[("net", "01.000", 4950, SYN.AGENT, "192.168.1.20", 22),
                                ("net", "01.100", 4950, SYN.AGENT, "192.168.1.20", 22, "false"),
                                ("net", "01.200", 4950, SYN.AGENT, "192.168.1.20", 22, "-"),
                                ("net", "01.300", 4950, SYN.AGENT, "192.168.1.20", 22, "maybe")]))
    # M15.2b (ADR-0014 AE-1): an Initiated not read is no key (it was null until then)
    assert [m.get("initiated", "no key") for m in nets(recs)] == [True, False, "no key", "no key"]
    assert [os_sysmon.initiated(v) for v in ("true", "FALSE", " True ", "", None, 1)] == [
        True, False, True, None, None, None]
    # pre and post carry the same keys (M15.2b, AE-1: initiated only where it was read)
    assert all(set(FOUR) - {"initiated"} <= set(r["input_meta"]) for r in recs if r["tool"] == "net")
    assert [r["phase"] for r in recs if r["tool"] == "net" and "initiated" in r["input_meta"]] == ["pre", "post"] * 2


def test_e1_image_and_parent_from_the_start_the_follow_holds_null_where_it_holds_none():
    text = export(start_root=False, acts=[
        ("net", "01.000", 4950, SYN.AGENT, "10.0.0.5", 22),          # the root's start is not in the export
        ("proc", "02.000", 4970, PWSH, 4950, SYN.AGENT), ("net", "02.500", 4970, PWSH, "192.168.1.20", 22),
        ("proc", "03.000", 4980, SSH, 4970, PWSH), ("net", "03.200", 4980, SSH, "10.0.0.5", 22)])
    recs = records(text)
    got = [(m["image"], m["parent_image"]) for m in nets(recs)]
    assert got == [(None, None), ("powershell", "agent"), ("ssh", "powershell")]
    # the same gate and the same values as the process line of that process
    procs = {r["input_meta"]["image"]: r["input_meta"]["parent_image"] for r in recs
             if r["tool"] == "process" and r["phase"] == "pre"}
    assert procs == {"powershell": "agent", "ssh": "powershell"}
    # a bounded follow: the start read by an earlier pass is held across passes (build's tree keeps it)
    lines = text.splitlines()
    head = [lines[0]] + [l for l in lines[1:] if "<EventID>1<" in l]
    tail = [lines[0]] + [l for l in lines[1:] if "<EventID>3<" in l]
    tree = {}
    os_sysmon.build("\n".join(head) + "\n", 4950, guid=SYN.pguid_of(4950), tree=tree, info={})
    later = [json.loads(x) for x in os_sysmon.build("\n".join(tail) + "\n", 4950, guid=SYN.pguid_of(4950),
                                                    tree=tree, info={})[0]]
    assert [(m["image"], m["parent_image"]) for m in nets(later)] == got
    fresh = [json.loads(x) for x in os_sysmon.build("\n".join(tail) + "\n", 4950, guid=SYN.pguid_of(4950),
                                                    tree={}, info={})[0]]
    assert [(m["image"], m["parent_image"]) for m in nets(fresh)] == [(None, None)]   # no start held: null


def test_e1_every_fixture_differs_from_its_old_bytes_only_in_the_four_keys(monkeypatch):
    """os_sysmon.build of every Sysmon fixture (tests/test_event_logged_time.py's walk) with the four keys taken out
    of every net line is what the code before M15.1 gave, to the byte; dest_port, dest_private, dest_sha256 and
    input_sha256 are untouched."""
    import test_event_logged_time as logged
    real = os_sysmon.build

    def without_four(*a, **kw):
        lines, silences = real(*a, **kw)
        out = []
        for line in lines:
            rec = json.loads(line)
            if rec.get("tool") == "net":
                assert all(k in rec["input_meta"] for k in FOUR), line
                for k in FOUR:
                    del rec["input_meta"][k]
                line = json.dumps(rec, separators=(",", ":"), ensure_ascii=True)
            out.append(line)
        return out, silences

    monkeypatch.setattr(os_sysmon, "build", without_four)
    assert logged.every_fixture_build() == ("c3d84456c2d1d899b64eb9bc20fa72e300f5b5bafcd274acc27b12468a94dca2", 2179)


# --- E2, E3 (A-3, A-4, A-8): the two rules ----------------------------------------------------------------------------

def test_e2_e3_the_two_rules_as_adr_0014_rules_them():
    want = {"PERSIST-AUTOSTART": ("PERSIST", ("T1547.001",)), "NET-ADMIN-PORT": ("NET", ("T1021",))}
    for rule_id, (cls, attack) in want.items():
        r = rule(rule_id)
        assert (r.cls, r.kind, r.severity, r.attack, r.fp_budget) == (cls, "signature", "high", attack, 0.05)
        assert r.doc["match"]["all"][0] == {"field": "phase", "eq": "pre"}
    assert "PERSIST" in engine.CLASSES
    persist, admin = rule("PERSIST-AUTOSTART").evasion, rule("NET-ADMIN-PORT").evasion
    for start in ("another autostart place", "a file moved or renamed into the folder",
                  "a Sysmon that logs no file creation there", "Linux has no os source"):
        assert any(e.startswith(start) for e in persist), start
    for start in ("another port", "a public address", "a relay or a tunnel", "a Sysmon that logs no connection there",
                  "the host's own sample of a connection", "this machine's own private address"):
        assert any(e.startswith(start) for e in admin), start


def judged(rule_id, name):
    lines, ctx, expect = fixtures.load_fixture(FX / rule_id / name)
    return lines, expect, engine.evaluate([rule(rule_id)], lines, ctx)


def test_e2_persist_autostart_fires_on_a_startup_file_and_on_no_other():
    lines, expect, (found, notes) = judged("PERSIST-AUTOSTART", "positive-os-file.json")
    paths = [r["input_meta"]["path"] for r in lines if r["seq"] in expect and r["phase"] == "pre"]
    assert any("\\AppData\\Roaming\\" in p for p in paths) and any(p.startswith("C:\\ProgramData\\") for p in paths)
    assert sorted(s for f in found for s in f["cited_seq"]) == expect and notes == []
    lines, expect, (found, notes) = judged("PERSIST-AUTOSTART", "positive-hooks-write.json")
    paths = [r["input_meta"]["path"] for r in lines if r["phase"] == "pre"]
    assert any("\\Startup\\" in p for p in paths) and any("/Startup/" in p for p in paths)
    assert sorted(s for f in found for s in f["cited_seq"]) == expect and notes == []
    for name, holds in (("negative-os-file.json", ("\\Startup\\desktop.ini", "\\Startup\\old\\", "\\Accessories\\",
                                                   "\\AppData\\Local\\Temp\\")),
                        ("negative-hooks.json", ("Read", "DESKTOP.INI"))):
        lines, _, (found, notes) = judged("PERSIST-AUTOSTART", name)
        flat = json.dumps(lines).replace("\\\\", "\\")
        assert found == [] and notes == [] and all(h in flat for h in holds), name


def test_e3_net_admin_port_fires_on_a_private_admin_port_made_by_any_program():
    lines, expect, (found, notes) = judged("NET-ADMIN-PORT", "positive-admin-ports.json")
    cited = {r["seq"]: r["input_meta"] for r in lines if r["seq"] in expect and r["phase"] == "pre"}
    assert {(m["image"], m["dest_port"]) for m in cited.values()} >= {("powershell", 22), ("ssh", 22)}
    assert {m["dest_port"] for m in cited.values()} == {22, 445, 3389, 5985, 5986}
    assert sorted(s for f in found for s in f["cited_seq"]) == expect and notes == []
    assert all(f["severity"] == "high" for f in found)
    lines, _, (found, notes) = judged("NET-ADMIN-PORT", "negative-not-admin.json")
    metas = nets(lines)
    assert found == [] and notes == []
    assert {m["dest_scope"] for m in metas if m["dest_port"] == 22} == {"loopback", "link-local", "public", "private"}
    assert any(m["dest_port"] == 443 and m["dest_scope"] == "private" for m in metas)
    assert any(m["initiated"] is False and m["dest_scope"] == "private" and m["dest_port"] == 22 for m in metas)
    # M15.2b (ADR-0014 AE-1): the 22 whose Initiated is not read moved to negative-initiated-unread.json (no key)
    assert all("initiated" in m for m in metas)
    assert any((m["image"], m["parent_image"]) == ("ssh", "git") and m["dest_scope"] == "private" for m in metas)


def test_e3_a_net_line_written_before_the_four_keys_is_not_judged_and_is_said():
    lines, _, (found, notes) = judged("NET-ADMIN-PORT", "negative-before-the-keys.json")
    assert nets(lines) and all(not set(FOUR) & set(m) for m in nets(lines))
    assert found == []
    (note,) = notes
    assert note["rule_id"] == "NET-ADMIN-PORT" and note["status"] == "partial"
    assert "could not judge 1 line(s)" in note["detail"]


# --- E4: the road a finding takes -----------------------------------------------------------------------------------

def test_e4_judge_source_gives_each_finding_once_as_a_source_finding_of_its_tree_high():
    text = export(acts=[
        ("proc", "02.000", 4960, "C:\\Windows\\System32\\cmd.exe", 4950, SYN.AGENT),
        ("proc", "02.100", 4970, PWSH, 4960, "C:\\Windows\\System32\\cmd.exe"),
        ("file", "02.500", 4970, PWSH, STARTUP + "raqib-rig-test.cmd"),
        ("net", "03.000", 4970, PWSH, "192.168.1.20", 22),
        ("proc", "04.000", 4980, SSH, 4950, SYN.AGENT), ("net", "04.200", 4980, SSH, "192.168.1.20", 22)])
    recs = records(text)
    found, notes = host.judge_source(host.source_rules(RULES), recs)
    pre = {r["seq"]: r for r in recs if r["phase"] == "pre"}
    by_rule = {}
    for f in found:
        by_rule.setdefault(f["rule_id"], []).append(f)
    file_seq = [s for s, r in pre.items() if r["tool"] == "file"]
    net_seq = [s for s, r in pre.items() if r["tool"] == "net"]
    assert [f["cited_seq"] for f in by_rule["PERSIST-AUTOSTART"]] == [file_seq]
    assert [f["cited_seq"] for f in by_rule["NET-ADMIN-PORT"]] == [[s] for s in net_seq]
    # NET-TOOL says the ssh by its name (MUST NOT TOUCH): the two say two things
    ssh_seq = [s for s, r in pre.items() if r["tool"] == "process" and r["input_meta"]["image"] == "ssh"]
    assert [f["cited_seq"] for f in by_rule["NET-TOOL"]] == [ssh_seq]
    tool = by_rule["NET-TOOL"][0]
    for f in by_rule["PERSIST-AUTOSTART"] + by_rule["NET-ADMIN-PORT"]:
        assert f["severity"] == "high" and f["session_id"] == tool["session_id"] == "os-4950"
        assert set(f) == set(tool) and f["kind"] == "signature"
    assert not [n for n in notes if n["rule_id"] in ("PERSIST-AUTOSTART", "NET-ADMIN-PORT")]
    # the host watch gives os lines to every rule of the catalog that is not of class HOST: the two are there
    assert {"PERSIST-AUTOSTART", "NET-ADMIN-PORT"} <= {r.id for r in host.source_rules(RULES)}


def test_e4_check_rules_lists_both_rules_ok_within_their_budgets():
    reports = {r["rule_id"]: r for r in fixtures.check_catalog(RULES, ROOT, cli.benign_default(ROOT))}
    got = {k: (reports[k]["verdict"], reports[k]["fp_rate"], reports[k]["measured"], reports[k]["unmeasured"])
           for k in ("PERSIST-AUTOSTART", "NET-ADMIN-PORT")}
    # PERSIST-AUTOSTART has no gate (C-1a): every benign file is measured; NET-ADMIN-PORT's gate is source os and
    # tool net, which no benign file holds: its one measured negative is its own, the line before the keys is partial
    # (M15.2b, AE-1: and so are the lines whose Initiated is not read, a negative of their own: 9 unmeasured -> 10)
    assert got == {"PERSIST-AUTOSTART": ("ok", 0.0, 10, 0), "NET-ADMIN-PORT": ("ok", 0.0, 1, 10)}
    out = subprocess.run([sys.executable, "-m", "raqib", "check-rules"], cwd=str(ROOT), capture_output=True,
                         text=True, timeout=300)
    assert out.returncode == 0, out.stderr
    rows = {line.split()[0]: line for line in out.stdout.splitlines()[1:]}
    assert re.match(r"PERSIST-AUTOSTART ok +0\.000 +0\.05 +2 positive; .* 10 measured, 0 unmeasured",
                    rows["PERSIST-AUTOSTART"])
    assert re.match(r"NET-ADMIN-PORT +ok +0\.000 +0\.05 +1 positive; .* 1 measured, 10 unmeasured",
                    rows["NET-ADMIN-PORT"])


# --- E7: ASCII, and only os_sysmon and engine of raqib/ change ----------------------------------------------------------

def test_e7_the_new_files_are_ascii():
    for path in [CATALOG / "PERSIST-AUTOSTART.yaml", CATALOG / "NET-ADMIN-PORT.yaml", Path(__file__),
                 ROOT / "raqib" / "hooks" / "os_sysmon.py", ROOT / "raqib" / "rules" / "engine.py"]:
        path.read_bytes().decode("ascii")
    for path in sorted((FX / "PERSIST-AUTOSTART").glob("*.json")) + sorted((FX / "NET-ADMIN-PORT").glob("*.json")):
        path.read_bytes().decode("ascii")   # the generator's bytes are held by tests/test_rules.py


# --- E6: the guide and the threat model say what the two rules read and what they do not -------------------------------

def test_e6_the_guide_and_the_threat_model_hold_the_sentences_that_matter():
    guide = " ".join((ROOT / "docs" / "GUIDE.md").read_text(encoding="utf-8").split())
    assert "| PERSIST-AUTOSTART | a file written directly in a Startup folder of Windows" in guide
    assert "read from Sysmon's file line (event 11) of a watched tree or from a Write, Edit, MultiEdit or" in guide
    assert "Linux has no os source for it: there only a hooks file tool is judged." in guide
    assert "| NET-ADMIN-PORT | a connection the process itself made (Sysmon's net line, event 3: `initiated` true)" in guide
    assert "whatever program of the tree opened the socket (PowerShell's own included), unless it is ssh started by git" in guide
    assert "Linux has no os source for it: nothing there is judged by it" in guide
    text = (ROOT / "docs" / "THREAT_MODEL.md").read_text(encoding="utf-8")
    part = text.split("### The rules of behaviour (PERSIST-AUTOSTART, NET-ADMIN-PORT; ADR-0014)", 1)[1].split("### ", 1)[0]
    flat = " ".join(part.split())
    for sentence in ("a scheduled task is written by the Schedule service (svchost, as SYSTEM, 24 ms after schtasks"
                     " started), not by a process of the tree.",
                     "A file moved or renamed into the folder: not measured.",
                     "connects to port 445 as System, not as a process of the tree.",
                     "The budgets of the two rules were measured on no real desktop's work.",
                     "nothing is then there to read, and Raqib cannot tell that from nothing done.",
                     "A port not on the list, a public address, a relay or a tunnel.",
                     "Measured: the two short connections to port 22 were in no sample of the host.",
                     "This machine's own private address, which a line cannot tell from another machine's.",
                     "Linux has no os source: neither rule judges an os line there;",
                     "a file under TEMP, and a shell under a shell, are an agent's ordinary work.",
                     "judged by no rule."):
        assert sentence in flat, sentence
    assert not re.search(r"\bM\d+\.\d+", part)   # no milestone token
