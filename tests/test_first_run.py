"""M9.1 (ADR-0010 decisions 1-6): a stranger's first run, as the outsider's
rehearsal of 2026-11-11 found it (docs/review/2026-11-11-outsider-rehearsal.md).
Each decision is tested for the case it is FOR and for what it MUST NOT
TOUCH (ADR-0007 Z-9). The signal tests start a real child process
(`python -m raqib watch`), with HOME and USERPROFILE in tmp_path, and end it
in a finally; a platform that cannot deliver a signal is asked first and the
test skips with the reason. Every record here is synthetic (no host, user or
address of any real machine)."""
import ast
import errno
import io
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "tests" / "fixtures" / "host"))

import raqib  # noqa: E402
from raqib import cli, doctor, host, notify, overlay, report, ruleform, ui, watch  # noqa: E402
from raqib.rules import engine, fixtures  # noqa: E402
from hostthreads import raqib_threads_end  # noqa: E402,F401  (every HostWatch ended, no thread leaked)

WINDOWS = sys.platform == "win32"
CATALOG_DIR = ROOT / "raqib" / "rules" / "catalog"
RULES = {r.id: r for r in engine.load_catalog(str(CATALOG_DIR))}
# The two summaries before M9.1 (main 0e8b007): they named input_meta.command_head.
OLD_SUMMARIES = {
    "DESTRUCT-CMD": "{tool} runs {input_meta.command_head} at seq {seq} (programs {input_meta.command_programs})",
    "NET-TOOL": "{tool} may reach the network at seq {seq} (host {input_meta.url_host}, program"
                " {input_meta.command_head}, programs {input_meta.command_programs})"}
CHILD_TIMEOUT = 120   # seconds a child may take to start or to end; polled, never slept through
REAL_NOTIFY, REAL_KEY, REAL_CATALOG = notify.Notifier.notify, watch.Watch.key, cli._overlay_catalog


@pytest.fixture
def home(tmp_path, monkeypatch):
    path = tmp_path / "home"
    path.mkdir()
    monkeypatch.setenv("HOME", str(path))
    monkeypatch.setenv("USERPROFILE", str(path))
    return path


def old_rule(rule):
    return engine.compile_rule(dict(rule.doc, summary=OLD_SUMMARIES[rule.id]), rule.source)


def line(seq, session="s-first", phase="pre", tool="Bash", at=0, **meta):
    rec = {"ts": "2026-11-11T10:00:%02d.000Z" % (at % 60), "seq": seq, "session_id": session, "phase": phase,
           "tool": tool, "cwd": "/work/demo"}
    if phase in ("pre", "post"):
        rec.update(input_sha256="0" * 64, input_meta=meta)
    return rec


def result_lines(text):
    return [x for x in text.splitlines() if x.startswith("RESULT:")]


def finished_rows(home):
    data = json.loads((Path(home) / ".raqib" / watch.REGISTRY_NAME).read_text(encoding="ascii"))
    return [(r.get("status"), r.get("finished") is not None) for r in data["watches"]]


# --- E2 (decision 2): --version -----------------------------------------------------------------------------

@pytest.mark.parametrize("flag", ["--version", "-V"])
def test_e2_version_prints_raqib_and_its_version_and_exits_0(flag, capsys):
    out = io.StringIO()
    assert cli.main([flag], out=out) == 0
    assert out.getvalue() == "raqib %s\n" % raqib.__version__
    assert capsys.readouterr().err == ""


def test_e2_version_from_the_console_entry_point():
    run = subprocess.run([sys.executable, "-m", "raqib", "--version"], capture_output=True, text=True,
                         timeout=CHILD_TIMEOUT, env=dict(os.environ, PYTHONPATH=str(ROOT)), cwd=str(ROOT))
    assert run.returncode == 0 and run.stdout == "raqib %s\n" % raqib.__version__


def test_e2_must_not_touch_raqib_alone_exits_2_with_its_usage(capsys):
    assert cli.main([], out=io.StringIO()) == 2
    err = capsys.readouterr().err
    assert err.startswith("usage: raqib") and "the following arguments are required: command" in err
    assert cli.main(["no-such-command"], out=io.StringIO()) == 2


# --- E3 (decision 3): the notifier line ----------------------------------------------------------------------

@pytest.mark.parametrize("platform, reason", [("linux", "no /usr/bin/notify-send or /bin/notify-send"),
                                              ("darwin", "no /usr/bin/osascript")])
def test_e3_a_working_terminal_fallback_is_unsure_said_and_never_fails_the_exit(tmp_path, platform, reason):
    verdict, text = doctor.check_notifier(str(tmp_path), {"PATH": "/x"}, platform, lambda p: False, lambda p: True)
    assert verdict == doctor.UNSURE
    assert text == "%s (%s)" % (doctor.NOTIFIER_UNSURE, reason)
    assert "a knock reaches the terminal" in text and "no desktop notification" in text   # what is, what is not
    lines = [("python", (True, "3.12")), ("notifier", (verdict, text))]
    assert doctor.summary(lines) == ("0 MISSING, 1 UNSURE", 0)


def test_e3_must_not_touch_notifications_off_stay_missing_exit_included(tmp_path):
    ci = doctor.check_notifier(str(tmp_path), {"PATH": "/x", "CI": "true"}, "linux", lambda p: True, lambda p: True)
    assert ci == (False, "off (CI is set: no notification is shown in CI)")
    root = doctor.check_notifier(str(tmp_path), {"SystemRoot": str(tmp_path)}, "win32", lambda p: True,
                                 lambda p: True)
    assert root[0] is False and "is not an existing directory named Windows" in root[1]
    assert doctor.summary([("notifier", ci)])[1] == 1 and doctor.summary([("notifier", root)])[1] == 1


def test_e3_must_not_touch_what_watch_says_of_its_own_notifier(tmp_path):
    n = notify.Notifier(str(tmp_path), environ={"PATH": "/x"}, platform="linux", isfile=lambda p: False)
    assert n.band() == ("incomplete", "notifications: terminal bell and stderr only (no /usr/bin/notify-send or"
                                      " /bin/notify-send)")


# --- E4 (decision 4): the finding names the program that made it ---------------------------------------------

def test_e4_destruct_cmd_and_net_tool_name_what_their_list_holds_not_the_head():
    rec = line(3, command_head="curl", command_programs=["curl", "bash", "rm"])
    (d,) = engine.run_rule(RULES["DESTRUCT-CMD"], [rec])
    assert d["summary"] == 'Bash runs rm at seq 3 (programs ["curl", "bash", "rm"])'
    (n,) = engine.run_rule(RULES["NET-TOOL"], [rec])
    assert n["summary"] == 'Bash may reach the network at seq 3 (host -, program curl, programs ["curl", "bash", "rm"])'
    many = line(4, command_head="cd", command_programs=["cd", "rm", "dd", "rm"])
    assert engine.run_rule(RULES["DESTRUCT-CMD"], [many])[0]["summary"].startswith("Bash runs rm, dd at seq 4")


def test_e4_head_only_os_and_host_lines_still_render_a_true_sentence():
    unread = line(5, command_head="rm", command_unread=True)                 # capture could not read it all
    assert engine.run_rule(RULES["DESTRUCT-CMD"], [unread])[0]["summary"] == "Bash runs rm at seq 5 (programs -)"
    odd = line(6, command_head="mkfs.foo", command_programs=["mkfs.foo"])     # the head's pattern, not the list
    assert engine.run_rule(RULES["DESTRUCT-CMD"], [odd])[0]["summary"] == \
        'Bash runs mkfs.foo at seq 6 (programs ["mkfs.foo"])'
    osline = dict(line(7, session="os-4100", tool="process", command_head="rm.exe", command_programs=["rm.exe"],
                       image="rm", parent_image="bash"), source="os")
    assert engine.run_rule(RULES["DESTRUCT-CMD"], [osline])[0]["summary"] == \
        'process runs rm at seq 7 (programs ["rm.exe"])'
    osnet = dict(osline, input_meta={"command_head": "curl.exe", "command_programs": ["curl.exe"],
                                     "image": "curl", "parent_image": "bash"})
    assert engine.run_rule(RULES["NET-TOOL"], [osnet])[0]["summary"] == \
        'process may reach the network at seq 7 (host -, program curl, programs ["curl.exe"])'
    git_ssh = dict(osline, input_meta={"image": "ssh", "parent_image": "git"})   # R-7: left out, no sentence
    assert engine.run_rule(RULES["NET-TOOL"], [git_ssh]) == []
    child = dict(line(8, session="host-1600", tool="HostChild", command_programs=["bash", "rm", "ssh"]),
                 source="host", cwd="host")
    assert engine.run_rule(RULES["DESTRUCT-CMD"], [child])[0]["summary"] == \
        'HostChild runs rm at seq 8 (programs ["bash", "rm", "ssh"])'
    assert engine.run_rule(RULES["NET-TOOL"], [child])[0]["summary"] == \
        'HostChild may reach the network at seq 8 (host -, program ssh, programs ["bash", "rm", "ssh"])'
    web = dict(line(9, tool="WebFetch", url_host="docs.example.org"))
    assert engine.run_rule(RULES["NET-TOOL"], [web])[0]["summary"] == \
        "WebFetch may reach the network at seq 9 (host docs.example.org, program -, programs -)"


def test_e4_matched_reads_only_the_branches_that_hold_and_never_a_not():
    doc = {"id": "TEST-MATCHED", "title": "t", "class": "NET", "kind": "signature", "evasion": ["x"],
           "severity": "low", "fp_budget": 0.1,
           "fixtures": {"positive": ["tests/fixtures/x.json"], "negative": ["tests/fixtures/y.json"]},
           "summary": "{matched:input_meta.command_programs,tool} | {matched:input_meta.image}",
           "match": {"any": [
               {"all": [{"field": "tool", "eq": "Bash"},
                        {"field": "input_meta.command_programs", "has_any": ["a", "b"]}]},
               {"all": [{"field": "tool", "eq": "Other"},
                        {"field": "input_meta.command_programs", "has_any": ["c"]}]},
               {"all": [{"field": "input_meta.image", "in": ["z"]},
                        {"not": {"field": "input_meta.image", "eq": "y"}}]}]}}
    rule = engine.compile_rule(doc)
    rec = line(1, command_programs=["c", "b", "a", "b"], image="z")
    (f,) = engine.run_rule(rule, [rec])
    # the Bash branch holds (b, a; then the tool), the Other branch does not (c is not named), the image branch
    # holds through its in (z); the not names nothing
    assert f["summary"] == "b, a, Bash | z"
    assert engine.run_rule(engine.compile_rule(dict(doc, summary="{matched:cwd}")), [rec])[0]["summary"] == "-"


@pytest.mark.parametrize("bad", ["{matched:}", "{matched:Bad}", "{matched:a,,b}", "{matched: tool}"])
def test_e4_a_bad_matched_placeholder_is_refused(bad):
    doc = dict(RULES["NET-TOOL"].doc, summary=bad)
    with pytest.raises(engine.RuleError, match="bad placeholder"):
        engine.compile_rule(doc)


def fixture_lines():
    """Every record of every rule fixture, the benign corpus and the real-trace logs (with its context)."""
    paths = sorted((ROOT / "tests" / "fixtures" / "rules").rglob("*.json"))
    paths += sorted((ROOT / "tests" / "fixtures").glob("*.log"))
    out = []
    for p in paths:
        try:
            lines, ctx, _ = fixtures.load_fixture(str(p))
        except fixtures.FixtureError:
            continue
        out.append((p, lines, ctx or {}))
    return out


FIXTURE_LINES = fixture_lines()


def test_e4_must_not_touch_the_explainer_judges_every_line_as_the_match_does():
    assert len(FIXTURE_LINES) > 50
    for rule in RULES.values():
        explain = engine._explainer(rule.doc["match"], "match", rule)
        for p, lines, ctx in FIXTURE_LINES:
            if not (rule.context_keys <= set(ctx) and all(engine.context_ok(ctx[k]) for k in rule.context_keys)):
                continue   # evaluate() does not run it there either
            for rec in lines:
                if isinstance(rec, dict):
                    assert explain(rec, ctx)[0] is rule.match(rec, ctx), (rule.id, p.name, rec.get("seq"))


@pytest.mark.parametrize("rule_id", sorted(OLD_SUMMARIES))
def test_e4_must_not_touch_the_same_lines_fire_and_the_same_lines_are_cited(rule_id):
    new, old = RULES[rule_id], old_rule(RULES[rule_id])
    fired = changed = 0
    for p, lines, ctx in FIXTURE_LINES:
        f_new, n_new = engine.evaluate([new], lines, ctx)
        f_old, n_old = engine.evaluate([old], lines, ctx)
        assert n_new == n_old, p.name
        strip = (lambda fs: [{k: v for k, v in f.items() if k != "summary"} for f in fs])
        assert strip(f_new) == strip(f_old), p.name
        fired += len(f_new)
        changed += sum(a["summary"] != b["summary"] for a, b in zip(f_new, f_old))
    assert fired and changed   # it fires on the fixtures as before, and some sentences are truer now
    # check-rules (A6): the same measurement of the rule, budget and verdict
    benign = cli.benign_default(str(ROOT))
    assert fixtures.check_catalog([new], str(ROOT), benign) == fixtures.check_catalog([old], str(ROOT), benign)


def project_watch(tmp_path, monkeypatch, summaries=None):
    """`raqib watch` in process over a live Bash line that DESTRUCT-CMD and NET-TOOL both fire on; summaries:
    the old templates instead of the catalog's. (out, notify calls, Watch keys, watch.json findings)."""
    proj = tmp_path / "proj"
    proj.mkdir(parents=True)
    home = Path(os.environ["HOME"])
    trace_path = Path(watch.default_trace(os.path.normpath(str(proj)), str(home)))
    monkeypatch.setattr(cli, "_overlay_catalog", lambda: [old_rule(r) if summaries and r.id in summaries else r
                                                          for r in REAL_CATALOG()])
    calls, keys = [], []
    real_notify, real_key = REAL_NOTIFY, REAL_KEY

    def recording_notify(self, event, where, now, **kw):
        calls.append((event, where, kw.get("limit_id")))
        return real_notify(self, event, where, now, **kw)

    def recording_key(self, finding):
        k = real_key(self, finding)
        keys.append(k)
        return k
    monkeypatch.setattr(notify.Notifier, "notify", recording_notify)
    monkeypatch.setattr(watch.Watch, "key", recording_key)
    lines = [line(1, phase="session_start", tool="-"),
             line(2, command_head="curl", command_programs=["curl", "bash", "rm"], at=1),
             dict(line(2, phase="post", command_head="curl", command_programs=["curl", "bash", "rm"], at=2),
                  ok=True, output_sha256="1" * 64, output_meta={"scan": "full", "secret_kinds": []}),
             line(3, phase="stop", tool="-", at=3)]
    def agent_works():
        with open(trace_path, "a", encoding="ascii", newline="\n") as f:
            f.write("".join(json.dumps(x) + "\n" for x in lines))
    queue = [agent_works, lambda: None]

    def fake_sleep(seconds):
        if not queue:
            raise KeyboardInterrupt
        queue.pop(0)()
    monkeypatch.setattr(watch, "_sleep", fake_sleep)
    out = io.StringIO()
    code = cli.main(["watch", str(proj), "--no-open", "--no-notify", "--port", "0"], out=out)
    state = json.loads(Path(str(trace_path) + ".watch.json").read_text(encoding="ascii"))
    return code, out.getvalue(), calls, keys, state


def test_e4_must_not_touch_a_project_watchs_knocks_folding_keys_and_findings(tmp_path, home, monkeypatch):
    new = project_watch(tmp_path / "new", monkeypatch)
    old = project_watch(tmp_path / "old", monkeypatch, summaries=OLD_SUMMARIES)
    assert new[0] == old[0] == 1
    # notification folding is keyed by the limit id or the event, never the sentence: the same calls
    assert new[2] == old[2] and any(e == notify.FIRST_EVENT for e, _, _ in new[2])
    # the B-2 key (epoch, rule_id, session_id, cited_seq, summary): the same but for its summary (Q-1)
    assert sorted({k[:4] for k in new[3]}) == sorted({k[:4] for k in old[3]})
    assert {k[1] for k in new[3]} >= {"DESTRUCT-CMD", "NET-TOOL"}
    clock = ("first_seen", "settled_at")   # wall-clock times of each run
    strip = (lambda st: [dict({k: v for k, v in f.items() if k not in ("summary", "key") + clock},
                              key=f["key"][:4]) for f in st["findings"]])
    assert strip(new[4]) == strip(old[4]) and all(f["key"][4] == f["summary"] for f in new[4]["findings"])
    said = {f["rule_id"]: f["summary"] for f in new[4]["findings"]}
    assert said["DESTRUCT-CMD"].startswith("Bash runs rm at seq 2")
    assert {f["rule_id"]: f["summary"] for f in old[4]["findings"]}["DESTRUCT-CMD"].startswith("Bash runs curl")


def host_watch(tmp_path, monkeypatch, summaries=None):
    import test_acts_judged as aj
    rules = [old_rule(r) if summaries and r.id in summaries else r for r in aj.RULES]
    monkeypatch.setattr(aj, "RULES", rules)
    lines = aj.after_start(aj.os_lines("net-windows.sysmon.xml", 4700))
    tmp_path.mkdir(parents=True, exist_ok=True)
    w = aj.watch_rounds(tmp_path, ["defender/before", "quiet/talking", "quiet/talking"],
                        follow=aj.CountingFollow(lines))
    try:
        found = [f for f in w.source_findings if f["rule_id"] == "NET-TOOL"]
        return (sorted(w.acts, key=repr),
                [(k["event"], k["limit_id"], k["title"], k["body"], k["status"]) for k in w.knock_rows()],
                [((os.path.basename(f["fkey"][0]),) + tuple(f["fkey"][1:5]), f["fkey"][5], f["summary"], f["notice"],
                 f["cited_seq"]) for f in found])
    finally:
        w.finish()


def test_e4_must_not_touch_the_host_watchs_act_registry_and_knock_ledger(tmp_path, monkeypatch):
    acts, knocks, found = host_watch(tmp_path / "new", monkeypatch)
    acts0, knocks0, found0 = host_watch(tmp_path / "old", monkeypatch, summaries=OLD_SUMMARIES)
    assert len(found) == 3
    assert acts == acts0 and any(a[0] == "NET-TOOL" for a in acts)   # the act registry's keys
    # the KNOCKS ledger (event, text, rate-limit id, status) is the same; its keys hold no sentence
    assert knocks == knocks0 and knocks
    # the source finding key: the same but for its last part, the summary (Q-1); the same notices and cites
    assert [(k, n, c) for k, _, _, n, c in found] == [(k, n, c) for k, _, _, n, c in found0]
    assert [s for _, s, summary, _, _ in found] == [summary for _, _, summary, _, _ in found]
    assert sorted(s.split("program ")[1].split(",")[0] for _, s, _, _, _ in found) == ["bitsadmin", "plink", "ssh"]
    assert sorted(s.split("program ")[1].split(",")[0] for _, s, _, _, _ in found0) == [
        "bitsadmin.exe", "plink.exe", "ssh.exe"]


# --- E5 (decision 5): the ALARMS line says what it counts ----------------------------------------------------

def write_trace(path, recs):
    path.write_text("".join(json.dumps(r) + "\n" for r in recs), encoding="ascii")
    return path


def test_e5_the_text_report_says_under_alarms_what_it_counts(tmp_path):
    trace = write_trace(tmp_path / "t.jsonl", [line(1, phase="session_start", tool="-"),
                                               line(2, command_head="rm", command_programs=["rm"]),
                                               line(3, phase="stop", tool="-")])
    out = io.StringIO()
    code = cli.main(["report", str(trace), "--scope", "."], out=out)
    rows = out.getvalue().splitlines()
    i = rows.index("ALARMS (A3, A5): 0")
    assert rows[i + 1:i + 3] == list(report.ALARMS_SAYS) and rows.count(report.ALARMS_SAYS[0]) == 1
    said = " ".join(x.strip() for x in rows[i + 1:i + 3])   # REDO 2 C-4: what is counted, named; two lines
    for named in ("silence", "a crash of the watch", "a knock that did not arrive",
                  "what could not be read, cited or kept", "the trace's and the watch's own",
                  "every finding below also makes the RESULT an ALARM"):
        assert named in said, named
    assert len(report.ALARMS_SAYS) == 2 and all(len(x) <= 120 for x in report.ALARMS_SAYS)
    assert code == 1 and result_lines(out.getvalue()) == ["RESULT: ALARM (exit 1)"]
    assert any(r.startswith("FINDINGS: ") and r != "FINDINGS: 0" for r in rows)


def test_e5_must_not_touch_the_json_report_counts_codes_and_page(tmp_path):
    trace = write_trace(tmp_path / "t.jsonl", [line(1, phase="session_start", tool="-"),
                                               line(2, command_head="rm", command_programs=["rm"])])
    text, js = io.StringIO(), io.StringIO()
    code_text = cli.main(["report", str(trace), "--scope", "."], out=text)
    code_json = cli.main(["report", str(trace), "--scope", ".", "--json"], out=js)
    rep = json.loads(js.getvalue())
    assert code_text == code_json == rep["exit"] == 1
    for said in report.ALARMS_SAYS:
        assert said.strip() not in js.getvalue()
    assert "a knock that did not arrive" not in js.getvalue()
    assert "ALARMS (A3, A5): %d" % len(rep["alarms"]) in text.getvalue()
    assert "FINDINGS: %d" % len(rep["findings"]) in text.getvalue()
    page = io.StringIO()
    cli.main(["ui", str(trace), "--scope", "."], out=page)
    for said in report.ALARMS_SAYS:
        assert said.strip() not in page.getvalue()
    assert "a knock that did not arrive" not in page.getvalue()   # no apostrophe: not hidden by an escape
    # an empty trace: the alarm is counted as before, the line is the same
    empty = write_trace(tmp_path / "e.jsonl", [])
    out = io.StringIO()
    assert cli.main(["report", str(empty)], out=out) == 1
    rows = out.getvalue().splitlines()
    k = rows.index("ALARMS (A3, A5): 1")
    assert rows[k + 1:k + 3] == list(report.ALARMS_SAYS)


# --- E6 (decision 6): the quickstart's first command succeeds ------------------------------------------------

README = (ROOT / "README.md").read_text(encoding="utf-8")
from readme_text import GUIDE, flat as flat_text, section as cut, units  # noqa: E402  (M9.2: README.md and docs/GUIDE.md)


def readme_section(title):
    return README.split("## %s\n" % title, 1)[1].split("\n## ", 1)[0]


def test_e6_install_block_is_clone_install_ensurepath_watch_and_doctor_follows():
    install = readme_section("Install and watch")
    block = install.split("```bash\n", 1)[1].split("```", 1)[0].splitlines()
    assert [b.split("#")[0].strip() for b in block] == [
        "git clone https://github.com/omanras/raqib ~/raqib", "pipx install ~/raqib", "pipx ensurepath",
        "raqib watch ~/my-project"]
    assert "puts `raqib` on PATH" in block[2]
    after = install.split("```bash\n", 1)[1].split("```\n", 1)[1]
    # M9.2: the README is wrapped at 120 now; the old first line (the two sentences) is the start of the first
    # paragraph after the block, flattened - and it must still start with exactly those two sentences.
    first = units(after)[0]
    assert first.startswith("`raqib doctor ~/my-project` says what is missing: one line per check, OK, MISSING or"
                            " UNSURE; exit 1 if anything is missing. Before the first watch it reports the hooks"
                            " MISSING and exits 1, because `raqib watch` is what installs them.")
    assert first.startswith("`raqib doctor ~/my-project` says what is missing")
    assert ("Before the first watch it reports the hooks MISSING and exits 1, because `raqib watch` is what"
            " installs them.") in first


def test_e6_must_not_touch_the_three_first_headings_and_the_first_screen():
    import re
    assert re.findall(r"^## (.+)$", README, re.M)[:3] == ["Install and watch", "Watch a project", "Doctor"]
    assert len(README.split("\n## Doctor\n", 1)[0].splitlines()) <= 25


def test_e1_readme_says_what_stops_a_watch_and_what_stays_out_of_reach():
    flat = " ".join(cut("Watch a project", GUIDE).split())   # M9.2: the stop's line is in docs/GUIDE.md
    for phrase in ("so do SIGTERM and SIGHUP", "Ctrl-Break on Windows", "`raqib watch --host`",
                   '"stopped (SIGTERM)"', "exit code 0 / 1 / 3", "SIGKILL", "TerminateProcess (`taskkill /F`,",
                   "`raqib report <trace>` gives the findings"):
        assert phrase in flat, phrase
    doctor_text = " ".join(cut("Doctor", GUIDE).split())
    assert "A notifier that is the terminal bell and stderr only is UNSURE too" in doctor_text


# --- E1 (decision 1): a watch asked to stop, stops as Ctrl-C does ---------------------------------------------

class FakeSignals:
    """The signal module as Stops uses it: getsignal, signal, SIG_DFL, SIG_IGN and the numbers."""
    SIG_DFL, SIG_IGN = "SIG_DFL", "SIG_IGN"

    def __init__(self, names=("SIGTERM", "SIGHUP"), ignored=()):
        self.numbers = {"SIGTERM": 15, "SIGHUP": 1, "SIGBREAK": 21}
        for name in names:
            setattr(self, name, self.numbers[name])
        self.handlers = {self.numbers[n]: (self.SIG_IGN if n in ignored else "earlier " + n) for n in names}
        self.calls = []

    def getsignal(self, number):
        return self.handlers[number]

    def signal(self, number, handler):
        self.calls.append((number, handler))
        old, self.handlers[number] = self.handlers[number], handler
        return old


def test_e1_stops_installs_in_the_main_thread_and_restores_the_earlier_handlers():
    fake = FakeSignals()
    stops = cli.Stops(fake)
    assert stops.install() == ["SIGHUP", "SIGTERM"]
    assert fake.handlers == {15: stops.handler, 1: stops.handler}
    stops.restore()
    assert fake.handlers == {15: "earlier SIGTERM", 1: "earlier SIGHUP"}
    win = FakeSignals(names=("SIGTERM", "SIGBREAK"))   # Windows: SIGBREAK, no SIGHUP
    assert cli.Stops(win).install() == ["SIGBREAK", "SIGTERM"]


def test_e1_stops_installs_nothing_outside_the_main_thread():
    fake, got = FakeSignals(), []
    t = threading.Thread(target=lambda: got.append(cli.Stops(fake).install()))
    t.start()
    t.join(10)
    assert got == [[]] and fake.calls == []


def test_e1_a_signal_ignored_at_the_start_stays_ignored():
    fake = FakeSignals(ignored=("SIGHUP",))   # nohup: Q-2
    stops = cli.Stops(fake)
    assert stops.install() == ["SIGTERM"] and stops.ignored == ["SIGHUP"] and fake.handlers[1] == fake.SIG_IGN


def test_e1_the_first_signal_ends_the_nap_a_later_one_is_counted_never_acted_on():
    stops = cli.Stops(FakeSignals())
    slept = []

    def sleep(seconds):   # the signal arrives while the watch waits
        slept.append(seconds)
        stops.handler(15, None)
        raise AssertionError("the nap was not ended")
    with pytest.raises(watch.AskedStop) as caught:
        stops.nap(sleep, 0.5)
    assert caught.value.name == "SIGTERM" and slept == [0.5] and isinstance(caught.value, KeyboardInterrupt)
    assert stops.handler(1, None) is None and stops.later == 1   # while the report is written: nothing
    stops.napping = True
    assert stops.handler(15, None) is None and stops.later == 2  # not even inside a nap: one stop only


def test_e1_a_signal_while_the_watch_polls_or_starts_stops_it_at_the_next_nap():
    stops = cli.Stops(FakeSignals())
    stops.handler(1, None)                         # not napping: kept, nothing raised
    with pytest.raises(watch.AskedStop, match="SIGHUP"):
        stops.nap(lambda s: pytest.fail("slept after the stop"), 0.5)


def test_e1_stopped_by_names_the_signal_and_keeps_ctrl_c_s_words():
    assert watch.stopped_by(watch.AskedStop("SIGTERM")) == "SIGTERM"
    assert watch.stopped_by(KeyboardInterrupt()) == "Ctrl-C"


def run_in_process(tmp_path, monkeypatch, argv, sleep_target, how):
    """cli.main(argv) with sleep_target's _sleep replaced: "SIGTERM" calls the handler the CLI installed, as the
    OS would (no signal is sent); "Ctrl-C" raises KeyboardInterrupt. A second call of the handler comes while
    the final report is written (finish)."""
    before = signal.getsignal(signal.SIGTERM)
    second = []

    def fake_sleep(seconds):
        if how == "Ctrl-C":
            raise KeyboardInterrupt
        installed = signal.getsignal(signal.SIGTERM)
        assert installed != before and getattr(installed, "__self__", None).__class__ is cli.Stops
        installed(signal.SIGTERM, None)
        raise AssertionError("the handler did not end the wait")
    monkeypatch.setattr(sleep_target, "_sleep", fake_sleep)
    cls = host.HostWatch if "--host" in argv else watch.Watch
    real_finish = cls.finish

    def finish(self, *a, **kw):
        installed = signal.getsignal(signal.SIGTERM)
        if how == "SIGTERM":
            second.append(installed(signal.SIGTERM, None))   # returns: the report is not cut short
        return real_finish(self, *a, **kw)
    monkeypatch.setattr(cls, "finish", finish)
    out = io.StringIO()
    code = cli.main(argv, out=out)
    assert signal.getsignal(signal.SIGTERM) == before   # restored when the command ended
    return code, out.getvalue(), second


@pytest.mark.parametrize("how", ["SIGTERM", "Ctrl-C"])
def test_e1_watch_in_process_stops_on_the_signal_with_its_report_and_code(tmp_path, home, monkeypatch, how):
    proj = tmp_path / "proj"
    proj.mkdir()
    code, text, second = run_in_process(tmp_path, monkeypatch, ["watch", str(proj), "--no-open", "--no-notify",
                                                                "--port", "0"], watch, how)
    assert "\nraqib watch: stopped (%s)\n" % how in text
    (result,) = result_lines(text)
    assert code in (0, 1, 3) and "(exit %d" % code in result
    assert second == ([None] if how == "SIGTERM" else [])
    assert finished_rows(home) == [("finished", True)]


@pytest.mark.parametrize("how", ["SIGTERM", "Ctrl-C"])
def test_e1_watch_host_in_process_stops_on_the_signal_with_its_report_and_code(tmp_path, home, monkeypatch, how):
    import make as host_fixtures   # tests/fixtures/host (on sys.path through test_acts_judged's imports)
    catalog = cli.discover.load_catalog(cli.discover.CATALOG)
    monkeypatch.setattr(host, "live_reader", lambda c, window, platform: lambda: host_fixtures.inventory(
        "linux", catalog))
    code, text, second = run_in_process(tmp_path, monkeypatch, ["watch", "--host", "--no-open", "--no-notify",
                                                                "--port", "0"], host, how)
    assert "\nraqib watch --host: stopped (%s)\n" % how in text
    (result,) = result_lines(text)
    assert code in (0, 1, 3) and "(exit %d" % code in result
    assert second == ([None] if how == "SIGTERM" else [])
    assert finished_rows(home) == [("finished", True)]


class Recorder:
    def __init__(self, monkeypatch):
        self.calls = []
        real = signal.signal

        def record(number, handler):
            self.calls.append(number)
            return real(number, handler)
        monkeypatch.setattr(signal, "signal", record)


def test_e1_must_not_touch_raqib_app_and_a_command_with_no_final_report_install_none(tmp_path, home, monkeypatch):
    rec = Recorder(monkeypatch)
    monkeypatch.setattr(cli.window_app, "run", lambda project, options, out=None: 0)
    assert cli.main(["app", str(tmp_path)], out=io.StringIO()) == 0
    trace = write_trace(tmp_path / "t.jsonl", [line(1, phase="session_start", tool="-")])
    cli.main(["report", str(trace)], out=io.StringIO())
    assert rec.calls == []
    monkeypatch.setattr(watch, "command", lambda *a, **kw: 0)
    assert cli.main(["watch", str(tmp_path), "--no-open"], out=io.StringIO()) == 0
    assert signal.SIGTERM in rec.calls   # installed, and set back (the restore is the second call)
    assert rec.calls.count(signal.SIGTERM) == 2


def test_e1_must_not_touch_a4_the_cli_signals_no_process():
    tree = ast.parse((ROOT / "raqib" / "cli.py").read_text(encoding="ascii"))
    banned = ("kill", "killpg", "send_signal", "terminate", "raise_signal", "pthread_kill", "alarm", "setitimer",
              "GenerateConsoleCtrlEvent", "TerminateProcess")
    used = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = node.func
            called = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", None)
            assert called not in banned, called
            if isinstance(f, ast.Attribute) and ast.unparse(f.value) in ("signal", "self.signal"):
                used.add(f.attr)
    assert used == {"signal", "getsignal"}


# --- E1 with a real child process (E7) ------------------------------------------------------------------------

def child_env(home):
    env = dict(os.environ, HOME=str(home), USERPROFILE=str(home))
    env["PYTHONPATH"] = os.pathsep.join([str(ROOT)] + ([env["PYTHONPATH"]] if env.get("PYTHONPATH") else []))
    return env


def wait_for(path, proc, text, timeout=CHILD_TIMEOUT):
    """Poll the child's output until text is in it (no fixed long sleep); fail if the child ends first."""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        got = Path(path).read_text(encoding="utf-8", errors="replace") if Path(path).exists() else ""
        if text in got:
            return got
        if proc.poll() is not None:
            pytest.fail("the child ended (%s) before printing %r:\n%s" % (proc.returncode, text, got))
        time.sleep(0.05)
    pytest.fail("no %r from the child within %d s" % (text, timeout))


def stop_child(tmp_path, home, args, send, ready, name, **popen):
    """Start `python -m raqib <args>`, wait for its ready line, send() the stop once, and read what it ended
    with (REDO B-4: one signal; a second one while the report is written is tested in process)."""
    out_path = tmp_path / "child.out"
    proj_args = [str(a) for a in args]
    with open(out_path, "wb") as out:
        proc = subprocess.Popen([sys.executable, "-m", "raqib"] + proj_args, stdout=out, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL, env=child_env(home), cwd=str(tmp_path), **popen)
        try:
            wait_for(out_path, proc, ready)
            send(proc)
            code = proc.wait(timeout=CHILD_TIMEOUT)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=CHILD_TIMEOUT)
    text = out_path.read_text(encoding="utf-8", errors="replace")
    return code, text


def posix_signal_or_skip(name):
    if WINDOWS:
        pytest.skip("Windows delivers no %s from another process (send_signal there is TerminateProcess, which"
                    " stays out of reach: ADR-0010 decision 1); SIGBREAK is its stop" % name)
    number = getattr(signal, name, None)
    if number is None:
        pytest.skip("this platform has no %s" % name)
    if signal.getsignal(number) == signal.SIG_IGN:
        pytest.skip("%s is ignored in this job (nohup?): the child would inherit it and keep it ignored (Q-2)" % name)
    return number


def assert_stopped(code, text, prefix, name, home):
    assert "%s: stopped (%s)" % (prefix, name) in text, text
    results = result_lines(text)
    assert len(results) == 1, text
    assert code in (0, 1, 3) and "(exit %d" % code in results[0], (code, results)
    assert finished_rows(home) == [("finished", True)]


@pytest.mark.parametrize("name", ["SIGTERM", "SIGHUP"])
def test_e7_a_real_watch_stopped_by_a_signal_ends_with_its_report_and_code(tmp_path, home, name):
    number = posix_signal_or_skip(name)
    proj = tmp_path / "proj"
    proj.mkdir()
    code, text = stop_child(tmp_path, home, ["watch", proj, "--no-open", "--no-notify", "--port", "0"],
                            lambda p: p.send_signal(number), "raqib watch: page ", name)
    assert_stopped(code, text, "raqib watch", name, home)


@pytest.mark.parametrize("name", ["SIGTERM", "SIGHUP"])
def test_e7_a_real_host_watch_stopped_by_a_signal_ends_with_its_report_and_code(tmp_path, home, name):
    number = posix_signal_or_skip(name)
    code, text = stop_child(tmp_path, home, ["watch", "--host", "--no-open", "--no-notify", "--port", "0"],
                            lambda p: p.send_signal(number), "raqib watch --host: page ", name)
    assert_stopped(code, text, "raqib watch --host", name, home)


def windows_console_or_skip():
    if not WINDOWS:
        pytest.skip("SIGBREAK (Ctrl-Break) is Windows'")
    import ctypes
    procs = (ctypes.c_uint32 * 8)()
    if ctypes.windll.kernel32.GetConsoleProcessList(procs, 8) == 0:
        pytest.skip("this job has no console, so no Ctrl-Break can be delivered")


@pytest.mark.parametrize("args, prefix", [(["watch", "PROJ"], "raqib watch"),
                                          (["watch", "--host"], "raqib watch --host")])
def test_e7_a_real_watch_on_windows_stopped_by_ctrl_break(tmp_path, home, args, prefix):
    windows_console_or_skip()
    proj = tmp_path / "proj"
    proj.mkdir()
    argv = [str(proj) if a == "PROJ" else a for a in args] + ["--no-open", "--no-notify", "--port", "0"]

    def send(proc):
        try:
            proc.send_signal(signal.CTRL_BREAK_EVENT)
        except OSError as exc:
            pytest.skip("this job cannot deliver Ctrl-Break: %s" % exc)
    code, text = stop_child(tmp_path, home, argv, send, "%s: page " % prefix, "SIGBREAK",
                            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
    assert_stopped(code, text, prefix, "SIGBREAK", home)


# --- M9.1 REDO (ADR-0010 Amendment B, rulings B-1..B-6) ----------------------------------------------------------

class DyingOut(io.StringIO):
    """A terminal that takes the words until it is gone (dead): from then every write and every flush raises
    OSError(EIO), as a hung-up tty does."""
    dead = False
    raised = 0

    def _gone(self):
        self.raised += 1
        raise OSError(errno.EIO, os.strerror(errno.EIO))

    def write(self, text):
        if self.dead:
            self._gone()
        return super().write(text)

    def flush(self):
        if self.dead:
            self._gone()
        return super().flush()


def use_host_fixture(monkeypatch):
    import make as host_fixtures   # tests/fixtures/host
    catalog = cli.discover.load_catalog(cli.discover.CATALOG)
    monkeypatch.setattr(host, "live_reader", lambda c, window, platform: lambda: host_fixtures.inventory(
        "linux", catalog))


def stop_in_process(base, monkeypatch, kind, how, out, during_finish=None, until=None, dies="stop"):
    """`raqib watch PROJ` or `raqib watch --host` (kind) in process, under base (its own HOME and project), ended
    by how: "SIGTERM" calls the handler the CLI installed as the OS would, "Ctrl-C" raises KeyboardInterrupt.
    A DyingOut is made dead the moment the stop is asked (dies "stop"), or (dies "mid-watch", REDO 2 C-3) at
    the first wait, the watch then polling once more before the stop. Returns (code, seen): the watcher, the
    code it computed, the text out held when the registry row was marked, the stop_sources calls. until(home):
    the stop waits for it (bounded), so a host watch can apply a round first."""
    base.mkdir(parents=True, exist_ok=True)
    home, proj = base / "home", base / "proj"
    home.mkdir(exist_ok=True)
    proj.mkdir(exist_ok=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    target, cls = (host, host.HostWatch) if kind == "--host" else (watch, watch.Watch)
    argv = (["watch", "--host"] if kind == "--host" else ["watch", str(proj)]) + ["--no-open", "--no-notify",
                                                                                  "--port", "0"]
    before = signal.getsignal(signal.SIGTERM)
    seen = {"stop_sources": 0, "home": home, "base": base}

    end = time.monotonic() + CHILD_TIMEOUT
    naps = []

    def fake_sleep(seconds):
        if until is not None and not until(home) and time.monotonic() < end:
            time.sleep(0.05)
            return
        naps.append(seconds)
        if isinstance(out, DyingOut) and dies == "mid-watch" and len(naps) == 1:
            out.dead = True   # the terminal goes away while the watch runs: one more poll, then the stop
            return
        if isinstance(out, DyingOut):
            out.dead = True   # the terminal is gone as the stop is asked
        if how == "Ctrl-C":
            raise KeyboardInterrupt
        signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
        raise AssertionError("the handler did not end the wait")
    monkeypatch.setattr(target, "_sleep", fake_sleep)
    real_finish, real_unregister = cls.finish, cls.unregister

    def finish(self, *a, **kw):
        seen["watcher"] = self
        if during_finish is not None:
            during_finish(self)
        got = real_finish(self, *a, **kw)
        seen["final_exit"], seen["final_text"] = self.final_exit, self.final_text
        return got

    def unregister(self, *a, **kw):
        got = real_unregister(self, *a, **kw)
        seen["said_at_keep"] = out.getvalue()
        return got
    monkeypatch.setattr(cls, "finish", finish)
    monkeypatch.setattr(cls, "unregister", unregister)
    if kind == "--host":
        real_stop_sources = host.HostWatch.stop_sources

        def stop_sources(self, now):
            seen["stop_sources"] += 1
            return real_stop_sources(self, now)
        monkeypatch.setattr(host.HostWatch, "stop_sources", stop_sources)
        use_host_fixture(monkeypatch)
    code = cli.main(argv, out=out)
    assert signal.getsignal(signal.SIGTERM) == before   # restored when the command ended
    return code, seen


def state_of(home, kind):
    if kind == "--host":
        path = Path(host.host_dir(str(home))) / (host.ROUNDS_NAME + host.STATE_SUFFIX)
    else:
        (row,) = json.loads((Path(home) / ".raqib" / watch.REGISTRY_NAME).read_text(encoding="ascii"))["watches"]
        path = Path(row["state"])
    return json.loads(path.read_text(encoding="ascii"))


@pytest.mark.parametrize("how", ["SIGTERM", "Ctrl-C"])
@pytest.mark.parametrize("kind", ["PROJ", "--host"])
def test_b1_a_terminal_gone_at_the_stop_loses_the_words_never_the_record_or_the_code(tmp_path, monkeypatch, kind,
                                                                                       how):
    out = DyingOut()
    code, seen = stop_in_process(tmp_path / "b1", monkeypatch, kind, how, out)
    prefix = "raqib watch --host" if kind == "--host" else "raqib watch"
    assert out.dead and out.raised > 0                      # every word after the stop raised OSError(EIO)
    assert "%s: page " % prefix in out.getvalue() and "stopped (" not in out.getvalue()
    assert code in (0, 1, 3) and code == seen["final_exit"]   # Raqib's code, not 1 from a traceback
    assert finished_rows(seen["home"]) == [("finished", True)]
    state = state_of(seen["home"], kind)
    assert state["status"] == "finished" and state["finished"] is not None
    if kind == "--host":   # its sources and channel closed: stop_sources ran, no source thread is left
        assert seen["stop_sources"] == 1
        assert all(s.thread is None or not s.thread.is_alive() for s in seen["watcher"].sources.values())


class Calls(io.StringIO):
    """A terminal that takes the words and records each write in calls, in the order of the calls (REDO 2 C-1)."""

    def __init__(self, calls):
        super().__init__()
        self.calls = calls

    def write(self, text):
        self.calls.append(("write", text))
        return super().write(text)


@pytest.mark.parametrize("how", ["SIGTERM", "Ctrl-C"])
@pytest.mark.parametrize("kind", ["PROJ", "--host"])
def test_c1_stopped_reaches_the_terminal_before_the_conclusion_begins(tmp_path, monkeypatch, kind, how):
    """REDO 2 C-1 (B-1's first sentence withdrawn): the words of a stop are said as they come - "stopped (...)" is
    written before conclude() begins, as before M9.1; asserted by the order of the calls, never by a clock."""
    calls = []
    target = host if kind == "--host" else watch
    real_conclude = target.conclude

    def conclude(running, crash):
        calls.append(("conclude", None))
        return real_conclude(running, crash)
    monkeypatch.setattr(target, "conclude", conclude)
    out = Calls(calls)
    code, seen = stop_in_process(tmp_path / "c1", monkeypatch, kind, how, out,
                                 during_finish=lambda w: calls.append(("finish", None)))
    prefix = "raqib watch --host" if kind == "--host" else "raqib watch"
    stopped = ("write", "\n%s: stopped (%s)\n" % (prefix, how))
    assert calls.count(stopped) == 1 and calls.count(("conclude", None)) == 1
    begins = calls.index(("conclude", None))
    assert calls.index(stopped) < begins < calls.index(("finish", None))
    assert stopped[1] in seen["said_at_keep"]   # on the terminal before the registry row was marked
    assert calls.index(("write", "\n" + seen["final_text"])) > begins   # the report after the conclusion, as before
    assert code == seen["final_exit"] and finished_rows(seen["home"]) == [("finished", True)]


@pytest.mark.parametrize("ends", ["returned", "raised", "interrupted"])
@pytest.mark.parametrize("kind", ["PROJ", "--host"])
def test_c1_must_not_touch_close_runs_on_every_path_of_the_finally(tmp_path, monkeypatch, kind, ends):
    """REDO 2 C-1 MUST NOT TOUCH (F5): close(running) - the page server down, the notifier's files removed - runs
    whether the conclusion returns, raises, or is cut by a second Ctrl-C (which, C-6, still cuts it, as before
    M9.1). The record is kept first here, so no watch is left running."""
    target = host if kind == "--host" else watch
    closed = []
    real_close, real_conclude = target.close, target.conclude

    def close(running):
        closed.append(running)
        return real_close(running)

    def conclude(running, crash):
        got = real_conclude(running, crash)
        if ends == "raised":
            raise RuntimeError("a synthetic failure at the end of the conclusion")
        if ends == "interrupted":
            raise KeyboardInterrupt   # a second Ctrl-C while the conclusion runs
        return got
    monkeypatch.setattr(target, "close", close)
    monkeypatch.setattr(target, "conclude", conclude)
    if ends == "returned":
        code, seen = stop_in_process(tmp_path / "c1c", monkeypatch, kind, "SIGTERM", io.StringIO())
        assert code == seen["final_exit"]
    else:
        with pytest.raises(RuntimeError if ends == "raised" else KeyboardInterrupt):
            stop_in_process(tmp_path / "c1c", monkeypatch, kind, "SIGTERM", io.StringIO())
    assert len(closed) == 1
    assert closed[0].server.socket.fileno() == -1   # the page server's socket is closed


def normalised(text, base):
    """The run's own words hidden (REDO 2 C-2): base's path in every spelling the code prints - str(base)
    (backslashes on Windows) and Path(base).as_posix() (the Windows hook command's forward slashes) - and the
    separators of a path under it, the trace directory's hash of the project's path, the clock and the port."""
    for spelling in (str(base), Path(base).as_posix()):
        text = text.replace(spelling, "BASE")
    text = re.sub(r"BASE[^\s'\"();]*", lambda m: m.group(0).replace("\\", "/"), text)
    return re.sub(r"\d+", "N", re.sub(r"proj-[0-9a-f]+", "proj-H", text))


STOP_LINE = object()   # the line naming what stops the watch: the platform's own (B-3, C-5)
# REDO 2 C-2: the watch's own first lines, in their order, as the code before this REDO printed them (normalised)
FIRST_LINES = {
    "PROJ": ["raqib watch: project BASE/proj",
             "raqib watch: trace BASE/home/.raqib/traces/proj-H/raqib.log.jsonl (watch default, outside the project)",
             "raqib watch: state BASE/home/.raqib/traces/proj-H/raqib.log.jsonl.watch.json",
             "raqib watch: scope: no HANDOFF.md in the project: no scope; rules that need one do not run",
             "raqib watch: silence limit Ns (RAQIB_GAP_SECONDS); polling every N.Ns",
             "raqib watch: notifications: off (--no-notify)",
             "raqib watch: rules overlay BASE/home/.raqib/rules.yaml: none (every rule as its YAML declares it)",
             "raqib watch: rules: no rule off",
             "raqib watch: page http://N.N.N.N:N/ (read-only, reloads every N s; Ctrl-C stops the watch and prints"
             " the final report)", STOP_LINE,
             "raqib watch: registry BASE/home/.raqib/watches.json (this watch is a row; rows are never removed)",
             "raqib watch: page not opened (--no-open)"],
    "--host": ["raqib watch --host: the host, not a name (ADR-N); nothing is installed, no project is touched (no"
               " --attach-hooks)", "raqib watch --host: record BASE/home/.raqib/host/rounds.jsonl",
               "raqib watch --host: state BASE/home/.raqib/host/rounds.jsonl.watch.json",
               "raqib watch --host: notifications: off (--no-notify)",
               "raqib watch --host: suspect: off (no --suspect): no model is asked, nothing leaves the machine",
               "raqib watch --host: rules overlay BASE/home/.raqib/rules.yaml: none (every rule as its YAML declares"
               " it)", "raqib watch --host: rules: no rule off",
               "raqib watch --host: page http://N.N.N.N:N/ (read-only, reloads every N s; Ctrl-C ends the watch)",
               STOP_LINE, "raqib watch --host: page not opened (--no-open)"]}
# ... and the report's own lines (not indented), through RESULT: the project watch's all, the host watch's
# headings that every platform prints (its report says the platform's own words beside them)
REPORT_LINES = {
    "PROJ": ["Raqib watch", "project: BASE/proj", "trace: BASE/home/.raqib/traces/proj-H/raqib.log.jsonl",
             "state: BASE/home/.raqib/traces/proj-H/raqib.log.jsonl.watch.json (finished)",
             "scope: no HANDOFF.md in the project: no scope; rules that need one do not run",
             "watched: N-N-NTN:N:N.NZ to N-N-NTN:N:N.NZ; N lines read in this trace content; N trace resets",
             "LIVE SILENCE WINDOWS (A3, limit Ns): N", "HOLES (A3): N",
             "PRIOR FINDINGS (history, in the trace at the start, not knocked): N",
             "FINDINGS SEEN LIVE: N settled, N pending at exit",
             "RULES OFF (ADR-N; they do not change the exit code, and the watch is not clean of what they would"
             " have found): N",
             "RULES OVERLAY: rules overlay BASE/home/.raqib/rules.yaml: none (every rule as its YAML declares it)",
             "NOTIFICATIONS: off (--no-notify); sent N, terminal N, failed N, folded N (N still waiting), off N",
             "Raqib report", "trace: BASE/home/.raqib/traces/proj-H/raqib.log.jsonl (N records, N sessions)",
             "findings: raqib watch: the rules re-run on the trace as it grows", "ALARMS (A3, A5): N", "FINDINGS: N",
             "SUSPICION (model, raises only, A2): N", "RULES THAT DID NOT RUN: N", "RULES (A6 fp_budget): N",
             "RESULT: ALARM (exit N)"],
    "--host": ["Raqib watch --host (ADR-N): the host, not a name",
               "state: BASE/home/.raqib/host/rounds.jsonl.watch.json (finished)",
               "record: BASE/home/.raqib/host/rounds.jsonl; latest inventory: BASE/home/.raqib/host/inventory.json",
               "ROUNDS", "TREES SEEN", "FINDINGS", "SUSPICION", "RHYTHM BEATS",
               "SOURCE FINDINGS", "NOT SETTLED", "ON BENIGN TREES", "HOOKS", "SYSMON", "FOOTPRINTS",
               "DARK AFTER A LIVE TREE", "NOTES", "HOLES", "BLIND SPOTS", "KNOCKS", "NOTIFICATIONS", "RESULT"]}


def in_order(wanted, rows, same):
    """The rows that match wanted's entries, one each, in wanted's order (other rows may sit between)."""
    got, k = [], 0
    for want in wanted:
        while k < len(rows) and not same(want, rows[k]):
            k += 1
        got.append(rows[k] if k < len(rows) else None)
        k += 1
    return got


@pytest.mark.parametrize("kind", ["PROJ", "--host"])
def test_b1_must_not_touch_a_terminal_that_takes_the_words_gets_them_as_before_in_their_order(tmp_path, monkeypatch,
                                                                                               kind):
    """B-1 MUST NOT TOUCH, rebuilt on its purpose (REDO 2 C-2): a terminal that takes the words gets the words the
    code before this REDO printed, in their order - the first lines, then "stopped (...)", a word said while the
    record is kept, and the final report's lines through RESULT. Paths are hidden in both spellings."""
    def word(w):
        w._say(w.clock(), "a word said while finishing")
    out = io.StringIO()
    base = tmp_path / "words"
    code, seen = stop_in_process(base, monkeypatch, kind, "SIGTERM", out, during_finish=word)
    prefix = "raqib watch --host" if kind == "--host" else "raqib watch"
    rows = out.getvalue().split("\n")
    i = rows.index("%s: stopped (SIGTERM)" % prefix)
    # the stop's lines: exactly these, in this order, and nothing after the report's RESULT line
    assert rows[i - 1] == "" and re.fullmatch(r"\[\d\d:\d\d:\d\dZ\] a word said while finishing", rows[i + 1])
    assert rows[i + 2] == "" and "\n".join(rows[i + 3:]) == seen["final_text"]
    report_rows = seen["final_text"].splitlines()
    assert report_rows[-1].startswith("RESULT: ") and len(result_lines(out.getvalue())) == 1
    assert code == seen["final_exit"]
    plain = [normalised(r, seen["base"]) for r in report_rows if r and not r.startswith(" ")]
    pinned = [w if w is STOP_LINE else normalised(w, seen["base"]) for w in REPORT_LINES[kind]]   # "A3": "AN" too
    if kind == "PROJ":
        assert plain == pinned
    else:
        same = (lambda w, r: r == w or r.startswith(w + ":") or r.startswith(w + " ("))
        assert None not in in_order(pinned, plain, same), plain
    # the first lines: the watch's own, in their order, before the stop
    own = [normalised(r, seen["base"]) for r in rows[:i] if r.startswith(prefix + ": ")]
    first = [w if w is STOP_LINE else normalised(w, seen["base"]) for w in FIRST_LINES[kind]]
    found = in_order(first, own, lambda w, r: (r.startswith(prefix + ": ") and (
        "stop it with its final report and code" in r)) if w is STOP_LINE else r == w)
    assert None not in found, (found, own)
    if kind == "PROJ":   # the hook command names the trace (forward slashes on Windows): hidden in that spelling too
        trace = "BASE/home/.raqib/traces/proj-H/raqib.log.jsonl"
        (command,) = [r for r in rows[:i] if r.lstrip().startswith("command: ")]
        assert trace in normalised(command, seen["base"])


def read_until(fd, proc, text, timeout=CHILD_TIMEOUT):
    """POSIX: read the child's output from fd (a pipe or a pty) until text is in it; bounded, never blocking."""
    import select
    got, end = b"", time.monotonic() + timeout
    while time.monotonic() < end:
        ready, _, _ = select.select([fd], [], [], 0.1)
        if ready:
            try:
                chunk = os.read(fd, 65536)
            except OSError:   # a pty whose other side is gone
                chunk = b""
            if not chunk:
                pytest.fail("the child's output ended (%s) before %r:\n%r" % (proc.poll(), text, got))
            got += chunk
            if text.encode("ascii") in got:
                return got
        elif proc.poll() is not None:
            pytest.fail("the child ended (%s) before printing %r:\n%r" % (proc.returncode, text, got))
    pytest.fail("no %r from the child within %d s" % (text, timeout))


def child_argv(kind, proj):
    return [sys.executable, "-m", "raqib", "watch"] + (["--host"] if kind == "--host" else [str(proj)]) + [
        "--no-open", "--no-notify", "--port", "0"]


def assert_kept(code, home, kind):
    assert code in (0, 1, 3), code   # Raqib's code: not 1 from a traceback, not 120 from the last flush
    assert finished_rows(home) == [("finished", True)]
    state = state_of(home, kind)
    assert state["status"] == "finished" and state["finished"] is not None


@pytest.mark.parametrize("buffered", [True, False], ids=["block-buffered", "unbuffered"])
@pytest.mark.parametrize("kind", ["PROJ", "--host"])
def test_b1_a_real_watch_whose_output_pipe_is_closed_before_the_sighup_keeps_its_record_and_code(tmp_path, home,
                                                                                                 kind, buffered):
    number = posix_signal_or_skip("SIGHUP")
    proj = tmp_path / "proj"
    proj.mkdir()
    env = child_env(home)
    if not buffered:
        env["PYTHONUNBUFFERED"] = "1"   # every write goes out at once, as to a terminal: the "stopped" line raises
    prefix = "raqib watch --host" if kind == "--host" else "raqib watch"
    proc = subprocess.Popen(child_argv(kind, proj), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            stdin=subprocess.DEVNULL, env=env, cwd=str(tmp_path))
    try:
        read_until(proc.stdout.fileno(), proc, "%s: page " % prefix)
        proc.stdout.close()   # the read end: every later write of the child fails (EPIPE)
        proc.send_signal(number)
        code = proc.wait(timeout=CHILD_TIMEOUT)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=CHILD_TIMEOUT)
        if not proc.stdout.closed:
            proc.stdout.close()
    assert_kept(code, home, kind)


@pytest.mark.parametrize("kind", ["PROJ", "--host"])
def test_b1_a_real_watch_on_a_terminal_that_hangs_up_keeps_its_record_and_code(tmp_path, home, kind):
    number = posix_signal_or_skip("SIGHUP")
    if not hasattr(os, "openpty"):
        pytest.skip("this platform has no os.openpty, so no terminal can be hung up here")
    proj = tmp_path / "proj"
    proj.mkdir()
    prefix = "raqib watch --host" if kind == "--host" else "raqib watch"
    master, slave = os.openpty()
    try:
        proc = subprocess.Popen(child_argv(kind, proj), stdout=slave, stderr=slave, stdin=subprocess.DEVNULL,
                                env=child_env(home), cwd=str(tmp_path))
    except BaseException:
        os.close(master)
        raise
    finally:
        os.close(slave)
    try:
        read_until(master, proc, "%s: page " % prefix)
        os.close(master)   # the terminal is closed: the child's writes now fail (EIO), as in D1's case
        master = None
        proc.send_signal(number)
        code = proc.wait(timeout=CHILD_TIMEOUT)
    finally:
        if master is not None:
            os.close(master)
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=CHILD_TIMEOUT)
    assert_kept(code, home, kind)


def test_b1_must_not_touch_a_live_stdout_is_left_as_it_is_and_a_dead_one_points_at_devnull(monkeypatch):
    live = io.StringIO()
    monkeypatch.setattr(sys, "stdout", live)
    assert cli._quiet_if_dead("stdout") is False and sys.stdout is live
    dead = DyingOut()
    dead.dead = True
    monkeypatch.setattr(sys, "stdout", dead)   # no descriptor to point: the stream is replaced by os.devnull
    assert cli._quiet_if_dead("stdout") is True and sys.stdout is not dead
    try:
        sys.stdout.write("lost\n")
        sys.stdout.flush()
    finally:
        sys.stdout.close()


def test_b2_readme_and_help_say_what_a_killed_watch_leaves_per_watch():
    state = "~/.raqib/host/%s%s" % (host.ROUNDS_NAME, host.STATE_SUFFIX)
    record = "~/.raqib/host/%s" % host.ROUNDS_NAME
    assert host.host_dir("~").replace("\\", "/") == "~/.raqib/host"
    flat = " ".join(cut("Watch a project", GUIDE).split())   # M9.2: docs/GUIDE.md
    for phrase in ("A watch ended that way prints nothing.",
                   "For a watch that printed nothing: for `raqib watch PROJECT`, `raqib report <trace>` gives the"
                   " findings.",
                   "For `raqib watch --host`, no command re-prints its report: what it had found up to its last round"
                   " is in its state file `%s`" % state, "and its record `%s` (one line per round" % record,
                   "`code_so_far`"):
        assert phrase in flat, phrase
    helped = " ".join(cli.__doc__.split())
    for phrase in ("for watch PROJECT, `raqib report TRACE` gives the findings; for watch --host no command re-prints"
                   " its report: what it had found up to its last round is in its state file %s" % state,
                   "and its record %s (one line per round)" % record):
        assert phrase in helped, phrase


def test_b2_the_host_state_and_record_hold_what_the_sentence_says(tmp_path, monkeypatch):
    def a_round(home):
        rounds = Path(host.host_dir(str(home))) / host.ROUNDS_NAME
        return rounds.exists() and rounds.stat().st_size > 0
    code, seen = stop_in_process(tmp_path / "b2", monkeypatch, "--host", "Ctrl-C", io.StringIO(), until=a_round)
    d = Path(host.host_dir(str(seen["home"])))
    w = seen["watcher"]
    assert Path(w.state_path) == d / (host.ROUNDS_NAME + host.STATE_SUFFIX) and Path(w.rounds_path) == d / host.ROUNDS_NAME
    state = json.loads(Path(w.state_path).read_text(encoding="ascii"))
    assert {"findings", "knocks", "source_findings"} <= set(state["host"])     # its findings and knocks
    assert {"holes", "heartbeat", "code_so_far"} <= set(state)                 # its holes, heartbeat, code so far
    rounds = [json.loads(x) for x in Path(w.rounds_path).read_text(encoding="ascii").splitlines() if x.strip()]
    assert rounds and all({"round", "holes", "lines"} <= set(r) for r in rounds)   # one line per round
    # no command re-prints its report: `raqib report` reads a trace, and finds none of the host watch's findings
    found = {f["rule_id"] for f in state["host"]["findings"]}
    rep = json.loads(cli_text(["report", w.rounds_path, "--json"]))
    assert not found & {f["rule_id"] for f in rep["findings"]}
    assert "raqib watch --host" not in cli_text(["report", w.rounds_path])


def cli_text(argv):
    out = io.StringIO()
    cli.main(argv, out=out)
    return out.getvalue()


def test_b3_readme_names_every_case_out_of_reach_and_the_ignored_signal():
    flat = " ".join(cut("Watch a project", GUIDE).split())   # M9.2: docs/GUIDE.md
    for phrase in ("Out of reach are SIGKILL and, on Windows, TerminateProcess (`taskkill /F`, the Task Manager) and"
                   " closing the console window, logoff and shutdown, which end the process before its report"
                   " (Ctrl-Break is what stops it there).",
                   "a signal already ignored when it started (`nohup`) stays ignored",
                   "The watch's first lines say which signals stop it and which were left ignored"):
        assert phrase in flat, phrase


NOHUP_WORDS = "left ignored (ignored when it started, as under nohup): "


def test_b3_the_stop_line_says_what_stops_it_and_what_was_left_ignored():
    stops = cli.Stops(FakeSignals(), platform="linux")   # REDO 2 C-5: the platform passed in, on every system
    stops.install()
    assert stops.line() == "Ctrl-C, SIGHUP, SIGTERM stop it with its final report and code; %snone" % NOHUP_WORDS
    one = cli.Stops(FakeSignals(ignored=("SIGHUP",)), platform="linux")
    one.install()
    assert one.line() == "Ctrl-C, SIGTERM stop it with its final report and code; %sSIGHUP" % NOHUP_WORDS
    win = cli.Stops(FakeSignals(names=("SIGTERM", "SIGBREAK")), platform="win32")   # Windows: SIGBREAK, no SIGHUP
    win.install()
    said = win.line()
    assert said == "Ctrl-C, SIGBREAK (Ctrl-Break) stop it with its final report and code; %snone" % NOHUP_WORDS
    win.restore()
    assert win.line() == said   # what the first lines said stays true of the watch after the restore
    sigint = FakeSignals()
    sigint.SIGINT = 2
    sigint.handlers[2] = sigint.SIG_IGN   # started with SIGINT ignored (a shell's `&`): Ctrl-C does nothing
    off = cli.Stops(sigint, platform="linux")
    off.install()
    assert off.line() == "SIGHUP, SIGTERM stop it with its final report and code; %sCtrl-C (SIGINT)" % NOHUP_WORDS


@pytest.mark.parametrize("ignore", [False, True], ids=["nothing-ignored", "one-ignored"])
@pytest.mark.parametrize("kind", ["PROJ", "--host"])
def test_b3_the_watch_s_first_lines_say_which_signals_stop_it(tmp_path, monkeypatch, kind, ignore):
    name = "SIGHUP" if hasattr(signal, "SIGHUP") else "SIGBREAK"
    number = getattr(signal, name)
    earlier = signal.getsignal(number)
    if earlier == signal.SIG_IGN and not ignore:
        pytest.skip("%s is ignored in this job already (nohup?)" % name)
    prefix = "raqib watch --host" if kind == "--host" else "raqib watch"
    out = io.StringIO()
    if ignore:
        signal.signal(number, signal.SIG_IGN)
    try:
        stop_in_process(tmp_path / "b3", monkeypatch, kind, "Ctrl-C", out)
        assert signal.getsignal(number) == (signal.SIG_IGN if ignore else earlier)   # left as it was
    finally:
        signal.signal(number, earlier)
    rows = out.getvalue().splitlines()
    (said,) = [r for r in rows if "stop it with its final report and code" in r or
               "stops it with its final report and code" in r]
    assert said.startswith(prefix + ": ") and rows.index(said) < rows.index("%s: stopped (Ctrl-C)" % prefix)
    shown = rows.index(said) - 1
    assert rows[shown].startswith(prefix + ": page ")   # among the first lines, under the page's own
    stop_part = said.split(";")[0]
    if ignore:
        assert said.endswith(NOHUP_WORDS + name) and name not in stop_part
    else:
        assert said.endswith(NOHUP_WORDS + "none") and name in stop_part


def test_b5_the_line_under_alarms_counts_the_watch_s_own_alarms_too(tmp_path, monkeypatch):
    def broken(self, *a, **kw):
        raise RuntimeError("a synthetic failure of the watch")
    monkeypatch.setattr(watch.Watch, "step", broken)
    out = io.StringIO()
    code, seen = stop_in_process(tmp_path / "b5", monkeypatch, "PROJ", "Ctrl-C", out)
    rows = out.getvalue().splitlines()
    (i,) = [k for k, r in enumerate(rows) if r.startswith("ALARMS (A3, A5): ")]
    assert int(rows[i].rsplit(" ", 1)[1]) >= 1 and rows[i + 1:i + 3] == list(report.ALARMS_SAYS)
    assert any("crash" in r for r in rows[i + 3:i + 3 + int(rows[i].rsplit(" ", 1)[1])])   # the watch's own
    assert code == 1 and all(len(x) <= 120 for x in report.ALARMS_SAYS)


OLD_PROGRAM = ("{tool} runs a watched program at seq {seq} (program {input_meta.command_head}, programs"
               " {input_meta.command_programs}, image {input_meta.image})")


def form(rid="MY-PROGRAM", values="terraform, tofu"):
    return {"id": rid, "when": "program", "values": values, "severity": "high", "fires": "terraform", "quiet": "ls"}


def test_b6_a_program_rule_from_the_form_names_the_matched_program(home):
    built = ruleform.build(form())
    assert "program {matched:input_meta.command_programs,input_meta.image,input_meta.command_head}" in built.yaml
    rule = engine.compile_rule(built.doc, "<form>")
    (f,) = engine.run_rule(rule, [line(2, command_head="env", command_programs=["env", "terraform"])])
    assert f["summary"] == ('Bash runs a watched program at seq 2 (program terraform, programs ["env", "terraform"],'
                            ' image -)')
    head = engine.run_rule(rule, [line(3, command_head="tofu")])[0]["summary"]
    assert "(program tofu," in head
    osl = dict(line(4, tool="process", image="tofu"), source="os")
    assert "(program tofu," in engine.run_rule(rule, [osl])[0]["summary"]
    child = dict(line(6, tool="HostChild", command_programs=["sh", "terraform"], pid=4206, round=1), source="host",
                 cwd="host")   # REDO 2 C-5: a host watch's line names the matched child, not the tree's first
    (hc,) = engine.run_rule(rule, [child])
    assert hc["summary"] == ('HostChild runs a watched program at seq 6 (program terraform, programs ["sh",'
                             ' "terraform"], image -)')
    assert engine.run_rule(rule, [line(5, command_head="env", command_programs=["env", "ls"])]) == []
    assert ruleform.add(form(), str(home)).ok   # its own fixtures pass the engine and the overlay


def test_b6_must_not_touch_the_other_three_forms_and_a_rule_already_in_rules_d(home, monkeypatch):
    assert ruleform.SUMMARIES["path"] == "{tool} touches {input_meta.path} at seq {seq}"
    assert ruleform.SUMMARIES["host"] == "{tool} reaches {input_meta.url_host} at seq {seq}"
    assert ruleform.SUMMARIES["tool"] == "{tool} is used at seq {seq}"
    with monkeypatch.context() as m:   # a person's rule added before this ruling, in its old words
        m.setitem(ruleform.SUMMARIES, "program", OLD_PROGRAM)
        assert ruleform.add(form("MY-OLD"), str(home)).ok
    (old,) = [p for p in Path(overlay.user_dir(str(home))).rglob("*.yaml") if "MY-OLD" in p.read_text("utf-8")]
    kept = old.read_bytes()
    assert ruleform.add(form("MY-NEW"), str(home)).ok
    assert old.read_bytes() == kept and b"program {input_meta.command_head}" in kept   # not rewritten


# --- M9.1 REDO 2 (ADR-0010 Amendment C, rulings C-1..C-5) ---------------------------------------------------------

def test_c1_readme_and_help_drop_the_sentence_about_the_order():
    flat = " ".join(cut("Watch a project", GUIDE).split())   # M9.2: docs/GUIDE.md
    helped = " ".join(cli.__doc__.split())
    for text in (flat, helped):
        assert "is written before what it prints" not in text and "What a stop keeps" not in text
        assert "loses the words only, never the record or the code" in text   # B-1's own case, still said
    top = flat_text(readme_section("Watch a project"))   # M9.2: and the part of the section README keeps
    assert "is written before what it prints" not in top and "What a stop keeps" not in top
    assert not hasattr(watch.Speech, "hold") and not hasattr(watch.Speech, "release")
    for target in (watch, host):
        src = (ROOT / "raqib" / (target.__name__.rsplit(".", 1)[1] + ".py")).read_text(encoding="ascii")
        assert "on_stop" not in src and ".hold(" not in src


LOST_AT = "2026-11-11T10:00:00Z"
LOST_WALL = 1794391200.0   # LOST_AT as seconds since the epoch


def eio_words():
    return "OSError: %s" % OSError(errno.EIO, os.strerror(errno.EIO))


def test_c3_the_guard_keeps_the_first_failure_and_counts_every_lost_write():
    import datetime
    assert datetime.datetime.fromtimestamp(LOST_WALL, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") == LOST_AT
    out, err = DyingOut(), DyingOut()
    speech = watch.Speech(out, err, wall=lambda: LOST_WALL)
    speech.out.write("taken\n")
    speech.out.flush()
    assert speech.note() is None and speech.lost == 0 and out.getvalue() == "taken\n"
    err.dead = True
    assert speech.err.write("lost\n") == len("lost\n")   # never raised
    speech.err.flush()
    out.dead = True
    speech.out.write("lost too\n")
    assert speech.lost == 3 and speech.first["stream"] == "stderr"   # the first failure is kept, every one counted
    assert speech.note() == "3 writes to the terminal were lost since %s: stderr: %s" % (LOST_AT, eio_words())
    assert watch.lost_note(speech.out) == watch.lost_note(speech.err) == speech.note()
    closed = io.StringIO()
    closed.close()
    with pytest.raises(ValueError) as why:   # a closed stream's own words
        closed.write("x")
    one = watch.Speech(closed, io.StringIO(), wall=lambda: LOST_WALL)
    one.out.write("x")
    assert one.note() == "1 write to the terminal was lost since %s: stdout: ValueError: %s" % (LOST_AT, why.value)
    assert watch.lost_note(io.StringIO()) is None and watch.lost_note(None) is None   # not a terminal watch


def lost_notes(texts):
    return [t for t in texts if re.search(r"\d+ writes? to the terminal (was|were) lost since ", t)]


def registry_row(home):
    (row,) = json.loads((Path(home) / ".raqib" / watch.REGISTRY_NAME).read_text(encoding="ascii"))["watches"]
    return row


@pytest.mark.parametrize("kind", ["PROJ", "--host"])
def test_c3_a_terminal_that_fails_from_mid_watch_is_noted_in_the_state_the_row_and_the_report(tmp_path, monkeypatch,
                                                                                            kind):
    """REDO 2 C-3 FOR: the terminal goes away while the watch runs; the state file and the registry row carry one
    note with the count, the first failure's time, stream and words; the terminal is back for the conclusion, so
    the final report says it, once. A note, never a hole: the code is the watch's own."""
    out, lost = DyingOut(), []

    def back(w):   # the terminal takes words again: what was lost is counted now
        out.dead = False
        lost.append(out.raised)
    code, seen = stop_in_process(tmp_path / "c3", monkeypatch, kind, "SIGTERM", out, during_finish=back,
                                 dies="mid-watch")
    (n,) = lost
    assert n >= 1 and out.raised == n   # the "stopped" line at least; nothing failed after the terminal came back
    pattern = r"%d %s to the terminal %s lost since \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ: stdout: %s\Z" % (
        n, "write" if n == 1 else "writes", "was" if n == 1 else "were", re.escape(eio_words()))
    state = state_of(seen["home"], kind)
    notes = state["notes"] if kind == "PROJ" else state["host"]["notes"]
    (note,) = lost_notes(notes)
    assert re.fullmatch(pattern, note), note
    assert lost_notes(registry_row(seen["home"])["notes"]) == [note]
    assert out.getvalue().count(note) == 1 and seen["final_text"].count(note) == 1   # the final report says it once
    assert not lost_notes(json.dumps(h) for h in state["holes"])   # not a hole
    assert code == seen["final_exit"] and finished_rows(seen["home"]) == [("finished", True)]


@pytest.mark.parametrize("kind", ["PROJ", "--host"])
def test_c3_must_not_touch_a_watch_that_lost_nothing_has_no_such_note(tmp_path, monkeypatch, kind):
    out = io.StringIO()
    code, seen = stop_in_process(tmp_path / "c3n", monkeypatch, kind, "SIGTERM", out)
    state = state_of(seen["home"], kind)
    if kind == "PROJ":
        assert "notes" not in state   # its state as before: no key added
    else:
        assert state["host"]["notes"] == seen["watcher"].notes   # the run's own notes, nothing added
    assert registry_row(seen["home"])["notes"] == []
    assert not lost_notes(out.getvalue().splitlines()) and code == seen["final_exit"]


def test_c3_readme_says_the_note_and_what_it_does_not_yet_do():
    flat = " ".join(cut("Watch a project", GUIDE).split())   # M9.2: docs/GUIDE.md
    for phrase in ("the watch's state file and its registry row carry one note of the writes that were lost (how many up"
                   " to the moment the record was kept, since when, on which stream and why), and the final report says it if it"
                   " can still be printed.",
                   "Not yet done (M9.4): a knock whose only road is the terminal's bell, rung on a terminal that is"
                   " gone, is still recorded as delivered (\"terminal\"), not as a failed knock."):
        assert phrase in flat, phrase


def test_c4_a_silence_window_and_a_crash_are_each_counted_under_the_alarms_line(tmp_path, monkeypatch):
    real_step, steps = watch.Watch.step, []

    def step(self, now=None):
        steps.append(now)
        if len(steps) == 1:   # no line for more than the limit: a live silence window opens
            return real_step(self, now=self.clock() + self.gap + 1)
        raise RuntimeError("a synthetic failure of the watch")
    monkeypatch.setattr(watch.Watch, "step", step)
    out = io.StringIO()
    code, seen = stop_in_process(tmp_path / "c4", monkeypatch, "PROJ", "Ctrl-C", out, until=lambda home: len(steps) > 1)
    rows = out.getvalue().splitlines()
    (i,) = [k for k, r in enumerate(rows) if r.startswith("ALARMS (A3, A5): ")]
    n = int(rows[i].rsplit(" ", 1)[1])
    assert rows[i + 1:i + 3] == list(report.ALARMS_SAYS) and rows[i + 3 + n] == ""
    kinds = [r.split(":", 1)[0] for r in rows[i + 3:i + 3 + n]]
    assert "  - silence-window" in kinds and "  - watch-crashed" in kinds   # each counted under the line
    assert "silence" in rows[i + 1] and "a crash of the watch" in rows[i + 1]   # and named by it
    assert code == 1 and "stopped (" not in out.getvalue()


def test_c5_on_windows_the_stop_line_names_ctrl_c_and_ctrl_break_only():
    fake = FakeSignals(names=("SIGTERM", "SIGBREAK"))
    win = cli.Stops(fake, platform="win32")
    assert win.install() == ["SIGBREAK", "SIGTERM"] and fake.handlers[15] == win.handler   # SIGTERM's stays installed
    assert win.line() == "Ctrl-C, SIGBREAK (Ctrl-Break) stop it with its final report and code; %snone" % NOHUP_WORDS
    off = cli.Stops(FakeSignals(names=("SIGTERM", "SIGBREAK"), ignored=("SIGTERM",)), platform="win32")
    off.install()
    assert off.line() == "Ctrl-C, SIGBREAK (Ctrl-Break) stop it with its final report and code; %snone" % NOHUP_WORDS
    # MUST NOT TOUCH: elsewhere SIGTERM reaches the watch, and the line names it; the default is this system's
    posix = cli.Stops(FakeSignals(names=("SIGTERM", "SIGBREAK")), platform="linux")
    posix.install()
    assert posix.line() == ("Ctrl-C, SIGBREAK (Ctrl-Break), SIGTERM stop it with its final report and code; %snone"
                            % NOHUP_WORDS)
    assert cli.Stops(FakeSignals()).platform == sys.platform


def test_c5_readme_names_a_terminal_that_stops_reading_and_the_newest_knocks():
    flat = " ".join(cut("Watch a project", GUIDE).split())   # M9.2: docs/GUIDE.md
    # ADR-0010 D-2 (G3): a terminal that stops reading is not "a watch that prints nothing": it prints when it drains
    assert ("A terminal that stops reading (Ctrl-S, a full pipe) is another matter: the stop waits until it drains,"
            " and then says its words." in flat)
    assert flat.index("A watch ended that way prints nothing.") < flat.index("A terminal that stops reading")
    assert "(written every tick: its findings, holes, its newest knocks and heartbeat," in flat
    assert host.KNOCKS_KEPT > 0   # the state keeps the newest KNOCKS_KEPT knocks and counts the older
    helped = " ".join(cli.__doc__.split())
    assert "a terminal that stops reading (Ctrl-S, a full pipe): the stop waits until it drains, and then says" in helped
    assert "its newest knocks" in helped
