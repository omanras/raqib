"""The rig's reader (ADR-0012): reads what `raqib watch --host` printed while the stand-in agent worked, beside
what the stand-in says it did, and states each expectation as MET, MISSED or OPEN (a gap already recorded, with
its task). Every expectation names the field run that taught it. Stdlib only; it reads text and writes text.

    python tools/rig/check.py --report WATCH.out --workload WORKLOAD.out [--sources DIR] [--exit-code N]
                              [--platform win32|linux] [--sysmon] [--events FILE] [--forward FACTS.json]
                              [--service FACTS.json] [--procevents FACTS.json] [--autostart FACTS.json]
                              [--summary FILE] [--strict]

--events: the watch's events file (~/.raqib/host/events.jsonl, ADR-0011 F-9); every line is checked with
raqib's own event.check where raqib can be imported (the rig installs it), else by the event's shape here.
--forward: what tools/rig/forward_run.py saw `raqib forward` do with that file (ADR-0011 J-14): X19 to X22
over HTTP, X23 to X25 over syslog (J-6), X26 to the journal (W-8, Linux; not run elsewhere), X27 to the Windows
event log (Y-7, Windows; not run elsewhere).
--service: what tools/rig/service_run.py saw `raqib service` do as root on the Linux machine (ADR-0013 A-9): X28
an install from a place a user can write is refused, X29 an install from root's own place gives an active unit
that sees a second user's stand-in agent, X30 the removal leaves no unit (n/a where it was not run, AA-4).
--procevents: what tools/rig/procevents_run.py saw the reader of Linux's process events give (ADR-0007 BQ-2, BR-7):
X31 every short act that ran is given with its program, its parent (the run's own process) and its end's code, and
nothing is lost (n/a off Linux, or where the start was refused for want of a right of this user, EPERM or EACCES;
any other refusal is MISSED, the refusal said).
X35 (ADR-0007 BU-5, BW-7; read from --report and --workload, Linux; n/a elsewhere): the watch's report holds its
PROCESS EVENTS section, every round asked was answered, no helper was started again, nothing was lost, and the
processes that began are at least the children the stand-in said it started (its "start" lines; a floor: the
count holds every process of the machine); MISSED otherwise, or where it says a refusal (X31's rule: n/a where
the refusal names a right this user lacks, EPERM or EACCES).

The rules of behaviour (ADR-0014): the stand-in leaves a file in its user's Startup folder, reaches port 22 of
this machine's own address and sets a value under its user's Run key (Windows; each harmless, each undone), and
says each in a WORKLOAD line: X32 PERSIST-AUTOSTART, X33 NET-ADMIN-PORT, X34 PERSIST-RUN-KEY name its tree
(n/a where there is no os source, or where the stand-in did not do the act); each is MISSED where the act was done
and no finding names its tree (X34 too, since its rule landed: ADR-0014 AC-8).
--autostart: what tools/rig/autostart_run.py saw raqib.autostart's reads give beside the stand-in (ADR-0014 AG-4):
X37 the stand-in's Run value, its Startup file and its service are each an `added` change and later a `removed`
one; MISSED otherwise (facts missing, not run on Windows, an error); n/a off Windows.

Exit 0; with --strict, 1 when an expectation is MISSED (OPEN never fails)."""
import argparse
import hashlib
import json
import os
import re
import sys

MET, MISSED, OPEN, SKIP = "MET", "MISSED", "OPEN", "n/a"
EXIT_OF = {"ALARM": 1, "CLEAN": 0, "INCOMPLETE": 3, "NONE-SEEN": 0}


def section(lines, head):
    """The report's lines from the one that starts with `head` up to the next line that is not indented."""
    for i, line in enumerate(lines):
        if line.startswith(head):
            out = [line]
            for more in lines[i + 1:]:
                if not more.startswith(" "):
                    break
                out.append(more)
            return out
    return []


def first(lines, head):
    return next((x for x in lines if x.startswith(head)), None)


def number(pattern, text, default=None):
    m = re.search(pattern, text or "")
    return int(m.group(1)) if m else default


def _checker():
    """raqib's event.check (the contract, docs/specs/EVENT.md) where raqib can be imported; else the shape."""
    try:
        from raqib import event
        return event.check
    except ImportError:
        root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        sys.path.insert(0, root)
        try:
            from raqib import event
            return event.check
        except ImportError:
            return lambda e: [] if isinstance(e, dict) and e.get("schema") == "raqib-event/1" and isinstance(
                e.get("kind"), str) and isinstance(e.get("n"), int) else ["event: not a raqib-event/1 event"]


def read_events(events, lines, code):
    """X16-X18 (ADR-0011 F-9): the watch's events file beside its report."""
    out = []
    if events is None:
        why = "the rig gave no events file"
        return [("X16 every line of the events file is an event", SKIP, why),
                ("X17 the events have a start and an end (and a heartbeat where the watch outlasted a beat)", SKIP, why),
                ("X18 an event for each finding the report lists", SKIP, why)]
    check = _checker()
    evs, bad = [], []
    for i, raw in enumerate(events.splitlines(), 1):
        try:
            e = json.loads(raw)
        except ValueError:
            bad.append("line %d: not JSON" % i)
            continue
        problems = check(e)
        if problems:
            bad.append("line %d: %s" % (i, problems[0]))
        else:
            evs.append(e)
    out.append(("X16 every line of the events file is an event", MET if evs and not bad else MISSED,
                "%d event(s)%s" % (len(evs), "; " + "; ".join(bad[:3]) if bad else "" if evs else
                                   ": the file is missing or empty (silence is a finding)")))
    start = evs[0] if evs and evs[0].get("kind") == "watch" and evs[0].get("state") == "start" else None
    end = evs[-1] if evs and evs[-1].get("kind") == "watch" and evs[-1].get("state") == "end" else None
    beats = sum(1 for e in evs if e.get("kind") == "heartbeat")
    every = re.search(r"^EVENTS: .*one every ([\d.]+) s", "\n".join(lines), re.M)
    outlasted = False
    if start and end and every:
        import datetime
        t = [datetime.datetime.strptime(e["time"][:-1], "%Y-%m-%dT%H:%M:%S.%f") for e in (start, end)]
        outlasted = (t[1] - t[0]).total_seconds() > 2 * float(every.group(1))
    ok = bool(start and end and (code is None or (end.get("result") or {}).get("exit") == code)
              and (beats or not outlasted))
    out.append(("X17 the events have a start and an end (and a heartbeat where the watch outlasted a beat)",
                MET if ok else MISSED, "start %s, end %s (exit %s; the report's %s), %d heartbeat(s)" % (
                    "yes" if start else "no", "yes" if end else "no", (end or {}).get("result", {}).get("exit"),
                    code, beats)))
    # X18 (G-1): things, not counts. Of the report's run only, the events that are alarms' own things (a finding;
    # a source finding not folded as one act with another, evidence.same_as), each by its last rev: every finding
    # and every listed source finding has its event, and no event of the run is a listed thing the report lacks
    text = "\n".join(lines)
    run = re.search(r"(?m)^run: (\S+) \(seqs", text)
    last = {}
    for e in evs:
        if e.get("kind") in ("finding", "source-finding") and (run is None or (e.get("watch") or {}).get(
                "run") == run.group(1)):
            last[((e.get("watch") or {}).get("run"), e.get("about"))] = e   # its last rev, of its run

    def listed(head):
        out_, on = [], False
        for ln in lines:
            if ln.startswith(head):
                on = True
            elif on and ln.startswith("  ["):
                out_.append(ln)
            elif on and not ln.startswith("  "):
                on = False
        return out_
    rule_of = re.compile(r"^  \[[a-z]+\] (\S+)")
    thing_of = re.compile(r"^  \[[a-z]+\] (\S+) on .* pid (\d+|\?) via ")
    want_f = sorted(rule_of.match(ln).group(1) for ln in listed("FINDINGS: ") if rule_of.match(ln))
    want_s = sorted((m.group(1), m.group(2)) for m in (thing_of.match(ln) for ln in listed("SOURCE FINDINGS: ")
                                                         + listed("ON BENIGN TREES")) if m)
    have_f = sorted(str((e.get("rule") or {}).get("id")) for e in last.values() if e.get("kind") == "finding")
    folded = [e for e in last.values() if e.get("kind") == "source-finding" and "same_as" in (e.get("evidence") or {})]
    have_s = sorted((str((e.get("rule") or {}).get("id")), str((e.get("subject") or {}).get("pid", "?")))
                    for e in last.values() if e.get("kind") == "source-finding" and e not in folded)
    n_f = number(r"(?m)^FINDINGS: (\d+)", text, 0)
    n_s = number(r"(?m)^SOURCE FINDINGS: (\d+)", text, 0)
    ok = have_f == want_f and have_s == want_s and len(want_f) == n_f and len(want_s) == n_s
    out.append(("X18 an event for each finding the report lists", MET if ok else MISSED,
                "findings %d of %d, source findings %d of %d (%d said as one act with another), run %s%s" % (
                    len(have_f), n_f, len(have_s), n_s, len(folded), run.group(1) if run else "-",
                    "" if ok else "; not alike: %s" % "; ".join(sorted(
                        {"%s pid %s" % t for t in set(have_s) ^ set(want_s)} | set(set(have_f) ^ set(want_f))))[:200])))
    return out


# ADR-0014: (the claim, the rule, the WORKLOAD words that say the act was done, the state where no finding names it)
BEHAVIOUR = (
    ("X32 a file left in the Startup folder is a PERSIST-AUTOSTART finding", "PERSIST-AUTOSTART",
     "startup file written", MISSED),
    ("X33 reaching a login port of a private address is a NET-ADMIN-PORT finding", "NET-ADMIN-PORT",
     "port 22 of this machine's own address reached", MISSED),
    # ADR-0014 AC-8: the rule has landed (Amendment B, M15.2): MISSED where absent, as the two above
    ("X34 an autostart value set in the registry is a PERSIST-RUN-KEY finding", "PERSIST-RUN-KEY",
     "autostart value set", MISSED),
)


def read(report, workload, sources=(), exit_code=None, platform="win32", sysmon=False, events=None):
    """[(id, state, words)] for one watch. `sources`: (name, text) of the files the watch kept. `events`: the text
    of its events file (None: the rig gave none, and X16-X18 are n/a)."""
    full = report.splitlines()
    at = next((i for i, x in enumerate(full) if x.startswith("Raqib watch --host")), None)
    lines = full[at:] if at is not None else []
    out = []

    def say(ident, state, words):
        out.append((ident, state, words))

    pid = number(r"WORKLOAD \S+ pid (\d+)", workload)
    result = first(lines, "RESULT:")
    word = (re.match(r"RESULT: ([A-Z-]+)", result or "") or [None, None])[1]
    if result is None:
        say("X1 the watch ends with its report", MISSED, "no RESULT line (the first field run of M9.1: a watch asked to stop)")
        return out
    code = number(r"\(exit (\d+)", result)
    ok = code == EXIT_OF.get(word) and (exit_code is None or exit_code == code)
    say("X1 the watch ends with its report and its code", MET if ok else MISSED,
        "%s; the process exited %s" % (result, exit_code))

    holes = section(lines, "HOLES (A3):")
    late = [h for h in holes if "did not return in" in h]
    say("X2 no read of the channel is ended at its deadline", MET if not late else MISSED,
        "%d hole(s) say 'did not return in' (M7.14: a follow that asked for the whole channel)" % len(late))

    channel = first(lines, "CHANNEL")
    rounds = number(r"ROUNDS: (\d+) started", first(lines, "ROUNDS:") or "")
    sysmon_line = first(lines, "SYSMON:") or ""
    if sysmon:
        kept, failed = number(r"(\d+) read\(s\) kept", channel), number(r"kept, (\d+) failed", channel)
        say("X3 every round reads the Sysmon channel", MET if channel and kept == rounds and failed == 0 else MISSED,
            "%s kept, %s failed, of %s round(s) (M7.13: a watch that was denied every read)" % (kept, failed, rounds))
        kinds = re.search(r"kinds read: ([^;]*)", channel or "")
        got = kinds.group(1) if kinds else "none"
        say("X4 the channel gives process and network events", MET if "event 1" in got and "event 3" in got else MISSED,
            "kinds read: %s" % got)
        lie = "the rounds read its channel" in sysmon_line and kept == 0
        say("X5 the SYSMON line agrees with the CHANNEL line", MISSED if lie else MET,
            "%s (M7.13: 'the rounds read its channel' beside 0 reads kept)" % sysmon_line[:90])
    else:
        for ident in ("X3 every round reads the Sysmon channel", "X4 the channel gives process and network events",
                      "X5 the SYSMON line agrees with the CHANNEL line"):
            say(ident, SKIP, "no Sysmon on this machine")

    findings = section(lines, "FINDINGS:")
    named = [f for f in findings if pid is not None and re.search(r"NEW-AGENT(-UNKNOWN)? .*\bpid %d\b" % pid, f)]
    say("X6 the stand-in agent's tree is a finding", MET if named else MISSED,
        "pid %s: %s" % (pid, (named[0].strip()[:110] if named else "no NEW-AGENT line names it")))

    listed = section(lines, "SOURCE FINDINGS:")
    tool = [f for f in listed if pid is not None and re.search(r"NET-TOOL on \S+ pid %d\b" % pid, f)]
    say("X7 its curl is a NET-TOOL finding", MET if tool else MISSED,
        "%d NET-TOOL line(s) on pid %s (the third field run: a curl of twenty seconds)" % (len(tool), pid))

    live = number(r"SOURCE FINDINGS: \d+ \((\d+) live", listed[0] if listed else "")
    alarms = first(lines, "ALARMS:") or ""
    said = number(r"(\d+) source finding\(s\)", alarms)
    agree = (said == live) if said is not None else (live in (0, None))
    say("X8 the ALARMS line counts what the listing lists", MET if agree else MISSED,
        "listing %s live, ALARMS says %s (M7.16: 2 listed, 4 said)" % (live, said))

    notes = section(lines, "NOTES:")
    seen, twice = set(), 0
    for n in notes:
        m = re.search(r"- tree (\S+), (\S+): rule (\S+) partial: could not judge", n)
        if m:
            twice += m.groups() in seen
            seen.add(m.groups())
    say("X9 a rule's not-judged note is said once for a tree's file", MET if not twice else MISSED,
        "%d repeated note(s) of %d (M7.16: nine notes for three facts)" % (twice, len(seen)))

    trees = section(lines, "TREES SEEN:")
    own = [i for i, t in enumerate(trees) if pid is not None and re.search(r"\bpid %d\b" % pid, t) and "[" in t]
    src = trees[own[0] + 1] if own and own[0] + 1 < len(trees) else ""
    say("X10 nothing the stand-in did in the watch is history", MISSED if "before the watch's start" in src else MET,
        "its source line: %s (M7.16: Sysmon's times weeks behind)" % (src.strip()[-70:] or "not found"))

    count = number(r"HOLES \(A3\): (\d+)", holes[0] if holes else "")
    if platform == "win32" and sysmon:
        say("X11 a healthy machine has no hole", MET if count == 0 else MISSED, "HOLES (A3): %s" % count)
    else:
        say("X11 a healthy machine has no hole", SKIP, "HOLES (A3): %s (not judged on this machine)" % count)

    beats = number(r"beats after the last round: (\d+)", first(lines, "RHYTHM BEATS:") or "")
    # ADR-0007 Amendment AP (AP-1, AP-4): a beat is judged in the round that reads it, quiet tree or not: a beat
    # left for the final poll is in no round and no rule judged it, so X12 can be MISSED (it was OPEN)
    # ADR-0007 AR-4: without Sysmon no tree can have a source with beats here (the rig attaches no hooks): a 0 there
    # measured nothing, so X12 is n/a, as X11 is. AS-2: a count that is not 0 is a measure wherever it is read (a
    # beat did wait, so a tree did have such a source): MISSED with or without Sysmon; so is a line that is not there
    if sysmon or beats != 0:
        say("X12 no beat waits for the final poll unjudged", MET if beats == 0 else MISSED,
            "%s beat(s) read by the final poll, in no round (ADR-0007 Amendment AP: a beat is judged in the round"
            " that reads it)" % beats)
    else:
        say("X12 no beat waits for the final poll unjudged", SKIP,
            "0 beat(s) read by the final poll: not judged on this machine (no Sysmon: no tree had a source"
            " with beats here, so the 0 measured nothing; ADR-0007 AR-4, AS-2)")

    text = "\n".join(t for _, t in sources)
    if sources and platform == "win32" and sysmon:
        for ident, needle, why in (("X13 the os source holds its powershell child", '"image":"powershell"', "an agent's shell"),
                                   ("X14 the os source holds the file it made", "raqib-rig-file", "Sysmon's event 11")):
            say(ident, MET if needle in text else MISSED, why)
        clip = [f for f in listed + findings if "CLIPBOARD" in f.upper()]
        say("X15 writing the clipboard is a finding", MET if clip else OPEN, "no rule for it yet (M7.10, recorded)")
    # ADR-0014 (the rules of behaviour): what the stand-in did to the host, each act said by its own WORKLOAD line
    for ident, rule, did, absent in BEHAVIOUR:
        if not (platform == "win32" and sysmon):
            say(ident, SKIP, "no os source on this machine (the rule reads Sysmon's lines)")
        elif did not in workload:
            say(ident, SKIP, "the stand-in did not do it here (no WORKLOAD line says '%s')" % did)
        else:
            hit = [f for f in listed if pid is not None and re.search(r"\b%s on \S+ pid %d\b" % (rule, pid), f)]
            say(ident, MET if hit else absent, "%d %s line(s) on pid %s%s" % (
                len(hit), rule, pid, ": " + hit[0].strip()[:120] if hit else ""))
    out += read_events(events, lines, code)
    return out


def _whole_events(events):
    """The whole lines of the events file that are events (a reader's view, EVENT.md), in the file's order."""
    check, out = _checker(), []
    for raw in (events or "").split("\n")[:-1]:
        try:
            e = json.loads(raw)
        except ValueError:
            continue
        if isinstance(e, dict) and not check(e):
            out.append(json.dumps(e, sort_keys=True, separators=(",", ":")))
    return out


def _first_arrivals(got):
    seen, out = set(), []
    for x in got or ():
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def read_forward(facts, events):
    """X19-X22 (ADR-0011 J-14, L-10): what tools/rig/forward_run.py saw `raqib forward` do with the watch's events
    file. facts None: the run left nothing (silence is a finding: all four MISSED). A case whose run failed is
    MISSED with its error; no events file is n/a for all four (X16 says the watch wrote none)."""
    names = ("X19 every whole line of the events file arrived, in order, each id at least once",
             "X20 a collector down from the start: the state says failing, and nothing is lost when it comes up",
             "X21 a forwarder killed between two batches and started again leaves no gap and sends no taken line"
             " again",
             "X22 neither token is in any output, state, error or process list of the forwarder")
    if not isinstance(facts, dict):
        return [(n, MISSED, "the forwarder's run left no facts (silence is a finding)") for n in names]
    if facts.get("events_missing"):
        return [(n, SKIP, "the watch wrote no events file: nothing to forward (X16 says so)") for n in names]
    if facts.get("error"):
        return [(n, MISSED, "the forwarder's run failed: %s" % facts["error"]) for n in names]
    want = _whole_events(events)

    def arrived(part):
        got = _first_arrivals((facts.get(part) or {}).get("events"))
        if not want:
            return False, "the events file holds no whole event to forward"
        lost = [x for x in want if x not in set(got)]
        return got == want, "%d of %d line(s) arrived%s%s" % (len(want) - len(lost), len(want), ", in the file's order"
                                                               if got == want else ", not in the file's order"
                                                               if not lost else "", "; %d lost" % len(lost) if lost
                                                               else "")

    def part(key):
        got = facts.get(key)
        return got if isinstance(got, dict) else {}
    out = []
    for i, key in enumerate(("x19", "x20", "x21")):
        if part(key).get("error"):
            out.append((names[i], MISSED, "the rig's run of it failed: %s" % part(key)["error"]))
            continue
        ok, words = arrived(key)
        if key == "x19":
            x = part(key)
            out.append((names[0], MET if ok and x.get("exit") == 0 else MISSED,
                        "%s; %s request(s); --once exit %s" % (words, x.get("requests"), x.get("exit"))))
        elif key == "x20":
            x = part(key)
            failing, final = x.get("failing") or {}, x.get("final") or {}
            ok = ok and bool(failing) and bool(final) and final.get("failing") is None and final.get("behind") == 0
            out.append((names[1], MET if ok else MISSED, "the state said failing: %s (%s); then %s; %s" % (
                "yes" if failing else "no", failing.get("error"), "taken, behind 0" if final else "never all taken",
                words)))
        else:
            x = part(key)
            killed = (x.get("killed") or {}).get("offset") or 0
            between = 0 < killed < (x.get("size") or 0)
            got, before = x.get("events") or [], x.get("before") or 0
            taken = set(got[:before])
            again = [e for e in got[before:] if e in taken]
            ok = ok and between and before > 0 and not again and x.get("exit") == 0
            out.append((names[2], MET if ok else MISSED,
                        "killed at the collector's request %s, %d line(s) taken before, at offset %s of %s (%s);"
                        " started again: exit %s, %d line(s) taken before the kill came again; %s" % (
                            x.get("requests_at_kill"), before, killed, x.get("size"),
                            "between two batches" if between else "not between two batches", x.get("exit"),
                            len(again), words)))
    x22 = part("x22")
    tokens, unread = [], []
    for key in ("token_file", "wrong_file"):
        try:
            with open(facts.get(key) or "", "rb") as f:
                tokens.append(f.read().strip().decode("ascii"))
        except (OSError, UnicodeDecodeError):
            unread.append(key)
    tokens = [t for t in tokens if t]
    texts, argvs, listed = x22.get("texts") or [], x22.get("argv") or [], x22.get("listed") or []
    found = [t.get("where") for t in texts for tok in tokens if tok in (t.get("text") or "")]
    found += ["an argument list" for a in argvs for tok in tokens if any(tok in str(x) for x in a)]
    found += ["the process list (%s)" % p.get("how") for p in listed for tok in tokens if tok in (p.get("text") or "")]
    seen = [p for p in listed if "--token-file" in (p.get("text") or "")]
    if x22.get("error"):
        ok, why = False, "the rig's run of it failed: %s" % x22["error"]
    elif unread or len(tokens) != 2:
        ok, why = False, "no token to look for (%s cannot be read)" % ", ".join(unread or ["a token file"])
    elif not texts:
        ok, why = False, "no output or state to read"
    elif not seen:
        ok, why = False, "the system's process list of a running forwarder was not read"
    elif found:
        ok, why = False, "a token is in " + ", ".join(found[:3])
    else:
        ok, why = True, "neither token is in any"
    out.append((names[3], MET if ok else MISSED, "%d output(s) and state(s), %d argument list(s), %d process"
                " list(s) read for 2 tokens: %s" % (len(texts), len(argvs), len(seen), why)))
    return out


def read_syslog(facts, events):
    """X23-X25 (ADR-0011 J-6, J-14): what tools/rig/forward_run.py saw `raqib forward` do over syslog with the
    watch's events file, against the stand-in syslog collector on loopback. It never raises: facts None (the
    run left nothing) or a case the run has no facts of is MISSED (silence is a finding); a case whose run
    failed is MISSED with its error; no events file is n/a for all three (X16 says the watch wrote none)."""
    cases = (("x23", "X23 over syslog+tcp (octet counting) every whole line of the events file arrived, in order,"
                     " each an RFC 5424 message in raqib's shape", "written", ["octet"]),
             ("x24", "X24 over syslog+udp every line sent arrived on loopback, in order, each an RFC 5424"
                     " message in raqib's shape", "sent", ["datagram"]),
             ("x25", "X25 over syslog+tcp with --framing newline every whole line arrived, in order, each an RFC"
                     " 5424 message in raqib's shape", "written", ["newline"]))
    try:
        if not isinstance(facts, dict):
            return [(n, MISSED, "the forwarder's run left no facts (silence is a finding)") for _, n, _, _ in cases]
        if facts.get("events_missing"):
            return [(n, SKIP, "the watch wrote no events file: nothing to forward (X16 says so)")
                    for _, n, _, _ in cases]
        if facts.get("error"):
            return [(n, MISSED, "the forwarder's run failed: %s" % facts["error"]) for _, n, _, _ in cases]
        want = _whole_events(events)
    except Exception as exc:   # never raises: what cannot be read is a fact
        return [(n, MISSED, "the facts cannot be read (%s)" % type(exc).__name__) for _, n, _, _ in cases]
    out = []
    for key, name, delivery, framing in cases:
        try:
            x = facts.get(key)
            if not isinstance(x, dict):
                out.append((name, MISSED, "the rig did not run it: no facts of %s" % key))
                continue
            if x.get("error"):
                out.append((name, MISSED, "the rig's run of it failed: %s" % x["error"]))
                continue
            got = _first_arrivals(x.get("events"))
            lost = [e for e in want if e not in set(got)]
            problems = x.get("problems") or []
            ok = bool(want) and got == want and x.get("exit") == 0 and not problems and \
                x.get("delivery") == delivery and x.get("framings") == framing and x.get("refused") == 0
            words = ("the events file holds no whole event to forward" if not want else
                     "%d of %d line(s) arrived%s%s" % (len(want) - len(lost), len(want),
                                                       ", in the file's order" if got == want else
                                                       ", not in the file's order" if not lost else "",
                                                       "; %d lost" % len(lost) if lost else ""))
            out.append((name, MET if ok else MISSED,
                        "%s; %s message(s) on %s connection(s), framed %s; %d not in raqib's RFC 5424 shape%s;"
                        " delivery %s, refused %s; --once exit %s" % (
                            words, x.get("messages"), x.get("connections"), "/".join(x.get("framings") or [])
                            or "never", len(problems), " (%s)" % problems[0] if problems else "",
                            x.get("delivery"), x.get("refused"), x.get("exit"))))
        except Exception as exc:   # never raises: a case whose facts cannot be read is MISSED
            out.append((name, MISSED, "its facts cannot be read (%s)" % type(exc).__name__))
    return out


def _whole_event_lines(events):
    """The whole lines of the events file that are events, each as written (W-2: MESSAGE is the line)."""
    check, out = _checker(), []
    for raw in (events or "").split("\n")[:-1]:
        try:
            e = json.loads(raw)
        except ValueError:
            continue
        if isinstance(e, dict) and not check(e):
            out.append(raw)
    return out


def read_journal(facts, events):
    """X26 (ADR-0011 W-8): what tools/rig/forward_run.py read back with journalctl after `raqib forward --to
    journal:` sent the watch's events file. MET where every whole line is a MESSAGE, as written, in order; MISSED
    (not met) with what is missing; n/a (not run) with the reason where the machine has no journal (Windows, no
    socket). It never raises: facts None or no facts of x26 is MISSED (silence is a finding); no events file is
    n/a (X16 says the watch wrote none)."""
    name = ("X26 to the journal every whole line of the events file is in it, as written and in order, read back"
            " by journalctl")
    try:
        if not isinstance(facts, dict):
            return [(name, MISSED, "the forwarder's run left no facts (silence is a finding)")]
        if facts.get("events_missing"):
            return [(name, SKIP, "the watch wrote no events file: nothing to forward (X16 says so)")]
        if facts.get("error"):
            return [(name, MISSED, "the forwarder's run failed: %s" % facts["error"])]
        x = facts.get("x26")
        if not isinstance(x, dict):
            return [(name, MISSED, "the rig did not run it: no facts of x26")]
        if x.get("not_run"):
            return [(name, SKIP, "not run: %s" % x["not_run"])]
        if x.get("error"):
            return [(name, MISSED, "the rig's run of it failed: %s" % x["error"])]
        want = _whole_event_lines(events)
        got = _first_arrivals([m for m in x.get("messages") or [] if isinstance(m, str)])
        lost = [i for i, line in enumerate(want, 1) if line not in set(got)]
        long = x.get("long") if isinstance(x.get("long"), dict) else {}
        long_ok = long.get("as_written") is True and long.get("exit") == 0   # X-5: the memory file's way, shown
        long_said = ("a made-up line of %s bytes came back whole (the memory file's way)" % max(long["lines"])
                     if long_ok and long.get("lines") else "the long line did NOT come back whole: %s" % (
                         long.get("error") or "sent %s, read %s, exit %s" % (
                             long.get("lines"), long.get("read"), long.get("exit"))))
        ok = bool(want) and got == want and x.get("exit") == 0 and x.get("delivery") == "sent" and long_ok
        words = ("the events file holds no whole event to forward" if not want else
                 "%d of %d line(s) in the journal%s%s" % (
                     len(want) - len(lost), len(want), ", as written and in the file's order" if got == want else
                     ", not in the file's order" if not lost else "",
                     "; missing: line %s" % ", ".join(str(i) for i in lost[:5]) + (" and %d more" % (len(lost) - 5)
                                                                                 if len(lost) > 5 else "")
                     if lost else ""))
        jc = x.get("journalctl") if isinstance(x.get("journalctl"), dict) else {}
        return [(name, MET if ok else MISSED,
                 "%s; %s; %s entr(y/ies) read by journalctl (exit %s, asked %s time(s)); delivery %s; --once exit"
                 " %s%s" % (
                     words, long_said, x.get("read"), jc.get("exit"), x.get("asked"), x.get("delivery"), x.get("exit"),
                     "" if ok or not jc.get("stderr") else "; journalctl said: %s" % str(jc["stderr"])[:120]))]
    except Exception as exc:   # never raises: facts that cannot be read are MISSED
        return [(name, MISSED, "its facts cannot be read (%s)" % type(exc).__name__)]


EVENTS_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
PART_HEAD = re.compile(r"raqib-part ([0-9]+)/([0-9]+) id=(\S+) sha256=([0-9a-f]{64}) chars=([0-9]+)\Z")


def eventlog_lines(text):
    """Y-3: the lines that wevtutil's XML holds (one <Event> after another, no root element), in order: an event
    of one string is a line; the parts of a long one (id 1009, two strings, the head first) are put together in
    order - a part 1 begins a line anew - and the line is whole where its sha256 and its length are the head's.
    (lines, broken): broken counts the parts that did not make a whole line. Raises on XML that cannot be read
    (the caller says so)."""
    import xml.etree.ElementTree as ET
    root = ET.fromstring("<Events>%s</Events>" % (text or ""))
    lines, parts, broken = [], [], 0
    for ev in root.iter(EVENTS_NS + "Event"):
        ident = ev.findtext("%sSystem/%sEventID" % (EVENTS_NS, EVENTS_NS))
        datas = [d.text or "" for d in ev.iter(EVENTS_NS + "Data")]
        head = PART_HEAD.match(datas[0]) if ident == "1009" and len(datas) == 2 else None
        if head is None:
            broken += len(parts)
            parts = []
            if len(datas) == 1:
                lines.append(datas[0])
            continue
        i, n = int(head.group(1)), int(head.group(2))
        if i == 1:
            broken += len(parts)
            parts = []
        if len(parts) != i - 1:   # a part out of its order
            broken += len(parts) + 1
            parts = []
            continue
        parts.append(datas[1])
        if i == n:
            whole = "".join(parts)
            if hashlib.sha256(whole.encode("utf-8")).hexdigest() == head.group(4) and len(whole) == int(
                    head.group(5)):
                lines.append(whole)
            else:
                broken += len(parts)
            parts = []
    return lines, broken + len(parts)


def read_eventlog(facts, events):
    """X27 (ADR-0011 Y-7): what tools/rig/forward_run.py read back with wevtutil after `raqib forward --to
    eventlog:` sent the watch's events file and a made-up file with a long line. MET where every whole line is in
    the Application log under this run's process, as written and in order, and the long line came back whole
    from its parts; MISSED (not met) with what is missing; n/a (not run) off Windows. It never raises."""
    name = ("X27 to the Windows event log every whole line of the events file is in it, as written and in order,"
            " and a long line came back whole from its parts, read back by wevtutil")
    try:
        if not isinstance(facts, dict):
            return [(name, MISSED, "the forwarder's run left no facts (silence is a finding)")]
        if facts.get("events_missing"):
            return [(name, SKIP, "the watch wrote no events file: nothing to forward (X16 says so)")]
        if facts.get("error"):
            return [(name, MISSED, "the forwarder's run failed: %s" % facts["error"])]
        x = facts.get("x27")
        if not isinstance(x, dict):
            return [(name, MISSED, "the rig did not run it: no facts of x27")]
        if x.get("not_run"):
            return [(name, SKIP, "not run: %s" % x["not_run"])]
        if x.get("error"):
            return [(name, MISSED, "the rig's run of it failed: %s" % x["error"])]
        want = _whole_event_lines(events)
        try:
            read, broken = eventlog_lines(x.get("xml"))
        except Exception as exc:
            read, broken = [], "its XML cannot be read (%s)" % type(exc).__name__
        got = _first_arrivals(read)
        lost = [i for i, line in enumerate(want, 1) if line not in set(got)]
        long = x.get("long") if isinstance(x.get("long"), dict) else {}
        try:
            back = eventlog_lines(long.get("xml"))[0]
            # Z-6: only the made-up file's own lines (a process id used again brings other lines of the log)
            mine = set(long["sha256"]) if isinstance(long.get("sha256"), list) else set()
            back = _first_arrivals([b for b in back if hashlib.sha256(b.encode("utf-8")).hexdigest() in mine])
        except Exception:
            back = []
        back = _first_arrivals(back)
        long_ok = (long.get("exit") == 0 and isinstance(long.get("sha256"), list) and len(long["sha256"]) > 0 and
                   [hashlib.sha256(b.encode("utf-8")).hexdigest() for b in back] == long["sha256"] and
                   [len(b) for b in back] == long.get("lines"))
        long_said = ("a made-up line of %s characters came back whole from its parts" % max(long["lines"])
                     if long_ok else "the long line did NOT come back whole: %s" % (
                         long.get("error") or "sent %s character(s), put together %s, exit %s" % (
                             long.get("lines"), [len(b) for b in back], long.get("exit"))))
        ok = bool(want) and got == want and x.get("exit") == 0 and x.get("delivery") == "written" and long_ok
        words = ("the events file holds no whole event to forward" if not want else
                 "%d of %d line(s) in the Application log%s%s" % (
                     len(want) - len(lost), len(want), ", as written and in the file's order" if got == want else
                     ", not in the file's order" if not lost else "",
                     "; missing: line %s" % ", ".join(str(i) for i in lost[:5]) + (" and %d more" % (len(lost) - 5)
                                                                                 if len(lost) > 5 else "")
                     if lost else ""))
        wv = x.get("wevtutil") if isinstance(x.get("wevtutil"), dict) else {}
        return [(name, MET if ok else MISSED,
                 "%s; %s; %s event(s) read by wevtutil for process %s (exit %s, asked %s time(s)), parts not made"
                 " whole %s; delivery %s; --once exit %s%s" % (
                     words, long_said, x.get("read"), x.get("pid"), wv.get("exit"), x.get("asked"), broken,
                     x.get("delivery"), x.get("exit"),
                     "" if ok or not wv.get("stderr") else "; wevtutil said: %s" % str(wv["stderr"])[:120]))]
    except Exception as exc:   # never raises: facts that cannot be read are MISSED
        return [(name, MISSED, "its facts cannot be read (%s)" % type(exc).__name__)]


SERVICE_NAMES = ("X28 an install from a place a user can write is refused, the path said, and no unit is written",
                 "X29 an install from root's own place gives an active unit that sees a second user's stand-in agent",
                 "X30 the removal leaves no unit")


def _service_case(facts, key):
    x = facts.get(key)
    if not isinstance(x, dict):
        return None, "the rig did not run it: no facts of %s" % key
    if x.get("error"):
        return None, "the rig's run of it failed: %s" % x["error"]
    return x, None


CAP_BOUND = (1 << 2) | (1 << 19)   # AD-6: CAP_DAC_READ_SEARCH (2) and CAP_SYS_PTRACE (19), and no other: 0x80004


def _hex(text):
    try:
        return int(str(text), 16)
    except ValueError:
        return None


def _below(path, place):
    return isinstance(path, str) and isinstance(place, str) and place.startswith("/") and (
        path == place or path.startswith(place.rstrip("/") + "/"))


def _roots_alone(uid, mode):
    try:
        return uid == 0 and not int(str(mode), 8) & 0o022
    except ValueError:
        return False


def read_service(facts):
    """X28-X30 (ADR-0013 A-9, AC-10): what tools/rig/service_run.py saw `raqib service` do as root on the Linux
    machine. MET; MISSED with what is missing (facts None or without a case: silence is a finding); n/a only
    where it was not run and the facts' platform is not Linux (AA-4): not run on Linux is MISSED. X28 is MET only
    where the refusal names the place every user can write (mode 0777, not sticky, inside a folder root's alone)
    or a path below it; X29 only where systemd's own word on the unit was read, its manager warned of none of the
    unit's directives, and the main process's own word (AD-6) is a bounding set of exactly the two capabilities,
    a seccomp filter and no new privileges; X30 only where the unit is not active, systemd does not know it and
    the record's folder is gone. It never raises: facts that cannot be read are MISSED."""
    try:
        if not isinstance(facts, dict):
            return [(n, MISSED, "the service's run left no facts (silence is a finding)") for n in SERVICE_NAMES]
        if facts.get("not_run"):
            if str(facts.get("platform") or "linux").startswith("linux"):
                return [(n, MISSED, "not run on Linux: %s" % facts["not_run"]) for n in SERVICE_NAMES]
            return [(n, SKIP, "not run: %s" % facts["not_run"]) for n in SERVICE_NAMES]
        if facts.get("error"):
            return [(n, MISSED, "the service's run failed: %s" % facts["error"]) for n in SERVICE_NAMES]
        rows = []
        x, why = _service_case(facts, "x28")
        if x is None:
            rows.append((SERVICE_NAMES[0], MISSED, why))
        else:
            said = " ".join(str(x.get("said") or "").split())
            m = re.search(r"refused: (/\S*) is ", said)
            place, parent = x.get("place"), x.get("parent")
            missing = [w for w, bad in (
                ("exit 2 (exit %s)" % x.get("exit"), x.get("exit") != 2),
                ("a place every user can write and not sticky (mode %s)" % x.get("mode"), x.get("mode") != "0777"),
                ("inside a folder root's alone (%s: uid %s, mode %s)" % (parent, x.get("parent_uid"),
                                                                         x.get("parent_mode")),
                 not (isinstance(place, str) and isinstance(parent, str) and place.startswith(parent + "/") and
                      _roots_alone(x.get("parent_uid"), x.get("parent_mode")))),
                ("the refusal naming %s or a path below it (it named %s)" % (place, m.group(1) if m else "none"),
                 not (m and _below(m.group(1), place))),
                ("no unit after it (one is there)", x.get("unit_after") is not False)) if bad]
            rows.append((SERVICE_NAMES[0], MISSED if missing else MET,
                         "from %s (mode %s, in %s, mode %s): %s" % (
                             place, x.get("mode"), parent, x.get("parent_mode"),
                             "exit 2, %s is named, no unit written" % m.group(1) if not missing else
                             "missing: " + "; ".join(missing) + ("; it said: %s" % said[:200]))))
        x, why = _service_case(facts, "x29")
        if x is None:
            rows.append((SERVICE_NAMES[1], MISSED, why))
        else:
            install = x.get("install") if isinstance(x.get("install"), dict) else {}
            agent = x.get("agent") if isinstance(x.get("agent"), dict) else {}
            mine = [f for f in x.get("mine") or [] if isinstance(f, dict)]
            seen = [f for f in x.get("findings") or [] if isinstance(f, dict)]
            show = x.get("show") if isinstance(x.get("show"), dict) else {}
            journal = x.get("journal") if isinstance(x.get("journal"), dict) else {}
            proc = x.get("proc") if isinstance(x.get("proc"), dict) else {}
            warned = [str(w) for w in journal.get("lines") or []] if isinstance(journal.get("lines"), list) else []
            missing = [w for w, bad in (
                ("the install exited %s" % install.get("exit"), install.get("exit") != 0),
                ("the unit is %s, not active" % x.get("active"), x.get("active") != "active"),
                ("the stand-in did not start as %s (exit %s)" % ((x.get("user") or {}).get("name"), agent.get("exit")),
                 agent.get("exit") != 0 or not isinstance(agent.get("pid"), int)),
                ("no finding on the stand-in's tree (pid %s) in %s event(s); findings seen: %s" % (
                    agent.get("pid"), x.get("events"), ", ".join("%s %s" % (f.get("rule"), f.get("tree"))
                                                                 for f in seen[-5:]) or "none"), not mine),
                ("systemd's word on the unit: its directives as systemctl show gives them (%s)" % (
                    x.get("show_error") or "none read"), not show),
                ("the manager's journal read (exit %s: %s)" % (journal.get("exit"), journal.get("err") or "no lines"),
                 journal.get("exit") != 0 or not isinstance(journal.get("lines"), list) or not journal.get("read")),
                ("no line of the manager's on the unit's directives; it said: %s" % " | ".join(warned[:3]),
                 bool(warned)),
                ("the main process's own word (%s)" % proc.get("error"), bool(proc.get("error")) or not proc),
                ("its bounding set exactly CAP_DAC_READ_SEARCH and CAP_SYS_PTRACE (CapBnd %#x); it read CapBnd=%s"
                 % (CAP_BOUND, proc.get("CapBnd")), _hex(proc.get("CapBnd")) != CAP_BOUND),
                ("a seccomp filter (Seccomp 2); it read Seccomp=%s" % proc.get("Seccomp"), proc.get("Seccomp") != "2"),
                ("no new privileges (NoNewPrivs 1); it read NoNewPrivs=%s" % proc.get("NoNewPrivs"),
                 proc.get("NoNewPrivs") != "1"))
                if bad]
            rows.append((SERVICE_NAMES[1], MISSED if missing else MET,
                         "missing: " + "; ".join(missing) if missing else
                         "active; the stand-in as %s (uid %s, pid %s): %s; systemd: %d directive(s) shown, none"
                         " warned of in %s journal line(s); the main process (pid %s): CapBnd=%s, Seccomp=2,"
                         " NoNewPrivs=1" % (
                             (x.get("user") or {}).get("name"), (x.get("user") or {}).get("uid"), agent.get("pid"),
                             "; ".join("%s on %s" % (f.get("rule"), f.get("tree")) for f in mine[:3]), len(show),
                             journal.get("read"), proc.get("pid"), proc.get("CapBnd"))))
        x, why = _service_case(facts, "x30")
        if x is None:
            rows.append((SERVICE_NAMES[2], MISSED, why))
        else:
            missing = [w for w, bad in (("the removal exited %s" % x.get("exit"), x.get("exit") != 0),
                                        ("the unit's file is left", x.get("unit_file") is not False),
                                        ("systemctl says LoadState=%s" % x.get("load_state"),
                                         x.get("load_state") != "not-found"),
                                        ("systemctl says ActiveState=%s" % x.get("active_state"),
                                         x.get("active_state") not in ("inactive", "failed")),
                                        ("the record's folder is left", x.get("state_dir") is not False)) if bad]
            rows.append((SERVICE_NAMES[2], MISSED if missing else MET,
                         "missing: " + "; ".join(missing) if missing else
                         "exit 0; no unit file; systemctl: LoadState=not-found, ActiveState=%s; no record's folder"
                         % x.get("active_state")))
        return rows
    except Exception as exc:   # never raises: facts that cannot be read are MISSED
        return [(n, MISSED, "its facts cannot be read (%s)" % type(exc).__name__) for n in SERVICE_NAMES]


PROCEVENTS_NAME = ("X31 every short act that ran is given by the process events' reader with its program, its parent"
                   " and its end's code, and nothing is lost")
NO_RIGHT = re.compile(r"\b(EPERM|EACCES)\b")


def read_procevents(facts):
    """X31's row, its words led by the kernel's release where the run's facts say it (BS-8)."""
    rows = _procevents_rows(facts)
    kernel = facts.get("kernel") if isinstance(facts, dict) else None
    if kernel:
        rows = [(n, state, "kernel %s: %s" % (kernel, words)) for n, state, words in rows]
    return rows


def _procevents_rows(facts):
    """X31 (ADR-0007 BQ-2): what tools/rig/procevents_run.py saw raqib.procevents.Reader give for the short acts it
    ran. MET where every act that ran was given by read() with its program read (the real path of the program the
    run started), its parent the run's own process (`run_pid`, BR-7) and its end's code (the run's exit code: the
    code where it exited, the signal where one ended it), and counts() shows no loss (nothing lost to ENOBUFS or
    by the kernel's count, nothing beyond the bound, the thread not ended before the stop); MISSED with what is missing (facts None, not
    run on Linux, an error: silence is a finding). A refused start: n/a where the refusal names a right this user
    lacks (EPERM, EACCES), else MISSED (on the measured kernels the kernel answers, BR-7); n/a off Linux. It never
    raises: facts that cannot be read are MISSED."""
    name = PROCEVENTS_NAME
    try:
        if not isinstance(facts, dict):
            return [(name, MISSED, "the process events' run left no facts (silence is a finding)")]
        platform = str(facts.get("platform") or "")
        if facts.get("not_run"):
            if platform.startswith("linux"):
                return [(name, MISSED, "not run on Linux: %s" % facts["not_run"])]
            return [(name, SKIP, "not run: %s" % facts["not_run"])]
        if not platform.startswith("linux"):
            return [(name, SKIP, "not run: not Linux (%s)" % (platform or "no platform said"))]
        if facts.get("refused"):
            if NO_RIGHT.search(str(facts["refused"])):
                return [(name, SKIP, "start() was refused for want of a right of this user: %s" % facts["refused"])]
            return [(name, MISSED, "start() was refused where the kernel is known to answer: %s" % facts["refused"])]
        if facts.get("error"):
            return [(name, MISSED, "the run failed: %s" % facts["error"])]
        acts = facts.get("acts") or []
        ran = [a for a in acts if a.get("pid") is not None]
        skipped = ["%s (%s)" % (a.get("act"), a.get("not_run")) for a in acts if a.get("pid") is None]
        missing = [] if ran else ["no act ran"]
        for a in ran:
            act, g, rc = "%s (pid %s)" % (a.get("act"), a.get("pid")), a.get("given"), a.get("rc")
            if not isinstance(g, dict):
                missing.append("%s not given by read()" % act)
                continue
            if g.get("ppid") is None or g.get("ppid") != facts.get("run_pid"):
                missing.append("%s: its parent %s, not the run's own %s" % (act, g.get("ppid"), facts.get("run_pid")))
            if not g.get("exe") or g.get("exe") != a.get("expect"):
                missing.append("%s: its program read as %s, not %s%s" % (
                    act, g.get("exe"), a.get("expect"), " (unread: %s)" % g["unread"] if g.get("unread") else ""))
            if g.get("ended") is None:
                missing.append("%s: its end not heard" % act)
            elif not isinstance(rc, int):
                missing.append("%s: the run has no exit code for it" % act)
            elif rc >= 0 and (g.get("code") != rc or g.get("signal") is not None):
                missing.append("%s: its end's code %s (signal %s), not %d" % (act, g.get("code"), g.get("signal"), rc))
            elif rc < 0 and g.get("signal") != -rc:
                missing.append("%s: its end's signal %s, not %d" % (act, g.get("signal"), -rc))
        c = facts.get("counts")
        if not isinstance(c, dict):
            missing.append("no counts")
            c = {}
        else:
            lost = c.get("lost") if isinstance(c.get("lost"), dict) else {}
            if lost.get("count") != 0:
                missing.append("lost %s (%s)" % (lost.get("count"), lost.get("why")))
            elif lost.get("events"):     # BS-5: a gap in the kernel's count with no ENOBUFS is a loss too
                missing.append("at least %s event(s) lost by the kernel's count (%s)" % (lost["events"],
                                                                                       lost.get("why")))
            if c.get("beyond") != 0:
                missing.append("beyond the bound %s" % c.get("beyond"))
            if c.get("ended"):
                missing.append("the reader's thread ended: %s" % c["ended"])
        if facts.get("stop_problems"):
            missing.append("the stop's problems: %s" % "; ".join(facts["stop_problems"]))
        if missing:
            return [(name, MISSED, "missing: " + "; ".join(missing))]
        return [(name, MET, "%d act(s) given with their program and their end's code (%s); not run: %s; events %s,"
                 " threads %s, reads missed %s, unread %s, lost 0, beyond 0" % (
                     len(ran), ", ".join(sorted({str(a.get("act")) for a in ran})), ", ".join(skipped) or "none",
                     c.get("events"), c.get("threads"), c.get("missed"), sum((c.get("unread") or {}).values())))]
    except Exception as exc:   # never raises: facts that cannot be read are MISSED
        return [(name, MISSED, "its facts cannot be read (%s)" % type(exc).__name__)]


AUTOSTART_NAME = ("X37 the autostart places read by Raqib itself: the stand-in's Run value, its Startup file and its"
                  " service are each added and later removed, its delete of its Startup file did not fail, and a"
                  " file held open is said as added by the first read that lists it")
AUTOSTART_HELD = "raqib-rig-held.cmd"          # tools/rig/autostart_run.py's HELD_NAME
AUTOSTART_DELETE_FAILED = "the startup file's delete failed"   # tools/rig/workload.py's words (AI-10)
AUTOSTART_ACTS = (("run", "RaqibRigValue"), ("startup", "raqib-rig-startup.cmd"), ("service", "RaqibRigService"))


def read_autostart(facts):
    """X37 (ADR-0014 AG-4, AI-10): what tools/rig/autostart_run.py saw raqib.autostart's watcher give while the
    stand-in worked. MET where each of the stand-in's three acts (its Run value, its Startup file, its service:
    AUTOSTART_ACTS, the names tools/rig/workload.py gives them) is an `added` change and, in a later read, a
    `removed` one; no WORKLOAD line says the stand-in's delete of its Startup file failed; and the file the run held
    open with no sharing across one read was made, said as `added` by the first read that listed it - the read
    made while it was held, its content not read - and removed after (AJ-7). MISSED
    otherwise, with what is missing and the reads that left a place unread (facts None, not run on Windows, an
    error: silence is a finding); n/a off Windows. Its words name every other change by its kind and place (one
    nobody of the rig made: Windows moves some of its own tasks). It never raises: facts that cannot be read are
    MISSED."""
    name = AUTOSTART_NAME
    try:
        if not isinstance(facts, dict):
            return [(name, MISSED, "the autostart run left no facts (silence is a finding)")]
        platform = str(facts.get("platform") or "")
        if not platform.startswith("win"):
            return [(name, SKIP, "not run: not Windows (%s)" % (platform or "no platform said"))]
        if facts.get("not_run"):
            return [(name, MISSED, "not run on Windows: %s" % facts["not_run"])]
        if facts.get("error"):
            return [(name, MISSED, "the run failed: %s%s" % (facts["error"], (
                "; the run ended the stand-in before its end: its acts were not undone"
                if facts.get("ended_by_run") else "")))]
        changes = [c for c in facts.get("changes") or [] if isinstance(c, dict)]
        seen, missing = [], []
        for place, want in AUTOSTART_ACTS:
            mine = [c for c in changes if c.get("place") == place and str(c.get("name") or "").lower() == want.lower()
                    and isinstance(c.get("round"), int)]
            added = [c["round"] for c in mine if c.get("change") == "added"]
            removed = [c["round"] for c in mine if c.get("change") == "removed" and added and c["round"] > min(added)]
            if not added:
                missing.append("%s %s: no added change" % (place, want))
            elif not removed:
                missing.append("%s %s: added in read %d, no removed change after it" % (place, want, min(added)))
            else:
                seen.append("%s added in read %d, removed in read %d" % (place, min(added), min(removed)))
        workload = [str(x) for x in facts.get("workload") or []]
        failed = [x for x in workload if AUTOSTART_DELETE_FAILED in x]
        if failed:
            kind = failed[0].split(AUTOSTART_DELETE_FAILED, 1)[1].strip(" ()")
            missing.append("the stand-in's delete of its Startup file failed beside the reads (%s)" % (kind or "said"))
        held = facts.get("held") if isinstance(facts.get("held"), dict) else {}
        listed = [r for r in held.get("reads") or [] if isinstance(r, dict) and r.get("listed")]
        if not held.get("made"):
            missing.append("the held file was not made (%s)" % (held.get("error") or "no word"))
        elif not listed:
            missing.append("the held file was listed by no read")
        elif "added" not in (listed[0].get("changes") or []):
            missing.append("the held file was not said as added by the first read that listed it (read %s: %s)" % (
                listed[0].get("round"), ", ".join(listed[0].get("changes") or []) or "no change"))
        elif not (listed[0].get("held") is True and listed[0].get("content") == "not read"):
            missing.append("the read that first listed the held file was not the one made while it was held with"
                           " its content not read (read %s: held %s, content %s)" % (
                               listed[0].get("round"), listed[0].get("held"), listed[0].get("content")))
        elif held.get("removed") is not True:
            missing.append("the held file was not removed after (it may be left in the Startup folder)")
        else:
            seen.append("the held file added in read %s while held, its content not read, and removed after" %
                        listed[0].get("round"))
        ours = {(p, w.lower()) for p, w in AUTOSTART_ACTS} | {("startup", AUTOSTART_HELD)}
        others = {}
        for c in changes:
            if (c.get("place"), str(c.get("name") or "").lower()) not in ours:
                k = "%s %s" % (c.get("change"), c.get("place"))
                others[k] = others.get(k, 0) + 1
        other = "other changes: %s" % (", ".join("%s %d" % (k, others[k]) for k in sorted(others)) or "none")
        unread, partly = [], []   # AJ-7: a place read in part is said as that, not as unread
        for u in facts.get("unread") or []:
            if isinstance(u, dict):
                places = u.get("places") or {}
                gone = sorted(p for p in places if not str(places[p]).startswith("in part"))
                inpart = sorted(p for p in places if str(places[p]).startswith("in part"))
                if gone:
                    unread.append("read %s: %s" % (u.get("round"), ", ".join(gone)))
                if inpart:
                    partly.append("read %s: %s" % (u.get("round"), ", ".join(inpart)))
        partly += ["read %s: %s" % (u.get("round"), ", ".join(sorted(u.get("places") or {})))
                   for u in facts.get("partly") or [] if isinstance(u, dict)]
        unread = "; ".join(unread) or "none"
        if partly:
            unread += "; read in part: %s" % "; ".join(partly)
        if missing:
            ended = ("; the run ended the stand-in before its end: its acts were not undone"
                     if facts.get("ended_by_run") else "")
            return [(name, MISSED, "missing: %s; %s; unread: %s%s" % ("; ".join(missing), other, unread, ended))]
        return [(name, MET, "%s; %s; %s read(s), the longest %s s; unread: %s" % (
            "; ".join(seen), other, facts.get("reads"), facts.get("seconds_max"), unread))]
    except Exception as exc:   # never raises: facts that cannot be read are MISSED
        return [(name, MISSED, "its facts cannot be read (%s)" % type(exc).__name__)]


WATCH_EVENTS_NAME = ("X35 the watch's helper heard the kernel's process events: its report's PROCESS EVENTS section,"
                     " every ask answered, no helper started again, nothing lost, at least the stand-in's children"
                     " began")
WATCH_EVENTS_HEAD = "PROCESS EVENTS (Linux):"


def read_watch_events(report, workload, platform):
    """X35 (ADR-0007 BU-5, BW-7): the watch's own count of the process events, read from its report beside what the
    stand-in said it started. MET only where the section is there, every round asked was answered, no helper was
    started again, nothing was lost and the processes that began are at least the stand-in's children (a floor:
    the count holds every process of the machine, the watch's own `ss` among them); MISSED otherwise on Linux, a
    workload that says no child included; n/a off Linux, or where the refusal names a right this user lacks (EPERM,
    EACCES; X31's rule). It never raises: a report that cannot be read is MISSED."""
    name = WATCH_EVENTS_NAME
    try:
        if not str(platform or "").startswith("linux"):
            return [(name, SKIP, "not run: not Linux (%s)" % (platform or "no platform said"))]
        lines = section(str(report or "").splitlines(), WATCH_EVENTS_HEAD)
        if not lines:
            return [(name, MISSED, "the watch's report holds no %s section (silence is a finding)" % WATCH_EVENTS_HEAD)]
        body = "\n".join(lines)
        refused = next((x.strip()[len("refused: "):] for x in lines if x.strip().startswith("refused: ")), None)
        if refused is not None:
            if NO_RIGHT.search(refused):
                return [(name, SKIP, "the helper's reader was refused for want of a right of this user: %s" % refused)]
            return [(name, MISSED, "the helper's reader was refused (not for want of a right): %s" % refused)]
        children = len(re.findall(r"(?m)^WORKLOAD \S+ start \S", str(workload or "")))
        began = number(r"processes that began: (\d+)", body)
        asked = number(r"rounds asked: (\d+)", body)
        answered = number(r"rounds asked: \d+, answered: (\d+)", body)
        lost = next((x.strip()[len("lost: "):] for x in lines if x.strip().startswith("lost: ")), None)
        restarts = [x.strip() for x in lines if x.strip().startswith(("started again", "and started again"))]
        holes = [x.strip() for x in lines if x.strip().startswith("hole, ")]
        missing = []
        if asked is None or answered is None:
            missing.append("no count of the rounds asked and answered")
        elif answered != asked or not asked:
            missing.append("%d of %d round(s) asked were answered" % (answered, asked))
        if restarts:
            missing.append("the helper was started again: %s" % "; ".join(restarts))
        if lost != "none":
            missing.append("lost: %s" % (lost if lost is not None else "not said"))
        if not children:
            missing.append("the stand-in said it started no child: nothing to hold the count against")
        if began is None:
            missing.append("no count of the processes that began")
        elif began < children:
            missing.append("%d process(es) began, fewer than the %d child(ren) the stand-in started" % (began,
                                                                                                     children))
        if missing:
            return [(name, MISSED, "missing: %s%s" % ("; ".join(missing), "; " + "; ".join(holes) if holes else ""))]
        return [(name, MET, "%d of %d round(s) answered; at least the stand-in's %d child(ren) began (%d process(es)"
                 " of the machine: a floor, not the stand-in's alone); no helper started again; lost: none%s" % (
                     answered, asked, children, began, "; " + "; ".join(holes) if holes else ""))]
    except Exception as exc:   # never raises
        return [(name, MISSED, "its report cannot be read (%s)" % type(exc).__name__)]


def table(rows, title):
    width = max([len(r[0]) for r in rows] + [10])
    out = [title, ""] + ["%-6s  %-*s  %s" % (state, width, ident, words) for ident, state, words in rows]
    counts = {s: sum(1 for r in rows if r[1] == s) for s in (MET, MISSED, OPEN)}
    out += ["", "RIG: %d met, %d missed, %d open" % (counts[MET], counts[MISSED], counts[OPEN])]
    return "\n".join(out)


def main(argv=None):
    p = argparse.ArgumentParser(prog="tools/rig/check.py")
    p.add_argument("--report", required=True)
    p.add_argument("--workload", required=True)
    p.add_argument("--sources")
    p.add_argument("--exit-code", type=int)
    p.add_argument("--platform", default=sys.platform)
    p.add_argument("--sysmon", action="store_true")
    p.add_argument("--events")
    p.add_argument("--forward")
    p.add_argument("--service")
    p.add_argument("--procevents")
    p.add_argument("--autostart")
    p.add_argument("--summary")
    p.add_argument("--strict", action="store_true")
    a = p.parse_args(argv)

    def text(path):
        with open(path, "rb") as f:
            raw = f.read()
        if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):   # a redirect of Windows PowerShell 5
            return raw.decode("utf-16", "replace")
        return raw.decode("utf-8", "replace").replace("\x00", "")
    sources = []
    if a.sources and os.path.isdir(a.sources):
        sources = [(name, text(os.path.join(a.sources, name))) for name in sorted(os.listdir(a.sources))]
    events = None
    if a.events:   # given and missing: the watch wrote none, which X16 says (not n/a)
        events = text(a.events) if os.path.isfile(a.events) else ""
    rows = read(text(a.report), text(a.workload), sources, a.exit_code, a.platform, a.sysmon, events)
    rows += read_watch_events(text(a.report), text(a.workload), a.platform)   # X35 (ADR-0007 BU-5)
    if a.forward:   # X19-X22 (ADR-0011 J-14): given and missing is the forwarder's silence, MISSED
        try:
            facts = json.loads(text(a.forward))
        except (OSError, ValueError):
            facts = None
        rows += read_forward(facts, events)
        rows += read_syslog(facts, events)
        rows += read_journal(facts, events)
        rows += read_eventlog(facts, events)
    if a.service:   # X28-X30 (ADR-0013 A-9): given and missing is the service run's silence, MISSED
        try:
            service_facts = json.loads(text(a.service))
        except (OSError, ValueError):
            service_facts = None
        rows += read_service(service_facts)
    if a.procevents:   # X31 (ADR-0007 BQ-2): given and missing is the run's silence, MISSED
        try:
            procevents_facts = json.loads(text(a.procevents))
        except (OSError, ValueError):
            procevents_facts = None
        rows += read_procevents(procevents_facts)
    if a.autostart:   # X37 (ADR-0014 AG-4): given and missing is the run's silence, MISSED
        try:
            autostart_facts = json.loads(text(a.autostart))
        except (OSError, ValueError):
            autostart_facts = None
        rows += read_autostart(autostart_facts)
    out = table(rows, "The rig: %s%s" % (a.platform, ", Sysmon" if a.sysmon else ""))
    print(out)
    if a.summary:
        with open(a.summary, "a", encoding="utf-8") as f:
            f.write("```\n%s\n```\n" % out)
    for ident, state, words in rows:
        if state == MISSED:
            print("::warning title=rig MISSED::%s: %s" % (ident, words))
    return 1 if a.strict and any(r[1] == MISSED for r in rows) else 0


if __name__ == "__main__":
    sys.exit(main())
