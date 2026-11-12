"""The rig's reader (ADR-0012): reads what `raqib watch --host` printed while the stand-in agent worked, beside
what the stand-in says it did, and states each expectation as MET, MISSED or OPEN (a gap already recorded, with
its task). Every expectation names the field run that taught it. Stdlib only; it reads text and writes text.

    python tools/rig/check.py --report WATCH.out --workload WORKLOAD.out [--sources DIR] [--exit-code N]
                              [--platform win32|linux] [--sysmon] [--summary FILE] [--strict]

Exit 0; with --strict, 1 when an expectation is MISSED (OPEN never fails)."""
import argparse
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


def read(report, workload, sources=(), exit_code=None, platform="win32", sysmon=False):
    """[(id, state, words)] for one watch. `sources`: (name, text) of the files the watch kept."""
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
    say("X12 no beat waits for the final poll unjudged", MET if beats == 0 else MISSED,
        "%s beat(s) read by the final poll, in no round (ADR-0007 Amendment AP: a beat is judged in the round"
        " that reads it)" % beats)

    text = "\n".join(t for _, t in sources)
    if sources and platform == "win32" and sysmon:
        for ident, needle, why in (("X13 the os source holds its powershell child", '"image":"powershell"', "an agent's shell"),
                                   ("X14 the os source holds the file it made", "raqib-rig-file", "Sysmon's event 11")):
            say(ident, MET if needle in text else MISSED, why)
        clip = [f for f in listed + findings if "CLIPBOARD" in f.upper()]
        say("X15 writing the clipboard is a finding", MET if clip else OPEN, "no rule for it yet (M7.10, recorded)")
    return out


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
    rows = read(text(a.report), text(a.workload), sources, a.exit_code, a.platform, a.sysmon)
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
