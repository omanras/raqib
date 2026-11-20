"""Probe only (never merged): a person's rules added, switched off and removed, measured against a live watch on
the rig's machine. One rule is made by the form (`raqib rules --new`, a program name: curl, which the rig's
stand-in agent starts), one is a file written by hand with its fixtures (`raqib rules --add`, an os net line to
port 443: the stand-in's own talk, read where Sysmon is). Then: a watch with both on, a watch with the first
switched off, a watch after both were removed. It prints what it saw and a table; it judges only its own steps."""
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PROBE = os.path.join(HERE, "rules_probe")
HOME = os.path.expanduser("~")
RULES_D = os.path.join(HOME, ".raqib", "rules.d")
RAQIB = [sys.executable, "-m", "raqib"]
ROWS = []


def row(name, ok, said):
    ROWS.append((name, "MET" if ok else "MISSED" if ok is False else "n/a", said))
    print("ROW %s %s %s" % (ROWS[-1][1], name, said), flush=True)


def cli(*args):
    got = subprocess.run(RAQIB + list(args), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=300)
    text = got.stdout.decode("utf-8", "replace")
    print("$ raqib %s -> exit %d" % (" ".join(args), got.returncode), flush=True)
    for line in text.splitlines()[-6:]:
        print("    " + line[:260], flush=True)
    return got.returncode, text


def folders():
    try:
        return sorted(os.listdir(RULES_D))
    except OSError:
        return []


def watch(tag):
    """One watch of 16 rounds while the stand-in works: (the watch's whole output, its exit code)."""
    out = os.path.join(os.environ.get("RUNNER_TEMP") or HOME, "rules-probe-%s.out" % tag)
    with open(out, "wb") as f:
        w = subprocess.Popen(RAQIB + ["watch", "--host", "--rounds", "16", "--every", "5", "--no-open"],
                             stdout=f, stderr=subprocess.STDOUT)
        time.sleep(7)
        subprocess.run([sys.executable, os.path.join(HERE, "workload.py")], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=240)
        try:
            code = w.wait(240)
        except subprocess.TimeoutExpired:
            w.kill()
            code = None
    text = open(out, encoding="utf-8", errors="replace").read()
    print("=== watch %s: exit %s" % (tag, code), flush=True)
    for line in text.splitlines():
        if ("RIG-" in line or line.startswith(("RULES OFF", "SOURCE FINDINGS", "FINDINGS:", "RESULT", "ALARMS"))
                or "rules:" in line or "rules overlay" in line):
            print("    " + line[:330], flush=True)
    return text, code


def fired(text, rule):
    return sum(1 for line in text.splitlines() if (" %s on " % rule) in line and line.lstrip().startswith("["))


def main():
    windows = os.name == "nt"
    code, text = cli("rules")
    row("R0 no rule of the probe's at the start", "RIG-" not in text and not folders(), "folders %s" % folders())
    code, text = cli("rules", "--new", "RIG-CURL", "--when", "program", "--values", "curl", "--severity", "high",
                     "--fires", "curl", "--quiet", "ls")
    row("R1 a rule from the form is added", code == 0 and "RIG-CURL" in folders(), "exit %s, folders %s" % (
        code, folders()))
    code, text = cli("rules", "--add", os.path.join(PROBE, "RIG-PORT.yaml"))
    row("R2 a rule from a file with its fixtures is added", code == 0 and "RIG-PORT" in folders(),
        "exit %s, folders %s" % (code, folders()))
    code, text = cli("rules", "--add", os.path.join(PROBE, "broken", "RIG-BROKEN.yaml"))
    row("R3 a rule whose own positive does not fire is refused and nothing is written", code == 2
        and "RIG-BROKEN" not in folders(), "exit %s, folders %s" % (code, folders()))
    code, text = cli("rules", "--new", "NET-TOOL", "--when", "program", "--values", "curl", "--severity", "high",
                     "--fires", "curl", "--quiet", "ls")
    row("R4 an id the package has is refused", code == 2, "exit %s" % code)
    code, text = cli("rules")
    listed = [line for line in text.splitlines() if line.startswith("RIG-")]
    row("R5 the listing shows both as a person's, on", len(listed) == 2 and all(
        " user " in line and " on " in line for line in listed), "; ".join(" ".join(x.split()[:7]) for x in listed))

    text, code = watch("both-on")
    curl, port = fired(text, "RIG-CURL"), fired(text, "RIG-PORT")
    row("R6 a live watch judges by the form's rule", curl >= 1, "%d listed finding(s) of RIG-CURL" % curl)
    row("R7 a live watch judges by the file's rule (os lines: where Sysmon is)", (port >= 1) if windows else None,
        "%d listed finding(s) of RIG-PORT%s" % (port, "" if windows else " (no os source on this machine)"))
    row("R8 the watch's start names the person's rules", "user rule RIG-CURL" in text and "user rule RIG-PORT"
        in text, "said at the start: %s" % ("user rule RIG-CURL" in text and "user rule RIG-PORT" in text))

    cli("rules", "--set", "RIG-CURL", "off")
    text, code = watch("curl-off")
    curl, port = fired(text, "RIG-CURL"), fired(text, "RIG-PORT")
    off = [line for line in text.splitlines() if line.startswith("RULES OFF")]
    row("R9 a rule switched off is not judged, and the report says it is off", curl == 0 and bool(off)
        and "RULES OFF" in off[0] and ": 1" in off[0], "%d finding(s) of RIG-CURL; %s" % (curl, (off or ["-"])[0][:120]))
    row("R10 the other rule goes on firing", (port >= 1) if windows else None, "%d finding(s) of RIG-PORT" % port)

    cli("rules", "--set", "RIG-CURL", "on")
    c1, _ = cli("rules", "--remove", "RIG-CURL")
    c2, _ = cli("rules", "--remove", "RIG-PORT")
    code, text = cli("rules")
    row("R11 both are removed: the listing and the folder have neither", c1 == 0 and c2 == 0 and "RIG-" not in text
        and not folders(), "exits %s %s, folders %s" % (c1, c2, folders()))
    text, code = watch("removed")
    curl, port = fired(text, "RIG-CURL"), fired(text, "RIG-PORT")
    row("R12 a watch after the removal judges by neither", curl == 0 and port == 0 and "RIG-" not in text,
        "%d and %d finding(s); named anywhere in the watch's words: %s" % (curl, port, "RIG-" in text))
    stand_in = sum(1 for line in text.splitlines() if " NET-TOOL on " in line and line.lstrip().startswith("["))
    row("R13 and the package's own rule still fires on the same act", stand_in >= 1,
        "%d listed finding(s) of NET-TOOL" % stand_in)
    print("\nThe probe of a person's rules: %s" % sys.platform)
    for name, state, said in ROWS:
        print("%-7s %s: %s" % (state, name, said))
    return 0


if __name__ == "__main__":
    sys.exit(main())
