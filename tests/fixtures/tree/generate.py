"""Generate tests/fixtures/tree/*.json (M4.3, ADR-0002 Amendment J): sessions
in the shape raqib/hooks/capture.py writes, whose session_start, stop and
session_end lines carry the git keys (git_head, git_index_sha256,
git_error), for HEAD-UNMOVED and INDEX-UNTOUCHED (raqib/rules/tree.py).

Run from the repository root: python3 tests/fixtures/tree/generate.py
"""
import datetime
import hashlib
import json
import os

T0 = datetime.datetime(2026, 11, 3, 9, 0, 0, tzinfo=datetime.timezone.utc)
CWD = "/work/proj"
D = "tests/fixtures/tree/"
KEYS = ["ts", "seq", "session_id", "phase", "tool", "tool_use_id", "input_sha256", "input_meta",
        "output_sha256", "output_meta", "ok", "error_class", "cwd", "git_head", "git_index_sha256", "git_error",
        "source"]


def h(*x):
    return hashlib.sha256(json.dumps(x, sort_keys=True).encode()).hexdigest()


HEAD_1, HEAD_2 = h("head", 1)[:40], h("head", 2)[:40]
INDEX_1, INDEX_2 = h("index", 1), h("index", 2)


def ts(sec):
    return (T0 + datetime.timedelta(seconds=sec)).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class S:
    def __init__(self, sid, cwd=CWD):
        self.sid, self.seq, self.t, self.lines, self.cwd = sid, 0, 0, [], cwd

    def event(self, phase, head=HEAD_1, index=INDEX_1, error=None, git=True, cwd=None):
        self.seq += 1
        self.t += 1
        rec = {"ts": ts(self.t), "seq": self.seq, "session_id": self.sid, "phase": phase, "tool": "-",
               "cwd": cwd or self.cwd, "source": "hook"}
        if git:
            rec.update(git_head=head, git_index_sha256=index, git_error=error)
        self.lines.append(rec)
        return self.seq

    def call(self, tool, meta, ok=True, post=True):
        self.seq += 1
        base = {"seq": self.seq, "session_id": self.sid, "tool": tool,
                "tool_use_id": "toolu_%s_%d" % (self.sid[-8:], self.seq),
                "input_sha256": h(self.sid, self.seq, tool, meta), "input_meta": meta, "cwd": self.cwd,
                "source": "hook"}
        self.t += 1
        self.lines.append(dict(base, ts=ts(self.t), phase="pre"))
        if post:
            self.t += 2
            self.lines.append(dict(base, ts=ts(self.t), phase="post", output_sha256=h("out", self.sid, self.seq),
                                   output_meta={"scan": "full", "secret_kinds": []}, ok=ok))
        return self.seq

    def bash(self, programs):
        return self.call("Bash", {"command_head": programs[0], "command_programs": programs})


def dump(lines):
    return ",\n".join("  " + json.dumps({k: r[k] for k in KEYS if k in r}, separators=(", ", ": ")) for r in lines)


def write(name, lines):
    path = D + name
    os.makedirs(os.path.dirname(path), exist_ok=True)
    open(path, "w", newline="\n").write("[\n" + dump(lines) + "\n]\n")  # LF on every platform (M5.1)
    print("wrote", path, len(lines))


# Positive for both: an edit, nothing staged, nothing committed; the head and
# the index read the same at session_start, at the turn's stop and at session_end.
s = S("fixture-tree-unmoved")
s.event("session_start"); s.call("Read", {"path": CWD + "/src/app.py"}); s.call("Edit", {"path": CWD + "/src/app.py"})
s.call("Write", {"path": "tests/test_app.py"}); s.bash(["pytest"]); s.event("stop"); s.event("session_end")
write("unmoved.json", s.lines)
# Positive for HEAD-UNMOVED, negative for INDEX-UNTOUCHED: staged, never committed.
s = S("fixture-tree-staged")
s.event("session_start"); s.call("Edit", {"path": CWD + "/src/app.py"}); s.bash(["git"])
s.event("stop", index=INDEX_2); s.event("session_end", index=INDEX_2)
write("staged.json", s.lines)
# Negative for both: staged and committed (an earlier turn's stop still read
# the starting values; the close is the session's last stop or session_end).
s = S("fixture-tree-committed")
s.event("session_start"); s.call("MultiEdit", {"path": CWD + "/src/app.py"}); s.event("stop")
s.call("NotebookEdit", {"path": CWD + "/notes/n.ipynb"}); s.bash(["git"]); s.event("stop", head=HEAD_2, index=INDEX_2)
s.event("session_end", head=HEAD_2, index=INDEX_2)
write("committed.json", s.lines)
# Positive for both on Windows: the edit's path places under the start cwd
# with \ and / alike and in any ASCII case (engine.norm_path, M5.1b).
s = S("fixture-tree-windows", cwd="C:\\Users\\dev\\Proj")
s.event("session_start"); s.call("Edit", {"path": "c:/users/dev/proj/src/app.py"}); s.event("stop")
write("unmoved-windows.json", s.lines)
# Negative for both: the only edits are outside the start cwd (J-4: not
# triggers), and a failed edit inside it is no trigger either.
s = S("fixture-tree-outside")
s.event("session_start"); s.call("Write", {"path": "/tmp/notes.md"}); s.call("Edit", {"path": "/work/other/a.py"})
s.call("Edit", {"path": CWD + "/src/app.py"}, ok=False); s.event("stop"); s.event("session_end")
write("outside-cwd.json", s.lines)
# Unknown for HEAD-UNMOVED (J-3: a null head at the start for another reason
# than "no repo" is a capture gap); INDEX-UNTOUCHED judges it and fires.
s = S("fixture-tree-unknown-head")
s.event("session_start", head=None, error="unreadable"); s.call("Edit", {"path": CWD + "/src/app.py"})
s.event("stop")
write("unknown-head.json", s.lines)
# Unknown for INDEX-UNTOUCHED: the index was not hashed within the budget at
# the close; HEAD-UNMOVED judges it and fires.
s = S("fixture-tree-unknown-index")
s.event("session_start"); s.call("Edit", {"path": CWD + "/src/app.py"}); s.event("stop", index=None, error="budget")
write("unknown-index.json", s.lines)
# Unknown for both (J-4): the close reads another cwd than the start.
s = S("fixture-tree-cwd-moved")
s.event("session_start"); s.call("Edit", {"path": CWD + "/src/app.py"}); s.event("stop", cwd="/work/other")
write("cwd-moved.json", s.lines)
# Not judged, no note (J-3): no repository at either end ...
s = S("fixture-tree-no-repo")
s.event("session_start", head=None, index=None, error="no repo"); s.call("Edit", {"path": CWD + "/a.txt"})
s.event("stop", head=None, index=None, error="no repo")
write("no-repo.json", s.lines)
# ... and a session written before M4.3 (no git keys on its session_start).
s = S("fixture-tree-before-m43")
s.event("session_start", git=False); s.call("Edit", {"path": CWD + "/src/app.py"}); s.event("stop", git=False)
write("no-git-keys.json", s.lines)
