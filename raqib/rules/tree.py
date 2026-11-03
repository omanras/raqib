"""HEAD-UNMOVED and INDEX-UNTOUCHED (M4.3, ADR-0002 Amendment J, rulings
J-1 to J-10 of docs/review/2026-11-03-M4.3-ruling.md): the tree as anchor.

Two code rules (J-1), not YAML: each compares a value of a session's
closing line with the same value of its starting line, which no construct
of the rule language does (Q-1 of docs/review/2026-11-03-M4.3-questions.md).
They declare their kinds here, in RULE_KINDS, as cross.py does; the gate
counts them, and report lists them beside the silence rules and
CROSS-SOURCE, class DRIFT, severity medium.

ADR-0002 kind: anchor. The values are the hook's own reading of the files
under cwd/.git at session_start, stop and session_end (git_head,
git_index_sha256, git_error; raqib/hooks/common.py git_state, which runs
nothing): the agent may know these rules; it cannot write the record they
are measured against, only the tree the hook reads (the holes below).

- HEAD-UNMOVED: the session made ok edits and its closing git_head equals
  its starting one: the edits were never committed.
- INDEX-UNTOUCHED: the session made ok edits and its closing
  git_index_sha256 equals its starting one: the edits were never staged.
Both may fire on one session: two facts (J-10).

Per session (J-3, J-4):
- start: the session's first session_start line; close: its last stop or
  session_end line.
- Not judged, no note (J-3): a session whose session_start line carries no
  git keys (a trace written before M4.3, the proxy, the os source), or with
  no session_start and no line with git keys at all; and a session whose
  start and close both say git_error "no repo".
- triggers (J-4): ok posts of Edit, Write, MultiEdit or NotebookEdit whose
  input_meta.path places under the start line's cwd (placed as the YAML
  rules place paths, engine.norm_path: a relative path against its own
  line's cwd). An edit whose path is elsewhere or cannot be read or placed
  is not a trigger (a named hole). A pre of those tools with no post later
  in the trace (SILENCE-HALF's fact) is an unknown trigger.
- unknown (a partial note naming each trigger seq and its cause, A3): a
  trigger before the first session_start ("edit before the start record",
  K-4, never dropped); the session has triggers and no session_start line
  (but git keys elsewhere), no close after the trigger, a start and close
  cwd that differ (J-4), or a value that is null on either side for any
  other git_error (J-3: a capture gap; a git_error outside the closed set
  is never echoed, K-5). An unknown trigger alone, with the value
  unchanged, is unknown.
- finding: at least one trigger before the close, the cwds equal, both
  values read and equal. One finding per session, citing the start, the
  triggers and the close, with the close's ts.

Known holes, listed in HOLES, the README and the THREAT_MODEL (J-10). A
false-positive source, not a hole: an edit of a path git ignores (build
output, .env) or work left for a human to commit is never committed by
design, so the rule fires on it.

FP_BUDGET 0.1 each; the fixtures are in FIXTURES: positive and negative,
which `raqib check-rules` measures (check()), and unknown (no finding, a
partial note) and not_judged (nothing, no note), which the tests assert.
STATUS is active or disabled per rule; a disabled rule writes only a
`disabled` note, and only on a trace it would judge.
"""
from __future__ import annotations

import os

from raqib.rules import engine
from raqib.rules.trace import GIT_ERRORS, HEX40, HEX64, is_record, parse_ts

RULE_HEAD = "HEAD-UNMOVED"
RULE_INDEX = "INDEX-UNTOUCHED"
RULES = (RULE_HEAD, RULE_INDEX)
RULE_KINDS = {RULE_HEAD: "anchor", RULE_INDEX: "anchor"}   # ADR-0002: rule id -> kind; read by the gate (J-1)
CLASS = "DRIFT"
SEVERITY = "medium"
TITLES = {
    RULE_HEAD: "ok edits in a session whose closing git head equals its starting one (never committed)",
    RULE_INDEX: "ok edits in a session whose closing git index equals its starting one (never staged)",
}
FIELDS = {RULE_HEAD: "git_head", RULE_INDEX: "git_index_sha256"}   # the value each rule compares
WHAT = {RULE_HEAD: "committed", RULE_INDEX: "staged"}
FP_BUDGET = {RULE_HEAD: 0.1, RULE_INDEX: 0.1}
STATUS = {RULE_HEAD: "active", RULE_INDEX: "active"}   # active | disabled (A6: a rule above budget is disabled)
EDIT_TOOLS = ("Edit", "Write", "MultiEdit", "NotebookEdit")
GIT_KEYS = ("git_head", "git_index_sha256", "git_error")
CLOSING = ("stop", "session_end")
NO_REPO = "no repo"
FIXTURE_DIR = "tests/fixtures/tree/"
FIXTURES = {
    RULE_HEAD: {
        "positive": [FIXTURE_DIR + "unmoved.json", FIXTURE_DIR + "staged.json", FIXTURE_DIR + "unmoved-windows.json"],
        "negative": [FIXTURE_DIR + "committed.json", FIXTURE_DIR + "outside-cwd.json"],
        "unknown": [FIXTURE_DIR + "unknown-head.json", FIXTURE_DIR + "cwd-moved.json"],
        "not_judged": [FIXTURE_DIR + "no-repo.json", FIXTURE_DIR + "no-git-keys.json"],
    },
    RULE_INDEX: {
        "positive": [FIXTURE_DIR + "unmoved.json", FIXTURE_DIR + "unmoved-windows.json"],
        "negative": [FIXTURE_DIR + "committed.json", FIXTURE_DIR + "staged.json", FIXTURE_DIR + "outside-cwd.json"],
        "unknown": [FIXTURE_DIR + "unknown-index.json", FIXTURE_DIR + "cwd-moved.json"],
        "not_judged": [FIXTURE_DIR + "no-repo.json", FIXTURE_DIR + "no-git-keys.json"],
    },
}
_SHARED = [
    "only cwd/.git is read: a session started in a subdirectory, a second repository, a nested repository or a"
    " submodule edited from the parent's cwd is judged against the cwd's .git or not at all",
    "GIT_DIR, GIT_WORK_TREE, GIT_INDEX_FILE, git -C or --git-dir in the agent's commands act on another"
    " repository or index than the one the hook reads (K-3)",
    "a linked worktree, whose .git file names an absolute gitdir or (worktree.useRelativePaths) a relative one"
    " above the cwd, and a submodule (gitdir: ../.git/modules/<name>) are never followed (J-6, K-2), and a"
    " worktree's commondir is not read (J-7): the session is unknown (partial)",
    "a file system mounted under the project directory (a network share) looks like a directory to the hook,"
    " which reads it as one (K-2)",
    "a Windows device name written with a space before its extension (CON .txt) is not refused by name; it is"
    " lstat'ed and never opened, since it is not a regular file (K-3)",
    "edits whose path is not under the start line's cwd are not triggers: edits outside the repository, in a"
    " second repository, or with no readable path (J-4)",
    "edits made through Bash (sed -i, a redirect, cp, mv) are not triggers: only Edit, Write, MultiEdit and"
    " NotebookEdit are",
    "a session with no stop or session_end after an edit leaves that edit unjudged (partial); SILENCE-OPEN has"
    " the session",
    "an edit before the session's first session_start is unjudged (partial: edit before the start record), never"
    " dropped (K-4)",
    "the start is the session's first session_start line: a session resumed after the human committed or staged"
    " counts that as a move",
]
HOLES = {
    RULE_HEAD: [
        "the rule sees that the head moved, not why: an empty commit, a commit of other files, a checkout or"
        " switch, a reset, or a hash written into .git/HEAD or a ref all count as moved",
        "an unborn branch (no commit yet) is git_error \"no ref\": a session in a fresh repository is unknown"
        " (partial) (J-7)",
        "a symlinked .git or a link below it, a gitdir that is absolute, above the cwd, UNC or a device path, a"
        " head in a SHA-256 repository, or a head not read within 50 ms is null: unknown (partial)",
        "a reftable repository (HEAD names refs/heads/.invalid; its refs are in reftable/, which is not read) is"
        " unreadable: unknown (partial) (K-3)",
        "a packed-refs file over 1 MiB is unreadable: a head that is only there is unknown (partial) (K-3)",
    ] + _SHARED,
    RULE_INDEX: [
        "the index is hashed as raw bytes: git status, git diff or any command that refreshes stat data rewrites"
        " it with nothing staged, and that counts as touched, a false negative (J-9)",
        "staging any file counts, not the edited ones: git add of another file, git add -N, git update-index,"
        " git read-tree",
        "a commit rewrites the index: a commit of other files counts as touched",
        "a repository with no index yet (nothing ever staged) is null: unknown (partial) (J-7)",
        "a symlinked .git or a link below it, a gitdir that is absolute, above the cwd, UNC or a device path, an"
        " index over 64 MiB, or an index not hashed within 50 ms is null: unknown (partial)",
    ] + _SHARED,
}
UNKNOWN_SHOWN = 5
CAUSE_NO_START = "no session_start line"
CAUSE_NO_CLOSE = "no close came"
CAUSE_CWD = "the cwd moved between start and close"
CAUSE_NO_POST = "no post line"
CAUSE_OK = "ok cannot be read"
CAUSE_START_CWD = "the start cwd cannot be placed"
CAUSE_BEFORE_START = "edit before the start record"   # K-4


def _has_git(rec):
    return any(k in rec for k in GIT_KEYS)


def _sessions(records):
    out = {}
    for i, rec in enumerate(records):
        out.setdefault(rec["session_id"], []).append((i, rec))
    return out


def _null_cause(rec, field, where):
    """Why a value is not compared. git_error is named only when it is one
    of the closed set (K-5): a hostile trace's text never reaches a note."""
    error = rec.get("git_error")
    if error is None or not isinstance(error, str):
        named = "-" if error is None else "not in the closed set"
    else:
        named = error if error in GIT_ERRORS else "not in the closed set"
    return "%s null at the %s (git_error %s)" % (field, where, named)


def _value(rec, field):
    """The field's value in the shape the hook writes it (J-2), else None:
    a value that is not 40-hex (git_head) or 64-hex (git_index_sha256) is
    never compared."""
    value = rec.get(field)
    shape = HEX40 if field == "git_head" else HEX64
    return value if isinstance(value, str) and shape.match(value) else None


def _judge(records):
    """{rule id: {"found": [findings], "unknown": [(session_id, seq, cause)],
    "judged": sessions judged}} over trace records (see the module
    docstring). Pure. A session is judged when J-3 does not set it aside,
    whether or not it has triggers."""
    later_posts = {(r["session_id"], r["seq"]) for r in records if r.get("phase") == "post"}
    results = {rid: {"found": [], "unknown": [], "judged": 0} for rid in RULES}
    for sid, lines in _sessions(records).items():
        starts = [(i, r) for i, r in lines if r.get("phase") == "session_start"]
        start_i, start = starts[0] if starts else (None, None)
        if start is not None and not _has_git(start):
            continue   # J-3: written before M4.3, or by the proxy or the os source
        if start is None and not any(_has_git(r) for _, r in lines):
            continue   # J-3: nothing in this session was written with git keys
        closes = [(i, r) for i, r in lines if r.get("phase") in CLOSING and (start_i is None or i > start_i)]
        close_i, close = closes[-1] if closes else (None, None)
        if start is not None and close is not None and start.get("git_error") == NO_REPO \
                and close.get("git_error") == NO_REPO:
            continue   # J-3: no repository at either end
        for rid in RULES:
            results[rid]["judged"] += 1
        root = engine._place(start.get("cwd"), start.get("cwd")) if start is not None else None
        triggers = []   # (index, rec, None for a true trigger, or the cause it is unknown)
        for i, rec in lines:   # every edit line, before the start too (K-4, set aside below)
            if rec.get("tool") not in EDIT_TOOLS or rec.get("phase") not in ("pre", "post"):
                continue
            if rec["phase"] == "pre" and (sid, rec["seq"]) in later_posts:
                continue   # judged on its post
            meta = rec.get("input_meta")
            path = engine._place(meta.get("path") if isinstance(meta, dict) else None, rec.get("cwd"))
            if start is None or root is None:
                if path is not None and (rec["phase"] == "pre" or rec.get("ok") is not False):
                    triggers.append((i, rec, CAUSE_NO_START if start is None else CAUSE_START_CWD))
                continue
            if path is None or not engine._under(path, root):
                continue   # J-4: not a trigger (a named hole)
            if rec["phase"] == "pre":
                triggers.append((i, rec, CAUSE_NO_POST))
            elif rec.get("ok") is True:
                triggers.append((i, rec, None))
            elif not isinstance(rec.get("ok"), bool):
                triggers.append((i, rec, CAUSE_OK))
        # K-4: a trigger before the first session_start is unknown, never dropped.
        before_start = [(i, r, CAUSE_BEFORE_START) for i, r, _ in triggers if start_i is not None and i < start_i]
        triggers = [t for t in triggers if start_i is None or t[0] > start_i]
        if not triggers and not before_start:
            continue
        after = [(i, r, CAUSE_NO_CLOSE) for i, r, _ in triggers if close_i is None or i > close_i]
        before = [(i, r, c) for i, r, c in triggers if close_i is not None and i < close_i]
        for rid in RULES:
            unknown = [(sid, r["seq"], c) for _, r, c in before_start + after]
            res = results[rid]
            if before and start is not None:
                field = FIELDS[rid]
                cause = None
                if engine.norm_path(start.get("cwd")) != engine.norm_path(close.get("cwd")) \
                        or engine.norm_path(start.get("cwd")) is None:
                    cause = CAUSE_CWD
                elif _value(start, field) is None:
                    cause = _null_cause(start, field, "start")
                elif _value(close, field) is None:
                    cause = _null_cause(close, field, "close")
                if cause is not None:
                    unknown += [(sid, r["seq"], c or cause) for _, r, c in before]
                elif _value(start, field) == _value(close, field):
                    true = [r for _, r, c in before if c is None]
                    if true:
                        res["found"].append(_finding(rid, start, true, close))
                    else:
                        unknown += [(sid, r["seq"], c) for _, r, c in before]
            elif before:
                unknown += [(sid, r["seq"], c) for _, r, c in before]
            res["unknown"] += sorted(unknown, key=lambda u: u[1])
    return results


def findings(lines):
    """(findings, notes) of HEAD-UNMOVED and INDEX-UNTOUCHED on trace
    records. Pure. A session not judged (J-3) gives nothing and no note."""
    records = [r for r in lines if is_record(r)]
    results = _judge(records)
    found, notes = [], []
    for rid in RULES:
        res = results[rid]
        if STATUS[rid] == "disabled":
            if res["judged"]:
                notes.append({"rule_id": rid, "status": "disabled",
                              "detail": "STATUS = disabled in raqib/rules/tree.py (A6)"})
            continue
        found += res["found"]
        unknown = res["unknown"]
        if unknown:
            shown = ", ".join("%s:%d (%s)" % u for u in unknown[:UNKNOWN_SHOWN])
            notes.append({"rule_id": rid, "status": "partial",
                          "detail": "could not judge %d line(s) (session:seq %s%s)" % (
                              len(unknown), shown, " ..." if len(unknown) > UNKNOWN_SHOWN else "")})
    order = {}
    for rec in records:
        order.setdefault(rec["session_id"], len(order))
    found.sort(key=lambda f: (order[f["session_id"]], f["cited_seq"][0], f["rule_id"]))
    return found, notes


def check(load, root, benign=()):
    """check-rules' reports for the two rules, in the shape of
    fixtures.check_rule: each positive must fire; a negative, or a benign
    file, is measured only when the rule judged a session of it (J-3: a file
    with no git keys is not judged at all) and left no partial note. load is
    fixtures.load_fixture; paths are relative to root."""
    reports = []
    for rid in RULES:
        positives = []
        for rel in FIXTURES[rid]["positive"]:   # measured whatever its status, as fixtures.check_rule does
            lines = [r for r in load(os.path.join(str(root), rel))[0] if is_record(r)]
            positives.append({"path": rel, "fired": bool(_judge(lines)[rid]["found"]), "missing_seq": []})
        negatives = []
        for path in [os.path.join(str(root), rel) for rel in FIXTURES[rid]["negative"]] + list(benign):
            lines = [r for r in load(path)[0] if is_record(r)]
            res = _judge(lines)[rid]
            fired = bool(res["found"])
            measured = fired or (bool(res["judged"]) and not res["unknown"])
            negatives.append({"path": os.path.relpath(path, str(root)), "fired": fired, "measured": measured})
        measured = [n for n in negatives if n["measured"]]
        fp_rate = sum(n["fired"] for n in measured) / len(measured) if measured else None
        if not all(p["fired"] for p in positives):
            verdict = "positive-missed"
        elif not measured:
            verdict = "unmeasured"
        elif STATUS[rid] == "disabled":
            verdict = "disabled"
        elif fp_rate > FP_BUDGET[rid]:
            verdict = "over-budget"
        else:
            verdict = "ok"
        reports.append({"rule_id": rid, "status": STATUS[rid], "fp_budget": FP_BUDGET[rid], "fp_rate": fp_rate,
                        "measured": len(measured), "unmeasured": len(negatives) - len(measured),
                        "positives": positives, "negatives": negatives, "verdict": verdict})
    return reports


def _finding(rid, start, triggers, close):
    seqs = sorted({start["seq"], close["seq"]} | {r["seq"] for r in triggers})
    return {
        "ts": close["ts"] if parse_ts(close.get("ts")) is not None else None,
        "rule_id": rid,
        "class": CLASS,
        "kind": RULE_KINDS[rid],
        "severity": SEVERITY,
        "session_id": start["session_id"],
        "cited_seq": seqs,
        "summary": "%d edit(s) under the session's cwd and %s unchanged from the session_start at seq %d to the"
                   " %s at seq %d: never %s" % (len(triggers), FIELDS[rid], start["seq"], close.get("phase"),
                                                close["seq"], WHAT[rid]),
    }
