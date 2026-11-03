"""M4.3 the tree as anchor (ADR-0002 Amendment J, rulings J-1 to J-11 of
docs/review/2026-11-03-M4.3-ruling.md): E1 git_state in common.py and the
three keys on the hook's boundary lines, J-2 their shape in trace.py, E2
HEAD-UNMOVED and E3 INDEX-UNTOUCHED in raqib/rules/tree.py, E4 the counts
and the docs."""
import ast
import builtins
import hashlib
import io
import json
import os
import runpy
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from raqib import cli, eval as evaluation, report  # noqa: E402
from raqib.hooks import capture, common  # noqa: E402
from raqib.rules import engine, fixtures, trace, tree  # noqa: E402

CAPTURE = ROOT / "raqib" / "hooks" / "capture.py"
COMMON = ROOT / "raqib" / "hooks" / "common.py"
TREE_FIXTURES = ROOT / "tests" / "fixtures" / "tree"
FILE_TOOLS = ROOT / "tests" / "fixtures" / "file-tools-d7841d1-claude-code-2.1.301.log"
README = (ROOT / "README.md").read_text(encoding="utf-8")
THREAT = (ROOT / "docs" / "THREAT_MODEL.md").read_text(encoding="utf-8")
WINDOWS = os.name == "nt"
HEAD_A = "0123456789abcdef0123456789abcdef01234567"
HEAD_B = "89abcdef0123456789abcdef0123456789abcdef"
INDEX = b"DIRC\x00\x00\x00\x02\x00\x00\x00\x00" + bytes(range(64))
INDEX_SHA = hashlib.sha256(INDEX).hexdigest()
GIT = shutil.which("git")
NEEDS_GIT = pytest.mark.skipif(GIT is None, reason="needs git to build a real repository (the hook runs none)")


def make_repo(root, head="ref: refs/heads/main\n", loose=HEAD_A, packed=None, index=INDEX):
    """A repository as git lays it out on disk, written by hand."""
    make_gitdir(Path(root) / ".git", head, loose, packed, index)
    return Path(root)


def make_gitdir(git, head="ref: refs/heads/main\n", loose=HEAD_A, packed=None, index=INDEX):
    """A gitdir (HEAD, refs, packed-refs, index), written by hand."""
    git = Path(git)
    (git / "refs" / "heads").mkdir(parents=True)
    (git / "HEAD").write_bytes(head.encode() if isinstance(head, str) else head)
    if loose is not None:
        (git / "refs" / "heads" / "main").write_text(loose + "\n")
    if packed is not None:
        (git / "packed-refs").write_text(packed)
    if index is not None:
        (git / "index").write_bytes(index)
    return git


def state(cwd, **kw):
    out = common.git_state(str(cwd), **kw)
    assert list(out) == list(common.GIT_KEYS)
    assert out["git_error"] is None or out["git_error"] in common.GIT_ERRORS
    assert trace.git_problem(dict(out, phase="stop")) is None, out   # the shape J-2 holds
    return out


def can_symlink(tmp_path):
    """Windows needs a privilege (or developer mode) to make a symlink."""
    probe = tmp_path / "probe-target"
    probe.write_text("x")
    try:
        os.symlink(str(probe), str(tmp_path / "probe-link"))
    except (OSError, NotImplementedError):
        return False
    os.remove(str(tmp_path / "probe-link"))
    return True


# --- E1 git_state: what it reads ---------------------------------------------------

def test_e1_a_repository_on_a_branch_gives_the_head_and_the_index_hash(tmp_path):
    assert state(make_repo(tmp_path)) == {"git_head": HEAD_A, "git_index_sha256": INDEX_SHA, "git_error": None}


def test_e1_a_detached_head_is_read_from_head_itself(tmp_path):
    repo = make_repo(tmp_path, head=HEAD_B + "\n", loose=None)
    assert state(repo) == {"git_head": HEAD_B, "git_index_sha256": INDEX_SHA, "git_error": None}


def test_e1_the_ref_comes_from_packed_refs_when_there_is_no_loose_file(tmp_path):
    packed = ("# pack-refs with: peeled fully-peeled sorted \n%s refs/heads/feature\n^%s\n%s refs/heads/main\n"
              % (HEAD_B, HEAD_A, HEAD_A))
    assert state(make_repo(tmp_path, loose=None, packed=packed))["git_head"] == HEAD_A
    # The loose file wins over packed-refs, as in git.
    other = tmp_path / "other"
    assert state(make_repo(other, loose=HEAD_B, packed=packed))["git_head"] == HEAD_B


def test_e1_j7_an_unborn_branch_is_no_ref_and_the_index_is_still_read(tmp_path):
    assert state(make_repo(tmp_path, loose=None)) == {"git_head": None, "git_index_sha256": INDEX_SHA,
                                                      "git_error": "no ref"}
    packed = "%s refs/heads/other\n" % HEAD_B
    assert state(make_repo(tmp_path / "p", loose=None, packed=packed))["git_error"] == "no ref"


def test_e1_j7_a_missing_index_is_no_index_and_the_head_is_kept(tmp_path):
    assert state(make_repo(tmp_path, index=None)) == {"git_head": HEAD_A, "git_index_sha256": None,
                                                      "git_error": "no index"}


def test_e1_j5_the_first_failure_is_named(tmp_path):
    # A fresh `git init`: no ref and no index; the head's failure comes first.
    assert state(make_repo(tmp_path, loose=None, index=None)) == {"git_head": None, "git_index_sha256": None,
                                                                  "git_error": "no ref"}


def test_e1_no_repo_and_nothing_walks_up_from_cwd(tmp_path):
    assert state(tmp_path) == {"git_head": None, "git_index_sha256": None, "git_error": "no repo"}
    repo = make_repo(tmp_path / "repo")
    (repo / "src").mkdir()
    assert state(repo / "src")["git_error"] == "no repo"
    assert state(tmp_path / "missing")["git_error"] == "no repo"
    assert common.git_state(None)["git_error"] == "no repo"
    assert common.git_state("")["git_error"] == "no repo"
    assert common.git_state("bad\0cwd")["git_error"] == "unreadable"


def test_e1_k2_a_relative_gitdir_under_the_cwd_is_followed_once(tmp_path):
    """K-2 (amends J-6): followed only when it resolves under the cwd."""
    make_gitdir(tmp_path / "inner" / "gd")
    (tmp_path / ".git").write_text("gitdir: inner/gd\n")
    assert state(tmp_path) == {"git_head": HEAD_A, "git_index_sha256": INDEX_SHA, "git_error": None}
    (tmp_path / ".git").write_bytes(b"gitdir: inner/../inner/gd \r\n")   # .. inside, CRLF and a trailing space
    assert state(tmp_path)["git_head"] == HEAD_A
    # Followed once: a gitdir that is itself a .git file is not followed.
    (tmp_path / "inner" / "file").write_text("gitdir: gd\n")
    (tmp_path / ".git").write_text("gitdir: inner/file\n")
    assert state(tmp_path)["git_error"] == "gitdir"


def test_e1_k5_gitdir_dot_is_the_cwd_and_dot_dot_is_refused(tmp_path):
    proj = tmp_path / "proj"
    make_gitdir(proj)                           # HEAD, refs, index in the cwd itself
    (proj / ".git").write_text("gitdir: .\n")
    assert state(proj) == {"git_head": HEAD_A, "git_index_sha256": INDEX_SHA, "git_error": None}
    make_gitdir(tmp_path / "up")
    for text in ("gitdir: ..", "gitdir: ../up", "gitdir: sub/../..", "gitdir: ./../up"):
        (proj / ".git").write_text(text + "\n")
        assert state(proj) == {"git_head": None, "git_index_sha256": None, "git_error": "gitdir"}, text


def test_e1_k2_a_submodule_and_a_linked_worktree_are_never_followed(tmp_path, monkeypatch):
    """Their gitdir lies above the cwd: `../.git/modules/sub`, an absolute
    worktree gitdir, and a relative one (worktree.useRelativePaths). Nothing
    above the cwd is touched."""
    make_gitdir(tmp_path / "super" / ".git" / "modules" / "sub")
    make_gitdir(tmp_path / "main" / ".git" / "worktrees" / "wt")
    cases = {tmp_path / "super" / "sub": "../.git/modules/sub",
             tmp_path / "wt-abs": str(tmp_path / "main" / ".git" / "worktrees" / "wt"),
             tmp_path / "wt-rel": "../main/.git/worktrees/wt"}
    for cwd, target in cases.items():
        cwd.mkdir()
        (cwd / ".git").write_text("gitdir: %s\n" % target)
        seen = []
        real = os.lstat
        monkeypatch.setattr(os, "lstat", lambda path, *a, **k: (seen.append(os.fspath(path)), real(path, *a, **k))[1])
        assert state(cwd) == {"git_head": None, "git_index_sha256": None, "git_error": "gitdir"}, target
        monkeypatch.setattr(os, "lstat", real)
        assert seen == [str(cwd / ".git")], seen


@pytest.mark.parametrize("text", [
    "gitdir:../x", "gitdir ../x", "../x", "gitdir: ", "gitdir: ../x\ngitdir: ../y", "gitdir: ../x\rmore",
    "gitdir: /abs/path/.git/worktrees/wt", "gitdir: \\\\host\\share\\x", "gitdir: //host/share/x",
    "gitdir: \\\\?\\C:\\x", "gitdir: \\\\.\\pipe\\x", "gitdir: C:\\x", "gitdir: C:x", "gitdir: \\x",
    "gitdir: x:stream", "gitdir: NUL", "gitdir: ../CON.txt", "gitdir: sub/com1", "gitdir: lpt9 .",
    "gitdir: ../missing", "gitdir: x\0y",
], ids=["no-space", "no-colon", "bare-path", "empty", "two-lines", "cr-inside", "absolute-worktree", "unc",
        "unc-forward", "device-drive", "device-pipe", "drive", "drive-relative", "rooted", "stream", "nul-device",
        "con-device", "com-device", "lpt-device", "missing-target", "nul-char"])
def test_e1_j6_a_gitdir_that_is_not_relative_safe_and_there_is_gitdir(tmp_path, text):
    (tmp_path / ".git").write_bytes(text.encode("utf-8"))
    assert state(tmp_path) == {"git_head": None, "git_index_sha256": None, "git_error": "gitdir"}


def test_e1_j6_a_non_utf8_or_oversized_git_file_is_gitdir(tmp_path):
    (tmp_path / ".git").write_bytes(b"gitdir: \xff\xfe\n")
    assert state(tmp_path)["git_error"] == "gitdir"
    (tmp_path / ".git").write_bytes(b"gitdir: " + b"a" * common.GIT_FILE_MAX)
    assert state(tmp_path)["git_error"] == "gitdir"


@pytest.mark.parametrize("target", ["\\\\host\\share\\x", "//host/share/x"], ids=["backslash-unc", "forward-unc"])
def test_e1_j6_a_git_file_naming_a_network_path_opens_nothing_there(tmp_path, monkeypatch, target):
    """Rule 5 (no network from capture): the UNC path a planted .git file
    names is refused lexically, so no lstat, stat or open ever touches it
    (on Windows any of them would connect to the host over SMB)."""
    (tmp_path / ".git").write_text("gitdir: %s\n" % target)
    seen = []

    def spy(name, real):
        def wrapped(path, *a, **k):
            seen.append((name, os.fspath(path) if isinstance(path, (str, bytes, os.PathLike)) else repr(path)))
            return real(path, *a, **k)
        return wrapped

    for module, name in ((os, "lstat"), (os, "stat"), (os, "open"), (builtins, "open"), (os, "listdir"),
                         (os, "scandir"), (os.path, "exists"), (os.path, "isdir"), (os.path, "isfile"),
                         (os.path, "realpath")):
        monkeypatch.setattr(module, name, spy(name, getattr(module, name)))
    out = common.git_state(str(tmp_path))
    assert out == {"git_head": None, "git_index_sha256": None, "git_error": "gitdir"}
    assert seen, "the .git file itself is read"
    assert not [s for s in seen if "host" in str(s[1])], seen
    assert {os.path.basename(str(p)) for _, p in seen} == {".git"}


def test_e1_j6_no_symlink_is_followed_at_any_component(tmp_path):
    if not can_symlink(tmp_path):
        pytest.skip("this host cannot create symlinks")
    real = make_repo(tmp_path / "real")
    linked = tmp_path / "linked"
    linked.mkdir()
    os.symlink(str(real / ".git"), str(linked / ".git"), target_is_directory=True)
    assert state(linked) == {"git_head": None, "git_index_sha256": None, "git_error": "symlink"}
    cases = {
        "HEAD": lambda g: (os.remove(str(g / "HEAD")), os.symlink(str(tmp_path / "real" / ".git" / "HEAD"),
                                                                   str(g / "HEAD"))),
        "ref": lambda g: (os.remove(str(g / "refs" / "heads" / "main")),
                          os.symlink(str(real / ".git" / "refs" / "heads" / "main"), str(g / "refs" / "heads" / "main"))),
        "ref-dir": lambda g: (shutil.rmtree(str(g / "refs" / "heads")),
                              os.symlink(str(real / ".git" / "refs" / "heads"), str(g / "refs" / "heads"),
                                         target_is_directory=True)),
        "index": lambda g: (os.remove(str(g / "index")), os.symlink(str(real / ".git" / "index"), str(g / "index"))),
    }
    expected = {"HEAD": (None, INDEX_SHA), "ref": (None, INDEX_SHA), "ref-dir": (None, INDEX_SHA),
                "index": (HEAD_A, None)}
    for name, plant in cases.items():
        repo = make_repo(tmp_path / ("case-" + name))
        plant(repo / ".git")
        out = state(repo)
        assert (out["git_head"], out["git_index_sha256"], out["git_error"]) == expected[name] + ("symlink",), name
    packed = make_repo(tmp_path / "case-packed", loose=None)
    (real / "packed.txt").write_text("%s refs/heads/main\n" % HEAD_A)
    os.symlink(str(real / "packed.txt"), str(packed / ".git" / "packed-refs"))
    assert state(packed)["git_error"] == "symlink"
    # The gitdir a .git file names: a link in its path is not followed either.
    sub = tmp_path / "sub"
    (sub / "links").mkdir(parents=True)
    os.symlink(str(real / ".git"), str(sub / "links" / "gitlink"), target_is_directory=True)
    (sub / ".git").write_text("gitdir: links/gitlink\n")
    assert state(sub)["git_error"] == "symlink"
    os.symlink(str(real / ".git"), str(sub / "dirlink"), target_is_directory=True)
    (sub / ".git").write_text("gitdir: dirlink/../dirlink\n")   # lexical: dirlink is lstat'ed, a link
    assert state(sub)["git_error"] == "symlink"


@pytest.mark.skipif(not WINDOWS, reason="junctions are Windows'")
def test_e1_j6_a_junction_is_a_link_too(tmp_path):
    import _winapi
    real = make_repo(tmp_path / "real")
    linked = tmp_path / "linked"
    linked.mkdir()
    _winapi.CreateJunction(str(real / ".git"), str(linked / ".git"))
    assert state(linked) == {"git_head": None, "git_index_sha256": None, "git_error": "symlink"}


@pytest.mark.parametrize("head", [
    "garbage\n", "ref: refs/heads/../../../etc/passwd\n", "ref: ../x\n", "ref: heads/main\n", "ref: refs\n",
    "ref: refs/heads/.hidden\n", "ref: refs/heads/x.lock\n", "ref: refs/heads/a..b\n", "ref: refs/heads/x@{1}\n",
    "ref: refs/heads/a b\n", "ref: refs/heads/a\\b\n", "ref: refs/heads/CON\n", HEAD_A.upper() + "\n",
    HEAD_A[:39] + "\n", "a" * 64 + "\n",
], ids=["garbage", "climbing", "outside-refs", "no-refs", "refs-only", "dot-part", "lock", "dot-dot", "reflog",
        "space", "backslash", "device", "upper-hex", "short-hex", "sha256-head"])
def test_e1_a_head_that_is_not_a_head_or_a_safe_ref_is_unreadable(tmp_path, head):
    out = state(make_repo(tmp_path, head=head))
    assert (out["git_head"], out["git_index_sha256"], out["git_error"]) == (None, INDEX_SHA, "unreadable")


@pytest.mark.parametrize("loose", ["ref: refs/heads/other", "a" * 64, "not hex"], ids=["symref", "sha256", "text"])
def test_e1_a_loose_ref_that_is_not_40_hex_is_unreadable(tmp_path, loose):
    assert state(make_repo(tmp_path, loose=loose))["git_error"] == "unreadable"


def test_e1_a_packed_ref_that_is_not_40_hex_is_unreadable(tmp_path):
    assert state(make_repo(tmp_path, loose=None, packed="%s refs/heads/main\n" % ("a" * 64)))["git_error"] == "unreadable"


def test_e1_j8_files_over_their_caps(tmp_path, monkeypatch):
    big = make_repo(tmp_path / "head", head=b"ref: refs/heads/main\n" + b" " * common.GIT_FILE_MAX)
    assert state(big)["git_error"] == "unreadable"
    packed = make_repo(tmp_path / "packed", loose=None,
                       packed="# x\n" + "#" * common.GIT_FILE_MAX + "\n%s refs/heads/main\n" % HEAD_A)
    assert state(packed)["git_error"] == "unreadable"
    monkeypatch.setattr(common, "GIT_INDEX_MAX", len(INDEX) - 1)
    assert state(make_repo(tmp_path / "index")) == {"git_head": HEAD_A, "git_index_sha256": None,
                                                    "git_error": "index too large"}
    monkeypatch.setattr(common, "GIT_INDEX_MAX", len(INDEX))
    assert state(make_repo(tmp_path / "index-at-cap"))["git_index_sha256"] == INDEX_SHA


def test_e1_j8_a_read_stops_at_cap_plus_one_byte(tmp_path):
    path = tmp_path / "f"
    path.write_bytes(b"x" * 10)
    got = []
    assert common._git_read(str(path), os.lstat(str(path)), 4, lambda: None, got.append) == 5
    assert b"".join(got) == b"xxxxx"
    got = []
    assert common._git_read(str(path), os.lstat(str(path)), 10, lambda: None, got.append) == 10


def test_e1_j8_the_budget_is_one_monotonic_clock_per_call(tmp_path):
    import inspect
    assert common.GIT_BUDGET_SECONDS == 0.05
    assert inspect.signature(common.git_state).parameters["clock"].default is time.monotonic
    repo = make_repo(tmp_path)
    real_head, real_index = common._git_head, common._git_index

    def run(late):
        """git_state with a clock that runs out as the step `late` begins."""
        over = [False]

        def spend(step):
            def wrapped(*a, **k):
                over[0] = True
                return step(*a, **k)
            return wrapped
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(common, late, spend(real_head if late == "_git_head" else real_index))
            return state(repo, clock=lambda: 0.06 if over[0] else 0.0)
    # Over the budget before HEAD is read: nothing is read.
    assert run("_git_head") == {"git_head": None, "git_index_sha256": None, "git_error": "budget"}
    # Over the budget as the index is hashed: the head read in time is kept.
    assert run("_git_index") == {"git_head": HEAD_A, "git_index_sha256": None, "git_error": "budget"}
    assert state(repo, clock=lambda: 0.0) == {"git_head": HEAD_A, "git_index_sha256": INDEX_SHA, "git_error": None}


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs are POSIX")
def test_e1_a_fifo_or_a_directory_in_place_of_a_file_is_not_read(tmp_path):
    repo = make_repo(tmp_path / "fifo")
    os.remove(str(repo / ".git" / "index"))
    os.mkfifo(str(repo / ".git" / "index"))
    started = time.monotonic()
    assert state(repo) == {"git_head": HEAD_A, "git_index_sha256": None, "git_error": "unreadable"}
    assert time.monotonic() - started < 2, "the hook must not wait on a FIFO"
    os.mkfifo(str(tmp_path / ".git"))
    assert state(tmp_path)["git_error"] == "unreadable"


def test_e1_a_directory_in_place_of_head_is_unreadable(tmp_path):
    repo = make_repo(tmp_path)
    os.remove(str(repo / ".git" / "HEAD"))
    (repo / ".git" / "HEAD").mkdir()
    assert state(repo)["git_error"] == "unreadable"
    os.rmdir(str(repo / ".git" / "HEAD"))
    assert state(repo)["git_error"] == "unreadable"   # no HEAD at all


def test_e1_j8_each_file_is_opened_once_and_only_the_listed_files(tmp_path, monkeypatch):
    repo = make_repo(tmp_path, loose=None, packed="%s refs/heads/main\n" % HEAD_A)
    opened = []
    real_open = os.open
    monkeypatch.setattr(os, "open", lambda path, *a, **k: (opened.append(os.path.relpath(path, str(repo))),
                                                            real_open(path, *a, **k))[1])
    assert state(repo)["git_head"] == HEAD_A
    assert sorted(opened) == sorted(os.path.join(".git", n) for n in ("HEAD", "packed-refs", "index"))


@pytest.mark.parametrize("error", [OSError("x"), PermissionError("x"), ValueError("x"), UnicodeDecodeError(
    "utf-8", b"\xff", 0, 1, "x"), RecursionError("x"), MemoryError("x")],
    ids=["OSError", "PermissionError", "ValueError", "UnicodeError", "RecursionError", "MemoryError"])
def test_e1_k1_only_read_errors_are_unreadable(tmp_path, monkeypatch, error):
    repo = make_repo(tmp_path)

    def boom(*a, **k):
        raise error
    monkeypatch.setattr(common, "_git_index", boom)
    assert state(repo) == {"git_head": HEAD_A, "git_index_sha256": None, "git_error": "unreadable"}
    monkeypatch.setattr(common, "_git_dir", boom)
    assert state(repo) == {"git_head": None, "git_index_sha256": None, "git_error": "unreadable"}
    assert common.GIT_READ_ERRORS == (OSError, ValueError, UnicodeError, RecursionError, MemoryError)


@pytest.mark.parametrize("error", [RuntimeError("anything"), KeyError("x"), capture.Deadline("capture did not"
                                                                                             " finish within 8s")],
                         ids=["RuntimeError", "KeyError", "Deadline"])
def test_e1_k1_any_other_exception_propagates(tmp_path, monkeypatch, error):
    repo = make_repo(tmp_path)

    def boom(*a, **k):
        raise error
    monkeypatch.setattr(common, "_git_read", boom)
    with pytest.raises(type(error)):
        common.git_state(str(repo))


@pytest.mark.parametrize("error", ["deadline", "unexpected"])
def test_e1_k1_an_exception_inside_a_read_ends_the_capture_with_one_silence_line(tmp_path, monkeypatch, capsys,
                                                                                error):
    """A3 (capture.py's invariant): a Deadline raised from inside git_state's
    read, or any exception it does not catch, makes the hook write its one
    RAQIB-SILENCE line, exit 0, and no record."""
    repo = make_repo(tmp_path / "repo")
    log = tmp_path / "t.jsonl"

    def boom(*a, **k):
        raise capture.deadline_error() if error == "deadline" else RuntimeError("an unexpected failure")
    monkeypatch.setattr(common, "_git_read", boom)
    stdin = io.TextIOWrapper(io.BytesIO(json.dumps(payload("Stop", repo)).encode()))
    monkeypatch.setattr(sys, "stdin", stdin)
    assert capture.main([str(log)]) == 0
    out, err = capsys.readouterr()
    assert out == "" and len(err.splitlines()) == 1, err
    want = "Deadline: capture did not finish within 8s" if error == "deadline" else "RuntimeError: an unexpected failure"
    assert err.startswith("RAQIB-SILENCE: capture failed event=Stop") and want in err, err
    assert not log.exists() or log.read_text() == ""


def test_e1_k5_eloop_at_open_is_symlink(tmp_path, monkeypatch):
    import errno
    repo = make_repo(tmp_path)
    real = os.open

    def opener(path, *a, **k):
        if os.path.basename(path) == "HEAD":
            raise OSError(errno.ELOOP, "Too many levels of symbolic links")
        return real(path, *a, **k)
    monkeypatch.setattr(os, "open", opener)
    assert state(repo) == {"git_head": None, "git_index_sha256": INDEX_SHA, "git_error": "symlink"}


def test_e1_k5_a_non_regular_file_at_fstat_is_unreadable(tmp_path, monkeypatch):
    repo = make_repo(tmp_path)
    real = os.fstat
    fifo = os.stat_result((stat.S_IFIFO | 0o644, 0, 0, 1, 0, 0, 0, 0, 0, 0))
    monkeypatch.setattr(os, "fstat", lambda fd: fifo)
    assert state(repo) == {"git_head": None, "git_index_sha256": None, "git_error": "unreadable"}
    monkeypatch.setattr(os, "fstat", real)
    assert state(repo)["git_error"] is None


def test_e1_k5_a_ref_naming_a_directory_and_a_file_in_the_middle_go_to_packed_refs(tmp_path):
    repo = make_repo(tmp_path / "dir", loose=None, packed="%s refs/heads/main\n" % HEAD_B)
    (repo / ".git" / "refs" / "heads" / "main").mkdir()   # refs/heads/main/x exists as a loose ref, main does not
    assert state(repo)["git_head"] == HEAD_B
    os.remove(str(repo / ".git" / "packed-refs"))
    assert state(repo)["git_error"] == "no ref"
    mid = make_repo(tmp_path / "mid", head="ref: refs/heads/feature/x\n", loose=None)
    (mid / ".git" / "refs" / "heads" / "feature").write_text("a file, not a directory\n")
    assert state(mid)["git_error"] == "no ref"
    (mid / ".git" / "packed-refs").write_text("%s refs/heads/feature/x\n" % HEAD_A)
    assert state(mid)["git_head"] == HEAD_A


@pytest.mark.parametrize("where", ["HEAD", "ref", "packed-refs"])
def test_e1_k5_invalid_utf8_is_unreadable(tmp_path, where):
    if where == "HEAD":
        repo = make_repo(tmp_path, head=b"ref: refs/heads/\xff\n")
    elif where == "ref":
        repo = make_repo(tmp_path, loose=None)
        (repo / ".git" / "refs" / "heads" / "main").write_bytes(b"\xfe" * 40 + b"\n")
    else:
        repo = make_repo(tmp_path, loose=None)
        (repo / ".git" / "packed-refs").write_bytes(b"%s refs/heads/main\n\xff\n" % HEAD_A.encode())
    assert state(repo) == {"git_head": None, "git_index_sha256": INDEX_SHA, "git_error": "unreadable"}


def test_e1_k5_k6_a_budget_spent_before_the_first_open_opens_nothing(tmp_path, monkeypatch):
    repo = make_repo(tmp_path)
    calls = []
    for name in ("lstat", "open"):
        real = getattr(os, name)
        monkeypatch.setattr(os, name, (lambda real, name: lambda path, *a, **k: (calls.append((name, path)),
                                                                                   real(path, *a, **k))[1])(real, name))
    ticks = iter([0.0])
    out = common.git_state(str(repo), clock=lambda: next(ticks, 0.06))
    assert out == {"git_head": None, "git_index_sha256": None, "git_error": "budget"} and calls == []


def test_e1_k6_the_budget_is_checked_before_each_lstat_of_a_walk(tmp_path, monkeypatch):
    """The budget runs out after the HEAD file is read: the ref's first
    component (refs) is never lstat'ed."""
    repo = make_repo(tmp_path)
    seen = []
    over = [False]
    real_lstat, real_read = os.lstat, os.read
    monkeypatch.setattr(os, "lstat", lambda path, *a, **k: (seen.append(os.path.basename(path)),
                                                             real_lstat(path, *a, **k))[1])

    def read(fd, n):
        over[0] = True   # HEAD is the first file read
        return real_read(fd, n)
    monkeypatch.setattr(os, "read", read)
    out = common.git_state(str(repo), clock=lambda: 0.06 if over[0] else 0.0)
    assert out == {"git_head": None, "git_index_sha256": None, "git_error": "budget"}
    assert seen == [".git", "HEAD"], seen


@pytest.mark.skipif(not WINDOWS, reason="junctions are Windows'")
def test_e1_k5_a_junction_below_dot_git_is_a_link(tmp_path):
    import _winapi
    real = make_repo(tmp_path / "real")
    repo = make_repo(tmp_path / "repo")
    shutil.rmtree(str(repo / ".git" / "refs" / "heads"))
    _winapi.CreateJunction(str(real / ".git" / "refs" / "heads"), str(repo / ".git" / "refs" / "heads"))
    assert state(repo) == {"git_head": None, "git_index_sha256": INDEX_SHA, "git_error": "symlink"}


@NEEDS_GIT
def test_e1_against_a_real_repository(tmp_path):
    repo = tmp_path / "repo"
    git = [GIT, "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c",
           "commit.gpgsign=false"]
    subprocess.run([GIT, "init", "-q", str(repo)], check=True)
    (repo / "a.txt").write_text("a\n")
    subprocess.run(git + ["add", "a.txt"], check=True)
    subprocess.run(git + ["commit", "-q", "-m", "one"], check=True)
    head = subprocess.run(git + ["rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
    index = hashlib.sha256((repo / ".git" / "index").read_bytes()).hexdigest()
    assert state(repo) == {"git_head": head, "git_index_sha256": index, "git_error": None}
    subprocess.run(git + ["pack-refs", "--all"], check=True)
    assert state(repo)["git_head"] == head


# --- E1: the hook executes nothing ---------------------------------------------------

GIT_SECTION_START = "# --- M4.3 git_state"


def git_section():
    source = COMMON.read_text(encoding="utf-8")
    assert source.count(GIT_SECTION_START) == 1
    return source.split(GIT_SECTION_START, 1)[1].split("\n", 1)[1]


def test_e1_no_execution_is_reachable_from_git_state():
    """No subprocess, os.system, os.popen, exec, eval, fork or spawn: by AST
    over every function of the git section, and common.py imports none of
    the modules that run programs."""
    module = ast.parse(COMMON.read_text(encoding="utf-8"))
    imported = {a.name.split(".")[0] for n in ast.walk(module) if isinstance(n, ast.Import) for a in n.names}
    imported |= {n.module.split(".")[0] for n in ast.walk(module) if isinstance(n, ast.ImportFrom) and n.module}
    assert not imported & {"subprocess", "multiprocessing", "importlib", "ctypes", "pty", "runpy"}, imported
    section = ast.parse(git_section())
    names = {n.name for n in section.body if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
    assert {"git_state", "_git_dir", "_git_follow", "_git_head", "_git_index", "_git_read"} <= names
    banned_attrs = {"system", "popen", "startfile", "fork", "forkpty", "posix_spawn", "posix_spawnp", "Popen", "run",
                    "call", "check_call", "check_output"}
    for node in ast.walk(section):
        if isinstance(node, ast.Attribute):
            assert node.attr not in banned_attrs and not node.attr.startswith(("exec", "spawn")), node.attr
        if isinstance(node, ast.Name):
            assert node.id not in {"exec", "eval", "compile", "__import__", "subprocess", "importlib"}, node.id
        assert not isinstance(node, (ast.Import, ast.ImportFrom))
    # The only calls on os are the reads J-6 and J-8 allow.
    os_calls = {n.func.attr for n in ast.walk(section) if isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name) and n.func.value.id == "os"}
    assert os_calls <= {"lstat", "open", "fstat", "read", "close"}, os_calls


def test_e1_no_execution_at_run_time(tmp_path, monkeypatch):
    def forbidden(*a, **k):
        raise AssertionError("git_state must not run anything")

    for module, name in ((builtins, "exec"), (builtins, "eval"), (os, "system"),
                         (os, "popen"), (os, "execv"), (os, "execvp"), (os, "fork"), (os, "spawnv"),
                         (os, "startfile"), (subprocess, "Popen"), (subprocess, "run")):
        if hasattr(module, name):
            monkeypatch.setattr(module, name, forbidden)
    assert state(make_repo(tmp_path))["git_head"] == HEAD_A


def test_e1_j10_common_names_git_state_as_its_one_file_reader():
    doc = " ".join(common.__doc__.split())
    assert "Pure but for git_state" in doc and "git_state is this file's one file reader (J-10)" in doc
    assert "the proxy never does" in doc
    assert "git_state" not in (ROOT / "raqib" / "hooks" / "proxy.py").read_text(encoding="utf-8")
    assert capture.git_state is common.git_state and capture.GIT_KEYS == common.GIT_KEYS


def test_j5_the_closed_set_is_one_set():
    assert common.GIT_ERRORS == trace.GIT_ERRORS == ("no repo", "symlink", "gitdir", "unreadable", "no ref",
                                                     "no index", "index too large", "budget")
    assert common.GIT_KEYS == trace.GIT_KEYS == tree.GIT_KEYS == ("git_head", "git_index_sha256", "git_error")


# --- E1: the hook writes the keys on the three boundary lines --------------------------

def run_hook(payloads, log, cwd):
    env = {k: v for k, v in os.environ.items() if not k.startswith("RAQIB_")}
    for p in payloads:
        proc = subprocess.run([sys.executable, "-I", str(CAPTURE), str(log)], input=json.dumps(p).encode(),
                              capture_output=True, env=env, cwd=str(cwd), timeout=30)
        assert (proc.returncode, proc.stdout, proc.stderr) == (0, b"", b""), proc
    return [json.loads(x) for x in Path(log).read_text(encoding="utf-8").splitlines()]


def payload(event, cwd, session="tree-hook", **extra):
    return dict({"session_id": session, "transcript_path": "/tmp/t.jsonl", "cwd": str(cwd),
                 "hook_event_name": event}, **extra)


def edit(event, cwd, path, use_id="toolu_1", **extra):
    return payload(event, cwd, tool_name="Edit", tool_input={"file_path": str(path), "old_string": "a",
                                                             "new_string": "b"}, tool_use_id=use_id, **extra)


def test_e1_the_hook_writes_the_three_keys_on_boundary_lines_only(tmp_path):
    repo = make_repo(tmp_path / "repo")
    recs = run_hook([payload("SessionStart", repo, source="startup"), edit("PreToolUse", repo, repo / "a.txt"),
                     edit("PostToolUse", repo, repo / "a.txt", tool_response={"filePath": "a.txt"}),
                     payload("Stop", repo, stop_hook_active=False), payload("SessionEnd", repo, reason="exit")],
                    tmp_path / "t.jsonl", tmp_path)
    for rec in recs:
        assert trace.strict_problem(rec) is None, rec
        if rec["phase"] in ("session_start", "stop", "session_end"):
            assert (rec["git_head"], rec["git_index_sha256"], rec["git_error"]) == (HEAD_A, INDEX_SHA, None)
            keys = list(rec)
            assert keys[keys.index("cwd"):] == ["cwd", "git_head", "git_index_sha256", "git_error", "source"]
        else:
            assert not set(rec) & set(common.GIT_KEYS), rec
    # The record holds no path or ref name of the repository: only the values.
    text = (tmp_path / "t.jsonl").read_text(encoding="utf-8")
    assert "refs/heads" not in text and "main" not in text


def test_e1_the_keys_are_read_before_the_lock_in_prepare(tmp_path):
    repo = make_repo(tmp_path)
    parts = capture.prepare(payload("Stop", repo))
    assert parts["git"] == {"git_head": HEAD_A, "git_index_sha256": INDEX_SHA, "git_error": None}
    assert "git" not in capture.prepare(edit("PreToolUse", repo, repo / "a.txt"))


def test_e1_the_hook_reads_the_cwd_of_the_payload(tmp_path):
    repo = make_repo(tmp_path / "repo")
    recs = run_hook([payload("Stop", repo)], tmp_path / "t.jsonl", tmp_path)   # the process runs elsewhere
    assert recs[0]["git_head"] == HEAD_A
    recs = run_hook([payload("Stop", tmp_path / "nowhere", session="s2")], tmp_path / "u.jsonl", repo)
    assert (recs[0]["git_head"], recs[0]["git_error"]) == (None, "no repo")


# --- J-2: trace.py holds the shape -------------------------------------------------

BOUNDARY = {"ts": "2026-11-03T09:00:01.000Z", "seq": 1, "session_id": "s", "phase": "stop", "tool": "-",
            "cwd": "/work/proj", "git_head": HEAD_A, "git_index_sha256": INDEX_SHA, "git_error": None}


@pytest.mark.parametrize("change, problem", [
    ({}, None),
    ({"git_head": None, "git_error": "no ref"}, None),
    ({"git_head": None, "git_index_sha256": None, "git_error": "no repo"}, None),
    ({"phase": "session_start"}, None),
    ({"phase": "session_end"}, None),
    ({"phase": "pre", "tool": "Edit", "input_meta": {}}, "git keys only on session_start, stop and session_end lines"),
    ({"git_error": "no index", "git_index_sha256": None, "git_head": None}, None),
    ({"git_head": HEAD_A.upper()}, "git_head must be 40 lower-case hex digits or null"),
    ({"git_head": HEAD_A[:39]}, "git_head must be 40 lower-case hex digits or null"),
    ({"git_head": 7}, "git_head must be 40 lower-case hex digits or null"),
    ({"git_index_sha256": INDEX_SHA[:63]}, "git_index_sha256 must be 64 lower-case hex digits or null"),
    ({"git_error": "timeout", "git_head": None}, "git_error must be one of no repo, symlink, gitdir"),
    ({"git_error": "budget"}, "git_error must be null exactly when git_head and git_index_sha256 are both read"),
    ({"git_head": None}, "git_error must be null exactly when git_head and git_index_sha256 are both read"),
], ids=["read", "no-ref", "no-repo", "start", "end", "on-a-pre", "no-index", "upper", "short", "not-a-string",
        "short-index", "unknown-error", "error-with-both", "null-without-error"])
def test_j2_strict_problem_checks_the_git_keys(change, problem):
    rec = dict(BOUNDARY, **change)
    got = trace.strict_problem(rec)
    assert (got is None) if problem is None else (got is not None and got.startswith(problem)), got


def test_j2_the_keys_come_together_and_are_known_fields():
    assert set(common.GIT_KEYS) <= set(trace.FIELDS)
    rec = {k: v for k, v in BOUNDARY.items() if k != "git_error"}
    assert trace.strict_problem(rec) == "git keys come together: git_head, git_index_sha256 without git_error"
    assert trace.strict_problem({k: v for k, v in BOUNDARY.items() if not k.startswith("git_")}) is None


def test_j2_a_json_fixture_with_the_keys_loads(tmp_path):
    path = tmp_path / "f.json"
    path.write_text(json.dumps([BOUNDARY]))
    assert fixtures.load_fixture(path)[0] == [BOUNDARY]
    path.write_text(json.dumps([dict(BOUNDARY, git_haed=HEAD_A)]))
    with pytest.raises(fixtures.FixtureError, match="unknown field"):
        fixtures.load_fixture(path)


# --- E2, E3: the two rules -----------------------------------------------------------

def fixture_lines(rel):
    return fixtures.load_fixture(ROOT / rel)[0]


def judged(lines):
    found, notes = tree.findings(lines)
    return sorted((f["rule_id"], f["session_id"], tuple(f["cited_seq"])) for f in found), notes


def test_j1_the_code_rules_declare_what_the_gate_and_report_read():
    assert tree.RULE_KINDS == {"HEAD-UNMOVED": "anchor", "INDEX-UNTOUCHED": "anchor"}
    assert (tree.CLASS, tree.SEVERITY) == ("DRIFT", "medium")
    assert tree.FP_BUDGET == {"HEAD-UNMOVED": 0.1, "INDEX-UNTOUCHED": 0.1}
    assert tree.STATUS == {"HEAD-UNMOVED": "active", "INDEX-UNTOUCHED": "active"}
    assert report.TREE_RULES == tuple((rid, tree.TITLES[rid]) for rid in tree.RULES)
    for rid in tree.RULES:
        assert set(tree.FIXTURES[rid]) == {"positive", "negative", "unknown", "not_judged"}
        assert all(tree.FIXTURES[rid][k] for k in tree.FIXTURES[rid]), rid
        for item in tree.HOLES[rid]:
            assert item.strip() and item.isprintable() and item.isascii(), item
        assert len(set(tree.HOLES[rid])) == len(tree.HOLES[rid])
    (ROOT / "raqib" / "rules" / "tree.py").read_bytes().decode("ascii")   # ASCII-safe


@pytest.mark.parametrize("rid", ["HEAD-UNMOVED", "INDEX-UNTOUCHED"])
def test_e2_e3_fixtures_positive_negative_unknown_and_not_judged(rid):
    for rel in tree.FIXTURES[rid]["positive"]:
        found, notes = tree.findings(fixture_lines(rel))
        assert [f["rule_id"] for f in found].count(rid) == 1, rel
        assert not [n for n in notes if n["rule_id"] == rid], rel
    for rel in tree.FIXTURES[rid]["negative"]:
        found, notes = tree.findings(fixture_lines(rel))
        assert rid not in [f["rule_id"] for f in found], rel
        assert not [n for n in notes if n["rule_id"] == rid], rel   # judged: measured, not partial
    for rel in tree.FIXTURES[rid]["unknown"]:
        found, notes = tree.findings(fixture_lines(rel))
        assert rid not in [f["rule_id"] for f in found], rel
        (note,) = [n for n in notes if n["rule_id"] == rid]
        assert note["status"] == "partial" and note["detail"].startswith("could not judge 1 line(s)"), note
    for rel in tree.FIXTURES[rid]["not_judged"]:
        assert tree.findings(fixture_lines(rel)) == ([], []), rel
        assert tree._judge(fixture_lines(rel))[rid]["judged"] == 0, rel


def test_e2_e3_the_unknown_fixtures_name_their_cause():
    _, notes = tree.findings(fixture_lines("tests/fixtures/tree/unknown-head.json"))
    assert notes == [{"rule_id": "HEAD-UNMOVED", "status": "partial", "detail": "could not judge 1 line(s) (session:seq"
                      " fixture-tree-unknown-head:2 (git_head null at the start (git_error unreadable)))"}]
    _, notes = tree.findings(fixture_lines("tests/fixtures/tree/unknown-index.json"))
    assert notes == [{"rule_id": "INDEX-UNTOUCHED", "status": "partial", "detail": "could not judge 1 line(s)"
                      " (session:seq fixture-tree-unknown-index:2 (git_index_sha256 null at the close (git_error"
                      " budget)))"}]
    _, notes = tree.findings(fixture_lines("tests/fixtures/tree/cwd-moved.json"))
    assert [n["detail"] for n in notes] == ["could not judge 1 line(s) (session:seq fixture-tree-cwd-moved:2 (the cwd"
                                            " moved between start and close))"] * 2


def test_e2_e3_the_findings_cite_start_edits_and_close():
    found, notes = tree.findings(fixture_lines("tests/fixtures/tree/unmoved.json"))
    assert notes == []
    head, index = found
    assert (head["rule_id"], index["rule_id"]) == ("HEAD-UNMOVED", "INDEX-UNTOUCHED")   # J-10: both, two facts
    for f in found:
        assert engine.check_finding(f) is f
        assert (f["class"], f["kind"], f["severity"], f["cited_seq"]) == ("DRIFT", "anchor", "medium", [1, 3, 4, 7])
        assert f["ts"] == "2026-11-03T09:00:15.000Z"   # the close's ts
    assert head["summary"] == ("2 edit(s) under the session's cwd and git_head unchanged from the session_start at"
                               " seq 1 to the session_end at seq 7: never committed")
    assert index["summary"].endswith("git_index_sha256 unchanged from the session_start at seq 1 to the session_end"
                                     " at seq 7: never staged")


def test_e2_e3_committed_fixtures_are_what_the_generator_writes(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    runpy.run_path(str(TREE_FIXTURES / "generate.py"))
    made = sorted(p.relative_to(tmp_path) for p in (tmp_path / "tests").rglob("*.json"))
    assert made == sorted(p.relative_to(ROOT) for p in TREE_FIXTURES.glob("*.json"))
    for rel in made:
        assert (tmp_path / rel).read_bytes() == (ROOT / rel).read_bytes(), rel
    listed = {rel for rid in tree.RULES for kind in tree.FIXTURES[rid].values() for rel in kind}
    assert listed == {p.as_posix() for p in made}


# Hand-built sessions for the behaviours the fixtures do not show.
T = "2026-11-03T09:00:%02d.000Z"


def line(seq, phase, sec, sid="s", cwd="/work/proj", git=(HEAD_A, INDEX_SHA, None), **kw):
    rec = {"ts": T % sec, "seq": seq, "session_id": sid, "phase": phase, "tool": kw.pop("tool", "-"), "cwd": cwd}
    if phase in ("pre", "post"):
        rec["input_meta"] = kw.pop("input_meta", {})
    if phase == "post":
        rec["ok"] = kw.pop("ok", True)
    rec.update(kw)
    if git is not None and phase in ("session_start", "stop", "session_end"):
        rec.update(zip(common.GIT_KEYS, git))
    assert trace.strict_problem(rec) is None, (rec, trace.strict_problem(rec))
    return rec


def edit_lines(seq, sec, path="/work/proj/a.py", tool="Edit", ok=True, sid="s", cwd="/work/proj", post=True):
    out = [line(seq, "pre", sec, sid=sid, cwd=cwd, tool=tool, input_meta={"path": path})]
    if post:
        out.append(line(seq, "post", sec + 1, sid=sid, cwd=cwd, tool=tool, input_meta={"path": path}, ok=ok))
    return out


MOVED = (HEAD_B, hashlib.sha256(b"other").hexdigest(), None)


def test_j3_not_judged_without_git_keys_or_with_no_repo_at_both_ends():
    old = [line(1, "session_start", 1, git=None)] + edit_lines(2, 2) + [line(3, "stop", 4, git=None)]
    assert tree.findings(old) == ([], [])
    nostart = edit_lines(2, 2) + [line(3, "stop", 4, git=None)]
    assert tree.findings(nostart) == ([], [])
    # The start without keys decides, even when the close has them (J-3).
    assert tree.findings([line(1, "session_start", 1, git=None)] + edit_lines(2, 2) + [line(3, "stop", 4)]) == ([], [])
    norepo = (None, None, "no repo")
    both = [line(1, "session_start", 1, git=norepo)] + edit_lines(2, 2) + [line(3, "stop", 4, git=norepo)]
    assert tree.findings(both) == ([], [])


@pytest.mark.parametrize("error", ["symlink", "gitdir", "unreadable", "no ref", "no index", "index too large",
                                   "budget"])
@pytest.mark.parametrize("side", ["start", "close"])
def test_j3_a_null_for_any_other_reason_is_unknown(error, side):
    head_null = error in ("symlink", "gitdir", "unreadable", "no ref")   # these stop before or at the head
    git = (None, None, error) if head_null else (HEAD_A, None, error)
    start = line(1, "session_start", 1, git=git if side == "start" else (HEAD_A, INDEX_SHA, None))
    close = line(4, "stop", 5, git=git if side == "close" else (HEAD_A, INDEX_SHA, None))
    found, notes = judged([start] + edit_lines(2, 2) + [close])
    assert found == ([("HEAD-UNMOVED", "s", (1, 2, 4))] if not head_null else [])
    by_rule = {n["rule_id"]: n["detail"] for n in notes}
    assert "INDEX-UNTOUCHED" in by_rule and "git_index_sha256 null at the %s (git_error %s)" % (side, error) in \
        by_rule["INDEX-UNTOUCHED"]
    assert ("HEAD-UNMOVED" in by_rule) == head_null


def test_j2_a_value_not_in_the_hook_s_shape_is_never_compared():
    bad = ("x" * 40, "y" * 64, None)
    found, notes = judged([line(1, "session_start", 1)] + edit_lines(2, 2) + [dict(line(3, "stop", 4), **dict(
        zip(common.GIT_KEYS, bad)))])
    assert found == [] and len(notes) == 2 and "null at the close" in notes[0]["detail"]


def test_j3_no_repo_on_one_side_only_is_unknown():
    lines = [line(1, "session_start", 1, git=(None, None, "no repo"))] + edit_lines(2, 2) + [line(3, "stop", 4)]
    found, notes = judged(lines)
    assert found == [] and [n["rule_id"] for n in notes] == ["HEAD-UNMOVED", "INDEX-UNTOUCHED"]
    assert "git_head null at the start (git_error no repo)" in notes[0]["detail"]


def test_j3_no_session_start_but_git_keys_elsewhere_is_unknown():
    found, notes = judged(edit_lines(2, 2) + [line(3, "stop", 4)])
    assert found == [] and len(notes) == 2 and all("(no session_start line)" in n["detail"] for n in notes)


def test_k4_edits_before_the_first_session_start_are_unknown_never_dropped():
    lines = edit_lines(1, 1) + [line(2, "session_start", 3), line(3, "stop", 4)]
    found, notes = judged(lines)
    assert found == [] and [n["detail"] for n in notes] == [
        "could not judge 1 line(s) (session:seq s:1 (edit before the start record))"] * 2
    # Beside a judged edit the session still fires, and the early edit is still named.
    lines = edit_lines(1, 1) + [line(2, "session_start", 3)] + edit_lines(3, 4) + [line(4, "stop", 6)]
    found, notes = judged(lines)
    assert found == [("HEAD-UNMOVED", "s", (2, 3, 4)), ("INDEX-UNTOUCHED", "s", (2, 3, 4))]
    assert all("s:1 (edit before the start record)" in n["detail"] for n in notes) and len(notes) == 2
    # An edit before the start outside the start cwd is not a trigger at all (J-4).
    lines = edit_lines(1, 1, path="/tmp/x") + [line(2, "session_start", 3), line(3, "stop", 4)]
    assert judged(lines) == ([], [])


def test_k5_a_git_error_outside_the_closed_set_is_never_echoed(tmp_path):
    hostile = "x\x1b[2J\nRESULT: CLEAN (exit 0)"
    start = dict(line(1, "session_start", 1), git_head=None, git_error=hostile)
    lines = [start] + edit_lines(2, 2) + [line(3, "stop", 4)]
    _, notes = tree.findings(lines)
    assert all("git_head null at the start (git_error not in the closed set)" in n["detail"] for n in notes[:1])
    path = tmp_path / "t.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in lines) + "\n")
    code, rep = report_json(path, "--scope", ".")
    details = [n["detail"] for n in rep["notes"] if n["rule_id"] == "HEAD-UNMOVED"]
    assert details == ["could not judge 1 line(s) (session:seq s:2 (git_head null at the start (git_error not in the"
                       " closed set)))"]
    assert "RESULT: CLEAN" not in json.dumps(rep["notes"])
    out = io.StringIO()
    code = cli.main(["report", str(path), "--scope", "."], out=out)
    text = out.getvalue()
    assert "HEAD-UNMOVED partial: could not judge 1 line(s) (session:seq s:2 (git_head null at the start (git_error"\
        " not in the closed set)))" in text
    assert text.count("RESULT: ") == 1 and "\x1b" not in text and "CLEAN" not in text
    assert code == 1 and [f["rule_id"] for f in rep["findings"]] == ["INDEX-UNTOUCHED"]   # the index still judged
    assert 'git_head=null  git_index_sha256="%s"  git_error="?"' % INDEX_SHA in text   # K-8, bounded


def test_j4_start_is_the_first_session_start_and_close_the_last_stop_or_end():
    # A resume writes a second session_start with the head the human moved; the first one counts.
    lines = [line(1, "session_start", 1)] + edit_lines(2, 2) + [line(3, "stop", 4, git=MOVED),
                                                                 line(4, "session_start", 5, git=MOVED),
                                                                 line(5, "stop", 6)]
    assert judged(lines)[0] == [("HEAD-UNMOVED", "s", (1, 2, 5)), ("INDEX-UNTOUCHED", "s", (1, 2, 5))]
    # The last close decides: an earlier stop with the same values does not fire when the session later commits.
    lines = [line(1, "session_start", 1)] + edit_lines(2, 2) + [line(3, "stop", 4)] + [line(4, "session_end", 5,
                                                                                            git=MOVED)]
    assert judged(lines) == ([], [])


def test_j4_edits_after_the_last_close_and_a_session_with_no_close_are_unknown():
    lines = [line(1, "session_start", 1)] + edit_lines(2, 2) + [line(3, "stop", 4)] + edit_lines(4, 5)
    found, notes = judged(lines)
    assert found == [("HEAD-UNMOVED", "s", (1, 2, 3)), ("INDEX-UNTOUCHED", "s", (1, 2, 3))]
    assert [n["detail"] for n in notes] == ["could not judge 1 line(s) (session:seq s:4 (no close came))"] * 2
    found, notes = judged([line(1, "session_start", 1)] + edit_lines(2, 2))
    assert found == [] and all("s:2 (no close came)" in n["detail"] for n in notes) and len(notes) == 2
    # With the head moved by the close, the later edit is still unjudged.
    found, notes = judged([line(1, "session_start", 1)] + edit_lines(2, 2) + [line(3, "stop", 4, git=MOVED)]
                          + edit_lines(4, 5))
    assert found == [] and len(notes) == 2


def test_j4_a_cwd_that_differs_between_start_and_close_is_unknown_and_windows_cwds_compare_folded():
    lines = [line(1, "session_start", 1)] + edit_lines(2, 2) + [line(3, "stop", 4, cwd="/work/proj/sub")]
    found, notes = judged(lines)
    assert found == [] and all("the cwd moved between start and close" in n["detail"] for n in notes)
    win = "C:\\Users\\dev\\Proj"
    lines = ([line(1, "session_start", 1, cwd=win)] + edit_lines(2, 2, path="C:/users/dev/proj/a.py", cwd=win)
             + [line(3, "stop", 4, cwd="c:/users/dev/proj/")])
    assert [f[0] for f in judged(lines)[0]] == ["HEAD-UNMOVED", "INDEX-UNTOUCHED"]


@pytest.mark.parametrize("edits, fires", [
    (edit_lines(2, 2), True),
    (edit_lines(2, 2, tool="Write"), True),
    (edit_lines(2, 2, tool="MultiEdit"), True),
    (edit_lines(2, 2, tool="NotebookEdit", path="/work/proj/n.ipynb"), True),
    (edit_lines(2, 2, path="src/a.py"), True),   # relative: placed against its own line's cwd
    (edit_lines(2, 2, path="/work/project2/a.py"), False),   # a sibling, not under the cwd
    (edit_lines(2, 2, path="/tmp/notes.md"), False),
    (edit_lines(2, 2, ok=False), False),
    (edit_lines(2, 2, tool="Read"), False),
    ([line(2, "pre", 2, tool="Bash", input_meta={"command_head": "sed", "command_programs": ["sed"]}),
      line(2, "post", 3, tool="Bash", input_meta={"command_head": "sed", "command_programs": ["sed"]})], False),
    ([line(2, "pre", 2, tool="Edit", input_meta={}), line(2, "post", 3, tool="Edit", input_meta={})], False),
    (edit_lines(2, 2, path="../outside/a.py"), False),
], ids=["edit", "write", "multiedit", "notebookedit", "relative", "sibling", "tmp", "failed", "read", "bash",
        "no-path", "climbs-out"])
def test_j4_triggers_are_ok_edits_under_the_start_cwd(edits, fires):
    lines = [line(1, "session_start", 1)] + edits + [line(3, "stop", 4)]
    found, notes = judged(lines)
    assert bool(found) == fires and notes == []
    assert len(found) == (2 if fires else 0)


def test_j4_a_pre_whose_post_never_came_is_an_unknown_trigger():
    lines = [line(1, "session_start", 1)] + edit_lines(2, 2, post=False) + [line(3, "stop", 4)]
    found, notes = judged(lines)
    assert found == [] and all("s:2 (no post line)" in n["detail"] for n in notes) and len(notes) == 2
    # It cannot fire when the value moved, so it is not unknown then (H-3's reading).
    assert judged([line(1, "session_start", 1)] + edit_lines(2, 2, post=False) + [line(3, "stop", 4, git=MOVED)]) == \
        ([], [])
    # Beside a true trigger, the session fires and the pre is not reported.
    lines = [line(1, "session_start", 1)] + edit_lines(2, 2) + edit_lines(3, 4, post=False) + [line(4, "stop", 6)]
    assert judged(lines) == ([("HEAD-UNMOVED", "s", (1, 2, 4)), ("INDEX-UNTOUCHED", "s", (1, 2, 4))], [])


def test_e2_e3_one_finding_per_session_in_session_order():
    a = [line(1, "session_start", 1, sid="b")] + edit_lines(2, 2, sid="b") + [line(3, "stop", 4, sid="b")]
    b = [line(1, "session_start", 1, sid="a", git=MOVED)] + edit_lines(2, 2, sid="a") + [line(3, "stop", 4, sid="a",
                                                                                              git=MOVED)]
    found, _ = tree.findings(a + b)
    assert [(f["session_id"], f["rule_id"]) for f in found] == [("b", "HEAD-UNMOVED"), ("b", "INDEX-UNTOUCHED"),
                                                                ("a", "HEAD-UNMOVED"), ("a", "INDEX-UNTOUCHED")]
    found, _ = tree.findings(a + [{"not": "a record"}, {"session_id": "x"}])
    assert len(found) == 2


def test_a6_a_disabled_rule_writes_only_a_disabled_note_on_a_trace_it_would_judge(monkeypatch):
    monkeypatch.setitem(tree.STATUS, "HEAD-UNMOVED", "disabled")
    found, notes = tree.findings(fixture_lines("tests/fixtures/tree/unmoved.json"))
    assert [f["rule_id"] for f in found] == ["INDEX-UNTOUCHED"]
    assert notes == [{"rule_id": "HEAD-UNMOVED", "status": "disabled",
                      "detail": "STATUS = disabled in raqib/rules/tree.py (A6)"}]
    assert tree.findings(fixture_lines("tests/fixtures/tree/no-git-keys.json")) == ([], [])
    (rep,) = [r for r in tree.check(fixtures.load_fixture, ROOT) if r["rule_id"] == "HEAD-UNMOVED"]
    assert rep["verdict"] == "disabled"


def test_a6_check_measures_each_rule_on_its_fixtures():
    reports = {r["rule_id"]: r for r in tree.check(fixtures.load_fixture, ROOT, cli.benign_default())}
    assert list(reports) == ["HEAD-UNMOVED", "INDEX-UNTOUCHED"]
    for rid, rep in reports.items():
        assert rep["verdict"] == "ok" and rep["fp_rate"] == 0.0 and rep["fp_budget"] == 0.1, rep
        assert all(p["fired"] for p in rep["positives"]) and len(rep["positives"]) == len(tree.FIXTURES[rid]["positive"])
        assert rep["measured"] == len(tree.FIXTURES[rid]["negative"]), rep
        assert rep["unmeasured"] == len(cli.benign_default())   # no benign file carries git keys (J-3)


def test_a6_check_reports_a_missed_positive_and_a_firing_negative(monkeypatch):
    real = dict(tree.FIXTURES["HEAD-UNMOVED"])
    monkeypatch.setitem(tree.FIXTURES, "HEAD-UNMOVED", dict(
        real, positive=["tests/fixtures/tree/committed.json"], negative=["tests/fixtures/tree/unmoved.json"]))
    (rep,) = [r for r in tree.check(fixtures.load_fixture, ROOT) if r["rule_id"] == "HEAD-UNMOVED"]
    assert rep["verdict"] == "positive-missed" and rep["fp_rate"] == 1.0
    monkeypatch.setitem(tree.FIXTURES, "HEAD-UNMOVED", dict(real, negative=["tests/fixtures/tree/unmoved.json"]))
    (rep,) = [r for r in tree.check(fixtures.load_fixture, ROOT) if r["rule_id"] == "HEAD-UNMOVED"]
    assert rep["verdict"] == "over-budget"
    monkeypatch.setitem(tree.FIXTURES, "HEAD-UNMOVED", dict(real, negative=["tests/fixtures/tree/no-repo.json"]))
    (rep,) = [r for r in tree.check(fixtures.load_fixture, ROOT) if r["rule_id"] == "HEAD-UNMOVED"]
    assert rep["verdict"] == "unmeasured"


# --- J-1: report, cli, eval and watch read tree.* as they read cross.* -------------------

def report_json(trace_path, *extra):
    out = io.StringIO()
    code = cli.main(["report", str(trace_path), "--json"] + list(extra), out=out)
    return code, json.loads(out.getvalue())


def test_j1_report_runs_the_tree_anchors(tmp_path):
    path = tmp_path / "t.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in fixture_lines("tests/fixtures/tree/unmoved.json")) + "\n")
    code, rep = report_json(path, "--scope", ".")
    assert code == 1 and sorted(f["rule_id"] for f in rep["findings"]) == ["HEAD-UNMOVED", "INDEX-UNTOUCHED"]
    assert all(f["source"] == "hook" for f in rep["findings"])
    path.write_text("\n".join(json.dumps(r) for r in fixture_lines("tests/fixtures/tree/cwd-moved.json")) + "\n")
    code, rep = report_json(path, "--scope", ".")
    assert {n["rule_id"] for n in rep["notes"] if n["status"] == "partial"} >= {"HEAD-UNMOVED", "INDEX-UNTOUCHED"}


def test_j3_a_trace_written_before_m43_reads_as_it_did():
    code, rep = report_json(FILE_TOOLS, "--scope", ".")
    assert code == 0 and rep["result"] == "clean", rep["notes"]


def test_j1_eval_flags_an_event_on_a_tree_finding():
    event = {"id": "tree-1", "label": "suspicious", "description": "edits never committed",
             "lines": fixture_lines("tests/fixtures/tree/unmoved.json")}
    found, notes = evaluation.rule_findings(event, engine.load_catalog(ROOT / "raqib" / "rules" / "catalog"))
    assert {"HEAD-UNMOVED", "INDEX-UNTOUCHED"} <= {f["rule_id"] for f in found}
    event["lines"] = fixture_lines("tests/fixtures/tree/cwd-moved.json")
    _, notes = evaluation.rule_findings(event, [])
    assert {n["rule_id"] for n in notes} == {"HEAD-UNMOVED", "INDEX-UNTOUCHED"}


def test_j1_cli_run_rules_carries_the_tree_findings_and_notes():
    found, notes = cli.run_rules(fixture_lines("tests/fixtures/tree/unknown-head.json"), [], {}, 60)
    assert [f["rule_id"] for f in found if f["rule_id"] in tree.RULES] == ["INDEX-UNTOUCHED"]
    assert [n["rule_id"] for n in notes] == ["HEAD-UNMOVED"]


def test_k8_report_describe_shows_the_git_keys_of_a_boundary_line():
    rec = line(1, "stop", 1)
    assert report.describe(rec) == ('stop - seq 1  2026-11-03T09:00:01.000Z  cwd="/work/proj"  git_head="%s"'
                                    '  git_index_sha256="%s"  git_error=null' % (HEAD_A, INDEX_SHA))
    rec = dict(line(1, "session_start", 1), git_head=None, git_index_sha256=None, git_error="no repo")
    assert report.describe(rec).endswith('git_head=null  git_index_sha256=null  git_error="no repo"')
    # Not in the hook's shape: "?", bounded; a long cwd is elided, the git keys never are.
    rec = dict(line(1, "session_end", 1, cwd="/w/" + "d" * 400), git_head="x" * 500, git_error="\x1b[2J" * 50)
    text = report.describe(rec)
    assert text.endswith('git_head="?"  git_index_sha256="%s"  git_error="?"' % INDEX_SHA) and "..." in text
    assert len(text) < report.LINE_TEXT_MAX + 160
    # A tool line shows no git keys, and a line written before M4.3 is as it was.
    assert "git_" not in report.describe(line(1, "pre", 1, tool="Edit", input_meta={"path": "/a"}))
    old = line(1, "stop", 1, git=None)
    assert report.describe(old) == 'stop - seq 1  2026-11-03T09:00:01.000Z  cwd="/work/proj"'


def test_k8_a_tree_finding_s_cited_lines_show_what_was_compared(tmp_path):
    path = tmp_path / "t.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in fixture_lines("tests/fixtures/tree/staged.json")) + "\n")
    out = io.StringIO()
    assert cli.main(["report", str(path), "--scope", "."], out=out) == 1
    text = out.getvalue()
    assert "[medium] HEAD-UNMOVED (DRIFT, anchor) session fixture-tree-staged seq 1,2,5" in text
    import re as _re
    shown = _re.findall(r"seq (1|5): line \d+  .* git_head=\"([0-9a-f]{40})\"  git_index_sha256=\"([0-9a-f]{64})\"", text)
    assert [s[0] for s in shown] == ["1", "5"] and shown[0][1] == shown[1][1] and shown[0][2] != shown[1][2]


# --- The real hook in a real repository: none, add, commit -----------------------------

@NEEDS_GIT
def test_e1_e2_e3_the_real_hook_in_a_real_repository(tmp_path):
    """SessionStart, one Edit, (a hand step), Stop, SessionEnd through the
    real hook in a repository git made: with no step both rules fire; after
    `git add` only HEAD-UNMOVED; after `git add` and `git commit` neither."""
    repo = tmp_path / "repo"
    git = [GIT, "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c",
           "commit.gpgsign=false"]
    subprocess.run([GIT, "init", "-q", str(repo)], check=True)
    (repo / "a.txt").write_text("a\n")
    subprocess.run(git + ["add", "a.txt"], check=True)
    subprocess.run(git + ["commit", "-q", "-m", "init"], check=True)
    expected = {"none": ["HEAD-UNMOVED", "INDEX-UNTOUCHED"], "add": ["HEAD-UNMOVED"], "commit": []}
    for step, rules in expected.items():
        log = tmp_path / ("%s.jsonl" % step)
        target = repo / "a.txt"
        recs = run_hook([payload("SessionStart", repo, session=step, source="startup"),
                         edit("PreToolUse", repo, target, session=step)], log, repo)
        with open(str(target), "a") as f:
            f.write("edited in %s\n" % step)
        if step in ("add", "commit"):
            subprocess.run(git + ["add", "a.txt"], check=True)
        if step == "commit":
            subprocess.run(git + ["commit", "-q", "-m", "landed: by hand"], check=True)
        recs = run_hook([edit("PostToolUse", repo, target, session=step, tool_response={"filePath": str(target)}),
                         payload("Stop", repo, session=step, stop_hook_active=False),
                         payload("SessionEnd", repo, session=step, reason="exit")], log, repo)
        boundary = [r for r in recs if r["phase"] in ("session_start", "stop", "session_end")]
        assert [r["phase"] for r in boundary] == ["session_start", "stop", "session_end"]
        assert all(r["git_error"] is None and r["git_head"] and r["git_index_sha256"] for r in boundary), boundary
        code, rep = report_json(log, "--scope", ".")
        assert sorted(f["rule_id"] for f in rep["findings"]) == rules, (step, rep["findings"])
        assert [n for n in rep["notes"] if n["rule_id"] in tree.RULES] == [], step
        assert code == (1 if rules else 0), (step, rep["result"])


# --- E4: the docs ----------------------------------------------------------------------

def test_e4_the_threat_model_names_what_the_anchor_sees_and_every_hole():
    flat = " ".join(THREAT.split())
    block = flat.split("### The tree anchor (HEAD-UNMOVED, INDEX-UNTOUCHED; ADR-0002 Amendment J)", 1)[1].split(
        "### ", 1)[0]
    for phrase in ("edits outside the repository", "in a second repository", "a linked worktree", "`GIT_DIR`",
                   "an index rewritten by the agent", "runs no `git`", "(`\\\\host\\share`, `//host/share`)",
                   "Not judged, unknown (J-3)", "False-positive sources:",
                   "The hook opens nothing outside the project directory (J-6 as K-2 amends it",   # K-2
                   "a file system mounted under the project directory (a network share) looks like a directory",
                   "an edit before the start record (K-4)", "`GIT_INDEX_FILE`"):
        assert phrase in block, phrase
    for rid in tree.RULES:
        part = block.split("- %s:" % rid, 1)[1]
        for hole in tree.HOLES[rid]:
            assert " ".join(hole.split()) in part, (rid, hole)
    stored = flat.split("**Stored in clear:**", 1)[1].split("## 5.", 1)[0]
    assert "`git_head`, the 40-hex commit" in stored and "(`git_index_sha256`)" in stored
    platform = flat.split("## 7. Platform", 1)[1]
    assert "15.6 ms" in platform and "Windows has no `O_NOFOLLOW`" in platform
    assert "without FILE_SHARE_DELETE" in platform and "(ruling K-7)" in platform   # K-7
    assert "cannot make the hook connect to another host" not in flat   # K-2: the claim is narrowed


def test_e4_the_readme_names_the_tree_anchors_and_their_gaps():
    flat = " ".join(README.split())
    assert "Seventeen rules turn the trace into findings" in flat
    assert "the local git state, read from the files under `.git` (no `git` is run)" in flat
    assert "for the tree anchors, what moved the head or the index" in flat
