"""M15.3a (ADR-0014 Amendment G, AG-1 to AG-3): raqib.autostart reads Windows' autostart places, standing alone,
and compares two reads; tools/rig/autostart_run.py runs it beside the stand-in. Every test but one runs on a
made-up registry and made-up folders handed to read(); the one real read is Windows' alone."""
import ast
import io
import json
import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from raqib import autostart

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools" / "rig"))
import autostart_run  # noqa: E402

SID = "S-1-5-21-1111111111-2222222222-3333333333-1001"   # made up
SYSTEM_SID = "S-1-5-18"
PERSON = "rig-person-x"                                   # made up: a user's name in the folders' path
CU = r"Microsoft\Windows\CurrentVersion"
SZ, EXPAND, BINARY, DWORD = 1, 2, 3, 4
TREE, TASKS = autostart.TASK_TREE, autostart.TASK_BODIES


class Reg:
    """A made-up registry: keys per (root, view32); a key made makes its parents; an error stands for a key."""

    def __init__(self):
        self.vals, self.names, self.errors = {}, {}, {}

    def put(self, root, path, values=(), views=(False, True)):
        for v in views:
            parts = path.split("\\") if path else []
            for i in range(len(parts) + 1):
                p = "\\".join(parts[:i])
                self.vals.setdefault((root, v, p.lower()), [])
                self.names[(root, v, p.lower())] = p
            self.vals[(root, v, path.lower())] += list(values)
        return self

    def fail(self, root, path, exc, views=(False, True)):
        for v in views:
            self.errors[(root, v, path.lower())] = exc
        return self

    def _key(self, root, path, view32):
        k = (root, view32, path.lower())
        if k in self.errors:
            raise self.errors[k]
        if k not in self.vals:
            raise FileNotFoundError(2, "not there")
        return k

    def subkeys(self, root, path, view32=False):
        self._key(root, path, view32)
        prefix = path.lower() + "\\" if path else ""
        return sorted({self.names[(r, v, p)][len(prefix):].split("\\")[0] for (r, v, p) in self.vals
                       if r == root and v == view32 and p and p != path.lower() and p.startswith(prefix)})

    def values(self, root, path, view32=False):
        return [(n, d, t) for n, d, t in self.vals[self._key(root, path, view32)]]


class Folders(autostart.Disk):
    """Real files in a temporary folder; a name in `refused` is a file whose content is refused, a folder in
    `refused` one whose listing is."""

    def __init__(self, refused=()):
        self.refused = set(refused)

    def files(self, folder):
        if folder in self.refused:
            raise PermissionError(13, "refused", folder)
        return super().files(folder)

    def sha256(self, folder, name):
        if name in self.refused:
            raise PermissionError(13, "refused", os.path.join(folder, name))
        return super().sha256(folder, name)


def user_run(leaf="Run"):
    return "%s\\Software\\%s\\%s" % (SID, CU, leaf)


def machine():
    reg = Reg()
    reg.put("HKU", "")
    reg.put("HKU", user_run(), [("RaqibRigValue", "cmd /c rem raqib rig", SZ)])
    reg.put("HKU", user_run("RunOnce"), [("Once", '"C:\\Tools\\once.exe" --now', SZ)])
    reg.put("HKLM", "SOFTWARE\\%s\\Run" % CU, [("Helper", "C:\\Program Files\\Helper\\helper.exe /quiet", EXPAND)],
            views=(False,))
    reg.put("HKLM", "SOFTWARE\\%s\\Run" % CU, [], views=(True,))
    reg.put("HKLM", "SOFTWARE\\%s\\RunOnce" % CU, [], views=(False, True))
    reg.put("HKLM", autostart.SERVICES + "\\RaqibRigService",
            [("ImagePath", "cmd.exe /c echo", EXPAND), ("Start", 3, DWORD), ("Type", 16, DWORD)], views=(False,))
    reg.put("HKLM", autostart.SERVICES + "\\NoImage", [("Start", 3, DWORD)], views=(False,))
    reg.put("HKLM", TREE + "\\Vendor\\Update", [("Id", "{0000-1}", SZ), ("Index", 3, DWORD)], views=(False,))
    reg.put("HKLM", TASKS + "\\{0000-1}", [("Actions", b"\x03\x00act-body", BINARY), ("Triggers", b"\x17trg-body", BINARY)],
            views=(False,))
    reg.put("HKLM", autostart.WINLOGON, [("Shell", "explorer.exe", SZ),
                                         ("Userinit", "C:\\Windows\\system32\\userinit.exe,", SZ),
                                         ("AutoRestartShell", 1, DWORD)], views=(False,))
    return reg


@pytest.fixture
def folders(tmp_path):
    user = tmp_path / PERSON / "Startup"
    common_ = tmp_path / "all" / "Startup"
    user.mkdir(parents=True)
    common_.mkdir(parents=True)
    (user / "raqib-rig-startup.cmd").write_text("rem raqib rig secret-content")
    (user / "desktop.ini").write_text("[.ShellClassInfo]")
    (user / "inner").mkdir()
    (common_ / "Shared.lnk").write_bytes(b"L\x00\x00\x00lnk-body")
    return {"user": str(user), "machine": str(common_)}


def entries(result, place):
    return [e for e in result["entries"] if e["place"] == place]


# --- E1: every place ---------------------------------------------------------------------------------------------

def test_every_place_is_read_with_its_entries(folders):
    got = autostart.read(machine(), folders, platform="win32")
    assert got["read"] is True and got["said"] is None
    assert {p: s["state"] for p, s in got["places"].items()} == {p: "read" for p in autostart.PLACES}
    run = entries(got, "run")
    assert [(e["scope"], e["view32"], e["name"], e["program"]) for e in run] == [
        ("machine", False, "Helper", "Program"), ("user", False, "RaqibRigValue", "cmd")]
    # "C:\Program Files\Helper\helper.exe /quiet" unquoted: its first word is C:\Program, as PERSIST-RUN-KEY's line
    assert [(e["scope"], e["name"], e["program"]) for e in entries(got, "runonce")] == [("user", "Once", "once.exe")]
    assert [(e["scope"], e["name"], e["program"]) for e in entries(got, "startup")] == [
        ("machine", "Shared.lnk", None), ("user", "raqib-rig-startup.cmd", None)]   # desktop.ini, a folder: out
    assert [(e["scope"], e["name"], e["program"]) for e in entries(got, "service")] == [
        ("machine", "RaqibRigService", "cmd.exe")]   # a key with no ImagePath runs nothing
    assert [(e["name"], e["program"]) for e in entries(got, "task")] == [("\\Vendor\\Update", None)]
    assert [(e["name"], e["program"]) for e in entries(got, "winlogon")] == [("Shell", "explorer.exe"),
                                                                              ("Userinit", None)]
    for e in got["entries"]:
        assert set(e) == set(autostart.FIELDS)
        assert e["sha256"] and len(e["sha256"]) == 64 and len(e["key"]) == 64
    assert got["seconds"] >= 0


def test_no_text_sid_or_user_name_leaves_the_read(folders):
    got = autostart.read(machine(), folders, platform="win32")
    out = io.StringIO()
    assert autostart.main(["--rounds", "1"], out=out, reader=lambda: got) == 0
    said = json.dumps(got) + out.getvalue()
    for secret in (SID, "S-1-5-21", PERSON, "rem raqib rig", "secret-content", "helper.exe /quiet", "Program Files",
                   "echo", "lnk-body", "act-body", "trg-body", "userinit.exe,"):
        assert secret not in said, secret
    said.encode("ascii")
    assert "content" not in said.replace("contents", "")


def test_ah1_a_sid_in_a_name_its_maker_chose_is_never_shown(folders):
    """ADR-0014 AH-1: a per-user task, a service or a Startup file whose NAME holds a SID is shown with [sid]."""
    reg = machine()
    reg.put("HKLM", TREE + "\\Vendor\\UpdateTaskUser" + SID + "Core", [("Id", "{0000-9}", SZ)], views=(False,))
    reg.put("HKLM", TASKS + "\\{0000-9}", [("Actions", b"\x03\x00a", BINARY)], views=(False,))
    reg.put("HKLM", autostart.SERVICES + "\\Sync_" + SID.lower(), [("ImagePath", "sync.exe", SZ)], views=(False,))
    first = autostart.read(machine(), folders, platform="win32")
    with open(os.path.join(folders["user"], "run-" + SID + ".cmd"), "w") as f:
        f.write("rem")
    got = autostart.read(reg, folders, platform="win32")
    names = sorted(e["name"] for e in got["entries"] if "[sid]" in e["name"])
    assert names == ["Sync_[sid]", "\\Vendor\\UpdateTaskUser[sid]Core", "run-[sid].cmd"]
    out = io.StringIO()
    reads = iter([first, got])
    assert autostart.main(["--rounds", "2", "--every", "0"], out=out, reader=lambda: next(reads),
                          sleep=lambda s: None) == 0
    said = json.dumps(got) + out.getvalue()
    assert SID not in said and SID.lower() not in said and "S-1-5-21" not in said.upper()
    assert out.getvalue().count("[sid]") >= 3          # each is said as added, by the name shown
    # two entries whose names differ only in their SID stay two entries (the key holds the name as it is)
    assert len({e["key"] for e in got["entries"]}) == len(got["entries"])


def test_ah2_a_folder_of_tasks_below_the_bound_is_said_as_not_read(folders):
    reg = machine()
    deep = TREE + "".join("\\d%d" % i for i in range(autostart.TASK_DEPTH + 3))
    reg.put("HKLM", deep + "\\Hidden", [("Id", "{0000-8}", SZ)], views=(False,))
    got = autostart.read(reg, folders, platform="win32")
    t = got["places"]["task"]
    assert (t["state"], t["keys_refused"]) == ("partly", 1)      # never "read": a task below the bound is not seen
    assert not [e for e in entries(got, "task") if e["name"].endswith("Hidden")]
    assert autostart.read(machine(), folders, platform="win32")["places"]["task"]["state"] == "read"


def test_ah5_a_key_deleted_while_it_is_read_is_not_there(folders):
    gone = OSError(22, "deleted")
    gone.winerror = autostart.GONE_WHILE_OPEN
    reg = machine().fail("HKLM", autostart.SERVICES + "\\RaqibRigService", gone, views=(False,))
    got = autostart.read(reg, folders, platform="win32")
    assert got["places"]["service"]["state"] == "read" and entries(got, "service") == []
    other = OSError(22, "another")
    other.winerror = 1
    reg = machine().fail("HKLM", autostart.SERVICES + "\\RaqibRigService", other, views=(False,))
    assert autostart.read(reg, folders, platform="win32")["places"]["service"]["state"] == "failed"


def test_a_task_body_and_a_service_change_their_hash():
    reg, other = machine(), machine()
    other.vals[("HKLM", False, (TASKS + "\\{0000-1}").lower())][0] = ("Actions", b"\x03\x00new", BINARY)
    other.vals[("HKLM", False, (autostart.SERVICES + "\\RaqibRigService").lower())][1] = ("Start", 2, DWORD)
    a, b = (autostart.read(r, {}, platform="win32", disk=Folders()) for r in (reg, other))
    ch = autostart.changes(a, b)
    assert sorted((c["place"], c["change"]) for c in ch["changes"]) == [("service", "changed"), ("task", "changed")]
    assert set(ch["unread"]) == {"startup"}   # no folder given: failed, said, no change


# --- E1/E3: one hive under two names, the two views -------------------------------------------------------------

def test_one_hive_under_two_names_and_its_views_is_one_entry(folders):
    reg = machine()
    value = [("Updater", "C:\\x\\up.exe", SZ)]
    reg.put("HKU", "%s\\Software\\%s\\Run" % (SYSTEM_SID, CU), value)
    reg.put("HKU", ".DEFAULT\\Software\\%s\\Run" % CU, value)            # SYSTEM's hive, its other name: not read
    reg.put("HKU", "%s_Classes\\Software\\%s\\Run" % (SID, CU), [("Classes", "x.exe", SZ)])   # left out
    got = autostart.read(reg, folders, platform="win32")
    run = entries(got, "run")
    assert [e["name"] for e in run if e["scope"] == "user"] == ["RaqibRigValue", "Updater"]   # each once
    assert all(not e["view32"] for e in run if e["scope"] == "user")   # the user's Run key is one key in both views
    assert len({e["key"] for e in got["entries"]}) == len(got["entries"])


def test_the_machines_32_bit_view_only_where_it_holds_another_entry(folders):
    reg = machine()
    path = "SOFTWARE\\%s\\Run" % CU
    reg.put("HKLM", path, [("Helper", "C:\\Program Files\\Helper\\helper.exe /quiet", EXPAND),   # the same: once
                           ("Old", "old.exe", SZ),                                                # only here
                           ("Tool", "tool32.exe", SZ)], views=(True,))
    reg.put("HKLM", path, [("Tool", "tool64.exe", SZ)], views=(False,))                          # same name, other
    got = autostart.read(reg, folders, platform="win32")
    run = [(e["name"], e["view32"], e["program"]) for e in entries(got, "run") if e["scope"] == "machine"]
    assert sorted(run) == [("Helper", False, "Program"), ("Old", True, "old.exe"), ("Tool", False, "tool64.exe"),
                           ("Tool", True, "tool32.exe")]


# --- E2: what the rights do not give ----------------------------------------------------------------------------

def test_the_task_tree_refused_whole_is_said_never_empty(folders):
    reg = machine().fail("HKLM", TREE, PermissionError(13, "refused"), views=(False,))
    got = autostart.read(reg, folders, platform="win32")
    assert got["places"]["task"]["state"] == "refused" and got["places"]["task"]["entries"] == 0
    assert {p for p, s in got["places"].items() if s["state"] != "read"} == {"task"}
    assert "refused: task;" in autostart.first_line(got)


def test_keys_refused_in_part_say_how_many(folders):
    reg = machine()
    reg.put("HKLM", TREE + "\\Locked\\One", [("Id", "{0000-2}", SZ)], views=(False,))
    reg.fail("HKLM", TREE + "\\Locked", PermissionError(5, "refused"), views=(False,))
    reg.put("HKLM", TREE + "\\Plain", [("Id", "{0000-3}", SZ)], views=(False,))
    reg.fail("HKLM", TASKS + "\\{0000-3}", PermissionError(5, "refused"), views=(False,))
    got = autostart.read(reg, folders, platform="win32")
    t = got["places"]["task"]
    assert (t["state"], t["keys_refused"], t["entries"]) == ("partly", 2, 2)
    plain = [e for e in entries(got, "task") if e["name"] == "\\Plain"]
    assert plain[0]["sha256"] is None                       # its body refused: not read, not empty
    assert "task 2 (2 key(s) refused)" in autostart.first_line(got)


def test_the_users_hives_refused_are_a_refusal_of_run_and_runonce(folders):
    reg = machine().fail("HKU", "", PermissionError(5, "refused"))
    got = autostart.read(reg, folders, platform="win32")
    for p in ("run", "runonce"):
        assert (got["places"][p]["state"], got["places"][p]["keys_refused"]) == ("partly", 1)
    assert [e["scope"] for e in entries(got, "run")] == ["machine"]


def test_a_failed_place_says_its_reason_without_a_path(folders):
    exc = OSError(1450, "insufficient", "C:\\Users\\%s\\x" % PERSON)
    got = autostart.read(machine().fail("HKLM", autostart.SERVICES, exc, views=(False,)), folders, platform="win32")
    s = got["places"]["service"]
    assert s["state"] == "failed" and s["reason"] == "OSError (1450)" and PERSON not in json.dumps(got)


def test_startup_refused_whole_and_in_part(folders):
    got = autostart.read(machine(), folders, platform="win32",
                         disk=Folders(refused={folders["machine"], "raqib-rig-startup.cmd"}))
    s = got["places"]["startup"]
    assert (s["state"], s["keys_refused"]) == ("partly", 2)
    assert [(e["name"], e["sha256"]) for e in entries(got, "startup")] == [("raqib-rig-startup.cmd", None)]
    both = autostart.read(machine(), folders, platform="win32", disk=Folders(refused=set(folders.values())))
    assert both["places"]["startup"]["state"] == "refused"


def test_a_place_not_there_is_empty_and_read(tmp_path):
    reg = Reg().put("HKU", "").put("HKLM", "SOFTWARE", views=(False, True)).put("HKLM", "SYSTEM", views=(False,))
    got = autostart.read(reg, {"user": str(tmp_path / "none"), "machine": str(tmp_path / "nor")}, platform="win32")
    assert {p: (s["state"], s["entries"]) for p, s in got["places"].items()} == {
        p: ("read", 0) for p in autostart.PLACES}


def test_read_never_raises_and_says_why():
    class Broken:
        def subkeys(self, *a):
            raise RuntimeError("broken")
        values = subkeys
    got = autostart.read(Broken(), {}, platform="win32")
    assert {s["state"] for s in got["places"].values()} == {"failed"}
    assert got["places"]["service"]["reason"] == "RuntimeError"
    got = autostart.read(object(), {}, platform="win32")
    assert {s["state"] for s in got["places"].values()} == {"failed"}
    late = autostart.read(machine(), {}, platform="win32", clock=lambda: 1 / 0)
    assert late["read"] is True and late["seconds"] is None and "in an unknown time" in autostart.first_line(late)


def test_off_windows_nothing_is_read_and_one_sentence_says_so():
    got = autostart.read(platform="linux")
    assert (got["read"], got["entries"], got["places"]) == (False, [], {})
    assert got["said"].startswith("autostart: not Windows (linux): nothing is read;") and "S4" in got["said"]
    assert autostart.changes(got, got) == {"changes": [], "unread": {p: "not read" for p in autostart.PLACES}}


def test_winreg_is_imported_inside_the_call_alone():
    tree = ast.parse((ROOT / "raqib" / "autostart.py").read_text(encoding="utf-8"))
    where = [n for n in ast.walk(tree) if isinstance(n, ast.Import) and any(a.name == "winreg" for a in n.names)]
    assert len(where) == 1
    read_fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "read")
    assert where[0] in list(ast.walk(read_fn))
    mods = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    mods |= {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    assert not mods & {"socket", "urllib", "http", "ssl", "subprocess", "ctypes", "tempfile", "shutil"}


class FakeWinreg:
    """winreg's shape, for WinRegistry: the end of an enumeration is OSError 259, as winreg gives it."""
    HKEY_USERS, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY = "HKU", "HKLM", 1, 0x200, 0x100

    def __init__(self, keys):
        self.keys, self.opened = keys, []

    class Key:
        def __init__(self, k):
            self.k = k

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def OpenKey(self, root, path, reserved, access):
        self.opened.append((root, path, access))
        if (root, path) not in self.keys:
            raise FileNotFoundError(2, "not there")
        return self.Key(self.keys[(root, path)])

    def QueryInfoKey(self, key):
        return len(key.k["subkeys"]) + 1, len(key.k["values"]) + 1, 0   # one more than there is: 259 ends it

    def _at(self, items, i):
        if i >= len(items):
            exc = OSError(22, "no more data")
            exc.winerror = autostart.NO_MORE_ITEMS
            raise exc
        return items[i]

    def EnumKey(self, key, i):
        return self._at(key.k["subkeys"], i)

    def EnumValue(self, key, i):
        return self._at(key.k["values"], i)


def test_the_registry_over_winreg_reads_both_views_read_only():
    w = FakeWinreg({("HKLM", "A"): {"subkeys": ["B", "C"], "values": [("V", "x.exe", SZ)]}})
    reg = autostart.WinRegistry(w)
    assert reg.subkeys("HKLM", "A") == ["B", "C"] and reg.values("HKLM", "A", True) == [("V", "x.exe", SZ)]
    assert [a for _, _, a in w.opened] == [1 | 0x100, 1 | 0x200]
    with pytest.raises(FileNotFoundError):
        reg.values("HKU", "none")


# --- E3: changes ------------------------------------------------------------------------------------------------

def test_each_kind_of_change(folders):
    before = autostart.read(machine(), folders, platform="win32")
    reg = machine()
    reg.vals[("HKU", False, user_run().lower())] = [("RaqibRigValue", "cmd /c rem other", SZ)]
    reg.vals[("HKU", True, user_run().lower())] = [("RaqibRigValue", "cmd /c rem other", SZ)]
    reg.put("HKLM", autostart.SERVICES + "\\New", [("ImagePath", "C:\\x\\new.exe", EXPAND)], views=(False,))
    reg.vals[("HKLM", False, autostart.WINLOGON.lower())] = []
    os.remove(os.path.join(folders["user"], "raqib-rig-startup.cmd"))
    after = autostart.read(reg, folders, platform="win32")
    ch = autostart.changes(before, after)
    assert ch["unread"] == {}
    got = [(c["change"], c["place"], c["name"]) for c in ch["changes"]]
    assert got == [("changed", "run", "RaqibRigValue"), ("removed", "startup", "raqib-rig-startup.cmd"),
                   ("added", "service", "New"), ("removed", "winlogon", "Shell"), ("removed", "winlogon", "Userinit")]
    changed = ch["changes"][0]
    assert changed["was"] != changed["sha256"] and set(changed) == set(autostart.FIELDS) | {"change", "was"}
    assert autostart.changes(after, after) == {"changes": [], "unread": {}}


def test_a_place_unread_in_either_read_gives_no_change(folders):
    before = autostart.read(machine(), folders, platform="win32")
    reg = machine().fail("HKLM", TREE, PermissionError(5, "refused"), views=(False,))
    reg.fail("HKLM", autostart.WINLOGON, OSError(1450, "x"), views=(False,))
    after = autostart.read(reg, folders, platform="win32")
    for a, b in ((before, after), (after, before)):
        ch = autostart.changes(a, b)
        assert ch["changes"] == [] and set(ch["unread"]) == {"task", "winlogon"}
        assert "refused" in ch["unread"]["task"] and "OSError (1450)" in ch["unread"]["winlogon"]


def test_keys_refused_in_part_compare_only_where_the_same_keys_are_refused(folders):
    reg = machine()
    reg.put("HKLM", TREE + "\\Locked", [("Id", "{0000-2}", SZ)], views=(False,))
    open_ = autostart.read(reg, folders, platform="win32")
    reg.fail("HKLM", TREE + "\\Locked", PermissionError(5, "refused"), views=(False,))
    shut = autostart.read(reg, folders, platform="win32")
    ch = autostart.changes(open_, shut)
    assert ch["changes"] == [] and "not the same" in ch["unread"]["task"]
    reg.put("HKLM", TREE + "\\Later", [("Id", "{0000-9}", SZ)], views=(False,))
    later = autostart.read(reg, folders, platform="win32")
    assert [(c["change"], c["name"]) for c in autostart.changes(shut, later)["changes"]] == [("added", "\\Later")]


# --- names and programs: the same gates as PERSIST-RUN-KEY's line ----------------------------------------------

def test_a_name_is_redacted_and_bounded_and_a_program_passes_the_gate(folders):
    token = "gh" + "p_" + "A1b2" * 10
    reg = machine()
    reg.put("HKU", user_run(), [("key " + token, "x.exe", SZ),
                                ("L" * 120, "ok.exe", SZ),
                                ('say "hi"', "{01234567-89AB-CDEF-0123-456789ABCDEF}", SZ),
                                ("unclosed", '"C:\\x\\never.exe --a', SZ),
                                ("keylike", "C:\\x\\AbCdEfGh12345678.exe", SZ),
                                ("binary", b"\x01\x02", BINARY),
                                ("number", 7, DWORD)])
    got = {e["name"]: e["program"] for e in entries(autostart.read(reg, folders, platform="win32"), "run")}
    assert got["key [redacted:github_token]"] == "x.exe" and token not in json.dumps(got)
    assert got["L" * 77 + "..."] == "ok.exe"
    assert got["say 'hi'"] is None and got["unclosed"] is None and got["keylike"] is None
    assert got["binary"] is None and got["number"] is None


# --- E4: python -m raqib.autostart ------------------------------------------------------------------------------

def test_the_command_says_the_first_read_then_each_change(folders):
    first = autostart.read(machine(), folders, platform="win32")
    reg = machine()
    reg.put("HKLM", autostart.SERVICES + "\\RaqibRigTwo", [("ImagePath", "cmd.exe /c echo", EXPAND)], views=(False,))
    second = autostart.read(reg, folders, platform="win32")
    third = autostart.read(machine().fail("HKLM", TREE, PermissionError(5, "x"), views=(False,)), folders,
                           platform="win32")
    reads, slept, out = iter([first, second, third]), [], io.StringIO()
    assert autostart.main(["--rounds", "3", "--every", "2"], out=out, reader=lambda: next(reads),
                          sleep=slept.append) == 0
    lines = out.getvalue().splitlines()
    assert lines[0].startswith("autostart round 1: 9 entries in ") and slept == [2.0, 2.0]
    assert "run 2, runonce 1, startup 2, service 1, task 1, winlogon 2; refused: none; failed: none" in lines[0]
    assert lines[1:] == ['CHANGE round 2: added service "RaqibRigTwo" (would run cmd.exe)',
                         'CHANGE round 3: removed service "RaqibRigTwo" (would run cmd.exe)',
                         "UNREAD round 3: task (refused)"]
    out.getvalue().encode("ascii")


@pytest.mark.parametrize("argv", [["--rounds", "0"], ["--every", "-1"], ["--every", "nan"], ["--bogus"],
                                  ["--rounds", "two"]])
def test_arguments_it_does_not_take_exit_2(argv, capsys):
    assert autostart.main(argv, out=io.StringIO(), reader=lambda: pytest.fail("read")) == 2


def test_the_command_off_windows_says_one_sentence_writes_nothing_and_opens_no_socket(tmp_path, monkeypatch):
    if sys.platform.startswith("win"):
        pytest.skip("off Windows only")
    env = dict(os.environ, PYTHONPATH=str(ROOT))
    run = subprocess.run([sys.executable, "-m", "raqib.autostart", "--rounds", "2", "--every", "0"], cwd=tmp_path,
                         capture_output=True, env=env, timeout=60)
    assert run.returncode == 0 and run.stderr == b"" and os.listdir(tmp_path) == []
    assert run.stdout.decode("ascii").splitlines() == [autostart.NOT_WINDOWS % sys.platform]

    def no_socket(*a, **k):
        raise AssertionError("a socket was opened")
    monkeypatch.setattr(socket, "socket", no_socket)
    assert autostart.main(["--rounds", "2", "--every", "0"], out=io.StringIO(), reader=lambda: autostart.read(
        machine(), {}, platform="win32", disk=Folders()), sleep=lambda s: None) == 0


@pytest.mark.skipif(not sys.platform.startswith("win"), reason="the real read is Windows' (E5)")
def test_the_real_read_on_windows():
    got = autostart.read()
    assert got["read"] is True and got["places"]["service"]["state"] in ("read", "partly")
    assert entries(got, "service") and got["seconds"] < 5
    assert autostart.changes(got, autostart.read())["unread"].get("service") is None


# --- E7: tools/rig/autostart_run.py -----------------------------------------------------------------------------

class StandIn:
    def __init__(self, lines, polls):
        self.stdout, self.polls, self.killed = io.StringIO("".join(x + "\n" for x in lines)), list(polls), False

    def poll(self):
        return self.polls.pop(0) if len(self.polls) > 1 else self.polls[0]

    def wait(self, timeout=None):
        return 0

    def kill(self):
        self.killed = True


def test_the_rig_run_writes_every_change_with_its_round(folders, tmp_path, capsys):
    plain = autostart.read(machine(), folders, platform="win32")
    reg = machine()
    reg.put("HKLM", autostart.SERVICES + "\\RaqibRigTwo", [("ImagePath", "cmd.exe /c echo", EXPAND)], views=(False,))
    made = autostart.read(reg, folders, platform="win32")
    reads = iter([plain, made, plain, plain])
    child = StandIn(["WORKLOAD 00:00:01 service made, never started", "noise"], [None, None, 0])
    facts = autostart_run.collect(reader=lambda: next(reads), start=lambda: child, platform="win32",
                                  sleep=lambda s: None, clock=lambda: 0.0)
    assert facts["error"] is None and facts["reads"] == 4 and facts["workload_rc"] == 0
    assert [(c["round"], c["change"], c["place"], c["name"], c["program"]) for c in facts["changes"]] == [
        (2, "added", "service", "RaqibRigTwo", "cmd.exe"), (3, "removed", "service", "RaqibRigTwo", "cmd.exe")]
    assert facts["workload"] == ["WORKLOAD 00:00:01 service made, never started"]
    assert facts["first"]["places"]["task"] == {"state": "read", "entries": 1, "keys_refused": 0, "reason": None}
    assert "sha256" not in json.dumps(facts) and SID not in json.dumps(facts)


def test_the_rig_run_off_windows_and_its_errors_are_facts(tmp_path, capsys):
    out = tmp_path / "f.json"
    assert autostart_run.main(["--out", str(out)], platform="linux") == 0
    facts = json.loads(out.read_text())
    assert facts["not_run"].startswith("not Windows (linux)") and facts["changes"] == []
    facts = autostart_run.collect(reader=lambda: 1 / 0, platform="win32")
    assert facts["error"].startswith("ZeroDivisionError")
    child = StandIn([], [None])
    reads = iter([{"seconds": 0.1}] * 3)
    ticks = iter([0.0, 500.0, 500.0])
    facts = autostart_run.collect(reader=lambda: next(reads), compare=lambda a, b: {"changes": [], "unread": {}},
                                  start=lambda: child, platform="win32", sleep=lambda s: None,
                                  clock=lambda: next(ticks))
    assert facts["ended_by_run"] is True and child.killed and facts["reads"] == 2


# --- E6, E7: the spec, the threat model, the rig's steps --------------------------------------------------------

def test_the_spec_says_what_is_not_read_what_is_refused_and_what_was_measured():
    flat = " ".join((ROOT / "docs" / "specs" / "AUTOSTART.md").read_text(encoding="utf-8").split())
    for words in ("Image File Execution Options", "`AppInit_DLLs`", "a WMI subscription", "the policies' Run keys",
                  "Active Setup", "`ServiceDll`", "a COM object", "a hive that is not loaded",
                  "A driver is not in this list: it is a key of the services with an `ImagePath`",
                  "is in the next read's base and is never said as added",
                  "the name shown holds `[sid]` in its place",
                  "a deeper one is counted as a key not read and the place says `partly`",
                  "`refused`: every key asked was refused", "`partly`: some keys were refused", "0.07 s",
                  "236 tasks, 26 of its keys refused", "687 with an `ImagePath`", "Not measured: a real desktop's"):
        assert words in flat, words
    threat = " ".join((ROOT / "docs" / "THREAT_MODEL.md").read_text(encoding="utf-8").split())
    assert threat.count("**What this read does not see** (docs/specs/AUTOSTART.md;") == 1


def test_the_rig_runs_the_read_on_both_machines_and_check_reads_it():
    text = (ROOT / ".github" / "workflows" / "rig.yml").read_text(encoding="ascii")
    jobs = text.split("\n  linux:\n")
    for job, facts in ((jobs[0], r"$env:RUNNER_TEMP\autostart.json"), (jobs[1], '"$RUNNER_TEMP/autostart.json"')):
        run = next(x for x in job.splitlines() if "run: python tools/rig/autostart_run.py" in x.replace("\\", "/"))
        reads = next(x for x in job.splitlines() if "run: python tools/rig/check.py" in x.replace("\\", "/"))
        assert "--out " + facts in run and "--autostart " + facts in reads and job.index(run) < job.index(reads)
    work = (ROOT / "tools" / "rig" / "workload.py").read_text(encoding="ascii")
    assert '["sc.exe", "create", SERVICE, "binPath=", SERVICE_BIN, "start=", "demand"]' in work
    assert '["sc.exe", "delete", SERVICE]' in work and 'SERVICE_BIN = "cmd.exe /c echo"' in work
    assert "sc.exe start" not in work and '"start", SERVICE' not in work   # never started
