"""M15.3a (ADR-0014 Amendment G, AG-1 to AG-3): raqib.autostart reads Windows' autostart places, standing alone,
and compares two reads; tools/rig/autostart_run.py runs it beside the stand-in. Every test but one runs on a
made-up registry and made-up folders handed to read(); the one real read is Windows' alone."""
import ast
import io
import hashlib
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
    """Real files in a temporary folder, opened by Python's open (the opener a test gives: AI-3); a name in
    `refused` is a file whose content is refused, a folder in `refused` one whose listing is."""

    def __init__(self, refused=()):
        super().__init__(lambda path: open(path, "rb"))
        self.refused = set(refused)

    def files(self, folder):
        if folder in self.refused:
            raise PermissionError(13, "refused", folder)
        return super().files(folder)

    def head(self, folder, name):
        if name in self.refused:
            raise PermissionError(13, "refused", os.path.join(folder, name))
        return super().head(folder, name)


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
    # AI-8: Winlogon's value is a list; its first item is named (the usual Userinit ends with a comma)
    assert [(e["name"], e["program"], e["sure"]) for e in entries(got, "winlogon")] == [
        ("Shell", "explorer.exe", True), ("Userinit", "userinit.exe", True)]
    for e in got["entries"]:
        assert set(e) == set(autostart.FIELDS) | {"sure", "list", "link", "triggers", "part"}
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


def test_ai7_the_machines_32_bit_view_is_always_its_own_entries(folders):
    reg = machine()
    path = "SOFTWARE\\%s\\Run" % CU
    reg.put("HKLM", path, [("Helper", "C:\\Program Files\\Helper\\helper.exe /quiet", EXPAND),   # the same text
                           ("Old", "old.exe", SZ),
                           ("Tool", "tool32.exe", SZ)], views=(True,))
    reg.put("HKLM", path, [("Tool", "tool64.exe", SZ)], views=(False,))
    got = autostart.read(reg, folders, platform="win32")
    run = [(e["name"], e["view32"], e["program"]) for e in entries(got, "run") if e["scope"] == "machine"]
    assert sorted(run) == [("Helper", False, "Program"), ("Helper", True, "Program"), ("Old", True, "old.exe"),
                           ("Tool", False, "tool64.exe"), ("Tool", True, "tool32.exe")]
    # the 64-bit twin changes: the 32-bit one, there all along, is not said as added (F7)
    w = autostart.Watcher(registry=reg, folders=folders, platform="win32")
    w.take(w.read())
    reg.vals[("HKLM", False, path.lower())] = [("Tool", "tool64.exe", SZ), ("Helper", "other.exe", SZ)]
    got = [(c["change"], c["name"], c["view32"]) for c in w.take(w.read())["changes"]]
    assert got == [("changed", "Helper", False)]


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
    assert not mods & {"socket", "urllib", "http", "ssl", "subprocess", "tempfile", "shutil"}
    top = {a.name.split(".")[0] for n in tree.body if isinstance(n, ast.Import) for a in n.names}
    top |= {n.module.split(".")[0] for n in tree.body if isinstance(n, ast.ImportFrom) and n.module}
    assert not top & {"winreg", "ctypes", "msvcrt"}   # AI-3: Windows' own calls, imported inside the calls alone


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


# --- E9: tools/rig/autostart_run.py -----------------------------------------------------------------------------

class StandIn:
    def __init__(self, lines, polls):
        self.stdout, self.polls, self.killed = io.StringIO("".join(x + "\n" for x in lines)), list(polls), False

    def poll(self):
        return self.polls.pop(0) if len(self.polls) > 1 else self.polls[0]

    def wait(self, timeout=None):
        return 0

    def kill(self):
        self.killed = True


def test_the_rig_run_holds_a_file_across_one_read_and_writes_what_each_read_said(folders, capsys):
    disk, reg, slept = Folders(), machine(), []

    def hold(path):   # the test's holder: the file is made, and its content is refused while it is held
        with open(path, "wb") as f:
            f.write(b"rem raqib rig held\r\n")
        disk.refused.add(os.path.basename(path))
        return lambda: (let_go.append(path), disk.refused.discard(os.path.basename(path)))
    let_go = []

    def sleep(s):   # the stand-in's service: made during its run, deleted before its end
        slept.append(s)
        if len(slept) == 4:
            reg.put("HKLM", autostart.SERVICES + "\\RaqibRigService2", [("ImagePath", "cmd.exe /c echo", EXPAND)],
                    views=(False,))
        if len(slept) == 5:
            del reg.vals[("HKLM", False, (autostart.SERVICES + "\\RaqibRigService2").lower())]
    w = autostart.Watcher(registry=reg, folders=folders, platform="win32", disk=disk)
    child = StandIn(["WORKLOAD 00:00:01 service made, never started", "noise"], [None, None, 0])
    facts = autostart_run.collect(watcher=w, hold=hold, start=lambda: child, folder=folders["user"],
                                  platform="win32", sleep=sleep, clock=lambda: 0.0)
    assert facts["error"] is None and facts["reads"] == 7 and facts["workload_rc"] == 0
    assert [(r["round"], r["held"], r["listed"], r["content"], r["changes"]) for r in facts["held"]["reads"]] == [
        (2, True, True, "not read", ["added"]), (3, False, True, "read", ["read"]), (4, False, False, None, ["removed"])]
    assert facts["held"]["made"] and facts["held"]["removed"] and len(let_go) == 1   # AJ-7: let go once
    assert not os.path.exists(os.path.join(folders["user"], autostart_run.HELD_NAME))
    assert [(c["round"], c["change"], c["place"], c["name"], c["program"], c["sure"]) for c in facts["changes"]
            if c["place"] == "service"] == [(5, "added", "service", "RaqibRigService2", "cmd.exe", True),
                                            (6, "removed", "service", "RaqibRigService2", "cmd.exe", True)]
    assert facts["workload"] == ["WORKLOAD 00:00:01 service made, never started"]
    assert facts["first"]["places"]["task"] == {"state": "read", "entries": 1, "keys_refused": 0, "keys_why": {},
                                                "reason": None}
    said = json.dumps(facts)
    assert "sha256" not in said and SID not in said and "triggers" not in said


def test_the_rig_run_off_windows_and_its_errors_are_facts(tmp_path, capsys):
    out = tmp_path / "f.json"
    assert autostart_run.main(["--out", str(out)], platform="linux") == 0
    facts = json.loads(out.read_text())
    assert facts["not_run"].startswith("not Windows (linux)") and facts["changes"] == []

    class Broken:
        def read(self):
            raise OSError(5, "refused", "C:\\Users\\%s\\x" % PERSON)
    facts = autostart_run.collect(watcher=Broken(), platform="win32")
    assert facts["error"] == "OSError (5)" and PERSON not in json.dumps(facts)

    def no_hold(path):
        raise PermissionError(13, "refused", path)
    child, ticks = StandIn([], [None]), iter([0.0, 500.0, 500.0])
    w = autostart.Watcher(registry=machine(), folders={}, platform="win32", disk=Folders())
    facts = autostart_run.collect(watcher=w, hold=no_hold, start=lambda: child, folder=str(tmp_path),
                                  platform="win32", sleep=lambda s: None, clock=lambda: next(ticks))
    assert facts["ended_by_run"] is True and child.killed and facts["reads"] == 2
    assert facts["held"] == {"made": False, "error": "PermissionError (13)", "reads": [], "removed": False}


# --- E6, E7: the spec, the threat model, the rig's steps --------------------------------------------------------

def test_the_spec_says_what_is_not_read_what_is_refused_and_what_was_measured():
    flat = " ".join((ROOT / "docs" / "specs" / "AUTOSTART.md").read_text(encoding="utf-8").split())
    for words in ("Image File Execution Options", "`AppInit_DLLs`", "a WMI subscription", "the policies' Run keys",
                  "Active Setup", "`ServiceDll`", "a COM object", "a hive that is not loaded",
                  "A driver is not in this list: it is a key of the services with an `ImagePath`",
                  "is said as added by the first read that reads it, once",
                  "`rescheduled` (AI-5): a task whose triggers alone changed",
                  "`hive loaded`, `hive unloaded` (AI-6)", "A sentence says `may run` where it is false",
                  "is not listed and no file in it is opened (AI-4; CLAUDE.md rule 5)",
                  "`FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE`", "keyed (HMAC-SHA256) with a salt (AI-9)",
                  "a rename of it by another handle failed 5406 times of 5406",
                  "the one change nobody made was a task `rescheduled`: it is that task's triggers",
                  "is looked at before each place and between keys and files", "never inside one call",
                  "A read begins with the step after the one the read before began with",
                  "The Watcher says once that it took a base late", "`more than 1000 entries: not read whole`",
                  "a list of more than one names none (AJ-3)", "`.exe`, `.com`, `.bat`, `.cmd`, `.scr`, `.pif`",
                  "a link: not opened or followed", "in the path's long form",
                  "`GetDriveTypeW` 0 (unknown) or 1 (no root)",
                  "the name shown holds `[sid]` in its place",
                  "a deeper one is counted as a key not read and the place says `partly`",
                  "`refused`: every key asked was refused", "`partly`: some keys were not read", "0.07 s",
                  "236 tasks, 26 of its keys refused", "687 with an `ImagePath`",
                  "a real desktop's churn (an updater that makes its own task or service)"):
        assert words in flat, words
    threat = " ".join((ROOT / "docs" / "THREAT_MODEL.md").read_text(encoding="utf-8").split())
    assert threat.count("**What this read does not see** (docs/specs/AUTOSTART.md;") == 1
    assert "**Closed** (ADR-0014 Amendments I and J). An entry that first appears while a place or a key" in threat
    assert "it is the base, and is never said" in threat and "**The lever that is left** (ADR-0014 AJ-2)" in threat
    assert "measured since, on Windows, by a test in which another call renames and then deletes a file" in threat


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
    assert "say(\"the startup file's delete failed (%s)\" % type(exc).__name__)" in work   # AI-10
    assert "sc.exe start" not in work and '"start", SERVICE' not in work   # never started


# --- M15.3b (ADR-0014 Amendment I) ------------------------------------------------------------------------------

def kinds(got):
    return [(c["change"], c["place"], c["name"]) for c in got["changes"]]


def watcher(reg, folders, **given):
    return autostart.Watcher(registry=reg, folders=folders, platform="win32", disk=given.pop("disk", Folders()),
                             **given)


def test_ai1_the_first_read_gives_none_and_a_place_refused_or_failed_then_read_says_its_new_entry_once(folders):
    reg = machine()
    w = watcher(reg, folders)
    first = w.take(w.read())
    assert first["first"] is True and first["changes"] == []
    reg.put("HKLM", TREE + "\\Vendor\\New", [("Id", "{0000-5}", SZ)], views=(False,))
    reg.put("HKLM", autostart.SERVICES + "\\NewSvc", [("ImagePath", "new.exe", SZ)], views=(False,))
    reg.fail("HKLM", TREE, PermissionError(5, "refused"), views=(False,))
    reg.fail("HKLM", autostart.SERVICES, OSError(1450, "x"), views=(False,))
    second = w.take(w.read())
    assert second["changes"] == [] and set(second["unread"]) == {"service", "task"}
    del reg.errors[("HKLM", False, TREE.lower())]
    del reg.errors[("HKLM", False, autostart.SERVICES.lower())]
    assert kinds(w.take(w.read())) == [("added", "service", "NewSvc"), ("added", "task", "\\Vendor\\New")]
    assert w.take(w.read())["changes"] == []


def test_ai1_a_place_read_in_part_says_a_new_entry_of_a_key_it_read_and_keeps_the_refused_ones(folders):
    reg = machine()
    reg.put("HKLM", TREE + "\\Locked", [("Id", "{0000-2}", SZ)], views=(False,))
    w = watcher(reg, folders)
    before = w.read()
    w.take(before)
    reg.fail("HKLM", TREE + "\\Locked", PermissionError(5, "refused"), views=(False,))
    reg.put("HKLM", TREE + "\\Vendor\\New", [("Id", "{0000-5}", SZ)], views=(False,))
    now = w.read()
    assert now["places"]["task"]["state"] == "partly"
    assert autostart.changes(before, now)["changes"] == []          # two reads: the coarse comparison, unchanged
    got = w.take(now)
    assert kinds(got) == [("added", "task", "\\Vendor\\New")] and "in part" in got["unread"]["task"]
    del reg.errors[("HKLM", False, (TREE + "\\Locked").lower())]
    assert w.take(w.read())["changes"] == []                          # the refused key held what it held: nothing


def test_ai1_a_place_unread_for_three_reads_loses_nothing(folders):
    reg = machine()
    reg.put("HKLM", TREE + "\\Old", [("Id", "{0000-3}", SZ)], views=(False,))
    w = watcher(reg, folders)
    w.take(w.read())
    reg.fail("HKLM", TREE, PermissionError(5, "refused"), views=(False,))
    for _ in range(3):
        assert w.take(w.read())["changes"] == []
        if ("HKLM", False, (TREE + "\\Old").lower()) in reg.vals:   # made and undone while the place is refused
            del reg.vals[("HKLM", False, (TREE + "\\Old").lower())]
            reg.put("HKLM", TREE + "\\Vendor\\Added", [("Id", "{0000-4}", SZ)], views=(False,))
            reg.vals[("HKLM", False, (TASKS + "\\{0000-1}").lower())][0] = ("Actions", b"other", BINARY)
    del reg.errors[("HKLM", False, TREE.lower())]
    assert kinds(w.take(w.read())) == [("removed", "task", "\\Old"), ("added", "task", "\\Vendor\\Added"),
                                       ("changed", "task", "\\Vendor\\Update")]


def test_ai2_a_startup_file_listed_with_its_content_unread_is_added_then_read(folders):
    disk = Folders()
    w = watcher(machine(), folders, disk=disk)
    w.take(w.read())
    with open(os.path.join(folders["user"], "held.cmd"), "wb") as f:
        f.write(b"rem held\r\n")
    disk.refused.add("held.cmd")
    got = w.take(w.read())
    assert kinds(got) == [("added", "startup", "held.cmd")] and got["changes"][0]["sha256"] is None
    assert autostart.change_line(2, got["changes"][0]) == \
        'CHANGE round 2: added startup "held.cmd" of the user, content not read'
    assert w.take(w.read())["changes"] == []                          # still held: nothing new
    disk.refused.clear()
    got = w.take(w.read())
    assert kinds(got) == [("read", "startup", "held.cmd")]
    assert autostart.change_line(4, got["changes"][0]) == 'CHANGE round 4: content read startup "held.cmd" of the user'
    disk.refused.add("held.cmd")                                      # held again: its last content is kept
    assert w.take(w.read())["changes"] == []


class FakeKernel32:
    def __init__(self, handle):
        self.handle, self.asked, self.closed = handle, [], []

    def CreateFileW(self, *args):
        self.asked.append(args)
        return self.handle

    def CloseHandle(self, handle):
        self.closed.append(handle)


def test_ai3_a_startup_file_is_opened_with_every_sharing(tmp_path):
    path = tmp_path / "x.cmd"
    path.write_bytes(b"rem x\r\n")
    k = FakeKernel32(7)
    opener = autostart.share_opener(k, lambda handle, flags: os.open(str(path), flags), lambda: 0)
    with opener(str(path)) as f:
        assert f.read() == b"rem x\r\n"
    (name, access, share, sa, how, flags, template), = k.asked   # the fd's flags: read-only, binary on Windows
    assert (name, access, share, how) == (str(path), autostart.GENERIC_READ, 0x7, autostart.OPEN_EXISTING)
    assert share == autostart.SHARE_ALL == 0x1 | 0x2 | 0x4
    assert flags == autostart.FILE_ATTRIBUTE_NORMAL | autostart.FILE_FLAG_OPEN_REPARSE_POINT == 0x00200080   # AK-4
    for code, kind in ((32, PermissionError), (5, PermissionError), (2, FileNotFoundError), (87, OSError)):
        with pytest.raises(kind):
            autostart.share_opener(FakeKernel32(-1), None, lambda: code)(str(path))


def test_ai3_where_no_file_can_be_opened_with_every_sharing_none_is_opened(folders):
    class NoOpener(autostart.Disk):
        def __init__(self):
            super().__init__(None)
    got = autostart.read(machine(), folders, platform="win32", disk=NoOpener())
    s = got["places"]["startup"]
    assert s["state"] == "partly" and s["keys_why"] == {autostart.NO_SHARING: 2}
    assert {e["sha256"] for e in entries(got, "startup")} == {None}


def test_ai4_a_content_is_hashed_by_its_length_and_its_first_64_kib(tmp_path):
    head = b"r" * autostart.HEAD_BYTES
    for name, body in (("a", head + b"one"), ("b", head + b"two"), ("c", head + b"three")):
        (tmp_path / name).write_bytes(body)
    disk = autostart.Disk(lambda p: open(p, "rb"))
    h = autostart._Hasher(b"salt")
    a, b, c = (h.file(*disk.head(str(tmp_path), n)) for n in "abc")
    assert a == b != c and len(disk.head(str(tmp_path), "a")[1]) == autostart.HEAD_BYTES
    assert h.content((SZ, "x" * 70000 + "1")) == h.content((SZ, "x" * 70000 + "2")) != h.content((SZ, "x" * 70002))


class Clock:
    """A made-up clock: it moves only when a place's read makes it move."""

    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


OTHER = "S-1-5-21-4444444444-5555555555-6666666666-1002"   # made up: another user's hive


class SlowReg(Reg):
    """One user's Run key takes the whole deadline each time it is read (a process made its own key slow)."""

    def __init__(self, clock, cost):
        super().__init__()
        self.clock, self.cost = clock, cost

    def values(self, root, path, view32=False):
        if self.cost and root == "HKU" and path.lower() == user_run().lower():
            self.clock.now += self.cost
        return super().values(root, path, view32)


def like(cls, *args):
    """A made-up registry of the class `cls`, holding machine()'s keys."""
    reg, m = cls(*args), machine()
    reg.vals, reg.names, reg.errors = m.vals, m.names, m.errors
    return reg


def slow_machine(clock, cost):
    return like(SlowReg, clock, cost)


def test_ai4_aj2_ak2_the_deadline_cuts_between_keys_and_no_key_is_starved(folders):
    clock = Clock()
    reg = slow_machine(clock, 0.0)
    reg.put("HKU", "%s\\Software\\%s\\Run" % (OTHER, CU), [("BRun", "b.exe", SZ)])
    reg.put("HKU", "%s\\Software\\%s\\RunOnce" % (OTHER, CU), [("BOnce", "b1.exe", SZ)])
    reg.vals[("HKLM", False, ("SOFTWARE\\%s\\RunOnce" % CU).lower())] = [("MOnce", "m1.exe", SZ)]
    reg.vals[("HKLM", True, ("SOFTWARE\\%s\\RunOnce" % CU).lower())] = [("MOnce32", "m2.exe", SZ)]
    reg.vals[("HKLM", True, ("SOFTWARE\\%s\\Run" % CU).lower())] = [("M32", "m3.exe", SZ)]
    w = autostart.Watcher(registry=reg, folders=folders, platform="win32", disk=Folders(), clock=clock, deadline=5)
    whole = w.read()                                         # S5a: a whole read first: the base holds everything
    assert w.take(whole)["first"] and {s["state"] for s in whole["places"].values()} == {"read"}
    reg.cost = 5.0                                           # now one user's Run key takes the whole deadline
    reads = []
    for _ in range(2 * len(autostart.STEPS)):                # the stated number: six reads for each of two hives
        r = w.read()
        reads.append(r)
        got = w.take(r)
        assert got["changes"] == [] and got["late"] == {}    # nothing cut is said as removed, added or late
        assert {p for p, x in r["places"].items() if x["state"] != "read"} <= set(got["unread"])
    assert [r["begin"] for r in reads] == 2 * list(autostart.STEPS[1:] + autostart.STEPS[:1])
    seen = {(e["place"], e["name"]) for r in reads for e in r["entries"]}
    for want in (("runonce", "Once"), ("runonce", "BOnce"), ("runonce", "MOnce"), ("runonce", "MOnce32"),
                 ("run", "Helper"), ("run", "M32"), ("run", "BRun"), ("startup", "Shared.lnk")):
        assert want in seen, want                            # each key read whole at least once (AK-2)
    for p in ("startup", "service", "task", "winlogon"):     # each place read whole in some read of the turn
        assert any(r["places"][p]["state"] == "read" for r in reads), p
    whole = [r for r in reads if r["begin"] == "run" and r["places"]["run"]["state"] == "read"]
    assert len(whole) == 1                                   # AL-2: in one turn the slow user's key comes last
    slow = [r for r in reads if r["begin"] == "run" and r["places"]["run"]["state"] == "partly"][0]
    cut = slow["places"]
    assert cut["run"]["state"] == "partly" and "passed before it was reached" in " ".join(cut["run"]["keys_why"])
    assert [e["name"] for e in slow["entries"] if e["place"] == "run"] == ["Helper", "M32", "RaqibRigValue"]
    for p in ("runonce", "startup", "service", "task", "winlogon"):
        assert cut[p]["state"] == "unread" and "deadline (5 s) passed" in cut[p]["reason"]
        assert not [e for e in slow["entries"] if e["place"] == p]          # never read as empty
    assert "; not read: " in autostart.first_line(slow)


def test_aj2_a_place_cut_while_it_is_read_keeps_what_it_reached(folders):
    clock = Clock()

    class SlowServices(Reg):
        slow = False

        def values(self, root, path, view32=False):
            if self.slow and path.lower().startswith(autostart.SERVICES.lower() + "\\"):
                clock.now += 2.0
            return super().values(root, path, view32)
    reg = like(SlowServices)
    for n in range(4):
        reg.put("HKLM", autostart.SERVICES + "\\S%d" % n, [("ImagePath", "s%d.exe" % n, SZ)], views=(False,))
    w = autostart.Watcher(registry=reg, folders=folders, platform="win32", disk=Folders(), clock=clock, deadline=5)
    w.take(w.read())                                         # S5a: a whole read first
    reg.slow = True
    got = w.read()
    while got["begin"] != "service":                         # the reads before the one that begins with the services
        assert w.take(got)["changes"] == []
        got = w.read()
    s = got["places"]["service"]
    # NoImage, RaqibRigService and S0 reached (2 s each; NoImage runs nothing), S1 to S3 not: parts not read
    assert s["state"] == "partly" and s["entries"] == 2 and s["keys_why"] == {autostart.CUT_KEY % 5: 3}
    assert w.take(got)["changes"] == []                      # no service not reached is said as removed


def test_aj2_a_folder_is_read_to_a_bound_of_entries(tmp_path):
    user, common_ = tmp_path / "u", tmp_path / "m"
    user.mkdir()
    common_.mkdir()
    for n in range(autostart.ENTRY_BOUND + 1):
        (user / ("f%04d.cmd" % n)).write_bytes(b"rem\r\n")
    folders = {"user": str(user), "machine": str(common_)}
    w = watcher(machine(), folders)
    got = w.read()
    s = got["places"]["startup"]
    assert s["state"] == "partly" and s["keys_why"] == {autostart.OVER_BOUND: 1}
    assert len(entries(got, "startup")) == autostart.ENTRY_BOUND
    w.take(got)
    os.remove(str(user / "f0000.cmd"))
    got = w.take(w.read())
    # S5f: at 1000 the folder is read whole for the first time: a base taken late, none of its files said
    assert got["changes"] == [] and got["late"] == {"startup": {"parts": 1, "entries": autostart.ENTRY_BOUND}}


def test_aj2_a_key_is_read_to_a_bound_of_entries(folders):
    reg = machine()
    reg.put("HKU", user_run(), [("V%04d" % n, "x.exe", SZ) for n in range(autostart.ENTRY_BOUND)])
    got = autostart.read(reg, folders, platform="win32", disk=Folders())
    assert got["places"]["run"]["keys_why"] == {autostart.OVER_BOUND: 1}
    assert len([e for e in entries(got, "run") if e["scope"] == "user"]) == autostart.ENTRY_BOUND


def test_ai4_a_startup_folder_on_a_share_is_not_listed_or_opened(folders):
    asked = []

    class Watching(Folders):
        def files(self, folder):
            asked.append(folder)
            return super().files(folder)
    unc = {"user": "\\\\fileserver\\home\\Startup", "machine": folders["machine"]}
    got = autostart.read(machine(), unc, platform="win32", disk=Watching())
    assert asked == [folders["machine"]]
    s = got["places"]["startup"]
    assert s["state"] == "partly" and s["keys_why"] == {autostart.ON_SHARE: 1}
    remote = autostart.read(machine(), folders, platform="win32", disk=Watching(), drive_kind=lambda f: "remote")
    assert remote["places"]["startup"]["state"] == "unread" and "on a share" in remote["places"]["startup"]["reason"]
    unknown = autostart.read(machine(), folders, platform="win32", disk=Watching(), drive_kind=lambda f: None)
    assert unknown["places"]["startup"]["keys_why"] == {autostart.SHARE_UNKNOWN: 2}
    assert asked == [folders["machine"]]
    assert autostart.on_share("\\\\?\\UNC\\fileserver\\x", None) is True
    assert autostart.on_share("\\\\?\\C:\\x", lambda f: "local") is False


def test_ai5_a_tasks_triggers_alone_are_rescheduled_its_actions_changed(folders):
    reg = machine()
    w = watcher(reg, folders)
    w.take(w.read())
    body = reg.vals[("HKLM", False, (TASKS + "\\{0000-1}").lower())]
    body[1] = ("Triggers", b"\x17later", BINARY)
    got = w.take(w.read())
    assert kinds(got) == [("rescheduled", "task", "\\Vendor\\Update")]
    assert autostart.change_line(2, got["changes"][0]) == 'CHANGE round 2: rescheduled task "\\Vendor\\Update"'
    body[0] = ("Actions", b"\x03\x00other", BINARY)
    assert kinds(w.take(w.read())) == [("changed", "task", "\\Vendor\\Update")]
    body[0], body[1] = ("Actions", b"\x03\x00third", BINARY), ("Triggers", b"\x17third", BINARY)
    assert kinds(w.take(w.read())) == [("changed", "task", "\\Vendor\\Update")]   # both: what it would run changed
    e = entries(w.read(), "task")[0]
    assert e["sha256"] and e["triggers"] and e["sha256"] != e["triggers"]


def test_ai6_a_hive_that_comes_or_goes_is_one_change_and_names_no_hive(folders):
    other = "S-1-5-21-4444444444-5555555555-6666666666-1002"   # made up
    reg = machine()
    w = watcher(reg, folders)
    w.take(w.read())
    reg.put("HKU", "%s\\Software\\%s\\Run" % (other, CU), [("A", "a.exe", SZ), ("B", "b.exe", SZ)])
    reg.put("HKU", "%s\\Software\\%s\\RunOnce" % (other, CU), [("C", "c.exe", SZ)])
    got = w.take(w.read())
    assert [(c["change"], c["entries"]) for c in got["changes"]] == [("hive loaded", 3)]
    assert autostart.change_line(2, got["changes"][0]) == "CHANGE round 2: hive loaded (a user's hive, 3 entries)"
    reg.vals[("HKU", False, ("%s\\Software\\%s\\Run" % (other, CU)).lower())].append(("D", "d.exe", SZ))
    assert kinds(w.take(w.read())) == [("added", "run", "D")]                      # set in a hive already there
    for k in [k for k in reg.vals if k[0] == "HKU" and k[2].startswith(other.lower())]:
        del reg.vals[k]
    got = w.take(w.read())
    assert [(c["change"], c["entries"]) for c in got["changes"]] == [("hive unloaded", 4)]
    said = json.dumps(got) + json.dumps(w.read())
    for sid in (other, SID):
        assert sid not in said and hashlib.sha256(sid.encode()).hexdigest() not in said
        assert hashlib.sha256(("HKU\\" + sid).encode()).hexdigest() not in said


def test_ai7_a_users_hive_is_read_in_one_view(folders):
    reg = machine()
    reg.vals[("HKU", True, user_run().lower())] = [("Only32", "x.exe", SZ)]
    got = autostart.read(reg, folders, platform="win32")
    assert [e["name"] for e in entries(got, "run") if e["scope"] == "user"] == ["RaqibRigValue"]


def test_ai8_a_name_that_may_not_be_what_runs_is_said_so(folders):
    reg = machine()
    reg.put("HKU", user_run(), [("Blank", "C:\\Program Files\\Helper\\helper.exe /quiet", SZ),
                                ("Quoted", '"C:\\Program Files\\Helper\\helper.exe" /quiet', SZ),
                                ("Bare", "cmd /c rem x", SZ), ("Alone", "C:\\x\\alone.exe", SZ)])
    reg.vals[("HKLM", False, autostart.WINLOGON.lower())] = [
        ("Shell", "explorer.exe", SZ), ("Userinit", "C:\\Windows\\system32\\userinit.exe,C:\\x\\other.exe,", SZ)]
    got = autostart.read(reg, folders, platform="win32")
    sure = {e["name"]: (e["program"], e["sure"]) for e in entries(got, "run") + entries(got, "winlogon")}
    assert sure["Blank"] == ("Program", False) and sure["Quoted"] == ("helper.exe", True)
    assert sure["Bare"] == ("cmd", True) and sure["Alone"] == ("alone.exe", True)
    assert sure["Userinit"] == (None, None) and sure["Shell"] == ("explorer.exe", True)   # AJ-3: a list names none
    assert [e["list"] for e in entries(got, "winlogon")] == [False, True]
    line = autostart.change_line(3, dict(entries(got, "winlogon")[1], change="changed"))
    assert line == 'CHANGE round 3: changed winlogon "Userinit" (a list of programs)'
    blank = [e for e in entries(got, "run") if e["name"] == "Blank"][0]
    assert autostart.change_line(3, dict(blank, change="added")).endswith("(may run Program)")


def test_ai9_the_hashes_are_salted_by_the_watcher_and_never_left_unsalted(folders):
    a, b = (watcher(machine(), folders) for _ in range(2))
    ra, rb = a.read(), b.read()
    assert {e["key"] for e in ra["entries"]}.isdisjoint({e["key"] for e in rb["entries"]})
    assert [e["sha256"] for e in ra["entries"]] != [e["sha256"] for e in rb["entries"]]
    plain = autostart.read(machine(), folders, platform="win32")    # a read of its own: the process's salt
    again = autostart.read(machine(), folders, platform="win32")
    assert [e["key"] for e in plain["entries"]] == [e["key"] for e in again["entries"]]
    said = json.dumps(ra) + json.dumps(plain) + repr(a)
    texts = [SID, "HKU\\" + SID, "RaqibRigValue", "cmd /c rem raqib rig", "explorer.exe", "rem raqib rig secret-content",
             "\0".join(("run", "HKU\\" + SID, "64", "raqibrigvalue"))]
    for t in texts:
        assert hashlib.sha256(t.encode()).hexdigest() not in said, t
    with open(os.path.join(folders["user"], "raqib-rig-startup.cmd"), "rb") as f:
        assert hashlib.sha256(f.read()).hexdigest() not in said
    assert a._Watcher__salt.hex() not in said and repr(a) == "<autostart.Watcher>"
    assert autostart._process_salt().hex() not in said                   # S5d: the process's salt too
    assert "salt" not in said.lower().replace("salt_id", "")             # and the word, but in the field's name


def test_e8_the_command_says_each_kind_and_may_run(folders):
    reg = machine()
    w = watcher(reg, folders)
    first = w.read()
    reg.put("HKU", user_run(), [("Blank", "C:\\Program Files\\x\\y.exe /q", SZ)])
    reg.vals[("HKLM", False, (TASKS + "\\{0000-1}").lower())][1] = ("Triggers", b"\x17later", BINARY)
    reg.put("HKU", "S-1-5-21-7-8-9-1003\\Software\\%s\\Run" % CU, [("Z", "z.exe", SZ)])
    second = w.read()
    reads, out = iter([first, second]), io.StringIO()
    assert autostart.main(["--rounds", "2", "--every", "0"], out=out, reader=lambda: next(reads), watcher=w,
                          sleep=lambda s: None) == 0
    assert out.getvalue().splitlines()[1:] == [
        'CHANGE round 2: added run "Blank" of the user (may run Program)',
        'CHANGE round 2: rescheduled task "\\Vendor\\Update"',
        "CHANGE round 2: hive loaded (a user's hive, 1 entries)"]


# --- M15.3b REDO (ADR-0014 Amendment J) -------------------------------------------------------------------------

def test_aj1_a_first_read_cut_before_the_services_then_a_whole_read_says_no_added_and_one_late_base(folders):
    clock = Clock()
    reg = slow_machine(clock, 5.0)
    w = autostart.Watcher(registry=reg, folders=folders, platform="win32", disk=Folders(), clock=clock, deadline=5)
    w.take(w.read())                                   # began with run: services, tasks, winlogon not reached
    reg.cost = 0.0
    got = w.take(w.read())
    assert got["changes"] == []
    # AK-2: the machine's Run keys come first, so the first read read Run whole before the slow key cut the rest
    assert {p: n["entries"] for p, n in got["late"].items()} == {"runonce": 1, "startup": 2, "service": 1, "task": 1,
                                                                 "winlogon": 2}
    out = autostart.late_line(2, got["late"])
    assert out.startswith("BASE round 2: taken late, none said as added: runonce (") and \
        "service (3 key(s), 1 entries)" in out
    again = w.take(w.read())
    assert again["changes"] == [] and again["late"] == {}   # said once


def test_aj1_aj5_a_hive_listed_while_runonce_fails_gives_one_hive_loaded_and_no_added(folders):
    other = "S-1-5-21-4444444444-5555555555-6666666666-1002"   # made up
    reg = machine()
    w = watcher(reg, folders)
    w.take(w.read())
    reg.put("HKU", "%s\\Software\\%s\\Run" % (other, CU), [("A", "a.exe", SZ), ("B", "b.exe", SZ)])
    reg.put("HKU", "%s\\Software\\%s\\RunOnce" % (other, CU), [("C", "c.exe", SZ)])
    reg.fail("HKLM", "SOFTWARE\\%s\\RunOnce" % CU, OSError(1450, "x"), views=(False,))
    said = [w.take(w.read())]
    del reg.errors[("HKLM", False, ("SOFTWARE\\%s\\RunOnce" % CU).lower())]
    said += [w.take(w.read()), w.take(w.read())]
    kinds_said = [c["change"] for got in said for c in got["changes"]]
    assert kinds_said == ["hive loaded"] and said[0]["changes"][0]["entries"] == 2
    assert "added" not in kinds_said and said[1]["late"]["runonce"]["entries"] >= 1
    reg.vals[("HKU", False, ("%s\\Software\\%s\\RunOnce" % (other, CU)).lower())].append(("D", "d.exe", SZ))
    assert kinds(w.take(w.read())) == [("added", "runonce", "D")]     # AI-1 holds once the key was read


def test_aj1_a_key_refused_in_the_first_read_then_readable_is_a_late_base(folders):
    reg = machine()
    reg.put("HKLM", TREE + "\\Locked", [("Id", "{0000-2}", SZ)], views=(False,))
    reg.fail("HKLM", TREE + "\\Locked", PermissionError(5, "refused"), views=(False,))
    w = watcher(reg, folders)
    w.take(w.read())
    del reg.errors[("HKLM", False, (TREE + "\\Locked").lower())]
    got = w.take(w.read())
    assert got["changes"] == [] and got["late"] == {"task": {"parts": 1, "entries": 1}}
    reg.put("HKLM", TREE + "\\Locked\\Inner", [("Id", "{0000-6}", SZ)], views=(False,))
    assert kinds(w.take(w.read())) == [("added", "task", "\\Locked\\Inner")]   # made under a key read before


def test_aj3_a_name_that_is_sure():
    for text, sure in (("C:\\Windows\\system32\\svchost.exe -k netsvcs", True), ('"C:\\a b\\c.exe" /x', True),
                       ("C:\\Program Files\\x\\y.exe", False), ("C:\\My Tools.exe", False), ("cmd /c rem x", True),
                       ("C:\\x\\run.CMD /q", True), ("C:\\x\\tool --x", False), ("C:\\x\\alone.exe", True)):
        assert autostart._program(text, "run")[1] is sure, text
    assert autostart._program("C:\\Windows\\system32\\userinit.exe,", "winlogon") == ("userinit.exe", True, False)
    assert autostart._program("userinit.exe, other.exe", "winlogon") == (None, None, True)
    assert autostart._program('"C:\\a,b\\x.exe" -x', "winlogon") == ("x.exe", True, False)   # a comma inside quotes


class Listing(autostart.Disk):
    """A made-up folder: its listing and its opener are the test's."""

    def __init__(self, listed, opener, long_form=True):
        super().__init__(opener, long_form)
        self.listed = listed

    def files(self, folder):
        return list(self.listed)


def test_aj4_a_file_is_opened_by_its_listed_name_in_the_long_form_and_a_link_is_not_opened():
    asked = []

    def opener(path):
        asked.append(path)
        if path.endswith("gone."):
            raise FileNotFoundError(2, "not found", path)
        if path.endswith("odd"):
            raise OSError(22, "invalid", path)
        return io.BytesIO(b"rem\r\n")
    folder = "C:\\Users\\" + PERSON + "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
    disk = Listing([("gone.", "file"), ("odd", "file"), ("link.cmd", "link"), ("ok.cmd", "file")], opener)
    with pytest.raises(io.UnsupportedOperation):   # BytesIO has no fileno: the opener was asked, by the long form
        disk.head(folder, "ok.cmd")
    assert asked == ["\\\\?\\" + folder + "\\ok.cmd"]
    assert autostart.long_path("\\\\?\\C:\\x\\", "a ") == "\\\\?\\C:\\x\\a "

    class Heads(Listing):
        def head(self, folder, name):
            with self.opener(self.path(folder, name)):
                return 5, b"rem\r\n"
    asked.clear()
    got = autostart.read(machine(), {"user": folder, "machine": "D:\\all"}, platform="win32",
                         disk=Heads(disk.listed, opener), drive_kind=lambda f: "local")
    s = got["places"]["startup"]
    assert s["state"] == "partly" and s["keys_why"] == {autostart.NOT_FOUND: 2, autostart.A_LINK: 2,
                                                        "OSError (22)": 2}
    user = {e["name"]: e["sha256"] for e in entries(got, "startup") if e["scope"] == "user"}
    assert set(user) == {"gone.", "odd", "link.cmd", "ok.cmd"} and user["ok.cmd"] and user["gone."] is None
    assert not [p for p in asked if p.endswith("link.cmd")] and "\\\\?\\" + folder + "\\gone." in asked
    assert PERSON not in json.dumps(got)


def test_aj4_a_symbolic_link_in_the_folder_is_listed_as_a_link_and_not_followed(tmp_path):
    folder = tmp_path / "Startup"
    folder.mkdir()
    (tmp_path / "target.cmd").write_bytes(b"rem target\r\n")
    try:
        os.symlink(str(tmp_path / "target.cmd"), str(folder / "link.cmd"))
    except (OSError, NotImplementedError):
        pytest.skip("this system gives no symbolic link to this user")
    (folder / "plain.cmd").write_bytes(b"rem\r\n")
    (folder / "inner").mkdir()
    assert sorted(autostart.Disk(None, long_form=False).files(str(folder))) == [("link.cmd", "link"),
                                                                                ("plain.cmd", "file")]


def test_aj4_the_drive_kind_by_a_made_up_kernel():
    class Kernel:
        def __init__(self, kind):
            self.kind, self.asked = kind, []

        def GetDriveTypeW(self, root):
            self.asked.append(root)
            return self.kind
    for code, said in ((0, None), (1, None), (2, "local"), (3, "local"), (4, "remote")):
        k = Kernel(code)
        assert autostart._windows_drive_kind(k)("c:\\Users\\x") == said and k.asked == ["C:\\"]
    assert autostart._windows_drive_kind(Kernel(3))("\\\\?\\D:\\x") == "local"
    assert autostart._windows_drive_kind(Kernel(3))("relative\\x") is None
    assert autostart.on_share("C:\\x", autostart._windows_drive_kind(Kernel(1))) is None   # not read


def test_aj6_a_read_of_another_salt_is_not_taken(folders):
    w = watcher(machine(), folders)
    w.take(w.read())
    base = {p: dict(q) for p, q in w.base.items()}
    got = w.take(autostart.read(machine(), folders, platform="win32", disk=Folders()))
    assert got["changes"] == [] and got["refused"] == autostart.OTHER_SALT
    assert {p: dict(q) for p, q in w.base.items()} == base and w.take(w.read())["changes"] == []
    reads, out = iter([w.read(), autostart.read(machine(), folders, platform="win32", disk=Folders())]), io.StringIO()
    autostart.main(["--rounds", "2", "--every", "0"], out=out, reader=lambda: next(reads), watcher=w,
                   sleep=lambda s: None)
    assert out.getvalue().splitlines()[1].startswith("REFUSED round 2: a read made with another salt")


@pytest.mark.skipif(not sys.platform.startswith("win"), reason="the module's own Windows opener is Windows' (R7)")
def test_aj7_while_the_modules_own_windows_opener_holds_a_file_it_is_renamed_and_deleted(tmp_path):
    path, moved = tmp_path / "held.cmd", tmp_path / "moved.cmd"
    path.write_bytes(b"rem held\r\n")
    opener = autostart._windows_opener()
    assert opener is not None
    with opener(str(path)) as f:
        assert f.read(3) == b"rem"
        os.rename(str(path), str(moved))          # another call renames it while it is open
        os.remove(str(moved))                     # and deletes it
    assert not path.exists() and not moved.exists()


def test_aj1_a_key_made_under_a_part_read_before_and_unread_at_first_is_said_as_added(folders):
    """AI-1 holds where AJ-1 meets it: a key that appeared under a part read before is new, even when the read that
    first saw it could not read it (refused here; the deadline does the same)."""
    reg = machine()
    w = watcher(reg, folders)
    w.take(w.read())
    reg.put("HKLM", autostart.SERVICES + "\\Planted", [("ImagePath", "planted.exe", SZ)], views=(False,))
    reg.fail("HKLM", autostart.SERVICES + "\\Planted", PermissionError(5, "refused"), views=(False,))
    got = w.take(w.read())
    assert got["changes"] == [] and "in part" in got["unread"]["service"]
    del reg.errors[("HKLM", False, (autostart.SERVICES + "\\Planted").lower())]
    got = w.take(w.read())
    assert kinds(got) == [("added", "service", "Planted")] and got["late"] == {}


# --- M15.3b REDO 2 (ADR-0014 Amendment K) -----------------------------------------------------------------------

class BoundReg(Reg):
    """A made-up registry that gives at most ENTRY_BOUND + 1 values of a key, as WinRegistry does."""

    def values(self, root, path, view32=False):
        return super().values(root, path, view32)[:autostart.ENTRY_BOUND + 1]


def test_ak1_a_service_a_task_and_winlogon_at_the_bound_are_said_not_read_and_nothing_is_removed(folders):
    reg = like(BoundReg)
    w = watcher(reg, folders)
    w.take(w.read())
    fill = [("F%04d" % n, n, DWORD) for n in range(autostart.ENTRY_BOUND + 1)]
    for key in (autostart.SERVICES + "\\RaqibRigService", TREE + "\\Vendor\\Update", autostart.WINLOGON):
        k = ("HKLM", False, key.lower())
        reg.vals[k] = fill + reg.vals[k]      # ImagePath the 1002nd value, the task's Id last, Shell after 1001
    for _ in range(2):                         # said each read
        got = w.read()
        said = w.take(got)
        assert said["changes"] == [] and said["late"] == {}
        for p in ("service", "task", "winlogon"):
            assert got["places"][p]["state"] == "partly" and got["places"][p]["keys_why"] == {autostart.OVER_BOUND: 1}
            assert "in part" in said["unread"][p]
    for key in (autostart.SERVICES + "\\RaqibRigService", TREE + "\\Vendor\\Update", autostart.WINLOGON):
        k = ("HKLM", False, key.lower())
        reg.vals[k] = reg.vals[k][len(fill):]
    assert w.take(w.read())["changes"] == []  # back under the bound: what it holds is what the base held
    bodies = [k for k in reg.vals if k[2].startswith(autostart.TASK_BODIES.lower() + "\\") and reg.vals[k]]
    assert bodies                              # S6: a task's body over the bound: no `changed`, no `rescheduled`
    reg.vals[bodies[0]] = fill + reg.vals[bodies[0]]
    got = w.read()
    said = w.take(got)
    assert said["changes"] == [] and got["places"]["task"]["keys_why"] == {autostart.OVER_BOUND: 1}


def test_ak1_the_registry_over_winreg_asks_at_most_1001_values():
    w = FakeWinreg({("HKLM", "A"): {"subkeys": [], "values": [("V%d" % n, n, DWORD) for n in range(1002)]}})
    asked = []
    enum = w.EnumValue
    w.EnumValue = lambda key, i: (asked.append(i), enum(key, i))[1]
    got = autostart.WinRegistry(w).values("HKLM", "A")
    assert len(got) == autostart.ENTRY_BOUND + 1 and asked == list(range(autostart.ENTRY_BOUND + 1))


def test_ak3_a_name_is_sure_only_where_the_text_names_one_program():
    for text, sure in (("C:\\Windows\\system32\\svchost.exe -k netsvcs", True), ('"C:\\a b\\c.exe" /x', True),
                       ("%ProgramFiles%\\x\\y.exe -z", False), ('"%ProgramFiles%\\x\\y.exe" -z', True),
                       ("C:\\Sites\\example.com files\\tool.exe", False), ("C:\\x\\a.exe\u00a0-q", False),
                       ("C:\\x\\a.exe -q\u2003x", False), ("C:\\x\\a.exe\t-q", True), ("C:\\x\\a.exe  -q", True),
                       ("cmd /c rem x", True), ("C:\\x\\run.CMD /q", True)):
        assert autostart._sure(text) is sure, text
    assert autostart._program("C:\\x\\tool.exe\t-k", "run") == ("tool.exe", True, False)   # a tab is a blank


def test_al4_a_machines_text_that_begins_with_the_systems_root_is_sure_and_a_users_is_not():
    """Measured before the ruling (GitHub's Windows machine): 243 of 689 services' ImagePath and both of the
    machine's Run values hold a `%`, 239 of them an unquoted first word - `%SystemRoot%\\system32\\svchost.exe -k
    netsvcs -p` and its like. AK-3 alone said each `may run`."""
    env = {"SystemRoot": "C:\\Windows", "WINDIR": "C:\\Windows", "ProgramFiles": "C:\\Program Files"}
    for text in ("%SystemRoot%\\system32\\svchost.exe -k netsvcs -p", "%windir%\\system32\\svchost.exe -k apphost",
                 "%SystemRoot%\\System32\\alg.exe", "%WINDIR%\\system32\\SecurityHealthSystray.exe"):
        assert autostart._sure(text, True, env) is True, text
        assert autostart._sure(text, False, env) is False, text          # a user's own text: the variable is the user's
        assert autostart._sure(text, True, {}) is False, text            # the reader does not hold the variable
        assert autostart._sure(text, True, {"SystemRoot": "C:\\Win dows", "windir": "C:\\Win\tdows"}) is False, text
    for text in ("%ProgramFiles%\\x\\y.exe -z", "%SystemRoot%\\%X%\\a.exe", "%SystemRootX%\\a.exe", "%Other%\\a.exe",
                 "%SystemRoot%\\Sites\\example.com files\\tool.exe", "%SystemRoot%\\My Tools\\a b"):
        assert autostart._sure(text, True, env) is False, text
    for text, sure in (('"%ProgramFiles%\\Windows Media Player\\wmpnetwk.exe"', True),
                       ('"%systemroot%\\Microsoft.NET\\SMSvcHost.exe" -NetMsmqActivator', True),
                       ('"%X%"', False), ('"C:\\a\\%X%.exe" -q', False), ('"%X%/a.exe"', True)):
        assert autostart._sure(text, False, {}) is sure, text            # quoted: the name alone decides
    assert autostart._program("%SystemRoot%\\system32\\svchost.exe -k x", "service", True, env)[1] is True
    assert autostart._program("%SystemRoot%\\system32\\svchost.exe -k x", "run", False, env)[1] is False
    assert autostart._program("C:\\x\\a.exe\u00a0-q", "run")[1] is False


class LinkDisk(Folders):
    """Real files; a name in `links` opens as a link (the handle says reparse point)."""

    def __init__(self):
        super().__init__()
        self.links = set()
        self.attributes = lambda f: (autostart.FILE_ATTRIBUTE_REPARSE_POINT
                                     if os.path.basename(f.name) in self.links else 0)


def test_ak4_a_handle_that_says_link_is_a_link_and_a_swap_is_changed(folders):
    disk = LinkDisk()
    w = watcher(machine(), folders, disk=disk)
    w.take(w.read())
    disk.links.add("raqib-rig-startup.cmd")
    got = w.take(w.read())
    assert kinds(got) == [("changed", "startup", "raqib-rig-startup.cmd")] and got["changes"][0]["link"] is True
    assert autostart.change_line(2, got["changes"][0]) == \
        'CHANGE round 2: changed startup "raqib-rig-startup.cmd" of the user, a link (not opened or followed)'
    assert w.take(w.read())["changes"] == []          # a link stays a link: its word does not change
    disk.links.clear()
    assert kinds(w.take(w.read())) == [("changed", "startup", "raqib-rig-startup.cmd")]


def test_al3_a_file_never_read_that_becomes_a_link_is_changed_and_so_is_the_way_back(folders):
    """The third review's S1: the base holds no content of a file that was refused; the swap is said all the same."""
    disk = LinkDisk()
    disk.refused = {"raqib-rig-startup.cmd"}
    w = watcher(machine(), folders, disk=disk)
    first = w.read()
    assert [e["sha256"] for e in entries(first, "startup") if e["name"] == "raqib-rig-startup.cmd"] == [None]
    w.take(first)
    disk.refused.clear()                                # the name now opens, and the handle says it is a link
    disk.links.add("raqib-rig-startup.cmd")
    got = w.take(w.read())
    assert kinds(got) == [("changed", "startup", "raqib-rig-startup.cmd")] and got["changes"][0]["link"] is True
    disk.links.clear()                                  # a file again, its content refused again: changed, not silent
    disk.refused = {"raqib-rig-startup.cmd"}
    got = w.take(w.read())
    assert kinds(got) == [("changed", "startup", "raqib-rig-startup.cmd")] and got["changes"][0]["link"] is False
    assert w.take(w.read())["changes"] == []


def test_ak4_two_names_equal_but_for_case_the_second_is_not_read(folders):
    listing = Listing([("Run.cmd", "file"), ("run.cmd", "file")], lambda path: open(__file__, "rb"), long_form=False)
    got = autostart.read(machine(), folders, platform="win32", disk=listing)
    s = got["places"]["startup"]
    assert s["state"] == "partly" and s["keys_why"] == {autostart.CASE_TWIN: 2}   # one in each folder
    assert [e["name"] for e in entries(got, "startup")] == ["Run.cmd", "Run.cmd"]


def test_ak4_s5b_a_made_up_directory_entry_that_is_a_reparse_point_is_a_link():
    class Entry:
        def __init__(self, name, attributes, file=True, link=False):
            self.name, self.attributes, self.file, self.link = name, attributes, file, link

        def is_symlink(self):
            return self.link

        def is_file(self, follow_symlinks=True):
            assert follow_symlinks is False    # never stats the target
            return self.file

        def stat(self, follow_symlinks=True):
            assert follow_symlinks is False
            return type("Stat", (), {"st_file_attributes": self.attributes})()

    class Scan:
        def __init__(self, folder):
            self.items = [Entry("junction.cmd", 0x400), Entry("plain.cmd", 0x20), Entry("folder", 0x10, file=False),
                          Entry("sym.cmd", 0x20, link=True)]

        def __enter__(self):
            return iter(self.items)

        def __exit__(self, *a):
            return False
    disk = autostart.Disk(None, long_form=False, scandir=Scan)
    assert disk.files("x") == [("junction.cmd", "link"), ("plain.cmd", "file"), ("sym.cmd", "link")]


@pytest.mark.skipif(not sys.platform.startswith("win"), reason="a real link read by the module's own opener (AK-4)")
def test_ak4_a_real_symbolic_link_on_windows_is_read_as_a_link(tmp_path):
    folder = tmp_path / "Startup"
    folder.mkdir()
    (tmp_path / "target.cmd").write_bytes(b"rem target\r\n")
    try:
        os.symlink(str(tmp_path / "target.cmd"), str(folder / "link.cmd"))
    except OSError:
        pytest.skip("this user cannot make a symbolic link here")
    got = autostart.read(machine(), {"user": str(folder), "machine": str(tmp_path / "none")}, platform="win32")
    assert [(e["name"], e["link"]) for e in entries(got, "startup")] == [("link.cmd", True)]
    assert got["places"]["startup"]["keys_why"] == {autostart.A_LINK: 1}
    with pytest.raises(autostart.IsALink):              # opened as itself, the handle says it is a link
        autostart._default_disk().head(str(folder), "link.cmd")


class RawReg(Reg):
    """A registry that gives a key's values as they are stored: a value of two fields makes the step itself raise
    (where it takes the three apart), not the ask around the registry's call."""

    def values(self, root, path, view32=False):
        return list(self.vals[self._key(root, path, view32)])


def test_ak5_a_step_that_raises_marks_what_it_listed_as_not_read(folders, monkeypatch):
    reg = like(RawReg)
    k = ("HKLM", False, (autostart.SERVICES + "\\RaqibRigService").lower())
    good = list(reg.vals[k])
    reg.vals[k] = [("ImagePath", "cmd.exe /c echo")]   # a value of two fields: the step raises while it reads
    with pytest.raises(ValueError):                    # the step itself raises: read()'s own net is what holds it
        autostart._services(reg, autostart._Place("service", autostart._Hasher(b"0" * 32)),
                            autostart._Deadline(lambda: 0.0, 0.0, 5), 5)
    w = watcher(reg, folders)
    first = w.read()
    assert first["places"]["service"]["state"] == "failed"
    assert first["parts"] and not any(q["read"] for q in first["parts"].values() if q["place"] == "service")
    w.take(first)
    reg.vals[k] = good
    got = w.take(w.read())
    assert got["changes"] == [] and got["late"] == {"service": {"parts": 3, "entries": 1}}


def test_al1_a_hive_that_comes_in_a_read_whose_run_step_raises_is_still_said_loaded(folders):
    """The third review's MUST FIX 1: the marking of a step that raised never takes a hive's own part: a hive
    first listed in that read is said loaded, and none of its keys enters the base without a word."""
    reg = like(RawReg)
    w = watcher(reg, folders)
    w.take(w.read())
    reg.put("HKU", "%s\\Software\\%s\\Run" % (OTHER, CU), [("BRun", "b.exe", SZ)])
    reg.put("HKU", "%s\\Software\\%s\\RunOnce" % (OTHER, CU), [("BOnce", "b1.exe", SZ)])
    k = ("HKLM", False, ("SOFTWARE\\%s\\Run" % CU).lower())
    good = list(reg.vals[k])
    reg.vals[k] = [("Helper", "two fields")]            # the machine's Run key makes the run step raise
    bad = w.read()
    assert bad["places"]["run"]["state"] == "failed"
    got = w.take(bad)
    loaded = [c for c in got["changes"] if c["change"] == "hive loaded"]
    assert len(loaded) == 1 and not [c for c in got["changes"] if c["change"] in ("added", "removed")]
    reg.vals[k] = good
    later = [c for _ in range(len(autostart.STEPS)) for c in w.take(w.read())["changes"]]
    assert not [c for c in later if c["change"] in ("added", "removed", "hive loaded")], later


def test_ak5_a_watcher_takes_no_salt_and_read_takes_no_bad_begin_or_salt(folders):
    for given in ({"salt": b"0" * 32}, {"begin": 3}):
        with pytest.raises(TypeError):
            autostart.Watcher(registry=machine(), **given)
    for bad in ({"begin": "x"}, {"begin": -1}, {"begin": True}, {"begin": 1.5}, {"salt": "text"}):
        got = autostart.read(machine(), folders, platform="win32", disk=Folders(), **bad)
        assert got["read"] is True and {s["state"] for s in got["places"].values()} == {"failed"}, bad
    assert autostart.read(machine(), folders, platform="win32", disk=Folders(), begin=7)["begin"] == "runonce"


def test_s5g_a_read_on_windows_uses_the_modules_own_opener(monkeypatch, folders):
    sentinel = object()
    monkeypatch.setattr(autostart, "_windows_opener", lambda: sentinel)
    nt = autostart._default_disk(system="nt")
    assert nt.opener is sentinel and nt.long_form is True
    assert autostart._default_disk(system="posix").opener is not sentinel
    used = []
    monkeypatch.setattr(autostart, "_default_disk", lambda opener=None: (used.append(opener), Folders())[1])
    autostart.read(machine(), folders, platform="win32")
    assert used == [None]                               # read() takes its disk from _default_disk



def test_ak6_the_words_say_no_more_than_the_code_does():
    """ADR-0014 AK-6: no sentence of the spec, the threat model's entry or the module's words promises that a
    change is never lost or that every other place is reached; each says what a slow key still delays, that a key
    over the bound is never compared while it is over, and what was measured of a held file."""
    spec = " ".join((ROOT / "docs" / "specs" / "AUTOSTART.md").read_text(encoding="utf-8").split())
    threat = " ".join((ROOT / "docs" / "THREAT_MODEL.md").read_text(encoding="utf-8").split())
    entry = threat.split("**What this read does not see** (docs/specs/AUTOSTART.md;", 1)[1].split("### ", 1)[0]
    module = " ".join(autostart.__doc__.split())
    for text in (spec, entry, module):
        for words in ("never lost", "every other place is reached", "at least once every five", "bounded by size"):
            assert words not in text, words
    for words in ("What a slow key still delays", "none of its entries is compared while it is over",
                  "enumeration reads each of its values whole", "another call's rename and delete",
                  "An open by another process that asks for no sharing still fails while the read holds the file",
                  "Never run on Windows, given to the code in tests alone", "drive kinds 0, 1 and 4",
                  "whether Winlogon keeps a quoted comma inside one program's name"):
        assert words in spec, words
    for words in ("is never compared while it is over", "reads each value whole", "asks for no sharing still fails"):
        assert words in entry, words
    for words in ("none of its entries compared while it is over", "another call's rename and delete",
                  "an open that asks for no sharing still fails", "a part first read late"):
        assert words in module, words
