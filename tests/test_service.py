"""M12.1 (ADR-0013 A-1 to A-9, Amendments A, B and C): `raqib service install | remove | status`, the host watch
as a unit of the system's, on Linux.

Every call of the system goes through a made-up machine (Fake, in place of service.System): no test here needs
root or Linux, writes under /etc or outside its tmp folder, or runs systemctl. Every path, uid and answer of
systemctl here is made up; a weakness is named by the made-up file that must be refused.
"""
import ast
import io
import os
import posixpath
import stat as statmod
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from raqib import cli, discover, service  # noqa: E402

VENV = "/usr/local/lib/raqib/venv"
PY = VENV + "/bin/python"
SITE = VENV + "/lib/python3.12/site-packages"
PKG = SITE + "/raqib"
STDLIB = "/usr/lib/python3.12"
SYSTEMCTL = "/usr/bin/systemctl"
UNIT = service.UNIT_PATH
SHOW_ACTIVE = ("LoadState=loaded\nUnitFileState=enabled\nActiveState=active\nSubState=running\nResult=success\n"
               "ExecMainStatus=0\nNRestarts=0\nFragmentPath=%s\nDropInPaths=\nNeedDaemonReload=no\n" % UNIT)
SHOW_FAILED = ("LoadState=loaded\nUnitFileState=enabled\nActiveState=failed\nSubState=failed\nResult=exit-code\n"
               "ExecMainStatus=1\nNRestarts=4\nFragmentPath=%s\nDropInPaths=\nNeedDaemonReload=no\n" % UNIT)
SHOW_GONE = "LoadState=not-found\nActiveState=inactive\n"
DISTUTILS = (b"import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, 'local') == 'local';"
             b" enabled and __import__('_distutils_hack').add_shim(); \n")
PROPS = "--property=" + ",".join(service.SHOW)
HELD = ["show", "raqib-watch.service", "--no-pager", "--property=LoadState,ActiveState,FragmentPath"]
LOADED = ["show", "raqib-watch.service", "--no-pager", "--property=" + ",".join(service.LOADED)]
AFTER = ["show", "raqib-watch.service", "--no-pager", PROPS]


class St:
    def __init__(self, mode, uid):
        self.st_mode, self.st_uid = mode, uid


class Fake:
    """A made-up machine: {path: [kind, mode, uid, content]}, kind "dir", "file" or "link" (content: a link's
    target, a file's bytes). It answers every call service makes of the system and records the ones that
    change something (systemctl's runs, the unit's writes, the removals, the waits) and what was read."""

    def __init__(self, uid=0, platform="linux", python=PY, sys_path=None, systemctl=SYSTEMCTL, show=SHOW_ACTIVE):
        self.nodes = {"/": ["dir", 0o755, 0, None]}
        self.uid, self.platform_name, self.python_path, self.systemctl_at, self.show = (
            uid, platform, python, systemctl, show)
        self.paths = sys_path if sys_path is not None else [
            "/usr/lib/python312.zip", STDLIB, STDLIB + "/lib-dynload", SITE]
        self.calls, self.writes, self.removed, self.fail = [], [], [], {}
        self.slept, self.reads, self.listed, self.lstats = [], [], [], set()
        self.no_site_flag, self.sites, self.pkg, self.gone, self.unreadable = False, [SITE], PKG, SHOW_GONE, False
        self.ignore_env, self.env, self.shows = False, {}, []
        for d in (STDLIB + "/lib-dynload", PKG + "/rules", service.UNIT_DIR, "/var/lib"):
            self.add(d)
        self.add("/usr/bin/python3.12", "file")
        self.add("/usr/bin/python3", "link", content="python3.12")
        self.add(PY, "link", content="/usr/bin/python3")
        for f in (VENV + "/pyvenv.cfg", STDLIB + "/os.py", STDLIB + "/json/__init__.py",
                  STDLIB + "/__pycache__/os.cpython-312.pyc", STDLIB + "/lib-dynload/_json.so",
                  PKG + "/__init__.py", PKG + "/cli.py", PKG + "/service.py", PKG + "/rules/engine.py"):
            self.add(f, "file", 0o644)
        self.add(SITE + "/distutils-precedence.pth", "file", 0o644, content=DISTUTILS)
        self.add("/usr/bin/ss", "file", 0o755)
        if systemctl:
            self.add(systemctl, "file", 0o755)

    def add(self, path, kind="dir", mode=0o755, uid=0, content=None):
        parent = posixpath.dirname(path)
        if parent not in self.nodes:
            self.add(parent)
        self.nodes[path] = [kind, mode, uid, content]
        return self

    def unit(self, text):
        return self.add(UNIT, "file", 0o644, 0, text.encode("ascii"))

    def resolve(self, path):
        for _ in range(50):
            node = self.nodes.get(path)
            if node is None:
                raise FileNotFoundError(path)
            if node[0] != "link":
                return path, node
            path = posixpath.normpath(posixpath.join(posixpath.dirname(path), node[3]))
        raise OSError(40, "too many links")

    # --- service.System's calls ---
    def platform(self):
        return self.platform_name

    def euid(self):
        return self.uid

    def python(self):
        return self.python_path

    def no_site(self):
        return self.no_site_flag

    def ignores_environment(self):
        return self.ignore_env

    def env_set(self, names):
        return [n for n in names if n in self.env]

    def site_packages(self):
        return list(self.sites)

    def sys_path(self):
        return list(self.paths)

    def getcwd(self):
        return "/"

    def package_dir(self):
        return self.pkg

    def stat(self, path, follow_symlinks=True):
        if not follow_symlinks:
            self.lstats.add(path)
            node = self.nodes.get(path)
            if node is None:
                raise FileNotFoundError(path)
        else:
            path, node = self.resolve(path)
        kind = {"dir": statmod.S_IFDIR, "file": statmod.S_IFREG, "link": statmod.S_IFLNK}[node[0]]
        return St(kind | node[1], node[2])

    def readlink(self, path):
        node = self.nodes.get(path)
        if node is None or node[0] != "link":
            raise OSError(22, "not a link")
        return node[3]

    def listdir(self, path):
        self.listed.append(path)
        pre = path.rstrip("/") + "/"
        return sorted(p[len(pre):] for p in self.nodes if p.startswith(pre) and "/" not in p[len(pre):])

    def read_head(self, path, limit=service.HEAD_MAX):
        if self.unreadable:
            raise PermissionError(13, "made-up")
        return self.nodes[path][3][:limit]

    def read_bytes(self, path, limit):
        self.reads.append(path)
        _, node = self.resolve(path)
        if node[0] != "file" or len(node[3] or b"") > limit:
            raise OSError("not read whole")
        return node[3] or b""

    def sleep(self, seconds):
        self.slept.append(seconds)

    def systemctl_path(self):
        return self.systemctl_at

    def systemctl(self, path, args):
        self.calls.append(list(args))
        if args[0] in self.fail:
            return self.fail[args[0]]
        if args[0] == "show" and self.shows:   # answers in order, where a test gives them
            return 0, self.shows.pop(0), ""
        return (0, self.show if UNIT in self.nodes else self.gone, "") if args[0] == "show" else (0, "", "")

    def write_unit(self, text):
        self.writes.append(text)
        self.unit(text)

    def remove_unit(self):
        self.removed.append(UNIT)
        del self.nodes[UNIT]

    def remove_state(self):
        self.removed.append(service.STATE_DIR)
        for p in [p for p in self.nodes if p == service.STATE_DIR or p.startswith(service.STATE_DIR + "/")]:
            del self.nodes[p]


def check(fake, paths):
    return service.owned_by_root(paths, stat=fake.stat, readlink=fake.readlink)


def bad_of(fake):
    return service.install_check(fake, fake.python_path, SYSTEMCTL)[0]


def run(fake, *argv):
    """cli.main over the made-up machine: (exit code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    old = sys.stderr
    sys.stderr = err
    platform = sys.platform
    if platform == "win32" and {"install", "remove", "status"} & set(argv):
        # The made-up machine is Linux's. On a Windows test machine `install`, `remove` and `status` would else go
        # to the real service manager (ADR-0013 V-4, W-5, X-2): the command is turned by sys.platform, so the test
        # says which it asks.
        sys.platform = "linux"
    try:
        saved = service.System
        service.System = lambda: fake
        try:
            code = cli.main(["service"] + list(argv), out=out)
        finally:
            service.System = saved
    finally:
        sys.stderr = old
        sys.platform = platform
    return code, out.getvalue(), err.getvalue()


# --- E1 (A-3, AB-3, AC-2): the walk, whole, over a made-up stat ---------------------------------------------------

def test_e1_the_clean_case_every_file_and_folder_under_sys_path_and_the_package_is_walked_and_counted():
    fake = Fake()
    bad, counts = service.install_check(fake, PY, SYSTEMCTL)
    assert bad is None
    under = [p for p in fake.nodes if p.startswith((STDLIB + "/", SITE + "/"))]
    assert len(under) > 12 and set(under) <= fake.lstats   # every file and folder below each entry, not only *.pth
    assert {PY, "/usr/bin/python3", "/usr/bin/python3.12", VENV + "/pyvenv.cfg", SYSTEMCTL, "/usr/bin/ss",
            service.UNIT_DIR} <= fake.lstats
    assert (counts["entries"], counts["missing"], counts["pth"], counts["pth_lines"], counts["cfg"], counts["ss"]) == (
        4, 1, 1, 0, 1, 1)   # the zip is missing under root's /usr/lib: checked as far as it exists, no refusal
    assert counts["links"] == 2 and counts["files"] >= 12 and counts["folders"] >= 10
    assert fake.reads == [SITE + "/distutils-precedence.pth"]   # read as text, its one line an import: no entry


def test_e1_a_users_file_inside_the_standard_librarys_folder():
    fake = Fake().add(STDLIB + "/json/decoder.py", "file", 0o644, uid=1000)
    assert bad_of(fake) == (STDLIB + "/json/decoder.py", "owned by uid 1000, not root")
    fake = Fake().add(STDLIB + "/__pycache__/json.cpython-312.pyc", "file", 0o666)
    assert bad_of(fake)[1] == "writable by others (mode 0666)"


def test_e1_a_users_sitecustomize_py_plain_or_by_a_link():
    fake = Fake().add(STDLIB + "/sitecustomize.py", "file", 0o644, uid=1000)
    assert bad_of(fake) == (STDLIB + "/sitecustomize.py", "owned by uid 1000, not root")
    fake = Fake().add("/etc/python3.12/sitecustomize.py", "file", 0o664).add(
        STDLIB + "/sitecustomize.py", "link", content="/etc/python3.12/sitecustomize.py")
    assert bad_of(fake) == ("/etc/python3.12/sitecustomize.py", "writable by its group (mode 0664) (on the way to"
                                                                  " %s/sitecustomize.py)" % STDLIB)


def test_e1_a_users_file_under_a_linked_sub_folder_of_the_package():
    fake = Fake().add("/srv/raqib-data/more/x.py", "file", 0o644, uid=1000).add(
        PKG + "/data", "link", content="/srv/raqib-data")
    assert bad_of(fake) == ("/srv/raqib-data/more/x.py", "owned by uid 1000, not root")
    fake.nodes["/srv/raqib-data/more/x.py"][2] = 0
    assert bad_of(fake) is None and "/srv/raqib-data/more" in fake.listed


def test_e1_a_missing_entry_under_a_folder_a_user_can_write_and_one_under_roots():
    fake = Fake(sys_path=[STDLIB, "/opt/shared/py/lib", SITE]).add("/opt/shared", mode=0o777)
    assert bad_of(fake) == ("/opt/shared", "writable by others (mode 0777) (on the way to /opt/shared/py/lib)")
    fake = Fake(sys_path=[STDLIB, "/opt/py/not-yet", SITE])
    bad, counts = service.install_check(fake, PY, SYSTEMCTL)
    assert bad is None and counts["missing"] == 1 and "/opt" in fake.lstats


def test_e1_a_pth_line_naming_such_a_place_absolute_or_relative_to_the_files_folder():
    fake = Fake().add("/opt/shared", mode=0o777).add(SITE + "/zz-extra.pth", "file", 0o644, content=(
        b"# a comment\n\nimport sys\n/opt/shared/later\n"))
    assert bad_of(fake) == ("/opt/shared", "writable by others (mode 0777) (on the way to /opt/shared/later)")
    fake = Fake().add("/srv/added/mod.py", "file", 0o644, uid=1000).add(
        SITE + "/zz-extra.pth", "file", 0o644, content=b"../../../../../../../../srv/added  \n")
    assert bad_of(fake) == ("/srv/added/mod.py", "owned by uid 1000, not root")
    assert service.pth_entries("# c\n\nimport os\n   \nrel/x  \n/abs\nimport\tsys\n", "/f/g") == ["/f/g/rel/x", "/abs"]


def test_e1_a_users_pth_file_is_refused_before_it_is_read():
    fake = Fake().add(SITE + "/zz-user.pth", "file", 0o644, uid=1000, content=b"/opt/elsewhere\n")
    assert bad_of(fake) == (SITE + "/zz-user.pth", "owned by uid 1000, not root")
    assert SITE + "/zz-user.pth" not in fake.reads


def test_e1_a_loop_of_folder_links_walks_each_real_folder_once():
    fake = Fake().add(PKG + "/loop", "link", content=".").add(PKG + "/rules/up", "link", content="..").add(
        SITE + "/back", "link", content=PKG).add(STDLIB + "/json/round", "link", content=STDLIB)
    bad, counts = service.install_check(fake, PY, SYSTEMCTL)
    assert bad is None and counts["links"] == 6
    walked = [p for p in fake.listed if p.startswith(("/usr/lib/", "/usr/local/"))]
    entries = (STDLIB, STDLIB + "/lib-dynload", SITE)   # an entry's folder is listed once more, for its *.pth
    assert {p: walked.count(p) for p in walked} == {p: 2 if p in entries else 1 for p in walked}


def test_e1_walk_max_passed_refuses_and_says_the_number(monkeypatch):
    monkeypatch.setattr(service, "WALK_MAX", 5)
    fake = Fake()
    where, why = bad_of(fake)
    assert why.startswith("more than 5 entries to walk (WALK_MAX): a walk that is not whole is not a pass")
    assert where == fake.listed[-1]   # the folder being walked when the bound was passed is the one said


def test_e1_a_world_writable_parent_three_levels_up_is_said_first_from_the_root_down():
    fake = Fake(python="/opt/venv/bin/python")
    fake.add("/opt", mode=0o777).add("/opt/venv/bin/python", "link", content="/usr/bin/python3")
    assert check(fake, ["/opt/venv/bin/python"]) == (
        "/opt", "writable by others (mode 0777) (on the way to /opt/venv/bin/python)")


def test_e1_a_user_owned_file_inside_the_package_and_a_group_writable_site_folder():
    fake = Fake().add(PKG + "/rules/engine.py", "file", 0o644, uid=1000)
    assert bad_of(fake) == (PKG + "/rules/engine.py", "owned by uid 1000, not root")
    fake = Fake()
    fake.nodes[SITE][1] = 0o775
    where, why = bad_of(fake)
    assert where == SITE and why.startswith("writable by its group (mode 0775)")


def test_e1_a_link_to_a_users_file_is_checked_as_what_it_points_to():
    fake = Fake().add("/srv/x.py", "file", 0o644, uid=1000).add(PKG + "/hooks.py", "link", content="/srv/x.py")
    assert bad_of(fake) == ("/srv/x.py", "owned by uid 1000, not root (on the way to %s/hooks.py)" % PKG)
    # a relative link through .. is walked as the system walks it, its folders checked too
    fake = Fake().add("/home/u", uid=1000).add("/home/u/x.py", "file", 0o644).add(
        PKG + "/x.py", "link", content="../../../../../../../../../../../home/u/x.py")
    assert check(fake, [PKG + "/x.py"])[0] == "/home/u"


def test_e1_a_link_is_checked_as_itself_by_its_owner_not_its_mode():
    fake = Fake()
    fake.nodes[PY] = ["link", 0o777, 0, "/usr/bin/python3"]   # a link's mode bits say nothing
    assert check(fake, [PY]) is None
    fake.nodes[PY][2] = 1000
    assert check(fake, [PY]) == (PY, "a link owned by uid 1000, not root")


def test_e1_a_loop_of_links_or_a_depth_past_the_bound_is_a_refusal_never_a_pass():
    fake = Fake().add("/srv/a", "link", content="/srv/b").add("/srv/b", "link", content="a")
    where, why = check(fake, ["/srv/a"])
    assert where in ("/srv/a", "/srv/b") and "more than 40 links" in why
    for i in range(service.LINK_DEPTH + 1):
        fake.add("/srv/l%d" % i, "link", content="/srv/l%d" % (i + 1))
    fake.add("/srv/l%d" % (service.LINK_DEPTH + 1), "file", 0o644)
    assert "more than 40 links" in check(fake, ["/srv/l0"])[1]
    assert check(fake, ["/srv/l1"]) is None   # 40 links: within the bound
    fake = Fake().add(PKG + "/a", "link", content="b").add(PKG + "/b", "link", content="a")
    assert "more than 40 links" in bad_of(fake)[1]   # a loop inside the package: refused, never a pass


def test_e1_pyvenv_cfg_beside_the_interpreter_or_one_folder_above_and_a_relative_sys_path_entry():
    fake = Fake().add(VENV + "/bin/pyvenv.cfg", "file", 0o666)
    assert bad_of(fake) == (VENV + "/bin/pyvenv.cfg", "writable by others (mode 0666)")
    fake = Fake(sys_path=["", "lib", SITE]).add("/lib/x.py", "file", 0o644, uid=1000)
    assert bad_of(fake) == ("/lib/x.py", "owned by uid 1000, not root")   # the folder it was started in, made whole


def test_e1_a_path_that_cannot_be_read_or_is_not_absolute_is_a_refusal():
    fake = Fake().add(PKG + "/gone.py", "link", content="/srv/none.py")
    assert check(fake, [PKG + "/gone.py"]) == (
        "/srv", "cannot be read (FileNotFoundError) (on the way to %s/gone.py)" % PKG)
    assert check(fake, ["raqib/cli.py"]) == ("raqib/cli.py", "not an absolute path")
    assert bad_of(fake) is None   # under an entry, a link's missing end is checked as far as it exists (root's /)


# --- E3 (A-3, A-5, A-6, AC-1, AC-5, AC-7): the unit's text, one constant with one hole ---------------------------

WHOLE = """# raqib-service/1
# Raqib's watch of this host as a unit of the system's (ADR-0013). Written by `raqib service install`,
# removed by `raqib service remove`. A unit of this name whose first line is not the mark above is not Raqib's.

[Unit]
Description=Raqib: the watch of this host (raqib watch --host)

[Service]
Type=simple
ExecStart=/usr/local/lib/raqib/venv/bin/python -I -m raqib watch --host --no-page --no-notify
Environment=HOME=/var/lib/raqib
StateDirectory=raqib
StateDirectoryMode=0700
Restart=always
RestartSec=5
KillSignal=SIGTERM
TimeoutStopSec=30
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
RestrictAddressFamilies=AF_UNIX AF_NETLINK
IPAddressDeny=any
CapabilityBoundingSet=CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
SystemCallFilter=@system-service
SystemCallArchitectures=native
UMask=0077

[Install]
WantedBy=multi-user.target
"""


def test_e3_the_whole_unit_text():
    assert service.unit_text(PY) == WHOLE
    assert service.UNIT_TEXT.count("%") == 1 and service.UNIT_TEXT.count("%s") == 1   # one hole, no other
    assert service.UNIT_TEXT.splitlines()[0] == service.MARK == "# raqib-service/1"
    assert service.UNIT_TEXT.isascii() and "ExecStart=%s " + service.EXEC + "\n" in service.UNIT_TEXT
    for gone in ("IPAddressAllow", "CAP_NET_ADMIN", "AF_INET", "SuccessExitStatus", "--no-open", "on-failure"):
        assert gone not in service.UNIT_TEXT, gone
    assert (service.UNIT_NAME, service.UNIT_DIR, service.STATE_DIR) == (
        "raqib-watch.service", "/etc/systemd/system", "/var/lib/raqib")


@pytest.mark.parametrize("python", ["/usr/local/lib/my venv/bin/python", "/x\nExecStartPre=/bin/sh",
                                    "/opt/%h/python", "bin/python", "", "/usr/../tmp/python", "/usr//bin/python",
                                    "/usr/bin/pyth\u00f6n", None])
def test_e3_the_hole_takes_only_a_plain_whole_path_of_the_safe_characters(python):
    with pytest.raises(service.Refused):
        service.unit_text(python)


# --- E2 (A-4, A-7, AC-3, AC-4): install, refused ------------------------------------------------------------------

def refused(fake, *argv):
    code, out, err = run(fake, *argv)
    assert code == 2 and fake.writes == [] and fake.calls == [] and fake.removed == [], (code, out, err)
    return err


def test_e2_refused_off_linux_and_without_root_no_elevation_asked():
    assert "Linux only (systemd); this is win32" in refused(Fake(platform="win32"), "install")
    err = refused(Fake(uid=1000), "install")
    assert "not root, nothing done" in err and "it asks for no elevation" in err


def test_e2_refused_where_the_interpreter_runs_without_its_site():
    fake = Fake()
    fake.no_site_flag = True
    assert "this interpreter runs without its site (-S, sys.flags.no_site)" in refused(fake, "install")


def test_e2_refused_where_the_package_is_not_in_one_of_the_interpreters_site_folders():
    fake = Fake()
    fake.pkg = "/srv/checkout/raqib"   # a checkout run by -m, or an editable install
    err = refused(fake.add("/srv/checkout/raqib/cli.py", "file", 0o644), "install")
    assert "the raqib package it runs from, /srv/checkout/raqib, is not directly in one of this interpreter's" in err
    assert "install raqib into this interpreter" in err and "a checkout, an editable install or a copy" in err
    fake = Fake()
    fake.sites = [SITE + "-other"]
    assert "is not directly in one of this interpreter's site folders (%s-other)" % SITE in refused(fake, "install")
    fake = Fake().add(SITE + "/vendor/raqib/cli.py", "file", 0o644)
    fake.pkg = SITE + "/vendor/raqib"   # AD-4 (G8): a copy deeper below a site folder is not the one -m imports
    assert "%s/vendor/raqib, is not directly in one" % SITE in refused(fake, "install")


def test_e4_refused_where_pythonhome_or_pythonplatlibdir_is_set_and_the_environment_is_read():
    for name in ("PYTHONHOME", "PYTHONPLATLIBDIR"):
        fake = Fake()
        fake.env = {name: ""}
        err = refused(fake, "install")
        assert "refused: %s is set and this interpreter reads its environment" % name in err and "-I or -E" in err
    fake = Fake()
    fake.env, fake.ignore_env = {"PYTHONHOME": "/srv/elsewhere"}, True   # -I or -E: the variable moves nothing
    assert run(fake, "install")[0] == 0
    assert service.ENV_MOVES == ("PYTHONHOME", "PYTHONPLATLIBDIR")


@pytest.mark.parametrize("content,byte", [(b"/srv/a\x0b../../x\n", "0x0b"), (b"\xef\xbb\xbf/srv/a\n", "0xef"),
                                          (b"/srv/a\x85\n", "0x85"), (b"/srv/\x00\n", "0x00"),
                                          (b"/srv/a\x1c\n", "0x1c")])
def test_e4_a_pth_file_holding_a_byte_site_reads_differently_is_refused_and_not_read_into_entries(content, byte):
    fake = Fake().add(SITE + "/zz-odd.pth", "file", 0o644, content=content)
    where, why = bad_of(fake)
    assert where == SITE + "/zz-odd.pth" and why.startswith("a .pth file holding byte %s at offset" % byte)
    assert "it is not read" in why and "/srv/a" not in fake.lstats
    fake = Fake().add("/srv/b").add(SITE + "/zz-ok.pth", "file", 0o644, content=b"\t/srv/tabbed\r\n/srv/b\r")
    assert bad_of(fake) is None and "/srv/b" in fake.lstats   # tab, CR and LF are what every site reads alike


def test_e2_the_list_holds_systemctl_the_watchs_ss_and_the_units_folder():
    assert service.SS_PATHS == discover.SS_PATHS
    fake = Fake()
    fake.nodes[SYSTEMCTL][2] = 1000
    assert "refused: /usr/bin/systemctl is owned by uid 1000, not root" in refused(fake, "install")
    fake = Fake()
    fake.nodes["/usr/bin/ss"][1] = 0o777
    assert "refused: /usr/bin/ss is writable by others (mode 0777)" in refused(fake, "install")
    fake = Fake().add("/usr/sbin", mode=0o775)   # no ss there yet: its folder comes first in the watch's order
    assert "refused: /usr/sbin is writable by its group (mode 0775)" in refused(fake, "install")
    fake = Fake()
    fake.nodes[service.UNIT_DIR][2] = 1000
    assert "refused: /etc/systemd/system is owned by uid 1000, not root" in refused(fake, "install")


def test_e2_refused_where_e1_fails_the_path_said():
    fake = Fake(python="/opt/venv/bin/python")
    fake.add("/opt", mode=0o777).add("/opt/venv/bin/python", "link", content="/usr/bin/python3")
    err = refused(fake, "install")
    assert "refused: /opt is writable by others (mode 0777)" in err and "ADR-0013 A-3" in err
    assert UNIT not in fake.nodes


def test_e2_refused_where_the_interpreters_path_holds_another_character():
    fake = Fake(python="/usr/local/lib/my venv/bin/python")
    assert "outside A-Za-z0-9/._+-" in refused(fake, "install")


def test_e2_refused_where_no_systemctl_is_at_a_fixed_path():
    assert "no systemctl at /usr/bin/systemctl or /bin/systemctl" in refused(Fake(systemctl=None), "install")
    assert service.SYSTEMCTLS == ("/usr/bin/systemctl", "/bin/systemctl")


def test_e2_refused_where_a_unit_of_the_name_is_not_raqibs_and_it_is_not_touched():
    fake = Fake().unit("[Service]\nExecStart=/usr/bin/other\n")
    assert "does not carry Raqib's mark" in refused(fake, "install")
    assert fake.nodes[UNIT][3] == b"[Service]\nExecStart=/usr/bin/other\n"
    fake = Fake().add(UNIT, "link", content="/srv/unit")
    assert "is a link, not Raqib's file" in refused(fake, "install")


def test_e2_run_systemctl_a_list_no_shell_a_fixed_environment_a_timeout(monkeypatch):
    seen = []

    def fake_run(argv, **kw):
        seen.append((argv, kw))
        return SimpleNamespace(returncode=0, stdout=b"ok\n", stderr=b"")
    monkeypatch.setattr(service.subprocess, "run", fake_run)
    assert service.run_systemctl("/usr/bin/systemctl", ["daemon-reload"]) == (0, "ok", "")
    ((argv, kw),) = seen
    assert argv == ["/usr/bin/systemctl", "daemon-reload"] and "shell" not in kw
    assert kw["env"] == service.SYSTEMCTL_ENV and kw["timeout"] == service.SYSTEMCTL_TIMEOUT and kw["cwd"] == "/"
    assert service.run_systemctl("systemctl", ["daemon-reload"])[0] is None and len(seen) == 1   # never by PATH

    def late(argv, **kw):
        raise subprocess.TimeoutExpired(argv, kw["timeout"])
    monkeypatch.setattr(service.subprocess, "run", late)
    code, _, err = service.run_systemctl("/bin/systemctl", ["show"])
    assert code is None and err.startswith("no answer in 120 s")

    def missing(argv, **kw):
        raise FileNotFoundError(argv[0])
    monkeypatch.setattr(service.subprocess, "run", missing)
    assert service.run_systemctl("/bin/systemctl", ["show"]) == (None, "", "cannot be run (FileNotFoundError)")


def test_e2_the_unit_is_written_beside_and_renamed_over_and_a_failed_write_leaves_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(service, "UNIT_DIR", str(tmp_path))
    monkeypatch.setattr(service, "UNIT_PATH", str(tmp_path / "raqib-watch.service"))
    owners = []
    monkeypatch.setattr(service.os, "fchown", lambda fd, uid, gid: owners.append((uid, gid)), raising=False)
    monkeypatch.setattr(service.os, "fchmod", lambda fd, mode: owners.append(mode), raising=False)
    service.System().write_unit("one\n")
    service.System().write_unit(WHOLE)
    assert (tmp_path / "raqib-watch.service").read_bytes() == WHOLE.encode("ascii")
    assert sorted(p.name for p in tmp_path.iterdir()) == ["raqib-watch.service"] and owners[:2] == [(0, 0), 0o644]

    def broken(fd):
        raise OSError(28, "no space")
    monkeypatch.setattr(service.os, "fsync", broken)
    with pytest.raises(OSError):
        service.System().write_unit("three\n")
    assert sorted(p.name for p in tmp_path.iterdir()) == ["raqib-watch.service"]
    assert (tmp_path / "raqib-watch.service").read_bytes() == WHOLE.encode("ascii")


def test_e2_the_system_object_gives_the_flags_and_the_site_folders():
    real = service.System()
    assert real.no_site() is bool(sys.flags.no_site)
    assert isinstance(real.site_packages(), list) and all(isinstance(s, str) for s in real.site_packages())


# --- E4 (A-4, AC-6, AC-8): install, its words, its wait -----------------------------------------------------------

def test_e4_install_says_its_counts_by_kind_waits_and_asks_systemctl():
    fake = Fake()
    code, out, err = run(fake, "install")
    assert code == 0 and err == "" and fake.writes == [WHOLE] and fake.slept == [service.START_WAIT] == [3]
    assert fake.calls == [HELD, ["daemon-reload"], LOADED, ["enable", "--now", "raqib-watch.service"], AFTER]
    assert "wrote /etc/systemd/system/raqib-watch.service (root, 0644): ExecStart=%s %s" % (PY, service.EXEC) in out
    line = [x for x in out.splitlines() if x.startswith("  checked ")][0]
    _, counts = service.install_check(Fake(), PY, SYSTEMCTL)
    assert line == "  " + service.checked_words(counts)
    assert ("each owned by root, and each but a link writable by neither its group nor others (a link is checked by"
            " its owner, then what it points to): %d folders, %d files, %d links, 0 of another kind" % (
                counts["folders"], counts["files"], counts["links"])) in line
    assert "root's alone (ADR-0013 A-3)" not in out and "every path the unit loads" not in out
    assert "after 3 s: ActiveState=active, SubState=running, Result=success, ExecMainStatus=0, NRestarts=0" in out
    assert out.rstrip().endswith("RESULT: installed, enabled, active 3 s after its start")
    assert "NOT AS INSTALLED" not in out


def test_e4_not_active_after_the_wait_is_exit_1_with_the_state_and_the_result():
    fake = Fake()
    fake.shows = [SHOW_GONE, SHOW_ACTIVE, SHOW_FAILED]   # before the write, after the reload, after the wait
    code, out, _ = run(fake, "install")
    assert code == 1 and "ActiveState=failed" in out and "Result=exit-code" in out and "ExecMainStatus=1" in out
    assert out.rstrip().endswith("RESULT: installed, enabled, NOT ACTIVE 3 s after its start (journalctl -u"
                                 " raqib-watch.service says why)")
    fake = Fake()
    fake.shows = [SHOW_GONE, SHOW_ACTIVE, "LoadState=loaded\n"]
    code, out, _ = run(fake, "install")
    assert code == 1 and "(no ActiveState)" in out and "its state 3 s after its start NOT KNOWN" in out


def test_e4_over_raqibs_own_unit_it_restarts_it():
    fake = Fake().unit(service.MARK + "\n[Service]\nExecStart=/old\n")
    code, out, _ = run(fake, "install")
    assert code == 0 and fake.nodes[UNIT][3] == WHOLE.encode("ascii")
    assert fake.calls == [["daemon-reload"], LOADED, ["enable", "raqib-watch.service"],
                          ["restart", "raqib-watch.service"], AFTER]
    assert "replaced Raqib's own /etc/systemd/system/raqib-watch.service" in out and fake.slept == [3]
    lines = out.splitlines()
    said = [i for i, x in enumerate(lines) if "it was restarted, so no watch keeps the old text" in x]
    done = [i for i, x in enumerate(lines) if x.endswith("restart raqib-watch.service: done")]
    assert said and done and said[0] > done[0]   # said after the restart ran, never before (G12)
    fake = Fake().unit(service.MARK + "\n[Service]\nExecStart=/old\n")
    fake.fail["restart"] = (1, "", "made-up")
    code, out, _ = run(fake, "install")
    assert code == 1 and "restarted" not in out


def test_e4_no_start_neither_enables_nor_starts_and_over_a_running_unit_says_it_keeps_its_text():
    fake = Fake()
    code, out, _ = run(fake, "install", "--no-start")
    assert code == 0 and fake.writes == [WHOLE] and fake.calls == [HELD, ["daemon-reload"], LOADED]
    assert "neither enabled nor started" in out and "keeps the text" not in out and fake.slept == []
    fake = Fake().unit(service.MARK + "\n[Service]\nExecStart=/old\n")
    code, out, _ = run(fake, "install", "--no-start")
    assert code == 0 and fake.calls == [["daemon-reload"], LOADED]
    assert "a watch is running: it keeps the text it started with until: systemctl restart raqib-watch.service" in out


def test_e4_a_systemctl_that_fails_is_said_and_left_as_it_is():
    fake = Fake()
    fake.fail["enable"] = (1, "", "Failed to enable unit: made-up")
    code, out, _ = run(fake, "install")
    assert code == 1 and fake.removed == [] and UNIT in fake.nodes
    assert "enable --now raqib-watch.service: FAILED: exit 1, said: Failed to enable unit: made-up" in out
    assert "left as it is" in out


# --- E4 (A-4): remove ------------------------------------------------------------------------------------------------

def installed(**kw):
    fake = Fake(**kw).unit(WHOLE)
    fake.add(service.STATE_DIR, mode=0o700).add(service.RECORD + "/events.jsonl", "file", 0o600)
    return fake


def test_e4_remove_stops_disables_removes_reloads_and_the_record_stays_its_path_said():
    fake = installed()
    code, out, err = run(fake, "remove")
    assert code == 0 and err == ""
    assert fake.calls == [["disable", "--now", "raqib-watch.service"], ["daemon-reload"],
                          ["show", "raqib-watch.service", "--no-pager", "--property=ActiveState"]]
    assert fake.removed == [UNIT] and "reset-failed" not in out
    assert UNIT not in fake.nodes and service.RECORD + "/events.jsonl" in fake.nodes
    assert "the record stays: /var/lib/raqib (its events: /var/lib/raqib/.raqib/host/events.jsonl)" in out


def test_e4_remove_is_root_only_and_linux_only():
    assert "not root" in refused(installed(uid=1000), "remove")
    assert "Linux only" in refused(installed(platform="darwin"), "remove")


def test_e4_a_unit_without_the_mark_is_not_touched():
    fake = Fake().unit("[Service]\nExecStart=/usr/bin/other\n")
    assert "does not carry Raqib's mark" in refused(fake, "remove") and UNIT in fake.nodes


def test_e4_purge_removes_that_folder_and_only_it():
    fake = installed()
    code, out, _ = run(fake, "remove", "--purge")
    assert code == 0 and fake.removed == [UNIT, service.STATE_DIR] and "/var/lib" in fake.nodes
    assert not [p for p in fake.nodes if p.startswith(service.STATE_DIR)]
    assert "--purge: removed /var/lib/raqib, and nothing else" in out
    code, out, _ = run(Fake(), "remove", "--purge")
    assert code == 0 and "--purge: no /var/lib/raqib, nothing to remove" in out


def test_e4_purge_refuses_a_state_path_that_is_a_link_or_is_not_var_lib_raqib_nothing_touched():
    fake = installed()
    with pytest.raises(service.Refused, match="removes /var/lib/raqib and nothing else; /var/lib/other"):
        service.remove(fake, io.StringIO(), purge=True, state="/var/lib/other")
    fake = Fake().unit(WHOLE).add("/srv/elsewhere").add(service.STATE_DIR, "link", content="/srv/elsewhere")
    assert "/var/lib/raqib is a link: not followed, not removed" in refused(fake, "remove", "--purge")
    assert UNIT in fake.nodes and "/srv/elsewhere" in fake.nodes
    fake = Fake().unit(WHOLE).add(service.STATE_DIR, uid=1000)
    assert "not root: not the service's" in refused(fake, "remove", "--purge")


def test_e4_a_failing_disable_leaves_the_unit_as_it_is():
    fake = installed()
    fake.fail["disable"] = (1, "", "made-up failure")
    code, out, _ = run(fake, "remove", "--purge")
    assert code == 1 and fake.removed == [] and "FAILED: exit 1, said: made-up failure" in out


@pytest.mark.skipif(os.name == "nt" or not getattr(os, "symlink", None), reason="links as POSIX makes them")
def test_e4_the_records_removal_does_not_follow_a_link_out_of_it(tmp_path, monkeypatch):
    state, outside = tmp_path / "raqib", tmp_path / "outside"
    (state / ".raqib" / "host").mkdir(parents=True)
    outside.mkdir()
    (outside / "keep.txt").write_text("kept", encoding="ascii")
    os.symlink(str(outside), str(state / ".raqib" / "out"))
    monkeypatch.setattr(service, "STATE_DIR", str(state))
    service.System().remove_state()
    assert not state.exists() and (outside / "keep.txt").read_text(encoding="ascii") == "kept"


def test_e4_and_e2_options_belong_to_their_action():
    assert "--no-start is install's only" in refused(Fake(), "remove", "--no-start")
    assert "--purge is remove's only" in refused(Fake(), "install", "--purge")


# --- E5 (A-8, AC-7, AC-9): remove with no file, status, the words of systemctl ------------------------------------

LOADSTATE = HELD


def test_e5_remove_with_no_unit_file_asks_systemctl_and_not_found_is_exit_0():
    fake = Fake()
    code, out, _ = run(fake, "remove")
    assert code == 0 and fake.calls == [LOADSTATE] and fake.removed == []
    assert ("no unit installed (no /etc/systemd/system/raqib-watch.service; systemd: LoadState=not-found,"
            " ActiveState=inactive)") in out
    assert "RESULT: nothing installed" in out


def test_e5_remove_with_no_unit_file_and_a_unit_of_the_name_still_loaded_is_exit_1_nothing_touched():
    fake = Fake().add(service.STATE_DIR, mode=0o700)
    fake.gone = "LoadState=loaded\nActiveState=active\n"
    code, out, _ = run(fake, "remove", "--purge")
    assert code == 1 and fake.calls == [LOADSTATE] and fake.removed == [] and service.STATE_DIR in fake.nodes
    assert "but systemd still has a unit of the name: LoadState=loaded, ActiveState=active" in out
    assert "nothing touched, nothing purged" in out
    assert "RESULT: nothing touched, a unit of the name is still held by systemd" in out
    fake = Fake()
    fake.fail["show"] = (None, "", "no answer in 120 s (made-up)")
    code, out, _ = run(fake, "remove")
    assert code == 1 and "is not known: systemctl show: no answer in 120 s" in out and "not run" not in out


def test_e5_status_active_is_0_by_systemctls_own_words_and_needs_no_rights():
    fake = installed(uid=1000)
    code, out, _ = run(fake, "status")
    assert code == 0 and fake.calls == [["show", "raqib-watch.service", "--no-pager", PROPS]]
    assert PROPS == ("--property=LoadState,UnitFileState,ActiveState,SubState,Result,ExecMainStatus,NRestarts,"
                     "FragmentPath,DropInPaths,NeedDaemonReload")
    assert "installed: /etc/systemd/system/raqib-watch.service (it carries # raqib-service/1)" in out
    assert "enabled: enabled (systemctl's UnitFileState)" in out and "active: active, running" in out
    assert "restarts: 0 (systemctl's NRestarts; each restart is a gap in the watch)" in out
    assert "ACTIVE says the unit runs, not that the watch writes its record" in out
    assert out.rstrip().endswith("RESULT: ACTIVE")


def test_e5_installed_and_not_active_is_1_with_the_last_result_the_restarts_and_what_exit_1_is():
    code, out, _ = run(installed(uid=1000, show=SHOW_FAILED), "status")
    assert code == 1 and "last result: exit-code, exit status 1" in out and "RESULT: INSTALLED, NOT ACTIVE" in out
    assert "restarts: 4" in out
    assert ("exit status 1: the watch's own ALARM at its end, or an error; the journal says which (journalctl -u"
            " raqib-watch.service)") in out


def test_e5_a_fragment_elsewhere_or_a_drop_in_is_said_and_is_not_exit_0():
    fake = installed(uid=1000, show=SHOW_ACTIVE.replace("FragmentPath=" + UNIT, "FragmentPath=/run/systemd/"
                                                        "transient/raqib-watch.service"))
    code, out, _ = run(fake, "status")
    assert code == 1 and out.rstrip().endswith("RESULT: ACTIVE, NOT AS INSTALLED")
    assert "loaded from /run/systemd/transient/raqib-watch.service, not %s" % UNIT in out
    fake = installed(uid=1000, show=SHOW_ACTIVE.replace("DropInPaths=", "DropInPaths=/etc/systemd/system/"
                                                        "raqib-watch.service.d/x.conf"))
    code, out, _ = run(fake, "status")
    assert code == 1 and "drop-ins change the unit: /etc/systemd/system/raqib-watch.service.d/x.conf" in out
    assert out.rstrip().endswith("RESULT: ACTIVE, NOT AS INSTALLED")
    code, out, _ = run(installed(uid=1000, show=SHOW_FAILED + "DropInPaths=/run/x.conf\n"), "status")
    assert code == 1 and out.rstrip().endswith("RESULT: INSTALLED, NOT ACTIVE, NOT AS INSTALLED")


def test_e5_not_installed_is_3_a_unit_without_the_mark_is_not_raqibs_and_one_that_cannot_be_read_is_not_known():
    code, out, _ = run(Fake(uid=1000), "status")
    assert code == 3 and "not installed: no /etc/systemd/system/raqib-watch.service" in out
    code, out, _ = run(Fake(uid=1000).unit("[Service]\n"), "status")
    assert code == 3 and "not Raqib's" in out
    fake = installed(uid=1000)
    fake.unreadable = True
    code, out, _ = run(fake, "status")
    assert code == 3 and "cannot be read (PermissionError)" in out and out.rstrip().endswith("RESULT: NOT KNOWN")
    assert "NOT INSTALLED" not in out


def test_e5_a_systemctl_that_timed_out_or_exited_non_zero_is_said_as_it_was_never_as_not_run():
    code, out, _ = run(installed(uid=1000, systemctl=None), "status")
    assert code == 3 and "no systemctl at /usr/bin/systemctl or /bin/systemctl" in out and "NOT KNOWN" in out
    fake = installed(uid=1000)
    fake.fail["show"] = (None, "", "no answer in 120 s (systemctl stopped; made-up)")
    code, out, _ = run(fake, "status")
    assert code == 3 and "gave no state: no answer in 120 s" in out
    fake = installed(uid=1000)
    fake.fail["show"] = (1, "", "Failed to connect to bus: made-up")
    code, out, _ = run(fake, "status")
    assert code == 3 and "gave no state: exit 1, said: Failed to connect to bus: made-up" in out
    said = [out]
    fake = Fake()
    fake.fail["enable"] = (None, "", "no answer in 120 s (systemctl stopped; made-up)")
    code, out, _ = run(fake, "install")
    assert code == 1 and "enable --now raqib-watch.service: FAILED: no answer in 120 s" in out
    said.append(out)
    for action, fail in (("status", (None, "", "no answer in 120 s (made-up)")), ("remove", (1, "", "made-up"))):
        fake = installed(uid=1000 if action == "status" else 0)
        fake.fail["show" if action == "status" else "disable"] = fail
        said.append(run(fake, action)[1])
    assert "FAILED: exit 1, said: made-up" in said[-1] and "gave no state: no answer in 120 s" in said[-2]
    for words in said:   # each a systemctl that ran: timed out or exited non-zero, never said as not run (G14)
        assert "not run" not in words and "cannot be run" not in words, words


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="a FIFO as POSIX makes it")
def test_e5_the_units_head_is_read_without_waiting_and_only_from_a_regular_file(tmp_path):
    (tmp_path / "unit").write_bytes(b"# raqib-service/1\n[Unit]\n")
    real = service.System()
    assert real.read_head(str(tmp_path / "unit")) == b"# raqib-service/1\n[Unit]\n"
    os.mkfifo(str(tmp_path / "fifo"))
    with pytest.raises(OSError, match="not a regular file"):
        real.read_head(str(tmp_path / "fifo"))   # O_NONBLOCK: no writer, and still no wait
    with pytest.raises(OSError, match="not a regular file"):
        real.read_bytes(str(tmp_path / "fifo"), service.PTH_MAX)
    (tmp_path / "a.pth").write_bytes(b"/srv/x\n")
    assert real.read_bytes(str(tmp_path / "a.pth"), service.PTH_MAX) == b"/srv/x\n"
    with pytest.raises(OSError, match="longer than 3 bytes"):
        real.read_bytes(str(tmp_path / "a.pth"), 3)
    assert real.read_head(str(tmp_path / "unit"), 7) == b"# raqib"


def test_e5_not_linux_is_2():
    assert "Linux only" in refused(Fake(uid=1000, platform="win32"), "status")


# --- REDO 4, E1 (AD-1): with no unit file, systemd is asked before a state is said or a file written -----------

HELD_BY = (("LoadState=not-found\nActiveState=active\nFragmentPath=\n", "ActiveState=active"),
           ("LoadState=loaded\nActiveState=inactive\nFragmentPath=/usr/lib/systemd/system/raqib-watch.service\n",
            "FragmentPath=/usr/lib/systemd/system/raqib-watch.service"),
           ("LoadState=not-found\nActiveState=activating\nFragmentPath=\n", "ActiveState=activating"),
           ("LoadState=not-found\nActiveState=reloading\nFragmentPath=\n", "ActiveState=reloading"),
           ("LoadState=masked\nActiveState=inactive\nFragmentPath=/dev/null\n", "LoadState=masked"))


@pytest.mark.parametrize("gone,words", HELD_BY)
def test_e1_install_with_no_file_refuses_a_unit_of_the_name_systemd_holds_naming_where_from(gone, words):
    fake = Fake()
    fake.gone = gone
    code, out, err = run(fake, "install")
    assert code == 2 and fake.writes == [] and fake.calls == [HELD] and UNIT not in fake.nodes, (out, err)
    assert "yet systemd holds a unit of the name (" in err and words in err and "FragmentPath=" in err
    assert "nothing written" in err


def test_e1_install_with_no_file_and_no_answer_from_systemctl_is_refused():
    for fail in ((None, "", "no answer in 120 s (made-up)"), (1, "", "Failed to connect to bus: made-up")):
        fake = Fake()
        fake.fail["show"] = fail
        code, _, err = run(fake, "install")
        assert code == 2 and fake.writes == [] and fake.calls == [HELD] and "systemd gave no word" in err
    fake = Fake()
    fake.gone = "LoadState=not-found\nActiveState=failed\n"   # a failed unit of the name, nothing of it running
    assert run(fake, "install")[0] == 0 and fake.writes == [WHOLE]


@pytest.mark.parametrize("gone,words", HELD_BY)
def test_e1_remove_with_no_file_and_a_unit_systemd_holds_is_exit_1_nothing_touched_nothing_purged(gone, words):
    fake = Fake().add(service.STATE_DIR, mode=0o700).add(service.RECORD + "/events.jsonl", "file", 0o600)
    fake.gone = gone
    code, out, _ = run(fake, "remove", "--purge")
    assert code == 1 and fake.calls == [HELD] and fake.removed == [] and service.RECORD + "/events.jsonl" in fake.nodes
    assert words in out and "nothing touched, nothing purged" in out and "RESULT: nothing installed" not in out


def test_e1_status_with_no_file_asks_and_says_a_unit_of_the_name_that_systemd_holds():
    fake = Fake(uid=1000)
    fake.gone = HELD_BY[0][0]   # LoadState=not-found, ActiveState=active: a file deleted under a running unit
    code, out, _ = run(fake, "status")
    assert code == 3 and fake.calls == [HELD]
    assert out.rstrip().endswith("RESULT: NOT INSTALLED BY RAQIB, YET A UNIT OF THE NAME IS ACTIVE")
    fake = Fake(uid=1000)
    fake.gone = HELD_BY[1][0]
    code, out, _ = run(fake, "status")
    assert code == 3 and out.rstrip().endswith("RESULT: NOT INSTALLED BY RAQIB, YET A UNIT OF THE NAME IS LOADED")
    assert "FragmentPath=/usr/lib/systemd/system/raqib-watch.service" in out
    fake = Fake(uid=1000)
    fake.fail["show"] = (None, "", "no answer in 120 s (made-up)")
    code, out, _ = run(fake, "status")
    assert code == 3 and "NOT KNOWN WHETHER A UNIT OF THE NAME RUNS" in out and "no answer in 120 s" in out
    code, out, _ = run(Fake(uid=1000), "status")
    assert code == 3 and out.rstrip().endswith("RESULT: NOT INSTALLED") and "NOT INSTALLED BY RAQIB" not in out


# --- REDO 4, E2 (AD-2): "as installed" is the whole text, and a file systemd has loaded ---------------------------

def test_e2_status_a_changed_directive_with_the_mark_kept_is_not_as_installed():
    fake = installed(uid=1000)
    fake.unit(WHOLE.replace("ProtectSystem=strict\n", "ProtectSystem=no\n"))
    code, out, _ = run(fake, "status")
    assert code == 1 and out.rstrip().endswith("RESULT: ACTIVE, NOT AS INSTALLED")
    assert ("NOT AS INSTALLED: the unit's file is a different text from the one this Raqib writes for %s" % PY) in out
    fake.unit(WHOLE.replace("ExecStart=" + PY, "ExecStart=/usr/bin/other " + PY))   # another program in front
    assert "different text from the one this Raqib writes for /usr/bin/other" in run(fake, "status")[1]
    fake.unit(WHOLE.replace("ExecStart=" + PY, "ExecStart=/usr/bin/other"))   # the interpreter is the file's word
    assert run(fake, "status")[0] == 0   # what status does not see: which interpreter the install named (docs)
    fake.unit(WHOLE.replace("ExecStart=" + PY, "ExecStart=-" + PY))
    assert "its ExecStart names no interpreter of the safe characters" in run(fake, "status")[1]
    fake.unit(WHOLE + "#" * service.UNIT_MAX)
    assert "longer than %d bytes (UNIT_MAX)" % service.UNIT_MAX in run(fake, "status")[1]


def test_e2_status_a_file_changed_and_not_reloaded_is_not_as_installed_and_the_clean_case_is_active():
    fake = installed(uid=1000, show=SHOW_ACTIVE.replace("NeedDaemonReload=no", "NeedDaemonReload=yes"))
    code, out, _ = run(fake, "status")
    assert code == 1 and "changed since systemd loaded it (systemctl's NeedDaemonReload=yes)" in out
    code, out, _ = run(installed(uid=1000), "status")
    assert code == 0 and "NOT AS INSTALLED" not in out and out.rstrip().endswith("RESULT: ACTIVE")
    assert service.text_differs(WHOLE.encode("ascii")) is None and service.UNIT_MAX == 16384


# --- REDO 4, E3 (AD-3): the install does not start what is not as installed ---------------------------------------

def test_e3_not_as_installed_after_the_reload_is_exit_1_neither_enabled_nor_started():
    for text, words in (("DropInPaths=", "DropInPaths=/etc/systemd/system/raqib-watch.service.d/x.conf"),
                        ("FragmentPath=" + UNIT, "FragmentPath=/run/systemd/transient/raqib-watch.service"),
                        ("NeedDaemonReload=no", "NeedDaemonReload=yes")):
        for argv in (["install"], ["install", "--no-start"]):
            fake = Fake(show=SHOW_ACTIVE.replace(text, words))
            code, out, _ = run(fake, *argv)
            assert code == 1 and fake.calls == [HELD, ["daemon-reload"], LOADED] and fake.slept == [], out
            assert "RESULT: the unit is written; NOT AS INSTALLED, not started: " in out
    fake = Fake(show=SHOW_ACTIVE.replace("DropInPaths=", "DropInPaths=/run/x.conf"))
    assert run(fake, "install")[1].rstrip().endswith("not started: drop-ins change the unit: /run/x.conf"
                                                     " (systemctl's DropInPaths)")


def test_e3_not_as_installed_after_the_wait_is_exit_1_and_the_result_says_it():
    fake = Fake()
    fake.shows = [SHOW_GONE, SHOW_ACTIVE, SHOW_ACTIVE.replace("DropInPaths=", "DropInPaths=/run/late.conf")]
    code, out, _ = run(fake, "install")
    assert code == 1 and out.rstrip().endswith("RESULT: installed, enabled, active 3 s after its start, NOT AS"
                                               " INSTALLED: drop-ins change the unit: /run/late.conf (systemctl's"
                                               " DropInPaths)")


# --- REDO 4, E5 (AD-5): remove forgets the failed state of the unit it removed ------------------------------------

def test_e5_remove_resets_a_failed_state_of_the_removed_unit_and_says_so_and_a_failed_reset_is_said():
    fake = installed()
    fake.gone = "LoadState=not-found\nActiveState=failed\n"
    code, out, _ = run(fake, "remove")
    assert code == 0 and fake.calls[-2:] == [["show", "raqib-watch.service", "--no-pager", "--property=ActiveState"],
                                            ["reset-failed", "raqib-watch.service"]]
    assert "systemd held the removed unit as failed" in out and "reset-failed raqib-watch.service: done" in out
    fake = installed()
    fake.gone = "LoadState=not-found\nActiveState=failed\n"
    fake.fail["reset-failed"] = (1, "", "made-up")
    code, out, _ = run(fake, "remove")
    assert code == 0 and "reset-failed raqib-watch.service: FAILED: exit 1, said: made-up" in out
    assert out.rstrip().endswith("RESULT: removed")


# --- E8: one object for the system; the standard library; imported only by the service command -------------------

SERVICE_PY = ROOT / "raqib" / "service.py"


def test_e8_every_call_of_the_system_is_in_system_or_run_systemctl_and_the_fake_answers_them_all():
    tree = ast.parse(SERVICE_PY.read_text(encoding="utf-8"))
    (system,) = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "System"]
    (runner,) = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "run_systemctl"]
    inside = {id(n) for top in (system, runner) for n in ast.walk(top)}
    for n in ast.walk(tree):
        if isinstance(n, ast.Call) and id(n) not in inside:
            root = n.func
            while isinstance(root, ast.Attribute):
                root = root.value
            assert not (isinstance(root, ast.Name) and root.id in ("os", "shutil", "subprocess", "open", "time",
                                                                    "site")), ast.unparse(n)
            assert not (isinstance(n.func, ast.Name) and n.func.id == "open"), ast.unparse(n)
    methods = {f.name for f in system.body if isinstance(f, ast.FunctionDef)}
    assert methods <= set(dir(Fake)), methods - set(dir(Fake))


def test_e8_service_is_the_standard_librarys_alone_no_network_nothing_run_at_import():
    tree = ast.parse(SERVICE_PY.read_text(encoding="utf-8"))
    imported = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    imported |= {(n.module or "").split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    if hasattr(sys, "stdlib_module_names"):
        assert imported - {"__future__"} <= set(sys.stdlib_module_names)
    assert not imported & {"socket", "ssl", "http", "urllib", "asyncio", "selectors", "select", "ctypes", "raqib"}
    for n in tree.body:   # at import: the docstring, imports, constants, functions and classes only
        assert isinstance(n, (ast.Expr, ast.Import, ast.ImportFrom, ast.Assign, ast.FunctionDef, ast.ClassDef)), \
            ast.unparse(n)
        if isinstance(n, ast.Expr):
            assert isinstance(n.value, ast.Constant)
        if isinstance(n, ast.Assign):
            assert not [c for c in ast.walk(n.value) if isinstance(c, ast.Call) and
                        ast.unparse(c.func) not in ("re.compile",)], ast.unparse(n)
    assert SERVICE_PY.read_bytes().isascii()


def test_e8_service_is_imported_only_inside_the_service_command():
    tree = ast.parse((ROOT / "raqib" / "cli.py").read_text(encoding="utf-8"))
    where = []
    for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        for n in ast.walk(fn):
            if isinstance(n, ast.ImportFrom) and any(a.name == "service" for a in n.names):
                where.append(fn.name)
    tops = [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))]
    assert where == ["cmd_service"] and not any("service" in ast.unparse(n) for n in tops)
    others = [p for p in (ROOT / "raqib").rglob("*.py") if p.name not in ("cli.py", "service.py") and
              "import service" in p.read_text(encoding="utf-8")]
    assert others == []
    code = "import sys, raqib.cli, raqib.host, raqib.watch; print('raqib.service' in sys.modules)"
    got = subprocess.run([sys.executable, "-c", code], cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         timeout=120)
    assert got.returncode == 0 and got.stdout.decode("ascii").strip() == "False", got.stderr
    assert (ROOT / "tests" / "test_service.py").read_bytes().isascii()


# --- E7: the spec, the threat model and the guide say what matters ------------------------------------------------

def flat(path):
    return " ".join((ROOT / path).read_text(encoding="utf-8").split())


SPEC_SAYS = (
    "Exit 0 active as installed, 1 installed and not active, or active but not as installed (`RESULT: ACTIVE, NOT"
    " AS INSTALLED`), 3 not installed or not known (a unit file that cannot be read, no systemctl, or no state from"
    " it), 2 not Linux.",
    "`--no-start` writes the unit, reloads and makes the same check after the reload; the unit is neither enabled"
    " nor started",
    "With no unit file it asks systemctl for the unit's LoadState and ActiveState: LoadState `not-found` with"
    " ActiveState `inactive` or `failed` is exit 0 (nothing installed, said); anything else, or no answer, is said"
    " and is exit 1, and nothing is touched and nothing purged.",
    "Each folder on the way and each path itself must be owned by uid 0 and writable by neither its group nor"
    " others.",
    "A symbolic link is checked as itself, by its owner (a link's mode bits say nothing).",
    "A loop of links, or more than 40 links to follow for one path, is a refusal, never a pass.",
    "A walk of more than 200000 entries is refused, and the number said: a walk that is not whole is not a pass.",
    "a `.pth` file is read as text only once it was found root's alone, and nothing is run",
    "If that code is a file a user can write, the unit gives that user the system.",
    "the events file is `/var/lib/raqib/.raqib/host/events.jsonl`",
    "No user's `~/.raqib` is read by it, so an agent that turns a rule off in its user's overlay turns nothing off"
    " in the service.",
    "It leaves the record: `/var/lib/raqib`, whose path it says.",
    "`raqib service remove --purge` also removes `/var/lib/raqib` and nothing else.",
    "A state path that is a link, or that is not `/var/lib/raqib`, is refused before anything is touched.",
    "A unit of this name whose first line is not the mark is not Raqib's: install and remove refuse it and leave it"
    " as it is, and status says it is not installed.",
    "no systemctl is at `/usr/bin/systemctl` or `/bin/systemctl` (it is never found by PATH);",
    # AC-11 (E7): no page and why; who can stop it; the restarts; the two capabilities; what is not checked
    "The unit's watch runs with `--no-page`: it opens no listener and nothing listens on a port for it.",
    "So no person and no agent reads root's view over a port, root parses no user's request, and there is no port"
    " for anyone to take first.",
    "Root can, and root is also any user with sudo (a password it knows, none asked, or a ticket still valid) and"
    " any user a polkit rule lets manage units: an agent running as such a user can stop it.",
    "A watch made to exit comes back after 5 s, a gap each time; systemd counts the restarts (NRestarts) and `raqib"
    " service status` says the count.",
    "As the kernel's rules read, not as measured: CAP_SYS_PTRACE lets a defect in the watch reach other processes,"
    " root's own included, and read and change their memory; CAP_DAC_READ_SEARCH lets it read every file and list"
    " every folder, whatever their modes.",
    "Not checked: the shared libraries the interpreter and its extension modules load (libpython and the libraries"
    " they name);",
    "The check guards the unit's starts, not the install itself: an install run from code a user can write has"
    " already run that code as root before it refuses.",
    "An agent in a network namespace of its own holds sockets the watch, in the host's namespace, may not see: not"
    " measured.",
    "ACTIVE says the unit runs, not that the watch writes: a blind or a stuck watch is still active",
    # AD-1 to AD-7 (REDO 4, E7)
    "With no unit file it first asks systemctl whether systemd holds a unit of the name (LoadState, ActiveState,"
    " FragmentPath): one loaded from any place, or running, is not Raqib's to replace",
    "With no unit file it asks systemctl too, and says a unit of the name that systemd holds (`RESULT: NOT"
    " INSTALLED BY RAQIB, YET A UNIT OF THE NAME IS ACTIVE`, or `IS LOADED`, exit 3).",
    "a unit not as installed is neither enabled nor started (exit 1, `RESULT: the unit is written; NOT AS"
    " INSTALLED, not started: ...`).",
    '"As installed" means all of these, by systemd\'s word and the file\'s:',
    "is byte for byte the text this Raqib writes for the interpreter its ExecStart names.",
    "What still does not show: a change of Raqib's own code by root, or by a user who is root by sudo or polkit,"
    " after the install (the check is made when it installs); which interpreter the install named, since status"
    " takes it from the file; and the drop-in folders, which are root's by default and are not walked",
    "PYTHONHOME or PYTHONPLATLIBDIR is set and the interpreter reads its environment",
    "or a copy deeper below a site folder is not it;",
    "the versions of site split and decode such a file differently, so it is refused, with its path, and not read"
    " into entries.",
    "Two things are outside that: the environment the unit's own `.pth` import lines run in, which is the unit's"
    " and not the install's, and what such a line may add or reach that is not an entry of sys.path",
    "A missing path under a place the system makes for a user (a login's run folder, a mounted medium, a new home)"
    " can become that user's when the system makes it",
    "whoever reads the journal reads the findings' lines the unit prints.",
    "A stop after a finding reads as `failed` to systemd, since the watch's own exit is 1 then; this stays for S1,"
    " and `raqib service remove` clears it (`systemctl reset-failed`).",
    "says what systemd warned of and what the main process holds",
    "the unit's main process's own word from /proc (its bounding set of capabilities, its seccomp mode and its"
    " no-new-privileges bit), MET only where they are the unit's (X29). That is not every directive in force.",
    "a link among them is checked by its owner, and then what it points to.",
    "No line says a thing was done before it was.",
)
THREAT_SAYS = (
    "Who can stop it: the watched agent, running as a person without rights, cannot stop, restart or change a unit"
    " of the system's. Root can, and root is also any user with sudo (a password it knows, none asked, or a ticket"
    " still valid) and any user a polkit rule lets manage units: an agent running as such a user can stop it.",
    "Who can write its record: the service writes under /var/lib/raqib, root's alone (mode 0700).",
    "Who can hide: the service reads every user's processes and sockets, so an agent that makes itself another"
    " user stays in its sight.",
    "An agent in a network namespace of its own (a person can make one where the system lets users make"
    " namespaces) holds sockets the watch, in the host's namespace, may not see: not measured.",
    "Raqib's code runs as root where the service is installed, so a defect in it is the system's.",
    "As the kernel's rules read, not as measured, the two capabilities still open this much to a defect in the"
    " watch: CAP_SYS_PTRACE lets it reach other processes, root's own included, and read and change their memory;"
    " CAP_DAC_READ_SEARCH lets it read every file and list every folder, whatever their modes.",
    "A watch made to exit comes back: the unit restarts it 5 s after any end but systemctl's own stop"
    " (Restart=always), whatever its exit. Each time is a gap in what the watch sees, and systemd counts them"
    " (NRestarts, which `raqib service status` says).",
    "The service serves no page. Its watch runs with --no-page and opens no listener;",
    "So no person and no agent reads root's view of the host over a port, root parses no user's request, and there"
    " is no port for anyone to take first.",
    "it refuses unless the interpreter, its pyvenv.cfg, every file and folder under each entry of sys.path and"
    " under each path its *.pth files name, the raqib package, systemctl, ss and the unit's folder, and every"
    " folder above each of these, are root's and writable by nobody else; it says which path is not, and how many"
    " paths of which kinds it checked.",
    "Not checked: the shared libraries the interpreter and its extension modules load (libpython and the libraries"
    " they name).",
    "The check guards the unit's starts, not the install itself: an install run from code a user can write has"
    " already run that code as root before it refuses.",
    "ACTIVE, as `raqib service status` says it, says the unit runs, not that the watch writes its record",
    "Two watches may run on one host, the service's and a person's own. They do not know each other, and each"
    " writes its own record.",
    # AD-1 to AD-7 (REDO 4, E7)
    "Such a user can also change the unit or Raqib's code. A change of the unit shows in `raqib service status`"
    " (NOT AS INSTALLED: the file's whole text, where systemd loaded it from, its drop-ins, a file changed and not"
    " reloaded); a change of Raqib's own code after the install does not.",
    "A stop after a finding reads as failed to systemd, since the watch's own exit is 1 then; `raqib service"
    " remove` clears that state of the unit it removed.",
    "whoever reads the journal reads the findings' lines the unit prints.",
    "one that reads PYTHONHOME or PYTHONPLATLIBDIR from its environment, a raqib that is not directly in that"
    " interpreter's own site folders, and a *.pth file holding a byte outside printable ASCII, tab and the two"
    " line ends;",
    "one under a place the system makes for a user (a login's run folder, a mounted medium, a new home) can become"
    " that user's.",
    "What a *.pth file's import line reaches that is not an entry of sys.path, and the environment it runs in, are"
    " the unit's and are not walked.",
    "The unit's drop-in folders are root's by default and are not walked; a drop-in that is there shows in status.",
)
NEVER_SAID = ("person without rights cannot read", "cannot read the record", "cannot read the service's record",
              "only root can", "ipaddressallow", "cap_net_admin", "bounds such a defect")


def test_e7_the_spec_holds_the_unit_the_three_commands_the_check_the_record_and_what_removal_leaves():
    text = (ROOT / "docs" / "specs" / "SERVICE.md").read_text(encoding="utf-8")
    block = text.split("```ini\n", 1)[1].split("```", 1)[0]
    assert block == service.UNIT_TEXT % "PYTHON"   # the unit's text, whole, its one hole named
    said = flat("docs/specs/SERVICE.md")
    for row in ("| `raqib service install [--no-start]` | As root only:", "| `raqib service remove [--purge]` | As"
                " root only:", "| `raqib service status` | Needs no rights:"):
        assert row in text, row
    for sentence in SPEC_SAYS:
        assert sentence in said, sentence
    assert service.LINK_DEPTH == 40 and service.WALK_MAX == 200000 and service.START_WAIT == 3


def test_e7_the_threat_model_says_what_the_service_changes_and_costs_without_a_milestone_token():
    said = flat("docs/THREAT_MODEL.md")
    for sentence in THREAT_SAYS:
        assert sentence in said, sentence
    part = said.split("**The service (`raqib service`; ADR-0013).**", 1)[1].split("## 7. Platform", 1)[0]
    assert not __import__("re").search(r"\bM\d+\.\d+", part)
    for words in NEVER_SAID:   # no sentence says a person without rights cannot read what is in fact served
        assert words not in part.lower(), words
        assert words not in flat("docs/specs/SERVICE.md").lower(), words


def test_e7_the_guide_names_the_three_commands_in_its_table_and_the_cli_says_them():
    import test_readme_top as registry
    guide = (ROOT / "docs" / "GUIDE.md").read_text(encoding="utf-8")
    commands = guide.split("## Commands\n", 1)[1].split("\n## ", 1)[0].split("\n")
    rows = [r for r in commands if r.startswith("| `raqib service ")
            and not r.startswith("| `raqib service check` |")]   # M12.4c1: the check's row is test_wincode's
    assert rows == registry.SERVICE_ROWS and len(rows) == 3
    assert [r.split("`")[1] for r in rows] == ["raqib service install [--no-start]", "raqib service remove [--purge]",
                                               "raqib service status"]
    assert "serves no page" in rows[0] and "3 s after the start it asks systemctl" in rows[0]
    assert "with no unit file, where systemd holds a unit of the name (loaded from any place, or running)" in rows[0]
    assert "after the reload, a unit not as installed is not started (exit 1)" in rows[0]
    assert ("with no unit file, exit 0 only where systemd holds no unit of the name (LoadState not-found,"
            " ActiveState inactive or failed), else exit 1, nothing touched and nothing purged") in rows[1]
    assert "`systemctl reset-failed`" in rows[1] and "a unit of the name that systemd holds is said" in rows[2]
    assert ("exit 0 active as installed, 1 installed and not active, or not as installed, 3 not installed or not"
            " known, 2 not Linux") in rows[2]
    assert "service install [--no-start] | remove [--purge] | status" in cli.__doc__
    assert "`raqib watch --host --no-page`" in " ".join(cli.__doc__.split())
