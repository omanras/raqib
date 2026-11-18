"""M12.1 (ADR-0013 A-1 to A-9, Amendments A and B): `raqib service install | remove | status`, the host watch as
a unit of the system's, on Linux.

Every call of the system goes through a made-up machine (Fake, in place of service.System): no test here needs
root or Linux, writes under /etc or outside its tmp folder, or runs systemctl. Every path, uid and answer of
systemctl here is made up.
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

from raqib import cli, service  # noqa: E402

VENV = "/usr/local/lib/raqib/venv"
PY = VENV + "/bin/python"
SITE = VENV + "/lib/python3.12/site-packages"
PKG = SITE + "/raqib"
SYSTEMCTL = "/usr/bin/systemctl"
UNIT = service.UNIT_PATH
SHOW_ACTIVE = ("LoadState=loaded\nUnitFileState=enabled\nActiveState=active\nSubState=running\nResult=success\n"
               "ExecMainStatus=0\n")
SHOW_FAILED = ("LoadState=loaded\nUnitFileState=enabled\nActiveState=failed\nSubState=failed\nResult=exit-code\n"
               "ExecMainStatus=1\n")


class St:
    def __init__(self, mode, uid):
        self.st_mode, self.st_uid = mode, uid


class Fake:
    """A made-up machine: {path: [kind, mode, uid, content]}, kind "dir", "file" or "link" (content: a link's
    target, a file's bytes). It answers every call service makes of the system and records the ones that
    change something (systemctl's runs, the unit's writes, the removals)."""

    def __init__(self, uid=0, platform="linux", python=PY, sys_path=None, systemctl=SYSTEMCTL, show=SHOW_ACTIVE):
        self.nodes = {"/": ["dir", 0o755, 0, None]}
        self.uid, self.platform_name, self.python_path, self.systemctl_at, self.show = (
            uid, platform, python, systemctl, show)
        self.paths = sys_path if sys_path is not None else [
            "/usr/lib/python312.zip", "/usr/lib/python3.12", "/usr/lib/python3.12/lib-dynload", SITE]
        self.calls, self.writes, self.removed, self.fail = [], [], [], {}
        for d in ("/usr/lib/python3.12/lib-dynload", PKG + "/rules", service.UNIT_DIR, "/var/lib"):
            self.add(d)
        self.add("/usr/bin/python3.12", "file")
        self.add("/usr/bin/python3", "link", content="python3.12")
        self.add(PY, "link", content="/usr/bin/python3")
        for f in (VENV + "/pyvenv.cfg", SITE + "/distutils-precedence.pth", PKG + "/__init__.py",
                  PKG + "/cli.py", PKG + "/service.py", PKG + "/rules/engine.py"):
            self.add(f, "file", 0o644)

    def add(self, path, kind="dir", mode=0o755, uid=0, content=None):
        parent = posixpath.dirname(path)
        if parent not in self.nodes:
            self.add(parent)
        self.nodes[path] = [kind, mode, uid, content]
        return self

    def unit(self, text):
        return self.add(UNIT, "file", 0o644, 0, text.encode("ascii"))

    # --- service.System's calls ---
    def platform(self):
        return self.platform_name

    def euid(self):
        return self.uid

    def python(self):
        return self.python_path

    def sys_path(self):
        return list(self.paths)

    def getcwd(self):
        return "/"

    def package_dir(self):
        return PKG

    def stat(self, path, follow_symlinks=True):
        for _ in range(50):
            node = self.nodes.get(path)
            if node is None:
                raise FileNotFoundError(path)
            if node[0] == "link" and follow_symlinks:
                path = posixpath.normpath(posixpath.join(posixpath.dirname(path), node[3]))
                continue
            kind = {"dir": statmod.S_IFDIR, "file": statmod.S_IFREG, "link": statmod.S_IFLNK}[node[0]]
            return St(kind | node[1], node[2])
        raise OSError(40, "too many links")

    def readlink(self, path):
        node = self.nodes.get(path)
        if node is None or node[0] != "link":
            raise OSError(22, "not a link")
        return node[3]

    def listdir(self, path):
        pre = path.rstrip("/") + "/"
        return sorted(p[len(pre):] for p in self.nodes if p.startswith(pre) and "/" not in p[len(pre):])

    def walk(self, top):
        out = []

        def go(folder):
            names = self.listdir(folder)
            dirs = [n for n in names if self.nodes[folder + "/" + n][0] == "dir"]
            out.append((folder, dirs, [n for n in names if n not in dirs]))
            for n in dirs:
                go(folder + "/" + n)
        go(top)
        return out

    def read_head(self, path):
        return self.nodes[path][3][:service.HEAD_MAX]

    def systemctl_path(self):
        return self.systemctl_at

    def systemctl(self, path, args):
        self.calls.append(list(args))
        if args[0] in self.fail:
            return self.fail[args[0]]
        return (0, self.show, "") if args[0] == "show" else (0, "", "")

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


def run(fake, *argv):
    """cli.main over the made-up machine: (exit code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    old = sys.stderr
    sys.stderr = err
    try:
        saved = service.System
        service.System = lambda: fake
        try:
            code = cli.main(["service"] + list(argv), out=out)
        finally:
            service.System = saved
    finally:
        sys.stderr = old
    return code, out.getvalue(), err.getvalue()


# --- E1 (A-3, AB-3): owned_by_root over a made-up stat -----------------------------------------------------------

def test_e1_the_clean_case_every_path_is_roots_alone():
    fake = Fake()
    paths = service.install_paths(fake, PY)
    assert check(fake, paths) is None
    # the interpreter as started, pyvenv.cfg beside it or above, sys.path's existing folders and their *.pth,
    # the package's every folder and file (the missing zip is not listed: nothing to load from)
    assert paths[:2] == [PY, VENV + "/pyvenv.cfg"]
    assert {"/usr/lib/python3.12", "/usr/lib/python3.12/lib-dynload", SITE, SITE + "/distutils-precedence.pth",
            PKG, PKG + "/rules", PKG + "/rules/engine.py", PKG + "/service.py"} <= set(paths)
    assert "/usr/lib/python312.zip" not in paths


def test_e1_a_world_writable_parent_three_levels_up_is_said_first_from_the_root_down():
    fake = Fake(python="/opt/venv/bin/python")
    fake.add("/opt", mode=0o777).add("/opt/venv/bin/python", "link", content="/usr/bin/python3")
    assert check(fake, ["/opt/venv/bin/python"]) == (
        "/opt", "writable by others (mode 0777) (on the way to /opt/venv/bin/python)")


def test_e1_a_user_owned_file_inside_the_package():
    fake = Fake().add(PKG + "/rules/engine.py", "file", 0o644, uid=1000)
    where, why = check(fake, service.install_paths(fake, PY))
    assert (where, why) == (PKG + "/rules/engine.py", "owned by uid 1000, not root")


def test_e1_a_group_writable_site_folder():
    fake = Fake()
    fake.nodes[SITE][1] = 0o775
    where, why = check(fake, service.install_paths(fake, PY))
    assert where == SITE and why.startswith("writable by its group (mode 0775)")


def test_e1_a_link_to_a_users_file_is_checked_as_what_it_points_to():
    fake = Fake().add("/srv/x.py", "file", 0o644, uid=1000).add(PKG + "/hooks.py", "link", content="/srv/x.py")
    assert check(fake, service.install_paths(fake, PY)) == (
        "/srv/x.py", "owned by uid 1000, not root (on the way to %s/hooks.py)" % PKG)
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


def test_e1_a_users_pth_file_in_a_folder_of_sys_path():
    fake = Fake().add(SITE + "/zz-user.pth", "file", 0o644, uid=1000)
    assert SITE + "/zz-user.pth" in service.install_paths(fake, PY)
    assert check(fake, service.install_paths(fake, PY)) == (SITE + "/zz-user.pth", "owned by uid 1000, not root")


def test_e1_pyvenv_cfg_beside_the_interpreter_or_one_folder_above_and_a_relative_sys_path_entry():
    fake = Fake().add(VENV + "/bin/pyvenv.cfg", "file", 0o666)
    paths = service.install_paths(fake, PY)
    assert VENV + "/bin/pyvenv.cfg" in paths and VENV + "/pyvenv.cfg" in paths
    assert check(fake, paths) == (VENV + "/bin/pyvenv.cfg", "writable by others (mode 0666)")
    fake = Fake(sys_path=["", "lib"]).add("/lib")
    assert {"/", "/lib"} <= set(service.install_paths(fake, PY))   # the folder it was started in, made whole


def test_e1_a_path_that_cannot_be_read_or_is_not_absolute_is_a_refusal():
    fake = Fake().add(PKG + "/gone.py", "link", content="/srv/none.py")
    assert check(fake, [PKG + "/gone.py"]) == (
        "/srv", "cannot be read (FileNotFoundError) (on the way to %s/gone.py)" % PKG)
    assert check(fake, ["raqib/cli.py"]) == ("raqib/cli.py", "not an absolute path")


# --- E3 (A-3, A-5, A-6): the unit's text, one constant with one hole ---------------------------------------------

WHOLE = """# raqib-service/1
# Raqib's watch of this host as a unit of the system's (ADR-0013). Written by `raqib service install`,
# removed by `raqib service remove`. A unit of this name whose first line is not the mark above is not Raqib's.

[Unit]
Description=Raqib: the watch of this host (raqib watch --host)

[Service]
Type=simple
ExecStart=/usr/local/lib/raqib/venv/bin/python -I -m raqib watch --host --no-open --no-notify
Environment=HOME=/var/lib/raqib
StateDirectory=raqib
StateDirectoryMode=0700
Restart=on-failure
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
RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6
IPAddressDeny=any
IPAddressAllow=localhost
CapabilityBoundingSet=CAP_SYS_PTRACE CAP_DAC_READ_SEARCH CAP_NET_ADMIN
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
    assert service.UNIT_TEXT.isascii()
    assert (service.UNIT_NAME, service.UNIT_DIR, service.STATE_DIR) == (
        "raqib-watch.service", "/etc/systemd/system", "/var/lib/raqib")


@pytest.mark.parametrize("python", ["/usr/local/lib/my venv/bin/python", "/x\nExecStartPre=/bin/sh",
                                    "/opt/%h/python", "bin/python", "", "/usr/../tmp/python", "/usr//bin/python",
                                    "/usr/bin/pyth\u00f6n", None])
def test_e3_the_hole_takes_only_a_plain_whole_path_of_the_safe_characters(python):
    with pytest.raises(service.Refused):
        service.unit_text(python)


# --- E2 (A-4, A-7): install ----------------------------------------------------------------------------------------

def refused(fake, *argv):
    code, out, err = run(fake, *argv)
    assert code == 2 and fake.writes == [] and fake.calls == [] and fake.removed == [], (code, out, err)
    return err


def test_e2_refused_off_linux_and_without_root_no_elevation_asked():
    assert "Linux only (systemd); this is win32" in refused(Fake(platform="win32"), "install")
    err = refused(Fake(uid=1000), "install")
    assert "not root, nothing done" in err and "it asks for no elevation" in err


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


def test_e2_install_writes_the_unit_reloads_enables_and_starts_and_says_so():
    fake = Fake()
    code, out, err = run(fake, "install")
    assert code == 0 and err == ""
    assert fake.writes == [WHOLE] and fake.calls == [["daemon-reload"], ["enable", "--now", "raqib-watch.service"]]
    assert "wrote /etc/systemd/system/raqib-watch.service (root, 0644)" in out
    assert "/usr/bin/systemctl enable --now raqib-watch.service: done" in out
    assert out.rstrip().endswith("RESULT: installed, enabled and started")


def test_e2_no_start_neither_enables_nor_starts():
    fake = Fake()
    code, out, _ = run(fake, "install", "--no-start")
    assert code == 0 and fake.writes == [WHOLE] and fake.calls == [["daemon-reload"]]
    assert "neither enabled nor started" in out


def test_e2_a_second_install_over_raqibs_own_unit_replaces_it():
    fake = Fake().unit(service.MARK + "\n[Service]\nExecStart=/old\n")
    code, out, _ = run(fake, "install")
    assert code == 0 and fake.nodes[UNIT][3] == WHOLE.encode("ascii")
    assert "replaced Raqib's own /etc/systemd/system/raqib-watch.service" in out and "systemctl restart" in out


def test_e2_a_systemctl_that_fails_is_said_and_left_as_it_is():
    fake = Fake()
    fake.fail["enable"] = (1, "", "Failed to enable unit: made-up")
    code, out, _ = run(fake, "install")
    assert code == 1 and fake.removed == [] and UNIT in fake.nodes
    assert "enable --now raqib-watch.service: FAILED (exit 1): Failed to enable unit: made-up" in out
    assert "left as it is" in out


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
    assert service.run_systemctl("/bin/systemctl", ["show"])[0] is None

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


# --- E4 (A-4): remove ------------------------------------------------------------------------------------------------

def installed(**kw):
    fake = Fake(**kw).unit(WHOLE)
    fake.add(service.STATE_DIR, mode=0o700).add(service.RECORD + "/events.jsonl", "file", 0o600)
    return fake


def test_e4_remove_stops_disables_removes_reloads_and_the_record_stays_its_path_said():
    fake = installed()
    code, out, err = run(fake, "remove")
    assert code == 0 and err == ""
    assert fake.calls == [["disable", "--now", "raqib-watch.service"], ["daemon-reload"]] and fake.removed == [UNIT]
    assert UNIT not in fake.nodes and service.RECORD + "/events.jsonl" in fake.nodes
    assert "the record stays: /var/lib/raqib (its events: /var/lib/raqib/.raqib/host/events.jsonl)" in out


def test_e4_remove_is_root_only_and_linux_only():
    assert "not root" in refused(installed(uid=1000), "remove")
    assert "Linux only" in refused(installed(platform="darwin"), "remove")


def test_e4_a_unit_without_the_mark_is_not_touched():
    fake = Fake().unit("[Service]\nExecStart=/usr/bin/other\n")
    assert "does not carry Raqib's mark" in refused(fake, "remove") and UNIT in fake.nodes


def test_e4_no_unit_installed_is_exit_0_saying_so():
    fake = Fake()
    code, out, _ = run(fake, "remove")
    assert code == 0 and fake.calls == [] and "no unit installed" in out and "RESULT: nothing installed" in out


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
    assert code == 1 and fake.removed == [] and "FAILED (exit 1): made-up failure" in out


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


# --- E5 (A-8): status ------------------------------------------------------------------------------------------------

def test_e5_status_active_is_0_by_systemctls_own_words_and_needs_no_rights():
    fake = installed(uid=1000)
    code, out, _ = run(fake, "status")
    assert code == 0 and fake.calls == [["show", "raqib-watch.service", "--no-pager",
                                         "--property=LoadState,UnitFileState,ActiveState,SubState,Result,"
                                         "ExecMainStatus"]]
    assert "installed: /etc/systemd/system/raqib-watch.service (it carries # raqib-service/1)" in out
    assert "enabled: enabled (systemctl's UnitFileState)" in out and "active: active, running" in out
    assert out.rstrip().endswith("RESULT: ACTIVE")


def test_e5_installed_and_not_active_is_1_with_the_last_result():
    code, out, _ = run(installed(uid=1000, show=SHOW_FAILED), "status")
    assert code == 1 and "last result: exit-code, exit status 1" in out and "RESULT: INSTALLED, NOT ACTIVE" in out


def test_e5_not_installed_is_3_and_a_unit_without_the_mark_is_not_raqibs():
    code, out, _ = run(Fake(uid=1000), "status")
    assert code == 3 and "not installed: no /etc/systemd/system/raqib-watch.service" in out
    code, out, _ = run(Fake(uid=1000).unit("[Service]\n"), "status")
    assert code == 3 and "not Raqib's" in out


def test_e5_where_systemctl_cannot_be_run_it_says_so_and_is_3():
    code, out, _ = run(installed(uid=1000, systemctl=None), "status")
    assert code == 3 and "systemctl cannot be run: none at /usr/bin/systemctl or /bin/systemctl" in out
    fake = installed(uid=1000)
    fake.fail["show"] = (None, "", "no answer in 120 s (stopped)")
    code, out, _ = run(fake, "status")
    assert code == 3 and "systemctl cannot be run" in out and "no answer in 120 s" in out


def test_e5_not_linux_is_2():
    assert "Linux only" in refused(Fake(uid=1000, platform="win32"), "status")


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
            assert not (isinstance(root, ast.Name) and root.id in ("os", "shutil", "subprocess", "open")), \
                ast.unparse(n)
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


def test_e7_the_spec_holds_the_unit_the_three_commands_the_check_the_record_and_what_removal_leaves():
    text = (ROOT / "docs" / "specs" / "SERVICE.md").read_text(encoding="utf-8")
    block = text.split("```ini\n", 1)[1].split("```", 1)[0]
    assert block == service.UNIT_TEXT % "PYTHON"   # the unit's text, whole, its one hole named
    said = flat("docs/specs/SERVICE.md")
    for row in ("| `raqib service install [--no-start]` | As root only:", "| `raqib service remove [--purge]` | As"
                " root only:", "| `raqib service status` | Needs no rights:"):
        assert row in text, row
    for sentence in (
            "Exit 0 active, 1 installed and not active, 3 not installed or systemctl cannot be run (said), 2 not"
            " Linux.",
            "`--no-start` writes the unit and reloads; the unit is neither enabled nor started.",
            "Each folder on the way and each path itself must be owned by uid 0 and writable by neither its group"
            " nor others.",
            "A symbolic link is checked as itself, by its owner (a link's mode bits say nothing).",
            "A loop of links, or more than 40 links to follow for one path, is a refusal, never a pass.",
            "every existing entry of sys.path, made whole against the folder the install runs in, and every"
            " `*.pth` file in each of those folders (`-I` does not stop a `.pth` file's lines from running);",
            "If that code is a file a user can write, the unit gives that user the system.",
            "the events file is `/var/lib/raqib/.raqib/host/events.jsonl`",
            "No user's `~/.raqib` is read by it, so an agent that turns a rule off in its user's overlay turns"
            " nothing off in the service.",
            "It leaves the record: `/var/lib/raqib`, whose path it says.",
            "`raqib service remove --purge` also removes `/var/lib/raqib` and nothing else.",
            "A state path that is a link, or that is not `/var/lib/raqib`, is refused before anything is touched.",
            "A unit of this name whose first line is not the mark is not Raqib's: install and remove refuse it and"
            " leave it as it is, and status says it is not installed.",
            "no systemctl is at `/usr/bin/systemctl` or `/bin/systemctl` (it is never found by PATH);"):
        assert sentence in said, sentence
    assert service.LINK_DEPTH == 40


def test_e7_the_threat_model_says_what_the_service_changes_and_costs_without_a_milestone_token():
    said = flat("docs/THREAT_MODEL.md")
    for sentence in (
            "Who can stop it: the watched agent runs as a person and cannot stop, restart or change a unit of the"
            " system's; only root can.",
            "Who can write its record: the service writes under /var/lib/raqib, root's alone (mode 0700).",
            "Who can hide: the service reads every user's processes and sockets, so an agent that makes itself"
            " another user stays in its sight.",
            "Raqib's code runs as root where the service is installed, so a defect in it is the system's.",
            "So the install refuses unless the interpreter, its pyvenv.cfg, every folder of sys.path and the *.pth"
            " files in them, the raqib package, and every folder above each of these are root's and writable by"
            " nobody else; it says which path is not.",
            "Two watches may run on one host, the service's and a person's own. They do not know each other, and"
            " each writes its own record."):
        assert sentence in said, sentence
    part = said.split("**The service (`raqib service`; ADR-0013).**", 1)[1].split("## 7. Platform", 1)[0]
    assert not __import__("re").search(r"\bM\d+\.\d+", part)


def test_e7_the_guide_names_the_three_commands_in_its_table_and_the_cli_says_them():
    import test_readme_top as registry
    guide = (ROOT / "docs" / "GUIDE.md").read_text(encoding="utf-8")
    commands = guide.split("## Commands\n", 1)[1].split("\n## ", 1)[0].split("\n")
    rows = [r for r in commands if r.startswith("| `raqib service ")]
    assert rows == registry.SERVICE_ROWS and len(rows) == 3
    assert [r.split("`")[1] for r in rows] == ["raqib service install [--no-start]", "raqib service remove [--purge]",
                                               "raqib service status"]
    assert ("exit 0 active, 1 installed and not active, 3 not installed or systemctl cannot be run, 2 not"
            " Linux") in rows[2]
    assert "service install [--no-start] | remove [--purge] | status" in cli.__doc__
