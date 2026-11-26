"""Probe only (never merged): what macOS gives a plain program, and the same program as root, of what a host watch
needs - every process with its parent, its start and its program's path; and which process holds which
connection - and how long each read takes. By the system's own tools (ps, lsof) and by libproc through ctypes (no
tool started). It reads and changes nothing."""
import ctypes
import ctypes.util
import os
import subprocess
import sys
import time


def run(argv, label):
    t0 = time.monotonic()
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=60)
        out, code = p.stdout, p.returncode
        err = p.stderr.strip().splitlines()[:1]
    except (OSError, subprocess.SubprocessError) as exc:
        out, code, err = "", "failed", [str(exc)]
    print("%s: exit %s in %.3f s, %d line(s)%s" % (label, code, time.monotonic() - t0, len(out.splitlines()),
                                                   "; stderr: %s" % err[0][:120] if err else ""))
    return out


def libproc():
    lib = ctypes.CDLL(ctypes.util.find_library("proc") or "/usr/lib/libproc.dylib", use_errno=True)
    t0 = time.monotonic()
    n = lib.proc_listallpids(None, 0)
    buf = (ctypes.c_int * (n + 64))()
    n = lib.proc_listallpids(buf, ctypes.sizeof(buf))
    pids = [p for p in buf[:max(n, 0)] if p > 0]
    path = ctypes.create_string_buffer(4096)

    class BSD(ctypes.Structure):   # struct proc_bsdinfo (sys/proc_info.h), PROC_PIDTBSDINFO = 3
        _fields_ = [("pbi_flags", ctypes.c_uint32), ("pbi_status", ctypes.c_uint32), ("pbi_xstatus", ctypes.c_uint32),
                    ("pbi_pid", ctypes.c_uint32), ("pbi_ppid", ctypes.c_uint32), ("pbi_uid", ctypes.c_uint32),
                    ("pbi_gid", ctypes.c_uint32), ("pbi_ruid", ctypes.c_uint32), ("pbi_rgid", ctypes.c_uint32),
                    ("pbi_svuid", ctypes.c_uint32), ("pbi_svgid", ctypes.c_uint32), ("rfu_1", ctypes.c_uint32),
                    ("pbi_comm", ctypes.c_char * 16), ("pbi_name", ctypes.c_char * 32),
                    ("pbi_nfiles", ctypes.c_uint32), ("pbi_pgid", ctypes.c_uint32), ("pbi_pjobc", ctypes.c_uint32),
                    ("e_tdev", ctypes.c_uint32), ("e_tpgid", ctypes.c_uint32), ("pbi_nice", ctypes.c_int32),
                    ("pbi_start_tvsec", ctypes.c_uint64), ("pbi_start_tvusec", ctypes.c_uint64)]
    info = BSD()
    with_path = with_info = fds_ok = 0
    mine = os.getuid()
    others_path = others_info = others = 0
    for pid in pids:
        got_info = lib.proc_pidinfo(pid, 3, ctypes.c_uint64(0), ctypes.byref(info), ctypes.sizeof(info)) == ctypes.sizeof(info)
        got_path = lib.proc_pidpath(pid, path, 4096) > 0
        with_info += got_info
        with_path += got_path
        if got_info and info.pbi_uid != mine:
            others += 1
            others_info += 1
            others_path += got_path
        size = lib.proc_pidinfo(pid, 1, ctypes.c_uint64(0), None, 0)   # PROC_PIDLISTFDS = 1: how many bytes
        fds_ok += size > 0
    took = time.monotonic() - t0
    print("libproc: %d pid(s) in %.3f s; parent, user and start read for %d; program's path for %d; its open "
          "files listable for %d" % (len(pids), took, with_info, with_path, fds_ok))
    print("  of processes of another user (%d whose user was read): path read for %d" % (others, others_path))
    return len(pids)


def main():
    print("PLATFORM %s %s; uid %d; python %s" % (sys.platform, os.uname().release, os.getuid(),
                                                 sys.version.split()[0]))
    ps = run(["ps", "-axo", "pid=,ppid=,uid=,lstart=,comm="], "ps (every process: pid, parent, user, start, path)")
    users = {l.split()[2] for l in ps.splitlines() if len(l.split()) > 3}
    print("  users seen by ps: %d; a line: %s" % (len(users), (ps.splitlines() or ["-"])[len(ps.splitlines()) // 2][:120]))
    net = run(["lsof", "-nP", "-iTCP", "-sTCP:ESTABLISHED", "-F", "pcnu"], "lsof (established TCP, by process)")
    pids = {l[1:] for l in net.splitlines() if l.startswith("p")}
    print("  processes holding an established connection, as this user sees them: %d" % len(pids))
    run(["lsof", "-nP", "-iUDP", "-F", "pcn"], "lsof (UDP sockets, by process)")
    run(["netstat", "-anv", "-p", "tcp"], "netstat -anv (connections with their pid column)")
    try:
        libproc()
    except Exception as exc:   # the probe says what failed and goes on
        print("libproc: failed: %s: %s" % (type(exc).__name__, exc))
    return 0


if __name__ == "__main__":
    sys.exit(main())
