"""Probe only (never merged): a small program that says what it was started with. Packed by the rig's packer's
own options, it is the instrument of packed_env_probe.py: its flags, its search path, which planted module it
took, its environment (a value only for the names a loader or an interpreter reads; a short hash for any other),
the folder Windows searches for libraries first, and the same two things as a program it starts sees them. It
writes nothing. usage: packed_env_entry.py [A_PYTHON_TO_START]"""
import colorsys
import ctypes
import hashlib  # noqa: F401 - packed for SRC
import json
import os
import subprocess
import sys

SRC = r'''
import hashlib, json, os, sys
WATCHED = ("_PYI", "_MEI", "PYI", "LD_", "DYLD_", "PYTHON", "TCL", "TK_", "SSL_", "GCONV", "LOCPATH")
def seen():
    env = {}
    for k, v in os.environ.items():
        told = k.upper().startswith(WATCHED) or k.upper() == "PATH"
        env[k] = v if told else "#" + hashlib.sha256(v.encode("utf-8", "replace")).hexdigest()[:10]
    out = {"env": env}
    if sys.platform == "win32":
        import ctypes
        buf = ctypes.create_unicode_buffer(2048)
        n = ctypes.windll.kernel32.GetDllDirectoryW(2048, buf)
        out["dll_directory"] = buf.value if n else ""
    return out
'''
TAIL = "\nprint(json.dumps(seen()))\n"
FLAGS = ("ignore_environment", "isolated", "safe_path", "no_site", "no_user_site", "verbose", "optimize",
         "inspect", "dont_write_bytecode", "utf8_mode", "hash_randomization", "dev_mode", "debug")


LATE = ("_ssl", "_hashlib", "_sqlite3", "_decimal", "_lzma", "_bz2", "pyexpat", "_socket", "select", "_ctypes",
        "unicodedata", "_overlapped", "_asyncio", "_multiprocessing", "_queue", "_uuid", "zlib")


def _packed_with():
    """Never called: names for the packer, so that LATE's modules are in the folder and are first loaded in
    main(), after the folder Windows searches first was put back."""
    import asyncio, bz2, decimal, lzma, multiprocessing, queue, select, socket, sqlite3, ssl  # noqa: F401,E401
    import unicodedata, uuid, xml.parsers.expat, zlib  # noqa: F401,E401


def cleaned(environ, frozen):
    """environ without what a packer's start added to it: the candidate of the ruling, tried here."""
    if not frozen:
        return dict(environ)
    out = dict((k, v) for k, v in environ.items()
               if not (k.upper().startswith("_PYI_") or k.upper() == "_MEIPASS2"))
    if sys.platform.startswith("linux"):
        if "LD_LIBRARY_PATH_ORIG" in out:
            out["LD_LIBRARY_PATH"] = out.pop("LD_LIBRARY_PATH_ORIG")
        else:
            out.pop("LD_LIBRARY_PATH", None)
    return out


def main():
    space = {}
    exec(SRC, space)
    got = space["seen"]()
    got["frozen"] = bool(getattr(sys, "frozen", False))
    got["home"] = getattr(sys, "_MEIPASS", None)
    got["executable"] = sys.executable
    got["flags"] = dict((n, getattr(sys.flags, n)) for n in FLAGS if hasattr(sys.flags, n))
    got["warnoptions"] = list(sys.warnoptions)
    got["path"] = list(sys.path)
    got["prefix"] = sys.prefix
    got["site"] = [m for m in ("site", "sitecustomize", "usercustomize") if m in sys.modules]
    taken = {"colorsys": "the planted one" if getattr(colorsys, "PLANTED", False) else "its own"}
    try:
        __import__("raqib_probe_planted")
        taken["raqib_probe_planted"] = "imported"
    except Exception as exc:
        taken["raqib_probe_planted"] = "not found (%s)" % type(exc).__name__
    got["taken"] = taken
    got["hash_a"] = hash("a")
    got["loaded_before"] = sorted(n for n in LATE if n in sys.modules)
    if os.environ.get("RAQIB_PROBE_RESET") and sys.platform == "win32":
        got["reset"] = bool(ctypes.windll.kernel32.SetDllDirectoryW(None))
        got["after_reset"] = space["seen"]().get("dll_directory")
    late = {}
    for name in LATE:   # modules of the runtime's own with a library beside them, first loaded only now
        try:
            __import__(name)
            late[name] = "ok"
        except Exception as exc:
            late[name] = "%s: %s" % (type(exc).__name__, str(exc)[:80])
    got["late"] = late
    try:
        import ssl
        got["ssl"] = ssl.OPENSSL_VERSION
        import sqlite3
        got["sqlite"] = sqlite3.connect(":memory:").execute("select sqlite_version()").fetchone()[0]
    except Exception as exc:
        got["ssl"] = "%s: %s" % (type(exc).__name__, str(exc)[:120])
    if len(sys.argv) > 1:
        clean = cleaned(os.environ, got["frozen"])
        for label, argv in (("child_cleaned", [sys.argv[1], "-I", "-c", SRC + TAIL]),
                            ("self_cleaned", [sys.executable] if got["frozen"] else None)):
            if argv is None:
                continue
            try:
                p = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, timeout=60, env=clean)
                text = p.stdout.split("PROBE_JSON ", 1)[-1]
                got[label] = (json.loads(text) if p.returncode == 0
                              else {"exit": p.returncode, "error": p.stderr[-400:]})
            except Exception as exc:
                got[label] = {"exit": None, "error": "%s: %s" % (type(exc).__name__, exc)}
        for label, kw in (("inherited", {}), ("handed", {"env": dict(os.environ)})):
            try:
                p = subprocess.run([sys.argv[1], "-I", "-c", SRC + TAIL], stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60, **kw)
                got["child_" + label] = (json.loads(p.stdout) if p.returncode == 0
                                         else {"exit": p.returncode, "error": p.stderr[-400:]})
            except Exception as exc:
                got["child_" + label] = {"exit": None, "error": "%s: %s" % (type(exc).__name__, exc)}
    print("PROBE_JSON " + json.dumps(got))
    return 0


if __name__ == "__main__":
    sys.exit(main())
