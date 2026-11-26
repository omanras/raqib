"""Probe only (never merged): the branch's own raqib.own and Raqib's own entry, packed, saying what they did
(ADR-0007 CI-5): the folder Windows searches first for a library before and after the entry ran, what
own.handed() gives, and what a program started with it sees. It writes nothing.
usage: packed_env_entry2.py A_PYTHON_TO_START"""
import io
import json
import subprocess
import sys

from raqib import cli, own

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
LATE = ("_ssl", "_hashlib", "_sqlite3", "_decimal", "_lzma", "_bz2", "pyexpat", "_socket", "_overlapped",
        "_asyncio", "_queue", "unicodedata")


def main():
    space = {}
    exec(SRC, space)
    got = {"frozen": bool(getattr(sys, "frozen", False)), "before": space["seen"]()}
    out = io.StringIO()
    got["entry_exit"] = cli.main(["--version"], out)   # Raqib's own entry: CI-3's call is its first step
    got["entry_said"] = out.getvalue().strip()[:60]
    got["library_folder"] = repr(own.LIBRARY_FOLDER)
    got["hole"] = own.library_folder_hole()
    got["after"] = space["seen"]()
    late = {}
    for name in LATE:
        try:
            __import__(name)
            late[name] = "ok"
        except Exception as exc:
            late[name] = "%s: %s" % (type(exc).__name__, str(exc)[:80])
    got["late"] = late
    handed = own.handed()
    import hashlib
    got["handed"] = dict((k, v if k.upper().startswith(("_PYI", "_MEI", "PYI", "LD_", "DYLD_", "PYTHON", "TCL", "TK_", "SSL_", "GCONV", "LOCPATH"))
                          or k.upper() == "PATH" else "#" + hashlib.sha256(v.encode("utf-8", "replace")).hexdigest()[:10])
                         for k, v in handed.items())
    try:
        p = subprocess.run([sys.argv[1], "-I", "-c", SRC + TAIL], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, text=True, timeout=60, env=handed)
        got["child"] = json.loads(p.stdout) if p.returncode == 0 else {"exit": p.returncode, "error": p.stderr[-400:]}
    except Exception as exc:
        got["child"] = {"exit": None, "error": "%s: %s" % (type(exc).__name__, exc)}
    print("PROBE_JSON " + json.dumps(got))
    return 0


if __name__ == "__main__":
    sys.exit(main())
