"""Probe only (never merged): a small program that says what it was started with. Packed by the rig's packer's
own options, it is the instrument of packed_env_probe.py: its flags, its search path, which planted module it
took, its environment (a value only for the names a loader or an interpreter reads; a short hash for any other),
the folder Windows searches for libraries first, and the same two things as a program it starts sees them. It
writes nothing. usage: packed_env_entry.py [A_PYTHON_TO_START]"""
import colorsys
import ctypes  # noqa: F401 - packed for SRC
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
    if len(sys.argv) > 1:
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
