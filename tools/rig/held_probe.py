"""Probe only (never merged): ADR-0014 AH-3's first case, measured. A file is made in the user's Startup folder and
held open with no sharing while the module reads, then let go; what do the reads and their comparisons say? The file
holds `rem` and is removed at the end. It measures also whether a delete by another handle fails while the module's
own read holds the file (the reviewer's F6). Windows only; it is never imported by raqib."""
import ctypes
import os
import sys
import threading
import time

from raqib import autostart

GENERIC_READ, OPEN_EXISTING, NO_SHARE = 0x80000000, 3, 0


def held(path):
    k = ctypes.windll.kernel32
    k.CreateFileW.restype = ctypes.c_void_p
    return k.CreateFileW(path, GENERIC_READ, NO_SHARE, None, OPEN_EXISTING, 0, None)


def said(label, before, after):
    ch = autostart.changes(before, after)
    mine = [(c["change"], c["place"], c["name"]) for c in ch["changes"] if "raqib-rig-held" in str(c["name"])]
    print("%s: startup is %s; changes of the held file: %s; unread: %s" % (
        label, after["places"]["startup"]["state"], mine or "none", ch["unread"] or "none"))


def main():
    if sys.platform != "win32":
        print("not Windows: nothing measured")
        return 0
    folder = autostart.default_folders()["user"]
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, "raqib-rig-held.cmd")
    first = autostart.read()
    with open(path, "w", encoding="ascii") as f:
        f.write("rem benign-persistence-test\n")
    handle = held(path)
    print("held with no sharing: handle %s" % ("taken" if handle not in (None, -1, 0xFFFFFFFFFFFFFFFF) else "NOT taken"))
    second = autostart.read()
    said("read 2 (the file made and held)", first, second)
    ctypes.windll.kernel32.CloseHandle(ctypes.c_void_p(handle))
    third = autostart.read()
    said("read 3 (let go), against read 2", second, third)
    said("read 3 (let go), against read 1", first, third)
    fourth = autostart.read()
    said("read 4, against read 3", third, fourth)
    # F6: does a delete fail while a read hashes the file? a large file, a read in a thread, a delete beside it
    with open(path, "wb") as f:
        f.write(b"rem \r\n" * 4_000_000)
    worker = threading.Thread(target=autostart.read)
    worker.start()
    tries, failed = 0, 0
    end = time.monotonic() + 5
    while worker.is_alive() and time.monotonic() < end:
        tries += 1
        try:
            os.replace(path, path + ".moved")
            os.replace(path + ".moved", path)
        except OSError:
            failed += 1
    worker.join(10)
    print("a rename beside a read of a 24 MB file: %d tries, %d failed while the read held it" % (tries, failed))
    for p in (path, path + ".moved"):
        try:
            os.remove(p)
        except OSError:
            pass
    left = [e for e in autostart.read()["entries"] if "raqib-rig-held" in str(e["name"])]
    print("left behind: %s" % (left or "nothing"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
