"""Probe only (never merged): give a letter to a name of the system's own kind, or take it back.

    python svc_letter.py give LETTER: TARGET      (DefineDosDeviceW, the target given as it is)
    python svc_letter.py take LETTER: TARGET

It is what `subst` does, with the target spelled as the system names a volume and a folder on it; the letter is the
asking session's own and is taken back by the run. It prints what the system answered."""
import ctypes
import sys
from ctypes import wintypes

RAW, REMOVE, EXACT = 0x1, 0x2, 0x4


def main(argv):
    if len(argv) != 4 or argv[1] not in ("give", "take"):
        print(__doc__)
        return 2
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.DefineDosDeviceW.argtypes = [wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR]
    flags = RAW if argv[1] == "give" else RAW | REMOVE | EXACT
    ok = k32.DefineDosDeviceW(flags, argv[2], argv[3])
    print("%s %s -> %s: %s" % (argv[1], argv[2], argv[3], "done" if ok else "error %d" % ctypes.get_last_error()))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
