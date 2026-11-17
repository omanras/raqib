"""Probe only (never merged): what the Windows event log takes from ReportEventW by a source nobody registered."""
import ctypes
import os
import subprocess
import sys
from ctypes import wintypes

adv = ctypes.WinDLL("advapi32", use_last_error=True)
adv.RegisterEventSourceW.restype = wintypes.HANDLE
adv.RegisterEventSourceW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
adv.ReportEventW.restype = wintypes.BOOL
adv.ReportEventW.argtypes = [wintypes.HANDLE, wintypes.WORD, wintypes.WORD, wintypes.DWORD, ctypes.c_void_p,
                             wintypes.WORD, wintypes.DWORD, ctypes.POINTER(wintypes.LPCWSTR), ctypes.c_void_p]
adv.DeregisterEventSource.argtypes = [wintypes.HANDLE]
SOURCE = "Raqib-probe-%d" % os.getpid()
h = adv.RegisterEventSourceW(None, SOURCE)
print("source", SOURCE, "handle", bool(h), "error", ctypes.get_last_error())


def report(event_id, kind, strings, raw=b""):
    arr = (wintypes.LPCWSTR * len(strings))(*strings) if strings else None
    buf = ctypes.create_string_buffer(raw, len(raw)) if raw else None
    ok = adv.ReportEventW(h, kind, 0, event_id, None, len(strings), len(raw), arr, buf)
    err = ctypes.get_last_error() if not ok else 0
    print("id", event_id, "type", kind, "strings", [len(s) for s in strings], "raw", len(raw), "->",
          "taken" if ok else "refused %d" % err)
    return bool(ok)


report(1001, 4, ['{"id":"r:1","kind":"note","text":"two\\nlines \u0645\u0631\u062d\u0628\u0627"}'])
report(1002, 2, ["x" * 1000])
report(1003, 1, ["first", "second"])


def most(make, low, high, quiet=True):
    """The largest n in [low, high] that make(n) is taken with (bisection)."""
    import io, contextlib
    while low < high:
        mid = (low + high + 1) // 2
        with contextlib.redirect_stdout(io.StringIO()):
            ok = make(mid)
        low, high = (mid, high) if ok else (low, mid - 1)
    return low


print("largest one string:", most(lambda n: report(3000, 4, ["x" * n]), 1000, 70000))
print("largest of two equal strings:", most(lambda n: report(3001, 4, ["x" * n, "y" * n]), 1000, 40000))
print("largest raw with one short string:", most(lambda n: report(3002, 4, ["s"], b"r" * n), 1000, 250000))
print("largest raw with a string of 30000:", most(lambda n: report(3003, 4, ["x" * 30000], b"r" * n), 0, 250000))
print("largest one string of non-ASCII (2-byte units):", most(lambda n: report(3004, 4, ["\u0645" * n]), 1000, 70000))
n = 0
for i in range(3000):
    n += adv.ReportEventW(h, 4, 0, 2000, None, 1, 0, (wintypes.LPCWSTR * 1)("burst %d" % i), None) and 1 or 0
print("burst taken", n, "of 3000")
adv.DeregisterEventSource(h)
ps = ("$e = Get-EventLog -LogName Application -Source '%s' -ErrorAction SilentlyContinue;"
      " 'read back (Get-EventLog): ' + @($e).Count;"
      " $e | Where-Object { $_.EventID -lt 2000 } | Sort-Object EventID | ForEach-Object {"
      " 'id ' + $_.EventID + ' type ' + $_.EntryType + ' strings ' + (($_.ReplacementStrings | ForEach-Object {"
      " $_.Length }) -join ',') + ' data ' + $_.Data.Length + ' msg ' + ([string]$_.Message).Length };"
      " $one = $e | Where-Object { $_.EventID -eq 1001 } | Select-Object -First 1;"
      " 'message 1001: ' + $one.Message; 'string 1001: ' + $one.ReplacementStrings[0];"
      " 'burst kept: ' + @($e | Where-Object { $_.EventID -eq 2000 }).Count;"
      " 'largest kept: ' + (($e | Where-Object { $_.EventID -ge 3000 } | ForEach-Object {"
      " '' + $_.EventID + ':' + (($_.ReplacementStrings | Measure-Object -Property Length -Sum).Sum) + '+' + $_.Data.Length }"
      " | Sort-Object -Unique | Select-Object -Last 12) -join ' ');"
      " wevtutil qe Application /q:\"*[System[Provider[@Name='%s'] and (EventID=1001)]]\" /f:xml /c:1") % (SOURCE, SOURCE)
p = subprocess.run(["powershell", "-NoProfile", "-Command", ps], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
sys.stdout.write(p.stdout.decode("utf-8", "replace"))
sys.stdout.write(p.stderr.decode("utf-8", "replace")[:500])
