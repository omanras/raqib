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


report(1001, 4, ['{"id":"r:1","kind":"note","text":"two\\nlines مرحبا"}'])
report(1002, 2, ["x" * 1000])
report(1003, 1, ["x" * 31839])
report(1004, 4, ["x" * 31840])
report(1005, 4, ["x" * 31839, "y" * 31839])
report(1006, 4, ["x" * 20000, "y" * 20000, "z" * 20000])
report(1007, 4, ["a" * 10000] * 10)
report(1008, 4, ["short"], b"r" * 60000)
report(1009, 4, ["short"], b"r" * 200000)
report(1010, 4, ["short"], b"r" * 61000)
report(1011, 4, ["x" * 31000, "y" * 31000, "z" * 31000, "w" * 31000])
n = 0
for i in range(3000):
    n += adv.ReportEventW(h, 4, 0, 2000, None, 1, 0, (wintypes.LPCWSTR * 1)("burst %d" % i), None) and 1 or 0
print("burst taken", n, "of 3000")
adv.DeregisterEventSource(h)
ps = ("$e = Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='%s'} -ErrorAction SilentlyContinue;"
      " 'read back: ' + $e.Count; $e | Where-Object { $_.Id -ne 2000 } | Sort-Object Id | ForEach-Object {"
      " 'id ' + $_.Id + ' level ' + $_.LevelDisplayName + ' props ' + (($_.Properties | ForEach-Object {"
      " ([string]$_.Value).Length }) -join ',') + ' msg ' + ([string]$_.Message).Length };"
      " $one = $e | Where-Object { $_.Id -eq 1001 } | Select-Object -First 1; 'message 1001: ' + $one.Message;"
      " 'property 1001: ' + $one.Properties[0].Value;"
      " 'burst kept: ' + ($e | Where-Object { $_.Id -eq 2000 }).Count") % SOURCE
p = subprocess.run(["powershell", "-NoProfile", "-Command", ps], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
sys.stdout.write(p.stdout.decode("utf-8", "replace"))
sys.stdout.write(p.stderr.decode("utf-8", "replace")[:500])
