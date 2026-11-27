"""Probe only (never merged): what the system answers a caller of its service calls, measured before ADR-0013's
ruling on `raqib service install | remove | status` for Windows. It makes one service of its own name and removes it.

    python svc_probe10.py numbers NAME COMMAND   the system's numbers for each call made at the wrong moment
    python svc_probe10.py plain NAME             what a caller with no rights may open and read
    python svc_probe10.py flag NAME COMMAND      made with "start again on an exit of its own" (the failure flag)
    python svc_probe10.py noflag NAME COMMAND    the same without the flag
    python svc_probe10.py make NAME COMMAND      made, and nothing more
    python svc_probe10.py remove NAME
"""
import ctypes
import sys
import time
from ctypes import wintypes


class STATUS(ctypes.Structure):
    _fields_ = [(n, wintypes.DWORD) for n in ("type", "state", "accepted", "exit", "own", "check", "hint")]


class STATUS_PROCESS(ctypes.Structure):
    _fields_ = [(n, wintypes.DWORD) for n in ("type", "state", "accepted", "exit", "own", "check", "hint", "pid",
                                              "flags")]


class CONFIG(ctypes.Structure):
    _fields_ = [("type", wintypes.DWORD), ("start", wintypes.DWORD), ("error", wintypes.DWORD),
                ("command", wintypes.LPWSTR), ("group", wintypes.LPWSTR), ("tag", wintypes.DWORD),
                ("needs", wintypes.LPWSTR), ("account", wintypes.LPWSTR), ("shown", wintypes.LPWSTR)]


class DESCRIPTION(ctypes.Structure):
    _fields_ = [("text", wintypes.LPWSTR)]


class ACTION(ctypes.Structure):
    _fields_ = [("kind", ctypes.c_int), ("delay", wintypes.DWORD)]


class ACTIONS(ctypes.Structure):
    _fields_ = [("reset", wintypes.DWORD), ("message", wintypes.LPWSTR), ("command", wintypes.LPWSTR),
                ("count", wintypes.DWORD), ("actions", ctypes.POINTER(ACTION))]


adv = ctypes.WinDLL("advapi32", use_last_error=True) if sys.platform == "win32" else None
err = ctypes.get_last_error if sys.platform == "win32" else None


def declare():
    adv.OpenSCManagerW.restype = adv.OpenServiceW.restype = adv.CreateServiceW.restype = wintypes.HANDLE
    adv.OpenSCManagerW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    adv.OpenServiceW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.DWORD]
    adv.CreateServiceW.argtypes = ([wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPCWSTR] + [wintypes.DWORD] * 4
                                   + [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPVOID] + [wintypes.LPCWSTR] * 3)
    adv.ChangeServiceConfig2W.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID]
    adv.QueryServiceConfigW.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
                                        ctypes.POINTER(wintypes.DWORD)]
    adv.QueryServiceConfig2W.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD,
                                         ctypes.POINTER(wintypes.DWORD)]
    adv.QueryServiceStatusEx.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD,
                                         ctypes.POINTER(wintypes.DWORD)]
    adv.StartServiceW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID]
    adv.ControlService.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(STATUS)]
    adv.DeleteService.argtypes = [wintypes.HANDLE]
    adv.CloseServiceHandle.argtypes = [wintypes.HANDLE]


def said(ok):
    return "done" if ok else "error %d" % err()


def manager(access, label):
    h = adv.OpenSCManagerW(None, None, access)
    print("the manager opened for %s (0x%x): %s" % (label, access, said(h)))
    return h


def opened(m, name, access, label):
    h = adv.OpenServiceW(m, name, access)
    print("the service opened for %s (0x%x): %s" % (label, access, said(h)))
    return h


def state(h):
    st, need = STATUS_PROCESS(), wintypes.DWORD()
    if adv.QueryServiceStatusEx(h, 0, ctypes.byref(st), ctypes.sizeof(st), ctypes.byref(need)):
        return "state %d, pid %d, exit %d, its own exit %d (0x%08x)" % (st.state, st.pid, st.exit, st.own, st.own)
    return "state not read: error %d" % err()


def config(h):
    need = wintypes.DWORD()
    adv.QueryServiceConfigW(h, None, 0, ctypes.byref(need))
    first = err()
    buf = ctypes.create_string_buffer(max(need.value, 1))
    if not adv.QueryServiceConfigW(h, buf, need.value, ctypes.byref(need)):
        return "its making not read: error %d" % err()
    c = ctypes.cast(buf, ctypes.POINTER(CONFIG)).contents
    return ("type 0x%x, start %d, error control %d, account %s, command %s, shown as %r; the first ask with no room"
            " answered error %d and %d bytes" % (c.type, c.start, c.error, c.account, c.command, c.shown, first,
                                                  need.value))


def described(h):
    need = wintypes.DWORD()
    adv.QueryServiceConfig2W(h, 1, None, 0, ctypes.byref(need))
    buf = ctypes.create_string_buffer(max(need.value, 1))
    if not adv.QueryServiceConfig2W(h, 1, buf, need.value, ctypes.byref(need)):
        return "its description not read: error %d" % err()
    return "its description read back: %r" % ctypes.cast(buf, ctypes.POINTER(DESCRIPTION)).contents.text


def make(m, name, command, flag=False):
    h = adv.CreateServiceW(m, name, "Raqib probe 10", 0xF01FF, 0x10, 3, 1, command, None, None, None, None, None)
    print("made (demand start): %s" % said(h))
    if not h:
        return None
    d = DESCRIPTION("raqib-probe/1 a description of its own")
    print("description set: %s" % said(adv.ChangeServiceConfig2W(h, 1, ctypes.byref(d))))
    acts = (ACTION * 3)(ACTION(1, 2000), ACTION(1, 2000), ACTION(1, 2000))
    f = ACTIONS(86400, None, None, 3, acts)
    print("started again after an end that was no Stop, after 2 s: %s"
          % said(adv.ChangeServiceConfig2W(h, 2, ctypes.byref(f))))
    if flag:
        on = wintypes.BOOL(True)
        print("the failure flag (start again on an exit of its own too): %s"
              % said(adv.ChangeServiceConfig2W(h, 4, ctypes.byref(on))))
    return h


def main(argv):
    if len(argv) < 3 or sys.platform != "win32":
        print(__doc__)
        return 2
    declare()
    what, name = argv[1], argv[2]
    if what == "plain":
        for access, label in ((0x1, "connecting"), (0x1 | 0x2, "connecting and making a service"), (0xF003F, "all")):
            m = manager(access, label)
            if m and access == 0x1:
                for a, lab in ((0x4, "asking its state"), (0x1, "asking its making"), (0x4 | 0x1, "both"),
                               (0x10, "starting it"), (0x20, "stopping it"), (0x10000, "removing it"),
                               (0x2, "changing its making"), (0x20000, "reading its own list")):
                    h = opened(m, name, a, lab)
                    if h:
                        if a & 0x4:
                            print("    " + state(h))
                        if a & 0x1:
                            print("    " + config(h))
                            print("    " + described(h))
                        adv.CloseServiceHandle(h)
                h = opened(m, name + "-not-there", 0x4, "asking the state of a name that is not there")
            if m:
                adv.CloseServiceHandle(m)
        return 0
    m = manager(0x1 | 0x2, "connecting and making a service")
    if not m:
        return 1
    if what == "remove":
        h = opened(m, name, 0xF01FF, "all")
        if h:
            st = STATUS()
            print("stop: %s" % said(adv.ControlService(h, 1, ctypes.byref(st))))
            time.sleep(3)
            print("remove: %s; then %s" % (said(adv.DeleteService(h)), state(h)))
            adv.CloseServiceHandle(h)
        return 0
    command = argv[3]
    h = make(m, name, command, flag=(what == "flag"))
    if not h:
        return 1
    print(config(h))
    print(described(h))
    if what == "make":
        adv.CloseServiceHandle(h)
        return 0
    if what in ("flag", "noflag"):
        print("start: %s; %s" % (said(adv.StartServiceW(h, 0, None)), state(h)))
        for i in range(6):
            time.sleep(3)
            print("    after %2d s: %s" % (3 * (i + 1), state(h)))
        adv.CloseServiceHandle(h)
        return 0
    print("made again under the same name: ", end="")
    again = adv.CreateServiceW(m, name, "x", 0xF01FF, 0x10, 3, 1, command, None, None, None, None, None)
    print(said(again))
    st = STATUS()
    print("stop asked of one that does not run: %s" % said(adv.ControlService(h, 1, ctypes.byref(st))))
    print("start: %s" % said(adv.StartServiceW(h, 0, None)))
    time.sleep(8)
    print(state(h))
    print("start asked of one that runs: %s" % said(adv.StartServiceW(h, 0, None)))
    print("remove asked of one that runs: %s; then %s" % (said(adv.DeleteService(h)), state(h)))
    print("remove asked again: %s" % said(adv.DeleteService(h)))
    h2 = opened(m, name, 0x4, "asking its state, after the removal was asked while it runs")
    if h2:
        print("    " + state(h2))
        adv.CloseServiceHandle(h2)
    print("made again under the name while the first is marked: ", end="")
    again = adv.CreateServiceW(m, name, "x", 0xF01FF, 0x10, 3, 1, command, None, None, None, None, None)
    print(said(again))
    print("stop: %s" % said(adv.ControlService(h, 1, ctypes.byref(st))))
    for i in range(10):
        time.sleep(1)
        now = state(h)
        if now.startswith("state 1,"):
            break
    print("after the stop: %s (%d s)" % (now, i + 1))
    adv.CloseServiceHandle(h)
    time.sleep(1)
    h3 = opened(m, name, 0x4, "asking its state, after it stopped and every handle of this caller is closed")
    if h3:
        adv.CloseServiceHandle(h3)
    adv.CloseServiceHandle(m)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
