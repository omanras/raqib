"""Probe only (never merged): the fourteenth measurement, before ADR-0013's ruling on `raqib service install |
remove` for Windows - a service made as Raqib's install would make it (automatic start, the mark as its
description, the system told to start it again after 5 s, 30 s and 300 s, on an exit of its own too), what is read
back of that by an administrator and by a caller with no rights, and its removal. It makes one service of the name
given and removes it.

    python svc_probe14.py make NAME COMMAND   made, read back, started, its state waited for
    python svc_probe14.py read NAME           what this caller reads of it (the least rights: 0x1 and 0x5)
    python svc_probe14.py remove NAME         stopped, removed, and asked for again
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
MARK = "raqib-service/1 Raqib's watch of this host (ADR-0013)"


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
    for call in (adv.ChangeServiceConfig2W, adv.QueryServiceConfigW, adv.QueryServiceConfig2W,
                 adv.QueryServiceStatusEx, adv.StartServiceW, adv.ControlService, adv.DeleteService,
                 adv.CloseServiceHandle):
        call.restype = wintypes.BOOL


def said(ok):
    return "done" if ok else "error %d" % err()


def state(h):
    st, need = STATUS_PROCESS(), wintypes.DWORD()
    if adv.QueryServiceStatusEx(h, 0, ctypes.byref(st), ctypes.sizeof(st), ctypes.byref(need)):
        return st.state, "state %d, pid %d, exit %d, its own %d (0x%08x), check-point %d, wait %d" % (
            st.state, st.pid, st.exit, st.own, st.own, st.check, st.hint)
    return None, "state not read: error %d" % err()


def level(h, number, kind):
    """(what was read at this level of QueryServiceConfig2W, or None, the words)."""
    need = wintypes.DWORD()
    first = adv.QueryServiceConfig2W(h, number, None, 0, ctypes.byref(need))
    code = 0 if first else err()
    if code != 122:
        return None, "level %d: the first ask answered %s" % (number, "done" if first else "error %d" % code)
    buf = ctypes.create_string_buffer(need.value)
    if not adv.QueryServiceConfig2W(h, number, buf, need.value, ctypes.byref(need)):
        return None, "level %d: error %d" % (number, err())
    return (ctypes.cast(buf, ctypes.POINTER(kind)).contents, buf), "level %d: read, %d bytes" % (number, need.value)


def read_back(h):
    need = wintypes.DWORD()
    adv.QueryServiceConfigW(h, None, 0, ctypes.byref(need))
    buf = ctypes.create_string_buffer(max(need.value, 1))
    if adv.QueryServiceConfigW(h, buf, need.value, ctypes.byref(need)):
        c = ctypes.cast(buf, ctypes.POINTER(CONFIG)).contents
        print("    its making: type 0x%x, start %d, error control %d, account %s, shown as %r, command %s" % (
            c.type, c.start, c.error, c.account, c.shown, c.command))
    else:
        print("    its making not read: error %d" % err())
    got, words = level(h, 1, DESCRIPTION)
    print("    its description, %s%s" % (words, ": %r" % got[0].text if got else ""))
    got, words = level(h, 2, ACTIONS)
    if got:
        a = got[0]
        acts = ", ".join("%d after %d ms" % (a.actions[i].kind, a.actions[i].delay) for i in range(a.count))
        print("    what the system does after an end that was no Stop, %s: the count forgotten after %d s; %d"
              " action(s): %s (1 is: start it again)" % (words, a.reset, a.count, acts))
    else:
        print("    what the system does after an end that was no Stop, %s" % words)
    for number, label in ((4, "started again on an exit of its own too (the failure flag)"),
                          (3, "its automatic start delayed")):
        got, words = level(h, number, wintypes.BOOL)
        print("    %s, %s%s" % (label, words, ": %s" % bool(got[0].value) if got else ""))


def main(argv):
    if len(argv) < 3 or sys.platform != "win32":
        print(__doc__)
        return 2
    declare()
    what, name = argv[1], argv[2]
    if what == "make":
        m = adv.OpenSCManagerW(None, None, 0x3)
        print("the manager opened to connect and to make a service (0x3): %s" % said(m))
        # the rights the install needs on what it makes: ask the state and the making, change the making, start
        h = adv.CreateServiceW(m, name, "Raqib watch", 0x1 | 0x2 | 0x4 | 0x10, 0x10, 2, 1, argv[3], None, None, None,
                               None, None)
        print("made (a process of its own, automatic start, the system's account by naming none), the handle asked"
              " with the rights 0x17 alone: %s" % said(h))
        if not h:
            return 1
        d = DESCRIPTION(MARK)
        print("the mark set as its description: %s" % said(adv.ChangeServiceConfig2W(h, 1, ctypes.byref(d))))
        acts = (ACTION * 3)(ACTION(1, 5000), ACTION(1, 30000), ACTION(1, 300000))
        f = ACTIONS(3600, None, None, 3, acts)
        print("started again after 5 s, 30 s, 300 s, the count forgotten after 3600 s: %s"
              % said(adv.ChangeServiceConfig2W(h, 2, ctypes.byref(f))))
        on = wintypes.BOOL(True)
        print("the failure flag: %s" % said(adv.ChangeServiceConfig2W(h, 4, ctypes.byref(on))))
        print("read back by its maker:")
        read_back(h)
        began = time.monotonic()
        print("started by the system's own call: %s" % said(adv.StartServiceW(h, 0, None)))
        last = None
        while time.monotonic() - began < 70:
            number, words = state(h)
            if words != last:
                print("    %5.1f s: %s" % (time.monotonic() - began, words))
                last = words
            if number in (1, 4, None):
                break
            time.sleep(0.25)
        adv.CloseServiceHandle(h)
        adv.CloseServiceHandle(m)
        return 0
    if what == "read":
        m = adv.OpenSCManagerW(None, None, 0x1)
        print("the manager opened to connect (0x1): %s" % said(m))
        h = adv.OpenServiceW(m, name, 0x5)
        print("the service opened to ask its state and its making (0x5): %s" % said(h))
        if h:
            print("    %s" % state(h)[1])
            read_back(h)
            adv.CloseServiceHandle(h)
        adv.CloseServiceHandle(m)
        return 0
    if what == "remove":
        m = adv.OpenSCManagerW(None, None, 0x1)
        h = adv.OpenServiceW(m, name, 0x4 | 0x20 | 0x10000)
        print("the service opened to ask its state, to stop it and to remove it (0x10024): %s" % said(h))
        if not h:
            return 1
        print("    before: %s" % state(h)[1])
        st = STATUS()
        print("    a Stop: %s" % said(adv.ControlService(h, 1, ctypes.byref(st))))
        began = time.monotonic()
        while time.monotonic() - began < 40 and state(h)[0] not in (1, None):
            time.sleep(0.25)
        print("    %5.1f s after the Stop: %s" % (time.monotonic() - began, state(h)[1]))
        print("    removed: %s" % said(adv.DeleteService(h)))
        adv.CloseServiceHandle(h)
        again = adv.OpenServiceW(m, name, 0x4)
        print("    asked for again, its handle closed: %s" % ("still there" if again else "error %d" % err()))
        if again:
            adv.CloseServiceHandle(again)
        adv.CloseServiceHandle(m)
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
