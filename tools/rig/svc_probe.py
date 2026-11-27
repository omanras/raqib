"""Probe only (never merged): can Raqib's host watch be a real service of Windows with nothing but the standard
library (M12.4)? This program is the candidate's shape, small: the service control dispatcher runs in a second
thread (ctypes; no third-party module), the watch runs in the main thread as it does from a console, and a Stop
from the system is turned into the same interrupt a person's Ctrl+C is. It writes what it saw into a folder of
its own under ProgramData, made by itself: who it runs as, its session, its standard streams, how long each step
took, how the watch ended. Run by `sc create NAME binPath= "... svc_probe.py --service NAME LABEL"`; run with no
service manager it says so and ends. It changes nothing outside its folder.

usage: svc_probe.py --service NAME LABEL [ROUNDS]"""
import ctypes
import io
import os
import signal
import sys
import threading
import time
from ctypes import wintypes

T0 = time.monotonic()
SERVICE_WIN32_OWN_PROCESS = 0x10
STOPPED, START_PENDING, STOP_PENDING, RUNNING = 1, 2, 3, 4
ACCEPT_STOP, ACCEPT_SHUTDOWN = 0x1, 0x4
CONTROL_STOP, CONTROL_INTERROGATE, CONTROL_SHUTDOWN = 1, 4, 5
NOT_BY_THE_MANAGER = 1063   # ERROR_FAILED_SERVICE_CONTROLLER_CONNECT: not started by the service manager


class SERVICE_STATUS(ctypes.Structure):
    _fields_ = [("dwServiceType", wintypes.DWORD), ("dwCurrentState", wintypes.DWORD),
                ("dwControlsAccepted", wintypes.DWORD), ("dwWin32ExitCode", wintypes.DWORD),
                ("dwServiceSpecificExitCode", wintypes.DWORD), ("dwCheckPoint", wintypes.DWORD),
                ("dwWaitHint", wintypes.DWORD)]


HANDLER_EX = ctypes.WINFUNCTYPE(wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, wintypes.LPVOID)
SERVICE_MAIN = ctypes.WINFUNCTYPE(None, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR))


class SERVICE_TABLE_ENTRY(ctypes.Structure):
    _fields_ = [("lpServiceName", wintypes.LPWSTR), ("lpServiceProc", SERVICE_MAIN)]


class Service:
    def __init__(self, name, log):
        self.name, self.log = name, log
        self.advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        self.advapi.RegisterServiceCtrlHandlerExW.restype = wintypes.LPVOID
        self.advapi.RegisterServiceCtrlHandlerExW.argtypes = [wintypes.LPCWSTR, HANDLER_EX, wintypes.LPVOID]
        self.advapi.SetServiceStatus.argtypes = [wintypes.LPVOID, ctypes.POINTER(SERVICE_STATUS)]
        self.advapi.StartServiceCtrlDispatcherW.argtypes = [ctypes.POINTER(SERVICE_TABLE_ENTRY)]
        self.handle = None
        self.running, self.stop_asked, self.work_done, self.ended = (threading.Event() for _ in range(4))
        self.failed = None      # the dispatcher's error where it could not connect
        self.refuse, self.pending = 0, False   # the fifth probe: a refusal's number, said from START_PENDING or not
        self.exit_code = 0
        self._handler = HANDLER_EX(self.handler)        # kept: the system calls them later
        self._main = SERVICE_MAIN(self.service_main)

    def status(self, state, hint=0):
        own = self.refuse if state == STOPPED and self.refuse else 0
        s = SERVICE_STATUS(SERVICE_WIN32_OWN_PROCESS, state,
                           (ACCEPT_STOP | ACCEPT_SHUTDOWN) if state == RUNNING else 0,
                           1066 if own else (self.exit_code if state == STOPPED else 0), own, 0, hint)
        ok = self.advapi.SetServiceStatus(self.handle, ctypes.byref(s))
        self.log("status %d set: %s" % (state, "ok" if ok else "FAILED %d" % ctypes.get_last_error()))

    def handler(self, control, kind, data, context):
        if control in (CONTROL_STOP, CONTROL_SHUTDOWN):
            self.log("control %d from the system (thread %s)" % (control, threading.current_thread().name))
            self.status(STOP_PENDING, 30000)
            self.stop_asked.set()
            self.stopped_at = time.monotonic()
            try:
                signal.raise_signal(signal.SIGINT)   # what a person's Ctrl+C is to the main thread
                self.log("the interrupt was raised")
            except Exception as exc:
                self.log("the interrupt could not be raised: %s: %s" % (type(exc).__name__, exc))
        return 0

    def service_main(self, argc, argv):
        self.handle = self.advapi.RegisterServiceCtrlHandlerExW(self.name, self._handler, None)
        self.log("the handler registered: %s (thread %s)" % (bool(self.handle), threading.current_thread().name))
        if self.refuse:
            self.status(START_PENDING if self.pending else RUNNING, 5000 if self.pending else 0)
            time.sleep(0.5)
            self.status(STOPPED)
            self.running.set()
            return
        self.status(RUNNING)
        self.running.set()
        self.work_done.wait()
        self.status(STOPPED)

    def dispatch(self):
        table = (SERVICE_TABLE_ENTRY * 2)()
        table[0].lpServiceName, table[0].lpServiceProc = self.name, self._main
        if not self.advapi.StartServiceCtrlDispatcherW(table):
            self.failed = ctypes.get_last_error()
        self.ended.set()


CLOSED = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"   # the system and the administrators, whole; nobody else; no inheriting
DACL_INFO, PROTECTED_DACL = 0x4, 0x80000000
SE_FILE_OBJECT = 1


def sddl_of(path, what=None):
    """The folder's access list as the system writes it (SDDL), or why it could not be read."""
    DACL_INFO = what or globals()["DACL_INFO"]
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.LocalFree.argtypes = [wintypes.LPVOID]
    sd, text, size = wintypes.LPVOID(), wintypes.LPWSTR(), wintypes.ULONG()
    adv.GetNamedSecurityInfoW.argtypes = [wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD] + [wintypes.LPVOID] * 5
    rc = adv.GetNamedSecurityInfoW(path, SE_FILE_OBJECT, DACL_INFO, None, None, None, None, ctypes.byref(sd))
    if rc:
        return "not read: error %d" % rc
    adv.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
        wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR),
        ctypes.POINTER(wintypes.ULONG)]
    ok = adv.ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, 1, DACL_INFO, ctypes.byref(text),
                                                                ctypes.byref(size))
    out = text.value if ok else "not written as text: error %d" % ctypes.get_last_error()
    k32.LocalFree(sd)
    if ok:
        k32.LocalFree(ctypes.cast(text, wintypes.LPVOID))
    return out


def close(path):
    """Give the folder CLOSED as its access list, by the system's own calls; say it before and after, and for a
    file and a folder that were in it before."""
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    inside = [os.path.join(path, n) for n in sorted(os.listdir(path))][:3]
    print("before: %s" % sddl_of(path))
    for p in inside:
        print("  before, inside (%s): %s" % (os.path.basename(p), sddl_of(p)))
    sd, size = wintypes.LPVOID(), wintypes.ULONG()
    adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.ULONG)]
    if not adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(CLOSED, 1, ctypes.byref(sd), ctypes.byref(size)):
        print("the text was not taken: error %d" % ctypes.get_last_error())
        return 1
    present, dacl, defaulted = wintypes.BOOL(), wintypes.LPVOID(), wintypes.BOOL()
    adv.GetSecurityDescriptorDacl.argtypes = [wintypes.LPVOID, ctypes.POINTER(wintypes.BOOL),
                                              ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.BOOL)]
    adv.GetSecurityDescriptorDacl(sd, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted))
    adv.SetNamedSecurityInfoW.argtypes = [wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD] + [wintypes.LPVOID] * 4
    rc = adv.SetNamedSecurityInfoW(path, SE_FILE_OBJECT, DACL_INFO | PROTECTED_DACL, None, None, dacl, None)
    print("set: %s" % ("ok" if rc == 0 else "error %d" % rc))
    after = sddl_of(path)
    print("after:  %s" % after)
    print("as asked: %s (asked %s)" % (after == CLOSED, CLOSED))
    for p in inside:
        print("  after, inside (%s): %s" % (os.path.basename(p), sddl_of(p)))
    return 0 if rc == 0 else 1


def owner(path, give=False):
    """The folder's owner and access list as text; with give, first make the administrators its owner."""
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    print("owner and list: %s" % sddl_of(path, 0x1 | 0x4))
    if give:
        sd, size = wintypes.LPVOID(), wintypes.ULONG()
        adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.ULONG)]
        adv.ConvertStringSecurityDescriptorToSecurityDescriptorW("O:BA", 1, ctypes.byref(sd), ctypes.byref(size))
        sid, defaulted = wintypes.LPVOID(), wintypes.BOOL()
        adv.GetSecurityDescriptorOwner.argtypes = [wintypes.LPVOID, ctypes.POINTER(wintypes.LPVOID),
                                                   ctypes.POINTER(wintypes.BOOL)]
        adv.GetSecurityDescriptorOwner(sd, ctypes.byref(sid), ctypes.byref(defaulted))
        adv.SetNamedSecurityInfoW.argtypes = [wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD] + [wintypes.LPVOID] * 4
        rc = adv.SetNamedSecurityInfoW(path, SE_FILE_OBJECT, 0x1, sid, None, None, None)
        print("the administrators made its owner: %s" % ("ok" if rc == 0 else "error %d" % rc))
        print("owner and list: %s" % sddl_of(path, 0x1 | 0x4))
    return 0


class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("nLength", wintypes.DWORD), ("lpSecurityDescriptor", wintypes.LPVOID),
                ("bInheritHandle", wintypes.BOOL)]


def make_closed(path):
    """Make the folder with CLOSED as its list in the one call that makes it. Says what the system answered."""
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    sd, size = wintypes.LPVOID(), wintypes.ULONG()
    adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.ULONG)]
    if not adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(CLOSED, 1, ctypes.byref(sd), ctypes.byref(size)):
        return "the text was not taken: error %d" % ctypes.get_last_error()
    sa = SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), sd, False)
    k32.CreateDirectoryW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(SECURITY_ATTRIBUTES)]
    ok = k32.CreateDirectoryW(path, ctypes.byref(sa))
    return "made" if ok else "not made: error %d" % ctypes.get_last_error()


def make_closed_no_follow(path):
    """The other way to make a folder: the opening call itself, told to make a new folder and not to follow a
    link at the name. Says what the system answered."""
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    sd, size = wintypes.LPVOID(), wintypes.ULONG()
    adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.ULONG)]
    if not adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(CLOSED, 1, ctypes.byref(sd), ctypes.byref(size)):
        return "the text was not taken: error %d" % ctypes.get_last_error()
    sa = SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), sd, False)
    k32.CreateFileW.restype = wintypes.HANDLE
    k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                ctypes.POINTER(SECURITY_ATTRIBUTES), wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    # CREATE_NEW; FILE_ATTRIBUTE_DIRECTORY | BACKUP_SEMANTICS | POSIX_SEMANTICS | OPEN_REPARSE_POINT
    h = k32.CreateFileW(path, 0x20000 | 0x80, 0x1 | 0x2, ctypes.byref(sa), 1,
                        0x10 | 0x02000000 | 0x01000000 | 0x00200000, None)
    if h is None or h == wintypes.HANDLE(-1).value:
        return "not made: error %d" % ctypes.get_last_error()
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.CloseHandle(h)
    return "made"


def open_folder(path):
    """A handle on the name itself (a link is not followed), that lets nobody take the name away while it is
    held: (handle, None) or (None, why)."""
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateFileW.restype = wintypes.HANDLE
    k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD,
                                wintypes.DWORD, wintypes.HANDLE]
    # READ_CONTROL | FILE_READ_ATTRIBUTES; shared for reading and writing, not for deleting; an existing one;
    # FILE_FLAG_BACKUP_SEMANTICS (a folder) | FILE_FLAG_OPEN_REPARSE_POINT (the link itself)
    h = k32.CreateFileW(path, 0x20000 | 0x80, 0x1 | 0x2, None, 3, 0x02000000 | 0x00200000, None)
    if h is None or h == wintypes.HANDLE(-1).value:
        return None, "not opened: error %d" % ctypes.get_last_error()
    return h, None


def read_handle(path):
    """What the name is, and its owner and list, read through one handle on the name itself."""
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    h, why = open_folder(path)
    if h is None:
        return why
    info = (wintypes.DWORD * 13)()
    k32.GetFileInformationByHandle.argtypes = [wintypes.HANDLE, wintypes.LPVOID]
    got = k32.GetFileInformationByHandle(h, ctypes.byref(info))
    attrs = info[0] if got else None
    kind = "attributes not read" if attrs is None else "%s%s (attributes 0x%x)" % (
        "a folder" if attrs & 0x10 else "a file", ", a reparse point" if attrs & 0x400 else "", attrs)
    sd, text, size = wintypes.LPVOID(), wintypes.LPWSTR(), wintypes.ULONG()
    adv.GetSecurityInfo.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.DWORD] + [wintypes.LPVOID] * 5
    rc = adv.GetSecurityInfo(h, SE_FILE_OBJECT, 0x1 | 0x4, None, None, None, None, ctypes.byref(sd))
    if rc:
        out = "owner and list not read: error %d" % rc
    else:
        adv.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
            wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR),
            ctypes.POINTER(wintypes.ULONG)]
        ok = adv.ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, 1, 0x1 | 0x4, ctypes.byref(text),
                                                                    ctypes.byref(size))
        out = text.value if ok else "not written as text: error %d" % ctypes.get_last_error()
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.CloseHandle(h)
    return "%s; %s" % (kind, out)


OWNED = "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"   # the closed list, and the administrators named as the owner


def make_owned(path):
    """Make the folder closed AND with its owner named in the one call that makes it."""
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    sd, size = wintypes.LPVOID(), wintypes.ULONG()
    adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.ULONG)]
    if not adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(OWNED, 1, ctypes.byref(sd), ctypes.byref(size)):
        return "the text was not taken: error %d" % ctypes.get_last_error()
    sa = SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), sd, False)
    k32.CreateDirectoryW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(SECURITY_ATTRIBUTES)]
    ok = k32.CreateDirectoryW(path, ctypes.byref(sa))
    return "made" if ok else "not made: error %d" % ctypes.get_last_error()


# --- the service made, read, started, stopped and removed by the system's own calls (no outside program) ----------
class SERVICE_DESCRIPTION(ctypes.Structure):
    _fields_ = [("lpDescription", wintypes.LPWSTR)]


class SC_ACTION(ctypes.Structure):
    _fields_ = [("Type", ctypes.c_int), ("Delay", wintypes.DWORD)]


class SERVICE_FAILURE_ACTIONS(ctypes.Structure):
    _fields_ = [("dwResetPeriod", wintypes.DWORD), ("lpRebootMsg", wintypes.LPWSTR), ("lpCommand", wintypes.LPWSTR),
                ("cActions", wintypes.DWORD), ("lpsaActions", ctypes.POINTER(SC_ACTION))]


class QUERY_SERVICE_CONFIG(ctypes.Structure):
    _fields_ = [("dwServiceType", wintypes.DWORD), ("dwStartType", wintypes.DWORD),
                ("dwErrorControl", wintypes.DWORD), ("lpBinaryPathName", wintypes.LPWSTR),
                ("lpLoadOrderGroup", wintypes.LPWSTR), ("dwTagId", wintypes.DWORD),
                ("lpDependencies", wintypes.LPWSTR), ("lpServiceStartName", wintypes.LPWSTR),
                ("lpDisplayName", wintypes.LPWSTR)]


class SERVICE_STATUS_PROCESS(ctypes.Structure):
    _fields_ = [("dwServiceType", wintypes.DWORD), ("dwCurrentState", wintypes.DWORD),
                ("dwControlsAccepted", wintypes.DWORD), ("dwWin32ExitCode", wintypes.DWORD),
                ("dwServiceSpecificExitCode", wintypes.DWORD), ("dwCheckPoint", wintypes.DWORD),
                ("dwWaitHint", wintypes.DWORD), ("dwProcessId", wintypes.DWORD), ("dwServiceFlags", wintypes.DWORD)]


def _scm():
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    adv.OpenSCManagerW.restype = wintypes.HANDLE
    adv.OpenSCManagerW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    adv.OpenServiceW.restype = wintypes.HANDLE
    adv.OpenServiceW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.DWORD]
    adv.CreateServiceW.restype = wintypes.HANDLE
    adv.CreateServiceW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
                                   wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.LPCWSTR,
                                   wintypes.LPCWSTR, wintypes.LPVOID, wintypes.LPCWSTR, wintypes.LPCWSTR,
                                   wintypes.LPCWSTR]
    adv.ChangeServiceConfig2W.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID]
    adv.QueryServiceConfigW.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
                                        ctypes.POINTER(wintypes.DWORD)]
    adv.QueryServiceStatusEx.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD,
                                         ctypes.POINTER(wintypes.DWORD)]
    adv.StartServiceW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID]
    adv.ControlService.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(SERVICE_STATUS)]
    adv.DeleteService.argtypes = [wintypes.HANDLE]
    adv.CloseServiceHandle.argtypes = [wintypes.HANDLE]
    return adv


def svc(what, name, binpath=None):
    """install | query | start | stop | remove, by the system's own calls; says what each answered."""
    adv = _scm()
    err = ctypes.get_last_error
    manager = adv.OpenSCManagerW(None, None, 0x1 | 0x2)   # CONNECT | CREATE_SERVICE
    if not manager:
        print("the service manager was not opened: error %d" % err())
        return 1
    try:
        if what == "install":
            h = adv.CreateServiceW(manager, name, "Raqib: the watch of this host (probe)", 0xF01FF, 0x10, 2, 1,
                                   binpath, None, None, None, None, None)   # own process, auto start, the system
            if not h:
                print("not made: error %d" % err())
                return 1
            print("made")
            d = SERVICE_DESCRIPTION("Raqib's watch of this host, as a service of the system's (a probe).")
            print("description: %s" % ("set" if adv.ChangeServiceConfig2W(h, 1, ctypes.byref(d)) else "error %d" % err()))
            actions = (SC_ACTION * 3)(SC_ACTION(1, 5000), SC_ACTION(1, 5000), SC_ACTION(1, 5000))
            f = SERVICE_FAILURE_ACTIONS(86400, None, None, 3, actions)
            print("started again after an end that was no Stop: %s"
                  % ("set" if adv.ChangeServiceConfig2W(h, 2, ctypes.byref(f)) else "error %d" % err()))
            delayed = wintypes.BOOL(True)
            print("its start at boot delayed: %s"
                  % ("set" if adv.ChangeServiceConfig2W(h, 3, ctypes.byref(delayed)) else "error %d" % err()))
            adv.CloseServiceHandle(h)
            return 0
        h = adv.OpenServiceW(manager, name, 0xF01FF)
        if not h:
            print("the service was not opened: error %d" % err())
            return 1
        try:
            if what == "query":
                need = wintypes.DWORD()
                adv.QueryServiceConfigW(h, None, 0, ctypes.byref(need))
                buf = ctypes.create_string_buffer(need.value)
                if adv.QueryServiceConfigW(h, buf, need.value, ctypes.byref(need)):
                    c = ctypes.cast(buf, ctypes.POINTER(QUERY_SERVICE_CONFIG)).contents
                    print("as the system holds it: type 0x%x, start %d, runs as %s, its command: %s"
                          % (c.dwServiceType, c.dwStartType, c.lpServiceStartName, c.lpBinaryPathName))
                else:
                    print("its making was not read: error %d" % err())
                st, need = SERVICE_STATUS_PROCESS(), wintypes.DWORD()
                if adv.QueryServiceStatusEx(h, 0, ctypes.byref(st), ctypes.sizeof(st), ctypes.byref(need)):
                    print("its state: %d, pid %d, exit %d, its own exit %d"
                          % (st.dwCurrentState, st.dwProcessId, st.dwWin32ExitCode, st.dwServiceSpecificExitCode))
                else:
                    print("its state was not read: error %d" % err())
            elif what == "start":
                print("start: %s" % ("asked" if adv.StartServiceW(h, 0, None) else "error %d" % err()))
            elif what == "stop":
                st = SERVICE_STATUS()
                print("stop: %s" % ("asked, state %d" % st.dwCurrentState if adv.ControlService(h, 1, ctypes.byref(st))
                                    else "error %d" % err()))
            elif what == "remove":
                print("remove: %s" % ("done" if adv.DeleteService(h) else "error %d" % err()))
        finally:
            adv.CloseServiceHandle(h)
        return 0
    finally:
        adv.CloseServiceHandle(manager)


def survey(paths):
    """Each path's kind, owner and list, read through one handle on its name."""
    for path in paths:
        print("%s\n    %s" % (path, read_handle(path)))
    return 0


def main(argv):
    if len(argv) == 3 and argv[1] == "--make-owned":
        print("made closed with its owner named: %s" % make_owned(argv[2]))
        print("by its handle: %s" % read_handle(argv[2]))
        return 0
    if len(argv) >= 4 and argv[1] == "--svc":
        return svc(argv[2], argv[3], argv[4] if len(argv) > 4 else None)
    if len(argv) >= 3 and argv[1] == "--survey":
        return survey(argv[2:])
    if len(argv) == 3 and argv[1] == "--make":
        print("made closed in one call: %s" % make_closed(argv[2]))
        print("by its handle: %s" % read_handle(argv[2]))
        return 0
    if len(argv) == 3 and argv[1] == "--make2":
        print("made by the opening call, a link not followed: %s" % make_closed_no_follow(argv[2]))
        print("by its handle: %s" % read_handle(argv[2]))
        return 0
    if len(argv) == 3 and argv[1] == "--read":
        print("by its handle: %s" % read_handle(argv[2]))
        return 0
    if len(argv) == 4 and argv[1] == "--hold":
        h, why = open_folder(argv[2])
        print("held: %s" % (why or "yes"), flush=True)
        time.sleep(float(argv[3]))
        return 0
    if len(argv) == 3 and argv[1] == "--close":
        return close(argv[2])
    if len(argv) == 3 and argv[1] in ("--owner", "--give"):
        return owner(argv[2], argv[1] == "--give")
    if len(argv) < 4 or argv[1] != "--service":
        print(__doc__)
        return 2
    name, label = argv[2], argv[3]
    rounds = argv[4] if len(argv) > 4 and label != "refuse" else "400"
    root = os.path.join(os.environ.get("ProgramData", "C:\\ProgramData"), "RaqibProbe")
    place = os.path.join(root, label)
    made = not os.path.isdir(root)
    os.makedirs(place, exist_ok=True)
    logf = open(os.path.join(place, "svc.log"), "a", encoding="utf-8")
    lock = threading.Lock()

    def log(text):
        with lock:
            logf.write("%7.2f %s\n" % (time.monotonic() - T0, text))
            logf.flush()
    log("START pid %d; frozen %s; exe %s; made the folder %s" % (os.getpid(), bool(getattr(sys, "frozen", False)),
                                                               os.path.basename(sys.executable), made))
    log("stdin %r stdout %r stderr %r" % (sys.stdin, sys.stdout, sys.stderr))
    session = wintypes.DWORD(0)
    ctypes.WinDLL("kernel32").ProcessIdToSessionId(os.getpid(), ctypes.byref(session))
    log("user %s\\%s; session %d; cwd %s" % (os.environ.get("USERDOMAIN"), os.environ.get("USERNAME"),
                                           session.value, os.getcwd()))
    log("USERPROFILE %s; TEMP %s; names in the environment %d" % (os.environ.get("USERPROFILE"),
                                                               os.environ.get("TEMP"), len(os.environ)))
    svc = Service(name, log)
    if label == "refuse":
        svc.refuse, svc.pending = int(argv[4]), argv[5:6] == ["pending"]
    threading.Thread(target=svc.dispatch, name="dispatcher", daemon=True).start()
    while not (svc.running.wait(0.1) or svc.ended.is_set()):
        if time.monotonic() - T0 > 25:
            break
    if not svc.running.is_set():
        log("NOT A SERVICE: the dispatcher %s" % ("failed with %s%s" % (svc.failed, " (not started by the service "
            "manager)" if svc.failed == NOT_BY_THE_MANAGER else "") if svc.ended.is_set() else "did not connect in 25 s"))
        return 1
    if label == "refuse":
        svc.ended.wait(15)
        log("refused with %d from %s; the dispatcher %s" % (svc.refuse, "START_PENDING" if svc.pending else "RUNNING",
                                                          "returned" if svc.ended.is_set() else "did not return"))
        return 0
    log("RUNNING reported %.2f s after the process began" % (time.monotonic() - T0))
    if label == "make":
        target = os.path.join(os.environ.get("ProgramData", "C:\\ProgramData"), "RaqibProbe5s")
        log("as the system: made closed in one call: %s" % make_closed(target))
        log("as the system: by its handle: %s" % read_handle(target))
        svc.work_done.set()
        svc.ended.wait(15)
        return 0
    home = os.path.join(place, "home")
    os.makedirs(home, exist_ok=True)
    os.environ["USERPROFILE"] = home   # the record's place: the service's own, as the Linux unit's HOME is
    os.environ["HOME"] = home
    out = open(os.path.join(place, "watch.out"), "w", encoding="utf-8", errors="backslashreplace")
    if sys.stderr is None:
        sys.stderr = open(os.path.join(place, "watch.err"), "w", encoding="utf-8", errors="backslashreplace")
    if sys.stdout is None:
        sys.stdout = io.StringIO()
    how = "returned"
    code = None
    try:
        from raqib import cli
        log("raqib imported %.2f s after the process began" % (time.monotonic() - T0))
        code = cli.main(["watch", "--host", "--rounds", rounds, "--every", "3", "--no-open", "--no-page",
                         "--no-notify"], out)
    except KeyboardInterrupt:
        how = "the interrupt came out of the entry"
    except SystemExit as exc:
        how = "SystemExit %r" % (exc.code,)
    except BaseException as exc:
        how = "%s: %s" % (type(exc).__name__, exc)
    took = (time.monotonic() - svc.stopped_at) if svc.stop_asked.is_set() else None
    log("the watch %s with %r; stop asked %s%s" % (how, code, svc.stop_asked.is_set(),
                                                 "; %.2f s after the control" % took if took is not None else ""))
    out.close()
    svc.exit_code = 0
    svc.work_done.set()
    svc.ended.wait(15)
    log("END: the dispatcher %s" % ("returned" if svc.ended.is_set() else "did not return in 15 s"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
