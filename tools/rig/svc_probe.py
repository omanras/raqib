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
        self.exit_code = 0
        self._handler = HANDLER_EX(self.handler)        # kept: the system calls them later
        self._main = SERVICE_MAIN(self.service_main)

    def status(self, state, hint=0):
        s = SERVICE_STATUS(SERVICE_WIN32_OWN_PROCESS, state,
                           (ACCEPT_STOP | ACCEPT_SHUTDOWN) if state == RUNNING else 0,
                           self.exit_code if state == STOPPED else 0, 0, 0, hint)
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


def main(argv):
    if len(argv) == 3 and argv[1] == "--close":
        return close(argv[2])
    if len(argv) == 3 and argv[1] in ("--owner", "--give"):
        return owner(argv[2], argv[1] == "--give")
    if len(argv) < 4 or argv[1] != "--service":
        print(__doc__)
        return 2
    name, label = argv[2], argv[3]
    rounds = argv[4] if len(argv) > 4 else "400"
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
    threading.Thread(target=svc.dispatch, name="dispatcher", daemon=True).start()
    while not (svc.running.wait(0.1) or svc.ended.is_set()):
        if time.monotonic() - T0 > 25:
            break
    if not svc.running.is_set():
        log("NOT A SERVICE: the dispatcher %s" % ("failed with %s%s" % (svc.failed, " (not started by the service "
            "manager)" if svc.failed == NOT_BY_THE_MANAGER else "") if svc.ended.is_set() else "did not connect in 25 s"))
        return 1
    log("RUNNING reported %.2f s after the process began" % (time.monotonic() - T0))
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
