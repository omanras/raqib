"""The Windows tray icon of `raqib app` (M6.4, ADR-0006): Win32 through ctypes.

On Windows, Tray.start() runs one thread that registers a window class,
creates a hidden message-only window (parent HWND_MESSAGE) whose WndProc is
a ctypes callback, adds a notification-area icon with Shell_NotifyIconW and
pumps that thread's messages with GetMessageW. The icon is drawn in code
(icon_masks: an AND and an XOR bitmask, CreateIcon); there is no image
file. A left click on the icon means Show; a right click opens a popup menu
Show / Stop / Quit (TrackPopupMenu with TPM_RETURNCMD). Each action is
handed to on_action(name) - the window puts it on a queue that its after()
reads, so no Tk call is ever made from the tray thread. When Explorer
restarts (the "TaskbarCreated" message) the icon is added again.

Nothing here raises into the window (A3): start() returns None or the
reason the tray is not there, and every later failure (an exception in the
WndProc, an icon that could not be re-added, a thread that did not stop) is
appended to `holes`, which the window shows. Off Windows the module imports,
and start() says "no tray on this platform" (ADR-0006: no tray on Linux in
v1). The tray touches only Raqib's own window and icon: it never signals or
writes to the agent (A4).

The pure parts - the menu, what a menu id or a mouse message means, the
icon's bitmasks - are plain functions, tested with fakes on any system.
"""
from __future__ import annotations

import sys
import threading

ID_SHOW, ID_STOP, ID_QUIT = 1001, 1002, 1003
MENU = ((ID_SHOW, "Show"), (ID_STOP, "Stop"), (ID_QUIT, "Quit"))
ACTIONS = {ID_SHOW: "show", ID_STOP: "stop", ID_QUIT: "quit"}
TIP = "Raqib"
START_SECONDS = 5.0     # how long start() waits for the tray thread to say it is up
STOP_SECONDS = 5.0      # how long stop() waits for the tray thread to end

# Win32 constants (winuser.h, shellapi.h).
WM_NULL = 0x0000
WM_DESTROY = 0x0002
WM_CLOSE = 0x0010
WM_CONTEXTMENU = 0x007B
WM_LBUTTONUP = 0x0202
WM_LBUTTONDBLCLK = 0x0203
WM_RBUTTONUP = 0x0205
WM_APP = 0x8000
WM_TRAY = WM_APP + 1    # the icon's callback message
HWND_MESSAGE = -3
NIM_ADD, NIM_MODIFY, NIM_DELETE = 0, 1, 2
NIF_MESSAGE, NIF_ICON, NIF_TIP = 0x1, 0x2, 0x4
MF_STRING = 0x0
TPM_RIGHTBUTTON, TPM_NONOTIFY, TPM_RETURNCMD = 0x2, 0x80, 0x100
SM_CXSMICON = 49
ICON_MIN, ICON_MAX = 16, 64


def unsupported(platform=None):
    """None on Windows, else why there is no tray (ADR-0006: Linux has none in v1)."""
    platform = platform or sys.platform
    if platform == "win32":
        return None
    return "no tray on this platform (%s): the window stays open; closing it stops the watch" % platform


def menu_action(item):
    """The action of a popup menu id ("show", "stop", "quit"), or None (the
    menu was dismissed: TrackPopupMenu returned 0)."""
    return ACTIONS.get(item)


def mouse_action(event):
    """What a callback message's mouse event means: "show" for a left click,
    "menu" for a right click or the context-menu key, else None."""
    if event in (WM_LBUTTONUP, WM_LBUTTONDBLCLK):
        return "show"
    if event in (WM_RBUTTONUP, WM_CONTEXTMENU):
        return "menu"
    return None


def icon_masks(size=16):
    """(AND mask, XOR mask) of a size x size monochrome icon, rows padded to
    16 bits as CreateIcon wants them. AND 1 is transparent; AND 0 with XOR 1
    is white, with XOR 0 black. The drawing: an eye - a black ring, a white
    iris, a black pupil - on a transparent ground."""
    row = (size + 15) // 16 * 2
    and_bits = bytearray(row * size)
    xor_bits = bytearray(row * size)
    c = (size - 1) / 2.0
    outer, ring, pupil = size / 2.0, size * 0.36, size * 0.16
    for y in range(size):
        for x in range(size):
            d = ((x - c) ** 2 + (y - c) ** 2) ** 0.5
            byte, bit = y * row + x // 8, 0x80 >> (x % 8)
            if d > outer:
                and_bits[byte] |= bit          # transparent
            elif ring < d or d <= pupil:
                pass                           # black: AND 0, XOR 0
            else:
                xor_bits[byte] |= bit          # white
    return bytes(and_bits), bytes(xor_bits)


def icon_size(metric):
    """The small-icon size the system asks for, kept to a sane square."""
    try:
        metric = int(metric)
    except (TypeError, ValueError):
        return ICON_MIN
    return min(max(metric, ICON_MIN), ICON_MAX)


def dispatch(msg, lparam, on_mouse):
    """The tray window's own handling of a message: True when it was the
    icon's callback (on_mouse(mouse_action) was called for a known event),
    else False (the caller passes it on)."""
    if msg != WM_TRAY:
        return False
    action = mouse_action(lparam & 0xFFFF)
    if action is not None:
        on_mouse(action)
    return True


class _Api:
    """The Win32 functions the tray uses, with their ctypes signatures.
    Built only on Windows (ctypes.WINFUNCTYPE and windll exist there only)."""

    def __init__(self):
        import ctypes
        from ctypes import wintypes as w
        self.ctypes, self.w = ctypes, w
        lresult = ctypes.c_ssize_t
        self.WNDPROC = ctypes.WINFUNCTYPE(lresult, w.HWND, w.UINT, w.WPARAM, w.LPARAM)

        class WNDCLASSEXW(ctypes.Structure):
            _fields_ = [("cbSize", w.UINT), ("style", w.UINT), ("lpfnWndProc", self.WNDPROC),
                        ("cbClsExtra", ctypes.c_int), ("cbWndExtra", ctypes.c_int), ("hInstance", w.HINSTANCE),
                        ("hIcon", w.HICON), ("hCursor", w.HANDLE), ("hbrBackground", w.HBRUSH),
                        ("lpszMenuName", w.LPCWSTR), ("lpszClassName", w.LPCWSTR), ("hIconSm", w.HICON)]

        class GUID(ctypes.Structure):
            _fields_ = [("Data1", w.DWORD), ("Data2", w.WORD), ("Data3", w.WORD), ("Data4", w.BYTE * 8)]

        class NOTIFYICONDATAW(ctypes.Structure):
            _fields_ = [("cbSize", w.DWORD), ("hWnd", w.HWND), ("uID", w.UINT), ("uFlags", w.UINT),
                        ("uCallbackMessage", w.UINT), ("hIcon", w.HICON), ("szTip", w.WCHAR * 128),
                        ("dwState", w.DWORD), ("dwStateMask", w.DWORD), ("szInfo", w.WCHAR * 256),
                        ("uVersion", w.UINT), ("szInfoTitle", w.WCHAR * 64), ("dwInfoFlags", w.DWORD),
                        ("guidItem", GUID), ("hBalloonIcon", w.HICON)]

        self.WNDCLASSEXW, self.NOTIFYICONDATAW, self.MSG, self.POINT = WNDCLASSEXW, NOTIFYICONDATAW, w.MSG, w.POINT
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        shell32 = ctypes.WinDLL("shell32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        def fn(dll, name, restype, *argtypes):
            f = getattr(dll, name)
            f.restype, f.argtypes = restype, list(argtypes)
            return f
        self.GetModuleHandleW = fn(kernel32, "GetModuleHandleW", w.HMODULE, w.LPCWSTR)
        self.RegisterClassExW = fn(user32, "RegisterClassExW", w.ATOM, ctypes.POINTER(WNDCLASSEXW))
        self.UnregisterClassW = fn(user32, "UnregisterClassW", w.BOOL, w.LPCWSTR, w.HINSTANCE)
        self.CreateWindowExW = fn(user32, "CreateWindowExW", w.HWND, w.DWORD, w.LPCWSTR, w.LPCWSTR, w.DWORD,
                                  ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, w.HWND, w.HMENU,
                                  w.HINSTANCE, w.LPVOID)
        self.DestroyWindow = fn(user32, "DestroyWindow", w.BOOL, w.HWND)
        self.DefWindowProcW = fn(user32, "DefWindowProcW", lresult, w.HWND, w.UINT, w.WPARAM, w.LPARAM)
        self.GetMessageW = fn(user32, "GetMessageW", w.BOOL, ctypes.POINTER(w.MSG), w.HWND, w.UINT, w.UINT)
        self.TranslateMessage = fn(user32, "TranslateMessage", w.BOOL, ctypes.POINTER(w.MSG))
        self.DispatchMessageW = fn(user32, "DispatchMessageW", lresult, ctypes.POINTER(w.MSG))
        self.PostMessageW = fn(user32, "PostMessageW", w.BOOL, w.HWND, w.UINT, w.WPARAM, w.LPARAM)
        self.PostQuitMessage = fn(user32, "PostQuitMessage", None, ctypes.c_int)
        self.RegisterWindowMessageW = fn(user32, "RegisterWindowMessageW", w.UINT, w.LPCWSTR)
        self.GetSystemMetrics = fn(user32, "GetSystemMetrics", ctypes.c_int, ctypes.c_int)
        self.CreateIcon = fn(user32, "CreateIcon", w.HICON, w.HINSTANCE, ctypes.c_int, ctypes.c_int, w.BYTE,
                             w.BYTE, ctypes.c_char_p, ctypes.c_char_p)
        self.DestroyIcon = fn(user32, "DestroyIcon", w.BOOL, w.HICON)
        self.CreatePopupMenu = fn(user32, "CreatePopupMenu", w.HMENU)
        self.AppendMenuW = fn(user32, "AppendMenuW", w.BOOL, w.HMENU, w.UINT, ctypes.c_size_t, w.LPCWSTR)
        self.TrackPopupMenu = fn(user32, "TrackPopupMenu", w.BOOL, w.HMENU, w.UINT, ctypes.c_int, ctypes.c_int,
                                 ctypes.c_int, w.HWND, w.LPVOID)
        self.DestroyMenu = fn(user32, "DestroyMenu", w.BOOL, w.HMENU)
        self.GetCursorPos = fn(user32, "GetCursorPos", w.BOOL, ctypes.POINTER(w.POINT))
        self.SetForegroundWindow = fn(user32, "SetForegroundWindow", w.BOOL, w.HWND)
        self.Shell_NotifyIconW = fn(shell32, "Shell_NotifyIconW", w.BOOL, w.DWORD, ctypes.POINTER(NOTIFYICONDATAW))

    def last_error(self):
        return self.ctypes.get_last_error()


class Tray:
    """One notification-area icon. on_action(name) gets "show", "stop" or
    "quit", called from the tray thread: it must only queue the action."""

    def __init__(self, on_action, platform=None, api=None, tip=TIP):
        self.on_action = on_action
        self.platform = platform or sys.platform
        self.api = api
        self.tip = tip
        self.holes = []          # what went wrong after start() (A3); the window shows them
        self.hwnd = None
        self.icon = None
        self.thread = None
        self.running = False
        self._ready = threading.Event()
        self._error = None
        self._proc = None        # the ctypes WndProc: kept, or it is collected while Windows calls it
        self._class = "RaqibTray-%d" % id(self)
        self._hinstance = None
        self._taskbar_created = None
        self._added = False      # the icon is in the notification area
        self._destroyed = False  # the hidden window is gone

    # --- what the window calls --------------------------------------------------

    def start(self):
        """None when the icon is up, else why not (a hole for the window)."""
        why = unsupported(self.platform)
        if why:
            return why
        self.thread = threading.Thread(target=self._run, name="raqib-tray", daemon=True)
        self.thread.start()
        if not self._ready.wait(START_SECONDS):
            return "the tray did not come up within %g s" % START_SECONDS
        if self._error:
            return self._error
        self.running = True
        return None

    def stop(self):
        """Remove the icon and end the tray thread; never raises."""
        if self.thread is None:
            return
        try:
            if self.hwnd:
                self.api.PostMessageW(self.hwnd, WM_CLOSE, 0, 0)
        except Exception as exc:
            self._hole("the tray could not be told to close: %s: %s" % (type(exc).__name__, exc))
        self.thread.join(STOP_SECONDS)
        if self.thread.is_alive():
            self._hole("the tray thread did not end within %g s" % STOP_SECONDS)
        self.running = False

    # --- the tray thread ----------------------------------------------------------

    def _hole(self, text):
        if text not in self.holes:
            self.holes.append(text)

    def _run(self):
        try:
            self._up()
        except Exception as exc:
            self._error = "the tray could not be set up: %s: %s" % (type(exc).__name__, exc)
            self._ready.set()
            self._down()
            return
        self._ready.set()
        try:
            self._pump()
        except Exception as exc:
            self._hole("the tray's message loop ended on %s: %s" % (type(exc).__name__, exc))
        finally:
            self.running = False
            self._down()

    def _up(self):
        api = self.api = self.api or _Api()
        self._hinstance = api.GetModuleHandleW(None)
        self._proc = api.WNDPROC(self._wndproc)
        wc = api.WNDCLASSEXW()
        wc.cbSize = api.ctypes.sizeof(api.WNDCLASSEXW)
        wc.lpfnWndProc = self._proc
        wc.hInstance = self._hinstance
        wc.lpszClassName = self._class
        if not api.RegisterClassExW(api.ctypes.byref(wc)):
            raise OSError("RegisterClassExW failed (error %d)" % api.last_error())
        self._taskbar_created = api.RegisterWindowMessageW("TaskbarCreated")
        self.hwnd = api.CreateWindowExW(0, self._class, TIP, 0, 0, 0, 0, 0, HWND_MESSAGE, None, self._hinstance,
                                        None)
        if not self.hwnd:
            raise OSError("CreateWindowExW failed (error %d)" % api.last_error())
        size = icon_size(api.GetSystemMetrics(SM_CXSMICON))
        and_bits, xor_bits = icon_masks(size)
        self.icon = api.CreateIcon(self._hinstance, size, size, 1, 1, and_bits, xor_bits)
        if not self.icon:
            raise OSError("CreateIcon failed (error %d)" % api.last_error())
        if not self._notify(NIM_ADD):
            raise OSError("Shell_NotifyIconW(NIM_ADD) failed (error %d): no notification area?" % api.last_error())
        self._added = True

    def _data(self):
        api = self.api
        data = api.NOTIFYICONDATAW()
        data.cbSize = api.ctypes.sizeof(api.NOTIFYICONDATAW)
        data.hWnd = self.hwnd
        data.uID = 1
        data.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP
        data.uCallbackMessage = WM_TRAY
        data.hIcon = self.icon
        data.szTip = self.tip[:127]
        return data

    def _notify(self, what):
        data = self._data()
        return bool(self.api.Shell_NotifyIconW(what, self.api.ctypes.byref(data)))

    def _pump(self):
        api = self.api
        msg = api.MSG()
        while True:
            got = api.GetMessageW(api.ctypes.byref(msg), None, 0, 0)
            if got == 0:        # WM_QUIT
                return
            if got == -1:
                raise OSError("GetMessageW failed (error %d)" % api.last_error())
            api.TranslateMessage(api.ctypes.byref(msg))
            api.DispatchMessageW(api.ctypes.byref(msg))

    def _wndproc(self, hwnd, msg, wparam, lparam):
        try:
            if dispatch(msg, lparam, self._mouse):
                return 0
            if msg == self._taskbar_created and self._taskbar_created:
                if not self._notify(NIM_ADD):   # Explorer restarted: the icon is added again
                    self._hole("the tray icon could not be added again after Explorer restarted")
                return 0
            if msg == WM_CLOSE:
                self._remove()            # the icon goes before its window
                self.api.DestroyWindow(hwnd)
                return 0
            if msg == WM_DESTROY:
                self._destroyed = True
                self.api.PostQuitMessage(0)
                return 0
        except Exception as exc:   # never into Windows' call: a hole
            self._hole("the tray failed on message 0x%04x: %s: %s" % (msg, type(exc).__name__, exc))
            return 0
        return self.api.DefWindowProcW(hwnd, msg, wparam, lparam)

    def _mouse(self, action):
        if action == "menu":
            action = menu_action(self._menu())
        if action is not None:
            self.on_action(action)

    def _menu(self):
        """Show the popup menu at the cursor; the chosen id, or 0."""
        api = self.api
        menu = api.CreatePopupMenu()
        if not menu:
            raise OSError("CreatePopupMenu failed (error %d)" % api.last_error())
        try:
            for item, label in MENU:
                api.AppendMenuW(menu, MF_STRING, item, label)
            point = api.POINT()
            api.GetCursorPos(api.ctypes.byref(point))
            api.SetForegroundWindow(self.hwnd)   # so the menu closes when the person clicks elsewhere
            chosen = api.TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_RETURNCMD | TPM_NONOTIFY, point.x, point.y,
                                        0, self.hwnd, None)
            api.PostMessageW(self.hwnd, WM_NULL, 0, 0)
            return chosen
        finally:
            api.DestroyMenu(menu)

    def _down(self):
        api = self.api
        if api is None:
            return
        for step in (self._remove, self._destroy_window, self._destroy_icon, self._unregister):
            try:
                step()
            except Exception as exc:
                self._hole("the tray did not clean up (%s): %s: %s" % (step.__name__.strip("_"), type(exc).__name__,
                                                                      exc))

    def _remove(self):
        if self._added:
            self._added = False
            if not self._notify(NIM_DELETE):
                self._hole("the tray icon could not be removed (Shell_NotifyIconW NIM_DELETE failed)")

    def _destroy_window(self):
        if self.hwnd and not self._destroyed:
            self.api.DestroyWindow(self.hwnd)
            self._destroyed = True
        self.hwnd = None

    def _destroy_icon(self):
        if self.icon:
            self.api.DestroyIcon(self.icon)
        self.icon = None

    def _unregister(self):
        if self._hinstance is not None:
            self.api.UnregisterClassW(self._class, self._hinstance)
