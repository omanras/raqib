"""PROBE (not for main): how long the real window takes to open on this system, and at each display scale.
The commander's Windows machine shows a white window, Not Responding. Each test ends by failing with its
timings, so the CI log holds them; a real hang is cut by faulthandler with every thread's stack."""
import faulthandler
import sys
import time

import pytest

SCALES = (1.0, 1.25, 1.5, 1.75, 2.0, 2.5, 3.0)


def test_probe_the_real_app_opens(tmp_path, monkeypatch):
    if sys.platform != "win32":
        pytest.skip("the probe of the real app is for Windows")
    tkinter = pytest.importorskip("tkinter")
    from raqib import cli
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    times = []

    def quick(self, n=0):
        t0 = time.monotonic()
        while time.monotonic() - t0 < 25:
            a = time.monotonic()
            self.update()
            times.append(round(time.monotonic() - a, 3))
            time.sleep(0.05)

    monkeypatch.setattr(tkinter.Tk, "mainloop", quick)
    faulthandler.dump_traceback_later(240, exit=True)
    t = time.monotonic()
    try:
        code = cli.main(["app", str(tmp_path)])
    except SystemExit as exc:
        code = exc.code
    finally:
        faulthandler.cancel_dump_traceback_later()
    total = time.monotonic() - t
    pytest.fail("PROBE real app: code %r, total %.1f s, %d updates, before the first update %.1f s, slowest %s, first %s"
                % (code, total, len(times), total - sum(times) - 0.05 * len(times),
                   sorted(times, reverse=True)[:8], times[:10]))


@pytest.mark.parametrize("scale", SCALES)
def test_probe_the_window_at_a_scale(scale, tmp_path, monkeypatch):
    tkinter = pytest.importorskip("tkinter")
    import test_app_redo as T
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    try:
        root = tkinter.Tk()
    except Exception as exc:
        pytest.skip("no display: %s" % exc)
    faulthandler.dump_traceback_later(240, exit=True)
    window = None
    try:
        t = time.monotonic()
        window, c = T._window(tkinter, root, home, tmp_path, scale=scale)
        built = time.monotonic() - t
        root.deiconify()
        times = []
        for _ in range(60):
            a = time.monotonic()
            root.update()
            window.tick()
            times.append(round(time.monotonic() - a, 3))
        settle = sum(times)
    finally:
        faulthandler.cancel_dump_traceback_later()
        if window is not None:
            window.destroy()
        else:
            root.destroy()
    pytest.fail("PROBE scale %s on %s: built %.1f s, 60 updates %.1f s, slowest %s, last ten %s"
                % (scale, sys.platform, built, settle, sorted(times, reverse=True)[:6], times[-10:]))
