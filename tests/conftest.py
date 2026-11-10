"""M8.1 REDO A-16 (ADR-0009 Amendment A): every Tk test ends what it started.

A Tk root, or a Tk object with a __del__ (a Variable, a PhotoImage), that is
garbage-collected from a thread other than the main one makes Tcl abort the
process ("Windows fatal exception: code 0x80000003"). So after each Tk test
(a test whose name starts with test_tk) this fixture, on the main thread:
destroys a root the test left, joins every thread the test started (a bounded
join; a thread still alive is a failure, never a hang), and collects the
garbage, so no Tk object is left for another thread to collect."""
import gc
import sys
import threading

import pytest

JOIN_SECONDS = 10.0


def end_tk_test(before, join=JOIN_SECONDS):
    """What a Tk test leaves: its root destroyed, its threads joined (each
    within `join` s), the garbage collected here. The names of the threads
    still alive (empty when it ended what it started)."""
    tkinter = sys.modules.get("tkinter")
    root = getattr(tkinter, "_default_root", None) if tkinter is not None else None
    if root is not None:
        try:
            root.destroy()
        except Exception:
            pass
    left = [t for t in threading.enumerate() if t not in before and t is not threading.current_thread()]
    for thread in left:
        thread.join(join)
    gc.collect()
    return [t.name for t in left if t.is_alive()]


@pytest.fixture(autouse=True)
def _tk_ends_what_it_started(request):
    if not request.node.name.startswith("test_tk"):
        yield
        return
    before = set(threading.enumerate())
    yield
    alive = end_tk_test(before)
    assert alive == [], "a Tk test left threads running after it returned: %s" % alive
