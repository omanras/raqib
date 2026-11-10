"""Tk objects are finalised on the main thread (ADR-0009 Amendment A, A-16, in its smallest form on this
branch; M8.1 brings the whole fixture, which also ends every thread a Tk test started).

A Tk test leaves Tk objects (a root, Variables) in reference cycles. When the cyclic collector later runs in
another thread - a watch's worker in a later test - each Variable's finaliser calls Tcl from that thread, and
tkinter makes it wait a second for a main loop that is not running before it gives up ("main thread is not in
main loop"); a Tk root collected there makes Tcl abort the process. On CI's windows jobs that stalled a
worker for long enough to fail a timing test in another file, and once killed the run. So after every Tk
test the garbage is collected here, on the main thread."""
import gc

import pytest


@pytest.fixture(autouse=True)
def tk_garbage_is_collected_on_the_main_thread(request):
    yield
    if request.node.name.startswith("test_tk"):
        gc.collect()
