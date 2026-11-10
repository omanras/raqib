"""M7.8 REDO 3 V-5 (ADR-0007 Amendments T-6 and V-5): no thread of Raqib's
outlives the test that started it.

`raqib_threads_end` is an autouse pytest fixture; a test module uses it by
importing it (`from hostthreads import raqib_threads_end  # noqa: F401`).
It records every raqib.host.HostWatch the test builds, ends each one the test
did not end (finish: its sources told to stop and joined, bounded), stops the
sources of the rest even when a finish raises, and then fails the test if a
thread whose name starts with "raqib-" that the test started is still alive
after a bounded join. Not a conftest.py: the M8.1 branch adds one for its Tk
tests, and two fixtures of one name would collide when the branches meet."""
import functools
import threading
import time

import pytest

from raqib import host

PREFIX = "raqib-"
JOIN_SECONDS = 10.0


def _stop_sources(watch):
    for src in list((getattr(watch, "sources", None) or {}).values()):
        stop = getattr(src, "stop", None)
        if stop is not None:
            stop.set()
        helpers = getattr(src, "helpers", None)
        if helpers is not None:
            try:
                helpers.end("the test ended")
            except Exception:
                pass


@pytest.fixture(autouse=True)
def raqib_threads_end(monkeypatch):
    started = []
    real_init = host.HostWatch.__init__

    @functools.wraps(real_init)   # the docstring stays what the tests read
    def init(self, *args, **kwargs):
        started.append(self)
        real_init(self, *args, **kwargs)
    monkeypatch.setattr(host.HostWatch, "__init__", init)
    before = {t for t in threading.enumerate() if t.name.startswith(PREFIX)}
    yield started
    for watch in started:
        try:
            if hasattr(watch, "sources") and getattr(watch, "finished", None) is None:
                watch.finish()
        except Exception:
            pass   # a finish that raises still lets the rest be stopped
        finally:
            _stop_sources(watch)
    deadline = time.monotonic() + JOIN_SECONDS
    left = [t for t in threading.enumerate() if t.name.startswith(PREFIX) and t not in before]
    for t in left:
        t.join(max(0.0, deadline - time.monotonic()))
    alive = sorted(t.name for t in left if t.is_alive())
    assert not alive, "thread(s) of Raqib outlived the test: %s (V-5)" % ", ".join(alive)
