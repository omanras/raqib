#!/usr/bin/env python3
"""Install the Raqib capture hook into a watched project (M0.3, M5.1).

Usage: python3 tools/install_hooks.py [--log PATH] <watched-project>
       (tools/install-hooks.sh runs this with `python3 -I`; on Windows run
       it with the Python that should run the hook, e.g. `py -I ...`)

A thin wrapper (M6.3, W14): the installer is raqib/install.py, which
`raqib watch` imports as part of the package; its docstring has the hook
commands and the exit codes (0 installed; 1 settings unreadable or
unwritable, left untouched; 2 usage; 3 installed, but disableAllHooks is
set). This file puts its own checkout first on sys.path, so the raqib it
imports is this checkout's and not an installed copy, and runs
install.main() with the checkout as the shell named it (its
raqib/hooks/capture.py is what the hooks run) and with WINDOWS below, the
platform switch the tests turn.
"""
from __future__ import annotations

import os
import sys

WINDOWS = os.name == "nt"
# This file's path; as the shell gave it when run as a script (see the end),
# so the checkout is named as `cd "$(dirname "$0")/.." && pwd` names it.
SCRIPT = __file__
CHECKOUT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if sys.path[:1] != [CHECKOUT]:
    sys.path.insert(0, CHECKOUT)

from raqib import install  # noqa: E402
# The installer's API under its old names, for the callers of this file.
from raqib.install import (EVENTS, LAUNCHER, TIMEOUT, Exit, is_raqib, log_of,  # noqa: E402,F401
                           posix_command, windows_command)


def main(argv=None):
    return install.main(argv, windows=WINDOWS, root=os.path.join(os.path.dirname(SCRIPT), ".."))


if __name__ == "__main__":
    SCRIPT = sys.argv[0]
    # A path the console cannot encode is escaped, not a crash after the write.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="backslashreplace")
    sys.exit(main())
