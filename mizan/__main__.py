"""Entry point for ``python3 -m mizan``.

Phase 0 stub: the command-line interface (mizan/cli.py) arrives with M1.1.
Until then any invocation is a usage error (exit code 2, ADR-0001 section 8).
"""

import sys


def _main(argv):
    try:
        from mizan.cli import main
    except ImportError:
        sys.stderr.write("mizan: no commands available yet (phase 0)\n")
        return 2
    return main(argv)


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
