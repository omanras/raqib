"""Entry point for ``python3 -m mizan``; the commands live in mizan/cli.py."""

import sys


def _main(argv):
    from mizan.cli import main
    return main(argv)


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
