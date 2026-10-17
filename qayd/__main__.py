"""Entry point for ``python3 -m qayd`` (ADR-0001 section 8)."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:], sys.stdout, sys.stderr))
