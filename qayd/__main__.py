"""Entry point for ``python3 -m qayd``.

Stub until M1.1 lands the command layer (qayd/cli.py): prints a usage note
and exits 2 (usage), per ADR-0001 section 6.
"""

import sys


def main(argv=None, stdout=None, stderr=None):
    err = stderr if stderr is not None else sys.stderr
    err.write("qayd: no commands yet; the check command arrives in M1.1\n")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
