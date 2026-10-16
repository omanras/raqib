"""python -m raqib: see raqib/cli.py."""
import sys

from raqib.cli import main

if __name__ == "__main__":
    sys.stdout.reconfigure(errors="backslashreplace")
    sys.exit(main())
