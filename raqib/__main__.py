"""python -m raqib: see raqib/cli.py (main() sets up stdout, as for the
`raqib` console script)."""
import sys

from raqib.cli import main

if __name__ == "__main__":
    sys.exit(main())
