"""Run ShellSuite as a module: ``python -m shellsuite ...``."""

import sys

from shellsuite.cli import main

if __name__ == "__main__":
    sys.exit(main())
