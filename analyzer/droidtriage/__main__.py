"""``python3 -m droidtriage`` entry point (see :mod:`droidtriage.cli`)."""
import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
