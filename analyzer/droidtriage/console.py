"""Terminal output helpers: colours (auto-disabled when not a TTY or NO_COLOR is set), progress, tables.

Everything that is not the requested result goes to stderr so stdout stays pipe-friendly
(``droidtriage analyze x.zip --json | jq .summary``).
"""
from __future__ import annotations

import os
import sys

_COLORS = {"CRITICAL": "1;97;41", "HIGH": "1;31", "MEDIUM": "33", "LOW": "36", "INFO": "2",
           "ok": "32", "warn": "33", "bad": "31", "dim": "2", "bold": "1", "title": "1;36"}


class Console:
    """Process-wide console settings; use the module-level ``console`` instance."""
    def __init__(self):
        self.quiet = False
        self.verbose = False
        self.color = sys.stderr.isatty() and sys.stdout.isatty() and not os.environ.get("NO_COLOR")

    def configure(self, quiet=False, verbose=False, color=None):
        """Apply --quiet / --verbose / --no-color."""
        self.quiet, self.verbose = quiet, verbose
        if color is not None:
            self.color = color

    def c(self, text: str, style: str) -> str:
        """Wrap ``text`` in an ANSI style (no-op without colour)."""
        code = _COLORS.get(style)
        return f"\033[{code}m{text}\033[0m" if self.color and code else text

    def step(self, msg: str) -> None:
        """Top-level progress line (stderr)."""
        if not self.quiet:
            print(self.c("▸ ", "title") + msg, file=sys.stderr, flush=True)

    def info(self, msg: str) -> None:
        """Indented progress detail (stderr)."""
        if not self.quiet:
            print("  " + msg, file=sys.stderr, flush=True)

    def debug(self, msg: str) -> None:
        """Only with --verbose."""
        if self.verbose and not self.quiet:
            print(self.c("  · " + msg, "dim"), file=sys.stderr, flush=True)

    def warn(self, msg: str) -> None:
        """Always printed (stderr)."""
        print(self.c("! " + msg, "warn"), file=sys.stderr, flush=True)

    def error(self, msg: str) -> None:
        """Always printed (stderr)."""
        print(self.c("✖ " + msg, "bad"), file=sys.stderr, flush=True)

    def table(self, rows: list[list[str]], header: list[str] | None = None, out=None) -> None:
        """Plain aligned table (no external dependency)."""
        out = out or sys.stdout
        data = ([header] if header else []) + rows
        if not data:
            return
        widths = [max(len(_strip(str(r[i]))) for r in data) for i in range(len(data[0]))]
        for n, r in enumerate(data):
            cells = [str(x) + " " * (widths[i] - len(_strip(str(x)))) for i, x in enumerate(r)]
            line = "  ".join(cells).rstrip()
            print(self.c(line, "bold") if header and n == 0 else line, file=out)


def _strip(s: str) -> str:
    """Length of a string without ANSI codes."""
    import re
    return re.sub(r"\033\[[\d;]*m", "", s)


console = Console()
