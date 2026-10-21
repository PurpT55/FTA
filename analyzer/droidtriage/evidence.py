"""Uniform read access to a collector zip, an extracted directory, or an adb_collect.sh folder."""
from __future__ import annotations

import fnmatch
import io
import json
import os
import zipfile


class Evidence:
    """Read-only view over a zip or folder with forward-slash relative names (a single wrapping folder in a zip is stripped)."""
    def __init__(self, path: str):
        self.path = path
        self._zip = None
        if os.path.isdir(path):
            self.kind = "dir"
            self._names = []
            for root, _, files in os.walk(path):
                for f in files:
                    full = os.path.join(root, f)
                    self._names.append(os.path.relpath(full, path).replace(os.sep, "/"))
        elif zipfile.is_zipfile(path):
            self.kind = "zip"
            self._zip = zipfile.ZipFile(path)
            self._names = [n for n in self._zip.namelist() if not n.endswith("/")]
            # Tolerate archives that wrap everything in one top-level folder.
            prefixes = {n.split("/", 1)[0] for n in self._names}
            self._prefix = ""
            if len(prefixes) == 1 and not any(n == "manifest.json" for n in self._names):
                only = prefixes.pop()
                if all(n.startswith(only + "/") for n in self._names):
                    self._prefix = only + "/"
                    self._names = [n[len(self._prefix):] for n in self._names]
        else:
            raise ValueError(f"{path}: not a directory or zip file")
        if self.kind == "dir":
            self._prefix = ""
        self._names.sort()

    # ------------------------------------------------------------------ queries
    def names(self, pattern: str = "*") -> list[str]:
        """Entry names matching a glob pattern (``fnmatch``: ``*`` also crosses ``/``)."""
        return [n for n in self._names if fnmatch.fnmatch(n, pattern)]

    def has(self, name: str) -> bool:
        """True if the entry exists."""
        return name in self._names

    def size(self, name: str) -> int:
        """Uncompressed size in bytes."""
        if self.kind == "zip":
            return self._zip.getinfo(self._prefix + name).file_size
        return os.path.getsize(os.path.join(self.path, name))

    def open(self, name: str):
        """Binary file object for an entry."""
        if self.kind == "zip":
            return self._zip.open(self._prefix + name)
        return open(os.path.join(self.path, name), "rb")

    def read(self, name: str, limit: int | None = None) -> bytes:
        """Entry bytes (optionally only the first ``limit`` bytes)."""
        with self.open(name) as f:
            return f.read(limit) if limit else f.read()

    def text(self, name: str, default: str = "") -> str:
        """Entry decoded as UTF-8 (errors replaced), or ``default`` if missing."""
        if not self.has(name):
            return default
        return self.read(name).decode("utf-8", "replace")

    def json(self, name: str, default=None):
        """Entry parsed as JSON, or ``default`` if missing/invalid."""
        if not self.has(name):
            return default
        try:
            return json.loads(self.read(name))
        except Exception:
            return default

    def lines(self, name: str):
        """Streams text lines (logcat files can be hundreds of MB)."""
        if not self.has(name):
            return
        with self.open(name) as f, io.TextIOWrapper(f, encoding="utf-8", errors="replace") as text:
            for raw in text:
                yield raw.rstrip("\n")

    def first(self, *names: str) -> str | None:
        """First existing name among candidates (collector vs adb_collect layouts)."""
        for n in names:
            if self.has(n):
                return n
        return None
