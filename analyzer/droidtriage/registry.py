"""Analyser registry.

An analyser is a function ``fn(ctx: Context) -> None`` registered with :func:`analyzer`.
Analysers run in ascending ``order``; anything with a higher order can rely on the data produced
by lower ones (e.g. ``packages`` rules need the inventory, dumpsys roles and VirusTotal verdicts).

Adding an analyser = one decorated function in any module imported by ``pipeline.py``::

    @analyzer("wifi", order=75, title="Wi-Fi networks", description="saved networks, open Wi-Fi")
    def analyse_wifi(ctx):
        ...
        ctx.add(Finding("wifi.open", "LOW", "SECURITY", "Auto-joins open networks", source="wifi"))
        ctx.coverage["wifi"] = "ok"

Order map (leave gaps for new analysers):
  10 inventory  20 apk  30 virustotal  40 device  50 dumpsys  60 packages  70 logcat  80 network
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class Analyzer:
    """A registered analyser."""
    name: str
    order: int
    title: str
    description: str
    fn: Callable


REGISTRY: dict[str, Analyzer] = {}


def analyzer(name: str, order: int, title: str, description: str = ""):
    """Decorator registering an analyser function under ``name``."""
    def deco(fn):
        if name in REGISTRY and REGISTRY[name].fn is not fn:
            raise ValueError(f"analyser {name!r} registered twice")
        REGISTRY[name] = Analyzer(name, order, title, description or (fn.__doc__ or "").strip().split("\n")[0], fn)
        return fn
    return deco


def ordered() -> list[Analyzer]:
    """Registered analysers sorted by ``order``."""
    return sorted(REGISTRY.values(), key=lambda a: a.order)
