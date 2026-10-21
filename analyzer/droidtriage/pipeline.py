"""Runs every registered analyser in order, then computes the derived results.

Importing the analyser modules below is what registers them (see :mod:`registry`).
"""
from __future__ import annotations

import time

from . import apkscan, logs, network, packages, system, vt  # noqa: F401  (registration side effect)
from .console import console
from .model import Context
from .packages import OWN, scores
from .registry import ordered


def run_all(ctx: Context) -> Context:
    """Run all analysers not listed in ``ctx.opt.skip`` and finalise scores / unknown binaries."""
    steps = ordered()
    for i, a in enumerate(steps, 1):
        if a.name in ctx.opt.skip:
            ctx.coverage[a.name] = "skipped (--skip)"
            continue
        console.step(f"[{i}/{len(steps)}] {a.title}")
        t0 = time.perf_counter()
        a.fn(ctx)
        ctx.timings[a.name] = round(time.perf_counter() - t0, 3)
        console.debug(f"{a.name}: {ctx.timings[a.name]} s")
    finalize(ctx)
    return ctx


def finalize(ctx: Context) -> None:
    """Unknown binaries = sideloaded and not known to VirusTotal (or not checked); dedupe; scores."""
    ctx.unknown = sorted(n for n, p in ctx.packages.items()
                         if n not in OWN and ctx.is_sideloaded(n)
                         and ctx.vt.get(p.get("apkSha256") or "", {}).get("malicious", -1) < 0)
    ctx.dedupe()
    ctx.scores = scores(ctx)
