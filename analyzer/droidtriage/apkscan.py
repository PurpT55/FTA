"""Static analysis of every APK in the evidence (``apks/<package>/*.apk``), optionally in parallel.

The parsing itself lives in :mod:`apk` (pure functions, no context). This module only:
  * picks the base APK of each package and respects ``--max-apk-mb``;
  * fans the work out to ``--jobs`` worker processes (each opens the evidence itself, so
    APK bytes are never pickled between processes);
  * merges the result into the package inventory and turns rule hits into findings.
"""
from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor, as_completed

from . import apk as apkmod
from .console import console
from .evidence import Evidence
from .model import Context, Finding
from .registry import analyzer

_EV_CACHE: dict[str, Evidence] = {}


def _scan(evidence_path: str, name: str) -> dict:
    """Worker: analyse one APK inside the evidence (zip or directory)."""
    ev = _EV_CACHE.get(evidence_path)
    if ev is None:
        ev = _EV_CACHE[evidence_path] = Evidence(evidence_path)
    return apkmod.analyse_apk(ev.read(name), name)


def _empty_record(pkg: str, manifest: dict) -> dict:
    """Inventory record for an APK whose package was not in the inventory."""
    return {"package": pkg, "label": pkg, "requested": manifest.get("permissions", []), "granted": set(),
            "components": [], "certSha256": [], "certSha1": [], "certSubjects": [], "nativeLibs": [],
            "hasLauncher": None, "system": False, "updatedSystem": False, "debuggable": False, "installer": None}


@analyzer("apk", 20, "APK static analysis", "manifest, DEX strings, signing certs, payloads, packers, trackers")
def analyse_apks(ctx: Context) -> None:
    """Analyse each package's base APK and merge results into ``ctx.packages``."""
    by_pkg: dict[str, list[str]] = {}
    for n in ctx.ev.names("apks/*/*.apk"):
        by_pkg.setdefault(n.split("/")[1], []).append(n)
    if not by_pkg:
        ctx.coverage["apk"] = "MISSING – no APK files in the archive"
        return
    limit = ctx.opt.max_apk_mb * 2**20
    todo: dict[str, str] = {}
    for pkg, files in sorted(by_pkg.items()):
        base = next((f for f in files if f.endswith("/base.apk")), files[0])
        if ctx.ev.size(base) > limit:
            ctx.apk_reports[pkg] = {"skipped": f"larger than {ctx.opt.max_apk_mb} MB"}
        else:
            todo[pkg] = base

    results: dict[str, dict] = {}
    jobs = max(1, ctx.opt.jobs)
    if jobs == 1 or len(todo) < 4:
        for i, (pkg, base) in enumerate(todo.items()):
            if i % 25 == 0:
                console.info(f"APK {i + 1}/{len(todo)}")
            results[pkg] = apkmod.analyse_apk(ctx.ev.read(base), base)
    else:
        console.info(f"{len(todo)} APKs on {jobs} workers")
        with ProcessPoolExecutor(max_workers=jobs) as pool:
            futs = {pool.submit(_scan, ctx.ev.path, base): pkg for pkg, base in todo.items()}
            for i, fut in enumerate(as_completed(futs)):
                pkg = futs[fut]
                try:
                    results[pkg] = fut.result()
                except Exception as e:  # noqa: BLE001 - one broken APK must not stop the run
                    results[pkg] = {"errors": [f"worker: {e}"], "findings": [], "certs": [], "trackers": [],
                                    "native_libs": [], "sha256": None, "manifest": None}
                if (i + 1) % 25 == 0:
                    console.info(f"APK {i + 1}/{len(todo)}")

    for pkg in sorted(results):
        rep = results[pkg]
        rep["splits"] = [f for f in by_pkg[pkg] if f != todo[pkg]]
        ctx.apk_reports[pkg] = rep
        _merge(ctx, pkg, rep)
    ctx.coverage["apk"] = f"ok – {len(results)} APKs analysed" + (f", {len(by_pkg) - len(todo)} skipped (size)" if len(todo) < len(by_pkg) else "")


def _merge(ctx: Context, pkg: str, rep: dict) -> None:
    """Fill gaps in the inventory from the APK and raise integrity / rule findings."""
    if not rep.get("sha256"):
        return
    p = ctx.packages.get(pkg)
    if p is None:
        p = ctx.packages[pkg] = _empty_record(pkg, rep.get("manifest") or {})
    if p.get("apkSha256") and p["apkSha256"] != rep["sha256"]:
        ctx.add(Finding("apk.mismatch", "HIGH", "SECURITY", "APK in archive differs from the hash recorded on the device",
                        "", pkg, "T1645", "apk"))
    p["apkSha256"] = p.get("apkSha256") or rep["sha256"]
    apk_signers = {c["sha256"] for c in rep["certs"]}
    if not p.get("certSha256") and rep["certs"]:
        p["certSha256"] = sorted(apk_signers)
        p["certSha1"] = sorted({c["sha1"] for c in rep["certs"]})
        p["certSubjects"] = sorted({c["subject"] for c in rep["certs"]})
    elif p.get("certSha256") and apk_signers and not set(p["certSha256"]) & apk_signers:
        ctx.add(Finding("apk.signer.mismatch", "HIGH", "SECURITY", "Signer inside APK ≠ signer reported by the device",
                        "", pkg, "T1645", "apk"))
    if not p.get("components") and rep.get("manifest"):
        p["components"] = rep["manifest"]["components"]
    if not p.get("nativeLibs"):
        p["nativeLibs"] = sorted({n.rsplit("/", 1)[-1] for n in rep["native_libs"]})
    side = ctx.is_sideloaded(pkg)
    for f in rep["findings"]:
        sev = f["severity"]
        # Capability findings matter far more for sideloaded apps: demote them for store/system apps.
        if not side and sev in ("MEDIUM", "LOW") and f["category"] in ("PRIVACY", "SUSPICIOUS"):
            sev = "INFO" if sev == "LOW" else "LOW"
        ctx.add(Finding(f["id"], sev, f["category"], f["title"], "", pkg, f.get("mitre"), "apk", f.get("evidence", [])))
    if rep["trackers"]:
        ctx.add(Finding("apk.trackers", "INFO", "PRIVACY",
                        f"{len(rep['trackers'])} tracker/ads SDKs: {', '.join(rep['trackers'][:8])}", "", pkg, None, "apk"))
