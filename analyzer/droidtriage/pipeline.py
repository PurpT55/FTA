"""Runs all analysers in dependency order."""
from __future__ import annotations

import hashlib
import sys

from . import apk as apkmod
from .logs import analyse_logs
from .model import Context, Finding
from .network import analyse_network
from .packages import analyse_packages, load_packages, scores
from .system import analyse_device, analyse_dumpsys
from .vt import VirusTotal


def log(msg):
    print(msg, file=sys.stderr, flush=True)


def analyse_apks(ctx: Context) -> None:
    apks = [n for n in ctx.ev.names("apks/*/*.apk")]
    if not apks:
        ctx.coverage["apk_static"] = "MISSING – no APK files in the archive"
        return
    by_pkg: dict[str, list[str]] = {}
    for n in apks:
        by_pkg.setdefault(n.split("/")[1], []).append(n)
    limit = ctx.opt.max_apk_mb * 2**20
    done = 0
    for i, (pkg, files) in enumerate(sorted(by_pkg.items())):
        base = next((f for f in files if f.endswith("/base.apk")), files[0])
        if ctx.ev.size(base) > limit:
            ctx.apk_reports[pkg] = {"skipped": f"larger than {ctx.opt.max_apk_mb} MB"}
            continue
        if i % 25 == 0:
            log(f"  static analysis {i + 1}/{len(by_pkg)} …")
        data = ctx.ev.read(base)
        rep = apkmod.analyse_apk(data, base)
        rep["splits"] = [f for f in files if f != base]
        ctx.apk_reports[pkg] = rep
        done += 1
        p = ctx.packages.get(pkg)
        if p is None:
            m = rep.get("manifest") or {}
            p = ctx.packages[pkg] = {"package": pkg, "label": pkg, "requested": m.get("permissions", []), "granted": set(),
                                     "components": [], "certSha256": [], "certSha1": [], "certSubjects": [], "nativeLibs": [],
                                     "hasLauncher": None, "system": False, "updatedSystem": False, "debuggable": False, "installer": None}
        if p.get("apkSha256") and p["apkSha256"] != rep["sha256"]:
            ctx.add(Finding("apk.mismatch", "HIGH", "SECURITY", "APK in archive differs from the hash recorded on the device", "", pkg,
                            "T1645", "apk"))
        p["apkSha256"] = p.get("apkSha256") or rep["sha256"]
        if not p.get("certSha256") and rep["certs"]:
            p["certSha256"] = sorted({c["sha256"] for c in rep["certs"]})
            p["certSha1"] = sorted({c["sha1"] for c in rep["certs"]})
            p["certSubjects"] = sorted({c["subject"] for c in rep["certs"]})
        if not p.get("components") and rep.get("manifest"):
            p["components"] = rep["manifest"]["components"]
        if not p.get("nativeLibs"):
            p["nativeLibs"] = sorted({n.rsplit("/", 1)[-1] for n in rep["native_libs"]})
        # On-device signer must equal the signer inside the APK we pulled
        if p.get("certSha256") and rep["certs"] and not set(p["certSha256"]) & {c["sha256"] for c in rep["certs"]}:
            ctx.add(Finding("apk.signer.mismatch", "HIGH", "SECURITY", "Signer inside APK ≠ signer reported by the device", "", pkg, None, "apk"))
        for f in rep["findings"]:
            sev = f["severity"]
            # Capability findings matter far more for sideloaded apps.
            if not ctx.is_sideloaded(pkg) and sev in ("MEDIUM", "LOW") and f["category"] in ("PRIVACY", "SUSPICIOUS"):
                sev = "INFO" if sev == "LOW" else "LOW"
            ctx.add(Finding(f["id"], sev, f["category"], f["title"], "", pkg, f.get("mitre"), "apk", f.get("evidence", [])))
        if rep["trackers"]:
            ctx.add(Finding("apk.trackers", "INFO", "PRIVACY", f"{len(rep['trackers'])} tracker/ads SDKs: {', '.join(rep['trackers'][:8])}",
                            "", pkg, None, "apk"))
    ctx.coverage["apk_static"] = f"ok – {done} APKs analysed"


def run_vt(ctx: Context) -> None:
    # Reuse verdicts DroidSentinel already obtained on the phone.
    rep = ctx.ev.json("sentinel/report.json") or {}
    for v in (rep.get("monitor") or {}).get("virustotal", []):
        if v.get("sha256") and v.get("positives", -1) >= 0:
            ctx.vt[v["sha256"]] = {"malicious": v["positives"], "total": v.get("total", 0), "label": v.get("label"), "source": "sentinel"}
    if not ctx.opt.vt_key:
        ctx.coverage["virustotal"] = "skipped – no API key (--vt-key or VT_API_KEY)"
        return
    vt = VirusTotal(ctx.opt.vt_key)
    todo = []
    for name, p in ctx.packages.items():
        h = p.get("apkSha256")
        if not h:
            continue
        side = ctx.is_sideloaded(name)
        if ctx.opt.vt_scope == "all" or (ctx.opt.vt_scope == "user" and not p.get("system")) or side:
            todo.append((0 if side else 1, name, h))
    todo.sort()
    todo = todo[: ctx.opt.vt_max]
    log(f"VirusTotal: looking up {len(todo)} hashes (≈{len(todo) * 16 // 60 + 1} min max on the free tier; cached results are instant)")
    n = 0
    try:
        for _, name, h in todo:
            r = vt.lookup(h)
            if r:
                ctx.vt[h] = r
                n += 1
    except RuntimeError as e:
        log(f"VirusTotal stopped: {e}")
    ctx.coverage["virustotal"] = f"ok – {n} hashes looked up (hash only, nothing uploaded)"


def run_all(ctx: Context) -> None:
    log("[1/7] package inventory");     load_packages(ctx)
    log("[2/7] APK static analysis");   analyse_apks(ctx)
    log("[3/7] VirusTotal");            run_vt(ctx)
    log("[4/7] device posture");        analyse_device(ctx)
    log("[5/7] dumpsys");               analyse_dumpsys(ctx)
    log("[6/7] package rules + logcat"); analyse_packages(ctx); analyse_logs(ctx)
    log("[7/7] network");               analyse_network(ctx)
    # unknown binaries: sideloaded and not known to VirusTotal (or not checked)
    from .packages import OWN
    ctx.unknown = sorted(n for n, p in ctx.packages.items()
                         if n not in OWN and ctx.is_sideloaded(n) and (ctx.vt.get(p.get("apkSha256") or "", {}).get("malicious", -1) < 0))
    ctx.dedupe()
    ctx.scores = scores(ctx)
