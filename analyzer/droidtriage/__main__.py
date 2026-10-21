"""CLI entry point:  python3 -m droidtriage EVIDENCE [-o OUT] [--vt-key KEY] ..."""
from __future__ import annotations

import argparse
import os
import sys
import tempfile

from . import __version__
from .evidence import Evidence
from .iocs import IocDb, update
from .model import Context
from .pipeline import run_all
from .report import write_all
from .vt import VirusTotal, confirm_upload

TRUSTED = ["com.android.vending", "com.sec.android.app.samsungapps", "com.huawei.appmarket", "com.xiaomi.mipicks",
           "com.xiaomi.market", "com.amazon.venezia", "com.oppo.market", "com.heytap.market", "com.bbk.appstore", "org.fdroid.fdroid"]
HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def compare_baseline(ctx: Context, path: str) -> None:
    import json
    from .model import Finding
    with open(path, encoding="utf-8") as fh:
        prev = json.load(fh)
    old = {x["package"]: x for x in prev.get("apps", [])}
    ctx.prev_keys = {(f["id"], f.get("package"), f["title"]) for f in prev.get("findings", [])}
    for name, p in ctx.packages.items():
        o = old.get(name)
        if o is None:
            ctx.add(Finding("baseline.new", "MEDIUM" if ctx.is_sideloaded(name) else "LOW", "UNKNOWN",
                            f"New since baseline ({prev.get('generated', '?')[:10]})", f"installer {p.get('installer') or 'none/adb'}",
                            name, None, "baseline"))
            continue
        if o.get("signer") and p.get("certSha256") and o["signer"] not in p["certSha256"]:
            ctx.add(Finding("baseline.signer", "CRITICAL", "SECURITY", "Signing certificate changed since baseline",
                            f"{o['signer']} -> {p['certSha256'][0]}", name, "T1645", "baseline"))
        if o.get("sha256") and p.get("apkSha256") and o["sha256"] != p["apkSha256"] and o.get("version") == p.get("versionName"):
            ctx.add(Finding("baseline.binary", "HIGH", "SECURITY", "Same version, different APK hash than baseline", "", name, "T1645", "baseline"))
    for name in set(old) - set(ctx.packages):
        ctx.event(prev.get("generated", ""), "baseline", "app present in baseline is gone", name, "LOW")
    ctx.dedupe()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="droidtriage", description="Offline Android triage of DroidCollector / adb_collect.sh evidence.")
    ap.add_argument("evidence", nargs="?", help="collector .zip or extracted / adb_collect directory")
    ap.add_argument("-o", "--out", help="output directory (default: <evidence>_report)")
    ap.add_argument("--ioc", action="append", default=[], help="extra IOC file or directory (repeatable)")
    ap.add_argument("--update-iocs", action="store_true", help="download public IOC feeds (stalkerware-indicators, MVT) into ./iocs")
    ap.add_argument("--vt-key", default=os.environ.get("VT_API_KEY"), help="VirusTotal API key (or env VT_API_KEY). Hash lookups only.")
    ap.add_argument("--vt-scope", choices=["sideloaded", "user", "all"], default="user", help="which apps to look up (default: user apps)")
    ap.add_argument("--vt-max", type=int, default=200, help="max hash lookups this run (free tier: 500/day)")
    ap.add_argument("--vt-upload", action="append", default=[], metavar="PACKAGE",
                    help="UPLOAD this package's APK to VirusTotal after interactive confirmation")
    ap.add_argument("--yes", action="store_true", help="skip the typed confirmation for --vt-upload (non-interactive use)")
    ap.add_argument("--trusted-installer", action="append", default=[], help="add a trusted installer package")
    ap.add_argument("--baseline", help="previous report.json: flag new/changed apps and mark new findings")
    ap.add_argument("--max-apk-mb", type=int, default=300, help="skip static analysis of APKs larger than this")
    ap.add_argument("--version", action="version", version=f"droidtriage {__version__}")
    a = ap.parse_args(argv)

    ioc_dir = os.path.join(HERE, "iocs")
    if a.update_iocs:
        print(f"Updating IOC feeds into {ioc_dir}")
        update(ioc_dir)
        if not a.evidence:
            return 0
    if not a.evidence:
        ap.error("evidence path required")

    iocs = IocDb()
    for p in [ioc_dir] + a.ioc:
        if os.path.exists(p):
            iocs.load_path(p)
    if not len(iocs):
        print("! No IOC feeds loaded. Run with --update-iocs once for stalkerware/spyware indicators.", file=sys.stderr)

    a.trusted_installers = set(TRUSTED + a.trusted_installer)
    ev = Evidence(a.evidence)
    ctx = Context(ev, iocs, a)
    run_all(ctx)
    if a.baseline:
        compare_baseline(ctx, a.baseline)

    out = a.out or (a.evidence.rstrip("/\\").rsplit(".zip", 1)[0] + "_report")
    data = write_all(ctx, out)

    # Optional, explicit uploads.
    for pkg in a.vt_upload:
        if not a.vt_key:
            print("--vt-upload needs --vt-key", file=sys.stderr)
            break
        apk = f"apks/{pkg}/base.apk"
        if not ev.has(apk):
            print(f"{pkg}: no base.apk in the evidence", file=sys.stderr)
            continue
        if not confirm_upload(f"{pkg} ({ev.size(apk) / 2**20:.1f} MB) sha256={ctx.packages.get(pkg, {}).get('apkSha256')}", a.yes):
            print("Upload cancelled.")
            continue
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, f"{pkg}.apk")
            with open(path, "wb") as fh:
                fh.write(ev.read(apk))
            print("analysis id:", VirusTotal(a.vt_key).upload(path))

    s = data["summary"]
    print("\n" + "=" * 64)
    print(f" Privacy risk {s['privacyRisk']}/100 | Security risk {s['securityRisk']}/100 | Suspicious {s['suspicious']}"
          f" | Unknown binaries {len(s['unknownBinaries'])} | Malware {len(s['malware'])}")
    print(" Findings by severity: " + ", ".join(f"{k} {v}" for k, v in s["bySeverity"].items()))
    for f in [f for f in ctx.findings if f.severity in ("CRITICAL", "HIGH")][:15]:
        print(f"  [{f.severity:8}] {f.package or 'device':40.40} {f.title}")
    print(" Coverage:")
    for k, v in ctx.coverage.items():
        print(f"   {k:12} {v}")
    print(f"\n Report: {os.path.join(out, 'report.html')}")
    print("=" * 64)
    return 2 if s["malware"] else (1 if any(f.severity == "HIGH" for f in ctx.findings) else 0)


if __name__ == "__main__":
    sys.exit(main())
