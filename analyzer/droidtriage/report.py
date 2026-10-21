"""Report writers: HTML dashboard, JSON, CSV.

``report.json`` is the canonical output (``schemaVersion`` is bumped on breaking changes); the HTML
dashboard is ``templates/report.html`` with the JSON embedded, so it works offline as a single file.
"""
from __future__ import annotations

import csv
import html
import json
import os
from datetime import datetime

SCHEMA_VERSION = 2
FORMATS = ("html", "json", "csv")
TEMPLATE_PATH = os.path.join(os.path.dirname(__file__), "templates", "report.html")

from . import __version__
from .model import SEVERITIES, WEIGHT, Context
from .playbook import advice


def summary(ctx: Context) -> dict:
    """The five dashboard numbers (same definitions as the DroidSentinel app) + counts by severity."""
    user = [s["privacy"] for n, s in ctx.scores.items() if not ctx.packages.get(n, {}).get("system")]
    top = sorted(user, reverse=True)[:10]
    privacy = int(0.6 * top[0] + 0.4 * sum(top) / len(top)) if top else 0
    sec = min(100, sum(WEIGHT[f.severity] for f in ctx.findings if f.category in ("SECURITY", "MALWARE")))
    return {
        "privacyRisk": min(privacy, 100),
        "securityRisk": sec,
        "suspicious": sum(1 for f in ctx.findings if f.category == "SUSPICIOUS" and f.severity in ("MEDIUM", "HIGH", "CRITICAL")),
        "unknownBinaries": ctx.unknown,
        "malware": sorted({f.package or "(device)" for f in ctx.findings if f.category == "MALWARE"}),
        "bySeverity": {s: sum(1 for f in ctx.findings if f.severity == s) for s in SEVERITIES},
    }


def to_json(ctx: Context) -> dict:
    """Build the full report document (see SCHEMA_VERSION)."""
    manifest = ctx.ev.json("manifest.json", {}) or {}
    apps = []
    for n, p in sorted(ctx.packages.items()):
        r = ctx.apk_reports.get(n, {})
        v = ctx.vt.get(p.get("apkSha256") or "")
        apps.append({
            "package": n, "label": p.get("label"), "version": p.get("versionName"), "installer": p.get("installer"),
            "system": p.get("system"), "sideloaded": ctx.is_sideloaded(n), "launcher": p.get("hasLauncher"),
            "firstInstall": p.get("firstInstall"), "lastUpdate": p.get("lastUpdate"), "sha256": p.get("apkSha256"),
            "signer": (p.get("certSha256") or [None])[0], "signerSubject": (p.get("certSubjects") or [None])[0],
            "privacy": ctx.scores.get(n, {}).get("privacy", 0), "security": ctx.scores.get(n, {}).get("security", 0),
            "vt": None if not v else (f"{v['malicious']}/{v['total']}" if v["malicious"] >= 0 else "unknown"),
            "vtLabel": v.get("label") if v else None,
            "granted": sorted(x.rsplit(".", 1)[-1] for x in p.get("granted", []) if x.startswith("android.permission.")),
            "trackers": r.get("trackers", []), "hosts": r.get("hosts", [])[:40], "payloads": r.get("payloads", []),
            "dns": (ctx.network.get("dns_per_app") or {}).get(n, {}),
        })
    findings = []
    for f in ctx.findings:
        d = f.to_dict()
        d["advice"] = advice(f.id)
        prev = getattr(ctx, "prev_keys", None)
        d["new"] = prev is not None and f.key() not in prev
        findings.append(d)
    tl = sorted((e.__dict__ for e in ctx.timeline), key=lambda e: e["ts"], reverse=True)[:3000]
    return {
        "tool": "droidtriage", "version": __version__, "schemaVersion": SCHEMA_VERSION, "timings": ctx.timings, "generated": datetime.now().isoformat(timespec="seconds"),
        "evidence": os.path.basename(ctx.ev.path), "collection": {k: manifest.get(k) for k in ("device", "startedAt", "capabilities", "sections")},
        "summary": summary(ctx), "coverage": ctx.coverage, "findings": findings, "apps": apps, "timeline": tl,
        "device": {k: v for k, v in ctx.device.items() if k not in ("settings",)},
        "enabled": {k: (sorted(v) if isinstance(v, set) else v) for k, v in ctx.enabled.items()},
        "network": ctx.network, "logHits": ctx.log_hits,
        "iocSources": ctx.iocs.sources, "iocCount": len(ctx.iocs),
    }


def write_all(ctx: Context, out_dir: str, formats=FORMATS) -> dict:
    """Write the requested formats into ``out_dir`` and return the report document."""
    os.makedirs(out_dir, exist_ok=True)
    data = to_json(ctx)
    if "json" in formats:
        with open(os.path.join(out_dir, "report.json"), "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=1, default=str)
    if "csv" in formats:
        _write_csv(data, out_dir)
    if "html" in formats:
        write_html(data, os.path.join(out_dir, "report.html"))
    return data


def write_html(data: dict, path: str) -> None:
    """Embed the report JSON in the single-file dashboard template."""
    with open(TEMPLATE_PATH, encoding="utf-8") as fh:
        tpl = fh.read()
    payload = json.dumps(data, default=str).replace("</", "<\\/")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(tpl.replace("__TITLE__", html.escape(data["collection"].get("device") or data["evidence"])).replace("__DATA__", payload))


def _write_csv(data: dict, out_dir: str) -> None:
    with open(os.path.join(out_dir, "findings.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["severity", "category", "package", "title", "detail", "mitre", "source", "advice"])
        for f in data["findings"]:
            w.writerow([f["severity"], f["category"], f["package"] or "", f["title"], f["detail"], f["mitre"] or "", f["source"], f["advice"]])
    with open(os.path.join(out_dir, "apps.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        cols = ["package", "label", "version", "installer", "system", "sideloaded", "launcher", "firstInstall", "privacy", "security", "vt", "sha256", "signer"]
        w.writerow(cols)
        for a in data["apps"]:
            w.writerow([a.get(c) for c in cols])
    with open(os.path.join(out_dir, "timeline.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["ts", "severity", "source", "package", "what"])
        for e in data["timeline"]:
            w.writerow([e["ts"], e["severity"], e["source"], e["package"] or "", e["what"]])
