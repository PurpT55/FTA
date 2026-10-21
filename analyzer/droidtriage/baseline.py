"""Compare an analysis with a previous ``report.json`` (``--baseline`` / ``droidtriage diff``)."""
from __future__ import annotations

import json

from .model import Context, Finding


def compare(ctx: Context, path: str) -> None:
    """Add findings for new apps / signer or binary changes and remember previous finding keys
    (the report marks findings that were not in the baseline as NEW)."""
    with open(path, encoding="utf-8") as fh:
        prev = json.load(fh)
    old = {x["package"]: x for x in prev.get("apps", [])}
    ctx.prev_keys = {(f["id"], f.get("package"), f["title"]) for f in prev.get("findings", [])}
    when = (prev.get("generated") or "?")[:10]
    for name, p in ctx.packages.items():
        o = old.get(name)
        if o is None:
            ctx.add(Finding("baseline.new", "MEDIUM" if ctx.is_sideloaded(name) else "LOW", "UNKNOWN",
                            f"New since baseline ({when})", f"installer {p.get('installer') or 'none/adb'}", name, None, "baseline"))
            continue
        if o.get("signer") and p.get("certSha256") and o["signer"] not in p["certSha256"]:
            ctx.add(Finding("baseline.signer", "CRITICAL", "SECURITY", "Signing certificate changed since baseline",
                            f"{o['signer']} -> {p['certSha256'][0]}", name, "T1645", "baseline"))
        if o.get("sha256") and p.get("apkSha256") and o["sha256"] != p["apkSha256"] and o.get("version") == p.get("versionName"):
            ctx.add(Finding("baseline.binary", "HIGH", "SECURITY", "Same version, different APK hash than baseline",
                            "", name, "T1645", "baseline"))
    for name in set(old) - set(ctx.packages):
        ctx.event(prev.get("generated", ""), "baseline", "app present in baseline is gone", name, "LOW")
    ctx.dedupe()


def diff_reports(old: dict, new: dict) -> dict:
    """Pure report-to-report diff used by ``droidtriage diff``."""
    oa = {a["package"]: a for a in old.get("apps", [])}
    na = {a["package"]: a for a in new.get("apps", [])}
    ok = {(f["id"], f.get("package"), f["title"]) for f in old.get("findings", [])}
    nk = {(f["id"], f.get("package"), f["title"]) for f in new.get("findings", [])}
    changed = []
    for p in sorted(set(oa) & set(na)):
        a, b = oa[p], na[p]
        delta = {k: (a.get(k), b.get(k)) for k in ("version", "installer", "sha256", "signer", "launcher") if a.get(k) != b.get(k)}
        if delta:
            changed.append({"package": p, "changes": delta})
    return {
        "apps_added": sorted(set(na) - set(oa)),
        "apps_removed": sorted(set(oa) - set(na)),
        "apps_changed": changed,
        "findings_new": [f for f in new.get("findings", []) if (f["id"], f.get("package"), f["title"]) in nk - ok],
        "findings_gone": [f for f in old.get("findings", []) if (f["id"], f.get("package"), f["title"]) in ok - nk],
        "scores": {k: (old.get("summary", {}).get(k), new.get("summary", {}).get(k)) for k in ("privacyRisk", "securityRisk", "suspicious")},
    }
