"""Network evidence: DroidSentinel DNS log/events, per-app traffic volume, hard-coded endpoints."""
from __future__ import annotations

import csv
import io
import math
from collections import Counter, defaultdict

from .model import Context, Finding

DYNDNS = ("duckdns.org", "no-ip.com", "no-ip.org", "ddns.net", "hopto.org", "zapto.org", "sytes.net", "dynu.net",
          "freedns.afraid.org", "mooo.com", "dyndns.org")
TUNNELS = ("ngrok.io", "ngrok-free.app", "ngrok.app", "trycloudflare.com", "serveo.net", "loca.lt", "localtunnel.me", "bore.pub")
EXFIL = ("pastebin.com", "paste.ee", "transfer.sh", "file.io", "webhook.site", "pipedream.net", "requestbin.net")
TRACKERS = ("doubleclick.net", "googlesyndication.com", "app-measurement.com", "graph.facebook.com", "appsflyer.com", "adjust.com",
            "branch.io", "onesignal.com", "applovin.com", "inmobi.com", "chartboost.com", "ironsrc.mobi", "mopub.com", "vungle.com",
            "startappservice.com", "mintegral.com", "pangle.io", "amplitude.com", "mixpanel.com", "segment.io", "kochava.com",
            "flurry.com", "crashlytics.com", "sentry.io", "bugsnag.com")
RISKY_TLDS = {"top", "xyz", "tk", "ml", "ga", "cf", "gq", "click", "zip", "mov", "cyou", "rest", "su", "icu"}
TELEGRAM = {"org.telegram.messenger", "org.telegram.messenger.web", "org.thunderdog.challegram", "org.telegram.plus"}
SEVERE = {"dynamic-dns", "tunnel-service", "telegram-bot-api", "tor", "dga-like", "paste/exfil-service"}


def _under(d, lst):
    return any(d == x or d.endswith("." + x) for x in lst)


def _entropy(s):
    c = Counter(s)
    return -sum(v / len(s) * math.log2(v / len(s)) for v in c.values())


def classify(domain: str, pkg: str, iocs) -> str | None:
    d = domain.lower().rstrip(".")
    fam = iocs.match_domain(d)
    if fam:
        return f"IOC:{fam}"
    if _under(d, DYNDNS):
        return "dynamic-dns"
    if _under(d, TUNNELS):
        return "tunnel-service"
    if _under(d, EXFIL):
        return "paste/exfil-service"
    if d == "api.telegram.org" and pkg not in TELEGRAM:
        return "telegram-bot-api"
    if d.endswith(".onion"):
        return "tor"
    parts = d.split(".")
    label = parts[-2] if len(parts) >= 2 else parts[0]
    if len(label) >= 12 and _entropy(label) > 3.4 and sum(ch in "aeiou" for ch in label) * 5 < len(label):
        return "dga-like"
    if parts[-1] in RISKY_TLDS:
        return "risky-tld"
    if _under(d, TRACKERS):
        return "tracker"
    return None


def analyse_network(ctx: Context) -> None:
    def add(fid, sev, cat, title, pkg=None, detail="", mitre=None, evidence=None, source="network"):
        ctx.add(Finding(fid, sev, cat, title, detail, pkg, mitre, source, evidence or []))

    # ---------------- DroidSentinel report
    rep = ctx.ev.json("sentinel/report.json")
    if not rep:
        rep = next((ctx.ev.json(n) for n in ctx.ev.names("sentinel*.json")), None)
    if rep and "error" not in rep:
        ctx.sentinel = rep
        mon = rep.get("monitor", {})
        dns = mon.get("dns", [])
        ctx.coverage["dns"] = f"ok – {len(dns)} DNS queries from DroidSentinel" if dns else "no DNS log (DNS monitor was not enabled)"
        per_pkg: dict[str, Counter] = defaultdict(Counter)
        flagged = defaultdict(set)
        for r in dns:
            pkg, d = r.get("package", "?"), r.get("domain", "")
            per_pkg[pkg][d] += 1
            flag = classify(d, pkg, ctx.iocs)
            if flag and flag != "tracker":
                flagged[(pkg, flag)].add(d)
        ctx.network["dns_per_app"] = {k: dict(v.most_common(40)) for k, v in per_pkg.items()}
        ctx.network["dns_flagged"] = {f"{k[0]} ⚑ {k[1]}": sorted(v)[:30] for k, v in flagged.items()}
        for (pkg, flag), ds in flagged.items():
            if flag.startswith("IOC:"):
                add("dns.ioc", "CRITICAL", "MALWARE", f"Resolved IOC domain(s) ({flag[4:]})", pkg if "." in pkg else None,
                    ", ".join(sorted(ds)[:10]), "T1437.001", sorted(ds)[:10])
            elif flag in SEVERE:
                add("dns." + flag, "MEDIUM", "SUSPICIOUS", f"DNS: {flag} ({len(ds)} names)", pkg if "." in pkg else None,
                    ", ".join(sorted(ds)[:10]), "T1437.001 / T1481", sorted(ds)[:10])
        for e in mon.get("events", []):
            ctx.event(e.get("ts"), "sentinel", f"{e.get('title')} {e.get('detail', '')[:120]}", e.get("package"), e.get("severity", "INFO"))
            if e.get("severity") in ("HIGH", "CRITICAL") and e.get("type") not in ("finding",):
                add("sentinel." + e.get("type", "event"), e["severity"], e.get("category", "SUSPICIOUS"),
                    f"DroidSentinel alert: {e.get('title')}", e.get("package"), e.get("detail", ""), source="sentinel")
        for v in mon.get("virustotal", []):
            if v.get("sha256") and v["sha256"] not in ctx.vt and v.get("positives", -1) >= 0:
                ctx.vt[v["sha256"]] = {"malicious": v["positives"], "total": v.get("total", 0), "label": v.get("label"), "source": "sentinel"}
        ctx.network["sentinel_traffic"] = mon.get("traffic", {})
    else:
        ctx.coverage["dns"] = "MISSING – install DroidSentinel and enable the DNS monitor for per-app domain logs"

    # ---------------- per-app traffic volume (NetworkStats)
    tsv = ctx.ev.text("usage/netstats_uid.tsv")
    vol: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    if tsv:
        for row in csv.DictReader(io.StringIO(tsv), delimiter="\t"):
            for p in (row.get("packages") or f"uid:{row.get('uid')}").split("|"):
                vol[p][0] += int(row.get("rxBytes") or 0)
                vol[p][1] += int(row.get("txBytes") or 0)
        ctx.coverage["traffic"] = f"ok – {len(vol)} apps with traffic (30 days)"
    else:
        ctx.coverage["traffic"] = "MISSING – give the Collector Usage access"
    ctx.network["volume"] = dict(sorted(vol.items(), key=lambda kv: -kv[1][1])[:60])

    # foreground usage (to spot apps that transmit but are never opened)
    fg = Counter()
    ut = ctx.ev.text("usage/usage_daily.tsv")
    for row in csv.DictReader(io.StringIO(ut), delimiter="\t") if ut else []:
        try:
            fg[row["package"]] += int(row.get("foregroundMs") or 0)
        except (KeyError, ValueError):
            pass
    for pkg, (rx, tx) in vol.items():
        p = ctx.packages.get(pkg)
        if not p or p.get("system"):
            continue
        if tx > 5 * 2**20 and ut and fg.get(pkg, 0) == 0:
            add("net.unused.tx", "HIGH" if ctx.is_sideloaded(pkg) else "MEDIUM", "SUSPICIOUS",
                f"Uploaded {tx / 2**20:.1f} MB in 30 days but was never in the foreground (7-day usage)", pkg, mitre="T1646")
        elif p.get("hasLauncher") is False and tx > 2**20:
            add("net.hidden.tx", "HIGH", "SUSPICIOUS", f"Hidden app uploaded {tx / 2**20:.1f} MB", pkg, mitre="T1646")

    # ---------------- endpoints hard-coded in APKs vs IOC
    for pkg, r in ctx.apk_reports.items():
        for h in r.get("hosts", []):
            fam = ctx.iocs.match_domain(h)
            if fam:
                add("apk.ioc.domain", "CRITICAL", "MALWARE", f"APK embeds IOC domain {h} ({fam})", pkg, mitre="T1437.001")
            else:
                flag = classify(h, pkg, ctx.iocs)
                if flag in SEVERE:
                    add("apk.domain." + flag, "MEDIUM", "SUSPICIOUS", f"APK embeds {flag} endpoint {h}", pkg, mitre="T1437.001")
        for ip in r.get("ips", []):
            if ip in ctx.iocs.ips:
                add("apk.ioc.ip", "CRITICAL", "MALWARE", f"APK embeds IOC IP {ip} ({ctx.iocs.ips[ip]})", pkg)
