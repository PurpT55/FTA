"""Logcat analysis: rule-based detections, per-package counters and timeline extraction."""
from __future__ import annotations

import re
from collections import Counter, defaultdict

from .model import Context, Finding

LINE = re.compile(r"^(?P<ts>\d\d-\d\d\s+\d\d:\d\d:\d\d\.\d+)\s+(?:(?P<uid>[a-z_][\w]*|\d+)\s+)?(?P<pid>\d+)\s+(?P<tid>\d+)\s+"
                  r"(?P<lvl>[VDIWEFAS])\s+(?P<tag>[^:]*?)\s*:\s?(?P<msg>.*)$")
PKG_IN = re.compile(r"\b((?:[a-z][a-z0-9_]*\.){1,}[a-z0-9_]+)\b")

# id, tag regex (or None), message regex, severity, category, title, mitre, timeline?
RULES = [
    ("root.su", None, r"(?i)\b(?:magisk|zygisk|supersu|superuser|kernelsu|\bsu\b.*(?:granted|allow|request))", "HIGH", "SECURITY",
     "Root manager / su activity", "T1404", True),
    ("hook.framework", None, r"(?i)\b(?:lsposed|edxposed|xposed|riru|substrate)\b", "HIGH", "SECURITY", "Hooking framework active", "T1625.001", True),
    ("frida", None, r"(?i)frida|gum-js-loop|linjector|re\.frida", "HIGH", "SUSPICIOUS", "Frida instrumentation traces", "T1625.001", True),
    ("dexload.odd", None, r"(?i)(?:dex2oat|DexFile|ClassLoader|odex).*(/sdcard/|/storage/emulated/|/data/local/tmp|/data/(?:data|user/\d+)/[\w.]+/(?:cache|files|app_\w+)/[^ ]+\.(?:dex|jar|apk|zip))",
     "MEDIUM", "SUSPICIOUS", "Code loaded from a writable location (dynamic payload)", "T1407", True),
    ("admin.add", r"DevicePolicyManager|DevicePolicy", r"(?i)(?:setActiveAdmin|Adding admin|admin added|setDeviceOwner|setProfileOwner)", "HIGH", "SECURITY",
     "Device administrator added", "T1626.001", True),
    ("acc.bind", r"Accessibility", r"(?i)(?:bind|enabl|connect)\w*.*?([\w.]+/[\w.$]+)", "LOW", "PRIVACY", "Accessibility service bound/enabled", "T1516", True),
    ("projection", r"MediaProjection", r"(?i)(?:start|createVirtualDisplay|projection)", "MEDIUM", "PRIVACY", "Screen capture session (MediaProjection)", "T1513", True),
    ("camera.open", r"CameraService", r"(?i)connect.*?(?:client|package)[^\w]*([\w.]+)", "INFO", "PRIVACY", "Camera opened", "T1512", True),
    ("mic.record", r"AudioFlinger|AudioPolicy|AudioRecord|APM_AudioPolicyManager", r"(?i)(?:startInput|start recording|AudioRecord.*start|record.*session)",
     "INFO", "PRIVACY", "Microphone recording started", "T1429", True),
    ("sms.send", r"SmsManager|SMSDispatcher|SmsController|GsmSMSDispatcher|ImsSmsDispatcher", r"(?i)send", "MEDIUM", "PRIVACY", "SMS sent programmatically", "T1582", True),
    ("ussd", None, r"(?i)\bussd\b.*(?:send|dial)|sendUssd", "MEDIUM", "SUSPICIOUS", "USSD code sent (balance/forwarding manipulation)", "T1616", True),
    ("call.forward", None, r"(?i)call ?forward|CallForwarding|setCallForwardingOption", "MEDIUM", "SUSPICIOUS", "Call forwarding change", "T1616", True),
    ("cert.install", r"KeyChain|CertInstaller|TrustedCertificateStore|CertificateManager", r"(?i)install|added|import", "HIGH", "SECURITY",
     "CA certificate installed", "T1638", True),
    ("vpn.establish", r"Vpn|VpnService|ConnectivityService", r"(?i)(?:establish|prepare|Switched from|Always-on VPN)", "LOW", "PRIVACY", "VPN session established", "T1638", True),
    ("adb.session", r"adbd|AdbDebuggingManager|adb", r"(?i)(?:connected|authorized|pairing|accept)", "LOW", "SECURITY",
     "ADB connection / pairing (expected if you collected over adb; check other dates)", None, True),
    ("clipboard.bg", r"ClipboardService", r"(?i)Denying clipboard access to ([\w.]+)", "MEDIUM", "PRIVACY", "App tried to read the clipboard in background", "T1414", True),
    ("verifier", r"PackageVerifier|Finsky|PlayProtect|Verifier", r"(?i)(?:harmful|malware|PHA|blocked|disabled)", "HIGH", "MALWARE",
     "Play Protect / verifier warning", "T1629.003", True),
    ("selinux.denied", None, r"avc:\s+denied", "INFO", "SECURITY", "SELinux denials", None, False),
    ("fatal", None, r"FATAL EXCEPTION|Fatal signal \d+|ANR in ", "INFO", "SECURITY", "Crashes / ANRs", None, False),
    ("tombstone", r"DEBUG|tombstoned|crash_dump", r"(?i)Tombstone written|backtrace:|signal \d+ \(SIG", "LOW", "SECURITY", "Native crash dump", None, True),
    ("perm.denial", None, r"Permission Denial", "INFO", "SECURITY", "Permission denials", None, False),
    ("wipe", None, r"(?i)wipeData|factory reset|MasterClear|RecoverySystem.*wipe", "HIGH", "SECURITY", "Wipe / factory reset requested", "T1630", True),
    ("pkg.install", r"PackageManager|PackageInstaller|InstallPackageHelper|PackageInstallerSession", r"(?i)(?:install|commit)\w*.*?([\w]+\.[\w.]+)",
     "INFO", "UNKNOWN", "Package installation", None, True),
    ("component.disable", r"PackageManager", r"(?i)(?:setComponentEnabledSetting|component.*disabled|COMPONENT_ENABLED_STATE_DISABLED)", "LOW", "SUSPICIOUS",
     "Component disabled (possible icon hiding)", "T1628.001", True),
    ("debugger", None, r"(?i)\bJDWP\b|debugger has (?:connected|attached)|Sending WAIT chunk", "MEDIUM", "SECURITY", "Debugger attached to an app", None, True),
]
COMPILED = [(i, re.compile(t) if t else None, re.compile(m), s, c, ti, mi, tl) for i, t, m, s, c, ti, mi, tl in RULES]
START_PROC = re.compile(r"Start proc \d+:([\w.]+)(?::[\w.]+)?/\w+ for (\w[\w\- ]*?) \{?([\w.]+)/")
URL = re.compile(r"https?://([A-Za-z0-9.\-]{3,253})")


def analyse_logs(ctx: Context) -> None:
    files = [n for n in ctx.ev.names("logs/*.txt") + ctx.ev.names("logcat*.txt") if "stats" not in n]
    if not files:
        ctx.coverage["logcat"] = "MISSING – no logcat in the archive"
        return
    total = 0
    uids = set()
    hits: dict[str, dict] = {}
    by_pkg: dict[str, Counter] = defaultdict(Counter)
    starts: dict[str, Counter] = defaultdict(Counter)
    domains: Counter = Counter()
    for name in files:
        for line in ctx.ev.lines(name):
            m = LINE.match(line)
            if not m:
                continue
            total += 1
            uid = m.group("uid")
            if uid:
                uids.add(uid)
            tag, msg = m.group("tag"), m.group("msg")
            for rid, tre, mre, sev, cat, title, mitre, tl in COMPILED:
                if tre and not tre.search(tag):
                    continue
                mm = mre.search(msg) if tre else (mre.search(msg) or mre.search(tag))
                if not mm:
                    continue
                h = hits.setdefault(rid, {"count": 0, "severity": sev, "category": cat, "title": title, "mitre": mitre,
                                          "samples": [], "packages": Counter()})
                h["count"] += 1
                if len(h["samples"]) < 8:
                    h["samples"].append(f"[{name.split('/')[-1]}] {line[:300]}")
                pk = [p for p in PKG_IN.findall(msg) if p in ctx.packages]
                for p in pk[:2]:
                    h["packages"][p] += 1
                    by_pkg[p][rid] += 1
                if tl and h["count"] <= 200:
                    ctx.event(m.group("ts"), f"logcat:{tag.strip()}", f"{title}: {msg[:160]}", pk[0] if pk else None,
                              sev if sev != "INFO" else "INFO")
            sm = START_PROC.search(msg)
            if sm:
                starts[sm.group(1)][sm.group(2).strip()] += 1
            for d in URL.findall(msg):
                domains[d.lower()] += 1
    others = {u for u in uids if u not in ("root", "system", "shell", "logd")}
    if len(others) <= 2:
        ctx.coverage["logcat"] = (f"LIMITED – {total} lines, apparently only the Collector's own logs. "
                                  "Grant READ_LOGS (adb shell pm grant org.droidsuite.collector android.permission.READ_LOGS) and accept the prompt.")
    else:
        ctx.coverage["logcat"] = f"ok – {total} lines from {len(files)} buffers"
    ctx.log_hits = {k: {**v, "packages": dict(v["packages"].most_common(10))} for k, v in hits.items()}

    for rid, h in hits.items():
        if h["severity"] == "INFO":
            continue
        pk = list(h["packages"])
        ctx.add(Finding("log." + rid, h["severity"], h["category"], f"{h['title']} ({h['count']}× in logcat)",
                        "Packages mentioned: " + (", ".join(pk[:5]) or "n/a"), pk[0] if len(pk) == 1 else None,
                        h["mitre"], "logcat", h["samples"][:5]))
    # Background wake-ups of sideloaded/hidden apps
    for pkg, c in starts.items():
        bg = sum(v for k, v in c.items() if k not in ("activity", "top-activity", "pre-top-activity", "next-top-activity"))
        if bg >= 5 and ctx.is_sideloaded(pkg):
            hidden = ctx.packages.get(pkg, {}).get("hasLauncher") is False
            ctx.add(Finding("log.bgstart", "MEDIUM" if hidden else "LOW", "SUSPICIOUS",
                            f"Started {bg}× in background ({', '.join(f'{k}:{v}' for k, v in c.most_common(4))})", "", pkg,
                            "T1624.001", "logcat"))
    # Domains in logs vs IOC
    for d, n in domains.items():
        fam = ctx.iocs.match_domain(d)
        if fam:
            ctx.add(Finding("log.ioc.domain", "CRITICAL", "MALWARE", f"IOC domain in logs: {d} ({fam})", f"{n} occurrences", None, None, "logcat"))
    ctx.network["log_domains"] = dict(domains.most_common(200))
