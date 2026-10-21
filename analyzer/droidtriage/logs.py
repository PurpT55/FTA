"""Logcat analysis: rule-based detections, per-package counters and timeline extraction.

Rules are data (:data:`RULES`). Each rule has an optional *tag* regex (matched against the logcat
tag, case-sensitive) and a *message* regex (case-insensitive). Rules without a tag regex are tested
against message and tag.

Performance: logcat exports reach millions of lines, so the scan uses two combined pre-filter
regexes (all untagged message patterns / all tag patterns). A line that passes neither, and contains
neither "Start proc" nor "://", is never fully parsed. On a 300k-line file this is ~5x faster than
testing every rule on every line.

Adding a rule: append a :class:`LogRule` to ``RULES`` (keep ids unique, prefix ``log.`` is added
automatically) and add a line to ``tests/fixtures`` + an assertion in ``tests/test_logs.py``.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass

from .model import Context, Finding
from .registry import analyzer

LINE = re.compile(r"^(?P<ts>\d\d-\d\d\s+\d\d:\d\d:\d\d\.\d+)\s+(?:(?P<uid>[a-z_][\w]*|\d+)\s+)?(?P<pid>\d+)\s+(?P<tid>\d+)\s+"
                  r"(?P<lvl>[VDIWEFAS])\s+(?P<tag>[^:]*?)\s*:\s?(?P<msg>.*)$")
PKG_IN = re.compile(r"\b((?:[a-z][a-z0-9_]*\.){1,}[a-z0-9_]+)\b")
START_PROC = re.compile(r"Start proc \d+:([\w.]+)(?::[\w.]+)?/\w+ for (\w[\w\- ]*?) \{?([\w.]+)/")
URL = re.compile(r"https?://([A-Za-z0-9.\-]{3,253})")
#: activity-type process starts are user driven; everything else counts as a background wake-up
FOREGROUND_STARTS = {"activity", "top-activity", "pre-top-activity", "next-top-activity"}


@dataclass(frozen=True)
class LogRule:
    """One logcat detection rule (see module docstring)."""
    id: str
    tag: str | None          # regex on the logcat tag (None = any tag)
    msg: str                 # regex on the message (case-insensitive)
    severity: str
    category: str
    title: str
    mitre: str | None
    timeline: bool           # copy matching lines into the timeline (first 200)
    keys: tuple = ()         # lowercase literals; a line must contain one of them to be tested.
                             # Required for rules without a tag regex; derived from the tag otherwise.


RULES: list[LogRule] = [LogRule(*r) for r in [
    ("root.su", None, r"\b(?:magisk|zygisk|supersu|superuser|kernelsu|\bsu\b.*(?:granted|allow|request))", "HIGH", "SECURITY",
     "Root manager / su activity", "T1404", True, ("magisk", "zygisk", "supersu", "superuser", "kernelsu", "su:", " su ", "/su")),
    ("hook.framework", None, r"\b(?:lsposed|edxposed|xposed|riru|substrate)\b", "HIGH", "SECURITY", "Hooking framework active", "T1625.001", True, ("xposed", "riru", "substrate")),
    ("frida", None, r"frida|gum-js-loop|linjector|re\.frida", "HIGH", "SUSPICIOUS", "Frida instrumentation traces", "T1625.001", True, ("frida", "gum-js-loop", "linjector")),
    ("dexload.odd", None, r"(?:dex2oat|DexFile|ClassLoader|odex).*(/sdcard/|/storage/emulated/|/data/local/tmp|/data/(?:data|user/\d+)/[\w.]+/(?:cache|files|app_\w+)/[^ ]+\.(?:dex|jar|apk|zip))",
     "MEDIUM", "SUSPICIOUS", "Code loaded from a writable location (dynamic payload)", "T1407", True, ("dex2oat", "dexfile", "classloader", "odex")),
    ("admin.add", r"DevicePolicyManager|DevicePolicy", r"(?:setActiveAdmin|Adding admin|admin added|setDeviceOwner|setProfileOwner)", "HIGH", "SECURITY",
     "Device administrator added", "T1626.001", True),
    ("acc.bind", r"Accessibility", r"(?:bind|enabl|connect)\w*.*?([\w.]+/[\w.$]+)", "LOW", "PRIVACY", "Accessibility service bound/enabled", "T1516", True),
    ("projection", r"MediaProjection", r"(?:start|createVirtualDisplay|projection)", "MEDIUM", "PRIVACY", "Screen capture session (MediaProjection)", "T1513", True),
    ("camera.open", r"CameraService", r"connect.*?(?:client|package)[^\w]*([\w.]+)", "INFO", "PRIVACY", "Camera opened", "T1512", True),
    ("mic.record", r"AudioFlinger|AudioPolicy|AudioRecord|APM_AudioPolicyManager", r"(?:startInput|start recording|AudioRecord.*start|record.*session)",
     "INFO", "PRIVACY", "Microphone recording started", "T1429", True),
    ("sms.send", r"SmsManager|SMSDispatcher|SmsController|GsmSMSDispatcher|ImsSmsDispatcher", r"send", "MEDIUM", "PRIVACY", "SMS sent programmatically", "T1582", True),
    ("ussd", None, r"\bussd\b.*(?:send|dial)|sendUssd", "MEDIUM", "SUSPICIOUS", "USSD code sent (balance/forwarding manipulation)", "T1616", True, ("ussd",)),
    ("call.forward", None, r"call ?forward|CallForwarding|setCallForwardingOption", "MEDIUM", "SUSPICIOUS", "Call forwarding change", "T1616", True, ("forward",)),
    ("cert.install", r"KeyChain|CertInstaller|TrustedCertificateStore|CertificateManager", r"install|added|import", "HIGH", "SECURITY",
     "CA certificate installed", "T1638", True),
    ("vpn.establish", r"Vpn|VpnService|ConnectivityService", r"(?:establish|prepare|Switched from|Always-on VPN)", "LOW", "PRIVACY", "VPN session established", "T1638", True),
    ("adb.session", r"adbd|AdbDebuggingManager|adb", r"(?:connected|authorized|pairing|accept)", "LOW", "SECURITY",
     "ADB connection / pairing (expected if you collected over adb; check other dates)", None, True),
    ("clipboard.bg", r"ClipboardService", r"Denying clipboard access to ([\w.]+)", "MEDIUM", "PRIVACY", "App tried to read the clipboard in background", "T1414", True),
    ("verifier", r"PackageVerifier|Finsky|PlayProtect|Verifier", r"(?:harmful|malware|PHA|blocked|disabled)", "HIGH", "MALWARE",
     "Play Protect / verifier warning", "T1629.003", True),
    ("selinux.denied", None, r"avc:\s+denied", "INFO", "SECURITY", "SELinux denials", None, False, ("avc:",)),
    ("fatal", None, r"FATAL EXCEPTION|Fatal signal \d+|ANR in ", "INFO", "SECURITY", "Crashes / ANRs", None, False, ("fatal exception", "fatal signal", "anr in ")),
    ("tombstone", r"DEBUG|tombstoned|crash_dump", r"Tombstone written|backtrace:|signal \d+ \(SIG", "LOW", "SECURITY", "Native crash dump", None, True),
    ("perm.denial", None, r"Permission Denial", "INFO", "SECURITY", "Permission denials", None, False, ("permission denial",)),
    ("wipe", None, r"wipeData|factory reset|MasterClear|RecoverySystem.*wipe", "HIGH", "SECURITY", "Wipe / factory reset requested", "T1630", True, ("wipe", "factory reset", "masterclear")),
    ("pkg.install", r"PackageManager|PackageInstaller|InstallPackageHelper|PackageInstallerSession", r"(?:install|commit)\w*.*?([\w]+\.[\w.]+)",
     "INFO", "UNKNOWN", "Package installation", None, True),
    ("component.disable", r"PackageManager", r"(?:setComponentEnabledSetting|component.*disabled|COMPONENT_ENABLED_STATE_DISABLED)", "LOW", "SUSPICIOUS",
     "Component disabled (possible icon hiding)", "T1628.001", True),
    ("debugger", None, r"\bJDWP\b|debugger has (?:connected|attached)|Sending WAIT chunk", "MEDIUM", "SECURITY", "Debugger attached to an app", None, True, ("jdwp", "debugger has", "sending wait chunk")),
]]


def _compile(rules):
    """Pre-compile rules and collect the keyword pre-filter (substring tests are far cheaper than regex)."""
    keys = {"start proc", "://"}
    for r in rules:
        if r.keys:
            keys.update(r.keys)
        elif r.tag:
            keys.update(k.lower() for k in r.tag.split("|"))     # tag regexes are literal alternations
        else:
            raise ValueError(f"log rule {r.id}: untagged rules need keys")
    comp = [(r, re.compile(r.tag) if r.tag else None, re.compile(r.msg, re.I)) for r in rules]
    return comp, tuple(sorted(keys))


COMPILED, KEYWORDS = _compile(RULES)


@analyzer("logcat", 70, "Logcat", "rule-based detections, background starts, domains in logs")
def analyse_logs(ctx: Context) -> None:
    """Stream every logcat file once and apply ``RULES``."""
    files = [n for n in ctx.ev.names("logs/*.txt") + ctx.ev.names("logcat*.txt") if "stats" not in n]
    if not files:
        ctx.coverage["logcat"] = "MISSING – no logcat in the archive"
        return
    total = 0
    uids: set[str] = set()
    hits: dict[str, dict] = {}
    starts: dict[str, Counter] = defaultdict(Counter)
    domains: Counter = Counter()
    for name in files:
        short = name.split("/")[-1]
        for line in ctx.ev.lines(name):
            total += 1
            # Cheap rejection before the full LINE parse (most lines match nothing).
            if len(uids) < 50:             # distinct writers -> coverage verdict (cheap token split)
                parts = line.split(None, 3)
                if len(parts) > 2:
                    uids.add(parts[2])
            low = line.lower()
            if not any(k in low for k in KEYWORDS):
                continue
            m = LINE.match(line)
            if not m:
                continue
            tag, msg = m.group("tag"), m.group("msg")
            for rule, tre, mre in COMPILED:
                if tre is not None:
                    if not tre.search(tag) or not mre.search(msg):
                        continue
                elif not (mre.search(msg) or mre.search(tag)):
                    continue
                _record(ctx, hits, rule, short, line, m.group("ts"), tag, msg)
            if "Start proc" in msg:
                sm = START_PROC.search(msg)
                if sm:
                    starts[sm.group(1)][sm.group(2).strip()] += 1
            if "://" in msg:
                for d in URL.findall(msg):
                    domains[d.lower()] += 1
    others = {u for u in uids if u not in ("root", "system", "shell", "logd") and not u.isdigit()}
    caps = (ctx.ev.json("manifest.json", {}) or {}).get("capabilities") or {}
    if caps.get("READ_LOGS") is False or (total > 200 and len(others) <= 2):
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
        bg = sum(v for k, v in c.items() if k not in FOREGROUND_STARTS)
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


def _record(ctx: Context, hits: dict, rule: LogRule, file: str, line: str, ts: str, tag: str, msg: str) -> None:
    """Count a rule hit, keep a few samples, attribute packages, copy to the timeline."""
    h = hits.get(rule.id)
    if h is None:
        h = hits[rule.id] = {"count": 0, "severity": rule.severity, "category": rule.category, "title": rule.title,
                             "mitre": rule.mitre, "samples": [], "packages": Counter()}
    h["count"] += 1
    if len(h["samples"]) < 8:
        h["samples"].append(f"[{file}] {line[:300]}")
    pk = [p for p in PKG_IN.findall(msg) if p in ctx.packages][:2]
    for p in pk:
        h["packages"][p] += 1
    if rule.timeline and h["count"] <= 200:
        ctx.event(ts, f"logcat:{tag.strip()}", f"{rule.title}: {msg[:160]}", pk[0] if pk else None, rule.severity)
