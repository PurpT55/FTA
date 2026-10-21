"""Synthetic DroidCollector archive with planted indicators, for the demo and the test-suite.

    droidtriage sample demo.zip [--apk some-real.apk]
    droidtriage analyze demo.zip

Planted: a known stalkerware package (from the public stalkerware-indicators list) that is hidden,
has accessibility + device admin + overlay and uploads while never opened; a fake "Google Update"
with a vendor-like package name and a StrandHogg task affinity; a platform-key-signed user app;
a packer library; root/Frida/clipboard lines in logcat; background mic use in appops; Sentinel DNS
lookups of an IOC domain and the Telegram Bot API. If ``--apk`` is given, that (real) APK is embedded
as ``com.example.flashlight`` so static analysis runs too.
"""
from __future__ import annotations

import hashlib
import json
import time
import zipfile

NOW = time.time()  # evaluated at import; the sample is always 'recent'


def iso(t):
    """Epoch seconds -> ISO-8601 UTC."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def app(pkg, label, installer, system=False, launcher=True, granted=(), requested=(), cert="aa" * 32, sha=None,
        first=NOW - 400 * 86400, comps=(), libs=()):
    """One packages.json record with sensible defaults."""
    return {"package": pkg, "label": label, "uid": 10000 + abs(hash(pkg)) % 9000, "versionCode": 1, "versionName": "1.0",
            "installer": installer, "firstInstallTime": iso(first), "lastUpdateTime": iso(first), "system": system,
            "updatedSystem": False, "enabled": True, "hasLauncher": launcher, "debuggable": False, "cleartextTraffic": False,
            "targetSdk": 33, "sharedUserId": None, "apkPaths": [f"/data/app/{pkg}/base.apk"], "apkSize": 1000,
            "apkSha256": sha or hashlib.sha256(pkg.encode()).hexdigest(), "certSha256": [cert],
            "certSha1": [hashlib.sha1(cert.encode()).hexdigest()], "certSubjects": ["CN=Test"], "certHistorySha256": [],
            "requestedPermissions": list(set(requested) | set(granted)), "grantedPermissions": list(granted),
            "components": list(comps), "nativeLibs": list(libs)}


P = "android.permission."
SPY = [P + x for x in ("ACCESS_FINE_LOCATION", "ACCESS_BACKGROUND_LOCATION", "RECORD_AUDIO", "READ_SMS", "SEND_SMS",
                       "READ_CALL_LOG", "READ_CONTACTS", "CAMERA", "RECEIVE_BOOT_COMPLETED")]


def build(out: str, apk_path: str | None = None) -> str:
    """Write the synthetic archive to ``out`` and return the path."""
    apk_bytes = open(apk_path, "rb").read() if apk_path else None
    platform = "pp" * 32
    t_side = NOW - 5 * 86400
    apps = [
        app("android", "Android System", None, system=True, launcher=False, cert=platform),
        app("com.android.vending", "Google Play Store", None, system=True),
        app("com.whatsapp", "WhatsApp", "com.android.vending", granted=[P + "CAMERA", P + "RECORD_AUDIO", P + "READ_CONTACTS"]),
        # TheTruthSpy package name from the public stalkerware-indicators list
        app("com.systemservice", "System Service", "com.google.android.packageinstaller", launcher=False, granted=SPY, first=t_side,
            comps=[{"type": "service", "name": "com.systemservice.Acc", "exported": True,
                    "permission": "android.permission.BIND_ACCESSIBILITY_SERVICE"}]),
        app("com.google.android.update.service", "Google Update", None, granted=[P + "READ_SMS", P + "SEND_SMS"], first=t_side + 300,
            comps=[{"type": "activity", "name": "x.Login", "exported": True, "taskAffinity": "com.whatsapp", "launchMode": 0,
                    "allowTaskReparenting": True}]),
        app("com.evil.platform", "Battery Saver", None, cert=platform, first=t_side + 600),
        app("com.example.flashlight", "Flashlight", "com.google.android.packageinstaller",
            sha=hashlib.sha256(apk_bytes).hexdigest() if apk_bytes else None, libs=["libjiagu.so"]),
        app("org.droidsuite.sentinel", "DroidSentinel", None),
    ]
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("manifest.json", json.dumps({"tool": "DroidCollector", "device": "Synthetic Pixel (Android 14, API 34)",
                                                "startedAt": iso(NOW), "capabilities": {"READ_LOGS": True, "DUMP": True}}))
        z.writestr("device/getprop.txt", "\n".join(f"[{k}]: [{v}]" for k, v in {
            "ro.build.version.sdk": "34", "ro.build.version.release": "14", "ro.build.version.security_patch": "2025-01-05",
            "ro.build.tags": "release-keys", "ro.build.type": "user", "ro.boot.verifiedbootstate": "green",
            "ro.boot.flash.locked": "1", "ro.product.model": "Pixel 7", "ro.product.manufacturer": "Google",
            "ro.crypto.state": "encrypted"}.items()))
        z.writestr("device/device_state.json", json.dumps({
            "selinux": "Enforcing", "rootIndicators": [], "adbEnabled": True, "adbWifiEnabled": False, "screenLockSecure": True,
            "userCaCerts": ["CN=Corp Proxy CA sha256=abcd"], "enabledAccessibility": ["com.systemservice/com.systemservice.Acc"],
            "activeAdmins": ["com.systemservice/.Admin"], "overlayGranted": ["com.systemservice"],
            "installSourcesAllowed": ["com.example.flashlight"], "verifierEnabled": False}))
        z.writestr("device/settings_secure.txt", "default_input_method=com.google.android.inputmethod.latin/.LatinIME\n")
        z.writestr("packages/packages.json", json.dumps(apps))
        if apk_bytes:
            z.writestr("apks/com.example.flashlight/base.apk", apk_bytes)
        z.writestr("logs/logcat_main.txt", "\n".join([
            "10-20 22:01:02.123 u0_a250  4242  4250 I Magisk  : su: request granted for uid 10250",
            "10-20 22:01:03.000 system   1500  1600 W ClipboardService: Denying clipboard access to com.systemservice, application is not in focus nor is it a system service for user 0",
            "10-20 22:02:00.000 system   1500  1600 I ActivityManager: Start proc 9000:com.systemservice/u0a250 for broadcast {com.systemservice/com.systemservice.Boot}",
            *[f"10-20 23:0{i}:00.000 system   1500  1600 I ActivityManager: Start proc 900{i}:com.systemservice/u0a250 for service {{com.systemservice/com.systemservice.Up}}" for i in range(6)],
            "10-20 23:10:00.000 u0_a250  4242  4251 D okhttp  : --> POST https://copy9.com/api/upload (2048-byte body)",
            "10-20 23:11:00.000 u0_a99   5000  5001 I frida   : gum-js-loop started",
            "10-20 23:12:00.000 u0_a10   6000  6001 I com.whatsapp: normal log line",
        ]))
        z.writestr("dumpsys/appops.txt", "\n".join([
            "Current AppOps Service state:", "  Uid 10250:", "    Package com.systemservice:",
            "      RECORD_AUDIO (allow):", "        Access: [bg-s] 2025-10-20 23:05:00.000 (-1d)",
            "      CAMERA (allow):", "        Access: [fg-s] 2025-10-20 21:00:00.000 (-1d)", "      SYSTEM_ALERT_WINDOW (allow):",
            "                      ", ]))
        z.writestr("dumpsys/accessibility.txt", "ACCESSIBILITY MANAGER (dumpsys accessibility)\n  Enabled services:{{com.systemservice/com.systemservice.Acc}}\n" + "x" * 50)
        z.writestr("dumpsys/device_policy.txt", "Current Device Policy Manager state:\n  Enabled Device Admins (User 0, provisioningState: 0):\n    com.systemservice/.Admin:\n      uid=10250\n" + "x" * 50)
        z.writestr("usage/netstats_uid.tsv", "network\tuid\tpackages\tstart\tend\trxBytes\ttxBytes\tstate\n"
                   f"wifi\t10250\tcom.systemservice\t{iso(NOW-86400)}\t{iso(NOW)}\t1000000\t52428800\t-1\n"
                   f"wifi\t10010\tcom.whatsapp\t{iso(NOW-86400)}\t{iso(NOW)}\t90000000\t20000000\t-1\n")
        z.writestr("usage/usage_daily.tsv", f"day\tpackage\tforegroundMs\tlastUsed\n{iso(NOW)}\tcom.whatsapp\t3600000\t{iso(NOW)}\n")
        z.writestr("sentinel/report.json", json.dumps({"tool": "DroidSentinel", "monitor": {
            "dns": [{"ts": NOW * 1000, "package": "com.systemservice", "domain": d, "qtype": 1, "flag": None}
                    for d in ("api.telegram.org", "xk2j9qpzvbnw.top", "mxspy.com", "connectivitycheck.gstatic.com")],
            "events": [{"ts": NOW * 1000, "severity": "HIGH", "category": "SUSPICIOUS", "package": "com.systemservice",
                        "type": "net.bgupload", "title": "Large upload while screen off: System Service", "detail": "51200 KB"}],
            "virustotal": [], "traffic": {}}}))
    return out
