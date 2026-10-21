"""Package inventory normalisation (collector JSON or adb dumpsys) and package-level rules."""
from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime, timedelta

from .model import Context, Finding

PRIVACY_WEIGHTS = {
    "android.permission.ACCESS_BACKGROUND_LOCATION": 12, "android.permission.ACCESS_FINE_LOCATION": 8,
    "android.permission.ACCESS_COARSE_LOCATION": 4, "android.permission.RECORD_AUDIO": 10, "android.permission.CAMERA": 8,
    "android.permission.READ_SMS": 10, "android.permission.RECEIVE_SMS": 8, "android.permission.SEND_SMS": 8,
    "android.permission.READ_CALL_LOG": 10, "android.permission.PROCESS_OUTGOING_CALLS": 8,
    "android.permission.READ_CONTACTS": 6, "android.permission.READ_CALENDAR": 4, "android.permission.GET_ACCOUNTS": 3,
    "android.permission.READ_PHONE_STATE": 3, "android.permission.READ_PHONE_NUMBERS": 3, "android.permission.BODY_SENSORS": 5,
    "android.permission.ACTIVITY_RECOGNITION": 3, "android.permission.READ_EXTERNAL_STORAGE": 3,
    "android.permission.READ_MEDIA_IMAGES": 4, "android.permission.READ_MEDIA_VIDEO": 3,
    "android.permission.MANAGE_EXTERNAL_STORAGE": 8, "android.permission.PACKAGE_USAGE_STATS": 6,
    "android.permission.QUERY_ALL_PACKAGES": 2, "android.permission.SYSTEM_ALERT_WINDOW": 6,
    "android.permission.NEARBY_WIFI_DEVICES": 2, "android.permission.BLUETOOTH_SCAN": 2,
}
SYSTEMISH_LABEL = re.compile(r"(?i)\b(system|update|updater|services?|google|android|wi-?fi|settings|security|sync|battery|device care|sim toolkit)\b")
SYSTEMISH_PKG = re.compile(r"^(com\.android\.|com\.google\.|android\.|com\.samsung\.|com\.qualcomm\.)")
OWN = {"org.droidsuite.sentinel", "org.droidsuite.collector"}


# --------------------------------------------------------------------------- loading
def _from_collector(items: list[dict]) -> dict[str, dict]:
    out = {}
    for a in items:
        out[a["package"]] = {
            "package": a["package"], "label": a.get("label") or a["package"], "uid": a.get("uid"),
            "versionCode": a.get("versionCode"), "versionName": a.get("versionName"),
            "installer": a.get("installer"), "initiatingInstaller": a.get("initiatingInstaller"),
            "firstInstall": a.get("firstInstallTime"), "lastUpdate": a.get("lastUpdateTime"),
            "system": bool(a.get("system")), "updatedSystem": bool(a.get("updatedSystem")),
            "hasLauncher": a.get("hasLauncher"), "debuggable": bool(a.get("debuggable")),
            "targetSdk": a.get("targetSdk"), "sharedUserId": a.get("sharedUserId"), "apkPaths": a.get("apkPaths", []),
            "apkSize": a.get("apkSize"), "apkSha256": a.get("apkSha256"), "certSha256": a.get("certSha256", []),
            "certSha1": a.get("certSha1", []), "certSubjects": a.get("certSubjects", []),
            "requested": a.get("requestedPermissions", []), "granted": set(a.get("grantedPermissions", [])),
            "components": a.get("components", []), "nativeLibs": a.get("nativeLibs", []), "enabled": a.get("enabled", True),
            "cleartext": a.get("cleartextTraffic"),
        }
    return out


def parse_dumpsys_package(text: str) -> dict[str, dict]:
    out: dict[str, dict] = {}
    cur = None
    mode = None
    in_packages = False
    for line in text.splitlines():
        if line.startswith("Packages:"):
            in_packages = True
            continue
        if in_packages and line and not line.startswith(" "):
            if cur:
                cur = None
            in_packages = line.startswith("Packages:")
            continue
        if not in_packages:
            continue
        m = re.match(r"^  Package \[([^\]]+)\]", line)
        if m:
            cur = out.setdefault(m.group(1), {"package": m.group(1), "label": m.group(1), "requested": [], "granted": set(),
                                              "components": [], "certSha256": [], "certSha1": [], "certSubjects": [],
                                              "apkPaths": [], "nativeLibs": [], "hasLauncher": None, "system": False,
                                              "updatedSystem": False, "debuggable": False, "installer": None})
            mode = None
            continue
        if cur is None:
            continue
        s = line.strip()
        if s.startswith("userId="):
            cur["uid"] = int(re.sub(r"\D.*", "", s[7:]) or 0)
        elif s.startswith("codePath="):
            cur["apkPaths"] = [s[9:] + "/base.apk" if not s.endswith(".apk") else s[9:]]
        elif s.startswith("versionCode="):
            m = re.match(r"versionCode=(\d+).*?targetSdk=(\d+)", s)
            if m:
                cur["versionCode"], cur["targetSdk"] = int(m.group(1)), int(m.group(2))
        elif s.startswith("versionName="):
            cur["versionName"] = s[12:]
        elif s.startswith("flags=[") or s.startswith("pkgFlags=["):
            cur["system"] = cur["system"] or " SYSTEM " in s + " "
            cur["updatedSystem"] = cur["updatedSystem"] or "UPDATED_SYSTEM_APP" in s
            cur["debuggable"] = cur["debuggable"] or "DEBUGGABLE" in s
        elif s.startswith("firstInstallTime="):
            cur["firstInstall"] = s[17:]
        elif s.startswith("lastUpdateTime="):
            cur["lastUpdate"] = s[15:]
        elif s.startswith("installerPackageName="):
            v = s[21:]
            cur["installer"] = None if v in ("null", "") else v
        elif s.startswith("initiatingPackageName="):
            cur["initiatingInstaller"] = s[22:]
        elif s.startswith("sharedUser="):
            m = re.search(r"SharedUserSetting\{\w+ ([^/]+)/", s)
            cur["sharedUserId"] = m.group(1) if m else None
        elif s == "requested permissions:":
            mode = "req"
        elif s in ("install permissions:", "runtime permissions:"):
            mode = "grant"
        elif s.startswith("User "):
            pass  # per-user block; runtime permissions header follows
        elif s.endswith(":"):
            mode = None
        elif mode == "req" and re.match(r"^[\w.]+$", re.split(r"[:,]", s)[0]):
            cur["requested"].append(re.split(r"[:,]", s)[0])
        elif mode == "grant":
            m = re.match(r"^([\w.]+): granted=(true|false)", s)
            if m and m.group(2) == "true":
                cur["granted"].add(m.group(1))
    return out


def load_packages(ctx: Context) -> None:
    ev = ctx.ev
    items = ev.json("packages/packages.json")
    if items:
        ctx.packages = _from_collector(items)
        ctx.coverage["inventory"] = f"ok – {len(items)} packages from DroidCollector"
    else:
        txt = ev.text(ev.first("dumpsys/package.txt", "dumpsys_package.txt") or "")
        ctx.packages = parse_dumpsys_package(txt) if txt else {}
        # pm list packages -f -i -U  ->  package:/path/base.apk=pkg  installer=x uid:N
        for line in ev.text("packages/pm_list.txt").splitlines():
            m = re.match(r"package:(.+?)=([\w.]+)\s+(?:installer=(\S+))?\s*(?:uid:(\d+))?", line)
            if m:
                p = ctx.packages.setdefault(m.group(2), {"package": m.group(2), "label": m.group(2), "requested": [], "granted": set(),
                                                          "components": [], "certSha256": [], "certSha1": [], "certSubjects": [],
                                                          "nativeLibs": [], "hasLauncher": None, "system": False, "updatedSystem": False,
                                                          "debuggable": False})
                p["apkPaths"] = [m.group(1)]
                if m.group(3) and m.group(3) != "null":
                    p["installer"] = m.group(3)
                if p.get("system") is False and m.group(1).startswith(("/system", "/product", "/vendor", "/system_ext", "/apex", "/odm")):
                    p["system"] = True
        launch = ev.text("packages/launcher_activities.txt")
        if launch:
            pk = set(re.findall(r"packageName=([\w.]+)", launch)) | set(re.findall(r"^\s*([\w.]+)/", launch, re.M))
            for p in ctx.packages.values():
                p["hasLauncher"] = p["package"] in pk
        ctx.coverage["inventory"] = (f"partial – {len(ctx.packages)} packages reconstructed from dumpsys/pm (no signer info unless APKs present)"
                                     if ctx.packages else "MISSING – no package inventory in the archive")
    for p in ctx.packages.values():
        p.setdefault("label", p["package"])
        p.setdefault("granted", set())


# --------------------------------------------------------------------------- helpers
def _parse_time(s):
    if not s:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"):
        try:
            return datetime.strptime(s, fmt)
        except (ValueError, TypeError):
            continue
    return None


def services_with(p, perm):
    return [c for c in p.get("components", []) if c.get("type") == "service" and c.get("permission") == perm]


# --------------------------------------------------------------------------- rules
def analyse_packages(ctx: Context) -> None:
    pk = ctx.packages
    en = ctx.enabled
    iocs = ctx.iocs
    trusted = ctx.opt.trusted_installers
    platform = set(pk.get("android", {}).get("certSha256", []))
    labels = defaultdict(list)
    for p in pk.values():
        labels[p["label"].strip().lower()].append(p["package"])
    acc = {c.split("/")[0] for c in en["accessibility"]}
    nls = {c.split("/")[0] for c in en["notification"]}
    adm = {c.split("/")[0] for c in en["admins"]}
    ime = (en["ime"] or "").split("/")[0]
    overlay = set(ctx.device.get("overlayGranted", []))
    installers_allowed = set(ctx.device.get("installSourcesAllowed", []))
    now = datetime.utcnow()

    def add(fid, sev, cat, title, pkg, detail="", mitre=None, evidence=None):
        ctx.add(Finding(fid, sev, cat, title, detail, pkg, mitre, "packages", evidence or []))

    for name, p in pk.items():
        if name in OWN:
            continue
        side = ctx.is_sideloaded(name)
        g = p["granted"]
        req = set(p.get("requested", []))

        # IOC
        if name in iocs.packages:
            add("ioc.package", "CRITICAL", "MALWARE", f"Known stalkerware/spyware package ({iocs.packages[name]})", name,
                "Package name listed in the loaded IOC feeds.", "T1636")
        for c in p.get("certSha1", []):
            if c.lower() in iocs.cert_sha1:
                add("ioc.cert", "CRITICAL", "MALWARE", f"Signing certificate matches IOC ({iocs.cert_sha1[c.lower()]})", name, c)
        h = (p.get("apkSha256") or "").lower()
        if h and h in iocs.hashes:
            add("ioc.hash", "CRITICAL", "MALWARE", f"APK hash matches IOC ({iocs.hashes[h]})", name, h)
        v = ctx.vt.get(h)
        if v and v.get("malicious", 0) >= 3:
            add("vt.malicious", "CRITICAL", "MALWARE", f"VirusTotal: {v['malicious']}/{v['total']} engines detect this APK", name, v.get("label") or "")
        elif v and v.get("malicious", 0) > 0:
            add("vt.low", "MEDIUM", "SUSPICIOUS", f"VirusTotal: {v['malicious']}/{v['total']} detections (verify, may be PUP/FP)", name, v.get("label") or "")

        # Firmware / signing
        if not p["system"] and platform and set(p.get("certSha256", [])) & platform:
            add("cert.platform", "CRITICAL", "MALWARE", "User app signed with the platform (firmware) key", name,
                "Grants system privileges; matches known abuse of leaked OEM platform keys.", "T1404")
        if p["system"] and p.get("debuggable"):
            add("sys.debuggable", "HIGH", "SECURITY", "Debuggable system app (engineering/modified firmware)", name)
        if p.get("updatedSystem") and p.get("installer") and p["installer"] not in trusted:
            add("sys.update.untrusted", "HIGH", "SECURITY", f"System app updated from untrusted installer {p['installer']}", name, mitre="T1645")
        if not p["system"] and any("Android Debug" in s for s in p.get("certSubjects", [])):
            add("cert.debug", "MEDIUM", "SUSPICIOUS", "Signed with the Android debug certificate", name)

        # Abusable roles
        if name in acc and not p["system"]:
            add("acc.enabled", "HIGH", "SECURITY", "Accessibility service ENABLED", name,
                "Full screen reading, keystroke capture and remote tapping.", "T1417.002 / T1516")
        if name in nls and not p["system"]:
            add("nls.enabled", "MEDIUM", "PRIVACY", "Notification listener ENABLED", name, "Reads every notification (OTP codes, messages).", "T1517")
        if name in adm and not p["system"]:
            add("admin.active", "HIGH", "SECURITY", "Active device administrator", name, "Can lock/wipe the device, hinders uninstall.", "T1626.001")
        if en.get("device_owner") and en["device_owner"].startswith(name + "/"):
            add("device.owner", "HIGH", "SECURITY", "App is DEVICE OWNER (fully managed device / MDM)", name,
                "Has near-total control: can install apps silently, read network logs, enforce policies.", "T1626.001")
        if name == ime and not p["system"]:
            add("ime.default", "MEDIUM", "PRIVACY", "Third-party keyboard is the default IME", name, mitre="T1417.001")
        if name == en.get("sms") and side:
            add("sms.default", "MEDIUM", "SUSPICIOUS", "Sideloaded app is the default SMS app", name, mitre="T1582")
        if name in overlay and not p["system"]:
            if name in acc:
                add("overlay.acc", "HIGH", "SECURITY", "Overlay + accessibility (banking-trojan combination)", name, mitre="T1417.002")
            else:
                add("overlay", "LOW", "PRIVACY", "Allowed to draw over other apps", name, mitre="T1417.002")
        if not p["system"] and {"android.permission.READ_SMS", "android.permission.SEND_SMS"} <= g and name != en.get("sms"):
            add("sms.full", "HIGH", "SECURITY", "Reads AND sends SMS without being the SMS app", name, mitre="T1636.004 / T1582")
        if side and services_with(p, "android.permission.BIND_VPN_SERVICE"):
            add("vpn.provider", "MEDIUM", "SUSPICIOUS", "Sideloaded app can act as VPN", name, mitre="T1638")

        # Task hijack
        for c in p.get("components", []):
            ta = c.get("taskAffinity")
            if c.get("type") == "activity" and ta and ta != name and not ta.startswith(name + ":") and not p["system"]:
                if ta in pk:
                    add("task.hijack", "HIGH", "SECURITY", f"Activity claims task affinity of {ta} (StrandHogg)", name, c.get("name", ""), "T1417.002")

        # Masquerading
        if not p["system"] and side:
            same = [x for x in labels[p["label"].strip().lower()] if x != name]
            if same:
                add("mask.label", "HIGH", "SUSPICIOUS", f"Same display name as {', '.join(same)}", name, mitre="T1655.001")
            if SYSTEMISH_PKG.match(name):
                add("mask.pkg", "HIGH", "SUSPICIOUS", "Sideloaded app with a vendor-like package name", name, mitre="T1655.001")
            elif SYSTEMISH_LABEL.search(p["label"]):
                add("mask.name", "MEDIUM", "SUSPICIOUS", f"Sideloaded app with a system-sounding name: \"{p['label']}\"", name, mitre="T1655.001")

        # Capability profile
        caps = [
            bool({"android.permission.ACCESS_BACKGROUND_LOCATION", "android.permission.ACCESS_FINE_LOCATION"} & g),
            "android.permission.RECORD_AUDIO" in g, "android.permission.READ_SMS" in g, "android.permission.READ_CALL_LOG" in g,
            "android.permission.READ_CONTACTS" in g, name in acc, name in nls, name in adm, "android.permission.CAMERA" in g,
            "android.permission.RECEIVE_BOOT_COMPLETED" in req,
        ]
        n = sum(caps)
        hidden = not p["system"] and p.get("hasLauncher") is False
        if hidden and n >= 2:
            add("hidden", "HIGH", "SUSPICIOUS", "Hidden app (no launcher icon) with sensitive capabilities", name, f"{n} capabilities", "T1628.001")
        if side and n >= 5:
            add("stalkerware.profile", "HIGH", "SUSPICIOUS", f"Surveillance capability profile ({n}/10)", name,
                "Combination typical of stalkerware: location, mic, SMS, call log, contacts, accessibility, admin, boot.", "T1430 / T1429 / T1636")

        # Hygiene
        if side:
            add("install.untrusted", "LOW", "UNKNOWN", f"Installed outside a trusted store (installer: {p.get('installer') or 'none/adb'})", name, mitre="T1474")
            if name in installers_allowed:
                add("dropper", "MEDIUM", "SUSPICIOUS", "Sideloaded app allowed to install other apps", name, mitre="T1407")
        ts = p.get("targetSdk")
        if not p["system"] and isinstance(ts, int) and 0 < ts < 23:
            add("sdk.old", "MEDIUM", "SECURITY", f"Targets API {ts}: permissions granted at install time", name)
        for lib in p.get("nativeLibs", []):
            for k, v in (("libjiagu", "Qihoo 360"), ("libsecexe", "Bangcle"), ("libDexHelper", "SecNeo"), ("libshella", "Tencent Legu"),
                         ("libexec", "ijiami"), ("libmobisec", "Alibaba")):
                if lib.startswith(k):
                    add("packer", "MEDIUM", "SUSPICIOUS", f"Packed with {v} ({lib})", name, mitre="T1406.002")
        fi = _parse_time(p.get("firstInstall"))
        if fi and side and now - fi < timedelta(days=30):
            add("recent.sideload", "MEDIUM" if hidden else "LOW", "UNKNOWN", f"Sideloaded within the last 30 days ({p.get('firstInstall')})", name)

        # Timeline
        if p.get("firstInstall"):
            ctx.event(p["firstInstall"], "package", f"installed via {p.get('installer') or 'none/adb'}", name,
                      "MEDIUM" if side else "INFO")
        if p.get("lastUpdate") and p.get("lastUpdate") != p.get("firstInstall") and not p["system"]:
            ctx.event(p["lastUpdate"], "package", f"updated to {p.get('versionName')}", name)

    # Install clustering: several sideloads within 15 minutes = someone had the phone in hand
    side_times = sorted((t, n) for n, p in pk.items() if ctx.is_sideloaded(n) and (t := _parse_time(p.get("firstInstall"))))
    for i in range(len(side_times)):
        group = [x for x in side_times if timedelta(0) <= x[0] - side_times[i][0] <= timedelta(minutes=15)]
        if len(group) >= 3:
            ctx.add(Finding("install.cluster", "MEDIUM", "SUSPICIOUS",
                            f"{len(group)} apps sideloaded within 15 minutes ({group[0][0]:%Y-%m-%d %H:%M})",
                            "Burst installs outside a store often mean someone set the phone up by hand (stalkerware install session).",
                            None, None, "packages", [n for _, n in group]))
            break


def scores(ctx: Context) -> dict[str, dict]:
    from .model import WEIGHT
    acc = {c.split("/")[0] for c in ctx.enabled["accessibility"]}
    nls = {c.split("/")[0] for c in ctx.enabled["notification"]}
    out = {}
    for name, p in ctx.packages.items():
        priv = sum(w if perm in p["granted"] else (w // 4 if perm in p.get("requested", []) else 0) for perm, w in PRIVACY_WEIGHTS.items())
        priv += 15 if name in acc else 0
        priv += 10 if name in nls else 0
        sec = sum(WEIGHT[f.severity] for f in ctx.findings if f.package == name and f.category != "PRIVACY")
        out[name] = {"privacy": min(priv, 100), "security": min(sec, 100)}
    return out
