"""Device posture (props/settings) and dumpsys parsers."""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import datetime

from .model import Context, Finding

COMP = re.compile(r"([a-zA-Z][\w.]*\.[\w]+)/((?:[\w.$]+))")


def _props(ctx: Context) -> dict[str, str]:
    props = {}
    for line in ctx.ev.text(ctx.ev.first("device/getprop.txt", "getprop.txt") or "").splitlines():
        m = re.match(r"\[([^\]]+)\]: \[(.*)\]", line)
        if m:
            props[m.group(1)] = m.group(2)
    st = ctx.ev.json("device/device_state.json", {}) or {}
    for k, v in (st.get("props") or {}).items():
        props.setdefault(k, v)
    return props


def _settings(ctx: Context) -> dict[str, dict[str, str]]:
    out = {}
    for ns in ("global", "secure", "system"):
        d = {}
        for name in (f"device/settings_{ns}.txt", f"settings_{ns}.txt"):
            for line in ctx.ev.text(name).splitlines():
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    d.setdefault(k.strip(), v.strip())
        out[ns] = d
    return out


def analyse_device(ctx: Context) -> None:
    props = _props(ctx)
    st = _settings(ctx)
    state = ctx.ev.json("device/device_state.json", {}) or {}
    ctx.device.update(state)
    ctx.device["props"] = props
    ctx.device["settings"] = {k: len(v) for k, v in st.items()}
    ctx.coverage["device"] = "ok" if props else "MISSING – no getprop output"
    sec, glob = st["secure"], st["global"]

    def add(fid, sev, cat, title, detail="", mitre=None):
        ctx.add(Finding(fid, sev, cat, title, detail, None, mitre, "device"))

    # Enabled roles from settings (dumpsys refines later)
    for c in (sec.get("enabled_accessibility_services") or "").split(":"):
        if c:
            ctx.enabled["accessibility"].add(c)
    for c in state.get("enabledAccessibility") or []:
        ctx.enabled["accessibility"].add(c)
    for c in (sec.get("enabled_notification_listeners") or "").split(":"):
        if c:
            ctx.enabled["notification"].add(c)
    for c in state.get("enabledNotificationListeners") or []:
        ctx.enabled["notification"].add(c)
    for c in state.get("activeAdmins") or []:
        ctx.enabled["admins"].add(c)
    ctx.enabled["ime"] = sec.get("default_input_method") or state.get("defaultIme")
    ctx.enabled["sms"] = sec.get("sms_default_application") or state.get("defaultSms")
    ctx.enabled["autofill"] = sec.get("autofill_service") or state.get("autofillService")

    tags, btype = props.get("ro.build.tags", ""), props.get("ro.build.type", "")
    if "test-keys" in tags:
        add("dev.testkeys", "HIGH", "SECURITY", "Firmware signed with test-keys (custom/unofficial ROM)")
    if btype in ("userdebug", "eng"):
        add("dev.buildtype", "HIGH", "SECURITY", f"Build type '{btype}' (debug firmware)")
    if props.get("ro.debuggable") == "1":
        add("dev.debuggable", "HIGH", "SECURITY", "ro.debuggable=1: every app is debuggable")
    if props.get("ro.secure") == "0" or props.get("service.adb.root") == "1":
        add("dev.adbroot", "CRITICAL", "SECURITY", "adb runs as root (ro.secure=0 / service.adb.root=1)", mitre="T1404")
    if props.get("ro.adb.secure") == "0":
        add("dev.adbsecure", "HIGH", "SECURITY", "ADB authentication disabled (ro.adb.secure=0)")
    vb = props.get("ro.boot.verifiedbootstate")
    if vb and vb != "green":
        add("dev.vb", "HIGH", "SECURITY", f"Verified boot state '{vb}' (OS not verified by vendor key)")
    if props.get("ro.boot.flash.locked") == "0" or props.get("ro.boot.vbmeta.device_state") == "unlocked":
        add("dev.unlocked", "HIGH", "SECURITY", "Bootloader unlocked")
    if props.get("ro.boot.veritymode") in ("disabled", "logging"):
        add("dev.verity", "HIGH", "SECURITY", f"dm-verity {props['ro.boot.veritymode']}")
    if (state.get("selinux") or "").lower() == "permissive" or props.get("ro.boot.selinux") == "permissive":
        add("dev.selinux", "HIGH", "SECURITY", "SELinux permissive")
    if state.get("rootIndicators"):
        add("dev.root", "HIGH", "SECURITY", "Root / Magisk indicators", "\n".join(state["rootIndicators"]), "T1404")
    if props.get("ro.crypto.state") == "unencrypted":
        add("dev.crypto", "HIGH", "SECURITY", "Storage NOT encrypted")
    patch = props.get("ro.build.version.security_patch")
    if patch:
        try:
            age = (datetime.utcnow() - datetime.strptime(patch, "%Y-%m-%d")).days
            if age > 365:
                add("dev.patch", "HIGH", "SECURITY", f"Security patch {patch} is {age} days old", mitre="T1404")
            elif age > 90:
                add("dev.patch", "MEDIUM", "SECURITY", f"Security patch {patch} is {age} days old")
        except ValueError:
            pass
    sdk = int(props.get("ro.build.version.sdk", "99") or 99)
    if sdk < 31:
        add("dev.eol", "MEDIUM", "SECURITY", f"Android API {sdk}: likely out of security support")
    if glob.get("adb_wifi_enabled") == "1" or state.get("adbWifiEnabled"):
        add("dev.adbwifi", "HIGH", "SECURITY", "Wireless debugging enabled")
    elif glob.get("adb_enabled") == "1" or state.get("adbEnabled"):
        add("dev.adb", "LOW", "SECURITY", "USB debugging enabled (expected during collection; disable afterwards)")
    if glob.get("package_verifier_enable") == "0" or state.get("verifierEnabled") is False:
        add("dev.verifier", "MEDIUM", "SECURITY", "Package verification / Play Protect disabled", mitre="T1629.003")
    if glob.get("verifier_verify_adb_installs") == "0":
        add("dev.verifier.adb", "MEDIUM", "SECURITY", "ADB installs are not verified")
    if sec.get("install_non_market_apps") == "1" or glob.get("install_non_market_apps") == "1":
        add("dev.unknownsources", "LOW", "SECURITY", "Legacy 'unknown sources' enabled")
    proxy = glob.get("http_proxy") or state.get("httpProxy")
    if proxy and proxy not in (":0", "null"):
        add("dev.proxy", "HIGH", "SECURITY", f"Global HTTP proxy {proxy}", "Traffic can be intercepted.", "T1638")
    if state.get("userCaCerts") or ctx.ev.names("device/ca_user/*"):
        lst = state.get("userCaCerts") or ctx.ev.names("device/ca_user/*")
        add("dev.userca", "HIGH", "SECURITY", "User-installed CA certificate(s): HTTPS interception possible", "\n".join(lst), "T1638")
    vpn = sec.get("always_on_vpn_app")
    if vpn:
        add("dev.alwaysonvpn", "MEDIUM", "PRIVACY", f"Always-on VPN app: {vpn}", "Verify you configured it.", "T1638")
    if state.get("screenLockSecure") is False:
        add("dev.nolock", "HIGH", "SECURITY", "No secure screen lock")
    tmp = [l for l in ctx.ev.text("device/data_local_tmp.txt").splitlines()
           if l[:1] in "-d" and not l.rstrip().endswith((" .", " ..")) and "No such file" not in l]
    if tmp:
        add("dev.localtmp", "MEDIUM", "SUSPICIOUS", f"{len(tmp)} item(s) in /data/local/tmp",
            "Staging area for exploits/root tools and test binaries. Check each file:\n" + "\n".join(tmp[:30]), "T1404")
    apks = [l for l in ctx.ev.text("device/sdcard_apks.txt").splitlines() if l.strip().lower().endswith(".apk")]
    if apks:
        add("dev.sdcardapk", "LOW", "UNKNOWN", f"{len(apks)} APK installer file(s) on shared storage",
            "Leftover installers show what was sideloaded and from where:\n" + "\n".join(apks[:30]), "T1474")
    if glob.get("private_dns_mode") == "off":
        add("dev.privatedns", "INFO", "PRIVACY", "Private DNS off (DNS visible to the network operator)")


# --------------------------------------------------------------------------- dumpsys
def _ds(ctx, name):
    return ctx.ev.text(ctx.ev.first(f"dumpsys/{name}.txt", f"dumpsys_{name}.txt") or "")


def _denied(text):
    return (not text) or text.lstrip().startswith(("Permission Denial", "Can't find service")) or len(text) < 40


def analyse_dumpsys(ctx: Context) -> None:
    got = [n for n in ctx.ev.names("dumpsys/*.txt") if not _denied(ctx.ev.text(n)[:200])]
    ctx.coverage["dumpsys"] = f"ok – {len(got)} services" if got else "MISSING – grant DUMP to the Collector or use tools/adb_collect.sh"
    if not got:
        return

    def add(fid, sev, cat, title, pkg=None, detail="", mitre=None, evidence=None):
        ctx.add(Finding(fid, sev, cat, title, detail, pkg, mitre, "dumpsys", evidence or []))

    # accessibility
    t = _ds(ctx, "accessibility")
    for line in t.splitlines():
        if re.search(r"(?i)enabled services|bound services|Enabled\s*Services", line):
            for p, c in COMP.findall(line):
                ctx.enabled["accessibility"].add(f"{p}/{c}")
    # device policy
    t = _ds(ctx, "device_policy")
    for m in re.finditer(r"ComponentInfo\{([\w.]+)/([\w.$]+)\}", t):
        ctx.enabled["admins"].add(f"{m.group(1)}/{m.group(2)}")
    m = re.search(r"Device Owner:\s*\n\s*admin=ComponentInfo\{([^}]+)\}", t)
    if m:
        ctx.enabled["device_owner"] = m.group(1)
    for m in re.finditer(r"Profile Owner \(User (\d+)\):\s*\n\s*admin=ComponentInfo\{([^}]+)\}", t):
        add("profile.owner", "MEDIUM", "SECURITY", f"Profile owner (work profile) for user {m.group(1)}", m.group(2).split("/")[0], m.group(2))
    # notification listeners
    t = _ds(ctx, "notification")
    sect = re.search(r"(?s)Notification listeners:(.*?)(?:\n  \S|\n\S)", t)
    if sect:
        for line in sect.group(1).splitlines():
            if re.search(r"(?i)(allowed|live|enabled|approved)", line) or line.startswith("      "):
                for p, c in COMP.findall(line):
                    ctx.enabled["notification"].add(f"{p}/{c}")
    # IME
    m = re.search(r"mCurMethodId=([\w.]+/[\w.$]+)", _ds(ctx, "input_method"))
    if m:
        ctx.enabled["ime"] = m.group(1)
    # roles (Android 10+)
    t = _ds(ctx, "role")
    roles = {}
    for m in re.finditer(r"name=android\.app\.role\.(\w+)\s*\n\s*holders=([^\n]*)", t):
        roles[m.group(1)] = [h.strip() for h in m.group(2).split(",") if h.strip()]
    ctx.device["roles"] = roles
    if roles.get("SMS"):
        ctx.enabled["sms"] = roles["SMS"][0]
    for role in ("SMS", "DIALER", "HOME", "ASSISTANT", "BROWSER"):
        for h in roles.get(role, []):
            if ctx.is_sideloaded(h):
                add("role.sideloaded", "MEDIUM", "SUSPICIOUS", f"Sideloaded app holds the {role} role", h)

    # appops: last access of sensitive ops, background access
    _appops(ctx, add)
    # jobs & alarms: persistence of sideloaded apps
    jobs = Counter(re.findall(r"JOB #u\d+a?\d*/\d+: \w+ ([\w.]+)/", _ds(ctx, "jobscheduler")))
    persisted = Counter()
    for block in re.split(r"\n\s*JOB #", _ds(ctx, "jobscheduler")):
        m = re.search(r"^u\d+a?\d*/\d+: \w+ ([\w.]+)/", block)
        if m and "PERSISTED" in block[:2000].upper():
            persisted[m.group(1)] += 1
    alarms = Counter(re.findall(r"(?:RTC_WAKEUP|ELAPSED_WAKEUP)\s+#\d+:\s+Alarm\{\w+ type \d+ (?:origWhen -?\d+ )?(?:window -?\d+ )?(?:exactAllowReason \w+ )?([\w.]+)", _ds(ctx, "alarm")))
    if not alarms:
        alarms = Counter(re.findall(r"WAKEUP #\d+: Alarm\{\w+ [^}]*? ([\w.]+)\}", _ds(ctx, "alarm")))
    ctx.device["jobs"] = dict(jobs.most_common(50))
    ctx.device["wakeup_alarms"] = dict(alarms.most_common(50))
    for pkg in set(jobs) | set(alarms):
        if ctx.is_sideloaded(pkg):
            hidden = ctx.packages.get(pkg, {}).get("hasLauncher") is False
            add("persist.sched", "MEDIUM" if hidden else "LOW", "SUSPICIOUS",
                f"Sideloaded app schedules background work ({jobs.get(pkg, 0)} jobs, {persisted.get(pkg, 0)} persisted, {alarms.get(pkg, 0)} wake-up alarms)",
                pkg, mitre="T1603")
    # dropbox: crashes of privileged processes (exploitation indicator)
    t = _ds(ctx, "dropbox_print") or _ds(ctx, "dropbox")
    tags = Counter(re.findall(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d (\w+)", t, re.M))
    ctx.device["dropbox"] = dict(tags)
    native = re.findall(r"(?s)(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) (?:SYSTEM_TOMBSTONE|system_app_native_crash|data_app_native_crash).{0,600}?(?:Cmdline|Process|>>>)\s*:?\s*([\w./:\-]+)", t)
    priv = [(ts, proc) for ts, proc in native if re.search(r"system_server|mediaserver|media\.|surfaceflinger|com\.android\.bluetooth|"
                                                         r"com\.android\.phone|cameraserver|audioserver|netd|vold|com\.google\.android\.gms|"
                                                         r"com\.android\.chrome|com\.whatsapp|com\.google\.android\.apps\.messaging", proc)]
    for ts, proc in priv[:20]:
        ctx.event(ts, "dropbox", f"native crash: {proc}", None, "MEDIUM")
    if priv:
        add("crash.privileged", "MEDIUM", "SUSPICIOUS", f"{len(priv)} native crashes in privileged/messaging processes",
            None, "Repeated crashes in media/Bluetooth/messaging components can be failed exploitation attempts (zero-click). "
            "Correlate dates with suspicious messages; consider MVT + an expert.", "T1404", [f"{a} {b}" for a, b in priv[:10]])
    # authorised adb keys
    t = _ds(ctx, "adb")
    keys = re.findall(r"(?m)^\s*(?:QAAAA[\w+/=]+)\s+(\S+)", t)
    if keys:
        ctx.device["adb_keys"] = keys
        add("adb.keys", "INFO", "SECURITY", f"{len(keys)} computer(s) authorised for ADB", None, "\n".join(keys),
            evidence=keys)
    # settings history (who toggled what, when)
    hist_keys = ("enabled_accessibility_services", "enabled_notification_listeners", "install_non_market_apps",
                 "package_verifier_enable", "adb_enabled", "adb_wifi_enabled", "http_proxy", "always_on_vpn_app",
                 "default_input_method", "location_mode", "sms_default_application", "autofill_service", "development_settings_enabled")
    for line in _ds(ctx, "settings").splitlines():
        if any(k in line for k in hist_keys) and re.match(r"\s*\d{4}-\d\d-\d\d|\s*\d\d-\d\d", line):
            m = re.match(r"\s*([\d\-: .]+)", line)
            ctx.event(m.group(1).strip() if m else "", "settings", line.strip()[:220], None, "LOW")
    # users / profiles
    t = _ds(ctx, "user")
    users = re.findall(r"UserInfo\{(\d+):([^:]*):", t)
    ctx.device["users"] = users
    if len(users) > 1:
        add("users.multi", "INFO", "SECURITY", f"{len(users)} users/profiles on the device", None, ", ".join(f"{u}:{n}" for u, n in users))
    # accounts
    acc = re.findall(r"Account \{name=([^,]+), type=([^}]+)\}", _ds(ctx, "account"))
    ctx.device["accounts"] = sorted({t for _, t in acc})


SENSITIVE_OPS = {"CAMERA": "T1512", "RECORD_AUDIO": "T1429", "FINE_LOCATION": "T1430", "COARSE_LOCATION": "T1430",
                 "MONITOR_LOCATION": "T1430", "READ_SMS": "T1636.004", "RECEIVE_SMS": "T1636.004", "SEND_SMS": "T1582",
                 "READ_CALL_LOG": "T1636.002", "READ_CONTACTS": "T1636.003", "READ_CLIPBOARD": "T1414",
                 "PROJECT_MEDIA": "T1513", "SYSTEM_ALERT_WINDOW": "T1417.002", "GET_USAGE_STATS": "T1418",
                 "REQUEST_INSTALL_PACKAGES": "T1407", "ACCESS_ACCESSIBILITY": "T1516", "READ_MEDIA_IMAGES": "T1533"}


def _appops(ctx, add):
    t = _ds(ctx, "appops")
    if not t:
        return
    pkg = op = None
    usage: dict[str, dict[str, dict]] = defaultdict(dict)
    overlay, installers = set(), set()
    for line in t.splitlines():
        m = re.match(r"^\s+Package ([\w.]+):", line)
        if m:
            pkg, op = m.group(1), None
            continue
        m = re.match(r"^\s+([A-Z_]+) \((\w+)[^)]*\):?(.*)$", line)
        if m and pkg:
            op = m.group(1)
            mode = m.group(2)
            if op == "SYSTEM_ALERT_WINDOW" and mode == "allow":
                overlay.add(pkg)
            if op == "REQUEST_INSTALL_PACKAGES" and mode == "allow":
                installers.add(pkg)
            rest = m.group(3)
            if op in SENSITIVE_OPS and "time=" in rest:
                usage[pkg].setdefault(op, {})["last"] = re.search(r"time=([^ ]+)", rest).group(1)
            continue
        if pkg and op in SENSITIVE_OPS:
            m = re.search(r"Access:\s*\[([^\]]+)\]\s*([\d\-]+ [\d:.]+)?", line)
            if m:
                rec = usage[pkg].setdefault(op, {})
                rec["last"] = m.group(2) or rec.get("last")
                if m.group(1).startswith("bg") or "bg" in m.group(1).split("-")[0]:
                    rec["background"] = True
    ctx.device.setdefault("overlayGranted", list(overlay))
    ctx.device["overlayGranted"] = sorted(set(ctx.device["overlayGranted"]) | overlay)
    ctx.device["installSourcesAllowed"] = sorted(set(ctx.device.get("installSourcesAllowed", [])) | installers)
    ctx.device["appops_usage"] = {k: v for k, v in usage.items()}
    for pkg, ops in usage.items():
        p = ctx.packages.get(pkg)
        if not p or p.get("system"):
            continue
        for op, rec in ops.items():
            if rec.get("last"):
                ctx.event(rec["last"], "appops", f"{op} used{' in BACKGROUND' if rec.get('background') else ''}", pkg,
                          "MEDIUM" if rec.get("background") else "INFO")
            if rec.get("background") and op in ("CAMERA", "RECORD_AUDIO", "FINE_LOCATION", "PROJECT_MEDIA", "READ_CLIPBOARD"):
                sev = "HIGH" if ctx.is_sideloaded(pkg) else "MEDIUM"
                add("appops.bg", sev, "PRIVACY", f"{op} accessed while app was in the background (last {rec.get('last')})",
                    pkg, mitre=SENSITIVE_OPS[op])
