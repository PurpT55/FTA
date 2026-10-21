"""Pure-python static APK analysis: binary manifest, DEX strings, signing certs, payloads."""
from __future__ import annotations

import hashlib
import io
import math
import re
import struct
import zipfile
from collections import Counter

# --------------------------------------------------------------------------- AXML
_ATTR_IDS = {0x01010003: "name", 0x01010006: "permission", 0x01010010: "exported", 0x0101001c: "priority",
             0x01010012: "taskAffinity", 0x0101001d: "launchMode", 0x0101000f: "debuggable",
             0x0101021b: "versionCode", 0x0101021c: "versionName", 0x0101020c: "minSdkVersion",
             0x01010270: "targetSdkVersion", 0x0101000b: "sharedUserId", 0x01010018: "authorities",
             0x01010204: "allowTaskReparenting", 0x01010280: "allowBackup", 0x010104ec: "usesCleartextTraffic",
             0x01010026: "scheme", 0x01010028: "host"}


def _pool(buf: bytes, off: int) -> list[str]:
    _, hsize, _, count, _, flags, sstart, _ = struct.unpack_from("<HHIIIIII", buf, off)
    utf8 = bool(flags & 0x100)
    offs = struct.unpack_from(f"<{count}I", buf, off + hsize)
    base = off + sstart
    out = []
    for o in offs:
        p = base + o
        try:
            if utf8:
                n = buf[p]; p += 2 if n & 0x80 else 1
                n = buf[p]
                if n & 0x80:
                    n = ((n & 0x7F) << 8) | buf[p + 1]; p += 2
                else:
                    p += 1
                out.append(buf[p:p + n].decode("utf-8", "replace"))
            else:
                n = struct.unpack_from("<H", buf, p)[0]; p += 2
                if n & 0x8000:
                    n = ((n & 0x7FFF) << 16) | struct.unpack_from("<H", buf, p)[0]; p += 2
                out.append(buf[p:p + 2 * n].decode("utf-16-le", "replace"))
        except (IndexError, struct.error):
            out.append("")
    return out


def parse_axml(buf: bytes) -> list[tuple[int, str, dict]]:
    """Returns [(depth, tag, attrs)] for every start element."""
    strings: list[str] = []
    resmap: list[int] = []
    elems = []
    depth = 0
    off = 8
    while off + 8 <= len(buf):
        ctype, hsize, csize = struct.unpack_from("<HHI", buf, off)
        if csize < 8:
            break
        if ctype == 0x0001:
            strings = _pool(buf, off)
        elif ctype == 0x0180:
            resmap = list(struct.unpack_from(f"<{(csize - 8) // 4}I", buf, off + 8))
        elif ctype == 0x0102:
            name_i = struct.unpack_from("<I", buf, off + 20)[0]
            astart, asize, acount = struct.unpack_from("<HHH", buf, off + 24)
            tag = strings[name_i] if name_i < len(strings) else "?"
            attrs = {}
            p = off + 16 + astart
            for _ in range(acount):
                _, an, raw, _, _, dtype, data = struct.unpack_from("<IIIHBBI", buf, p)
                p += asize or 20
                key = strings[an] if an < len(strings) and strings[an] else _ATTR_IDS.get(resmap[an] if an < len(resmap) else -1, f"attr{an}")
                if dtype == 0x03:
                    val = strings[data] if data < len(strings) else ""
                elif dtype == 0x12:
                    val = data != 0
                elif dtype in (0x10, 0x11):
                    val = data if data < 0x80000000 else data - 0x100000000
                elif raw != 0xFFFFFFFF and raw < len(strings):
                    val = strings[raw]
                else:
                    val = f"@0x{data:08x}"
                attrs[key] = val
            elems.append((depth, tag, attrs))
            depth += 1
        elif ctype == 0x0103:
            depth -= 1
        off += csize
    return elems


def manifest_info(axml: bytes) -> dict:
    elems = parse_axml(axml)
    m = {"package": None, "permissions": [], "components": [], "application": {}, "sdk": {}}
    stack: list[dict] = []
    cur_filter = None
    for depth, tag, a in elems:
        while stack and stack[-1]["_depth"] >= depth:
            stack.pop()
        if tag == "manifest":
            m["package"] = a.get("package")
            m["versionCode"] = a.get("versionCode")
            m["versionName"] = a.get("versionName")
            m["sharedUserId"] = a.get("sharedUserId")
        elif tag == "uses-sdk":
            m["sdk"] = {"min": a.get("minSdkVersion"), "target": a.get("targetSdkVersion")}
        elif tag in ("uses-permission", "uses-permission-sdk-23"):
            if a.get("name"):
                m["permissions"].append(a["name"])
        elif tag == "application":
            m["application"] = {k: a.get(k) for k in ("debuggable", "allowBackup", "usesCleartextTraffic", "name")}
        elif tag in ("activity", "activity-alias", "service", "receiver", "provider"):
            c = {"type": "activity" if tag == "activity-alias" else tag, "name": a.get("name"), "exported": a.get("exported"),
                 "permission": a.get("permission"), "taskAffinity": a.get("taskAffinity"),
                 "authorities": a.get("authorities"), "filters": [], "_depth": depth}
            m["components"].append(c)
            stack.append(c)
        elif tag == "intent-filter" and stack:
            cur_filter = {"actions": [], "categories": [], "schemes": [], "hosts": [], "priority": a.get("priority", 0) or 0}
            stack[-1]["filters"].append(cur_filter)
        elif tag in ("action", "category", "data") and cur_filter is not None:
            if tag == "action" and a.get("name"):
                cur_filter["actions"].append(a["name"])
            elif tag == "category" and a.get("name"):
                cur_filter["categories"].append(a["name"])
            elif tag == "data":
                if a.get("scheme"):
                    cur_filter["schemes"].append(a["scheme"])
                if a.get("host"):
                    cur_filter["hosts"].append(a["host"])
    for c in m["components"]:
        c.pop("_depth", None)
        if c["exported"] is None:
            c["exported"] = bool(c["filters"])
    return m


# --------------------------------------------------------------------------- DEX
def _uleb(b: bytes, p: int) -> tuple[int, int]:
    r = s = 0
    while True:
        x = b[p]; p += 1
        r |= (x & 0x7F) << s
        if x < 0x80:
            return r, p
        s += 7


def dex_strings(dex: bytes, cap: int = 400_000) -> list[str]:
    if len(dex) < 0x70 or not dex.startswith(b"dex\n"):
        return []
    size, off = struct.unpack_from("<II", dex, 0x38)
    out = []
    for i in range(min(size, cap)):
        try:
            p = struct.unpack_from("<I", dex, off + 4 * i)[0]
            _, p = _uleb(dex, p)
            e = dex.index(b"\x00", p)
            out.append(dex[p:e].decode("utf-8", "replace"))
        except (struct.error, ValueError, IndexError):
            break
    return out


# --------------------------------------------------------------------------- signing certs
def _der_len(b: bytes, p: int) -> tuple[int, int]:
    n = b[p]; p += 1
    if n < 0x80:
        return n, p
    k = n & 0x7F
    return int.from_bytes(b[p:p + k], "big"), p + k


def _der_children(b: bytes, start: int, end: int):
    p = start
    while p < end:
        tag = b[p]
        ln, q = _der_len(b, p + 1)
        yield tag, p, q, q + ln
        p = q + ln


def pkcs7_first_cert(b: bytes) -> bytes | None:
    """ContentInfo -> [0] -> SignedData -> [0] certificates -> first Certificate."""
    try:
        _, _, q, e = next(_der_children(b, 0, len(b)))              # ContentInfo SEQ
        kids = list(_der_children(b, q, e))
        _, _, q, e = kids[1]                                        # [0] EXPLICIT
        _, _, q, e = next(_der_children(b, q, e))                   # SignedData SEQ
        for tag, s, cq, ce in _der_children(b, q, e):
            if tag == 0xA0:                                         # certificates [0] IMPLICIT
                _, cs, _, cend = next(_der_children(b, cq, ce))
                return b[cs:cend]
    except (StopIteration, IndexError, ValueError):
        return None
    return None


def _lp(b: bytes, p: int) -> tuple[bytes, int]:
    n = struct.unpack_from("<I", b, p)[0]
    return b[p + 4:p + 4 + n], p + 4 + n


def signing_block_certs(apk: bytes) -> dict[str, list[bytes]]:
    """Certificates from APK Signature Scheme v2 / v3 blocks."""
    out: dict[str, list[bytes]] = {}
    eocd = apk.rfind(b"PK\x05\x06", max(0, len(apk) - 70000))
    if eocd < 0:
        return out
    cd_off = struct.unpack_from("<I", apk, eocd + 16)[0]
    if cd_off < 32 or apk[cd_off - 16:cd_off] != b"APK Sig Block 42":
        return out
    size = struct.unpack_from("<Q", apk, cd_off - 24)[0]
    start = cd_off - (size + 8)
    p = start + 8
    while p < cd_off - 24:
        ln, bid = struct.unpack_from("<QI", apk, p)
        val = apk[p + 12:p + 8 + ln]
        p += 8 + ln
        scheme = {0x7109871A: "v2", 0xF05368C0: "v3", 0x1B93AD61: "v3.1"}.get(bid)
        if not scheme:
            continue
        try:
            signers, _ = _lp(val, 0)
            q = 0
            while q < len(signers):
                signer, q = _lp(signers, q)
                signed, _ = _lp(signer, 0)
                _, r = _lp(signed, 0)                 # digests
                certs, _ = _lp(signed, r)
                c = 0
                while c < len(certs):
                    cert, c = _lp(certs, c)
                    out.setdefault(scheme, []).append(cert)
        except struct.error:
            continue
    return out


def cert_subject_hint(der: bytes) -> str:
    """Printable strings of the subject (cheap: no ASN.1 name decoding)."""
    hits = re.findall(rb"[\x13\x0c]([\x01-\x7f])([ -~]{2,64})", der[:1200])
    vals = [h[1][: h[0][0]].decode("ascii", "replace") for h in hits]
    vals = [v for v in vals if len(v) >= 2 and re.fullmatch(r"[\w .,@'&/\-]+", v) and re.search(r"[A-Za-z]", v)]
    return ", ".join(dict.fromkeys(vals))[:200]


# --------------------------------------------------------------------------- rules
API_RULES = [
    # (id, needles(all must appear; "=x" means an exact DEX string, else substring), severity, category, title, mitre)
    ("dcl", ["Ldalvik/system/DexClassLoader;"], "MEDIUM", "SUSPICIOUS", "Loads code at runtime (DexClassLoader)", "T1407"),
    ("dcl.mem", ["Ldalvik/system/InMemoryDexClassLoader;"], "HIGH", "SUSPICIOUS", "Loads DEX from memory (fileless payload)", "T1407"),
    ("exec.su", ["Ljava/lang/Runtime;", "=exec", "=su"], "LOW", "SECURITY", "Executes shell commands (Runtime.exec + 'su' string)", "T1404"),
    ("sms.send", ["sendTextMessage"], "MEDIUM", "PRIVACY", "Can send SMS programmatically", "T1582"),
    ("sms.read", ["content://sms"], "MEDIUM", "PRIVACY", "Reads the SMS database (content://sms)", "T1636.004"),
    ("calllog.read", ["content://call_log"], "MEDIUM", "PRIVACY", "Reads call history", "T1636.002"),
    ("screen.capture", ["createScreenCaptureIntent"], "MEDIUM", "PRIVACY", "Screen capture (MediaProjection)", "T1513"),
    ("audio.record", ["Landroid/media/AudioRecord;"], "LOW", "PRIVACY", "Records audio (AudioRecord)", "T1429"),
    ("acc.gesture", ["dispatchGesture"], "MEDIUM", "SECURITY", "Injects taps/gestures via accessibility", "T1516"),
    ("acc.global", ["performGlobalAction"], "LOW", "SECURITY", "Performs global actions via accessibility", "T1516"),
    ("hide.icon", ["setComponentEnabledSetting", "android.intent.category.LAUNCHER"], "LOW", "SUSPICIOUS", "Can disable its own components (icon hiding)", "T1628.001"),
    ("admin.wipe", ["wipeData"], "MEDIUM", "SECURITY", "Device-admin wipe capability", "T1630"),
    ("admin.lock", ["lockNow", "resetPassword"], "MEDIUM", "SECURITY", "Device-admin lock / password reset", "T1629"),
    ("ids", ["getSubscriberId"], "LOW", "PRIVACY", "Reads SIM subscriber id (IMSI)", "T1426"),
    ("clipboard", ["getPrimaryClip"], "LOW", "PRIVACY", "Reads clipboard", "T1414"),
    ("pkg.discovery", ["getInstalledPackages"], "INFO", "PRIVACY", "Enumerates installed apps", "T1418"),
    ("c2.telegram", ["api.telegram.org"], "HIGH", "SUSPICIOUS", "Embedded Telegram Bot API endpoint (common exfil channel)", "T1481"),
    ("c2.discord", ["discord.com/api/webhooks"], "HIGH", "SUSPICIOUS", "Embedded Discord webhook (exfil channel)", "T1481"),
    ("c2.pastebin", ["pastebin.com/raw"], "MEDIUM", "SUSPICIOUS", "Fetches pastebin raw content (dead-drop resolver)", "T1481"),
    ("evasion.emu", ["=goldfish", "ro.kernel.qemu"], "LOW", "SUSPICIOUS", "Emulator checks (sandbox evasion)", "T1633"),
    ("hooking", ["de/robv/android/xposed"], "LOW", "SUSPICIOUS", "References Xposed hooking framework", "T1625.001"),
    ("installer", ["Landroid/content/pm/PackageInstaller;"], "LOW", "SUSPICIOUS", "Installs other packages (PackageInstaller)", "T1407"),
    ("keylog.acc", ["TYPE_VIEW_TEXT_CHANGED"], "MEDIUM", "PRIVACY", "Watches text-change accessibility events (keylogging)", "T1417.001"),
    ("notif.read", ["Landroid/service/notification/NotificationListenerService;"], "LOW", "PRIVACY", "Reads notifications", "T1517"),
    ("cam", ["Landroid/hardware/camera2/CameraManager;", "openCamera"], "INFO", "PRIVACY", "Uses the camera", "T1512"),
    ("location", ["requestLocationUpdates"], "INFO", "PRIVACY", "Tracks location", "T1430"),
]

TRACKERS = {
    "Lcom/google/firebase/analytics": "Google Firebase Analytics", "Lcom/google/android/gms/ads": "Google AdMob",
    "Lcom/facebook/appevents": "Facebook Analytics", "Lcom/facebook/ads": "Facebook Audience Network",
    "Lcom/appsflyer": "AppsFlyer", "Lcom/adjust/sdk": "Adjust", "Lio/branch": "Branch", "Lcom/onesignal": "OneSignal",
    "Lcom/applovin": "AppLovin", "Lcom/unity3d/ads": "Unity Ads", "Lcom/ironsource": "ironSource", "Lcom/mopub": "MoPub",
    "Lcom/bytedance/sdk": "Pangle (ByteDance)", "Lcom/huawei/hms/analytics": "Huawei Analytics", "Lcom/amplitude": "Amplitude",
    "Lcom/mixpanel": "Mixpanel", "Lcom/segment/analytics": "Segment", "Lcom/google/firebase/crashlytics": "Firebase Crashlytics",
    "Lio/sentry": "Sentry", "Lcom/flurry": "Flurry", "Lcom/inmobi": "InMobi", "Lcom/vungle": "Vungle", "Lcom/chartboost": "Chartboost",
    "Lcom/startapp": "StartApp", "Lcom/kochava": "Kochava", "Lcom/yandex/metrica": "Yandex AppMetrica", "Lcom/mbridge": "Mintegral",
    "Lcom/tencent/bugly": "Tencent Bugly", "Lcom/umeng": "Umeng", "Lcom/xiaomi/push": "Xiaomi Push",
}

PACKER_CLASSES = {"Lcom/secneo/": "Bangcle/SecNeo", "Lcom/qihoo/util/": "Qihoo 360 Jiagu", "Lcom/stub/StubApp": "Qihoo 360 Jiagu",
                  "Lcom/tencent/StubShell": "Tencent Legu", "Lcom/baidu/protect": "Baidu", "Lcom/shell/SuperApplication": "ijiami",
                  "Lcom/bangcle": "Bangcle", "Lcom/ali/mobisecenhance": "Alibaba"}
PACKER_LIBS = {"libjiagu": "Qihoo 360 Jiagu", "libsecexe": "Bangcle", "libsecmain": "Bangcle", "libDexHelper": "Bangcle/SecNeo",
               "libshella": "Tencent Legu", "libshellx": "Tencent Legu", "libexec": "ijiami", "libexecmain": "ijiami",
               "libmobisec": "Alibaba", "libnqshield": "NQ Shield", "libprotectClass": "Unknown packer", "libbaiduprotect": "Baidu"}

URL_RE = re.compile(r"https?://[A-Za-z0-9.\-]{3,253}(?::\d+)?(?:/[^\s\"'<>]{0,120})?")
HOST_RE = re.compile(r"(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,24}|xn--[a-z0-9\-]+)|\d{1,3}(?:\.\d{1,3}){3}")
GTLDS = set("""com net org info biz io app dev xyz top site online club shop store tech me tv cc pw edu gov mil int arpa onion
cloud live link click zip mov cyou rest icu space fun website host pro mobi name asia tel jobs travel ltd group email digital network
systems services solutions agency media news blog page win bid loan work today life plus one global world center support software
""".split())
IP_RE = re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b")
BENIGN_HOSTS = ("schemas.android.com", "www.w3.org", "xmlpull.org", "apache.org", "www.apache.org", "xml.org",
                "ns.adobe.com", "purl.org", "json-schema.org", "www.google.com", "play.google.com", "developer.android.com",
                "goo.gl", "github.com", "www.example.com", "example.com", "localhost")
COMPRESSED_EXT = (".png", ".jpg", ".jpeg", ".webp", ".gif", ".mp3", ".mp4", ".ogg", ".zip", ".gz", ".xz", ".7z", ".m4a",
                  ".aac", ".webm", ".woff", ".woff2", ".br", ".bundle", ".jsbundle", ".hbc", ".pak", ".obb", ".tflite", ".lz4", ".zst")


def entropy(b: bytes) -> float:
    if not b:
        return 0.0
    c = Counter(b)
    n = len(b)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def analyse_apk(data: bytes, name: str = "") -> dict:
    """Returns a report dict with keys: sha256, manifest, certs, strings-derived findings, urls, trackers, payloads."""
    rep: dict = {"file": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                 "findings": [], "urls": [], "ips": [], "trackers": [], "payloads": [], "certs": [], "native_libs": [],
                 "manifest": None, "dex_count": 0, "dex_bytes": 0, "errors": []}
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as e:
        rep["errors"].append(f"bad zip: {e}")
        return rep
    names = z.namelist()

    def f(i, sev, cat, title, mitre=None, ev=None):
        rep["findings"].append({"id": "apk." + i, "severity": sev, "category": cat, "title": title,
                                "mitre": mitre, "evidence": ev or []})

    # Manifest
    try:
        rep["manifest"] = manifest_info(z.read("AndroidManifest.xml"))
    except Exception as e:  # noqa: BLE001
        rep["errors"].append(f"manifest: {e}")

    # Certificates (v1 + v2/v3)
    for n in names:
        if re.match(r"META-INF/[^/]+\.(RSA|DSA|EC)$", n, re.I):
            c = pkcs7_first_cert(z.read(n))
            if c:
                rep["certs"].append({"scheme": "v1", "sha1": hashlib.sha1(c).hexdigest(), "sha256": hashlib.sha256(c).hexdigest(),
                                     "subject": cert_subject_hint(c)})
    for scheme, certs in signing_block_certs(data).items():
        for c in certs:
            rep["certs"].append({"scheme": scheme, "sha1": hashlib.sha1(c).hexdigest(), "sha256": hashlib.sha256(c).hexdigest(),
                                 "subject": cert_subject_hint(c)})
    if not rep["certs"]:
        f("unsigned", "MEDIUM", "SUSPICIOUS", "No signing certificate found in the APK")
    if any("Android Debug" in c["subject"] for c in rep["certs"]):
        f("debugcert", "MEDIUM", "SUSPICIOUS", "Signed with an Android debug certificate")

    # DEX strings
    strings: list[str] = []
    for n in names:
        if re.match(r"classes\d*\.dex$", n):
            d = z.read(n)
            rep["dex_count"] += 1
            rep["dex_bytes"] += len(d)
            strings.extend(dex_strings(d))
    blob = "\n".join(strings)
    sset = set(strings)
    for rid, needles, sev, cat, title, mitre in API_RULES:
        if all((nd[1:] in sset) if nd.startswith("=") else (nd in blob) for nd in needles):
            f(rid, sev, cat, title, mitre)
    rep["trackers"] = sorted({v for k, v in TRACKERS.items() if k in blob})
    for k, v in PACKER_CLASSES.items():
        if k in blob:
            f("packer.class", "MEDIUM", "SUSPICIOUS", f"Packed with {v}", "T1406.002", [k])
    hosts = Counter()
    for u in URL_RE.findall(blob):
        host = u.split("/")[2].split(":")[0].lower()
        if host.endswith(BENIGN_HOSTS) or not HOST_RE.fullmatch(host):
            continue
        tld = host.rsplit(".", 1)[-1]
        if not (len(tld) == 2 or tld in GTLDS or tld.isdigit() or tld.startswith("xn--")):
            continue
        hosts[host] += 1
        if len(rep["urls"]) < 300 and u not in rep["urls"]:
            rep["urls"].append(u)
    rep["hosts"] = [h for h, _ in hosts.most_common(200)]
    ips = {ip for ip in IP_RE.findall(blob) if not ip.startswith(("0.", "127.", "255.", "1.0.", "2.0.", "10.0.0.0"))
           and not re.match(r"^\d+\.0\.0\.0$", ip)}
    rep["ips"] = sorted(ips)[:100]
    if any(u.startswith("http://") and IP_RE.match(u[7:].split("/")[0].split(":")[0]) for u in rep["urls"]):
        f("http.ip", "MEDIUM", "SUSPICIOUS", "Hard-coded http:// URL to a raw IP address (typical C2)", "T1437.001",
          [u for u in rep["urls"] if IP_RE.match(u[7:].split("/")[0].split(":")[0])][:5])

    # Native libs, embedded payloads, encrypted assets
    small_dex = rep["dex_bytes"] < 150_000
    for info in z.infolist():
        n = info.filename
        base = n.rsplit("/", 1)[-1]
        if n.startswith("lib/") and n.endswith(".so"):
            rep["native_libs"].append(n)
            for k, v in PACKER_LIBS.items():
                if base.startswith(k):
                    f("packer.lib", "MEDIUM", "SUSPICIOUS", f"Packed with {v} ({base})", "T1406.002", [n])
            continue
        if n.startswith(("META-INF/", "res/drawable", "res/mipmap", "res/layout")) or re.match(r"classes\d*\.dex$", n):
            continue
        if info.file_size < 64:
            continue
        try:
            head = z.open(info).read(4096)
        except Exception:  # noqa: BLE001
            continue
        kind = None
        if head.startswith(b"dex\n"):
            kind = "DEX"
        elif head.startswith(b"\x7fELF"):
            kind = "ELF"
        elif head.startswith(b"PK\x03\x04") and base.lower().endswith((".apk", ".jar", ".dex", ".bin", ".dat", "")) and not base.lower().endswith((".zip", ".aar")):
            kind = "ZIP/APK"
        if kind:
            rep["payloads"].append({"path": n, "type": kind, "size": info.file_size})
            sev = "HIGH" if kind in ("DEX", "ELF") else "MEDIUM"
            f("payload", sev, "SUSPICIOUS", f"Embedded {kind} payload outside the normal locations: {n}", "T1407", [n])
        elif info.file_size > 200_000 and n.startswith(("assets/", "res/raw/")) and not base.lower().endswith(COMPRESSED_EXT):
            if entropy(head) > 7.95:
                rep["payloads"].append({"path": n, "type": "high-entropy", "size": info.file_size})
                if small_dex:
                    f("encrypted", "HIGH", "SUSPICIOUS", f"Tiny DEX + large encrypted asset ({n}): packed/dropper", "T1406.002", [n])

    # Manifest-based rules
    m = rep["manifest"] or {}
    for c in m.get("components", []):
        for flt in c.get("filters", []):
            acts = flt.get("actions", [])
            prio = flt.get("priority") or 0
            if "android.provider.Telephony.SMS_RECEIVED" in acts and isinstance(prio, int) and prio >= 999:
                f("sms.intercept", "HIGH", "SECURITY", f"SMS receiver with maximum priority ({prio}): SMS interception", "T1636.004", [c["name"]])
            if "android.intent.action.NEW_OUTGOING_CALL" in acts or "android.intent.action.PHONE_STATE" in acts:
                f("call.monitor", "LOW", "PRIVACY", "Monitors phone calls (PHONE_STATE / NEW_OUTGOING_CALL receiver)", "T1616", [c["name"]])
            if "android.intent.action.BOOT_COMPLETED" in acts:
                f("boot", "INFO", "SUSPICIOUS", "Starts at boot (BOOT_COMPLETED receiver)", "T1624.001", [c["name"]])
            if "android.app.action.DEVICE_ADMIN_ENABLED" in acts:
                f("admin.decl", "LOW", "SECURITY", "Declares a device administrator", "T1626.001", [c["name"]])
            if "android.accessibilityservice.AccessibilityService" in acts:
                f("acc.decl", "LOW", "PRIVACY", "Declares an accessibility service", "T1516", [c["name"]])
            if "android.provider.Telephony.SECRET_CODE" in acts or "android.telephony.action.SECRET_CODE" in acts:
                f("secret.code", "MEDIUM", "SUSPICIOUS", "Reacts to dialer secret codes (hidden-app re-launch trick)", "T1628.001", [c["name"]])
    if m.get("application", {}).get("debuggable") is True:
        f("debuggable", "LOW", "SECURITY", "android:debuggable=true")
    return rep
