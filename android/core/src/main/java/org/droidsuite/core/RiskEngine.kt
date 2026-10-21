package org.droidsuite.core

import java.text.SimpleDateFormat
import java.util.Locale

/** VirusTotal verdict for one SHA-256. positives < 0 means "not known to VT". */
data class VtVerdict(val sha256: String, val positives: Int, val total: Int, val label: String?, val checkedAt: Long)

data class AppScore(val pkg: String, val label: String, val privacy: Int, val security: Int)

data class RiskReport(
    val findings: List<Finding>,
    val appScores: Map<String, AppScore>,
    val privacyRisk: Int,
    val securityRisk: Int,
    val suspicious: Int,
    val unknownBinaries: List<String>,
    val malware: List<String>,
)

object RiskEngine {
    val DEFAULT_TRUSTED_INSTALLERS = setOf(
        "com.android.vending",               // Google Play
        "com.sec.android.app.samsungapps",   // Galaxy Store
        "com.huawei.appmarket",              // AppGallery
        "com.xiaomi.mipicks", "com.xiaomi.market",
        "com.amazon.venezia",                // Amazon Appstore
        "com.oppo.market", "com.heytap.market", "com.bbk.appstore",
        "org.fdroid.fdroid",                 // F-Droid (remove if you do not use it)
    )

    /** Rough sensitivity weight of each permission for the privacy score. */
    val PRIVACY_WEIGHTS = mapOf(
        "android.permission.ACCESS_BACKGROUND_LOCATION" to 12,
        "android.permission.ACCESS_FINE_LOCATION" to 8,
        "android.permission.ACCESS_COARSE_LOCATION" to 4,
        "android.permission.RECORD_AUDIO" to 10,
        "android.permission.CAMERA" to 8,
        "android.permission.READ_SMS" to 10,
        "android.permission.RECEIVE_SMS" to 8,
        "android.permission.SEND_SMS" to 8,
        "android.permission.READ_CALL_LOG" to 10,
        "android.permission.PROCESS_OUTGOING_CALLS" to 8,
        "android.permission.READ_CONTACTS" to 6,
        "android.permission.READ_CALENDAR" to 4,
        "android.permission.GET_ACCOUNTS" to 3,
        "android.permission.READ_PHONE_STATE" to 3,
        "android.permission.READ_PHONE_NUMBERS" to 3,
        "android.permission.BODY_SENSORS" to 5,
        "android.permission.ACTIVITY_RECOGNITION" to 3,
        "android.permission.READ_EXTERNAL_STORAGE" to 3,
        "android.permission.READ_MEDIA_IMAGES" to 4,
        "android.permission.READ_MEDIA_VIDEO" to 3,
        "android.permission.MANAGE_EXTERNAL_STORAGE" to 8,
        "android.permission.PACKAGE_USAGE_STATS" to 6,
        "android.permission.QUERY_ALL_PACKAGES" to 2,
        "android.permission.SYSTEM_ALERT_WINDOW" to 6,
        "android.permission.NEARBY_WIFI_DEVICES" to 2,
        "android.permission.BLUETOOTH_SCAN" to 2,
    )

    val PACKERS = mapOf(
        "libjiagu" to "Qihoo 360 Jiagu", "libsecexe" to "Bangcle", "libsecmain" to "Bangcle",
        "libDexHelper" to "Bangcle/SecNeo", "libshella" to "Tencent Legu", "libshellx" to "Tencent Legu",
        "libtup" to "Tencent", "libexec" to "ijiami", "libexecmain" to "ijiami", "libmobisec" to "Alibaba",
        "libnqshield" to "NQ Shield", "libapkprotect" to "APKProtect", "libprotectClass" to "Unknown packer",
    )

    private val SYSTEMISH_LABEL = Regex(
        "(?i)\\b(system|update|updater|service|services|google|android|wi-?fi|settings|security|sync|battery|device care|sim toolkit)\\b"
    )
    private val SYSTEMISH_PKG = Regex("^(com\\.android\\.|com\\.google\\.|android\\.|com\\.samsung\\.|com\\.qualcomm\\.)")

    private const val ACC = "android.permission.BIND_ACCESSIBILITY_SERVICE"
    private const val NLS = "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"
    private const val ADMIN = "android.permission.BIND_DEVICE_ADMIN"
    private const val IME = "android.permission.BIND_INPUT_METHOD"
    private const val AUTOFILL = "android.permission.BIND_AUTOFILL_SERVICE"
    private const val VPN = "android.permission.BIND_VPN_SERVICE"
    private const val INCALL = "android.permission.BIND_INCALL_SERVICE"

    fun evaluate(
        apps: List<AppRecord>,
        dev: DeviceState,
        iocs: IocDb,
        vt: Map<String, VtVerdict>,
        trusted: Set<String>,
        ownPackages: Set<String>,
    ): RiskReport {
        val f = ArrayList<Finding>()
        deviceFindings(dev, f)
        val platformCert = apps.firstOrNull { it.pkg == "android" }?.certSha256?.toSet() ?: emptySet()
        val labels = apps.groupBy { it.label.trim().lowercase() }
        val pkgNames = apps.map { it.pkg }.toSet()
        val accPkgs = dev.enabledAccessibility.map { it.substringBefore('/') }.toSet()
        val nlsPkgs = dev.enabledNotificationListeners?.map { it.substringBefore('/') }?.toSet() ?: emptySet()
        val adminPkgs = dev.activeAdmins.map { it.substringBefore('/') }.toSet()
        val imePkg = dev.defaultIme?.substringBefore('/')
        val autofillPkg = dev.autofillService?.substringBefore('/')
        val scores = HashMap<String, AppScore>()
        val unknown = ArrayList<String>()

        for (a in apps) {
            if (a.pkg in ownPackages) continue
            val before = f.size
            val sideloaded = !a.system && (a.installer == null || a.installer !in trusted)
            val p = a.pkg

            // --- Malware / IOC
            iocs.packages[p]?.let {
                f += Finding("ioc.package", Severity.CRITICAL, Category.MALWARE,
                    "Known ${it.kind} package: ${it.family}", "Package name $p is listed in the IOC database (${it.family}).", p, "T1636")
            }
            a.certSha1.forEach { c ->
                iocs.certSha1[c.lowercase()]?.let {
                    f += Finding("ioc.cert", Severity.CRITICAL, Category.MALWARE,
                        "Signed with a known ${it.kind} certificate (${it.family})", "Signing cert SHA-1 $c matches IOC.", p)
                }
            }
            a.apkSha256?.let { h ->
                iocs.hashes[h]?.let {
                    f += Finding("ioc.hash", Severity.CRITICAL, Category.MALWARE, "APK hash matches IOC (${it.family})", h, p)
                }
                vt[h]?.let { v ->
                    if (v.positives >= 3) f += Finding("vt.malicious", Severity.CRITICAL, Category.MALWARE,
                        "VirusTotal: ${v.positives}/${v.total} engines flag this APK", v.label ?: "", p)
                    else if (v.positives > 0) f += Finding("vt.low", Severity.MEDIUM, Category.SUSPICIOUS,
                        "VirusTotal: ${v.positives}/${v.total} detections (possible PUP/false positive)", v.label ?: "", p)
                }
            }
            if (sideloaded) {
                val v = a.apkSha256?.let { vt[it] }
                if (v == null || v.positives < 0) unknown += p
            }

            // --- Platform key abuse / firmware tampering
            if (!a.system && platformCert.isNotEmpty() && a.certSha256.any { it in platformCert }) {
                f += Finding("cert.platform", Severity.CRITICAL, Category.MALWARE,
                    "User app signed with the PLATFORM key",
                    "A non-system app shares the firmware signing key. This grants system-level privileges and is a known abuse of leaked OEM keys.", p, "T1404")
            }
            if (a.sharedUserId == "android.uid.system" && !a.system) {
                f += Finding("uid.system", Severity.CRITICAL, Category.SECURITY, "Non-system app runs as android.uid.system", "", p)
            }
            if (a.system && a.debuggable) {
                f += Finding("sys.debuggable", Severity.HIGH, Category.SECURITY, "Debuggable system app",
                    "Production firmware should never ship debuggable system apps (custom/modified ROM or engineering build).", p)
            }
            if (a.updatedSystem && a.installer != null && a.installer !in trusted && a.installer != "android") {
                f += Finding("sys.update.untrusted", Severity.HIGH, Category.SECURITY,
                    "System app updated from an untrusted source (${a.installer})", "", p, "T1645")
            }
            if (!a.system && a.certSubjects.any { it.contains("CN=Android Debug") }) {
                f += Finding("cert.debug", Severity.MEDIUM, Category.SUSPICIOUS, "Signed with an Android debug certificate",
                    "Released apps are never signed with the debug key; typical of repackaged or home-made builds.", p)
            }

            // --- Abusable bindings (accessibility, notification, admin, IME, autofill)
            if (p in accPkgs && !a.system) f += Finding("acc.enabled", Severity.HIGH, Category.SECURITY,
                "Accessibility service ENABLED",
                "Can read the whole screen, keystrokes and perform taps on your behalf (banking trojans, stalkerware).", p, "T1417.002 / T1516")
            else if (a.servicesWith(ACC).isNotEmpty() && sideloaded) f += Finding("acc.declared", Severity.LOW, Category.PRIVACY,
                "Declares an accessibility service (not enabled)", "", p)
            if (p in nlsPkgs && !a.system) f += Finding("nls.enabled", Severity.MEDIUM, Category.PRIVACY,
                "Notification listener ENABLED", "Can read every notification, including 2FA codes and messages.", p, "T1517")
            if (p in adminPkgs && !a.system) f += Finding("admin.active", Severity.HIGH, Category.SECURITY,
                "Active device administrator", "Can lock/wipe the device and resist uninstallation.", p, "T1626.001")
            if (p == imePkg && !a.system) f += Finding("ime.default", Severity.MEDIUM, Category.PRIVACY,
                "Third-party keyboard is the default input method", "A keyboard sees everything you type.", p, "T1417.001")
            else if (a.servicesWith(IME).isNotEmpty() && sideloaded) f += Finding("ime.declared", Severity.LOW, Category.PRIVACY,
                "Sideloaded app provides a keyboard", "", p)
            if (p == autofillPkg && !a.system) f += Finding("autofill.default", Severity.LOW, Category.PRIVACY,
                "Selected autofill service", "Receives the content of login forms.", p)
            if (a.servicesWith(VPN).isNotEmpty() && sideloaded) f += Finding("vpn.provider", Severity.MEDIUM, Category.SUSPICIOUS,
                "Sideloaded app can act as a VPN", "VPN apps can see/redirect all traffic.", p, "T1638")
            if (a.servicesWith(INCALL).isNotEmpty() && sideloaded) f += Finding("incall.provider", Severity.MEDIUM, Category.SUSPICIOUS,
                "Sideloaded app implements an in-call UI", "Can see and control phone calls.", p, "T1616")
            if (p in dev.overlayGranted && !a.system) {
                val combo = p in accPkgs
                f += Finding("overlay", if (combo) Severity.HIGH else Severity.LOW,
                    if (combo) Category.SECURITY else Category.PRIVACY,
                    if (combo) "Overlay + accessibility (classic banking-trojan combo)" else "Can draw over other apps",
                    "Overlays enable phishing screens on top of real apps and tapjacking.", p, "T1417.002")
            }
            if (!a.system && a.has("android.permission.READ_SMS") && a.has("android.permission.SEND_SMS") && p != dev.defaultSms) {
                f += Finding("sms.full", Severity.HIGH, Category.SECURITY, "Reads and sends SMS without being the SMS app",
                    "Typical of OTP stealers and premium-SMS fraud.", p, "T1636.004 / T1582")
            }

            // --- Task / activity hijacking (StrandHogg-style)
            a.components.filter { it.type == "activity" && it.taskAffinity != null && it.taskAffinity != p && !it.taskAffinity.startsWith("$p:") }
                .forEach { c ->
                    val target = c.taskAffinity!!
                    if (target in pkgNames && !a.system) {
                        f += Finding("task.hijack", Severity.HIGH, Category.SECURITY,
                            "Activity claims another app's task affinity ($target)",
                            "${c.name} can be inserted into $target's task (StrandHogg task hijacking: fake login screens).", p, "T1417.002")
                    } else if (c.allowTaskReparenting && !a.system && target.isNotEmpty()) {
                        f += Finding("task.reparent", Severity.LOW, Category.SUSPICIOUS,
                            "Activity with foreign taskAffinity + allowTaskReparenting", "${c.name} -> $target", p)
                    }
                }

            // --- Masquerading
            if (!a.system) {
                val same = labels[a.label.trim().lowercase()].orEmpty().filter { it.pkg != p }
                if (same.isNotEmpty() && sideloaded) f += Finding("mask.label", Severity.HIGH, Category.SUSPICIOUS,
                    "Same name as another installed app (${same.joinToString { it.pkg }})",
                    "Sideloaded app uses an identical label: possible impersonation.", p, "T1655.001")
                if (sideloaded && SYSTEMISH_PKG.containsMatchIn(p)) f += Finding("mask.pkg", Severity.HIGH, Category.SUSPICIOUS,
                    "Sideloaded app uses a system-like package name", "Package $p imitates a vendor namespace.", p, "T1655.001")
                else if (sideloaded && SYSTEMISH_LABEL.containsMatchIn(a.label)) f += Finding("mask.name", Severity.MEDIUM, Category.SUSPICIOUS,
                    "Sideloaded app with a system-sounding name (\"${a.label}\")", "", p, "T1655.001")
            }

            // --- Hidden + persistent + spyware capability profile
            val caps = listOf(
                a.has("android.permission.ACCESS_BACKGROUND_LOCATION") || a.has("android.permission.ACCESS_FINE_LOCATION"),
                a.has("android.permission.RECORD_AUDIO"),
                a.has("android.permission.READ_SMS"),
                a.has("android.permission.READ_CALL_LOG"),
                a.has("android.permission.READ_CONTACTS"),
                p in accPkgs, p in nlsPkgs, p in adminPkgs,
                a.has("android.permission.CAMERA"),
                a.requests("android.permission.RECEIVE_BOOT_COMPLETED"),
            ).count { it }
            val hidden = !a.system && !a.hasLauncher
            if (hidden && caps >= 2) f += Finding("hidden", Severity.HIGH, Category.SUSPICIOUS,
                "Hidden app (no launcher icon) with sensitive permissions", "$caps sensitive capabilities.", p, "T1628.001")
            if (sideloaded && caps >= 5) f += Finding("stalkerware.profile", Severity.HIGH, Category.SUSPICIOUS,
                "Surveillance capability profile ($caps/10)",
                "Sideloaded app combining location/mic/SMS/call log/contacts/accessibility/admin/boot. Matches stalkerware behaviour.", p, "T1430 / T1429 / T1636")

            // --- Supply / integrity hygiene
            if (sideloaded) f += Finding("install.untrusted", Severity.LOW, Category.UNKNOWN,
                "Installed outside a trusted store (installer: ${a.installer ?: "none/adb"})", "", p, "T1474")
            if (!a.system && a.requests("android.permission.REQUEST_INSTALL_PACKAGES") && p in dev.installSourcesAllowed && sideloaded)
                f += Finding("dropper", Severity.MEDIUM, Category.SUSPICIOUS,
                    "Sideloaded app allowed to install other apps", "Dropper capability.", p, "T1407")
            if (!a.system && a.targetSdk in 1..22) f += Finding("sdk.old", Severity.MEDIUM, Category.SECURITY,
                "Targets Android ${a.targetSdk} (pre-runtime-permissions)", "Old target SDK lets the app get dangerous permissions at install time.", p)
            if (!a.system && a.debuggable) f += Finding("app.debuggable", Severity.LOW, Category.SECURITY, "App is debuggable", "", p)
            a.nativeLibs.forEach { lib ->
                PACKERS.entries.firstOrNull { lib.startsWith(it.key) }?.let {
                    f += Finding("packer", Severity.MEDIUM, Category.SUSPICIOUS, "Packed/protected with ${it.value} ($lib)",
                        "Packers hide code from analysis; legitimate in some regional apps, common in malware.", p, "T1406.002")
                }
            }

            // --- Scores
            var priv = 0
            for ((perm, w) in PRIVACY_WEIGHTS) {
                if (a.has(perm)) priv += w else if (a.requests(perm)) priv += w / 4
            }
            if (p in accPkgs) priv += 15
            if (p in nlsPkgs) priv += 10
            if (p in adminPkgs) priv += 8
            if (a.cleartext && !a.system) priv += 2
            val sec = f.subList(before, f.size).filter { it.category != Category.PRIVACY }.sumOf { it.severity.weight }
            scores[p] = AppScore(p, a.label, priv.coerceAtMost(100), sec.coerceAtMost(100))
        }

        val top = scores.values.filter { s -> apps.firstOrNull { it.pkg == s.pkg }?.system == false }
            .map { it.privacy }.sortedDescending().take(10)
        val privacy = if (top.isEmpty()) 0 else (0.6 * top.first() + 0.4 * top.average()).toInt()
        val security = f.filter { it.category == Category.SECURITY || it.category == Category.MALWARE }
            .sumOf { it.severity.weight }.coerceAtMost(100)
        return RiskReport(
            findings = f.sortedByDescending { it.severity.ordinal },
            appScores = scores,
            privacyRisk = privacy.coerceAtMost(100),
            securityRisk = security,
            suspicious = f.count { it.category == Category.SUSPICIOUS && it.severity >= Severity.MEDIUM },
            unknownBinaries = unknown,
            malware = f.filter { it.category == Category.MALWARE }.mapNotNull { it.pkg }.distinct(),
        )
    }

    private fun deviceFindings(d: DeviceState, f: MutableList<Finding>) {
        if (d.rootIndicators.isNotEmpty()) f += Finding("dev.root", Severity.HIGH, Category.SECURITY,
            "Root / modification indicators", d.rootIndicators.joinToString("\n"), null, "T1404")
        val vb = d.props["ro.boot.verifiedbootstate"].orEmpty()
        if (vb.isNotEmpty() && vb != "green") f += Finding("dev.vb", Severity.HIGH, Category.SECURITY,
            "Verified boot state: $vb", "Not 'green': the OS image is not verified by the vendor key.")
        if (d.props["ro.boot.flash.locked"] == "0" || d.props["ro.boot.vbmeta.device_state"] == "unlocked")
            f += Finding("dev.unlocked", Severity.HIGH, Category.SECURITY, "Bootloader unlocked",
                "Anyone with physical access can flash a modified system.")
        if (d.selinux.equals("Permissive", true)) f += Finding("dev.selinux", Severity.HIGH, Category.SECURITY, "SELinux is permissive", "")
        if (d.adbWifiEnabled) f += Finding("dev.adbwifi", Severity.HIGH, Category.SECURITY, "Wireless debugging (ADB over Wi-Fi) is ON",
            "Anyone paired on the network can fully control the phone. Turn it off when not in use.")
        else if (d.adbEnabled) f += Finding("dev.adb", Severity.MEDIUM, Category.SECURITY, "USB debugging is ON",
            "Fine during an investigation; disable afterwards.")
        if (d.verifierEnabled == false) f += Finding("dev.playprotect", Severity.MEDIUM, Category.SECURITY,
            "Package verification (Play Protect) appears disabled", "Malware frequently disables Play Protect.", null, "T1629.003")
        if (!d.screenLockSecure) f += Finding("dev.nolock", Severity.HIGH, Category.SECURITY, "No secure screen lock",
            "Physical access = full access (the #1 way stalkerware gets installed).")
        if (d.userCaCerts.isNotEmpty()) f += Finding("dev.userca", Severity.HIGH, Category.SECURITY,
            "User-installed CA certificate(s)", "Enables HTTPS interception (MITM):\n" + d.userCaCerts.joinToString("\n"), null, "T1638")
        if (d.httpProxy != null) f += Finding("dev.proxy", Severity.HIGH, Category.SECURITY, "Global HTTP proxy set: ${d.httpProxy}", "", null, "T1638")
        if (d.vpnActive) f += Finding("dev.vpn", Severity.INFO, Category.PRIVACY, "A VPN is active", "Make sure you know which app provides it.")
        if (d.privateDnsMode == "hostname") f += Finding("dev.privatedns", Severity.INFO, Category.PRIVACY,
            "Private DNS (strict) to ${d.privateDnsHost}", "Sentinel's DNS monitor cannot see queries in strict Private DNS mode.")
        val patch = d.props["ro.build.version.security_patch"].orEmpty()
        try {
            val t = SimpleDateFormat("yyyy-MM-dd", Locale.US).parse(patch)!!.time
            val days = (System.currentTimeMillis() - t) / 86_400_000L
            if (days > 365) f += Finding("dev.patch", Severity.HIGH, Category.SECURITY, "Security patch is $days days old ($patch)",
                "Known, public exploits apply to this device.", null, "T1404")
            else if (days > 90) f += Finding("dev.patch", Severity.MEDIUM, Category.SECURITY, "Security patch is $days days old ($patch)", "")
        } catch (_: Exception) { }
        val sdk = d.props["ro.build.version.sdk"]?.toIntOrNull() ?: 99
        if (sdk < 31) f += Finding("dev.eol", Severity.MEDIUM, Category.SECURITY, "Android version likely out of support (API $sdk)", "")
    }
}
