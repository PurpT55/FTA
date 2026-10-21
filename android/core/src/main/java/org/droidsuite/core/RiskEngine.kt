package org.droidsuite.core

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

/**
 * Orchestrates [DeviceRules] and [AppRules] and computes the dashboard scores.
 * Scoring definitions are mirrored in analyzer/droidtriage/report.py (`summary`).
 */
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

    /** Privacy points for one app: weighted permissions (1/4 if only requested) + abusable roles. */
    fun privacyScore(a: AppRecord, ctx: RuleContext): Int {
        var priv = 0
        for ((perm, w) in PRIVACY_WEIGHTS) {
            if (a.has(perm)) priv += w else if (a.requests(perm)) priv += w / 4
        }
        if (a.pkg in ctx.accessibility) priv += 15
        if (a.pkg in ctx.notificationListeners) priv += 10
        if (a.pkg in ctx.admins) priv += 8
        if (a.cleartext && !a.system) priv += 2
        return priv.coerceAtMost(100)
    }

    /**
     * Runs [DeviceRules.ALL] once and [AppRules.ALL] on every app not in [ownPackages], then derives the
     * five dashboard numbers. Pure function: no Android API calls, unit-tested on the JVM.
     */
    fun evaluate(
        apps: List<AppRecord>,
        dev: DeviceState,
        iocs: IocDb,
        vt: Map<String, VtVerdict>,
        trusted: Set<String>,
        ownPackages: Set<String>,
        appRules: List<AppRule> = AppRules.ALL,
        deviceRules: List<DeviceRule> = DeviceRules.ALL,
    ): RiskReport {
        val ctx = RuleContext(apps, dev, iocs, vt, trusted)
        val f = ArrayList<Finding>()
        deviceRules.forEach { it.check(dev, f) }
        val scores = HashMap<String, AppScore>()
        val unknown = ArrayList<String>()
        for (a in apps) {
            if (a.pkg in ownPackages) continue
            val before = f.size
            appRules.forEach { it.check(a, ctx, f) }
            if (ctx.sideloaded(a)) {
                val v = a.apkSha256?.let { vt[it] }
                if (v == null || v.positives < 0) unknown += a.pkg
            }
            val sec = f.subList(before, f.size).filter { it.category != Category.PRIVACY }.sumOf { it.severity.weight }
            scores[a.pkg] = AppScore(a.pkg, a.label, privacyScore(a, ctx), sec.coerceAtMost(100))
        }
        val top = scores.values.filter { ctx.byPackage[it.pkg]?.system == false }.map { it.privacy }.sortedDescending().take(10)
        val privacy = if (top.isEmpty()) 0 else (0.6 * top.first() + 0.4 * top.average()).toInt()
        return RiskReport(
            findings = f.sortedByDescending { it.severity.ordinal },
            appScores = scores,
            privacyRisk = privacy.coerceAtMost(100),
            securityRisk = f.filter { it.category == Category.SECURITY || it.category == Category.MALWARE }
                .sumOf { it.severity.weight }.coerceAtMost(100),
            suspicious = f.count { it.category == Category.SUSPICIOUS && it.severity >= Severity.MEDIUM },
            unknownBinaries = unknown,
            malware = f.filter { it.category == Category.MALWARE }.mapNotNull { it.pkg }.distinct(),
        )
    }
}
