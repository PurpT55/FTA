package org.droidsuite.sentinel

import android.content.Context
import org.droidsuite.core.AppRecord
import org.droidsuite.core.Category
import org.droidsuite.core.DeviceProbe
import org.droidsuite.core.DeviceState
import org.droidsuite.core.Finding
import org.droidsuite.core.HashPolicy
import org.droidsuite.core.Inventory
import org.droidsuite.core.IocDb
import org.droidsuite.core.RiskEngine
import org.droidsuite.core.RiskReport
import org.droidsuite.core.Severity
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

class ScanResult(val ts: Long, val apps: List<AppRecord>, val device: DeviceState, val report: RiskReport)

/** Full scan + integrity diff against the stored baseline. */
object Scanner {
    @Volatile var last: ScanResult? = null
    private val lock = Object()
    val OWN = setOf("org.droidsuite.sentinel", "org.droidsuite.collector")

    fun iocs(ctx: Context): IocDb = IocDb().apply { loadDir(File(ctx.filesDir, "iocs").apply { mkdirs() }) }

    fun scan(ctx: Context, progress: ((Int, Int) -> Unit)? = null): ScanResult = synchronized(lock) {
        val store = Store.get(ctx)
        val apps = Inventory(ctx).scan(HashPolicy.USER_AND_UPDATED, progress)
        val dev = DeviceProbe(ctx).probe()
        val trusted = store.trustedInstallers
        diffBaseline(ctx, store, apps, trusted)
        val report = RiskEngine.evaluate(apps, dev, iocs(ctx), store.vtAll(), trusted, OWN)
        alertNewFindings(ctx, store, report.findings)
        val r = ScanResult(System.currentTimeMillis(), apps, dev, report)
        last = r
        store.prefs.edit().putLong("last_scan", r.ts).apply()
        if (store.autoVt) queueVt(ctx, r)
        return r
    }

    /** Sideloaded apps first, then other user apps. System apps are skipped (quota). */
    fun queueVt(ctx: Context, r: ScanResult, onDone: (() -> Unit)? = null) {
        val trusted = Store.get(ctx).trustedInstallers
        val items = r.apps.filter { !it.system && it.pkg !in OWN && it.apkSha256 != null }
            .sortedBy { if (it.installer in trusted) 1 else 0 }
            .map { it.pkg to it.apkSha256!! }
        VtClient(ctx).enqueue(items, onDone)
    }

    private fun snapshot(a: AppRecord) = JSONObject()
        .put("versionCode", a.versionCode).put("versionName", a.versionName ?: "")
        .put("lastUpdate", a.lastUpdate).put("firstInstall", a.firstInstall)
        .put("sha256", a.apkSha256 ?: "").put("certs", a.certSha256.sorted().joinToString(","))
        .put("history", a.certHistorySha256.joinToString(","))
        .put("installer", a.installer ?: "").put("path", a.apkPaths.firstOrNull() ?: "")
        .put("system", a.system).put("launcher", a.hasLauncher)

    private fun diffBaseline(ctx: Context, store: Store, apps: List<AppRecord>, trusted: Set<String>) {
        val base = store.baseline()
        val now = System.currentTimeMillis()
        fun ev(sev: Severity, cat: Category, pkg: String?, type: String, title: String, detail: String, notify: Boolean = sev >= Severity.HIGH) {
            store.addEvent(Event(now, sev, cat, pkg, type, title, detail))
            if (notify) Notifier.alert(ctx, title, "${pkg ?: ""}\n$detail")
        }
        if (base.isEmpty()) {
            apps.forEach { store.putBaseline(it.pkg, snapshot(it)) }
            ev(Severity.INFO, Category.UNKNOWN, null, "baseline", "Integrity baseline created for ${apps.size} packages", "", false)
            return
        }
        val seen = HashSet<String>()
        for (a in apps) {
            seen += a.pkg
            val cur = snapshot(a)
            val old = base[a.pkg]
            if (old == null) {
                val side = !a.system && (a.installer == null || a.installer !in trusted)
                val sev = when {
                    side && !a.hasLauncher -> Severity.HIGH
                    side -> Severity.MEDIUM
                    else -> Severity.LOW
                }
                ev(sev, Category.UNKNOWN, a.pkg, "install", "New app installed: ${a.label}",
                    "installer=${a.installer ?: "none/adb"} launcherIcon=${a.hasLauncher} sha256=${a.apkSha256}", sev >= Severity.MEDIUM)
                store.putBaseline(a.pkg, cur)
                continue
            }
            val certsChanged = old.optString("certs") != cur.optString("certs")
            val hashChanged = old.optString("sha256").isNotEmpty() && cur.optString("sha256").isNotEmpty() &&
                old.optString("sha256") != cur.optString("sha256")
            val vOld = old.optLong("versionCode"); val vNew = a.versionCode
            val updOld = old.optLong("lastUpdate")
            if (certsChanged) {
                val rotated = old.optString("certs").split(',').all { it.isEmpty() || cur.optString("history").contains(it) }
                if (rotated) ev(Severity.INFO, Category.SECURITY, a.pkg, "cert.rotation", "Signing key rotated (APK Signature Scheme v3)", "")
                else ev(Severity.CRITICAL, Category.SECURITY, a.pkg, "cert.changed", "Signing certificate CHANGED: ${a.label}",
                    "old=${old.optString("certs")}\nnew=${cur.optString("certs")}\nThe app was replaced by a binary from a different author.")
            }
            if (hashChanged && vNew == vOld && a.lastUpdate == updOld) {
                ev(Severity.HIGH, Category.SECURITY, a.pkg, "apk.tampered", "APK changed on disk without any update: ${a.label}",
                    "Same versionCode $vNew and same install time but different SHA-256. Possible on-device tampering (T1645).")
            } else if (hashChanged && vNew == vOld) {
                ev(Severity.MEDIUM, Category.SUSPICIOUS, a.pkg, "apk.reinstalled", "Same version reinstalled with a different binary: ${a.label}",
                    "versionCode $vNew, installer ${a.installer}. Could be a repackaged copy.")
            }
            if (vNew < vOld) ev(Severity.MEDIUM, Category.SECURITY, a.pkg, "downgrade", "App downgraded: ${a.label}", "$vOld -> $vNew")
            if (old.optString("installer") != cur.optString("installer"))
                ev(Severity.MEDIUM, Category.SUSPICIOUS, a.pkg, "installer.changed", "Installer changed for ${a.label}",
                    "${old.optString("installer")} -> ${cur.optString("installer")}")
            if (old.optBoolean("launcher") && !a.hasLauncher && !a.system)
                ev(Severity.HIGH, Category.SUSPICIOUS, a.pkg, "icon.hidden", "App hid its launcher icon: ${a.label}",
                    "Typical stalkerware / malware behaviour after first launch (T1628.001).")
            if (vNew > vOld) ev(Severity.INFO, Category.UNKNOWN, a.pkg, "update", "Updated ${a.label}",
                "${old.optString("versionName")} -> ${a.versionName} via ${a.installer ?: "none/adb"}", false)
            store.putBaseline(a.pkg, cur)
        }
        base.keys.filter { it !in seen }.forEach {
            ev(Severity.INFO, Category.UNKNOWN, it, "uninstall", "App removed: $it", "", false)
            store.removeBaseline(it)
        }
    }

    private fun alertNewFindings(ctx: Context, store: Store, findings: List<Finding>) {
        val keys = findings.filter { it.severity >= Severity.HIGH }.map { "${it.id}|${it.pkg}" }.toSet()
        val prev = store.prefs.getStringSet("finding_keys", null)
        if (prev != null) {
            findings.filter { it.severity >= Severity.HIGH && "${it.id}|${it.pkg}" !in prev }.forEach {
                store.addEvent(Event(System.currentTimeMillis(), it.severity, it.category, it.pkg, "finding", it.title, it.detail))
                Notifier.alert(ctx, it.title, "${it.pkg ?: "device"}\n${it.detail}")
            }
        }
        store.prefs.edit().putStringSet("finding_keys", keys).apply()
    }

    fun reportJson(ctx: Context, r: ScanResult): JSONObject {
        val store = Store.get(ctx)
        val rep = r.report
        return JSONObject()
            .put("tool", "DroidSentinel").put("version", 1).put("generatedAt", System.currentTimeMillis())
            .put("scanTime", r.ts)
            .put("scores", JSONObject().put("privacyRisk", rep.privacyRisk).put("securityRisk", rep.securityRisk)
                .put("suspicious", rep.suspicious).put("unknownBinaries", JSONArray(rep.unknownBinaries))
                .put("malware", JSONArray(rep.malware)))
            .put("device", r.device.toJson())
            .put("findings", JSONArray(rep.findings.map { it.toJson() }))
            .put("appScores", JSONObject().apply {
                rep.appScores.values.forEach { put(it.pkg, JSONObject().put("privacy", it.privacy).put("security", it.security)) }
            })
            .put("monitor", store.exportJson(System.currentTimeMillis() - 30L * 86_400_000L))
    }
}
