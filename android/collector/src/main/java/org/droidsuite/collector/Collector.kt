package org.droidsuite.collector

import android.accounts.AccountManager
import android.app.usage.NetworkStats
import android.app.usage.NetworkStatsManager
import android.app.usage.UsageEvents
import android.app.usage.UsageStatsManager
import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.Uri
import android.os.Build
import android.provider.Settings
import android.util.Base64
import org.droidsuite.core.AppRecord
import org.droidsuite.core.DeviceProbe
import org.droidsuite.core.Inventory
import org.droidsuite.core.IocDb
import org.droidsuite.core.RiskEngine
import org.droidsuite.core.Util
import org.droidsuite.core.hasUsageAccess
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.FilterOutputStream
import java.io.OutputStream
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.util.zip.Deflater
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

enum class Section(val title: String, val detail: String, val default: Boolean) {
    DEVICE("Device & security settings", "build props, settings, CA certificates, network config, accounts list", true),
    PACKAGES("App inventory", "every package: version, installer, signer, permissions, components, APK hashes", true),
    APKS_USER("APK files – user apps", "copies of installed (non-system) APKs incl. split APKs", true),
    APKS_SYSTEM("APK files – updated system apps", "system apps that were updated (large)", false),
    APKS_ALL_SYSTEM("APK files – ALL system apps", "full firmware app set (very large, 1–4 GB)", false),
    LOGS("Logcat", "main/system/crash/events/radio buffers (all apps only if READ_LOGS granted)", true),
    DUMPSYS("dumpsys", "~35 system services: accessibility, device policy, appops, jobs, alarms, netstats… (needs DUMP)", true),
    USAGE("Usage history", "7 days of app usage events + per-app network volume (needs Usage access)", true),
    PROC("/proc snapshot", "kernel version, mounts, cpu/mem, readable network tables", true),
    SENTINEL("DroidSentinel report", "real-time monitor events, DNS log, VirusTotal results (if installed)", true),
}

/** Streams everything into a single zip. Every entry is hashed; see manifest.json. */
class Collector(
    private val ctx: Context,
    private val sections: Set<Section>,
    private val progress: (String) -> Unit,
) {
    private val pm = ctx.packageManager
    private val manifest = JSONArray()
    private val errors = StringBuilder()
    private lateinit var zip: ZipOutputStream
    private var bytes = 0L

    companion object {
        val DUMPSYS = listOf(
            "package", "activity", "accessibility", "device_policy", "notification", "appops", "jobscheduler",
            "alarm", "usagestats", "netstats", "connectivity", "wifi", "location", "telecom", "telephony.registry",
            "account", "user", "settings", "input_method", "autofill", "role", "permission", "persistent_data_block",
            "battery", "batterystats", "power", "deviceidle", "media.camera", "audio", "media_projection",
            "sensorservice", "vpn_management", "dropbox --print", "procstats", "meminfo", "cpuinfo", "window windows",
            "overlay", "credential", "clipboard", "bluetooth_manager", "statusbar", "adb", "package_native",
        )
        val LOG_BUFFERS = listOf("main", "system", "crash", "events", "radio", "kernel")
        const val SENTINEL_URI = "content://org.droidsuite.sentinel.report/report.json"
    }

    // ---------------------------------------------------------------- zip helpers
    private inner class HashingStream(out: OutputStream) : FilterOutputStream(out) {
        val md: MessageDigest = MessageDigest.getInstance("SHA-256")
        var count = 0L
        override fun write(b: Int) { out.write(b); md.update(b.toByte()); count++ }
        override fun write(b: ByteArray, off: Int, len: Int) { out.write(b, off, len); md.update(b, off, len); count += len }
        override fun close() {}  // never close the zip stream underneath
    }

    private fun entry(name: String, store: Boolean = false, source: String? = null, writer: (OutputStream) -> Unit) {
        val t0 = System.currentTimeMillis()
        try {
            zip.setLevel(if (store) Deflater.NO_COMPRESSION else Deflater.BEST_SPEED)
            zip.putNextEntry(ZipEntry(name))
            val hs = HashingStream(zip)
            writer(hs)
            zip.closeEntry()
            bytes += hs.count
            manifest.put(JSONObject().put("path", name).put("size", hs.count).put("sha256", Util.hex(hs.md.digest()))
                .put("source", source ?: JSONObject.NULL).put("ms", System.currentTimeMillis() - t0))
        } catch (e: Exception) {
            err("$name: ${e.javaClass.simpleName}: ${e.message}")
            try { zip.closeEntry() } catch (_: Exception) { }
        }
    }

    private fun text(name: String, s: String, source: String? = null) = entry(name, source = source) { it.write(s.toByteArray()) }
    private fun json(name: String, o: Any) = entry(name) { it.write((if (o is JSONObject) o.toString(1) else (o as JSONArray).toString(1)).toByteArray()) }
    private fun err(s: String) { errors.append(s).append('\n') }

    private fun cmd(name: String, c: List<String>, timeout: Long = 60) {
        val r = Util.exec(c, timeout, 64 shl 20)
        entry(name, source = c.joinToString(" ")) {
            it.write(r.output)
            if (r.code != 0 || r.timedOut) it.write("\n# exit=${r.code} timedOut=${r.timedOut}\n".toByteArray())
        }
    }

    // ---------------------------------------------------------------- run
    fun run(dest: Uri): JSONObject {
        val t0 = System.currentTimeMillis()
        val out = ctx.contentResolver.openOutputStream(dest) ?: throw IllegalStateException("Cannot open destination")
        zip = ZipOutputStream(out.buffered(1 shl 20))
        var apps: List<AppRecord> = emptyList()
        if (Section.PACKAGES in sections || sections.any { it.name.startsWith("APKS") }) {
            progress("Inventorying packages (hashing APKs)…")
            apps = Inventory(ctx).scan(Section.PACKAGES in sections) { i, n -> if (i % 20 == 0) progress("Inventory $i/$n") }
        }
        if (Section.DEVICE in sections) device()
        if (Section.PACKAGES in sections) packages(apps)
        if (Section.PROC in sections) proc()
        if (Section.LOGS in sections) logs()
        if (Section.DUMPSYS in sections) dumpsys()
        if (Section.USAGE in sections) usage()
        if (Section.SENTINEL in sections) sentinel()
        apks(apps)

        val summary = JSONObject()
            .put("tool", "DroidCollector").put("formatVersion", 1)
            .put("startedAt", Util.iso(t0)).put("finishedAt", Util.iso(System.currentTimeMillis()))
            .put("durationMs", System.currentTimeMillis() - t0)
            .put("device", "${Build.MANUFACTURER} ${Build.MODEL} (Android ${Build.VERSION.RELEASE}, API ${Build.VERSION.SDK_INT})")
            .put("sections", JSONArray(sections.map { it.name }))
            .put("capabilities", capabilities(ctx))
            .put("files", manifest)
        text("collection_errors.txt", errors.toString())
        json("manifest.json", summary)
        zip.finish()
        zip.close()
        summary.put("totalBytes", bytes)
        return summary
    }

    // ---------------------------------------------------------------- sections
    private fun device() {
        progress("Device information…")
        val b = JSONObject()
        Build::class.java.fields.forEach { f -> try { b.put(f.name, f.get(null)?.toString()) } catch (_: Exception) { } }
        Build.VERSION::class.java.fields.forEach { f -> try { b.put("VERSION." + f.name, f.get(null)?.toString()) } catch (_: Exception) { } }
        json("device/build.json", b)
        cmd("device/getprop.txt", listOf("getprop"))
        val state = DeviceProbe(ctx).probe()
        json("device/device_state.json", state.toJson())
        for ((cls, label) in listOf(Settings.Global::class.java to "global", Settings.Secure::class.java to "secure", Settings.System::class.java to "system")) {
            val sb = StringBuilder()
            cls.fields.filter { it.type == String::class.java && java.lang.reflect.Modifier.isStatic(it.modifiers) }.forEach { f ->
                try {
                    val key = f.get(null) as String
                    val v = when (label) {
                        "global" -> Settings.Global.getString(ctx.contentResolver, key)
                        "secure" -> Settings.Secure.getString(ctx.contentResolver, key)
                        else -> Settings.System.getString(ctx.contentResolver, key)
                    }
                    if (v != null) sb.append(key).append('=').append(v).append('\n')
                } catch (_: Exception) { }
            }
            for (k in listOf("enabled_notification_listeners", "autofill_service", "adb_wifi_enabled", "package_verifier_enable",
                "private_dns_mode", "private_dns_specifier", "http_proxy", "always_on_vpn_app", "install_non_market_apps")) {
                try {
                    val v = if (label == "global") Settings.Global.getString(ctx.contentResolver, k) else if (label == "secure") Settings.Secure.getString(ctx.contentResolver, k) else null
                    if (v != null) sb.append(k).append('=').append(v).append('\n')
                } catch (_: Exception) { }
            }
            text("device/settings_$label.txt", sb.toString())
        }
        cmd("device/settings_cmd_secure.txt", listOf("settings", "list", "secure"), 15)
        // CA certificates
        try {
            val ks = KeyStore.getInstance("AndroidCAStore").apply { load(null) }
            val idx = StringBuilder()
            ks.aliases().toList().forEach { alias ->
                val c = ks.getCertificate(alias) as? X509Certificate ?: return@forEach
                idx.append("$alias\t${c.subjectX500Principal.name}\tsha256=${Util.digest("SHA-256", c.encoded)}\tnotAfter=${c.notAfter}\n")
                if (alias.startsWith("user:")) {
                    val pem = "-----BEGIN CERTIFICATE-----\n" + Base64.encodeToString(c.encoded, Base64.DEFAULT) + "-----END CERTIFICATE-----\n"
                    text("device/ca_user/${alias.replace(':', '_')}.pem", pem)
                }
            }
            text("device/ca_all.tsv", idx.toString())
        } catch (e: Exception) { err("CA store: ${e.message}") }
        // Networks
        try {
            val cm = ctx.getSystemService(ConnectivityManager::class.java)
            val sb = StringBuilder()
            @Suppress("DEPRECATION")
            cm.allNetworks.forEach { n ->
                sb.append("== $n\ncaps: ${cm.getNetworkCapabilities(n)}\nlink: ${cm.getLinkProperties(n)}\n\n")
            }
            sb.append("defaultProxy: ${cm.defaultProxy}\n")
            text("device/networks.txt", sb.toString())
        } catch (e: Exception) { err("networks: ${e.message}") }
        try {
            val acc = AccountManager.get(ctx).accounts.joinToString("\n") { "${it.type}\t${it.name}" }
            text("device/accounts_visible.txt", acc.ifEmpty { "(none visible to this app)" })
        } catch (e: Exception) { err("accounts: ${e.message}") }
    }

    private fun packages(apps: List<AppRecord>) {
        progress("Writing package inventory…")
        json("packages/packages.json", JSONArray(apps.map { it.toJson(true) }))
        val tsv = StringBuilder("package\tlabel\tversion\tinstaller\tsystem\tlauncher\tfirstInstall\tlastUpdate\tsha256\tsignerSha256\n")
        apps.forEach {
            tsv.append("${it.pkg}\t${it.label}\t${it.versionName}\t${it.installer}\t${it.system}\t${it.hasLauncher}\t" +
                "${Util.iso(it.firstInstall)}\t${Util.iso(it.lastUpdate)}\t${it.apkSha256}\t${it.certSha256.joinToString(",")}\n")
        }
        text("packages/packages.tsv", tsv.toString())
        // On-device pre-assessment (same engine as Sentinel, without VirusTotal).
        try {
            val iocs = IocDb()
            val r = RiskEngine.evaluate(apps, DeviceProbe(ctx).probe(), iocs, emptyMap(), RiskEngine.DEFAULT_TRUSTED_INSTALLERS,
                setOf(ctx.packageName, "org.droidsuite.sentinel"))
            json("packages/ondevice_findings.json", JSONArray(r.findings.map { it.toJson() }))
        } catch (e: Exception) { err("risk engine: ${e.message}") }
    }

    private fun proc() {
        progress("/proc snapshot…")
        for (f in listOf("version", "cpuinfo", "meminfo", "mounts", "uptime", "cmdline", "filesystems", "modules",
            "net/tcp", "net/tcp6", "net/udp", "net/udp6", "net/unix", "net/route", "net/arp", "net/if_inet6")) {
            try {
                val data = File("/proc/$f").readBytes()
                entry("proc/${f.replace('/', '_')}.txt", source = "/proc/$f") { it.write(data) }
            } catch (e: Exception) { err("/proc/$f: ${e.message}") }
        }
        cmd("proc/ps.txt", listOf("ps", "-A", "-o", "USER,PID,PPID,NAME"), 15)
        cmd("proc/id.txt", listOf("id"), 5)
        cmd("proc/getenforce.txt", listOf("getenforce"), 5)
    }

    private fun logs() {
        for (b in LOG_BUFFERS) {
            progress("logcat -b $b…")
            cmd("logs/logcat_$b.txt", listOf("logcat", "-b", b, "-d", "-v", "threadtime", "-v", "uid"), 120)
        }
        cmd("logs/logcat_last_boot.txt", listOf("logcat", "-L", "-d", "-v", "threadtime"), 60)
        cmd("logs/logcat_stats.txt", listOf("logcat", "-S"), 30)
    }

    private fun dumpsys() {
        cmd("dumpsys/_services.txt", listOf("dumpsys", "-l"), 30)
        for (s in DUMPSYS) {
            progress("dumpsys $s…")
            cmd("dumpsys/${s.replace(' ', '_').replace("--", "")}.txt", listOf("dumpsys") + s.split(' '), 90)
        }
    }

    private fun usage() {
        if (!hasUsageAccess(ctx)) { err("usage: Usage access not granted"); return }
        progress("Usage events…")
        val usm = ctx.getSystemService(UsageStatsManager::class.java)
        val end = System.currentTimeMillis()
        val start = end - 7L * 86_400_000L
        entry("usage/usage_events.tsv") { out ->
            out.write("time\tpackage\tclass\teventType\n".toByteArray())
            val ev = usm.queryEvents(start, end)
            val e = UsageEvents.Event()
            while (ev.hasNextEvent()) {
                ev.getNextEvent(e)
                out.write("${Util.iso(e.timeStamp)}\t${e.packageName}\t${e.className ?: ""}\t${e.eventType}\n".toByteArray())
            }
        }
        entry("usage/usage_daily.tsv") { out ->
            out.write("day\tpackage\tforegroundMs\tlastUsed\n".toByteArray())
            usm.queryUsageStats(UsageStatsManager.INTERVAL_DAILY, start, end).forEach {
                out.write("${Util.iso(it.firstTimeStamp)}\t${it.packageName}\t${it.totalTimeInForeground}\t${Util.iso(it.lastTimeUsed)}\n".toByteArray())
            }
        }
        progress("Network statistics…")
        val nsm = ctx.getSystemService(NetworkStatsManager::class.java)
        entry("usage/netstats_uid.tsv") { out ->
            out.write("network\tuid\tpackages\tstart\tend\trxBytes\ttxBytes\tstate\n".toByteArray())
            @Suppress("DEPRECATION")
            for ((t, name) in listOf(ConnectivityManager.TYPE_WIFI to "wifi", ConnectivityManager.TYPE_MOBILE to "mobile")) {
                try {
                    val st = nsm.querySummary(t, null, end - 30L * 86_400_000L, end)
                    val b = NetworkStats.Bucket()
                    while (st.hasNextBucket()) {
                        st.getNextBucket(b)
                        val pk = pm.getPackagesForUid(b.uid)?.joinToString("|") ?: ""
                        out.write("$name\t${b.uid}\t$pk\t${Util.iso(b.startTimeStamp)}\t${Util.iso(b.endTimeStamp)}\t${b.rxBytes}\t${b.txBytes}\t${b.state}\n".toByteArray())
                    }
                    st.close()
                } catch (e: Exception) { err("netstats $name: ${e.message}") }
            }
        }
    }

    private fun sentinel() {
        progress("Reading DroidSentinel report…")
        try {
            ctx.contentResolver.openInputStream(Uri.parse(SENTINEL_URI))?.use { ins ->
                entry("sentinel/report.json", source = SENTINEL_URI) { ins.copyTo(it) }
            } ?: err("sentinel: provider returned nothing")
        } catch (e: Exception) {
            err("sentinel: ${e.javaClass.simpleName} ${e.message} (not installed, or not signed with the same key)")
        }
    }

    private fun apks(apps: List<AppRecord>) {
        val pick = apps.filter { a ->
            (Section.APKS_USER in sections && !a.system) ||
                (Section.APKS_SYSTEM in sections && a.updatedSystem) ||
                (Section.APKS_ALL_SYSTEM in sections && a.system)
        }.filter { it.pkg != ctx.packageName }
        pick.forEachIndexed { i, a ->
            progress("APK ${i + 1}/${pick.size}: ${a.pkg}")
            a.apkPaths.forEach { path ->
                val f = File(path)
                if (!f.canRead()) { err("apk unreadable: $path"); return@forEach }
                entry("apks/${a.pkg}/${f.name}", store = true, source = path) { out -> f.inputStream().use { it.copyTo(out, 1 shl 16) } }
            }
        }
    }
}

fun capabilities(ctx: Context): JSONObject = JSONObject()
    .put("READ_LOGS", ctx.checkSelfPermission("android.permission.READ_LOGS") == PackageManager.PERMISSION_GRANTED)
    .put("DUMP", ctx.checkSelfPermission("android.permission.DUMP") == PackageManager.PERMISSION_GRANTED)
    .put("USAGE_ACCESS", hasUsageAccess(ctx))
    .put("SENTINEL_REPORT", ctx.checkSelfPermission("org.droidsuite.permission.READ_REPORT") == PackageManager.PERMISSION_GRANTED)
