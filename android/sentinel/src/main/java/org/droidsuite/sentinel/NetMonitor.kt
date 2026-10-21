package org.droidsuite.sentinel

import android.app.usage.NetworkStats
import android.app.usage.NetworkStatsManager
import android.content.Context
import android.net.ConnectivityManager
import android.os.PowerManager
import org.droidsuite.core.Category
import org.droidsuite.core.Severity
import org.droidsuite.core.hasUsageAccess

/**
 * Per-app traffic accounting from NetworkStatsManager (needs Usage Access).
 * Android batches these statistics, so attribution lags by a few minutes: this is
 * near-real-time volume monitoring, complemented by the DNS monitor for "who talks to whom".
 */
class NetMonitor(private val ctx: Context) {
    private val store = Store.get(ctx)
    private val prev = HashMap<Int, LongArray>()
    private var primed = false

    private fun totals(): Map<Int, LongArray> {
        val nsm = ctx.getSystemService(NetworkStatsManager::class.java)
        val out = HashMap<Int, LongArray>()
        val start = System.currentTimeMillis() - 24L * 3600_000L
        val end = System.currentTimeMillis() + 3600_000L
        @Suppress("DEPRECATION")
        for (type in intArrayOf(ConnectivityManager.TYPE_WIFI, ConnectivityManager.TYPE_MOBILE)) {
            try {
                val stats = nsm.querySummary(type, null, start, end)
                val b = NetworkStats.Bucket()
                while (stats.hasNextBucket()) {
                    stats.getNextBucket(b)
                    val t = out.getOrPut(b.uid) { LongArray(2) }
                    t[0] += b.rxBytes; t[1] += b.txBytes
                }
                stats.close()
            } catch (_: Exception) { }
        }
        return out
    }

    fun poll() {
        if (!hasUsageAccess(ctx)) return
        val now = System.currentTimeMillis()
        val screenOn = ctx.getSystemService(PowerManager::class.java).isInteractive
        val cur = totals()
        if (!primed) { prev.putAll(cur); primed = true; return }
        val byPkg = Scanner.last?.apps?.associateBy { it.pkg } ?: emptyMap()
        val trusted = store.trustedInstallers
        val thresholdTx = store.bgUploadThresholdMb * 1024L * 1024L
        for ((uid, v) in cur) {
            val p = prev[uid] ?: LongArray(2)
            val drx = v[0] - p[0]; val dtx = v[1] - p[1]
            if (drx <= 0 && dtx <= 0) continue
            val pkgs = ctx.packageManager.getPackagesForUid(uid)
            val pkg = pkgs?.joinToString("|") ?: when (uid) {
                0 -> "root"; 1000 -> "android.system"; -4 -> "removed"; -5 -> "tethering"; else -> "uid:$uid"
            }
            val firstTime = !store.hasTrafficHistory(pkg)
            store.addTraffic(now, uid, pkg, maxOf(drx, 0), maxOf(dtx, 0), screenOn)
            val app = pkgs?.firstNotNullOfOrNull { byPkg[it] }
            if (app == null || app.system || app.pkg in Scanner.OWN) continue
            val sideloaded = app.installer == null || app.installer !in trusted
            if (firstTime && (sideloaded || !app.hasLauncher)) {
                store.addEvent(Event(now, Severity.LOW, Category.UNKNOWN, app.pkg, "net.first",
                    "First network activity: ${app.label}", "rx=${drx} tx=${dtx} screenOn=$screenOn"))
            }
            if (!screenOn && dtx > thresholdTx) {
                val sev = if (sideloaded || !app.hasLauncher) Severity.HIGH else Severity.MEDIUM
                store.addEvent(Event(now, sev, Category.SUSPICIOUS, app.pkg, "net.bgupload",
                    "Large upload while screen off: ${app.label}", "${dtx / 1024} KB sent since last poll"))
                if (sev == Severity.HIGH) Notifier.alert(ctx, "Background upload: ${app.label}", "${dtx / 1024} KB sent while the screen was off")
            }
            if (!app.hasLauncher && dtx > 512 * 1024) {
                store.addEvent(Event(now, Severity.MEDIUM, Category.SUSPICIOUS, app.pkg, "net.hidden",
                    "Hidden app uploading data: ${app.label}", "${dtx / 1024} KB"))
            }
        }
        prev.clear(); prev.putAll(cur)
    }
}
