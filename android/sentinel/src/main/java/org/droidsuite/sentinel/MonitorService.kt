package org.droidsuite.sentinel

import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.os.IBinder
import org.droidsuite.core.Category
import org.droidsuite.core.Severity

/**
 * Foreground monitor: reacts instantly to package installs/updates/removals,
 * rescans every 15 min (integrity + risk) and polls traffic every 2 min.
 */
class MonitorService : Service() {
    companion object {
        const val SCAN_MS = 15 * 60_000L
        const val NET_MS = 2 * 60_000L
        @Volatile var running = false

        fun start(ctx: Context) {
            Store.get(ctx).monitorEnabled = true
            ctx.startForegroundService(Intent(ctx, MonitorService::class.java))
        }

        fun stop(ctx: Context) {
            Store.get(ctx).monitorEnabled = false
            ctx.stopService(Intent(ctx, MonitorService::class.java))
        }
    }

    private lateinit var thread: HandlerThread
    private lateinit var h: Handler
    private lateinit var net: NetMonitor

    private val pkgReceiver = object : BroadcastReceiver() {
        override fun onReceive(c: Context, i: Intent) {
            val pkg = i.data?.schemeSpecificPart ?: return
            val store = Store.get(c)
            val title = when (i.action) {
                Intent.ACTION_PACKAGE_ADDED -> if (i.getBooleanExtra(Intent.EXTRA_REPLACING, false)) "Package replaced" else "Package added"
                Intent.ACTION_PACKAGE_REPLACED -> "Package updated"
                Intent.ACTION_PACKAGE_REMOVED -> if (i.getBooleanExtra(Intent.EXTRA_REPLACING, false)) return else "Package removed"
                Intent.ACTION_PACKAGE_CHANGED -> "Package components changed"
                else -> return
            }
            store.addEvent(Event(System.currentTimeMillis(), Severity.INFO, Category.UNKNOWN, pkg, "pkg.broadcast", "$title: $pkg",
                i.getStringArrayExtra(Intent.EXTRA_CHANGED_COMPONENT_NAME_LIST)?.joinToString() ?: ""))
            // Re-scan shortly after so integrity diffing classifies the change.
            h.removeCallbacks(scanTask)
            h.postDelayed(scanTask, 5_000)
        }
    }

    private val scanTask = object : Runnable {
        override fun run() {
            try { Scanner.scan(this@MonitorService); Store.get(this@MonitorService).prune() } catch (_: Exception) { }
            updateNotification()
            h.removeCallbacks(this)
            h.postDelayed(this, SCAN_MS)
        }
    }

    private val netTask = object : Runnable {
        override fun run() {
            try { net.poll() } catch (_: Exception) { }
            h.postDelayed(this, NET_MS)
        }
    }

    override fun onCreate() {
        super.onCreate()
        thread = HandlerThread("sentinel-monitor").also { it.start() }
        h = Handler(thread.looper)
        net = NetMonitor(this)
        val f = IntentFilter().apply {
            addAction(Intent.ACTION_PACKAGE_ADDED); addAction(Intent.ACTION_PACKAGE_REPLACED)
            addAction(Intent.ACTION_PACKAGE_REMOVED); addAction(Intent.ACTION_PACKAGE_CHANGED)
            addDataScheme("package")
        }
        if (Build.VERSION.SDK_INT >= 33) registerReceiver(pkgReceiver, f, Context.RECEIVER_NOT_EXPORTED)
        else registerReceiver(pkgReceiver, f)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val n = Notifier.ongoing(this, "Watching packages, integrity and traffic")
        if (Build.VERSION.SDK_INT >= 34) startForeground(1, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        else startForeground(1, n)
        if (!running) {
            running = true
            h.post(scanTask)
            h.postDelayed(netTask, 10_000)
        }
        return START_STICKY
    }

    private fun updateNotification() {
        val r = Scanner.last ?: return
        val t = "Security ${r.report.securityRisk} · Privacy ${r.report.privacyRisk} · Malware ${r.report.malware.size}"
        getSystemService(android.app.NotificationManager::class.java).notify(1, Notifier.ongoing(this, t))
    }

    override fun onDestroy() {
        running = false
        try { unregisterReceiver(pkgReceiver) } catch (_: Exception) { }
        h.removeCallbacksAndMessages(null)
        thread.quitSafely()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null
}
