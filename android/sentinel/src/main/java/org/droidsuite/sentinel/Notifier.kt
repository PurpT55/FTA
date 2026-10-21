package org.droidsuite.sentinel

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent

/** Notification channels: high-importance alerts and the low-importance foreground-service status. */
object Notifier {
    const val CH_ALERT = "alerts"
    const val CH_SERVICE = "service"
    private var nextId = 1000

    fun channels(ctx: Context) {
        val nm = ctx.getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(CH_ALERT, "Security alerts", NotificationManager.IMPORTANCE_HIGH))
        nm.createNotificationChannel(NotificationChannel(CH_SERVICE, "Monitor status", NotificationManager.IMPORTANCE_LOW))
    }

    fun openApp(ctx: Context): PendingIntent = PendingIntent.getActivity(
        ctx, 0, Intent(ctx, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
    )

    fun ongoing(ctx: Context, text: String): Notification {
        channels(ctx)
        return Notification.Builder(ctx, CH_SERVICE)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle("DroidSentinel monitoring")
            .setContentText(text)
            .setContentIntent(openApp(ctx))
            .setOngoing(true)
            .build()
    }

    fun alert(ctx: Context, title: String, text: String) {
        try {
            channels(ctx)
            val n = Notification.Builder(ctx, CH_ALERT)
                .setSmallIcon(android.R.drawable.stat_sys_warning)
                .setContentTitle(title)
                .setContentText(text)
                .setStyle(Notification.BigTextStyle().bigText(text))
                .setContentIntent(openApp(ctx))
                .setAutoCancel(true)
                .build()
            ctx.getSystemService(NotificationManager::class.java).notify(nextId++, n)
        } catch (_: SecurityException) { }
    }
}
