package org.droidsuite.sentinel

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** Restarts the monitor after reboot/update, only if the user enabled it. */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(c: Context, i: Intent) {
        if (i.action != Intent.ACTION_BOOT_COMPLETED && i.action != Intent.ACTION_MY_PACKAGE_REPLACED) return
        if (Store.get(c).monitorEnabled) try { MonitorService.start(c) } catch (_: Exception) { }
    }
}
