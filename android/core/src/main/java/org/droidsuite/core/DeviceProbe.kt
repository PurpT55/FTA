package org.droidsuite.core

import android.app.AppOpsManager
import android.app.KeyguardManager
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Process
import android.provider.Settings
import android.provider.Telephony
import java.io.File
import java.security.KeyStore
import java.security.cert.X509Certificate

/** Collects device-wide security posture using only APIs open to normal apps. */
class DeviceProbe(private val ctx: Context) {

    companion object {
        val PROPS = listOf(
            "ro.build.fingerprint", "ro.build.tags", "ro.build.type", "ro.build.version.release",
            "ro.build.version.sdk", "ro.build.version.security_patch", "ro.product.manufacturer",
            "ro.product.model", "ro.debuggable", "ro.secure", "ro.boot.verifiedbootstate",
            "ro.boot.flash.locked", "ro.boot.vbmeta.device_state", "ro.boot.selinux",
            "ro.crypto.state", "ro.crypto.type", "persist.sys.usb.config", "service.adb.root",
            "ro.adb.secure", "init.svc.adbd", "ro.boot.veritymode", "ro.oem_unlock_supported",
        )
        val SU_PATHS = listOf(
            "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su", "/data/local/su",
            "/data/local/xbin/su", "/data/local/bin/su", "/system/sd/xbin/su", "/system/bin/failsafe/su",
            "/system/app/Superuser.apk", "/system/xbin/daemonsu", "/system/etc/init.d/99SuperSUDaemon",
            "/system/bin/.ext/.su", "/cache/su", "/data/adb/magisk", "/sbin/.magisk", "/data/adb/ksu",
        )
        val ROOT_PACKAGES = listOf(
            "com.topjohnwu.magisk", "eu.chainfire.supersu", "com.koushikdutta.superuser",
            "com.noshufou.android.su", "me.weishu.kernelsu", "com.kingroot.kinguser",
            "de.robv.android.xposed.installer", "org.lsposed.manager", "io.github.vvb2060.magisk",
        )
    }

    fun probe(): DeviceState {
        val props = PROPS.associateWith { Util.getprop(it) }
        val cr = ctx.contentResolver
        fun secure(k: String): String? = try { Settings.Secure.getString(cr, k) } catch (_: Exception) { null }
        fun global(k: String): String? = try { Settings.Global.getString(cr, k) } catch (_: Exception) { null }

        val root = ArrayList<String>()
        SU_PATHS.filter { File(it).exists() }.forEach { root.add("file:$it") }
        if (props["ro.build.tags"]?.contains("test-keys") == true) root.add("build tags test-keys")
        if (props["ro.debuggable"] == "1") root.add("ro.debuggable=1")
        if (props["ro.secure"] == "0") root.add("ro.secure=0")
        ROOT_PACKAGES.forEach { p ->
            try { ctx.packageManager.getPackageInfo(p, 0); root.add("package:$p") } catch (_: Exception) { }
        }
        try {
            File("/proc/self/mounts").readLines().filter { it.contains("magisk", true) || it.contains("/sbin/.core") }
                .take(3).forEach { root.add("mount:${it.take(120)}") }
        } catch (_: Exception) { }

        val selinux = Util.exec(listOf("getenforce"), 5).text.trim().ifEmpty { "unknown" }

        val dpm = ctx.getSystemService(DevicePolicyManager::class.java)
        val admins = dpm?.activeAdmins?.map { it.flattenToShortString() } ?: emptyList()

        val km = ctx.getSystemService(KeyguardManager::class.java)
        val cm = ctx.getSystemService(ConnectivityManager::class.java)
        val vpn = try {
            cm?.allNetworks?.any { cm.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true } ?: false
        } catch (_: Exception) { false }
        val proxy = try {
            cm?.defaultProxy?.let { "${it.host}:${it.port}" } ?: global("http_proxy")?.takeIf { it.isNotBlank() && it != ":0" }
        } catch (_: Exception) { null }

        val acc = secure(Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES)
            ?.split(':')?.filter { it.isNotBlank() } ?: emptyList()
        val nls = secure("enabled_notification_listeners")?.split(':')?.filter { it.isNotBlank() }

        return DeviceState(
            props = props,
            rootIndicators = root,
            selinux = selinux,
            adbEnabled = global(Settings.Global.ADB_ENABLED) == "1",
            adbWifiEnabled = global("adb_wifi_enabled") == "1",
            devOptions = global(Settings.Global.DEVELOPMENT_SETTINGS_ENABLED) == "1",
            verifierEnabled = global("package_verifier_enable")?.let { it != "0" },
            screenLockSecure = km?.isDeviceSecure ?: false,
            userCaCerts = userCas(),
            vpnActive = vpn,
            httpProxy = proxy,
            privateDnsMode = global("private_dns_mode"),
            privateDnsHost = global("private_dns_specifier"),
            enabledAccessibility = acc,
            enabledNotificationListeners = nls,
            activeAdmins = admins,
            defaultSms = try { Telephony.Sms.getDefaultSmsPackage(ctx) } catch (_: Exception) { null },
            defaultIme = secure(Settings.Secure.DEFAULT_INPUT_METHOD),
            autofillService = secure("autofill_service"),
            overlayGranted = opGrantedPackages("android:system_alert_window"),
            installSourcesAllowed = opGrantedPackages("android:request_install_packages"),
            usageAccessGranted = hasUsageAccess(ctx),
        )
    }

    /** User-installed CA certificates are a strong TLS interception (MITM) signal. */
    private fun userCas(): List<String> = try {
        val ks = KeyStore.getInstance("AndroidCAStore")
        ks.load(null)
        ks.aliases().toList().filter { it.startsWith("user:") }.map { alias ->
            val c = ks.getCertificate(alias) as? X509Certificate
            "${c?.subjectX500Principal?.name ?: alias} sha256=${c?.let { Util.digest("SHA-256", it.encoded) } ?: "?"}"
        }
    } catch (_: Exception) { emptyList() }

    /**
     * Checks an app-op for every app that requests the matching permission.
     * Checking other UIDs may be refused on some builds; those apps are then omitted.
     */
    private fun opGrantedPackages(op: String): Set<String> {
        val perm = when (op) {
            "android:system_alert_window" -> "android.permission.SYSTEM_ALERT_WINDOW"
            else -> "android.permission.REQUEST_INSTALL_PACKAGES"
        }
        val aom = ctx.getSystemService(AppOpsManager::class.java) ?: return emptySet()
        val out = HashSet<String>()
        @Suppress("DEPRECATION")
        val pkgs = try {
            ctx.packageManager.getPackagesHoldingPermissions(arrayOf(perm), 0)
        } catch (_: Exception) { emptyList() }
        // For app-op backed permissions PackageManager reports every requester as a holder,
        // so the app-op mode below is the real answer.
        for (p in pkgs) {
            val uid = p.applicationInfo?.uid ?: continue
            try {
                val mode = if (Build.VERSION.SDK_INT >= 29) aom.unsafeCheckOpNoThrow(op, uid, p.packageName)
                else @Suppress("DEPRECATION") aom.checkOpNoThrow(op, uid, p.packageName)
                if (mode == AppOpsManager.MODE_ALLOWED) out.add(p.packageName)
            } catch (_: Exception) { }
        }
        return out
    }
}

fun hasUsageAccess(ctx: Context): Boolean = try {
    val aom = ctx.getSystemService(AppOpsManager::class.java)
    val mode = if (Build.VERSION.SDK_INT >= 29)
        aom.unsafeCheckOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), ctx.packageName)
    else @Suppress("DEPRECATION") aom.checkOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), ctx.packageName)
    mode == AppOpsManager.MODE_ALLOWED
} catch (_: Exception) { false }
