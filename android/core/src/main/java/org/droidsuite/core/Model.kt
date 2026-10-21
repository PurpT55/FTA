package org.droidsuite.core

import org.json.JSONArray
import org.json.JSONObject

enum class Severity(val weight: Int) {
    INFO(0), LOW(1), MEDIUM(5), HIGH(15), CRITICAL(40);
}

/** Dashboard buckets. */
enum class Category { PRIVACY, SECURITY, SUSPICIOUS, UNKNOWN, MALWARE }

data class Finding(
    val id: String,
    val severity: Severity,
    val category: Category,
    val title: String,
    val detail: String,
    val pkg: String? = null,
    val mitre: String? = null,
) {
    fun toJson(): JSONObject = JSONObject()
        .put("id", id).put("severity", severity.name).put("category", category.name)
        .put("title", title).put("detail", detail).put("package", pkg ?: JSONObject.NULL)
        .put("mitre", mitre ?: JSONObject.NULL)
}

data class ComponentInfo(
    val type: String,               // activity|service|receiver|provider
    val name: String,
    val exported: Boolean,
    val permission: String?,
    val taskAffinity: String? = null,
    val launchMode: Int = 0,
    val allowTaskReparenting: Boolean = false,
    val authority: String? = null,
) {
    fun toJson(): JSONObject = JSONObject().put("type", type).put("name", name)
        .put("exported", exported).put("permission", permission ?: JSONObject.NULL)
        .apply {
            if (taskAffinity != null) put("taskAffinity", taskAffinity)
            if (type == "activity") put("launchMode", launchMode).put("allowTaskReparenting", allowTaskReparenting)
            if (authority != null) put("authority", authority)
        }
}

data class AppRecord(
    val pkg: String,
    val label: String,
    val uid: Int,
    val versionCode: Long,
    val versionName: String?,
    val installer: String?,
    val initiatingInstaller: String?,
    val firstInstall: Long,
    val lastUpdate: Long,
    val system: Boolean,
    val updatedSystem: Boolean,
    val enabled: Boolean,
    val hasLauncher: Boolean,
    val debuggable: Boolean,
    val cleartext: Boolean,
    val targetSdk: Int,
    val sharedUserId: String?,
    val apkPaths: List<String>,
    val apkSize: Long,
    var apkSha256: String?,
    val certSha256: List<String>,
    val certSha1: List<String>,
    val certSubjects: List<String>,
    val certHistorySha256: List<String>,
    val requested: List<String>,
    val granted: Set<String>,
    val components: List<ComponentInfo>,
    val nativeLibs: List<String>,
) {
    fun has(perm: String) = perm in granted
    fun requests(perm: String) = perm in requested
    fun servicesWith(permission: String) =
        components.filter { it.type == "service" && it.permission == permission }

    fun toJson(full: Boolean = true): JSONObject {
        val o = JSONObject()
            .put("package", pkg).put("label", label).put("uid", uid)
            .put("versionCode", versionCode).put("versionName", versionName ?: JSONObject.NULL)
            .put("installer", installer ?: JSONObject.NULL)
            .put("initiatingInstaller", initiatingInstaller ?: JSONObject.NULL)
            .put("firstInstallTime", Util.iso(firstInstall)).put("lastUpdateTime", Util.iso(lastUpdate))
            .put("firstInstallMs", firstInstall).put("lastUpdateMs", lastUpdate)
            .put("system", system).put("updatedSystem", updatedSystem).put("enabled", enabled)
            .put("hasLauncher", hasLauncher).put("debuggable", debuggable).put("cleartextTraffic", cleartext)
            .put("targetSdk", targetSdk).put("sharedUserId", sharedUserId ?: JSONObject.NULL)
            .put("apkPaths", JSONArray(apkPaths)).put("apkSize", apkSize)
            .put("apkSha256", apkSha256 ?: JSONObject.NULL)
            .put("certSha256", JSONArray(certSha256)).put("certSha1", JSONArray(certSha1))
            .put("certSubjects", JSONArray(certSubjects)).put("certHistorySha256", JSONArray(certHistorySha256))
            .put("nativeLibs", JSONArray(nativeLibs))
        if (full) {
            o.put("requestedPermissions", JSONArray(requested))
            o.put("grantedPermissions", JSONArray(granted.sorted()))
            o.put("components", JSONArray(components.map { it.toJson() }))
        }
        return o
    }
}

/** Device-wide state that the risk engine and both apps need. */
data class DeviceState(
    val props: Map<String, String>,
    val rootIndicators: List<String>,
    val selinux: String,
    val adbEnabled: Boolean,
    val adbWifiEnabled: Boolean,
    val devOptions: Boolean,
    val verifierEnabled: Boolean?,
    val screenLockSecure: Boolean,
    val userCaCerts: List<String>,
    val vpnActive: Boolean,
    val httpProxy: String?,
    val privateDnsMode: String?,
    val privateDnsHost: String?,
    val enabledAccessibility: List<String>,   // flattened component names
    val enabledNotificationListeners: List<String>?,
    val activeAdmins: List<String>,
    val defaultSms: String?,
    val defaultIme: String?,
    val autofillService: String?,
    val overlayGranted: Set<String>,
    val installSourcesAllowed: Set<String>,
    val usageAccessGranted: Boolean,
) {
    fun toJson(): JSONObject = JSONObject()
        .put("props", JSONObject(props as Map<*, *>))
        .put("rootIndicators", JSONArray(rootIndicators)).put("selinux", selinux)
        .put("adbEnabled", adbEnabled).put("adbWifiEnabled", adbWifiEnabled).put("devOptions", devOptions)
        .put("verifierEnabled", verifierEnabled ?: JSONObject.NULL).put("screenLockSecure", screenLockSecure)
        .put("userCaCerts", JSONArray(userCaCerts)).put("vpnActive", vpnActive)
        .put("httpProxy", httpProxy ?: JSONObject.NULL)
        .put("privateDnsMode", privateDnsMode ?: JSONObject.NULL).put("privateDnsHost", privateDnsHost ?: JSONObject.NULL)
        .put("enabledAccessibility", JSONArray(enabledAccessibility))
        .put("enabledNotificationListeners", enabledNotificationListeners?.let { JSONArray(it) } ?: JSONObject.NULL)
        .put("activeAdmins", JSONArray(activeAdmins)).put("defaultSms", defaultSms ?: JSONObject.NULL)
        .put("defaultIme", defaultIme ?: JSONObject.NULL).put("autofillService", autofillService ?: JSONObject.NULL)
        .put("overlayGranted", JSONArray(overlayGranted.sorted()))
        .put("installSourcesAllowed", JSONArray(installSourcesAllowed.sorted()))
        .put("usageAccessGranted", usageAccessGranted)
}
