package org.droidsuite.core

/**
 * Everything an [AppRule] may need, computed once per evaluation so rules stay O(1) per app.
 *
 * Same semantics as the Python analyzer's `Context` (analyzer/droidtriage/model.py): keep the two in
 * sync when adding fields that rules depend on.
 */
class RuleContext(
    val apps: List<AppRecord>,
    val device: DeviceState,
    val iocs: IocDb,
    val vt: Map<String, VtVerdict>,
    val trusted: Set<String>,
) {
    val byPackage: Map<String, AppRecord> = apps.associateBy { it.pkg }
    /** Signing certificate(s) of the `android` package = firmware platform key. */
    val platformCerts: Set<String> = byPackage["android"]?.certSha256?.toSet() ?: emptySet()
    val labels: Map<String, List<AppRecord>> = apps.groupBy { it.label.trim().lowercase() }
    val accessibility: Set<String> = device.enabledAccessibility.map { it.substringBefore('/') }.toSet()
    val notificationListeners: Set<String> =
        device.enabledNotificationListeners?.map { it.substringBefore('/') }?.toSet() ?: emptySet()
    val admins: Set<String> = device.activeAdmins.map { it.substringBefore('/') }.toSet()
    val ime: String? = device.defaultIme?.substringBefore('/')
    val autofill: String? = device.autofillService?.substringBefore('/')

    /** Non-system app whose installer is missing (adb / package installer UI) or not a trusted store. */
    fun sideloaded(a: AppRecord): Boolean = !a.system && (a.installer == null || a.installer !in trusted)

    /** Count of surveillance capabilities (0-10) used by the hidden-app and stalkerware-profile rules. */
    fun capabilityCount(a: AppRecord): Int = listOf(
        a.has("android.permission.ACCESS_BACKGROUND_LOCATION") || a.has("android.permission.ACCESS_FINE_LOCATION"),
        a.has("android.permission.RECORD_AUDIO"),
        a.has("android.permission.READ_SMS"),
        a.has("android.permission.READ_CALL_LOG"),
        a.has("android.permission.READ_CONTACTS"),
        a.pkg in accessibility, a.pkg in notificationListeners, a.pkg in admins,
        a.has("android.permission.CAMERA"),
        a.requests("android.permission.RECEIVE_BOOT_COMPLETED"),
    ).count { it }
}

/**
 * One family of per-app checks. Implementations append to [out] and must not throw.
 * Register new rules in [AppRules.ALL].
 */
fun interface AppRule {
    fun check(a: AppRecord, ctx: RuleContext, out: MutableList<Finding>)
}

/** One family of device-wide checks. Register new rules in [DeviceRules.ALL]. */
fun interface DeviceRule {
    fun check(d: DeviceState, out: MutableList<Finding>)
}
