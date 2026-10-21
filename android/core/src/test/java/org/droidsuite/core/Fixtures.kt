package org.droidsuite.core

/** Builders with safe defaults so each test only states what matters. */
object Fixtures {
    fun app(
        pkg: String,
        label: String = pkg,
        installer: String? = "com.android.vending",
        system: Boolean = false,
        launcher: Boolean = true,
        granted: Set<String> = emptySet(),
        cert: String = "aa".repeat(32),
        components: List<ComponentInfo> = emptyList(),
        nativeLibs: List<String> = emptyList(),
        targetSdk: Int = 33,
        sha: String? = "f".repeat(64),
    ) = AppRecord(
        pkg = pkg, label = label, uid = 10000, versionCode = 1, versionName = "1.0", installer = installer,
        initiatingInstaller = null, firstInstall = 0, lastUpdate = 0, system = system, updatedSystem = false,
        enabled = true, hasLauncher = launcher, debuggable = false, cleartext = false, targetSdk = targetSdk,
        sharedUserId = null, apkPaths = listOf("/data/app/$pkg/base.apk"), apkSize = 1, apkSha256 = sha,
        certSha256 = listOf(cert), certSha1 = emptyList(), certSubjects = listOf("CN=Test"), certHistorySha256 = emptyList(),
        requested = granted.toList(), granted = granted, components = components, nativeLibs = nativeLibs,
    )

    fun device(
        props: Map<String, String> = mapOf("ro.boot.verifiedbootstate" to "green", "ro.build.version.sdk" to "35"),
        accessibility: List<String> = emptyList(),
        admins: List<String> = emptyList(),
        overlay: Set<String> = emptySet(),
        userCas: List<String> = emptyList(),
        lock: Boolean = true,
    ) = DeviceState(
        props = props, rootIndicators = emptyList(), selinux = "Enforcing", adbEnabled = false, adbWifiEnabled = false,
        devOptions = false, verifierEnabled = true, screenLockSecure = lock, userCaCerts = userCas, vpnActive = false,
        httpProxy = null, privateDnsMode = null, privateDnsHost = null, enabledAccessibility = accessibility,
        enabledNotificationListeners = emptyList(), activeAdmins = admins, defaultSms = null, defaultIme = null,
        autofillService = null, overlayGranted = overlay, installSourcesAllowed = emptySet(), usageAccessGranted = true,
    )

    const val P = "android.permission."
    val TRUSTED = setOf("com.android.vending")
}
