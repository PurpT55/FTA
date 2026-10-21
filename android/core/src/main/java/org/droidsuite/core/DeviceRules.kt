package org.droidsuite.core

import java.text.SimpleDateFormat
import java.util.Locale

/**
 * Device-wide detection rules. Ids match analyzer/droidtriage/system.py so on-device and offline
 * reports can be compared. Register new rules in [ALL].
 */
object DeviceRules {
    /** Root, verified boot, bootloader, SELinux. */
    val integrity = DeviceRule { d, out ->
        if (d.rootIndicators.isNotEmpty()) out += Finding("dev.root", Severity.HIGH, Category.SECURITY,
            "Root / modification indicators", d.rootIndicators.joinToString("\n"), null, "T1404")
        val vb = d.props["ro.boot.verifiedbootstate"].orEmpty()
        if (vb.isNotEmpty() && vb != "green") out += Finding("dev.vb", Severity.HIGH, Category.SECURITY,
            "Verified boot state: $vb", "Not 'green': the OS image is not verified by the vendor key.")
        if (d.props["ro.boot.flash.locked"] == "0" || d.props["ro.boot.vbmeta.device_state"] == "unlocked")
            out += Finding("dev.unlocked", Severity.HIGH, Category.SECURITY, "Bootloader unlocked",
                "Anyone with physical access can flash a modified system.")
        if (d.selinux.equals("Permissive", true))
            out += Finding("dev.selinux", Severity.HIGH, Category.SECURITY, "SELinux is permissive", "")
    }

    /** Debugging, Play Protect, screen lock. */
    val access = DeviceRule { d, out ->
        if (d.adbWifiEnabled) out += Finding("dev.adbwifi", Severity.HIGH, Category.SECURITY, "Wireless debugging (ADB over Wi-Fi) is ON",
            "Anyone paired on the network can fully control the phone. Turn it off when not in use.")
        else if (d.adbEnabled) out += Finding("dev.adb", Severity.MEDIUM, Category.SECURITY, "USB debugging is ON",
            "Fine during an investigation; disable afterwards.")
        if (d.verifierEnabled == false) out += Finding("dev.verifier", Severity.MEDIUM, Category.SECURITY,
            "Package verification (Play Protect) appears disabled", "Malware frequently disables Play Protect.", null, "T1629.003")
        if (!d.screenLockSecure) out += Finding("dev.nolock", Severity.HIGH, Category.SECURITY, "No secure screen lock",
            "Physical access = full access (the #1 way stalkerware gets installed).")
    }

    /** TLS interception and traffic redirection. */
    val network = DeviceRule { d, out ->
        if (d.userCaCerts.isNotEmpty()) out += Finding("dev.userca", Severity.HIGH, Category.SECURITY,
            "User-installed CA certificate(s)", "Enables HTTPS interception (MITM):\n" + d.userCaCerts.joinToString("\n"), null, "T1638")
        if (d.httpProxy != null) out += Finding("dev.proxy", Severity.HIGH, Category.SECURITY,
            "Global HTTP proxy set: ${d.httpProxy}", "", null, "T1638")
        if (d.vpnActive) out += Finding("dev.vpn", Severity.INFO, Category.PRIVACY, "A VPN is active",
            "Make sure you know which app provides it.")
        if (d.privateDnsMode == "hostname") out += Finding("dev.privatedns", Severity.INFO, Category.PRIVACY,
            "Private DNS (strict) to ${d.privateDnsHost}", "Sentinel's DNS monitor cannot see queries in strict Private DNS mode.")
    }

    /** Patch level age and OS support. [now] is injectable for tests. */
    fun patchLevel(now: () -> Long = System::currentTimeMillis) = DeviceRule { d, out ->
        val patch = d.props["ro.build.version.security_patch"].orEmpty()
        try {
            val t = SimpleDateFormat("yyyy-MM-dd", Locale.US).parse(patch)!!.time
            val days = (now() - t) / 86_400_000L
            if (days > 365) out += Finding("dev.patch", Severity.HIGH, Category.SECURITY, "Security patch is $days days old ($patch)",
                "Known, public exploits apply to this device.", null, "T1404")
            else if (days > 90) out += Finding("dev.patch", Severity.MEDIUM, Category.SECURITY,
                "Security patch is $days days old ($patch)", "")
        } catch (_: Exception) {
            // missing or unparsable property: no finding
        }
        val sdk = d.props["ro.build.version.sdk"]?.toIntOrNull() ?: 99
        if (sdk < 31) out += Finding("dev.eol", Severity.MEDIUM, Category.SECURITY, "Android version likely out of support (API $sdk)", "")
    }

    val ALL: List<DeviceRule> = listOf(integrity, access, network, patchLevel())
}
