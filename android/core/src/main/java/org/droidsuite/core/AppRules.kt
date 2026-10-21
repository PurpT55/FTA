package org.droidsuite.core

/**
 * Per-app detection rules, grouped by family. Each rule is an [AppRule]; [ALL] is the registry
 * the [RiskEngine] iterates.
 *
 * Adding a rule:
 *  1. write a `val myRule = AppRule { a, ctx, out -> ... }` below (finding id = `family.name`);
 *  2. add it to [ALL];
 *  3. add a case to `core/src/test/.../RiskEngineTest.kt`;
 *  4. if the evidence is also visible offline, mirror it in analyzer/droidtriage/packages.py with the same id.
 */
object AppRules {
    private const val ACC = "android.permission.BIND_ACCESSIBILITY_SERVICE"
    private const val IME = "android.permission.BIND_INPUT_METHOD"
    private const val VPN = "android.permission.BIND_VPN_SERVICE"
    private const val INCALL = "android.permission.BIND_INCALL_SERVICE"

    private val SYSTEMISH_LABEL = Regex(
        "(?i)\\b(system|update|updater|service|services|google|android|wi-?fi|settings|security|sync|battery|device care|sim toolkit)\\b"
    )
    private val SYSTEMISH_PKG = Regex("^(com\\.android\\.|com\\.google\\.|android\\.|com\\.samsung\\.|com\\.qualcomm\\.)")

    /** Known-bad: IOC package / signer / hash and VirusTotal verdicts. */
    val malware = AppRule { a, ctx, out ->
        val p = a.pkg
        ctx.iocs.packages[p]?.let {
            out += Finding("ioc.package", Severity.CRITICAL, Category.MALWARE,
                "Known ${it.kind} package: ${it.family}", "Package name $p is listed in the IOC database (${it.family}).", p, "T1636")
        }
        a.certSha1.forEach { c ->
            ctx.iocs.certSha1[c.lowercase()]?.let {
                out += Finding("ioc.cert", Severity.CRITICAL, Category.MALWARE,
                    "Signed with a known ${it.kind} certificate (${it.family})", "Signing cert SHA-1 $c matches IOC.", p)
            }
        }
        a.apkSha256?.let { h ->
            ctx.iocs.hashes[h]?.let {
                out += Finding("ioc.hash", Severity.CRITICAL, Category.MALWARE, "APK hash matches IOC (${it.family})", h, p)
            }
            ctx.vt[h]?.let { v ->
                if (v.positives >= 3) out += Finding("vt.malicious", Severity.CRITICAL, Category.MALWARE,
                    "VirusTotal: ${v.positives}/${v.total} engines flag this APK", v.label ?: "", p)
                else if (v.positives > 0) out += Finding("vt.low", Severity.MEDIUM, Category.SUSPICIOUS,
                    "VirusTotal: ${v.positives}/${v.total} detections (possible PUP/false positive)", v.label ?: "", p)
            }
        }
    }

    /** Firmware key abuse, system uid, debuggable/updated system apps, debug certificates. */
    val firmware = AppRule { a, ctx, out ->
        val p = a.pkg
        if (!a.system && ctx.platformCerts.isNotEmpty() && a.certSha256.any { it in ctx.platformCerts })
            out += Finding("cert.platform", Severity.CRITICAL, Category.MALWARE, "User app signed with the PLATFORM key",
                "A non-system app shares the firmware signing key. This grants system-level privileges and is a known abuse of leaked OEM keys.", p, "T1404")
        if (a.sharedUserId == "android.uid.system" && !a.system)
            out += Finding("uid.system", Severity.CRITICAL, Category.SECURITY, "Non-system app runs as android.uid.system", "", p)
        if (a.system && a.debuggable)
            out += Finding("sys.debuggable", Severity.HIGH, Category.SECURITY, "Debuggable system app",
                "Production firmware should never ship debuggable system apps (custom/modified ROM or engineering build).", p)
        if (a.updatedSystem && a.installer != null && a.installer !in ctx.trusted && a.installer != "android")
            out += Finding("sys.update.untrusted", Severity.HIGH, Category.SECURITY,
                "System app updated from an untrusted source (${a.installer})", "", p, "T1645")
        if (!a.system && a.certSubjects.any { it.contains("CN=Android Debug") })
            out += Finding("cert.debug", Severity.MEDIUM, Category.SUSPICIOUS, "Signed with an Android debug certificate",
                "Released apps are never signed with the debug key; typical of repackaged or home-made builds.", p)
    }

    /** Abusable bindings: accessibility, notifications, admin, keyboard, autofill, VPN, in-call, overlay, SMS. */
    val roles = AppRule { a, ctx, out ->
        if (a.system) return@AppRule
        val p = a.pkg
        val side = ctx.sideloaded(a)
        if (p in ctx.accessibility) out += Finding("acc.enabled", Severity.HIGH, Category.SECURITY, "Accessibility service ENABLED",
            "Can read the whole screen, keystrokes and perform taps on your behalf (banking trojans, stalkerware).", p, "T1417.002 / T1516")
        else if (side && a.servicesWith(ACC).isNotEmpty()) out += Finding("acc.declared", Severity.LOW, Category.PRIVACY,
            "Declares an accessibility service (not enabled)", "", p)
        if (p in ctx.notificationListeners) out += Finding("nls.enabled", Severity.MEDIUM, Category.PRIVACY,
            "Notification listener ENABLED", "Can read every notification, including 2FA codes and messages.", p, "T1517")
        if (p in ctx.admins) out += Finding("admin.active", Severity.HIGH, Category.SECURITY,
            "Active device administrator", "Can lock/wipe the device and resist uninstallation.", p, "T1626.001")
        if (p == ctx.ime) out += Finding("ime.default", Severity.MEDIUM, Category.PRIVACY,
            "Third-party keyboard is the default input method", "A keyboard sees everything you type.", p, "T1417.001")
        else if (side && a.servicesWith(IME).isNotEmpty()) out += Finding("ime.declared", Severity.LOW, Category.PRIVACY,
            "Sideloaded app provides a keyboard", "", p)
        if (p == ctx.autofill) out += Finding("autofill.default", Severity.LOW, Category.PRIVACY,
            "Selected autofill service", "Receives the content of login forms.", p)
        if (side && a.servicesWith(VPN).isNotEmpty()) out += Finding("vpn.provider", Severity.MEDIUM, Category.SUSPICIOUS,
            "Sideloaded app can act as a VPN", "VPN apps can see/redirect all traffic.", p, "T1638")
        if (side && a.servicesWith(INCALL).isNotEmpty()) out += Finding("incall.provider", Severity.MEDIUM, Category.SUSPICIOUS,
            "Sideloaded app implements an in-call UI", "Can see and control phone calls.", p, "T1616")
        if (p in ctx.device.overlayGranted) {
            out += if (p in ctx.accessibility) Finding("overlay.acc", Severity.HIGH, Category.SECURITY,
                "Overlay + accessibility (classic banking-trojan combo)",
                "Overlays enable phishing screens on top of real apps and tapjacking.", p, "T1417.002")
            else Finding("overlay", Severity.LOW, Category.PRIVACY, "Can draw over other apps",
                "Overlays enable phishing screens on top of real apps and tapjacking.", p, "T1417.002")
        }
        if (a.has("android.permission.READ_SMS") && a.has("android.permission.SEND_SMS") && p != ctx.device.defaultSms)
            out += Finding("sms.full", Severity.HIGH, Category.SECURITY, "Reads and sends SMS without being the SMS app",
                "Typical of OTP stealers and premium-SMS fraud.", p, "T1636.004 / T1582")
    }

    /** StrandHogg-style task hijacking: an activity whose taskAffinity is another installed package. */
    val taskHijack = AppRule { a, ctx, out ->
        if (a.system) return@AppRule
        for (c in a.components) {
            val target = c.taskAffinity ?: continue
            if (c.type != "activity" || target == a.pkg || target.startsWith("${a.pkg}:") || target.isEmpty()) continue
            if (target in ctx.byPackage) out += Finding("task.hijack", Severity.HIGH, Category.SECURITY,
                "Activity claims another app's task affinity ($target)",
                "${c.name} can be inserted into $target's task (StrandHogg task hijacking: fake login screens).", a.pkg, "T1417.002")
            else if (c.allowTaskReparenting) out += Finding("task.reparent", Severity.LOW, Category.SUSPICIOUS,
                "Activity with foreign taskAffinity + allowTaskReparenting", "${c.name} -> $target", a.pkg)
        }
    }

    /** Impersonation of other apps or of the OS vendor (sideloaded apps only). */
    val masquerade = AppRule { a, ctx, out ->
        if (!ctx.sideloaded(a)) return@AppRule
        val p = a.pkg
        val same = ctx.labels[a.label.trim().lowercase()].orEmpty().filter { it.pkg != p }
        if (same.isNotEmpty()) out += Finding("mask.label", Severity.HIGH, Category.SUSPICIOUS,
            "Same name as another installed app (${same.joinToString { it.pkg }})",
            "Sideloaded app uses an identical label: possible impersonation.", p, "T1655.001")
        if (SYSTEMISH_PKG.containsMatchIn(p)) out += Finding("mask.pkg", Severity.HIGH, Category.SUSPICIOUS,
            "Sideloaded app uses a system-like package name", "Package $p imitates a vendor namespace.", p, "T1655.001")
        else if (SYSTEMISH_LABEL.containsMatchIn(a.label)) out += Finding("mask.name", Severity.MEDIUM, Category.SUSPICIOUS,
            "Sideloaded app with a system-sounding name (\"${a.label}\")", "", p, "T1655.001")
    }

    /** Hidden apps and the stalkerware capability profile. */
    val surveillance = AppRule { a, ctx, out ->
        if (a.system) return@AppRule
        val caps = ctx.capabilityCount(a)
        if (!a.hasLauncher && caps >= 2) out += Finding("hidden", Severity.HIGH, Category.SUSPICIOUS,
            "Hidden app (no launcher icon) with sensitive permissions", "$caps sensitive capabilities.", a.pkg, "T1628.001")
        if (ctx.sideloaded(a) && caps >= 5) out += Finding("stalkerware.profile", Severity.HIGH, Category.SUSPICIOUS,
            "Surveillance capability profile ($caps/10)",
            "Sideloaded app combining location/mic/SMS/call log/contacts/accessibility/admin/boot. Matches stalkerware behaviour.",
            a.pkg, "T1430 / T1429 / T1636")
    }

    /** Install origin, dropper capability, old target SDK, debuggable, packers. */
    val hygiene = AppRule { a, ctx, out ->
        if (a.system) return@AppRule
        val p = a.pkg
        val side = ctx.sideloaded(a)
        if (side) out += Finding("install.untrusted", Severity.LOW, Category.UNKNOWN,
            "Installed outside a trusted store (installer: ${a.installer ?: "none/adb"})", "", p, "T1474")
        if (side && a.requests("android.permission.REQUEST_INSTALL_PACKAGES") && p in ctx.device.installSourcesAllowed)
            out += Finding("dropper", Severity.MEDIUM, Category.SUSPICIOUS, "Sideloaded app allowed to install other apps",
                "Dropper capability.", p, "T1407")
        if (a.targetSdk in 1..22) out += Finding("sdk.old", Severity.MEDIUM, Category.SECURITY,
            "Targets Android ${a.targetSdk} (pre-runtime-permissions)",
            "Old target SDK lets the app get dangerous permissions at install time.", p)
        if (a.debuggable) out += Finding("app.debuggable", Severity.LOW, Category.SECURITY, "App is debuggable", "", p)
        for (lib in a.nativeLibs) {
            RiskEngine.PACKERS.entries.firstOrNull { lib.startsWith(it.key) }?.let {
                out += Finding("packer", Severity.MEDIUM, Category.SUSPICIOUS, "Packed/protected with ${it.value} ($lib)",
                    "Packers hide code from analysis; legitimate in some regional apps, common in malware.", p, "T1406.002")
            }
        }
    }

    /** Registry iterated by [RiskEngine.evaluate], in report order. */
    val ALL: List<AppRule> = listOf(malware, firmware, roles, taskHijack, masquerade, surveillance, hygiene)
}
