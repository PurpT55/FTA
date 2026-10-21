"""What to do next, per finding family (matched by id prefix)."""

PLAYBOOK = [
    ("ioc.", "Treat as confirmed compromise. If you may be a victim of domestic abuse, think about your safety BEFORE removing it "
             "(the person who installed it may notice). Contact a support organisation (e.g. stopstalkerware.org). Then: back up evidence "
             "(keep this zip), disable device admin for the app, uninstall it, change Google/Apple/email passwords from ANOTHER device, enable 2FA."),
    ("vt.", "Open the VirusTotal report for the SHA-256, read the family name, check the vendor names. 1–2 detections are often adware/false "
            "positives; ≥3 from reputable engines = remove the app."),
    ("cert.platform", "Platform-signed user apps were used in real attacks (leaked OEM keys, 2022). Uninstall, update firmware, report to the vendor."),
    ("acc.", "Settings → Accessibility → Installed apps: turn it off unless you knowingly enabled it (screen readers, password managers, automation)."),
    ("nls.", "Settings → Notifications → Device & app notifications / Notification access: revoke if unexpected."),
    ("admin.", "Settings → Security → Device admin apps: deactivate, then uninstall."),
    ("device.owner", "A device owner can only be removed by factory reset (or by the MDM). If this is not your employer's phone, back up and reset."),
    ("hidden", "Find it in Settings → Apps (show system), check its permissions, uninstall. Hidden apps are the #1 stalkerware sign."),
    ("stalkerware", "Compare with stopstalkerware.org guidance. Check the install date against when someone else had access to the phone."),
    ("mask.", "Compare package name, installer and signer with the genuine app (Play Store page). Impersonators are usually sideloaded."),
    ("task.hijack", "Open the app's manifest in jadx and check the activity's taskAffinity. Uninstall unless it is a known launcher/overlay app."),
    ("sms.", "Revoke SMS permissions; check your carrier bill for premium SMS; move 2FA from SMS to an authenticator app."),
    ("dev.userca", "Settings → Security → Encryption & credentials → User credentials: remove certificates you did not install."),
    ("dev.proxy", "Remove the proxy (Wi-Fi network → Advanced → Proxy: None) and check MDM/VPN apps that may set it."),
    ("dev.root", "If you did not root the phone yourself, re-flash stock firmware from the vendor."),
    ("dev.vb", "Unverified boot = modified OS. Re-flash official firmware and relock the bootloader."),
    ("dev.patch", "Install system updates. If the vendor no longer ships updates, plan to replace the phone."),
    ("dev.adb", "Settings → System → Developer options: turn off USB / wireless debugging after the investigation."),
    ("dev.nolock", "Set a PIN/password (6+ digits). Physical access is how most stalkerware is installed."),
    ("crash.privileged", "Possible exploitation attempt. Run MVT (mvt-android check-bugreport) with Amnesty/Citizen Lab IOCs and contact an expert (Amnesty Security Lab, Access Now helpline)."),
    ("dns.", "Look the domain up on VirusTotal/URLhaus, identify the app that resolved it, and block/uninstall."),
    ("net.", "Check what the app is (Play page, developer). An app that uploads data without ever being opened deserves removal."),
    ("apk.payload", "Extract the payload (unzip the APK) and scan it separately; embedded DEX/ELF is how droppers ship second stages."),
    ("apk.encrypted", "Packed apps hide behaviour from static analysis: rely on dynamic evidence (DNS/traffic) or analyse in a sandbox."),
    ("apk.c2", "Telegram/Discord endpoints inside a non-messaging app are a strong exfiltration indicator. Search the token/URL in jadx."),
    ("persist.", "Check the app: why does it schedule background jobs if you never use it?"),
    ("install.cluster", "Correlate the time with who had the phone. Review each app in the cluster."),
    ("appops.bg", "Settings → Privacy → Permission manager: set camera/mic/location to 'Only while using the app' or deny."),
    ("log.", "Open the sample lines in the report; search the full logcat file in the zip around the same timestamp."),
    ("install.untrusted", "Not malicious by itself. Confirm you installed it on purpose; prefer the store version."),
]


def advice(fid: str) -> str:
    for prefix, text in PLAYBOOK:
        if fid.startswith(prefix):
            return text
    return ""
