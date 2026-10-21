# Android risk coverage matrix

How the main Android threats are covered by **Malwarebytes for Android**, **DroidSentinel** (on-device, real time),
**DroidCollector + droidtriage** (export + offline analysis), and **what to use for the rest**.

**Legend:** ✅ detects it directly · 🟡 partial / indirect signal · ❌ not covered · ❓ not publicly documented

> **About the Malwarebytes column.** It is based on Malwarebytes' public product descriptions (malware/PUP scanner,
> real-time protection, Privacy Audit, Safe Browsing, scam/SMS protection, Security Advisor) as of 2025. Features differ
> between Free/Premium, regions and versions. Check them in your installed app, especially during your 7-day trial.
> Malwarebytes is a **signature- and reputation-based** scanner: it's strong on *known* threats and weak on configuration
> abuse and forensic history. This suite covers the opposite end.

## 1. Main matrix

| # | Risk / technique | Malwarebytes | DroidSentinel (real time) | Collector + droidtriage (offline) | How to investigate what's not covered |
|---|---|---|---|---|---|
| 1 | **Known malware families** (trojans, droppers, spyware with signatures) | ✅ core feature (signatures + heuristics, real-time in Premium) | 🟡 VirusTotal hash lookup of every user APK (70+ engines), IOC feeds | ✅ VirusTotal hashes, IOC feeds (package / signer / hash / domain), static APK rules | Upload a sample only if it's unknown and not private: VirusTotal, Pithus, MobSF. Decompile it with **jadx** |
| 2 | **Stalkerware** (mSpy, TheTruthSpy, Cocospy, …) | ✅ detected as "monitor"/PUP (Malwarebytes is a member of the Coalition Against Stalkerware) | ✅ IOC package/cert/domain match, hidden-icon, accessibility/admin/notification abuse, background uploads | ✅ same plus install-burst clustering, timeline of installs and settings changes, background mic/location use (appops) | **TinyCheck** (network-side, no phone install). Read **stopstalkerware.org** before removing anything (safety) |
| 3 | **Mercenary spyware** (Pegasus, Predator, Hermit…), incl. **zero-click** | 🟡 only known APK components | 🟡 IOC domains in DNS log (with MVT STIX2 feeds), crashes not visible | 🟡 MVT STIX2 IOCs on packages/domains/hashes, native crashes in privileged processes (dropbox), suspicious logcat | **MVT** (`mvt-android check-androidqf`/`check-bugreport` with Amnesty/Citizen Lab IOCs), **AndroidQF**, then expert help (Amnesty Security Lab, Access Now Helpline). Use Lockdown-style hardening, reboot often |
| 4 | **Banking trojans** (accessibility + overlay, ATS) | ✅ known families | ✅ enabled accessibility service, overlay + accessibility combo, sideloaded origin | ✅ same + `dispatchGesture`/`TYPE_VIEW_TEXT_CHANGED` code rules, SMS interception receivers | Check *Settings → Accessibility*; jadx on the APK; MobSF dynamic analysis |
| 5 | **PUP / aggressive adware** | ✅ core (PUP detection) | 🟡 tracker DNS flags, background traffic | 🟡 tracker SDK inventory (30 SDKs), VT labels | **Exodus Privacy** / **App Manager** tracker reports |
| 6 | **Hidden apps** (no launcher icon) | ❓ | ✅ "hidden + sensitive perms", alert when an app *hides its icon after install* | ✅ hidden + capability profile, secret-code receivers | `adb shell pm list packages -3` vs your launcher; Settings → Apps → *show system* |
| 7 | **Device admin / device-owner (MDM) abuse** | 🟡 | ✅ active admins (DevicePolicyManager) | ✅ admins, **device owner / profile owner** (dumpsys), wipe/lock capabilities | Settings → Security → Device admin apps. Device owner only goes away with a factory reset |
| 8 | **Notification-listener theft** (OTP, messages) | 🟡 Privacy Audit lists permissions | ✅ enabled listeners | ✅ enabled listeners (settings + dumpsys) | Settings → Notifications → Notification access |
| 9 | **Malicious keyboard / autofill** (keylogging) | ❓ | ✅ non-system default IME, autofill service, sideloaded IME | ✅ same + `TYPE_VIEW_TEXT_CHANGED` accessibility keylogging rule | Settings → System → Keyboard; Settings → Passwords & autofill |
| 10 | **Repackaged / impersonating apps** (fake "System Update", clones) | 🟡 known samples | ✅ duplicate labels, vendor-like package names, system-sounding names, debug-key signing, untrusted installer | ✅ same + signer subject, APK-vs-device signer mismatch | Compare the signer SHA-256 with the Play version (`apksigner verify --print-certs`) |
| 11 | **APK modified on disk / signing key changed / silent downgrade** | ❌ | ✅ **integrity baseline**: hash changed w/o update, signer changed, downgrade, installer changed | ✅ `--baseline` diff between two collections, archive-vs-device hash check | `adb shell pm path` + `sha256sum`, compare with the store copy |
| 12 | **Firmware / pre-installed malware, platform-key abuse** | 🟡 if the sample is known | ✅ user app signed with **platform key**, debuggable system apps, test-keys, verified-boot state | ✅ same + system apps updated from untrusted installers, optional full system APK export | Reflash vendor firmware; check the model on known pre-installed malware reports; MVT |
| 13 | **Task hijacking (StrandHogg) / intent & bind hijacking** | ❌ | ✅ foreign `taskAffinity` pointing at an installed app, abusable bindings (VPN, InCall, IME, accessibility) | ✅ same + manifest intent-filter analysis (priority receivers, secret codes) | **jadx**/apktool manifest review; Drozer-style exported-component testing on your own apps |
| 14 | **SMS fraud / OTP interception / premium SMS** | ✅ known families; 🟡 SMS scam filter (Premium, region-dependent) | ✅ apps that read and send SMS without being the SMS app, sideloaded SMS role | ✅ same + max-priority `SMS_RECEIVED` receivers, `sendTextMessage` code, SMS sends seen in logcat | Carrier bill; move 2FA from SMS to an authenticator app or passkeys |
| 15 | **Droppers, dynamic code loading, packers** | 🟡 heuristics | 🟡 "allowed to install apps", packer libs | ✅ `DexClassLoader`/`InMemoryDexClassLoader`, embedded DEX/ELF/APK, encrypted assets, 12 packers, code loaded from writable paths (logcat) | MobSF dynamic analysis, Frida on a **test** device |
| 16 | **Data exfiltration** (background uploads) | ❌ | ✅ per-app upload volume, **uploads while the screen is off**, hidden apps sending data | ✅ 30-day per-app volume, "uploads but never opened" | **PCAPdroid** (on-device pcap + TLS decryption for your own apps), router logs |
| 17 | **C2 / DNS abuse** (DGA, dynamic DNS, tunnels, Telegram/Discord bots) | 🟡 Safe Browsing (Premium) blocks known-bad domains | ✅ **per-app DNS log** with IOC/DGA/dyn-DNS/tunnel/Telegram flags, VT domain lookup on tap | ✅ same on the exported DNS log + endpoints hard-coded in APKs + hostnames seen in logs | PCAPdroid, NextDNS/AdGuard DNS logs, Pi-hole |
| 18 | **Phishing sites & smishing** | ✅ Safe Browsing + scam/text protection (Premium) | 🟡 DNS flags only for apps that use the system resolver | 🟡 IOC domains in logs | Browser Safe Browsing, Google Messages spam protection. Report to your carrier (7726 in many countries) |
| 19 | **TLS interception** (user CA, global proxy, rogue VPN) | 🟡 Security Advisor may flag some settings | ✅ user CA certificates, global proxy, active VPN, VPN-capable sideloaded apps | ✅ same + exported CA PEMs, always-on VPN, cert-install events in logs | Settings → Security → Encryption & credentials; check MDM profiles |
| 20 | **Root, unlocked bootloader, custom ROM, SELinux permissive** | 🟡 root detection (verify) | ✅ su/Magisk/KernelSU files & packages, test-keys, verified boot, SELinux | ✅ same + adb-root props, dm-verity, hooking frameworks/Frida in logs | Play Integrity check app; `fastboot getvar unlocked` (bootloader) |
| 21 | **Outdated patch level / end-of-life OS** | 🟡 | ✅ patch age > 90 / 365 days, API level | ✅ same | Vendor update page; Android security bulletins |
| 22 | **ADB / wireless debugging exposure** | 🟡 Security Advisor (verify) | ✅ USB / wireless debugging state | ✅ same + **list of computers authorised for ADB**, ADB sessions in logs | Developer options → *Revoke USB debugging authorisations* |
| 23 | **Over-permissioned apps & trackers** (privacy) | ✅ Privacy Audit | ✅ per-app privacy score (weighted permissions), tracker domains | ✅ same + tracker SDKs in code, cleartext traffic | Exodus Privacy; Android Privacy Dashboard |
| 24 | **Background camera / mic / location / clipboard use** | ❌ | 🟡 (relies on the Android privacy indicators) | ✅ appops **background access** timestamps, clipboard-read denials, camera/mic events in logcat | Settings → Privacy → Privacy dashboard (24 h); permission manager |
| 25 | **Ransomware / screen lockers** | ✅ Ransomware protection (Premium) | 🟡 admin + overlay combos | 🟡 device-admin lock/wipe capabilities | Safe mode boot to uninstall |
| 26 | **Account compromise** (Google account, WhatsApp/Telegram linked devices, cloud backups) | ❌ | ❌ | 🟡 account types present on the phone | Google **Security Checkup** (devices, third-party access), WhatsApp → *Linked devices*, Telegram → *Active sessions*, iCloud/Google Photos sharing |
| 27 | **SIM swap, SS7, call forwarding** | ❌ | ❌ | 🟡 call-forwarding/USSD events in logcat | Dial `*#21#` / `*#62#` (GSM) to check forwarding; carrier SIM PIN / port-out lock |
| 28 | **Rogue Wi-Fi / Bluetooth attacks / juice-jacking** | 🟡 Wi-Fi security warnings (verify) | ❌ | 🟡 networks config, Bluetooth dumpsys | Forget unknown networks; disable Bluetooth when unused; use a USB data blocker |
| 29 | **Physical access** (someone unlocking your phone) | ❌ | ✅ no secure lock, install-time alerts | ✅ **install-burst clustering**, timeline of settings changes (who enabled accessibility, when) | Change PIN, check *Google Find My Device* history, review the timeline |

## 2. Who catches what, in one line each

* **Malwarebytes:** "Is this a known bad app or site?" Fast and broad for known threats, but limited forensic depth.
* **DroidSentinel:** "Is something changing or calling out *right now*?" Integrity baseline, per-app DNS, background uploads, abusable permissions.
* **Collector + droidtriage:** "What happened on this phone, and what is configured to abuse it?" Logs, dumpsys, appops history, timeline, static APK analysis, IOC feeds.
* **MVT / AndroidQF / experts:** mercenary spyware and exploitation. Use these when the threat model includes state actors.

## 3. Blind spots of all on-device tools (including this suite)

* Kernel/firmware implants and exploits that leave no app, crash or log trace.
* Data *inside* other apps' sandboxes (messages, browser history) without root.
* Apps that use their own DNS-over-HTTPS or hard-coded IPs bypass the DNS monitor (Strict Private DNS bypasses it too).
* Server-side compromise: your cloud accounts, your carrier, the network.
* Logcat only covers a few hours or days. The evidence is lost if you factory-reset or reboot repeatedly **before** collecting.

## 4. MITRE ATT&CK for Mobile mapping used in the reports

| ID | Technique | Raised by |
|---|---|---|
| T1404 | Exploitation for Privilege Escalation | root, platform key, old patch, privileged crashes |
| T1407 | Download New Code at Runtime | DexClassLoader, embedded payloads, droppers |
| T1406.002 | Obfuscated Files: Software Packing | packers, encrypted assets |
| T1414 | Clipboard Data | clipboard reads |
| T1417.001 / .002 | Input Capture: Keylogging / GUI Input Capture | IME, accessibility text events, overlays, StrandHogg |
| T1418 | Software Discovery | installed-package enumeration |
| T1426 | System Information Discovery | IMSI / device-id reads |
| T1533 | Data from Local System | media access in background |
| T1429 / T1512 / T1513 | Audio / Video / Screen Capture | mic, camera, MediaProjection |
| T1430 | Location Tracking | background location |
| T1437.001 | Application Layer Protocol: Web | raw-IP http C2, IOC domains |
| T1474 | Supply Chain Compromise | untrusted installers |
| T1481 | Web Service | Telegram/Discord/Pastebin C2 |
| T1516 | Input Injection | accessibility gestures |
| T1517 | Access Notifications | notification listeners |
| T1582 / T1616 | SMS Control / Call Control | SMS send, USSD, forwarding |
| T1603 | Scheduled Task/Job | persisted jobs, wake-up alarms |
| T1625.001 | Hijack Execution Flow: System Runtime API Hijacking | Xposed/LSPosed/Frida |
| T1624.001 | Event Triggered Execution: Broadcast Receivers | boot receivers, background starts |
| T1626.001 | Device Administrator Permissions | admins, device owner |
| T1628.001 | Hide Artifacts: Suppress Application Icon | hidden apps |
| T1629.003 | Impair Defenses: Disable or Modify Tools | Play Protect disabled |
| T1630 | Indicator Removal on Host | wipe capabilities |
| T1633 | Virtualization/Sandbox Evasion | emulator checks |
| T1636.x | Protected User Data (call log, contacts, SMS) | permission and code rules |
| T1638 | Adversary-in-the-Middle | user CA, proxy, VPN |
| T1645 | Compromise Client Software Binary | APK tampering, signer change |
| T1646 | Exfiltration Over C2 Channel | background uploads |
| T1655.001 | Masquerading: Match Legitimate Name | impersonation |
