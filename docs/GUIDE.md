# FTA user guide (Forensic Triage for Android)

Three tools that work together:

```
PHONE                                                    COMPUTER
┌──────────────────────────────────────┐
│ DroidSentinel (always on)            │
│  integrity baseline · per-app DNS    │
│  per-app traffic · abusable perms    │
│  VirusTotal hashes · dashboard       │
└──────────────┬───────────────────────┘
               │ report (signature-protected)
┌──────────────▼───────────────────────┐   zip    ┌───────────────────────────────────┐
│ DroidCollector (on demand)           ├─────────▶│ droidtriage                       │
│  logs · dumpsys · settings · APKs    │          │  package + APK static analysis    │
│  usage · Sentinel report             │          │  logcat / dumpsys / appops rules  │
└──────────────────────────────────────┘          │  IOC feeds · VirusTotal (hashes)  │
  or: tools/adb_collect.sh (same layout) ────────▶│  timeline · HTML report · CSV     │
                                                  │  baseline diff between runs       │
                                                  └───────────────────────────────────┘
```

* **DroidSentinel** (APK 1) monitors the phone continuously and shows a dashboard with *Privacy risk*,
  *Security risk*, *Suspicious activity*, *Unknown binaries* and *Malware detected*.
* **DroidCollector** (APK 2) exports logs, system state and APKs into **one zip**, only after you confirm and
  pick where to save it. It never uploads anything.
* **droidtriage** (Python, no dependencies) analyses the zip on a computer and produces `report.html`,
  `report.json` and CSV files.

---

## 0. Before you start: safety and evidence

1. **If you suspect someone close to you is spying on you** (stalkerware), removing the app can alert that
   person. Read <https://stopstalkerware.org> or contact a support organisation first. Collecting evidence
   (step 4) does not remove anything.
2. **Collect before cleaning.** If Malwarebytes or Play Protect flags an app, **note the package name and
   collect first**. Then remove it. Logcat only covers hours or days, and uninstalling erases the APK and its history.
3. Don't reboot or factory-reset before collecting if you can avoid it. A reboot clears part of the logs.
4. The zip contains personal data (app list, account names, logs, Wi-Fi config). Store it encrypted
   (`7z a -p -mhe=on evidence.7z evidence.zip`) and delete it when you are done.
5. Use these tools only on devices you own or are explicitly authorised to examine.

---

## 1. Build the two APKs

The project has no AndroidX or third-party dependencies, so builds are small and reproducible.
**Both apps must be signed with the same key**: the Collector reads Sentinel's report through a
signature-protected endpoint.

### Option A: GitHub Actions (no Android SDK needed)

1. Push this folder to a **private** GitHub repository.
2. *(Recommended)* Create a persistent signing key once, so future builds can update the installed apps:
   ```bash
   tools/make_keystore.sh                      # creates android/suite.keystore
   base64 -w0 android/suite.keystore           # copy the output
   ```
   In the repo: *Settings → Secrets and variables → Actions*, add `SUITE_KEYSTORE_B64` (the base64 text).
   Add `SUITE_KEYSTORE_PASSWORD`, `SUITE_KEY_ALIAS` and `SUITE_KEY_PASSWORD` too if you changed the defaults.
   Without the secret, each build generates a throw-away key. That works, but you then have to uninstall
   before you can install a newer build.
3. *Actions → Build APKs → Run workflow*. Download the `droid-forensics-apks` artifact, which contains
   `DroidSentinel.apk`, `DroidCollector.apk` and `SHA256SUMS`.

### Option B: Android Studio

Open the `android/` folder, wait for Gradle sync, then *Build → Build APK(s)*.
Optionally run `tools/make_keystore.sh` first. Otherwise both apps use your machine's debug key, which is
also fine because it's the same key for both.

### Option C: command line (Android SDK installed, `ANDROID_HOME` set)

```bash
tools/make_keystore.sh
cd android && ./gradlew assembleRelease
# → sentinel/build/outputs/apk/release/sentinel-release.apk
# → collector/build/outputs/apk/release/collector-release.apk
```

---

## 2. Install

Install **DroidSentinel first**, then DroidCollector. Signature permissions are granted at install time,
so the definer must already be there.

```bash
adb install DroidSentinel.apk
adb install DroidCollector.apk
```

You can also copy the APKs to the phone and open them (allow "install unknown apps" for your file manager
just for this, then turn it off again).

Expected warnings:
* **Play Protect** may say "unknown app". These are self-built apps; check `SHA256SUMS`.
* **Malwarebytes may flag them as riskware/PUP.** That's expected: they use the same powerful capabilities they
  look for (package visibility, local VPN, usage access, log access). Whitelist them in Malwarebytes or ignore
  the detection for these two package names: `org.droidsuite.sentinel` and `org.droidsuite.collector`.

---

## 3. DroidSentinel: real-time monitor and dashboard

### 3.1 First launch checklist

| Step | Where | Why |
|---|---|---|
| Allow notifications | prompt at first launch | alerts for new high/critical events |
| **Grant usage access** | Dashboard → *Grant usage access* (Settings → Usage access → DroidSentinel) | per-app network volume, screen-off uploads |
| **Battery: don't optimise** | Dashboard button | stops Android from killing the monitor |
| **VirusTotal key** | Settings tab | hash lookups (see 3.4) |
| **Download stalkerware IOCs** | Settings tab | known stalkerware packages, certificates, domains |
| Start monitor | Dashboard → *Start monitor* | package/integrity/traffic watching, survives reboot |
| Start DNS monitor | Dashboard → *Start DNS monitor* → accept VPN prompt | per-app domain log |

The first scan builds the **integrity baseline**: package name, version, APK SHA-256, signing certificate,
installer, install time and launcher-icon state for every package. Later scans compare against it.

### 3.2 The dashboard

| Tile | Meaning | How it's computed |
|---|---|---|
| **Privacy risk** /100 | How exposed your personal data is to installed apps | Each user app gets a score from its granted permissions (background location 12, mic 10, SMS 10, call log 10, camera 8, …; a requested-but-not-granted permission counts for 1/4), plus 15 for an enabled accessibility service and 10 for notification access. Dashboard = 0.6 × worst app + 0.4 × average of the top 10 |
| **Security risk** /100 | Weaknesses and compromise signals | Sum of SECURITY + MALWARE findings: critical 40, high 15, medium 5, low 1 (capped at 100) |
| **Suspicious activity** | Things that behave like malware | Medium+ "suspicious" findings + medium+ events in the last 24 h |
| **Unknown binaries** | Apps nobody vouches for | Installed outside a trusted store **and** unknown to VirusTotal (or not checked yet) |
| **Malware detected** | Confirmed bad | IOC match (package, signer, hash, domain), VirusTotal ≥ 3 engines, user app signed with the platform key |

Tap a tile to open the matching findings. Tap a finding or an app for details: install source, signer, SHA-256,
VirusTotal verdict, sensitive permissions, bindable services, DNS domains contacted and 24 h traffic.

### 3.3 What is monitored in real time

| Monitor | Detects | Delay |
|---|---|---|
| Package broadcasts | install / update / removal / component change, then a rescan after 5 s | instant |
| Integrity diff (every 15 min + after package events) | **APK changed on disk without an update**, **signing certificate changed**, same version reinstalled with a different binary, **downgrade**, installer changed, **app hid its launcher icon**, new app (high if hidden + sideloaded) | ≤ 15 min |
| Risk engine (same schedule) | new HIGH/CRITICAL findings, then a notification | ≤ 15 min |
| Traffic (NetworkStatsManager, every 2 min) | first network activity of sideloaded/hidden apps, **uploads above the threshold while the screen is off** (default 5 MB), hidden apps uploading | Android batches stats, so a few minutes |
| DNS monitor (local VPN) | every DNS query with the **app that made it**: IOC domains, dynamic DNS, tunnels (ngrok…), Telegram Bot API from non-Telegram apps, paste/exfil sites, DGA-looking names, risky TLDs, trackers | instant |

How the DNS monitor works: a VPN that routes **only** the fake resolver address `10.111.222.2`. Your normal
traffic does not go through Sentinel. Each query is attributed to an app (Android 10+), logged, classified, and
forwarded unchanged to your network's DNS server (or 9.9.9.9 if that can't be determined).
Limits: apps that use DNS-over-HTTPS or hard-coded IPs, and **Strict Private DNS** (Settings → Network →
Private DNS = hostname), bypass it. Only one VPN can be active at a time, so it can't run alongside another VPN app.
For full packet capture use **PCAPdroid**.

### 3.4 VirusTotal

* Create a free account at virustotal.com and copy the API key from your profile into the Settings tab.
* Free tier: 4 lookups/min, 500/day. Sentinel spaces requests 16 s apart and stops at 480/day.
* **Automatic lookups send only SHA-256 hashes** of user-installed APKs. Sideloaded apps go first, and results
  are cached for 7 days.
* **Uploading a file** is only possible from an app's detail → *VirusTotal…* → *Upload APK file…*, after a
  confirmation screen. Don't upload private, enterprise or self-built apps: uploaded samples can be downloaded
  by VirusTotal premium users.
* "Unknown to VirusTotal" for a sideloaded app isn't proof of malware, but it deserves a closer look.
* Domain lookups (tap a DNS row) send only the domain name.

### 3.5 Indicators of compromise

*Settings → Download stalkerware IOCs* fetches
[AssoEchap/stalkerware-indicators](https://github.com/AssoEchap/stalkerware-indicators) (packages,
signing-certificate SHA-1s, domains, IPs). *Import file…* accepts the same YAML format or a text list:

```
package:com.bad.app
domain:evil.example
sha256:<apk hash>
cert:<signing cert sha1>
```

### 3.6 Exporting / stopping / uninstalling

* *Settings → Export JSON report* saves the full state. DroidCollector also includes it automatically.
* *Stop monitor* / *Stop DNS monitor* turn everything off. Uninstalling removes all data. Nothing is stored
  anywhere else.

---

## 4. DroidCollector: export everything into a zip

### 4.1 One-time permission boost (strongly recommended)

A normal app can only read **its own** logs and can't run `dumpsys`. Grant these development permissions
once from a computer, with USB debugging enabled:

```bash
adb shell pm grant org.droidsuite.collector android.permission.READ_LOGS
adb shell pm grant org.droidsuite.collector android.permission.DUMP
adb shell appops set org.droidsuite.collector GET_USAGE_STATS allow
```

The app shows ✔ or ✖ for each capability, and can copy these commands for you. On **Android 13+**, the system
also asks *"Allow DroidCollector to access all device logs?"* when collection starts. Tap **Allow**.

### 4.2 Collecting

1. Tick the sections you want (defaults are fine).
2. Tap **Collect…**, read the list of what will be included, then tap **I agree – choose destination**.
3. Choose where to save `droidcollect_<model>_<date>.zip` (Downloads, SD card, or a cloud folder you trust).
4. Wait. Typical times: 1–3 min without APKs. With user APKs, about 1 min per GB (APKs are stored uncompressed, which is fast).

| Section | Content | Needs |
|---|---|---|
| Device & security settings | `getprop`, all readable Settings (global/secure/system), CA certificate index + user CAs as PEM, networks/proxy, visible accounts, device posture | – |
| App inventory | every package: version, installer, install times, signer SHA-1/SHA-256, permissions requested/granted, every component (exported, permissions, taskAffinity), native libs, base.apk SHA-256, on-device risk findings | – |
| APK files | user apps (+ split APKs). Optional: updated system apps, or all system apps | – |
| Logcat | main/system/crash/events/radio buffers, last boot, statistics | READ_LOGS for other apps' logs |
| dumpsys | about 40 services: package, activity, accessibility, device_policy, notification, appops, jobscheduler, alarm, netstats, settings (with change history), dropbox (crash history), role, adb (authorised computers)… | DUMP |
| Usage history | 7 days of usage events, daily foreground time, 30 days of per-app network volume | Usage access |
| /proc snapshot | kernel version, mounts, process list, readable network tables | – |
| DroidSentinel report | dashboard, events, DNS log, traffic, VirusTotal results | Sentinel installed, same key |

Every file in the zip is listed in `manifest.json` with its SHA-256, size and source command, so you can show
the evidence wasn't modified after collection. Errors go to `collection_errors.txt`.

### 4.3 Getting the zip to the computer

USB file transfer (MTP), or `adb pull /sdcard/Download/droidcollect_*.zip`, or *Share zip…* to a channel you
trust. Don't send it through apps you suspect.

### 4.4 Alternative: `tools/adb_collect.sh` (no app needed)

The adb shell user has more rights than any app, so this gets the most complete picture:

```bash
tools/adb_collect.sh                       # user APKs, logs, dumpsys, settings, props
tools/adb_collect.sh --bugreport           # + full bugreport.zip (also usable by MVT)
tools/adb_collect.sh --system-apks out_dir # + every system APK (large)
```

It produces the same folder layout, plus `/data/local/tmp` listing and APK installer files found on shared storage.
You can run both: the Collector for the Sentinel report and usage stats, the script for the bugreport.

---

## 5. droidtriage: offline analysis

### 5.1 Install and run

```bash
cd analyzer
pip install -e .                      # adds the `droidtriage` command (or use: python3 -m droidtriage …)
droidtriage iocs update               # once: stalkerware + MVT spyware feeds
droidtriage analyze ~/evidence/droidcollect_Pixel_7_20261021.zip --open
```

Python 3.9+, standard library only. `analyze` accepts a zip, an extracted folder, or an `adb_collect.sh` folder.
`droidtriage EVIDENCE` without a command still works (shortcut for `analyze`).

### 5.2 Commands

| Command | What it does | Exit code |
|---|---|---|
| `analyze EVIDENCE` | full analysis → `report.html`, `report.json`, `findings.csv`, `apps.csv`, `timeline.csv` | 0 clean · 1 HIGH · 2 malware · 3 error |
| `apk FILE.apk …` | static analysis of standalone APKs (manifest, signers, code rules, trackers, hosts) + IOC check | 2 on IOC hit |
| `diff OLD.json NEW.json` | apps added/removed/changed, new and resolved findings, score changes | 0 |
| `iocs update` / `stats` / `check VALUE…` | download feeds, show what's loaded, test a package/domain/hash/IP | `check`: 2 on match |
| `vt lookup HASH_OR_FILE…` | VirusTotal verdicts (files are hashed locally; only the hash is sent) | 2 if ≥3 engines |
| `vt upload FILE` | uploads a file after you type `UPLOAD` (`--yes` for scripts) | 0 |
| `sample OUT.zip [--apk real.apk]` | synthetic evidence with planted indicators: try the whole pipeline without a phone | 0 |
| `rules [--json]` | list analysers, logcat rules, APK code rules, trackers, packers | 0 |

Global flags (any position): `-q/--quiet`, `-v/--verbose` (per-analyser timings), `--no-color` (or `NO_COLOR=1`).

**`analyze` options**

| Group | Option | Effect |
|---|---|---|
| output | `-o DIR` | output folder (default `<evidence>_report`) |
| | `-f html,json,csv` | formats to write (default all) |
| | `--open` | open the HTML report when done |
| | `--json` | print summary + findings as JSON on stdout (`--json -q \| jq .summary`) |
| | `--top N`, `--min-severity SEV` | how much of the console summary to show (default 15, HIGH) |
| | `--fail-on high\|malware\|never` | exit-code policy for scripts (default high) |
| intelligence | `--ioc PATH` | extra IOC file/folder (YAML, STIX2, or text list), repeatable |
| | `--no-default-iocs` | ignore the default IOC folder (`$DROIDTRIAGE_IOCS`, `analyzer/iocs`, or `~/.local/share/droidtriage/iocs`) |
| | `--trusted-installer PKG` | treat another store as trusted, repeatable |
| | `--baseline report.json` | flag apps new since last time and signer/binary changes; NEW badge on findings |
| VirusTotal | `--vt-key` / `VT_API_KEY` | hash lookups (cached 7 days in `~/.cache/droidtriage`) |
| | `--vt-scope sideloaded\|user\|all`, `--vt-max N` | what to look up (default user apps, sideloaded first, 200 max) |
| | `--vt-upload PKG`, `--yes` | **upload** that APK after typed confirmation |
| performance | `-j N` | parallel APK workers (default min(4, CPUs)) |
| | `--max-apk-mb MB` | skip static analysis of larger APKs (default 300) |
| | `--skip a,b` | skip analysers: `inventory, apk, virustotal, device, dumpsys, packages, logcat, network` |

Examples:

```bash
VT_API_KEY=xxx droidtriage analyze e.zip --vt-scope sideloaded --vt-max 100
droidtriage analyze new.zip --baseline old_report/report.json --fail-on malware
droidtriage analyze e.zip --ioc my_iocs.txt --trusted-installer org.fdroid.basic -j 8
droidtriage apk ~/Downloads/suspicious.apk
droidtriage iocs check com.systemservice copy9.com
droidtriage diff march/report.json april/report.json
droidtriage sample demo.zip && droidtriage analyze demo.zip --open
```

### 5.3 What it analyses

| Analyser | Input | Examples of detections |
|---|---|---|
| Inventory | `packages.json`, or dumpsys package + pm list | sideloaded, hidden, impersonation, platform key, debug cert, StrandHogg affinity, stalkerware capability profile, install bursts, recent sideloads |
| APK static | `apks/*/*.apk` | binary manifest (receivers, priorities, secret codes), signing certs (v1/v2/v3), 26 code rules (DexClassLoader, SMS send, screen capture, gesture injection, Telegram/Discord C2…), 30 tracker SDKs, 12 packers, embedded DEX/ELF/APK payloads, encrypted assets, hard-coded hosts and IPs, archive vs device hash and signer mismatch |
| Device | getprop, settings, device_state | test-keys, userdebug, adb root, verified boot, unlocked bootloader, dm-verity, SELinux, encryption, patch age, Play Protect off, proxy, user CAs, always-on VPN, `/data/local/tmp` content |
| dumpsys | ~40 services | enabled accessibility/notification/admins, **device owner**, roles held by sideloaded apps, **background camera/mic/location use (appops)**, persisted jobs and wake-up alarms, privileged native crashes (dropbox), authorised ADB computers, settings change history, users/profiles, account types |
| Logcat | all buffers | su/Magisk, Xposed/LSPosed, Frida, code loaded from writable paths, admin added, MediaProjection, SMS sends, USSD, call forwarding, CA installs, ADB sessions, background clipboard reads, Play Protect warnings, wipe requests, background process starts, IOC domains |
| Network | Sentinel DNS log, netstats, APK hosts | IOC/DGA/dyn-DNS/tunnel/Telegram lookups per app, apps uploading while never opened, hidden apps uploading, IOC endpoints embedded in code |
| VirusTotal | hashes | detections and family labels |

### 5.4 Reading the report

Open `report.html` (works offline, light/dark).

1. **Start with "Coverage & blind spots".** A clean report with `logcat LIMITED` or `dumpsys MISSING` only
   means those sources weren't available. Grant the permissions and collect again.
2. **Malware tile / CRITICAL findings:** IOC matches and VirusTotal ≥ 3 engines. Treat these as confirmed and follow
   the *evidence / next steps* advice under each finding.
3. **HIGH findings:** abusable access (accessibility, admin, SMS), hidden apps, tampering, insecure device state.
   For each app, ask *"Did I install this and enable this on purpose?"*
4. **Timeline:** sort out *when* things happened. An install burst, then accessibility enabled, then Play Protect
   disabled within minutes is the classic sequence of someone setting up stalkerware by hand.
5. **Apps tab:** sort by Security/Privacy. Expand *more* for signer, trackers, endpoints in code, DNS seen and payloads.
6. **Network tab:** flagged DNS per app and the top uploaders.
7. Export `findings.csv` / `timeline.csv` for your notes or a support organisation.

### 5.5 Common false positives

| Finding | Usually benign when… |
|---|---|
| Accessibility enabled | password managers, automation (Tasker), screen readers, launchers you chose |
| Installed outside a trusted store | F-Droid apps, apps you built yourself, enterprise apps |
| Debug certificate | your own builds (including these two tools if built in debug) |
| Packed with … | some Chinese-market banking and OEM apps |
| VirusTotal 1–2 detections | adware SDKs, generic heuristics: read the labels |
| Root indicators | you rooted the phone yourself |
| ADB session / USB debugging on | you collected over adb |
| VPN provider / active VPN | your VPN app, DroidSentinel's DNS monitor, PCAPdroid |

---

## 6. A semi-automated routine

| When | What |
|---|---|
| Always | DroidSentinel monitor + DNS monitor on. React to its notifications |
| Weekly | Glance at the dashboard. Run *VirusTotal check apps* after installing new apps |
| Monthly, or when something feels off | DroidCollector → zip → `droidtriage analyze evidence.zip --baseline last/report.json` → review the NEW findings |
| After a Malwarebytes detection | Collect **before** removing, run droidtriage, look at the timeline around the install date, then remove |
| If you suspect state-level spyware | `tools/adb_collect.sh --bugreport`, then MVT `mvt-android check-bugreport --iocs …`, then contact Amnesty Security Lab or Access Now |

`droidtriage`'s exit codes let you script it, for example: `droidtriage analyze new.zip --baseline old.json -q || notify-send "Phone check: findings"`.

---

## 7. Using this alongside Malwarebytes

* During the trial, run a full Malwarebytes scan **and** this suite. Compare the results with
  [`RISK_MATRIX.md`](RISK_MATRIX.md): Malwarebytes covers known threats and web/SMS scams, while this suite covers
  configuration abuse, integrity, per-app network behaviour and forensic history.
* If Malwarebytes detects something, search its package name in `report.html`. The timeline shows when it arrived
  and what it was allowed to do.
* After the trial ends, Malwarebytes Free still allows manual scans.

---

## 8. Troubleshooting

| Problem | Fix |
|---|---|
| Collector shows ✖ READ_LOGS after `pm grant` | reopen the app; on Android 13+ accept the log-access dialog during collection |
| `SENTINEL_REPORT ✖` | install Sentinel **before** the Collector, and sign both with the same key. Reinstall the Collector |
| Sentinel stops after a while | battery optimisation: allow unrestricted battery use; some OEMs (Xiaomi, Huawei, Samsung) need "autostart" too, see dontkillmyapp.com |
| DNS monitor shows no queries | Private DNS set to a hostname (Strict) bypasses it; another VPN is active; the app uses DoH |
| Traffic tab empty | grant usage access; NetworkStats arrive with a delay |
| `logcat LIMITED` in report | READ_LOGS not granted, or you denied the Android 13 prompt |
| Analyzer is slow | huge logcat or many APKs; use `--max-apk-mb 100`, or collect without system APKs |
| Malwarebytes flags the tools | expected (see §2); verify `SHA256SUMS` from your own build |

## 9. Privacy statement of the tools

* DroidSentinel: on-device only. Network use is limited to VirusTotal lookups (hashes/domains) you enabled,
  a VirusTotal upload you confirmed, the IOC download you tapped, and forwarding DNS queries to your resolver.
* DroidCollector: no network permission use at all (it doesn't even request `INTERNET`). It writes only to the
  file you choose.
* droidtriage: offline, except `iocs update` and the VirusTotal options/commands you use.
