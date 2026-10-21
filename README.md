# FTA – Forensic Triage for Android

A defensive toolkit to check **your own** Android phone for spyware, stalkerware, tampering and privacy abuse,
built to complement scanners like Malwarebytes.

| Component | What it is | Where |
|---|---|---|
| **DroidSentinel** (APK) | Real-time monitor with a dashboard: privacy risk, security risk, suspicious activity, unknown binaries, malware detected. Watches app installs/updates, **APK integrity** (binary or signer changed without a proper update), per-app **DNS** (local DNS-only VPN), screen-off uploads, accessibility/admin/notification/overlay abuse, task hijacking, root/CA/proxy. **VirusTotal hash lookups**; uploads only after explicit confirmation | `android/sentinel` |
| **DroidCollector** (APK) | After you confirm, exports logcat, ~40 dumpsys services, settings, props, CA certs, usage and network history, full app inventory, **APKs** and the Sentinel report into one hashed zip. No network access | `android/collector` |
| **droidtriage** (Python) | Offline deep analysis of that zip: package and permission rules, pure-python APK static analysis (manifest, DEX, v1/v2/v3 certs, payloads, packers, trackers), logcat/dumpsys/appops parsing, stalkerware + MVT spyware IOCs, VirusTotal, timeline, baseline diff → `report.html`, JSON, CSV | `analyzer/` |
| `adb_collect.sh` | Same evidence collected from a computer over adb (+ optional bugreport for MVT) | `tools/` |

**Docs:** [User guide](docs/GUIDE.md) · [Risk coverage matrix: Malwarebytes vs this suite vs other tools](docs/RISK_MATRIX.md) ·
[Project index (machine-readable)](PROJECT_INDEX.json) · [Contributor notes for agents](CLAUDE.md)

## Development

```bash
./setup.sh --check                                            # toolchain status (JDK 17, Android SDK)
tools/build.sh                                                # all tests + release APKs into dist/
cd analyzer && python3 -m unittest discover -s tests -t .     # Python tests only (stdlib)
tools/kotlin_check.sh                                         # Kotlin compile + 16 JVM tests, no Android SDK needed
. ./.fta-env && cd android && ./gradlew test assembleRelease # Gradle by hand (after setup.sh)
python3 tools/gen_index.py                                    # refresh PROJECT_INDEX.json after changes
```

Extending: add an analyser with `@analyzer(...)` (Python) or a rule to `AppRules.ALL` / `DeviceRules.ALL` (Kotlin);
step-by-step in `.claude/skills/add-detection-rule/SKILL.md`.

## Quick start

```bash
# 1. Install the pinned toolchain (JDK 17 + Android SDK), build and test everything -> dist/
./setup.sh                     # Debian/Ubuntu/Fedora/Arch/openSUSE; add -y --accept-licenses for unattended

# 2. Install (Sentinel first) and boost the Collector
adb install dist/DroidSentinel-release.apk
adb install dist/DroidCollector-release.apk
adb shell pm grant org.droidsuite.collector android.permission.READ_LOGS
adb shell pm grant org.droidsuite.collector android.permission.DUMP
adb shell appops set org.droidsuite.collector GET_USAGE_STATS allow

# 3. On the phone: DroidSentinel → grant usage access, add VirusTotal key, download IOCs, start monitor + DNS monitor
#    Later: DroidCollector → Collect… → confirm → save zip → copy to computer

# 4. Analyse
cd analyzer && pip install -e .
droidtriage iocs update
droidtriage analyze /path/to/droidcollect_*.zip --open

# Demo without a phone:
droidtriage sample /tmp/demo.zip && droidtriage analyze /tmp/demo.zip --open
```

## Design principles

* **Nothing leaves the phone without you asking.** VirusTotal gets hashes only. File uploads need a per-file confirmation (app) or a typed `UPLOAD` (CLI).
* **Collect before you clean.** The guide explains how to preserve evidence before removing anything flagged.
* **Honest coverage.** Every report lists what it could not see (missing permissions, bypassed DNS, etc.).
* **No dependencies.** The Android apps use only framework APIs (no AndroidX); the analyzer uses only the Python standard library.

## Requirements

Android 8.0+ (API 26; per-app DNS attribution needs Android 10+). Python 3.9+ for the analyzer.

## Legal

Use only on devices you own or are explicitly authorised to examine. If you think a partner or family member is monitoring
you, see <https://stopstalkerware.org> before removing anything.
