# Android Forensics Suite

A defensive toolkit to check **your own** Android phone for spyware, stalkerware, tampering and privacy abuse,
built to complement scanners like Malwarebytes.

| Component | What it is | Where |
|---|---|---|
| **DroidSentinel** (APK) | Real-time monitor with a dashboard: privacy risk, security risk, suspicious activity, unknown binaries, malware detected. Watches app installs/updates, **APK integrity** (binary or signer changed without a proper update), per-app **DNS** (local DNS-only VPN), screen-off uploads, accessibility/admin/notification/overlay abuse, task hijacking, root/CA/proxy. **VirusTotal hash lookups**; uploads only after explicit confirmation | `android/sentinel` |
| **DroidCollector** (APK) | After you confirm, exports logcat, ~40 dumpsys services, settings, props, CA certs, usage and network history, full app inventory, **APKs** and the Sentinel report into one hashed zip. No network access | `android/collector` |
| **droidtriage** (Python) | Offline deep analysis of that zip: package and permission rules, pure-python APK static analysis (manifest, DEX, v1/v2/v3 certs, payloads, packers, trackers), logcat/dumpsys/appops parsing, stalkerware + MVT spyware IOCs, VirusTotal, timeline, baseline diff → `report.html`, JSON, CSV | `analyzer/` |
| `adb_collect.sh` | Same evidence collected from a computer over adb (+ optional bugreport for MVT) | `tools/` |

**Docs:** [User guide](docs/GUIDE.md) · [Risk coverage matrix: Malwarebytes vs this suite vs other tools](docs/RISK_MATRIX.md)

## Quick start

```bash
# 1. Build both APKs (or use the GitHub Actions workflow, see the guide)
tools/make_keystore.sh && (cd android && ./gradlew assembleRelease)

# 2. Install (Sentinel first) and boost the Collector
adb install android/sentinel/build/outputs/apk/release/sentinel-release.apk
adb install android/collector/build/outputs/apk/release/collector-release.apk
adb shell pm grant org.droidsuite.collector android.permission.READ_LOGS
adb shell pm grant org.droidsuite.collector android.permission.DUMP
adb shell appops set org.droidsuite.collector GET_USAGE_STATS allow

# 3. On the phone: DroidSentinel → grant usage access, add VirusTotal key, download IOCs, start monitor + DNS monitor
#    Later: DroidCollector → Collect… → confirm → save zip → copy to computer

# 4. Analyse
cd analyzer
python3 -m droidtriage --update-iocs
python3 -m droidtriage /path/to/droidcollect_*.zip -o report     # open report/report.html

# Demo without a phone:
python3 tests/make_sample.py /tmp/sample.zip && python3 -m droidtriage /tmp/sample.zip -o /tmp/sample_report
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
