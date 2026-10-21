# FTA – Forensic Triage for Android

Defensive toolkit for checking one's own Android phone: two Android apps (Kotlin, no AndroidX) and an offline
Python analyzer (stdlib only). **Start with `PROJECT_INDEX.json`**: components, files, rules, CLI, tests,
maturity and known limitations in one machine-readable file. Regenerate it after changes with
`python3 tools/gen_index.py`. CI fails on a stale index.

## Layout
- `android/core`: shared Kotlin: `Inventory` (packages, HashPolicy), `DeviceProbe`, `RiskEngine` + `AppRules` / `DeviceRules` (pluggable), `IocDb`, `Ui`.
- `android/sentinel`: DroidSentinel: monitor service, DNS-only VPN, NetworkStats poller, VirusTotal client, SQLite `Store`, dashboard.
- `android/collector`: DroidCollector: consent-gated zip export (`Collector.kt`).
- `analyzer/droidtriage`: `cli.py` → `pipeline.py` → analysers registered with `@analyzer` (`registry.py`) → `report.py`.
- `tools/`: `adb_collect.sh`, `make_keystore.sh`, `kotlin_check.sh` (JVM build/test without SDK), `gen_index.py`, `index_meta.json`.
- `docs/`: `GUIDE.md` (user guide), `RISK_MATRIX.md` (coverage vs Malwarebytes), `sample_report.html`.

## Commands
```bash
cd analyzer && python3 -W error::ResourceWarning -m unittest discover -s tests -t .
tools/kotlin_check.sh                   # Kotlin compile + JVM tests without the Android SDK
python3 tools/gen_index.py [--check]
cd analyzer && python3 -m droidtriage sample /tmp/d.zip && python3 -m droidtriage analyze /tmp/d.zip
```

## Rules of the house
- **Privacy contract**: nothing leaves the phone or computer without an explicit user action. VirusTotal gets
  hashes and domains only. File uploads need typed (CLI) or two-step (app) confirmation. Keep it that way.
- Finding ids are stable `family.rule` strings shared by Kotlin and Python (`tests/test_parity.py`).
- Tests use plain-text/JSON fixtures. Binary parsers are tested against a real APK (`DROIDTRIAGE_TEST_APK`).
  Do not fabricate APK/DEX/signature files.
- Don't add dependencies (no AndroidX, no pip packages) without a strong reason.
- Skills: `.claude/skills/fta-*`: triage, add-detection-rule, verify-without-sdk, android-internals.
