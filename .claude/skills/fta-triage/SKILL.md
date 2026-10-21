---
name: fta-triage
description: Analyse Android phone evidence (DroidCollector zip, adb_collect.sh folder, or a single APK) with droidtriage and explain the results. Use when the user wants to check a phone for stalkerware/spyware/malware, analyse a collection zip, compare two collections, check an APK, or interpret report.html / report.json from this repo.
---

# Android evidence triage with droidtriage

## 0. Safety first (say this to the user when relevant)
- **Collect before cleaning**: uninstalling a flagged app destroys its APK and history. Collect first.
- **Possible abusive partner/family member** (stalkerware): removing the app can alert them. Point to
  https://stopstalkerware.org before advising removal.
- **Never upload a file to VirusTotal without explicit user consent.** Hash lookups are fine if they asked for VirusTotal.
  Uploads go through `droidtriage vt upload` / `--vt-upload`, which require typed confirmation.
- Evidence zips contain personal data: don't paste their contents into external services.

## 1. Run
```bash
cd analyzer                                   # or `pip install -e analyzer` once, then `droidtriage …` anywhere
python3 -m droidtriage iocs update            # once per session if analyzer/iocs/ has no feeds (network)
python3 -m droidtriage analyze EVIDENCE -o OUT -q            # zip, extracted folder, or adb_collect.sh folder
python3 -m droidtriage analyze EVIDENCE --json -q > summary.json   # machine-readable summary + findings
```
- Exit code: 0 clean, 1 HIGH findings, 2 malware indicators, 3 usage/IO error (not a crash).
- No phone handy? `python3 -m droidtriage sample demo.zip` builds evidence with planted indicators.
- Single APK: `python3 -m droidtriage apk file.apk` (add `--json` to get everything).
- Two collections: `analyze new.zip --baseline old/report.json`, or `diff old/report.json new/report.json`.
- VirusTotal (hash only): `VT_API_KEY=… analyze … --vt-scope sideloaded`. The free tier allows 4 lookups/min, so
  warn the user about the time (`--vt-max` limits it).

## 2. Read the results in this order
1. `coverage` in report.json (or the console COVERAGE table). Anything not starting with `ok` is a **blind spot**:
   - `logcat LIMITED`: READ_LOGS wasn't granted (`adb shell pm grant org.droidsuite.collector android.permission.READ_LOGS`).
   - `dumpsys MISSING`: grant DUMP, or use `tools/adb_collect.sh`.
   - `dns MISSING`: DroidSentinel's DNS monitor wasn't running.
   Never call a phone "clean" without listing these.
2. `summary.malware`: IOC matches (package, signer SHA-1, hash, domain), VirusTotal ≥3, platform-key-signed user apps.
3. CRITICAL/HIGH findings, grouped by package. For each package, check `apps[]`: installer
   (`sideloaded`), `launcher` false = hidden icon, `firstInstall`, signer, granted permissions.
4. `timeline`: look for clusters. Sideload burst → accessibility enabled → Play Protect off within minutes is
   the classic hands-on stalkerware install.
5. Each finding has `advice` (playbook) and `mitre`. Quote the advice instead of inventing remediation.

## 3. Known false positives (don't alarm the user)
Accessibility enabled for password managers, Tasker or launchers; F-Droid or self-built apps flagged as "untrusted
installer"; 1–2 VirusTotal hits (adware heuristics); root indicators on a phone the user rooted; ADB sessions/USB
debugging during the collection itself; VPN findings for the user's own VPN or DroidSentinel's DNS monitor.

## 4. Reporting back
Lead with the verdict and the blind spots, then the top findings per app with the evidence (finding id,
installer, install date), then the next steps from `advice`. Link `report.html` for the full picture.
