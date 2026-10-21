---
name: fta-android-internals
description: Reference on the Android data formats and platform limits this repo relies on — evidence zip layout, dumpsys/logcat/appops formats, binary manifest/DEX/signing-block parsing, timestamps, IOC feed formats, and what apps can or cannot see without root. Use when parsing a new evidence source, debugging a parser, or deciding whether a detection is feasible on device vs offline.
---

# Android internals used by FTA

## Evidence layout (DroidCollector zip == adb_collect.sh folder)
`manifest.json` (tool, device, startedAt, capabilities{READ_LOGS,DUMP,USAGE_ACCESS}, files[{path,size,sha256,source}]) ·
`device/{getprop.txt,settings_{global,secure,system}.txt,device_state.json,ca_user/*.pem,ca_all.tsv,networks.txt,data_local_tmp.txt,sdcard_apks.txt}` ·
`packages/{packages.json | pm_list.txt + launcher_activities.txt}` · `apks/<pkg>/{base,split_*}.apk` ·
`logs/logcat_<buffer>.txt` · `dumpsys/<service>.txt` (`dropbox --print` → `dropbox_print.txt`) ·
`usage/{usage_events,usage_daily,netstats_uid}.tsv` · `proc/*` · `sentinel/report.json`.
`Evidence` strips one wrapping folder in zips. Always use `ev.first(a, b)` when both layouts differ.

## Text formats
- **getprop**: `[key]: [value]`.
- **logcat** `-v threadtime -v uid`: `MM-DD HH:MM:SS.mmm UID PID TID L Tag: msg`. **No year**: `model.norm_ts`
  takes it from `manifest.startedAt` (and goes back a year if the date would be in the future). `Start proc N:pkg/uid for <type> {comp}`
  gives the reason a process started (`activity` = user, `service`/`broadcast` = background).
- **dumpsys package** (`Packages:` section only; stop at the next column-0 header such as `Hidden system packages:`):
  `  Package [pkg] (hash):`, then `userId=`, `versionCode=N minSdk=N targetSdk=N`, `flags=[ SYSTEM … ]`,
  `firstInstallTime=YYYY-MM-DD HH:MM:SS`, `installerPackageName=`, `requested permissions:` list,
  `install permissions:` and per-user `runtime permissions:` as `perm: granted=true`.
- **dumpsys appops**: `Package pkg:` → `OP (mode):` → `Access: [fg-s|bg-s|…] YYYY-MM-DD HH:MM:SS.mmm`
  (older Android: `time=+1h2m ago`). `bg` = used while the app was in the background.
- **dumpsys device_policy**: `Device Owner:` / `admin=ComponentInfo{pkg/cls}`. **role**: `name=android.app.role.SMS` / `holders=pkg`.
- **dumpsys dropbox --print**: `YYYY-MM-DD HH:MM:SS TAG` entries. `SYSTEM_TOMBSTONE` / `*_native_crash` in media,
  Bluetooth or messaging processes can mean exploitation attempts. They're an indicator, not proof.
- **dumpsys adb**: authorised ADB keys `QAAAA… user@host`. **settings**: historical operations include who changed
  `enabled_accessibility_services`, `package_verifier_enable`, …

## Binary formats (parsers in `apk.py`)
- **Binary XML (AndroidManifest.xml)**: chunk header `<HHI` (type, headerSize, size). 0x0001 string pool (UTF-8 flag
  0x100; lengths are 1–2 bytes in UTF-8 and 2–4 bytes in UTF-16), 0x0180 resource-id map (used when attribute names are
  stripped: 0x01010003 name, 0x01010006 permission, 0x01010010 exported, 0x0101001c priority, 0x01010012 taskAffinity),
  0x0102 start element (name index at +20; attrStart/attrSize/attrCount at +24; attributes 20 bytes each:
  ns, name, raw, size, res0, type, data; type 0x03 string, 0x10/0x11 int, 0x12 bool). `exported` defaults to
  "has an intent-filter".
- **DEX string table**: `string_ids_size`/`off` at header 0x38/0x3C → u32 offsets → ULEB128 length + MUTF-8 bytes,
  NUL-terminated. The strings include class names (`Lcom/x/Y;`), method names and literals. Matching on them is
  cheap static analysis; use exact-match for short tokens like `su`.
- **Signing certs**: v1 = PKCS#7 in `META-INF/*.RSA|DSA|EC` (first cert in SignedData `[0]`). v2/v3 = "APK Signing
  Block" just before the central directory (magic `APK Sig Block 42`; ids 0x7109871a v2, 0xf05368c0 v3,
  0x1b93ad61 v3.1; signer → signed data → certificates, all u32-length-prefixed). Stalkerware IOCs use **SHA-1 of
  the cert DER**, while the device and VirusTotal use SHA-256.

## IOC feeds
AssoEchap `ioc.yaml` (`- name:` blocks with packages / certificates / websites / distribution / c2.ips / c2.domains),
MVT STIX2 bundles (`[app:id = '…']`, `[domain-name:value = '…']`, `[file:hashes.sha256 = '…']`, malware ↔ indicator
via `indicates` relationships), plain `type:value` text lists. Domains match by suffix.

## Platform limits (decide on-device vs offline)
| Need | Normal app | With adb grants | adb shell |
|---|---|---|---|
| other apps' logcat | ✗ | READ_LOGS (+ user consent dialog on Android 13+) | ✓ |
| dumpsys | ✗ | DUMP | ✓ |
| list packages | QUERY_ALL_PACKAGES (Android 11+) | – | ✓ |
| APK files of other apps | ✓ readable (`sourceDir`) | – | `pm path` + pull |
| per-app traffic | NetworkStatsManager + usage access (minutes of delay) | – | dumpsys netstats |
| which app opened a socket | only as the VPN owner: `getConnectionOwnerUid` (API 29+) | – | – |
| other apps' app-ops | sometimes refused; wrap in try/catch | – | dumpsys appops |
| Secure settings | public keys + some @Readable hidden ones; others throw on targetSdk ≥ 31 | – | `settings list` |
| app private data, kernel | ✗ | ✗ | ✗ (needs root) |
Foreground services on API 34 need a type (`specialUse` + PROPERTY_SPECIAL_USE_FGS_SUBTYPE here). BOOT_COMPLETED may
start `specialUse` services but not `dataSync`/camera/mic/media types on Android 15.
