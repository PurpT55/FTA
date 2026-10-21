#!/usr/bin/env bash
# adb_collect.sh – collect the same evidence as DroidCollector, from a computer over USB.
# The shell user has more rights than an app (full dumpsys, all logcat, pm), so use this
# when you can. Nothing is uploaded; output is a folder (+ optional zip) on this computer.
#
# usage: tools/adb_collect.sh [-s SERIAL] [--system-apks] [--bugreport] [--no-apks] [OUTDIR]
set -uo pipefail

SERIAL=() ; SYSAPKS=0 ; BUGREPORT=0 ; APKS=1 ; OUT=""
while [ $# -gt 0 ]; do
  case "$1" in
    -s) SERIAL=(-s "$2"); shift 2 ;;
    --system-apks) SYSAPKS=1; shift ;;
    --bugreport) BUGREPORT=1; shift ;;
    --no-apks) APKS=0; shift ;;
    -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
    *) OUT="$1"; shift ;;
  esac
done
A() { adb "${SERIAL[@]}" "$@"; }
S() { A shell "$@" 2>&1 | tr -d '\r'; }

command -v adb >/dev/null || { echo "adb not found (install Android platform-tools)"; exit 1; }
STATE=$(A get-state 2>&1)
[ "$STATE" = "device" ] || { echo "No authorised device ($STATE). Enable USB debugging and accept the prompt."; exit 1; }
MODEL=$(S getprop ro.product.model | tr ' ' '_')
OUT=${OUT:-droidcollect_adb_${MODEL}_$(date +%Y%m%d_%H%M%S)}
mkdir -p "$OUT"/{device,packages,dumpsys,logs,proc,apks,usage}
echo "Collecting into $OUT"
log() { printf '  %s\n' "$*"; }

cat > "$OUT/manifest.json" <<JSON
{"tool":"adb_collect.sh","formatVersion":1,"device":"$(S getprop ro.product.manufacturer) $(S getprop ro.product.model) (Android $(S getprop ro.build.version.release), API $(S getprop ro.build.version.sdk))","startedAt":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","capabilities":{"READ_LOGS":true,"DUMP":true,"USAGE_ACCESS":false}}
JSON

log "device properties and settings"
S getprop > "$OUT/device/getprop.txt"
for ns in global secure system; do S settings list "$ns" > "$OUT/device/settings_$ns.txt"; done
S ls -la /data/local/tmp > "$OUT/device/data_local_tmp.txt"          # exploit/dropper staging area
S "find /sdcard -iname '*.apk' 2>/dev/null" > "$OUT/device/sdcard_apks.txt"
S dumpsys connectivity > "$OUT/device/networks.txt"

log "package inventory"
S pm list packages -f -i -U > "$OUT/packages/pm_list.txt"
S pm list packages -u > "$OUT/packages/pm_list_uninstalled_kept_data.txt"
S cmd package query-activities --brief -a android.intent.action.MAIN -c android.intent.category.LAUNCHER \
  > "$OUT/packages/launcher_activities.txt"

log "dumpsys"
S dumpsys -l > "$OUT/dumpsys/_services.txt"
for svc in package activity accessibility device_policy notification appops jobscheduler alarm usagestats netstats \
  connectivity wifi location telecom telephony.registry account user settings input_method autofill role permission \
  persistent_data_block battery batterystats power deviceidle media.camera audio media_projection sensorservice \
  vpn_management "dropbox --print" procstats meminfo cpuinfo "window windows" overlay credential clipboard \
  bluetooth_manager statusbar adb package_native; do
  f=$(echo "$svc" | sed 's/ --/_/; s/ /_/g')
  read -r -a svc_args <<< "$svc"        # "dropbox --print" -> two arguments
  timeout 120 adb "${SERIAL[@]}" shell dumpsys "${svc_args[@]}" 2>&1 | tr -d '\r' > "$OUT/dumpsys/$f.txt"
done

log "logcat (all buffers)"
for b in main system crash events radio; do
  A logcat -b "$b" -d -v threadtime -v uid 2>&1 | tr -d '\r' > "$OUT/logs/logcat_$b.txt"
done
A logcat -L -d -v threadtime 2>&1 | tr -d '\r' > "$OUT/logs/logcat_last_boot.txt"

log "processes and /proc"
S ps -A -o USER,PID,PPID,NAME > "$OUT/proc/ps.txt"
for f in version cpuinfo meminfo mounts net/tcp net/tcp6 net/udp net/udp6; do S cat "/proc/$f" > "$OUT/proc/$(echo $f | tr / _).txt"; done
S getenforce > "$OUT/proc/getenforce.txt"

if [ "$APKS" = 1 ]; then
  if [ "$SYSAPKS" = 1 ]; then LIST=$(S pm list packages | cut -d: -f2); else LIST=$(S pm list packages -3 | cut -d: -f2); fi
  N=$(echo "$LIST" | wc -l); i=0
  for p in $LIST; do
    i=$((i+1)); printf '\r  APKs %d/%d %-60s' "$i" "$N" "$p"
    mkdir -p "$OUT/apks/$p"
    for path in $(S pm path "$p" | sed 's/^package://'); do
      A pull "$path" "$OUT/apks/$p/$(basename "$path")" >/dev/null 2>&1 || echo "$p $path" >> "$OUT/collection_errors.txt"
    done
  done
  echo
fi

if [ "$BUGREPORT" = 1 ]; then
  log "bugreport (takes 2–5 min; also usable with: mvt-android check-bugreport)"
  A bugreport "$OUT/bugreport.zip" >/dev/null
fi

if command -v zip >/dev/null; then (cd "$OUT/.." && zip -qr "$(basename "$OUT").zip" "$(basename "$OUT")") && echo "Zipped: $OUT.zip"; fi
echo "Done. Analyse with:  cd analyzer && python3 -m droidtriage ../$OUT"
