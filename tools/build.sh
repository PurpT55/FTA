#!/usr/bin/env bash
# Build and test everything with the toolchain chosen by ./setup.sh; artefacts land in dist/.
#
#   tools/build.sh                 Python tests + Android unit tests + release APKs + index check
#   tools/build.sh --debug         debug APKs instead
#   tools/build.sh --skip-tests    APKs only
#
# Reads .fta-env (JAVA_HOME, ANDROID_HOME) written by setup.sh; refuses to run with anything but a
# JDK 17 so builds are identical on every machine. dist/BUILD_INFO.txt records the exact toolchain.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TYPE=release; TESTS=1
for a in "$@"; do
  case "$a" in
    --release) TYPE=release ;; --debug) TYPE=debug ;; --skip-tests) TESTS=0 ;;
    -h|--help) sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $a" >&2; exit 2 ;;
  esac
done
die() { echo "✖ $*" >&2; exit 1; }
step() { printf '\e[1m▸ %s\e[0m\n' "$*"; }

ENV_FILE=${FTA_ENV:-$ROOT/.fta-env}       # FTA_ENV=/dev/null ignores it (tests)
# shellcheck source=/dev/null
if [ -f "$ENV_FILE" ]; then . "$ENV_FILE"; fi
[ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/javac" ] || die "JAVA_HOME is not a JDK (no javac). Run ./setup.sh first."
jv=$(sed -n 's/^JAVA_VERSION="\([0-9]*\).*/\1/p' "$JAVA_HOME/release" 2>/dev/null || true)
[ "$jv" = 17 ] || die "JAVA_HOME=$JAVA_HOME is Java ${jv:-?}, the build is pinned to 17. Run ./setup.sh (or export JAVA_HOME to a JDK 17)."
if [ -z "${ANDROID_HOME:-}" ] && ! grep -q '^sdk.dir=' "$ROOT/android/local.properties" 2>/dev/null; then
  die "Android SDK location unknown (no ANDROID_HOME, no android/local.properties). Run ./setup.sh."
fi
export PATH="$JAVA_HOME/bin:$PATH"
# Reproducibility: tools that honour SOURCE_DATE_EPOCH use the last commit time instead of "now".
SOURCE_DATE_EPOCH=$(git -C "$ROOT" log -1 --format=%ct 2>/dev/null || date +%s); export SOURCE_DATE_EPOCH

if [ "$TESTS" = 1 ]; then
  step "Python tests (analyzer)"
  (cd "$ROOT/analyzer" && python3 -W error::ResourceWarning -m unittest discover -s tests -t . 2>&1 | tail -3)
  (cd "$ROOT" && python3 -m unittest discover -s tools/tests -t . 2>&1 | tail -3)
fi

step "Gradle ($TYPE)"
Cap=${TYPE^}
tasks=("assemble$Cap"); [ "$TESTS" = 1 ] && tasks=("test" "${tasks[@]}")
(cd "$ROOT/android" && ./gradlew --no-daemon --console=plain --warning-mode=summary "${tasks[@]}")

step "Collecting artefacts in dist/"
rm -rf "$ROOT/dist" && mkdir -p "$ROOT/dist"
cp "$ROOT/android/sentinel/build/outputs/apk/$TYPE/"*.apk "$ROOT/dist/DroidSentinel-$TYPE.apk"
cp "$ROOT/android/collector/build/outputs/apk/$TYPE/"*.apk "$ROOT/dist/DroidCollector-$TYPE.apk"
(cd "$ROOT/dist" && sha256sum ./*.apk > SHA256SUMS)
{
  echo "commit=$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)$(git -C "$ROOT" diff --quiet 2>/dev/null || echo ' (dirty)')"
  echo "commit_date=$(git -C "$ROOT" log -1 --format=%cI 2>/dev/null || echo unknown)"
  echo "jdk=$(sed -n 's/^IMPLEMENTOR="\(.*\)"/\1/p' "$JAVA_HOME/release") $(sed -n 's/^JAVA_VERSION="\(.*\)"/\1/p' "$JAVA_HOME/release")"
  echo "gradle=$(sed -n 's/^distributionUrl=.*gradle-\(.*\)-bin.zip/\1/p' "$ROOT/android/gradle/wrapper/gradle-wrapper.properties")"
  echo "agp=$(sed -n 's/.*com.android.application") version "\(.*\)".*/\1/p' "$ROOT/android/build.gradle.kts")"
  echo "kotlin=$(sed -n 's/.*kotlin.android") version "\(.*\)".*/\1/p' "$ROOT/android/build.gradle.kts")"
  echo "build_type=$TYPE"
  echo "signing_cert_sha256=$("$JAVA_HOME/bin/keytool" -list -v -keystore "$ROOT/android/suite.keystore" -storepass "${SUITE_KEYSTORE_PASSWORD:-droidsuite}" 2>/dev/null | sed -n 's/.*SHA256: //p' | head -1 || true)"
} > "$ROOT/dist/BUILD_INFO.txt"
if [ "$TESTS" = 1 ]; then (cd "$ROOT" && python3 tools/gen_index.py --check); fi
cat "$ROOT/dist/SHA256SUMS"
echo "✔ APKs in dist/  –  install: adb install dist/DroidSentinel-$TYPE.apk && adb install dist/DroidCollector-$TYPE.apk"
