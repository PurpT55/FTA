#!/usr/bin/env bash
# Compile the Android Kotlin sources and run their JVM unit tests WITHOUT the Android SDK.
# Uses Robolectric's android-all jar (full Android 14 framework) from Maven Central.
# Useful where dl.google.com is unreachable (CI sandboxes) or for a 1-minute check before a full build.
#
#   tools/kotlin_check.sh            # compile + tests
#   tools/kotlin_check.sh compile    # type-check only
#
# Limits: the jar also contains hidden APIs, so a call to a non-public API would still compile here;
# the real AGP build (./gradlew assembleRelease) remains the authority. Lint/resources are not checked.
set -euo pipefail
cd "$(dirname "$0")/kotlin_check"
JAR=android-all.jar
URL=https://repo1.maven.org/maven2/org/robolectric/android-all/14-robolectric-10818077/android-all-14-robolectric-10818077.jar
[ -s "$JAR" ] || { echo "downloading android-all (≈130 MB)…"; curl -fsSL -o "$JAR" "$URL"; }
JDK_VERSION=${JDK_VERSION:-$(java -version 2>&1 | sed -n 's/.*version "\([0-9]*\).*/\1/p' | head -1)}
export JDK_VERSION
GRADLE=${GRADLE:-$(command -v gradle || echo ../../android/gradlew)}
task=${1:-test}; [ "$task" = compile ] && task=compileKotlin
# Maven Central sometimes answers 429 to bursts: retry a few times.
for i in 1 2 3 4; do
  if "$GRADLE" --console=plain -q "$task" 2>&1 | tee /tmp/kotlin_check.log | { grep -v -e "is deprecated" -e "Picked up JAVA_TOOL_OPTIONS" || true; }; then
    grep -q "429" /tmp/kotlin_check.log && { sleep $((i*20)); continue; }
    echo "kotlin_check: $task OK"; exit 0
  fi
  grep -q "429" /tmp/kotlin_check.log || exit 1
  sleep $((i*20))
done
exit 1
