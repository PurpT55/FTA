---
name: fta-verify-without-sdk
description: Build, test and verify this repo in a restricted sandbox (no Android SDK, dl.google.com blocked, Maven Central rate limits, no device). Use before committing changes to android/ or analyzer/, when a Gradle/Android build is impossible, or when checking the HTML report renders.
---

# Verifying FTA without the Android SDK

## Python analyzer (always possible)
```bash
cd analyzer
python3 -W error::ResourceWarning -m unittest discover -s tests -t .      # 51 tests, < 1 s
uv python install 3.9 && $(uv python find 3.9) -m unittest discover -s tests -t .   # minimum supported version
```
- Real-APK parser tests are opt-in. Download any public APK (GitHub releases work; f-droid.org may be blocked), e.g.
  `curl -LO https://github.com/emanuele-f/PCAPdroid/releases/download/v1.7.2/PCAPdroid_v1.7.2.apk`, then
  `DROIDTRIAGE_TEST_APK=PCAPdroid_v1.7.2.apk python3 -m unittest tests.test_apk`.
- **Don't use `python3 -I -m droidtriage`**: `-I` drops the cwd from `sys.path`, so the package isn't found. Run from
  `analyzer/` without `-I`, or `pip install -e analyzer`.
- Never generate fake/synthetic APK, DEX or signature files as test fixtures. Test the rule layer with plain
  strings/dicts (`apk.code_findings`, `apk.manifest_findings`) and the binary parsers with a real APK.

## Kotlin (Android apps) without the SDK
```bash
tools/kotlin_check.sh            # compile all modules + run JVM unit tests (≈1 min, first run downloads 130 MB)
tools/kotlin_check.sh compile    # type-check only
```
How it works: `tools/kotlin_check/` is a plain Kotlin/JVM Gradle project that compiles `android/*/src/main`
against Robolectric's `android-all` jar (the real Android 14 framework, published on Maven Central) and runs
`core`/`sentinel` unit tests with that jar on the classpath (real `org.json`, etc.).
Limits: hidden APIs also compile there, and resources, manifests and lint aren't checked. `./gradlew test assembleRelease`
in CI is the real authority.

Sandbox pitfalls seen in this project:
- `dl.google.com` (Android SDK, Google Maven via dl) is blocked, while `maven.google.com` and Maven Central are reachable.
- Maven Central returns **HTTP 429** under bursts. Use `repo1.maven.org/maven2` explicitly and retry with backoff (the script does).
- `gradle wrapper` run inside `android/` tries to resolve AGP plugins. Generate the wrapper in an empty folder and copy it in.
- `JAVA_TOOL_OPTIONS` proxy settings print a "Picked up…" line on every JVM start. Filter it, don't treat it as an error.
- The JDK in the sandbox may be 21 while the project targets 17: the harness reads `JDK_VERSION` from `java -version`.

## HTML report
Render with Playwright and Chromium (preinstalled; don't run `playwright install`):
```js
const { chromium } = require('/opt/node-tools/node_modules/playwright');   // global install location here
// open file://…/report.html in dark (1280px) and light (390px) colour schemes, collect pageerror/console errors,
// click every nav tab, assert document.documentElement.scrollWidth <= viewport width
```

## Before committing
1. Python tests + `tools/kotlin_check.sh` green.
2. `python3 tools/gen_index.py` (CI runs `--check`).
3. No `android-all.jar`, `build/`, `.gradle/` or evidence zips staged (`git status --short`).
