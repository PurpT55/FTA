// JVM-only harness: type-checks the Android Kotlin sources and runs their unit tests without the
// Android SDK, using Robolectric's "android-all" framework jar (API 34). See tools/kotlin_check.sh.
pluginManagement { repositories { maven("https://repo1.maven.org/maven2"); gradlePluginPortal() } }
rootProject.name = "kotlin-check"
