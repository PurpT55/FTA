plugins { kotlin("jvm") version "1.9.24" }

repositories { maven("https://repo1.maven.org/maven2") }

val androidAll = files(System.getenv("ANDROID_ALL_JAR") ?: "android-all.jar")
val src = rootDir.resolve("../../android")

dependencies {
    compileOnly(androidAll)
    testImplementation(androidAll)          // real framework classes (org.json etc.) at test runtime
    testImplementation("junit:junit:4.13.2")
}

kotlin { jvmToolchain((System.getenv("JDK_VERSION") ?: "17").toInt()) }

sourceSets {
    main { kotlin.srcDirs("$src/core/src/main/java", "$src/sentinel/src/main/java", "$src/collector/src/main/java") }
    test { kotlin.srcDirs("$src/core/src/test/java", "$src/sentinel/src/test/java") }
}

tasks.test {
    testLogging {
        events("passed", "failed")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}
