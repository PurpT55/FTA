plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "org.droidsuite.collector"
    compileSdk = 34
    defaultConfig {
        applicationId = "org.droidsuite.collector"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "1.0.0"
    }
    // Both apps MUST be signed with the same key: the Collector reads the Sentinel
    // report through a signature-protected ContentProvider.
    // Both apps MUST be signed with the same key: the Collector reads the Sentinel
    // report through a signature-protected ContentProvider. Order of preference:
    // 1) SUITE_KEYSTORE env vars (CI / your own release key), 2) android/suite.keystore
    // (created by tools/make_keystore.sh), 3) this machine's default debug key.
    val suiteKs = System.getenv("SUITE_KEYSTORE")?.let { file(it) } ?: rootProject.file("suite.keystore")
    signingConfigs {
        if (suiteKs.exists()) create("suite") {
            storeFile = suiteKs
            storePassword = System.getenv("SUITE_KEYSTORE_PASSWORD") ?: "droidsuite"
            keyAlias = System.getenv("SUITE_KEY_ALIAS") ?: "suite"
            keyPassword = System.getenv("SUITE_KEY_PASSWORD") ?: "droidsuite"
        }
    }
    buildTypes {
        val cfg = signingConfigs.findByName("suite") ?: signingConfigs.getByName("debug")
        getByName("debug") { signingConfig = cfg }
        getByName("release") {
            isMinifyEnabled = false
            signingConfig = cfg
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    lint { abortOnError = false; checkReleaseBuilds = false }
}

dependencies {
    implementation(project(":core"))
}
