import java.util.Properties

plugins {
    alias(libs.plugins.agp.app)
}

// Signing credentials live in keystore.properties (gitignored) so they stay out of
// source control. When the file is absent, release falls back to the debug key.
val keystoreProperties = Properties().apply {
    val file = rootProject.file("keystore.properties")
    if (file.exists()) file.inputStream().use { load(it) }
}
val hasSigningConfig = keystoreProperties.getProperty("storeFile")
    ?.let { file(it).isFile } == true
if (!hasSigningConfig) logger.warn("LocketX: release uses the local debug signing key")

android {
    namespace = "com.locketx.module"
    compileSdk = 37
    buildToolsVersion = "37.0.0"

    defaultConfig {
        applicationId = "com.locketx.module"
        // libxposed api requires minSdk 26.
        minSdk = 26
        targetSdk = 37
        versionCode = 6
        versionName = "1.3.0"
    }

    signingConfigs {
        if (hasSigningConfig) {
            create("release") {
                storeFile = file(keystoreProperties.getProperty("storeFile"))
                storePassword = keystoreProperties.getProperty("storePassword")
                keyAlias = keystoreProperties.getProperty("keyAlias")
                keyPassword = keystoreProperties.getProperty("keyPassword")
                enableV1Signing = true
                enableV2Signing = true
                enableV3Signing = true
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            // Deliberately NOT using the default AGP proguard file: a module is
            // not a normal app, proguard-rules.pro carries the Xposed rules.
            proguardFiles("proguard-rules.pro")
            // Sign with the configured keystore, or the debug key if none is set.
            signingConfig = if (hasSigningConfig) signingConfigs.getByName("release")
                            else signingConfigs["debug"]
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    packaging {
        resources {
            // Keep the Xposed metadata, drop every other java resource so the
            // module APK stays minimal. Note: this affects java resources only,
            // NOT android assets/ or res/.
            merges += "META-INF/xposed/*"
            excludes += "**"
        }
    }

    lint {
        abortOnError = false
        checkReleaseBuilds = false
    }
}

dependencies {
    // Provided by the framework at runtime - must never be packaged.
    compileOnly(libs.libxposed.api)
    // Real code shipped in the APK: manager IPC, remote prefs, remote files.
    implementation(libs.libxposed.service)
    // Not transitive from the AARs above; needed for @RequiresApi etc.
    compileOnly(libs.androidx.annotation)
    testImplementation("junit:junit:4.13.2")
}
