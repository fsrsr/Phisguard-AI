import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    id("com.google.devtools.ksp")
    // Firebase
    id("com.google.gms.google-services")
}

// Kredensial penandatangan dibaca dari keystore.properties yang TIDAK
// dilacak git. Bila berkasnya tidak ada (mis. di mesin lain atau CI tanpa
// kunci), build release tetap jalan tapi keluarannya belum ditandatangani.
val keystorePropsFile = rootProject.file("keystore.properties")
val keystoreProps = Properties().apply {
    if (keystorePropsFile.exists()) keystorePropsFile.inputStream().use { load(it) }
}

android {
    namespace = "com.phishguard.ai"
    compileSdk = 36

    buildFeatures {
        buildConfig = true
    }

    defaultConfig {
        applicationId = "com.phishguard.ai"
        minSdk = 24
        targetSdk = 36
        versionCode = 2
        versionName = "2.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    signingConfigs {
        create("release") {
            if (keystorePropsFile.exists()) {
                storeFile = rootProject.file(keystoreProps.getProperty("storeFile"))
                storePassword = keystoreProps.getProperty("storePassword")
                keyAlias = keystoreProps.getProperty("keyAlias")
                keyPassword = keystoreProps.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        release {
            if (keystorePropsFile.exists()) {
                signingConfig = signingConfigs.getByName("release")
            }
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    
    kotlinOptions {
        jvmTarget = "11"
    }

    // android.util.Log melempar "not mocked" di unit test JVM. Kelas
    // heuristik memakai Log untuk penelusuran, jadi kembalikan nilai
    // default supaya bisa diuji tanpa emulator.
    testOptions {
        unitTests.isReturnDefaultValues = true
    }

    // Jangan kompres: keduanya dipetakan ke memori langsung dari APK.
    // .tflite untuk model, .bloom untuk blocklist domain (DomainBlocklist).
    aaptOptions {
        noCompress("tflite", "bloom")
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.material)
    implementation(libs.androidx.activity)
    implementation(libs.androidx.constraintlayout)

    // Room Database (local phishing DB)
    implementation("androidx.room:room-runtime:2.6.1")
    ksp("androidx.room:room-compiler:2.6.1")

    // Gson (JSON parsing untuk server sync)
    implementation("com.google.code.gson:gson:2.10.1")

    // RecyclerView (untuk detected apps list)
    implementation("androidx.recyclerview:recyclerview:1.3.2")

    // TensorFlow Lite — NLP Classifier untuk SMS phishing (framework saja, tanpa support lib)
    // Model inference via Interpreter langsung dari assets/
    implementation("org.tensorflow:tensorflow-lite:2.13.0") {
        exclude(group = "org.tensorflow", module = "tensorflow-lite-api")
    }

    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)

    // ── Firebase (Cloud Phishing DB + Community Crowd) ──────────────────
    // BoM = semua versi Firebase otomatis sinkron
    implementation(platform("com.google.firebase:firebase-bom:33.9.0"))
    implementation("com.google.firebase:firebase-firestore-ktx")  // Cloud phishing/official URL DB
    implementation("com.google.firebase:firebase-analytics-ktx") // Optional analytics
}