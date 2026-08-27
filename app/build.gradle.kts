import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    id("com.google.devtools.ksp")
    id("com.google.gms.google-services")
}

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
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
        debug {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    kotlinOptions {
        jvmTarget = "11"
    }

    testOptions {
        unitTests.isReturnDefaultValues = true
    }

    aaptOptions {
        noCompress("tflite", "bloom")
    }
}

dependencies {
    // Peta pola ancaman. osmdroid dipilih ketimbang Google Maps karena
    // tidak butuh API key — satu langkah provisioning yang bisa gagal
    // diam-diam, untuk fitur yang sifatnya opsional.
    implementation("org.osmdroid:osmdroid-android:6.1.20")

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.material)
    implementation(libs.androidx.activity)
    implementation(libs.androidx.constraintlayout)

    implementation("androidx.room:room-runtime:2.6.1")
    ksp("androidx.room:room-compiler:2.6.1")

    implementation("com.google.code.gson:gson:2.10.1")

    implementation("androidx.recyclerview:recyclerview:1.3.2")

    // CardView — dipakai layout_floating_check.xml (Check Website button)
    implementation("androidx.cardview:cardview:1.0.0")

    implementation("org.tensorflow:tensorflow-lite:2.13.0") {
        exclude(group = "org.tensorflow", module = "tensorflow-lite-api")
    }

    testImplementation(libs.junit)
    // org.json di unit test JVM hanya stub; implementasi asli untuk test.
    testImplementation("org.json:json:20240303")
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)

    implementation(platform("com.google.firebase:firebase-bom:33.9.0"))
    implementation("com.google.firebase:firebase-firestore-ktx")
    implementation("com.google.firebase:firebase-analytics-ktx")
}
