plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.securitydemo.systeminfo"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.securitydemo.systeminfo"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"

        // Configure your training server URL here
        buildConfigField("String", "BEACON_URL", "\"http://10.13.4.142:9090/beacon\"")
        // WorkManager minimum is 15 min, but the app also fires immediate beacons on open
        buildConfigField("int", "BEACON_INTERVAL_MINUTES", "15")
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }

    kotlinOptions {
        jvmTarget = "1.8"
    }

    buildFeatures {
        viewBinding = true
        buildConfig = true
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.12.0")
    implementation("androidx.appcompat:appcompat:1.6.1")
    implementation("com.google.android.material:material:1.11.0")
    implementation("androidx.constraintlayout:constraintlayout:2.1.4")
    implementation("androidx.work:work-runtime-ktx:2.9.0")
}
