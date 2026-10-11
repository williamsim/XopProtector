plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.yqsh.protector"
    compileSdk = 35

    // NDK r28+ ships a 16K page-size aligned libc++_shared.so prebuilt.
    // Older NDKs package a 4K-aligned libc++_shared.so which crashes on
    // 16K-page devices (and fails the Play Nov-2025 16KB requirement).
    ndkVersion = "28.2.13676358"

    defaultConfig {
        minSdk = 23
        consumerProguardFiles("consumer-rules.pro")

        externalNativeBuild {
            cmake {
                cppFlags += listOf("-std=c++20", "-fvisibility=hidden")
                val llvmObf = (project.findProperty("protector.llvmObf") as String?)
                    ?.equals("true", ignoreCase = true) == true
                val llvmObfVm = (project.findProperty("protector.llvmObfVm") as String?)
                    ?.equals("true", ignoreCase = true) == true
                val srcObf = (project.findProperty("protector.srcObf") as String?)
                    ?.equals("false", ignoreCase = true) != true
                val args = mutableListOf(
                    "-DANDROID_STL=c++_shared",
                    "-DDOBBY_GENERATE_SHARED=OFF",
                    "-DDOBBY_DEBUG=OFF",
                    "-DPROTECTOR_LLVM_OBF=${if (llvmObf) "ON" else "OFF"}",
                    "-DPROTECTOR_LLVM_OBF_VM=${if (llvmObfVm) "ON" else "OFF"}",
                    "-DPROTECTOR_SRC_OBF=${if (srcObf) "ON" else "OFF"}"
                )
                val obfFlags = project.findProperty("protector.llvmObfFlags") as String?
                if (!obfFlags.isNullOrBlank()) {
                    // Pass as CMake list using ';' separators (Gradle property uses ',').
                    args += "-DPROTECTOR_LLVM_OBF_FLAGS=${obfFlags.replace(',', ';')}"
                }
                arguments(*args.toTypedArray())
                // shadowhook 官方 1.1.1 prefab 无 x86/x86_64 模块（开源库本身不支持 x86）。
                // bytehook 在 x86/x86_64 下不链 shadowhook，仅用本地 AAR 的空桩骗过 prefab 解包，
                // 真实 x86/x86_64 库见 D:/local-shadowhook/shadowhook-1.1.1.aar。
                abiFilters += listOf("armeabi-v7a", "arm64-v8a", "x86", "x86_64")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
        debug {
            isJniDebuggable = true
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    packaging {
        jniLibs {
            useLegacyPackaging = true
            // Prefab already pulls shadowhook into the app; avoid duplicating from CMake link output
            excludes += setOf("**/libshadowhook.so", "**/libshadowhook_nothing.so")
        }
    }

    buildFeatures {
        prefab = true
    }
}

dependencies {
    implementation("androidx.annotation:annotation:1.7.1")
    // bytehook 在 arm/arm64 链 shadowhook；x86/x86_64 不链。
    // shadowhook 官方 1.1.1 prefab 无 x86/x86_64 模块（开源库本身不支持 x86），
    // 已从 Maven Central 替换为本地 maven 仓库 D:/local-maven 中的修改版
    // （arm/arm64 为官方真实库，x86/x86_64 为仅供 prefab 解包的空桩）。
    implementation("com.bytedance.android:shadowhook:1.1.1")
}
