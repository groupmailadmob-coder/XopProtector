plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.yqsh.protector"
    compileSdk = 34

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
    // Required by bytehook on arm/arm64 (dl init/fini monitor). x86/x86_64 skip it.
    implementation("com.bytedance.android:shadowhook:2.0.1")
}

// Shadowhook has no x86/x86_64 modules; AGP still resolves it for every ABI.
fun plantShadowhookPrefabBypass() {
    val abis = listOf("x86", "x86_64")
    fun plantInLibs(libsDir: File) {
        for (abi in abis) {
            val so = File(libsDir, "android.$abi/libshadowhook.so")
            if (so.isFile) continue
            so.parentFile.mkdirs()
            File(so.parentFile, "abi.json").writeText(
                """
                {
                  "abi": "$abi",
                  "api": 16,
                  "ndk": 23,
                  "stl": "none",
                  "static": false
                }
                """.trimIndent()
            )
            so.createNewFile()
        }
    }
    val gradleHome = file("${System.getProperty("user.home")}/.gradle/caches")
    val searchRoots = mutableListOf<File>()
    gradleHome.listFiles()?.filter { it.isDirectory && it.name.startsWith("transforms") }
        ?.let { searchRoots.addAll(it) }
    searchRoots += layout.buildDirectory.get().asFile
    searchRoots.filter { it.isDirectory }.forEach { root ->
        root.walkTopDown()
            .filter { it.isDirectory && it.name == "libs" && it.path.contains("shadowhook") }
            .forEach { plantInLibs(it) }
    }
}

tasks.matching {
    val n = it.name
    n.startsWith("configureCMake") && (n.endsWith("[x86]") || n.contains("[x86_64]"))
}.configureEach {
    doFirst { plantShadowhookPrefabBypass() }
}
