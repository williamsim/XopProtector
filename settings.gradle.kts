pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        // 本地 maven 仓库：含修改版 shadowhook 1.1.1（arm/arm64 官方真实库 + x86/x86_64 空桩）。
        // 必须放在最前，优先于 Aliyun 镜像，确保解析到本地的 4-abi 版本而非官方缺 x86 的版本。
        maven { url = uri("file:///D:/local-maven") }
        maven { url = uri("https://maven.aliyun.com/repository/public") }
        maven { url = uri("https://maven.aliyun.com/repository/google") }
        maven { url = uri("https://maven.aliyun.com/repository/central") }
        maven { url = uri("https://maven.aliyun.com/repository/gradle-plugin") }
    }
}

rootProject.name = "XopProtector"
include(":native")
include(":demo")
include(":packer")

// UniMP host needs local SDK AARs; skip when missing so packer/native/desktop still build.
val unimpLibsProp = providers.gradleProperty("unimp.sdk.libs").orNull?.trim().orEmpty()
val unimpLibsCandidates = listOfNotNull(
    unimpLibsProp.takeIf { it.isNotEmpty() }?.let { file(it) },
    file("E:/Android/SDK-Android@5.14-20260706/SDK/libs"),
    file("../SDK-Android@5.14-20260706/SDK/libs"),
)
if (unimpLibsCandidates.any { it.isDirectory }) {
    include(":unimp-host")
} else {
    logger.warn(
        "Skipping :unimp-host — UniMP SDK libs not found. " +
            "Set unimp.sdk.libs in gradle.properties to enable it."
    )
}
