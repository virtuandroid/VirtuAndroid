package com.lody.virtual.server.security

import android.annotation.SuppressLint
import android.content.pm.ApplicationInfo
import android.os.Build
import com.lody.virtual.client.core.VirtualCore
import com.lody.virtual.os.VEnvironment
import com.lody.virtual.os.VUserHandle
import kotlinx.collections.immutable.PersistentMap
import kotlinx.collections.immutable.persistentHashMapOf
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.update
import timber.log.Timber
import java.io.File

/**
 * A path is only allowed if the deepest rule is [ALLOW].
 *
 * 1. All paths are blocked by default.
 * 2. Specific directories can be whitelisted
 * 3. Specific directories can be blocklisted, to block
 *    specific subdirectories in an otherwise whitelisted directory
 *
 */
class StorageSandbox {
    private val ruleList = MutableStateFlow(DirectoryRule())
    private val redirectMap = MutableStateFlow(persistentHashMapOf<String, String>())

    data class DirectoryRule(
        val rules: Int = 0,
        val directories: PersistentMap<String, DirectoryRule> = persistentHashMapOf()
    )

    fun blocklistPaths(vararg paths: String) {
        ruleList.update { rule ->
            paths.fold(rule) { current, path ->
                blocklist(path, current)
            }
        }
    }

    fun whitelistPaths(vararg paths: String) {
        ruleList.update { rule ->
            paths.fold(rule) { current, path ->
                Timber.i("Whitelist path: $path")
                whitelist(path, current)
            }
        }
    }

    fun redirectDirectory(from: String, to: String) {
        val fromFixed = from.trimEnd('/') + "/"
        val toFixed = to.trimEnd('/') + "/"

        redirectMap.update { map ->
            map.putting(fromFixed, toFixed)
        }
    }

    @SuppressLint("SdCardPath")
    fun initSandboxForPid(info: ApplicationInfo, pid: Int) {
        val userId = VUserHandle.getUserId(info.uid)
        val hostPkg = VirtualCore.get().hostPkg

        // Only allow the app to inspect its own proc
        whitelistPaths("/proc/$pid/")
        redirectDirectory("/proc/self", "/proc/$pid")

        // Important system directories required for runtime
        whitelistPaths(
            "/dev/",
            "/mnt/",
            "/vendor/", // /vendor/lib64/egl/libEGL_emulation.so
            "/system/",
            "/apex/", // System libraries such as libart.so
            "/sys/",
            "/data/misc/",
            "/system_ext/"
        )

        whitelistPaths("/storage/") // External storage, should be restricted in the future
        whitelistPaths("/data/data/$hostPkg/virtual/data/app/system/permissions.xml") // TODO Move to server writer

        // Redirect user data access to VirtualXposed internal file system
        whitelistPaths(info.dataDir + "/")
        redirectDirectory("/data/data/${info.packageName}", info.dataDir)
        redirectDirectory("/data/user/0/${info.packageName}", info.dataDir)

        // /data/data/$hostPkg/virtual/data/user/0/
        // /data/data/io.va.exposed64/virtual/data/user/0/com.virtualxposed.guestattacker false
        // Redirect native library access
        val libPath = VEnvironment.getAppLibDirectory(info.packageName).absolutePath

        val userLibPath = File(
            VEnvironment.getUserSystemDirectory(userId),
            info.packageName + "/lib"
        ).absolutePath

        redirectDirectory(userLibPath, libPath)
        redirectDirectory("/data/data/${info.packageName}/lib/", libPath)
        redirectDirectory("/data/user/0/${info.packageName}/lib/", libPath)

        whitelistPaths("/data/data/$hostPkg/virtual/data/app/${info.packageName}/")
        whitelistPaths("/data/data/$hostPkg/virtual/data/user/$userId/${info.packageName}/")

        // TODO Maybe make a runtime copy and redirect?
        whitelistPaths("/data/data/$hostPkg/files/modules.json")

        // Read the base apk of VirtualXposed
        whitelistPaths("/data/app/")

//        val wifiMacAddressFile = deviceInfo.getWifiFile(userId).getPath();
//        NativeEngine.redirectDirectory("/sys/class/net/wlan0/address", wifiMacAddressFile);
//        NativeEngine.redirectDirectory("/sys/class/net/eth0/address", wifiMacAddressFile);
//        NativeEngine.redirectDirectory("/sys/class/net/wifi/address", wifiMacAddressFile);
    }

    fun getRedirectPath(path: String): String {
        val absolutePath = normalized(path)
        val redirectMap = redirectMap.value

        val redirectPath =
            // Get the largest match
            redirectMap.keys.filter {
                absolutePath.startsWith(it)
            }.maxByOrNull { it.length }?.let { redirectKey ->
                // If there is a match then get the replacement value
                val replacement = redirectMap.getValue(redirectKey)
                absolutePath.replace(redirectKey, replacement)
            } ?: absolutePath

        Timber.i("Redirected: $path -> $redirectPath")
        return redirectPath
    }

    /** Does not normalize path or account for redirect paths.
     * @see [getRedirectPath]
     */
    fun isPathAllowed(absolutePath: String): Boolean {
        return isPathAllowed(absolutePath, ruleList.value)
//            .also {
//                Timber.d("Is path allowed: $absolutePath $it")
//            }
    }

    companion object {
        // TODO READONLY?
        const val ALLOW = 1
        const val BLOCK = 1 shl 1
        const val NOTIFY = 1 shl 2

        fun isPathAllowed(
            path: String,
            directoryRule: DirectoryRule,
        ): Boolean {
            // Change isAllowed to change the default deny/allow
            return isPathAllowed(path, directoryRule, false)
        }

        internal fun blocklist(path: String, directoryRule: DirectoryRule): DirectoryRule {
            return setFlag(BLOCK, path, directoryRule)
        }

        internal fun whitelist(path: String, directoryRule: DirectoryRule): DirectoryRule {
            return setFlag(ALLOW, path, directoryRule)
        }

        private fun normalized(path: String): String {
            val isDir = path.endsWith("/") ||
                    path.endsWith("/.") ||
                    path.endsWith("/..") ||
                    path == "." || path == ".."
            val suffix = if (isDir) "/" else ""

            return File(path).normalize().path.trimEnd('/') + suffix
        }

        private fun isPathAllowed(
            path: String?,
            directoryRule: DirectoryRule,
            isAllowed: Boolean
        ): Boolean {
            val newIsAllowed = if (isAllowed) {
                // If already allowed then wait until an explicit BLOCK is encountered
                (directoryRule.rules and BLOCK) == 0
            } else {
                // If not allowed then wait until an explicit ALLOW is reached
                (directoryRule.rules and (ALLOW or BLOCK)) == ALLOW
            }

            if (path == null) {
                return newIsAllowed
            }

            val firstIndex = path.indexOf("/").takeIf { it != -1 }?.plus(1) ?: path.length
            val parentPath = path.take(firstIndex)
            val childPath = path.takeLast(path.length - firstIndex).ifEmpty { null }

            val subDir = directoryRule.directories[parentPath]

            if (subDir != null) {
                return isPathAllowed(childPath, subDir, newIsAllowed)
            }

            return newIsAllowed
        }

        fun setFlag(flag: Int, path: String, directoryRule: DirectoryRule): DirectoryRule {
            val firstIndex = path.indexOf("/").takeIf { it != -1 }?.plus(1) ?: path.length
            val parentPath = path.take(firstIndex)
            val childPath = path.takeLast(path.length - firstIndex).ifEmpty { null }

            if (childPath != null) {
                val currentRule = directoryRule.directories[parentPath] ?: DirectoryRule()
                return directoryRule.copy(
                    directories = directoryRule.directories.putting(
                        parentPath, setFlag(
                            flag,
                            childPath,
                            currentRule
                        )
                    )
                )
            } else {
                val currentRule = directoryRule.directories[parentPath] ?: DirectoryRule()
                return directoryRule.copy(
                    directories = directoryRule.directories.putting(
                        parentPath, currentRule.copy(rules = currentRule.rules or flag)
                    )
                )
            }
        }
    }
}