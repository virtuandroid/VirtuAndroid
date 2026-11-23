package com.lody.virtual.server.security

import android.annotation.SuppressLint
import android.content.pm.ApplicationInfo
import com.lody.virtual.client.core.VirtualCore
import com.lody.virtual.client.ipc.VDeviceManager
import com.lody.virtual.os.VEnvironment
import com.lody.virtual.os.VUserHandle
import kotlinx.collections.immutable.PersistentMap
import kotlinx.collections.immutable.persistentHashMapOf
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.update
import timber.log.Timber
import java.io.File

/**
 * A path is only allowed if the deepest rule is [READ] or [WRITE].
 *
 * 1. All paths are blocked by default.
 * 2. Specific directories can be whitelisted
 * 3. Specific directories can be blocklisted, to block
 *    specific subdirectories in an otherwise whitelisted directory
 *
 */
class StorageSandbox {
    private val ruleList = MutableStateFlow(RuleList())

    data class RuleList(
        val directories: PersistentMap<String, Int> = persistentHashMapOf(),
        val redirectMap: PersistentMap<String, String> = persistentHashMapOf()
    )

    fun blocklistPaths(vararg paths: String) {
        ruleList.update { rule ->
            paths.fold(rule) { current, path ->
                blocklist(path, current)
            }
        }
    }

    fun whitelistPaths(vararg paths: String, readOnly: Boolean = false) {
        val flags = if (readOnly) READ else READ_WRITE
        ruleList.update { rule ->
            paths.fold(rule) { current, path ->
                Timber.i("Whitelist path: $path")
                setFlag(path, current, flags)
            }
        }
    }

    fun redirectDirectory(from: String, to: String) {
        val fromFixed = from.trimEnd('/') + "/"
        val toFixed = to.trimEnd('/') + "/"

        ruleList.update { rules ->
            rules.copy(
                redirectMap = rules.redirectMap.putting(fromFixed, toFixed)
            )
        }
    }

    @SuppressLint("SdCardPath")
    fun initSandboxForPid(info: ApplicationInfo, pid: Int) {
        val userId = VUserHandle.getUserId(info.uid)
        val hostPkg = VirtualCore.get().hostPkg
        Timber.i("Init sandbox for ${info.packageName} on pid $pid")
        val hostUser = 0

        // Only allow the app to inspect its own proc
        whitelistPaths("/proc/$pid") // TODO implement checks for child processes
        whitelistPaths("/proc/sys")
        whitelistPaths("/data/data/$hostPkg/.agent-logs") // TODO This is called sometimes ???

        // Important system directories required for runtime
        whitelistPaths(
            "/dev",
            "/mnt",
            "/vendor", // /vendor/lib64/egl/libEGL_emulation.so
            "/system",
            "/apex", // System libraries such as libart.so
            "/sys",
            "/data/misc",
            "/system_ext",
            "/odm", // For exec
            "/linkerconfig" // For exec
        )

        whitelistPaths("/storage") // External storage, should be restricted in the future
        whitelistPaths(
            "/data/data/$hostPkg/virtual/data/app/system/permissions.xml", readOnly = true
        )

        // Redirect user data access to VirtualXposed internal file system
        whitelistPaths(info.dataDir)
        redirectDirectory("/data/data/${info.packageName}", info.dataDir)
        redirectDirectory("/data/user/$userId/${info.packageName}", info.dataDir)

        // Redirect native library access
        val libPath = VEnvironment.getAppLibDirectory(info.packageName).absolutePath

        val userLibPath = File(
            VEnvironment.getUserSystemDirectory(userId), info.packageName + "/lib"
        ).absolutePath

        redirectDirectory(userLibPath, libPath)
        redirectDirectory("/data/data/${info.packageName}/lib/", libPath)
        redirectDirectory("/data/user/$userId/${info.packageName}/lib/", libPath)
        whitelistPaths("/data/data/$hostPkg/virtual/data/app/${info.packageName}")
        whitelistPaths("/data/data/$hostPkg/virtual/data/user/$userId/${info.packageName}")
        whitelistPaths("/data/data/$hostPkg/files/modules.json", readOnly = true)
        // TODO redirect /data/misc/profiles/cur/0/com.virtualxposed.guestattacker/primary.prof

        // Read the base apk of VirtualXposed
        whitelistPaths("/data/app")
        whitelistPaths("/data/user/$hostUser/$hostPkg/virtual/data/app", readOnly = true)
        whitelistPaths("/data/data/$hostPkg/virtual/data/app", readOnly = true)

        whitelistPaths("/data/data/$hostPkg/files/.disable_xposed", readOnly = true)

        val deviceInfo = VDeviceManager.get().getDeviceInfo(userId)
        val wifiMacAddressFile = deviceInfo.getWifiFile(userId).path
        redirectDirectory("/sys/class/net/wlan0/address", wifiMacAddressFile)
        redirectDirectory("/sys/class/net/eth0/address", wifiMacAddressFile)
        redirectDirectory("/sys/class/net/wifi/address", wifiMacAddressFile)

        whitelistPaths("/storage/emulated/0/Android/data/$hostPkg/${info.packageName}")
        redirectDirectory(
            "/storage/emulated/0/Android/data/${info.packageName}",
            "/storage/emulated/0/Android/data/$hostPkg/${info.packageName}"
        )
    }


    /** Does not normalize path or account for redirect paths.
     * @see [getRedirectPath]
     */
    fun isFlagAllowed(absolutePath: String, permission: Int): Boolean {
        return isFlagAllowed(absolutePath, ruleList.value, permission)
//            .also {
//                Timber.d("Is path allowed $it on $absolutePath with flags $permission")
//            }
    }

    fun isFlagAllowed(absolutePath: ByteArray, permission: Int): Boolean {
        return isFlagAllowed(absolutePath.decodeToString(), permission)
    }

    fun getRedirectPath(path: String): String {
        return getRedirectPath(path, ruleList.value.redirectMap)
    }

    fun getRedirectPath(path: ByteArray): String {
        return getRedirectPath(path.decodeToString(), ruleList.value.redirectMap)
    }

    companion object {
        // TODO actual per-directory permissions to support operations on parent dirs
        const val READ = 1
        const val WRITE = 1 shl 1
        const val READ_WRITE = READ or WRITE
        const val NOTIFY = 1 shl 2
        const val BLOCK = 1 shl 3

        internal fun blocklist(path: String, ruleList: RuleList): RuleList {
            return setFlag(BLOCK, path, ruleList)
        }

        internal fun setFlag(
            path: String, ruleList: RuleList, permission: Int
        ): RuleList {
            return setFlag(permission, path, ruleList)
        }

        fun getRedirectPath(path: String, redirectMap: Map<String, String>): String {
            val absolutePath = normalized(path)

            val redirectPath =
                // Get the largest match
                redirectMap.keys.filter {
                    absolutePath.startsWith(it)
                }.maxByOrNull { absolutePath.commonPrefixWith(it) }?.let { redirectKey ->
                    // If there is a match then get the replacement value
                    val replacement = redirectMap.getValue(redirectKey)
                    absolutePath.replace(redirectKey, replacement)
                } ?: absolutePath

            // Timber.i("Redirected: $path -> $redirectPath")
            return redirectPath
        }

        private fun normalized(path: String): String {
            val isDir =
                path.endsWith("/") || path.endsWith("/.") || path.endsWith("/..") || path == "." || path == ".."
            val suffix = if (isDir) "/" else ""

            return File(path).normalize().path.trimEnd('/') + suffix
        }

        fun isPathAllowed(
            path: String?,
            ruleList: RuleList,
        ): Boolean {
            return isFlagAllowed(path, ruleList, READ_WRITE)
        }

        fun isFlagAllowed(
            path: String?,
            ruleList: RuleList,
            flag: Int,
        ): Boolean {
            if (path.isNullOrBlank()) return false
            val realPath = path.trimEnd('/') + "/"

            // First check if any rule applies to subdirectories
            // e.g. Rule: /data/ applicable to /data/app
            val bestDown = ruleList.directories.entries.filter {
                realPath.startsWith(it.key)
            }.maxByOrNull {
                realPath.commonPrefixWith(it.key)
            }

            val best = bestDown ?:
            // Then check if any rules applies to parent directories
            // e.g. Rule: /data/app applicable to /data
            ruleList.directories.entries.filter {
                it.key.startsWith(realPath)
            }.maxByOrNull {
                realPath.commonPrefixWith(it.key)
            } ?: return false

            // Blocks only apply to itself and subdirectories
            val blocked = (best.value and BLOCK == BLOCK) && path.length >= best.key.length

            return !blocked && (best.value and flag == flag)
        }

        fun setFlag(flag: Int, path: String, ruleList: RuleList): RuleList {
            val realPath = path.trimEnd('/') + "/"
            val existingRule = ruleList.directories[realPath] ?: 0
            return ruleList.copy(
                directories = ruleList.directories.putting(
                    realPath, flag or existingRule
                )
            )
        }
    }
}