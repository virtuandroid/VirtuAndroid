package com.lody.virtual.helper.compat

import android.os.Build
import mirror.com.android.internal.content.NativeLibraryHelper
import mirror.dalvik.system.VMRuntime
import timber.log.Timber
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import kotlin.time.measureTimedValue

object NativeLibraryHelperCompat {
    private val TAG: String = NativeLibraryHelperCompat::class.java.getSimpleName()

    fun copyNativeBinaries(apkFile: File, sharedLibraryDir: File?): Int {
        return copyNativeBinariesAfterL(apkFile, sharedLibraryDir)
    }

    private fun copyNativeBinariesAfterL(apkFile: File, sharedLibraryDir: File?): Int {
        try {
            val handle = NativeLibraryHelper.Handle.create.call(apkFile) ?: return -1

            var abi: String? = null
            val abiSet = getABIsFromApk(apkFile.absolutePath)
            if (abiSet.isEmpty()) {
                return 0
            }
            val is64Bit = VMRuntime.is64Bit.call(VMRuntime.getRuntime.call())
            if (is64Bit && isVM64(abiSet)) {
                if (Build.SUPPORTED_64_BIT_ABIS.size > 0) {
                    val abiIndex = NativeLibraryHelper.findSupportedAbi.call(
                        handle,
                        Build.SUPPORTED_64_BIT_ABIS
                    )
                    if (abiIndex >= 0) {
                        abi = Build.SUPPORTED_64_BIT_ABIS[abiIndex]
                    }
                }
            } else {
                if (Build.SUPPORTED_32_BIT_ABIS.size > 0) {
                    val abiIndex = NativeLibraryHelper.findSupportedAbi.call(
                        handle,
                        Build.SUPPORTED_32_BIT_ABIS
                    )
                    if (abiIndex >= 0) {
                        abi = Build.SUPPORTED_32_BIT_ABIS[abiIndex]
                    }
                }
            }

            if (abi == null) {
                Timber.e(TAG, "Not match any abi [%s].", apkFile.path)
                return -1
            }
            return NativeLibraryHelper.copyNativeBinaries.call(handle, sharedLibraryDir, abi)
        } catch (e: Throwable) {
            Timber.e(e, "copyNativeBinaries with error")
        }

        return -1
    }

    private fun isVM64(supportedABIs: Set<String>): Boolean {
        if (Build.SUPPORTED_64_BIT_ABIS.size == 0) {
            return false
        }

        if (supportedABIs.isEmpty()) {
            return true
        }

        for (supportedAbi in supportedABIs) {
            if ("arm64-v8a".endsWith(supportedAbi) || "x86_64" == supportedAbi || "mips64" == supportedAbi) {
                return true
            }
        }

        return false
    }

    private fun getABIsFromApk(apk: String?): Set<String> {
        val apkFile = apk?.let { File(it) } ?: return emptySet()

        // Seems like newer Android versions with split APKs use directories instead
        if (apkFile.isDirectory) {
            val entries = File(apkFile, "lib").listFiles()
            val abis = entries?.filter { it.isDirectory }?.map {
                when (it.name) {
                    "arm64" -> {
                        "arm64-v8a"
                    }
                    "arm" -> {
                        "armeabi-v7a"
                    }
                    else -> {
                        it.name
                    }
                }
            }?.toSet()
            return abis ?: emptySet()
        } else if (apkFile.isFile) {
            try {
                ZipFile(apkFile).use { apkFile ->
                    val entries = apkFile.entries()
                    val supportedABIs: MutableSet<String> = HashSet()
                    while (entries.hasMoreElements()) {
                        val entry: ZipEntry = entries.nextElement()
                        val name = entry.name
                        if (name.contains("../")) {
                            continue
                        }
                        if (name.startsWith("lib/") && !entry.isDirectory && name.endsWith(".so")) {
                            val supportedAbi =
                                name.substring(name.indexOf("/") + 1, name.lastIndexOf("/"))
                            supportedABIs.add(supportedAbi)
                        }
                    }
                    return supportedABIs
                }
            } catch (e: Exception) {
                Timber.e(e)
            }
        }


        return emptySet()
    }

    @JvmStatic
    fun isApk64(apk: String?): Boolean {
        val abisFromApk = measureTimedValue {
            getABIsFromApk(apk)
        }
        Timber.i("pkg: $apk, abis: ${abisFromApk.value}, cost: ${abisFromApk.duration}")
        return isVM64(abisFromApk.value)
    }
}
