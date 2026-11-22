package com.lody.virtual.remote.logging

import android.annotation.SuppressLint
import android.content.pm.PackageManager
import com.lody.virtual.os.VBinder
import com.lody.virtual.os.VEnvironment
import com.lody.virtual.os.VEnvironment.getPackageResourcePath
import com.lody.virtual.server.permission.VPermissionManager
import com.lody.virtual.server.pm.VPackageManagerService
import com.lody.virtual.server.security.SecurityUtils
import com.virtualxposed.log.client.LogMessage
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.ClassDiscriminatorMode
import kotlinx.serialization.json.Json
import kotlinx.serialization.modules.SerializersModule
import kotlinx.serialization.modules.polymorphic
import kotlinx.serialization.modules.subclass
import org.matrix.vector.service.VectorManagerService

/**
 * This class wraps over the log message to provide additional metadata about the log message.
 *
 * It is assumed that an attacker targeting this project can send forged log messages to the logging service,
 * therefore this holder determines additional metadata about the sender such as the PID and package name.
 */
@SuppressLint("UnsafeOptInUsageError")
@Serializable
class LogMessageHolder private constructor(
    val logMessage: LogMessage?,
    val pid: Int,
    val packageName: String?,
    val timestamp: Long,
    val dangerous: Boolean,
    val userId: Int
) {
    class Builder(private val logMessage: LogMessage) {
        private var initialCallingUid: Int? = VBinder.getCallingUid()
        private var pid: Int = VBinder.getCallingPid()
        private var userId: Int = VBinder.getCallingUserHandle().identifier
        private var packageName: String? =
            VPackageManagerService.get().getNameForUid(initialCallingUid!!)
        private val timestamp: Long = System.currentTimeMillis()

        fun setPid(pid: Int): Builder {
            this.pid = pid
            this.initialCallingUid = null
            return this
        }

        fun setPackage(packageName: String, userId: Int): Builder {
            this.packageName = packageName
            this.userId = userId
            this.initialCallingUid = null
            return this
        }

        fun build(): LogMessageHolder {
            val callingUid by lazy {
                initialCallingUid ?: VPackageManagerService.get()
                    .getPackageUid(packageName!!, userId)
            }

            val dangerous = when (logMessage) {
                is LogMessage.CodeLoad -> {
                    val appDir = VEnvironment.getDataAppDirectory().absolutePath

                    // System file loading is not dangerous
                    val isSystem =
                        logMessage.path.startsWith("/system") || (logMessage.path.startsWith("/vendor"))

                    val pathSuffix = logMessage.path.removePrefix("$appDir/").substringAfter("/")
                    // Dynamic code loading from storage is classified as dangerous
                    // Apps should only use bundled native code
                    val isBundledCode =
                        logMessage.path.startsWith(appDir) && pathSuffix == "base.apk" || pathSuffix.startsWith(
                            "base.apk!"
                        )

                    // Apps can load so files without an absolute path such as "mapper.ranchu.so"
                    // which is difficult to resolve to an absolute path
                    // For now we cannot guarantee that they are dangerous
                    val isNativeUndeterminedPath =
                        logMessage.codeLoadMethod == LogMessage.CodeLoadMethod.Native && !logMessage.path.startsWith(
                            "/"
                        )

                    !isSystem && !isBundledCode && !isNativeUndeterminedPath
                }

                // Apps should never access each others non-exported services, it breaks the Android Sandbox
                is LogMessage.GetService -> {
                    val serviceInfo = logMessage.serviceInfo
                    serviceInfo != null && SecurityUtils.isServiceAllowed(serviceInfo, callingUid)
                        .not()
                }

                is LogMessage.BindService -> {
                    val serviceInfo = logMessage.serviceInfo
                    serviceInfo != null && SecurityUtils.isServiceAllowed(serviceInfo, callingUid)
                        .not()
                }

                is LogMessage.GetProvider -> {
                    val providerInfo = logMessage.providerInfo
                    providerInfo != null && SecurityUtils.isProviderAllowed(
                        providerInfo,
                        callingUid
                    ).not()
                }

                is LogMessage.GetActivity -> {
                    val activityInfo = logMessage.activityInfo
                    activityInfo != null && SecurityUtils.isActivityAllowed(
                        activityInfo,
                        callingUid
                    ).not()
                }

                is LogMessage.GetReceiver -> {
                    val activityInfo = logMessage.activityInfo
                    activityInfo != null && SecurityUtils.isActivityAllowed(
                        activityInfo,
                        callingUid
                    ).not()
                }

                is LogMessage.BroadCastReceived -> {
                    val activityInfo = logMessage.activityInfo
                    activityInfo != null && SecurityUtils.isActivityAllowed(
                        activityInfo,
                        callingUid
                    ).not()
                }

                is LogMessage.FingerprintChange -> {
                    // The fingerprint should never change at runtime
                    logMessage.changedFields.isNotEmpty()
                }

                is LogMessage.FileAccess -> {
                    logMessage.forbidden
                }

                is LogMessage.HookAttach -> {
                    val dangerousPackage = listOf(
                        "android.",
                        "java.",
                        "mirror.",
                        "javax.",
                        "com.lody.virtual",
                        "de.robv.android",
                        "me.weishu.exposed",
                        "com.virtualxposed.lsplantbridge",
                        "com.virtualxposed.log",
                        "org.chickenhook.restrictionbypass"
                    )
                    // Dangerous to hook VirtualXposed or Android/Java references. Hooks should only affect the app code.
                    dangerousPackage.any {
                        logMessage.targetClass.startsWith(it)
                    }
                }

                is LogMessage.UsePermission -> {
                    val permission = logMessage.permission
                    val isGranted = runCatching {
                        VPermissionManager.get().checkPermission(permission, callingUid)
                    }.getOrNull() == PackageManager.PERMISSION_GRANTED

                    !isGranted
                }

                is LogMessage.SocketConnect -> {
                    val pkgName = packageName
                    val processName = logMessage.peerProcessName

                    // Dangerous if processName does not start with the packageName
                    // E.g. if one app is connecting to another apps' socket
                    (processName != null) && (pkgName != null) && !processName.startsWith(pkgName)
                }

                is LogMessage.AppKill -> {
                    val pkgName = packageName
                    val processName = logMessage.processName

                    // Dangerous if processName does not start with the packageName
                    // E.g. if one app is killing another app. The Android sandbox prevents cross-app killing.
                    (processName != null) && (pkgName != null) && !processName.startsWith(pkgName)
                }

                is LogMessage.HookArgumentsRewrite, is LogMessage.HookReturnRewrite, is LogMessage.HookExceptionMismatch -> {
                    VectorManagerService.get().getManagerServer()?.methodRewriteAllowed?.contains(
                        logMessage.modulePackage
                    ) != true
                }

                else -> false
            }
            return LogMessageHolder(logMessage, pid, packageName, timestamp, dangerous, userId)
        }
    }


    companion object {
        @OptIn(ExperimentalSerializationApi::class)
        val prettyJson = Json {
            prettyPrint = false
            classDiscriminatorMode = ClassDiscriminatorMode.NONE
            encodeDefaults = true
            explicitNulls = false
            serializersModule = SerializersModule {
                polymorphic(LogMessage::class) {
                    subclass(LogMessage.HookReturnRewrite::class)
                    subclass(LogMessage.HookArgumentsRewrite::class)
                    subclass(LogMessage.HookExceptionMismatch::class)
                }
            }
        }
    }

    fun shouldBeDisplayed(): Boolean {
        // It is not interesting that an app loads its own base apk
        // It is expected behavior on every app startup, and already captured by AppLoad
        if (logMessage is LogMessage.CodeLoad) {
            val basePackage = getPackageResourcePath(packageName).absolutePath
            if (basePackage == logMessage.path) {
                return false
            }
        }

        return true
    }

    fun toPrettyJson(): String {
        return prettyJson.encodeToString(this)
    }
}