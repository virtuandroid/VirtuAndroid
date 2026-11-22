package com.lody.virtual.server.settings

import android.annotation.SuppressLint
import com.lody.virtual.server.IVirtualSettingsManager
import kotlinx.serialization.Serializable
import org.matrix.vector.service.GenericStore
import java.io.File

@SuppressLint("UnsafeOptInUsageError")
@Serializable
data class VirtualSettings(
    // Make sure these mirror TransparentHardening
    val fingerprintAction: Int = IVirtualSettingsManager.ACTION_KILL_APP,
    val dangerousGuestAction: Int = IVirtualSettingsManager.ACTION_LOG_ONLY,
    val permissionBypassAction: Int = IVirtualSettingsManager.ACTION_TOAST,
    val servicePolicy: Int = IVirtualSettingsManager.POLICY_TRANSPARENT_HARDENING,
    val seccompEnabled: Boolean = true
)

object PersistentSettingStore : GenericStore<VirtualSettings>(VirtualSettings.serializer())  {
    override fun writeBlankStore(backingFile: File) {
        val store = VirtualSettings()
        writeStore(backingFile, store)
    }
}