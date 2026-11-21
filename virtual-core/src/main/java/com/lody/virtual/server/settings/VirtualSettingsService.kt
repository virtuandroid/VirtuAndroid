package com.lody.virtual.server.settings

import android.os.Build
import com.lody.virtual.client.core.VirtualCore
import com.lody.virtual.client.ipc.VActivityManager
import com.lody.virtual.os.VBinder
import com.lody.virtual.server.IVirtualSettingsManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.FlowPreview
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.debounce
import kotlinx.coroutines.flow.drop
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.flow.update
import java.io.File
import kotlin.time.Duration.Companion.milliseconds

object VirtualSettingsService : IVirtualSettingsManager.Stub() {
    @JvmStatic
    fun get() = this

    fun start() {
        val store = PersistentSettingStore.getStore(backingFile) ?: return
        settings.update { store }
        setupStoreJob()
    }

    private val settings = MutableStateFlow(VirtualSettings())

    val backingFile by lazy {
        File(VirtualCore.get().context.applicationContext.filesDir, "settings.json")
    }
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    @OptIn(FlowPreview::class)
    private fun setupStoreJob() {
        settings
            .drop(1) // Drop initial state
            .debounce(500.milliseconds)
            .onEach { settings ->
                PersistentSettingStore.writeStore(backingFile, settings)
            }
            .launchIn(scope)
    }

    private fun onlyAllowSystem(fn: () -> Unit): Boolean {
        return if (VActivityManager.get().systemPid == VBinder.getCallingUid()) {
            fn.invoke()
            true
        } else {
            false
        }
    }

    override fun getFingerprintLogAction(): Int {
        return settings.value.fingerprintAction
    }

    override fun setFingerprintLogAction(action: Int): Boolean {
        return onlyAllowSystem {
            settings.update {
                it.copy(fingerprintAction = action)
            }
        }
    }

    override fun getDangerousGuestAction(): Int {
        return settings.value.dangerousGuestAction
    }

    override fun setDangerousGuestAction(action: Int): Boolean {
        return onlyAllowSystem {
            settings.update {
                it.copy(dangerousGuestAction = action)
            }
        }
    }


    override fun getSeccompEnabled(): Boolean {
        // The seccomp implementation is only supported on A11+
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.R
                && settings.value.seccompEnabled
    }

    override fun setSeccompEnabled(enabled: Boolean): Boolean {
        return onlyAllowSystem {
            settings.update {
                it.copy(seccompEnabled = enabled)
            }
        }
    }

    override fun getServicePolicy(): Int {
        return settings.value.servicePolicy
    }

    override fun setServicePolicy(policy: Int): Boolean {
        return onlyAllowSystem {
            settings.update {
                it.copy(servicePolicy = policy)
            }
        }
    }
}