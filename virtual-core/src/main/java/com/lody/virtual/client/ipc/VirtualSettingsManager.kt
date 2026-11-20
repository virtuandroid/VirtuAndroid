package com.lody.virtual.client.ipc

import android.os.RemoteException
import com.lody.virtual.client.core.VirtualCore
import com.lody.virtual.client.env.VirtualRuntime
import com.lody.virtual.server.IVirtualSettingsManager

object VirtualSettingsManager {
    @JvmStatic
    fun get() = this

    private var mRemote: IVirtualSettingsManager? = null
    private fun getRemoteInterface(): IVirtualSettingsManager? {
        val logBinder = ServiceManagerNative.getService(ServiceManagerNative.VIRTUAL_SETTINGS)
        return IVirtualSettingsManager.Stub.asInterface(logBinder)
    }

    fun getInterface(): IVirtualSettingsManager? {
        if (mRemote == null || (!mRemote!!.asBinder()
                .pingBinder() && !VirtualCore.get().isVAppProcess)
        ) {
            synchronized(VPackageManager::class.java) {
                val remote = this.getRemoteInterface()
                mRemote = LocalProxyUtils.genProxy(
                    IVirtualSettingsManager::class.java,
                    remote
                )
            }
        }
        return mRemote
    }

    fun getDangerousGuestAction(): Int {
        return try {
            getInterface()!!.dangerousGuestAction
        } catch (e: RemoteException) {
            VirtualRuntime.crash(e)
        }
    }

    fun setDangerousGuestAction(action: Int): Boolean {
        return try {
            getInterface()!!.setDangerousGuestAction(action)
        } catch (e: RemoteException) {
            VirtualRuntime.crash(e)
        }
    }

    fun getFingerprintLogAction(): Int {
        return try {
            getInterface()!!.fingerprintLogAction
        } catch (e: RemoteException) {
            VirtualRuntime.crash(e)
        }
    }

    fun setFingerprintLogAction(action: Int): Boolean {
        return try {
            getInterface()!!.setFingerprintLogAction(action)
        } catch (e: RemoteException) {
            VirtualRuntime.crash(e)
        }
    }


    fun setSeccompEnabled(enabled: Boolean): Boolean {
        return try {
            getInterface()!!.setSeccompEnabled(enabled)
        } catch (e: RemoteException) {
            VirtualRuntime.crash(e)
        }
    }

    fun getSeccompEnabled(): Boolean {
        return try {
            getInterface()!!.seccompEnabled
        } catch (e: RemoteException) {
            VirtualRuntime.crash(e)
        }
    }

    fun getServicePolicy(): Int {
        return try {
            getInterface()!!.servicePolicy
        } catch (e: RemoteException) {
            VirtualRuntime.crash(e)
        }
    }

    fun setServicePolicy(action: Int): Boolean {
        return try {
            getInterface()!!.setServicePolicy(action)
        } catch (e: RemoteException) {
            VirtualRuntime.crash(e)
        }
    }
}