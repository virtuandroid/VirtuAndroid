package com.lody.virtual.server.security

import android.os.ParcelFileDescriptor
import androidx.tracing.trace
import kotlinx.collections.immutable.PersistentMap
import kotlinx.collections.immutable.persistentHashMapOf
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.update
import timber.log.Timber
import kotlin.concurrent.thread

object SyscallBroker {
    /**
     * This is null if the parent does hand over a broker (seccomp disabled).
     */
    var childBrokerDescriptor: ParcelFileDescriptor? = null

    // Child VUID -> Local FD
    val processBrokerTable: MutableStateFlow<PersistentMap<Int, ParcelFileDescriptor>> =
        MutableStateFlow(
            persistentHashMapOf()
        )

    /** Generate a ParcelFileDescriptor to send to the child process. */
    fun generateBroker(guestVuid: Int): ParcelFileDescriptor? {
        runCatching {
            val (local, remote) = ParcelFileDescriptor.createSocketPair()

            processBrokerTable.update { it.putting(guestVuid, local) }
            return remote
        }.onFailure {
            Timber.e(it, "Failed to generate broker")
        }
        return null
    }

    @JvmStatic
    fun initClient(): Boolean {
        val fd = childBrokerDescriptor?.fd ?: return false
        return brokerClientInstall(fd)
    }

    @JvmStatic
    fun initServer(guestPid: Int, guestVuid: Int, sandbox: StorageSandbox) {
        val local = processBrokerTable.value[guestVuid] ?: return

        // TODO stop thread on death
        thread {
            // TODO implement correct g_cwd
            // Use readlink("/proc/$guestPid/cwd")
            runCatching {
                trace("SyscallBroker") {
                    brokerServe(local.fd, guestPid, sandbox)
                }
            }
            Timber.e("Broker server crashed!")
        }
    }

    private external fun brokerServe(fd: Int, pid: Int, sandbox: StorageSandbox)
    private external fun brokerClientInstall(fd: Int): Boolean
}