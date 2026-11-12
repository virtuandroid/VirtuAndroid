package com.lody.virtual.server.security

import android.os.ParcelFileDescriptor
import kotlinx.collections.immutable.PersistentMap
import kotlinx.collections.immutable.persistentHashMapOf
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.update
import timber.log.Timber
import kotlin.concurrent.thread

object SyscallBroker {
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
    fun initClient() {
        val fd = childBrokerDescriptor?.fd ?: return
        brokerClientInstall(fd)
    }

    @JvmStatic
    fun initServer(guestPid: Int, guestVuid: Int) {
        val local = processBrokerTable.value[guestVuid] ?: return

        thread {
            brokerServe(local.fd, guestPid)
        }
    }

    private external fun brokerServe(fd: Int, pid: Int)
    private external fun brokerClientInstall(fd: Int)
}