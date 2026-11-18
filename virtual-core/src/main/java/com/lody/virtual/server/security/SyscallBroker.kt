package com.lody.virtual.server.security

import android.system.Os
import androidx.tracing.trace
import timber.log.Timber
import kotlin.concurrent.thread

object SyscallBroker {
    @JvmStatic
    fun initClient(): Int {
        return clientInstall()
    }

    fun shutdownServer(guestPid: Int) {
        serverDestroy(guestPid)
    }

    @JvmStatic
    fun initServer(listenFd: Int, guestPid: Int, sandbox: StorageSandbox) {
        // TODO use both vuid and pid to prevent pid-reuse vulnerabilities
        thread {
            val cwd = runCatching {
                Os.readlink("/proc/$guestPid/cwd")
            }.getOrElse {
                "/"
            }

            runCatching {
                trace("SyscallBroker") {
                    serverServe(listenFd, guestPid, sandbox, cwd)
                }
            }

            Timber.i("Broker server for guest pid: $guestPid exited!")
        }
    }

    private external fun serverServe(fd: Int, pid: Int, sandbox: StorageSandbox, cwd: String)
    private external fun serverDestroy(pid: Int)
    private external fun clientInstall(): Int
}