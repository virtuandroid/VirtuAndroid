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

        // Do not return until its started
        while (!serverIsRunning(guestPid)) {
            Thread.sleep(10)
        }
        // Necessary extra time to ensure that the FD is set up
        // after the flag is set. This is somewhat unavoidable since
        // we want to make the FD listening blocking in order to avoid busy waiting
        Thread.sleep(10)
    }

    private external fun serverServe(fd: Int, pid: Int, sandbox: StorageSandbox, cwd: String)
    private external fun serverDestroy(pid: Int)
    private external fun serverIsRunning(pid: Int): Boolean
    private external fun clientInstall(): Int
}