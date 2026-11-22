package com.lody.virtual.server.log

import android.widget.Toast
import com.lody.virtual.client.core.VirtualCore
import com.lody.virtual.client.ipc.VActivityManager
import com.lody.virtual.remote.logging.LogMessageHolder
import com.lody.virtual.server.IVirtualSettingsManager.ACTION_KILL_APP
import com.lody.virtual.server.IVirtualSettingsManager.ACTION_TOAST
import com.lody.virtual.server.IVirtualSettingsManager.POLICY_STRICT_HARDENING
import com.lody.virtual.server.settings.VirtualSettingsService
import com.virtualxposed.log.client.LogMessage
import com.virtualxposed.log.server.IVLoggingService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.onFailure
import kotlinx.coroutines.launch
import kotlinx.datetime.LocalDateTime
import kotlinx.datetime.TimeZone
import kotlinx.datetime.format
import kotlinx.datetime.format.FormatStringsInDatetimeFormats
import kotlinx.datetime.format.byUnicodePattern
import kotlinx.datetime.toLocalDateTime
import timber.log.Timber
import java.io.File
import kotlin.time.Clock

object VLoggingManagerService : IVLoggingService.Stub() {
    fun start() {
        initLogChannel()
    }

    // Keep writing asynchronously all the time, no waiting on IO
    private val logChannel = Channel<LogMessageHolder>(capacity = Channel.BUFFERED)

    private fun initLogChannel() {
        val writeDispatcher =
            Dispatchers.IO.limitedParallelism(1)
        CoroutineScope(writeDispatcher).launch {
            for (logItem in logChannel) {
                runCatching {
                    logWriter.write(logItem.toPrettyJson())
                    logWriter.newLine()
                    logWriter.flush()
                }.onFailure { e ->
                    Timber.e(e, "Failed to write log line!")
                }
            }
        }
    }

    val logDir: String by lazy {
        val context = VirtualCore.get().context
        "${context.cacheDir.absolutePath}/logs"
    }

    private val logFile: File by lazy {
        val now = Clock.System.now().toLocalDateTime(TimeZone.currentSystemDefault())

        val customFormat = LocalDateTime.Format {
            @OptIn(FormatStringsInDatetimeFormats::class) byUnicodePattern("yyyy-MM-dd_HH_mm_ss")
        }

        val logTime = now.format(customFormat)
        // Cache dir makes it easy to clean the log files
        val file = File(logDir, "$logTime.jsonl")
        file.parentFile?.mkdirs()
        file.createNewFile()
        file
    }

    private val logWriter by lazy {
        logFile.bufferedWriter()
    }


    @JvmStatic
    fun get() = this

    fun log(logMessageHolder: LogMessageHolder) {
        if (!logMessageHolder.shouldBeDisplayed()) {
            return
        }

        logChannel.trySend(logMessageHolder).onFailure {
            Timber.e(it, "Failed to send long message to channel!")
        }

        runCatching {
            Timber.i("Received log message: ${logMessageHolder.toPrettyJson()}")
        }.onFailure {
            Timber.e(it, "Failed to log message")
        }

        enforceLogSecurity(logMessageHolder)
    }

    fun enforceLogSecurity(logMessageHolder: LogMessageHolder) {
        if (logMessageHolder.dangerous) {
            runCatching {
                val settings = VirtualSettingsService.get().dangerousGuestAction
                when (settings) {
                    ACTION_TOAST -> {
                        CoroutineScope(Dispatchers.Main).launch {
                            Toast.makeText(
                                VirtualCore.get().context,
                                "Dangerous app action detected: ${logMessageHolder.logMessage?.logType}",
                                Toast.LENGTH_LONG
                            ).show()
                        }
                    }

                    ACTION_KILL_APP -> {
                        val pkg = logMessageHolder.packageName
                        val userId = logMessageHolder.userId

                        VActivityManager.get().killAppByPkg(pkg, userId)
                        CoroutineScope(Dispatchers.Main).launch {
                            Toast.makeText(
                                VirtualCore.get().context,
                                "App killed due to dangerous app action: ${logMessageHolder.logMessage?.logType}",
                                Toast.LENGTH_LONG
                            ).show()
                        }

                        return
                    }
                }
            }.onFailure {
                Timber.e(it)
            }

            val logMessage = logMessageHolder.logMessage
            when (logMessage) {
                is LogMessage.HookArgumentsRewrite, is LogMessage.HookReturnRewrite, is LogMessage.HookExceptionMismatch -> {
                    val pkg = logMessageHolder.packageName
                    val userId = logMessageHolder.userId

                    VActivityManager.get().killAppByPkg(pkg, userId)
                    CoroutineScope(Dispatchers.Main).launch {
                        Toast.makeText(
                            VirtualCore.get().context,
                            "App killed due to disallowed return value rewriting!",
                            Toast.LENGTH_LONG
                        ).show()
                    }
                }

                is LogMessage.FingerprintChange -> runCatching {
                    val settings = VirtualSettingsService.get().fingerprintLogAction
                    when (settings) {
                        ACTION_TOAST -> {
                            CoroutineScope(Dispatchers.Main).launch {
                                Toast.makeText(
                                    VirtualCore.get().context,
                                    "Suspicious fingerprint change detected!",
                                    Toast.LENGTH_LONG
                                ).show()
                            }
                        }

                        ACTION_KILL_APP -> {
                            val pkg = logMessageHolder.packageName
                            val userId = logMessageHolder.userId

                            VActivityManager.get().killAppByPkg(pkg, userId)
                            CoroutineScope(Dispatchers.Main).launch {
                                Toast.makeText(
                                    VirtualCore.get().context,
                                    "App killed due to suspicious fingerprint change!",
                                    Toast.LENGTH_LONG
                                ).show()
                            }
                        }
                    }
                }.onFailure {
                    Timber.e(it)
                }

                is LogMessage.GetService,
                is LogMessage.GetActivity,
                is LogMessage.GetProvider,
                is LogMessage.GetReceiver,
                is LogMessage.BindService,
                is LogMessage.BroadCastReceived -> {
                    if (VirtualSettingsService.get().servicePolicy == POLICY_STRICT_HARDENING) {
                        val pkg = logMessageHolder.packageName
                        val userId = logMessageHolder.userId

                        VActivityManager.get().killAppByPkg(pkg, userId)
                        CoroutineScope(Dispatchers.Main).launch {
                            Toast.makeText(
                                VirtualCore.get().context,
                                "App killed due to dangerous service usage!",
                                Toast.LENGTH_LONG
                            ).show()
                        }
                    }
                }

                else -> {}
            }
        }
    }


    override fun log(message: LogMessage?) {
        if (message == null) {
            Timber.w("Received null message")
            return
        }

        val logMessageHolder = LogMessageHolder.Builder(message).build()
        log(logMessageHolder)
    }
}