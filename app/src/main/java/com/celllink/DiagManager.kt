package com.celllink

import android.util.Log
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/**
 * Manages modem connections across all supported chipset backends.
 * Auto-detects Qualcomm (DIAG/QMI), HiSilicon (AT), MediaTek (AT), or Generic AT.
 */
object DiagManager {

    private const val TAG = "CellLink-Modem"

    enum class Backend { DIAG_QMI, HISILICON_AT, MEDIATEK_AT, GENERIC_AT, NONE }

    sealed class State {
        data object Closed : State()
        data object Detecting : State()
        data object Opening : State()
        data class Ready(
            val backend: Backend,
            val diagHandle: Long = 0,
            val hisiliconHandle: Long = 0,
            val deviceInfo: Long = 0
        ) : State()
        data class NeedsRoot(val diagnosis: String) : State()
        data class Error(val message: String) : State()
    }

    private val _state = MutableStateFlow<State>(State.Closed)
    val state: StateFlow<State> = _state

    @Volatile var nativeHandle: Long = 0; private set
    @Volatile var hisiliconHandle: Long = 0; private set
    @Volatile var backend: Backend = Backend.NONE; private set
    @Volatile var deviceInfoHandle: Long = 0; private set

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    /**
     * Detect device and open the correct modem backend.
     */
    fun detectAndOpen(): State {
        if (_state.value !is State.Closed) return _state.value
        _state.value = State.Detecting

        scope.launch {
            try {
                // Step 1: Detect device
                Log.i(TAG, "Detecting device...")
                val devInfo = NativeBridge.nativeDeviceDetect()
                if (devInfo == 0L) {
                    _state.value = State.Error("Device detection failed")
                    return@launch
                }
                deviceInfoHandle = devInfo

                val chipset = NativeBridge.nativeDeviceGetChipset(devInfo)
                val modem = NativeBridge.nativeDeviceGetModem(devInfo)
                val isRooted = NativeBridge.nativeDeviceIsRooted(devInfo)
                val backendId = NativeBridge.nativeDeviceGetBackend(devInfo)
                backend = when (backendId) { 0 -> Backend.DIAG_QMI; 1 -> Backend.HISILICON_AT; 2 -> Backend.MEDIATEK_AT; 3 -> Backend.GENERIC_AT; else -> Backend.NONE }

                Log.i(TAG, "Device: $chipset / $modem | Backend: $backend | Rooted: $isRooted")

                // Step 2: Try root if needed
                if (!isRooted) {
                    Log.i(TAG, "Root not found. Attempting...")
                    val rooted = NativeBridge.nativeDeviceAttemptRoot(devInfo)
                    if (!rooted) {
                        val selinux = NativeBridge.nativeDeviceSelinuxEnforcing(devInfo)
                        val bl = NativeBridge.nativeDeviceBootloaderUnlocked(devInfo)
                        val diag = buildString {
                            appendLine("Root required for modem control.")
                            appendLine("Device: $chipset ($modem)")
                            if (selinux) appendLine("SELinux: Enforcing (must be Permissive)")
                            if (bl) appendLine("Bootloader: LOCKED")
                            appendLine()
                            when (backend) {
                                Backend.HISILICON_AT -> appendLine("HiSilicon: /dev/ttyAMA0 needs root or media group")
                                Backend.DIAG_QMI -> appendLine("Qualcomm: /dev/diag needs root")
                                else -> appendLine("Root the device and grant superuser access.")
                            }
                        }
                        _state.value = State.NeedsRoot(diag)
                        return@launch
                    }
                    Log.i(TAG, "Root gained successfully")
                }

                // Step 3: Open the right backend
                _state.value = State.Opening
                when (backend) {
                    Backend.DIAG_QMI -> {
                        val diagHandle = NativeBridge.nativeDiagOpen(null)
                        if (diagHandle == 0L || !NativeBridge.nativeDiagIsReady(diagHandle)) {
                            if (diagHandle != 0L) NativeBridge.nativeDiagClose(diagHandle)
                            // Fallback to generic AT
                            Log.w(TAG, "DIAG failed, falling back to generic AT")
                            backend = Backend.GENERIC_AT
                        } else {
                            nativeHandle = diagHandle
                            _state.value = State.Ready(Backend.DIAG_QMI, diagHandle = diagHandle, deviceInfo = devInfo)
                            Log.i(TAG, "DIAG/QMI backend ready")
                            return@launch
                        }
                    }
                    else -> {} // Will fall through to AT path
                }

                // Step 4: Try HiSilicon or Generic AT backend
                val atPath = NativeBridge.nativeDeviceAtPrimary(devInfo)
                if (atPath.isNotEmpty()) {
                    val hisiHandle = NativeBridge.nativeHisiliconOpen(atPath)
                    if (hisiHandle != 0L && NativeBridge.nativeHisiliconIsAlive(hisiHandle)) {
                        hisiliconHandle = hisiHandle
                        nativeHandle = 0L
                        _state.value = State.Ready(
                            if (backend == Backend.HISILICON_AT) Backend.HISILICON_AT else Backend.GENERIC_AT,
                            hisiliconHandle = hisiHandle, deviceInfo = devInfo
                        )
                        Log.i(TAG, "HiSilicon/AT backend ready on $atPath")
                        return@launch
                    } else {
                        if (hisiHandle != 0L) NativeBridge.nativeHisiliconClose(hisiHandle)
                    }
                }

                _state.value = State.Error("No modem interface accessible. Need root.")
            } catch (e: Exception) {
                Log.e(TAG, "Modem setup failed", e)
                _state.value = State.Error(e.message ?: "Unknown error")
            }
        }

        return _state.value
    }

    /** Close all modem connections. */
    fun close() {
        scope.launch {
            if (nativeHandle != 0L) { NativeBridge.nativeDiagClose(nativeHandle); nativeHandle = 0L }
            if (hisiliconHandle != 0L) { NativeBridge.nativeHisiliconClose(hisiliconHandle); hisiliconHandle = 0L }
            if (deviceInfoHandle != 0L) { NativeBridge.nativeDeviceFree(deviceInfoHandle); deviceInfoHandle = 0L }
            backend = Backend.NONE
            _state.value = State.Closed
            Log.i(TAG, "Modem closed")
        }
    }

    /** Send an AT command through whichever backend is active. */
    fun sendAtCommand(command: String): String? {
        return when {
            hisiliconHandle != 0L -> NativeBridge.nativeHisiliconAtSend(hisiliconHandle, command)
            nativeHandle != 0L -> NativeBridge.nativeDiagAtCommand(nativeHandle, command)
            else -> null
        }
    }

    /** Get RSSI through the active backend. */
    fun getSignal(): Int {
        return when {
            hisiliconHandle != 0L -> NativeBridge.nativeHisiliconGetSignal(hisiliconHandle)
            else -> -120
        }
    }
}
