package com.celllink

import android.util.Log
import kotlinx.coroutines.*

/**
 * Checks for root access and attempts to gain root if not present.
 * Provides root status as a StateFlow for UI observation.
 */
object RootChecker {

    private const val TAG = "CellLink-Root"

    enum class RootState {
        UNKNOWN,        // Haven't checked yet
        CHECKING,       // Running root detection
        ROOTED,         // Root is available
        NOT_ROOTED,     // Root not available
        MEDIA_ACCESS,   // Partial: can access modem via media group (Huawei)
        ATTEMPTING,     // Trying to gain root
        FAILED          // Root attempt failed
    }

    data class Status(
        val state: RootState = RootState.UNKNOWN,
        val chipsetName: String = "",
        val modemName: String = "",
        val basebandVersion: String = "",
        val androidVersion: String = "",
        val preferredBackend: String = "",
        val diagnosis: String = ""
    )

    @Volatile
    var status: Status = Status()
        private set

    /**
     * Check root access and detect device capabilities.
     * Must be called from a background thread/coroutine.
     */
    suspend fun check(): Status = withContext(Dispatchers.IO) {
        status = Status(state = RootState.CHECKING)
        Log.i(TAG, "Checking root and device...")

        try {
            // Native check via JNI
            val deviceInfo = NativeBridge.nativeDeviceDetect()
            if (deviceInfo == 0L) {
                Log.e(TAG, "Device detection returned null")
                return@withContext Status(
                    state = RootState.FAILED,
                    diagnosis = "Device detection failed. Modem interface not found."
                ).also { status = it }
            }

            // Parse device info from native
            val chipset = NativeBridge.nativeDeviceGetChipset(deviceInfo)
            val modem = NativeBridge.nativeDeviceGetModem(deviceInfo)
            val isRooted = NativeBridge.nativeDeviceIsRooted(deviceInfo)
            val backend = NativeBridge.nativeDeviceGetBackend(deviceInfo)
            val selinux = NativeBridge.nativeDeviceSelinuxEnforcing(deviceInfo)
            val bootloader = NativeBridge.nativeDeviceBootloaderUnlocked(deviceInfo)

            val backendName = when (backend) {
                0 -> "DIAG/QMI"
                1 -> "HiSilicon AT"
                2 -> "MediaTek AT"
                3 -> "Generic AT"
                4 -> "RIL Proxy"
                else -> "Unknown"
            }

            Log.i(TAG, "Chipset: $chipset, Modem: $modem, Root: $isRooted, Backend: $backendName")
            Log.i(TAG, "SELinux: ${if (selinux) "Enforcing" else "Permissive"}, Bootloader: ${if (bootloader) "Locked" else "Unlocked"}")

            if (!isRooted) {
                Log.i(TAG, "Root not found. Attempting to gain root...")
                status = Status(
                    state = RootState.ATTEMPTING,
                    chipsetName = chipset,
                    modemName = modem,
                    preferredBackend = backendName
                )

                // Attempt root
                val rooted = NativeBridge.nativeDeviceAttemptRoot(deviceInfo)
                if (rooted) {
                    Log.i(TAG, "Root gained successfully!")
                    status = Status(
                        state = RootState.ROOTED,
                        chipsetName = chipset,
                        modemName = modem,
                        preferredBackend = backendName
                    )
                } else {
                    Log.w(TAG, "Root attempt failed")
                    // Check if we can still access the modem (media group for Huawei)
                    val mediaAccess = checkMediaAccess()
                    status = Status(
                        state = if (mediaAccess) RootState.MEDIA_ACCESS else RootState.NOT_ROOTED,
                        chipsetName = chipset,
                        modemName = modem,
                        preferredBackend = backendName,
                        diagnosis = buildDiagnosis(chipset, isRooted, selinux, bootloader, backendName)
                    )
                }
            } else {
                status = Status(
                    state = RootState.ROOTED,
                    chipsetName = chipset,
                    modemName = modem,
                    preferredBackend = backendName
                )
            }

            NativeBridge.nativeDeviceFree(deviceInfo)
        } catch (e: Exception) {
            Log.e(TAG, "Root check failed", e)
            status = Status(
                state = RootState.FAILED,
                diagnosis = "Error: ${e.message}"
            )
        }

        status
    }

    private fun checkMediaAccess(): Boolean {
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("su", "-c", "test -r /dev/ttyAMA0 && echo YES"))
            val result = process.inputStream.bufferedReader().readText()
            process.waitFor()
            result.contains("YES")
        } catch (e: Exception) {
            false
        }
    }

    private fun buildDiagnosis(
        chipset: String,
        isRooted: Boolean,
        selinux: Boolean,
        bootloaderLocked: Boolean,
        backend: String
    ): String {
        val sb = StringBuilder()
        sb.appendLine("Device: $chipset")
        sb.appendLine("Backend: $backend")
        sb.appendLine()

        if (!isRooted) {
            sb.appendLine("ROOT REQUIRED. Options:")

            if (chipset.contains("Qualcomm")) {
                sb.appendLine("1. Enable DIAG port: dial *#0808# -> DM+MODEM+ADB")
                sb.appendLine("2. Root: Install Magisk via TWRP or patch boot.img")
            } else if (chipset.contains("Kirin") || chipset.contains("HiSilicon")) {
                sb.appendLine("1. Root: Use Magisk + patch ramdisk.img")
                sb.appendLine("2. If bootloader is locked, use DC-unlocker")
                sb.appendLine("3. Verify /dev/ttyAMA0 is accessible after root")
                if (bootloaderLocked) {
                    sb.appendLine("NOTE: Bootloader is LOCKED. You need:")
                    sb.appendLine("  - DC-unlocker / HCU Client (paid) for unlock code")
                    sb.appendLine("  - Or testpoint method to enter download mode")
                }
            } else if (chipset.contains("MediaTek")) {
                sb.appendLine("1. Root: Magisk or mtk-su exploit")
                sb.appendLine("2. Use SP Flash Tool for bootloader unlock")
            } else {
                sb.appendLine("1. Install Magisk Manager")
                sb.appendLine("2. Patch boot.img and flash via fastboot")
            }

            if (selinux) {
                sb.appendLine("3. Set SELinux permissive: su -c setenforce 0")
            }
        }

        return sb.toString()
    }
}
