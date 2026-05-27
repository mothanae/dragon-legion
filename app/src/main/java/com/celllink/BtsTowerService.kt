package com.celllink

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.os.Binder
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.lifecycle.LifecycleService
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/**
 * Foreground service that runs the BTS tower.
 *
 * BTS State flow:
 *   OFF(0) -> INIT(1) -> BROADCASTING(2) -> CONNECTED(3) -> IN_CALL(4)
 *                                                 \-> ERROR(5)
 */
class BtsTowerService : LifecycleService() {

    companion object {
        private const val TAG = "CellLink-BTS"
        private const val NOTIFICATION_ID = 1001
        private const val CHANNEL_ID = "bts_tower_channel"
        const val ACTION_STOP = "com.celllink.action.STOP_BTS"
    }

    enum class BtsState(val code: Int) {
        OFF(0), INIT(1), BROADCASTING(2), CONNECTED(3), IN_CALL(4), ERROR(5);

        companion object {
            fun fromCode(code: Int) = entries.firstOrNull { it.code == code } ?: ERROR
        }
    }

    data class BtsStatus(
        val state: BtsState = BtsState.OFF,
        val arfcn: Int = 0,
        val dlFreqMhz: Float = 0f,
        val errorMessage: String? = null
    )

    private val _status = MutableStateFlow(BtsStatus())
    val status: StateFlow<BtsStatus> = _status

    private var btsHandle: Long = 0
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val binder = BtsBinder()

    inner class BtsBinder : Binder() {
        fun getService(): BtsTowerService = this@BtsTowerService
    }

    override fun onBind(intent: Intent): IBinder {
        super.onBind(intent)
        return binder
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> stopTower()
            else -> {
                val arfcn = intent?.getIntExtra("arfcn", 1) ?: 1
                val band = intent?.getIntExtra("band", 1) ?: 1  // GSM_BAND_900
                val txPower = intent?.getIntExtra("tx_power", 15) ?: 15
                startTower(arfcn, band, txPower)
            }
        }
        return START_STICKY
    }

    fun startTower(arfcn: Int, band: Int, txPower: Int) {
        if (btsHandle != 0L) return

        startForeground(NOTIFICATION_ID, buildNotification("Starting tower..."))

        scope.launch {
            try {
                // Ensure modem is open
                if (DiagManager.state.value !is DiagManager.State.Ready) {
                    DiagManager.detectAndOpen()
                }
                val diagState = DiagManager.state.value as? DiagManager.State.Ready
                    ?: throw IllegalStateException("Modem not available. Check root and backend.")

                val modemHandle = when (diagState.backend) {
                    DiagManager.Backend.DIAG_QMI -> diagState.diagHandle
                    else -> diagState.hisiliconHandle
                }

                // Initialize BTS — use DIAG or HiSilicon backend
                btsHandle = NativeBridge.nativeBtsInit(
                    modemHandle, arfcn, band, txPower
                )

                if (btsHandle == 0L) {
                    throw IllegalStateException("BTS initialization failed")
                }

                val freq = NativeBridge.nativeBtsGetDlFrequency(btsHandle)
                _status.value = BtsStatus(BtsState.INIT, arfcn, freq)

                // Start broadcasting
                if (!NativeBridge.nativeBtsStart(btsHandle)) {
                    throw IllegalStateException("BTS broadcast start failed")
                }

                _status.value = BtsStatus(BtsState.BROADCASTING, arfcn, freq)
                updateNotification("Broadcasting on ARFCN $arfcn (${"%.1f".format(freq)} MHz)")

                // Monitor BTS state
                while (isActive) {
                    delay(1000)
                    val nativeState = NativeBridge.nativeBtsGetState(btsHandle)
                    val newState = BtsState.fromCode(nativeState)
                    val currentFreq = NativeBridge.nativeBtsGetDlFrequency(btsHandle)

                    _status.value = BtsStatus(
                        state = newState,
                        arfcn = arfcn,
                        dlFreqMhz = currentFreq
                    )

                    when (newState) {
                        BtsState.IN_CALL -> updateNotification("In call — ${"%.1f".format(currentFreq)} MHz")
                        BtsState.CONNECTED -> updateNotification("UE connected — ${"%.1f".format(currentFreq)} MHz")
                        BtsState.ERROR -> {
                            stopTower()
                            break
                        }
                        else -> {}
                    }
                }

            } catch (e: Exception) {
                Log.e(TAG, "BTS tower error", e)
                _status.value = BtsStatus(BtsState.ERROR, errorMessage = e.message)
                stopTower()
            }
        }
    }

    fun stopTower() {
        scope.launch {
            if (btsHandle != 0L) {
                NativeBridge.nativeBtsStop(btsHandle)
                NativeBridge.nativeBtsFree(btsHandle)
                btsHandle = 0L
            }
            _status.value = BtsStatus(BtsState.OFF)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    fun acceptCall() {
        if (btsHandle != 0L) {
            NativeBridge.nativeBtsAcceptCall(btsHandle)
        }
    }

    fun endCall() {
        if (btsHandle != 0L) {
            NativeBridge.nativeBtsEndCall(btsHandle)
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "CellLink Tower",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "BTS tower operation status"
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(text: String): Notification {
        val stopIntent = Intent(this, BtsTowerService::class.java).apply {
            action = ACTION_STOP
        }
        val stopPendingIntent = PendingIntent.getService(
            this, 0, stopIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val openIntent = Intent(this, MainActivity::class.java)
        val openPendingIntent = PendingIntent.getActivity(
            this, 0, openIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
                .setContentTitle("CellLink Tower")
                .setContentText(text)
                .setSmallIcon(android.R.drawable.ic_menu_call)
                .setContentIntent(openPendingIntent)
                .addAction(android.R.drawable.ic_media_pause, "Stop", stopPendingIntent)
                .setOngoing(true)
                .build()
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
                .setContentTitle("CellLink Tower")
                .setContentText(text)
                .setSmallIcon(android.R.drawable.ic_menu_call)
                .setContentIntent(openPendingIntent)
                .setOngoing(true)
                .build()
        }
    }

    private fun updateNotification(text: String) {
        val manager = getSystemService(NotificationManager::class.java)
        manager.notify(NOTIFICATION_ID, buildNotification(text))
    }

    override fun onDestroy() {
        stopTower()
        scope.cancel()
        super.onDestroy()
    }
}
