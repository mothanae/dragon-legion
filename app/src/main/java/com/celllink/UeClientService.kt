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
 * Foreground service that runs the UE (User Equipment) client.
 *
 * UE State flow:
 *   IDLE(0) -> SCANNING(1) -> CONNECTING(2) -> REGISTERED(3) -> CALLING(4) -> IN_CALL(5)
 *                                                                   \-> ERROR(6)
 */
class UeClientService : LifecycleService() {

    companion object {
        private const val TAG = "CellLink-UE"
        private const val NOTIFICATION_ID = 1002
        private const val CHANNEL_ID = "ue_client_channel"
        const val ACTION_STOP = "com.celllink.action.STOP_UE"
        const val ACTION_CALL = "com.celllink.action.CALL_UE"
        const val ACTION_END_CALL = "com.celllink.action.END_CALL_UE"
    }

    enum class UeState(val code: Int) {
        IDLE(0), SCANNING(1), CONNECTING(2), REGISTERED(3),
        CALLING(4), IN_CALL(5), ERROR(6);

        companion object {
            fun fromCode(code: Int) = entries.firstOrNull { it.code == code } ?: ERROR
        }
    }

    data class UeStatus(
        val state: UeState = UeState.IDLE,
        val rssiDbm: Int = -120,
        val scanCount: Int = 0,
        val errorMessage: String? = null
    )

    private val _status = MutableStateFlow(UeStatus())
    val status: StateFlow<UeStatus> = _status

    private var ueHandle: Long = 0
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val binder = UeBinder()

    // Polling job for signal strength
    private var signalPollJob: Job? = null

    inner class UeBinder : Binder() {
        fun getService(): UeClientService = this@UeClientService
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
            ACTION_STOP -> disconnect()
            ACTION_CALL -> makeCall()
            ACTION_END_CALL -> endCall()
            else -> {
                val mcc = intent?.getIntExtra("mcc", 901) ?: 901
                val mnc = intent?.getIntExtra("mnc", 1) ?: 1
                connectAndRegister(mcc, mnc)
            }
        }
        return START_STICKY
    }

    fun connectAndRegister(mcc: Int, mnc: Int) {
        if (ueHandle != 0L) return

        startForeground(NOTIFICATION_ID, buildNotification("Connecting..."))

        scope.launch {
            try {
                if (DiagManager.state.value !is DiagManager.State.Ready) {
                    DiagManager.detectAndOpen()
                }
                val diagState = DiagManager.state.value as? DiagManager.State.Ready
                    ?: throw IllegalStateException("Modem not available. Check root and backend.")

                val modemHandle = when (diagState.backend) {
                    DiagManager.Backend.DIAG_QMI -> diagState.diagHandle
                    else -> diagState.hisiliconHandle
                }

                // Initialize UE
                ueHandle = NativeBridge.nativeUeInit(modemHandle)
                if (ueHandle == 0L) {
                    throw IllegalStateException("UE initialization failed")
                }

                // Scan for networks
                _status.value = UeStatus(UeState.SCANNING)
                updateNotification("Scanning for networks...")
                val count = NativeBridge.nativeUeScanNetworks(ueHandle)
                _status.value = UeStatus(UeState.SCANNING, scanCount = count)
                Log.i(TAG, "Network scan found $count networks")

                // Register on target network
                _status.value = UeStatus(UeState.CONNECTING)
                updateNotification("Registering on $mcc/$mnc...")
                val registered = NativeBridge.nativeUeRegisterNetwork(ueHandle, mcc, mnc)

                if (!registered) {
                    throw IllegalStateException("Failed to register on network $mcc/$mnc")
                }

                _status.value = UeStatus(UeState.REGISTERED)
                updateNotification("Connected to $mcc/$mnc — Ready")
                startSignalPolling()

            } catch (e: Exception) {
                Log.e(TAG, "UE connection error", e)
                _status.value = UeStatus(UeState.ERROR, errorMessage = e.message)
                disconnect()
            }
        }
    }

    fun makeCall() {
        if (ueHandle == 0L) return

        scope.launch {
            _status.value = _status.value.copy(state = UeState.CALLING)
            updateNotification("Calling...")

            if (NativeBridge.nativeUeMakeCall(ueHandle)) {
                _status.value = _status.value.copy(state = UeState.IN_CALL)
                updateNotification("In call")
            } else {
                _status.value = _status.value.copy(
                    state = UeState.ERROR,
                    errorMessage = "Call failed"
                )
            }
        }
    }

    fun endCall() {
        if (ueHandle == 0L) return

        scope.launch {
            NativeBridge.nativeUeEndCall(ueHandle)
            _status.value = _status.value.copy(state = UeState.REGISTERED)
            updateNotification("Connected — Ready")
        }
    }

    fun answerCall() {
        if (ueHandle == 0L) return

        scope.launch {
            if (NativeBridge.nativeUeAnswerCall(ueHandle)) {
                _status.value = _status.value.copy(state = UeState.IN_CALL)
                updateNotification("In call")
            }
        }
    }

    fun disconnect() {
        scope.launch {
            signalPollJob?.cancel()
            if (ueHandle != 0L) {
                NativeBridge.nativeUeEndCall(ueHandle) // Ensure call is ended
                NativeBridge.nativeUeFree(ueHandle)
                ueHandle = 0L
            }
            _status.value = UeStatus(UeState.IDLE)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    private fun startSignalPolling() {
        signalPollJob = scope.launch {
            while (isActive) {
                val rssi = NativeBridge.nativeUeGetRssi(ueHandle)
                _status.value = _status.value.copy(rssiDbm = rssi)
                delay(2000)
            }
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "CellLink Client",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "UE client connection status"
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(text: String): Notification {
        val stopIntent = Intent(this, UeClientService::class.java).apply {
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
                .setContentTitle("CellLink Client")
                .setContentText(text)
                .setSmallIcon(android.R.drawable.ic_menu_call)
                .setContentIntent(openPendingIntent)
                .addAction(android.R.drawable.ic_media_pause, "Disconnect", stopPendingIntent)
                .setOngoing(true)
                .build()
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
                .setContentTitle("CellLink Client")
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
        disconnect()
        scope.cancel()
        super.onDestroy()
    }
}
