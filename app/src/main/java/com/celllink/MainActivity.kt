package com.celllink

import android.Manifest
import android.util.Log
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.IBinder
import android.view.View
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.Spinner
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import java.util.Locale

class MainActivity : AppCompatActivity() {

    // ── Mode selection state ────────────────────────────────────────────

    private enum class AppMode { NONE, TOWER, CLIENT }

    private var currentMode = AppMode.NONE

    // BTS state
    private var btsService: BtsTowerService? = null
    private var btsBound = false

    // UE state
    private var ueService: UeClientService? = null
    private var ueBound = false

    // Audio routing
    private lateinit var audioRouter: AudioRouter

    // ── View references ─────────────────────────────────────────────────

    private lateinit var btnStartTower: Button
    private lateinit var btnScanConnect: Button
    private lateinit var btnCall: Button
    private lateinit var btnEndCall: Button
    private lateinit var btsStatusText: TextView
    private lateinit var btsStatusLayout: View
    private lateinit var ueStatusText: TextView
    private lateinit var ueStatusLayout: View
    private lateinit var callLayout: View
    private lateinit var signalText: TextView
    private lateinit var bandSpinner: Spinner

    // ── Service connections ─────────────────────────────────────────────

    private val btsConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName, service: IBinder) {
            btsService = (service as BtsTowerService.BtsBinder).getService()
            btsBound = true
            observeBtsStatus()
        }

        override fun onServiceDisconnected(name: ComponentName) {
            btsService = null
            btsBound = false
        }
    }

    private val ueConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName, service: IBinder) {
            ueService = (service as UeClientService.UeBinder).getService()
            ueBound = true
            observeUeStatus()
        }

        override fun onServiceDisconnected(name: ComponentName) {
            ueService = null
            ueBound = false
        }
    }

    // ── Permission launcher ─────────────────────────────────────────────

    private val permissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { permissions ->
        val allGranted = permissions.values.all { it }
        if (!allGranted) {
            Toast.makeText(this, "All permissions are required", Toast.LENGTH_LONG).show()
        }
    }

    // ── Lifecycle ───────────────────────────────────────────────────────

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        audioRouter = AudioRouter(this)
        bindViews()
        setupBandSpinner()

        requestPermissionsIfNeeded()

        // Detect device and open correct modem backend
        lifecycleScope.launch {
            when (val state = DiagManager.detectAndOpen()) {
                is DiagManager.State.Ready -> {
                    Log.i("CellLink-UI", "Modem ready: backend=${state.backend}")
                    Toast.makeText(this@MainActivity,
                        "Modem ready: ${state.backend}", Toast.LENGTH_SHORT).show()
                }
                is DiagManager.State.NeedsRoot -> {
                    Log.w("CellLink-UI", "Root needed: ${state.diagnosis}")
                    showRootDialog(state.diagnosis)
                }
                is DiagManager.State.Error -> {
                    Toast.makeText(this@MainActivity, state.message, Toast.LENGTH_LONG).show()
                }
                else -> {}
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        if (btsBound) unbindService(btsConnection)
        if (ueBound) unbindService(ueConnection)
        DiagManager.close()
    }

    // ── UI Binding ──────────────────────────────────────────────────────

    private fun bindViews() {
        btnStartTower = findViewById(R.id.btnStartTower)
        btnScanConnect = findViewById(R.id.btnScanConnect)
        btnCall = findViewById(R.id.btnCall)
        btnEndCall = findViewById(R.id.btnEndCall)
        btsStatusText = findViewById(R.id.btsStatusText)
        btsStatusLayout = findViewById(R.id.btsStatusLayout)
        ueStatusText = findViewById(R.id.ueStatusText)
        ueStatusLayout = findViewById(R.id.ueStatusLayout)
        callLayout = findViewById(R.id.callLayout)
        signalText = findViewById(R.id.signalText)
        bandSpinner = findViewById(R.id.bandSpinner)

        btnStartTower.setOnClickListener { toggleTower() }
        btnScanConnect.setOnClickListener { toggleClient() }
        btnCall.setOnClickListener { makeCall() }
        btnEndCall.setOnClickListener { endCall() }
    }

    private fun setupBandSpinner() {
        val bands = arrayOf(
            "P-GSM-900 (CH 1-124)",
            "E-GSM-900 (CH 0,975-1023)",
            "GSM-850 (CH 128-251)",
            "DCS-1800 (CH 512-885)",
            "PCS-1900 (CH 512-810)"
        )
        val adapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, bands)
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        bandSpinner.adapter = adapter
        bandSpinner.setSelection(0) // Default: P-GSM-900
    }

    // ── Permissions ─────────────────────────────────────────────────────

    private fun requestPermissionsIfNeeded() {
        val permissions = mutableListOf(
            Manifest.permission.READ_PHONE_STATE,
            Manifest.permission.RECORD_AUDIO,
            Manifest.permission.MODIFY_AUDIO_SETTINGS,
            Manifest.permission.ACCESS_FINE_LOCATION,
        )

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            permissions.add(Manifest.permission.READ_MEDIA_AUDIO)
            permissions.add(Manifest.permission.POST_NOTIFICATIONS)
        } else {
            @Suppress("DEPRECATION")
            permissions.add(Manifest.permission.READ_EXTERNAL_STORAGE)
        }

        val missing = permissions.filter {
            ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
        }

        if (missing.isNotEmpty()) {
            permissionLauncher.launch(missing.toTypedArray())
        }
    }

    // ── Tower Mode ──────────────────────────────────────────────────────

    private fun toggleTower() {
        when (currentMode) {
            AppMode.TOWER -> stopTower()
            AppMode.CLIENT -> {
                stopClient()
                startTower()
            }
            AppMode.NONE -> startTower()
        }
    }

    private fun startTower() {
        val arfcn = 1 // Default: P-GSM-900 channel 1
        val band = bandSpinner.selectedItemPosition // 0=900, 1=900-E, 2=850, 3=1800, 4=1900
        val txPower = 15

        val intent = Intent(this, BtsTowerService::class.java).apply {
            putExtra("arfcn", arfcn)
            putExtra("band", band)
            putExtra("tx_power", txPower)
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }

        bindService(
            Intent(this, BtsTowerService::class.java),
            btsConnection,
            Context.BIND_AUTO_CREATE
        )

        currentMode = AppMode.TOWER
        btnStartTower.text = "Stop Tower"
        btnStartTower.setOnClickListener { stopTower() }
        btnScanConnect.isEnabled = false
    }

    private fun stopTower() {
        btsService?.stopTower()
        if (btsBound) {
            unbindService(btsConnection)
            btsBound = false
            btsService = null
        }

        currentMode = AppMode.NONE
        resetUI()
        audioRouter.stopVoiceCall()
    }

    private fun observeBtsStatus() {
        lifecycleScope.launch {
            btsService?.status?.collectLatest { status ->
                when (status.state) {
                    BtsTowerService.BtsState.INIT -> {
                        btsStatusLayout.visibility = View.VISIBLE
                        btsStatusText.text = "Initializing..."
                    }
                    BtsTowerService.BtsState.BROADCASTING -> {
                        btsStatusLayout.visibility = View.VISIBLE
                        btsStatusText.text = String.format(
                            Locale.US,
                            "Broadcasting on ARFCN %d (%.1f MHz)",
                            status.arfcn, status.dlFreqMhz
                        )
                    }
                    BtsTowerService.BtsState.CONNECTED -> {
                        btsStatusText.text = "UE connected — awaiting call"
                    }
                    BtsTowerService.BtsState.IN_CALL -> {
                        btsStatusText.text = "In call (%.1f MHz)".format(status.dlFreqMhz)
                        audioRouter.startVoiceCall()
                    }
                    BtsTowerService.BtsState.ERROR -> {
                        btsStatusText.text = "Error: ${status.errorMessage}"
                        Toast.makeText(
                            this@MainActivity,
                            "Tower error: ${status.errorMessage}",
                            Toast.LENGTH_LONG
                        ).show()
                        stopTower()
                    }
                    BtsTowerService.BtsState.OFF -> {}
                }
            }
        }
    }

    // ── Client (UE) Mode ────────────────────────────────────────────────

    private fun toggleClient() {
        when (currentMode) {
            AppMode.CLIENT -> stopClient()
            AppMode.TOWER -> {
                stopTower()
                startClient()
            }
            AppMode.NONE -> startClient()
        }
    }

    private fun startClient() {
        val intent = Intent(this, UeClientService::class.java).apply {
            putExtra("mcc", 901)
            putExtra("mnc", 1)
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }

        bindService(
            Intent(this, UeClientService::class.java),
            ueConnection,
            Context.BIND_AUTO_CREATE
        )

        currentMode = AppMode.CLIENT
        btnScanConnect.text = "Disconnect"
        btnScanConnect.setOnClickListener { stopClient() }
        btnStartTower.isEnabled = false
    }

    private fun stopClient() {
        ueService?.disconnect()
        if (ueBound) {
            unbindService(ueConnection)
            ueBound = false
            ueService = null
        }

        currentMode = AppMode.NONE
        resetUI()
        audioRouter.stopVoiceCall()
    }

    private fun observeUeStatus() {
        lifecycleScope.launch {
            ueService?.status?.collectLatest { status ->
                when (status.state) {
                    UeClientService.UeState.SCANNING -> {
                        ueStatusLayout.visibility = View.VISIBLE
                        ueStatusText.text = "Scanning for networks..."
                    }
                    UeClientService.UeState.CONNECTING -> {
                        ueStatusText.text = "Connecting to tower..."
                    }
                    UeClientService.UeState.REGISTERED -> {
                        ueStatusText.text = "Connected — Ready"
                        callLayout.visibility = View.VISIBLE
                        btnCall.visibility = View.VISIBLE
                        btnEndCall.visibility = View.GONE
                        signalText.visibility = View.VISIBLE
                    }
                    UeClientService.UeState.CALLING -> {
                        ueStatusText.text = "Calling..."
                    }
                    UeClientService.UeState.IN_CALL -> {
                        ueStatusText.text = "In call"
                        btnCall.visibility = View.GONE
                        btnEndCall.visibility = View.VISIBLE
                        audioRouter.startVoiceCall()
                    }
                    UeClientService.UeState.ERROR -> {
                        ueStatusText.text = "Error: ${status.errorMessage}"
                        Toast.makeText(
                            this@MainActivity,
                            "Client error: ${status.errorMessage}",
                            Toast.LENGTH_LONG
                        ).show()
                        stopClient()
                    }
                    UeClientService.UeState.IDLE -> {}
                }

                // Update signal display
                if (signalText.visibility == View.VISIBLE) {
                    signalText.text = String.format(
                        Locale.US,
                        "Signal: %d dBm | Networks found: %d",
                        status.rssiDbm, status.scanCount
                    )
                }
            }
        }
    }

    // ── Call Controls ───────────────────────────────────────────────────

    private fun makeCall() {
        ueService?.makeCall()
    }

    private fun endCall() {
        when (currentMode) {
            AppMode.TOWER -> btsService?.endCall()
            AppMode.CLIENT -> ueService?.endCall()
            else -> {}
        }
        audioRouter.stopVoiceCall()
        btnCall.visibility = View.VISIBLE
        btnEndCall.visibility = View.GONE
    }

    // ── Root Dialog ───────────────────────────────────────────────────────

    private fun showRootDialog(diagnosis: String) {
        androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle(R.string.root_required_title)
            .setMessage(diagnosis)
            .setPositiveButton("Try Again") { _, _ ->
                lifecycleScope.launch {
                    Toast.makeText(this@MainActivity, "Retrying...", Toast.LENGTH_SHORT).show()
                    DiagManager.close()
                    when (val s = DiagManager.detectAndOpen()) {
                        is DiagManager.State.Ready ->
                            Toast.makeText(this@MainActivity, "Root OK!", Toast.LENGTH_SHORT).show()
                        is DiagManager.State.NeedsRoot ->
                            showRootDialog(s.diagnosis)
                        else ->
                            Toast.makeText(this@MainActivity, "Still no root", Toast.LENGTH_SHORT).show()
                    }
                }
            }
            .setNegativeButton("Continue Anyway") { _, _ ->
                Toast.makeText(this@MainActivity,
                    "Limited functionality. Root for full access.", Toast.LENGTH_LONG).show()
            }
            .setCancelable(false)
            .show()
    }

    // ── UI Reset ────────────────────────────────────────────────────────

    private fun resetUI() {
        btnStartTower.text = "Start Tower"
        btnStartTower.isEnabled = true
        btnStartTower.setOnClickListener { toggleTower() }

        btnScanConnect.text = "Scan & Connect"
        btnScanConnect.isEnabled = true
        btnScanConnect.setOnClickListener { toggleClient() }

        btsStatusLayout.visibility = View.GONE
        ueStatusLayout.visibility = View.GONE
        callLayout.visibility = View.GONE
        signalText.visibility = View.GONE
        btnCall.visibility = View.VISIBLE
        btnEndCall.visibility = View.GONE
    }
}
