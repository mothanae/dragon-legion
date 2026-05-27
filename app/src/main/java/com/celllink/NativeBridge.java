package com.celllink;

/**
 * JNI bridge to the native celllink library (libcelllink_native.so).
 * All modem control goes through this class.
 */
public final class NativeBridge {

    static {
        System.loadLibrary("celllink_native");
    }

    private NativeBridge() {}

    // ── DIAG Port ──────────────────────────────────────────────────────

    /** Open the DIAG diagnostic port. Returns native handle or 0 on failure. */
    public static native long nativeDiagOpen(String devicePath);

    /** Close the DIAG port. */
    public static native void nativeDiagClose(long handle);

    /** Check if the DIAG port is open and responsive. */
    public static native boolean nativeDiagIsReady(long handle);

    /** Send a raw AT command and get the response. Returns null on timeout. */
    public static native String nativeDiagAtCommand(long handle, String command);

    /** Enter Factory Test Mode. */
    public static native boolean nativeDiagEnterFtm(long handle);

    // ── BTS Tower Mode ─────────────────────────────────────────────────

    /** Initialize BTS tower. Returns native handle. */
    public static native long nativeBtsInit(long diagHandle, int arfcn, int band, int txPower);

    /** Start broadcasting. */
    public static native boolean nativeBtsStart(long handle);

    /** Stop broadcasting and Tx. */
    public static native boolean nativeBtsStop(long handle);

    /** Free BTS resources. */
    public static native void nativeBtsFree(long handle);

    /** Get BTS state: 0=OFF, 1=INIT, 2=BROADCASTING, 3=CONNECTED, 4=IN_CALL, 5=ERROR */
    public static native int nativeBtsGetState(long handle);

    /** Get the downlink frequency in MHz for display. */
    public static native float nativeBtsGetDlFrequency(long handle);

    /** Accept an incoming call on the tower. */
    public static native boolean nativeBtsAcceptCall(long handle);

    /** End the active call on the tower. */
    public static native boolean nativeBtsEndCall(long handle);

    // ── UE Client Mode ─────────────────────────────────────────────────

    /** Initialize UE client. Returns native handle. */
    public static native long nativeUeInit(long diagHandle);

    /** Scan for available networks. Returns count found. */
    public static native int nativeUeScanNetworks(long handle);

    /** Register on a specific network (MCC/MNC). */
    public static native boolean nativeUeRegisterNetwork(long handle, int mcc, int mnc);

    /** Initiate a voice call to the tower. */
    public static native boolean nativeUeMakeCall(long handle);

    /** End the active call. */
    public static native boolean nativeUeEndCall(long handle);

    /** Answer an incoming call. */
    public static native boolean nativeUeAnswerCall(long handle);

    /** Get UE state: 0=IDLE, 1=SCANNING, 2=CONNECTING, 3=REGISTERED, 4=CALLING, 5=IN_CALL, 6=ERROR */
    public static native int nativeUeGetState(long handle);

    /** Get current RSSI in dBm. */
    public static native int nativeUeGetRssi(long handle);

    /** Get scan results as a raw string. */
    public static native String nativeUeGetScanResults(long handle);

    /** Free UE resources. */
    public static native void nativeUeFree(long handle);

    // ── Utilities ──────────────────────────────────────────────────────

    /** Convert ARFCN + band to downlink frequency in MHz. */
    public static native float nativeArfcnToDlFreq(int arfcn, int band);

    // ── SMS ─────────────────────────────────────────────────────────────

    /** Send an SMS message via the active modem connection. */
    public static native boolean nativeSmsSend(long diagHandle, String recipient, String text);

    /** List received SMS messages. Returns count. */
    public static native int nativeSmsListReceived(long diagHandle, android.os.Parcelable[] outArray);

    // ── GPS Timing ──────────────────────────────────────────────────────

    /** Initialize GPS timing system. Returns native handle. */
    public static native long nativeGpsTimingInit();

    /** Free GPS timing resources. */
    public static native void nativeGpsTimingFree(long handle);

    /** Feed an NMEA sentence for GPS time extraction. */
    public static native void nativeGpsFeedNmea(long handle, String nmea);

    /** Get GPS timing state: 0=FREE_RUNNING, 1=3D_FIX, 2=DISCIPLINED, 3=HOLDOVER */
    public static native int nativeGpsGetState(long handle);

    /** Get human-readable GPS timing status. */
    public static native String nativeGpsStatusString(long handle);

    /** Get estimated oscillator frequency error in parts-per-billion. */
    public static native double nativeGpsFreqError(long handle);

    // ── Hexagon DSP ─────────────────────────────────────────────────────

    /** Open a FastRPC channel to the Hexagon DSP. Returns native handle. */
    public static native long nativeHexagonOpen(String devicePath);

    /** Close the Hexagon RPC channel. */
    public static native void nativeHexagonClose(long handle);

    /** Enable mic-to-DSP and DSP-to-speaker audio paths. */
    public static native boolean nativeHexagonEnableAudio(long handle);

    /** Configure L1 (physical layer) parameters for transmission. */
    public static native boolean nativeHexagonL1Configure(
            long handle, int arfcn, int timeslot, int trainingSeq, int txPower);

    /** Start L1 transmission. */
    public static native boolean nativeHexagonL1StartTx(long handle);

    /** Stop L1 transmission. */
    public static native boolean nativeHexagonL1StopTx(long handle);

    /** Send a raw RF frame through the Hexagon DSP to transmit. */
    public static native boolean nativeHexagonRfSendFrame(long handle, byte[] frame);

    // ── Secure Boot ─────────────────────────────────────────────────────

    /** Apply live RAM patches to bypass SIM authentication and network checks. */
    public static native int nativeSecureBootBypass(long diagHandle);

    // ── RF Spectrum Analyzer ───────────────────────────────────────────────

    /** Initialize spectrum scanner. Returns native handle. */
    public static native long nativeSpectrumInit();

    /** Free spectrum scanner. */
    public static native void nativeSpectrumFree(long handle);

    /** Sweep all GSM bands for channel quality. Returns channel count. */
    public static native int nativeSpectrumSweepAll(long diagHandle, long scanHandle);

    /** Find the clearest ARFCN in the scan results. */
    public static native int nativeSpectrumFindBest(long scanHandle, int preferredBand);

    /** Export spectrum scan results as CSV string. */
    public static native String nativeSpectrumExportCsv(long scanHandle);

    // ── Virtual SIM ────────────────────────────────────────────────────────

    /** Create a virtual SIM card with custom identity. Returns native handle. */
    public static native long nativeVsimCreate(int mcc, int mnc, String imsi,
                                                String msisdn, String spn);

    /** Free virtual SIM resources. */
    public static native void nativeVsimFree(long handle);

    /** Activate the virtual SIM in the modem. */
    public static native boolean nativeVsimActivate(long simHandle, long diagHandle);

    // ── Modem Crash Recovery ───────────────────────────────────────────────

    /** Initialize modem recovery watchdog. Returns native handle. */
    public static native long nativeModemRecoveryInit(long diagHandle);

    /** Free modem recovery resources. */
    public static native void nativeModemRecoveryFree(long handle);

    /** Check if modem is responsive. */
    public static native boolean nativeModemIsAlive(long handle);

    /** Attempt full modem recovery sequence. Returns final state. */
    public static native int nativeModemRecover(long handle);

    /** Get last crash information. */
    public static native String nativeModemCrashInfo(long handle);

    // ── Call Recorder ──────────────────────────────────────────────────────

    /** Create a call recorder. Returns native handle. */
    public static native long nativeCallRecorderCreate(String filename);

    /** Free recorder resources. */
    public static native void nativeCallRecorderFree(long handle);

    /** Start recording to WAV file. */
    public static native boolean nativeCallRecorderStart(long handle);

    /** Stop recording and finalize WAV file. */
    public static native boolean nativeCallRecorderStop(long handle);

    /** Get recording duration in seconds. */
    public static native double nativeCallRecorderGetDuration(long handle);

    // ── DTMF ───────────────────────────────────────────────────────────────

    /** Send a single DTMF digit via the modem. */
    public static native boolean nativeDtmfSend(long diagHandle, char digit);

    /** Send a DTMF digit string via the modem. */
    public static native boolean nativeDtmfSendString(long diagHandle, String digits);

    // ── GSM Protocol Sniffer ───────────────────────────────────────────────

    /** Create a GSM L3 protocol sniffer. Returns native handle. */
    public static native long nativeSnifferCreate(String filename);

    /** Free sniffer resources. */
    public static native void nativeSnifferFree(long handle);

    /** Start sniffing GSM L3 messages. */
    public static native boolean nativeSnifferStart(long handle);

    /** Stop sniffing. */
    public static native boolean nativeSnifferStop(long handle);

    // ── Band Scanner ───────────────────────────────────────────────────────

    /** Create a band scanner. Returns native handle. */
    public static native long nativeBandScanCreate();

    /** Free band scanner. */
    public static native void nativeBandScanFree(long handle);

    /** Perform full band scan for visible cells. Returns cell count. */
    public static native int nativeBandScanFull(long diagHandle, long scanHandle);

    /** Export band scan results as CSV. */
    public static native String nativeBandScanExportCsv(long handle);

    // ── PA Protection ──────────────────────────────────────────────────────

    /** Initialize PA protection system. Returns native handle. */
    public static native long nativePaProtectInit();

    /** Free PA protection resources. */
    public static native void nativePaProtectFree(long handle);

    /** Notify PA protection of Tx start. Returns true if Tx allowed. */
    public static native boolean nativePaProtectTxStart(long handle, int powerDbm, int arfcn);

    /** Notify PA protection of Tx stop. */
    public static native boolean nativePaProtectTxStop(long handle);

    /** Update PA thermal/power state. Returns true if Tx can continue. */
    public static native boolean nativePaProtectUpdate(long handle, float tempC,
                                                        float fwdPower, float revPower);

    /** Get PA protection state as a string. */
    public static native String nativePaProtectState(long handle);

    // ── Modem Logger ───────────────────────────────────────────────────────

    /** Create a structured modem logger. Returns native handle. */
    public static native long nativeModemLoggerCreate(String filename);

    /** Free modem logger resources. */
    public static native void nativeModemLoggerFree(long handle);

    /** Start logging to file. */
    public static native boolean nativeModemLoggerStart(long handle);

    /** Stop logging. */
    public static native boolean nativeModemLoggerStop(long handle);

    /** Export recent log entries as text. */
    public static native String nativeModemLoggerExport(long handle, int lastN);

    // ── Device Detection ────────────────────────────────────────────────────

    /** Detect device chipset, modem, and capabilities. Returns native handle. */
    public static native long nativeDeviceDetect();

    /** Free device info. */
    public static native void nativeDeviceFree(long handle);

    /** Get chipset name (e.g. "HiSilicon Kirin"). */
    public static native String nativeDeviceGetChipset(long handle);

    /** Get modem name (e.g. "HiSilicon Balong"). */
    public static native String nativeDeviceGetModem(long handle);

    /** Check if device is rooted. */
    public static native boolean nativeDeviceIsRooted(long handle);

    /** Get preferred backend: 0=DIAG/QMI, 1=HiSilicon AT, 2=MTK AT, 3=Generic AT, 4=RIL */
    public static native int nativeDeviceGetBackend(long handle);

    /** Check if SELinux is enforcing. */
    public static native boolean nativeDeviceSelinuxEnforcing(long handle);

    /** Check if bootloader is unlocked. */
    public static native boolean nativeDeviceBootloaderUnlocked(long handle);

    /** Attempt to gain root access. Returns true if now rooted. */
    public static native boolean nativeDeviceAttemptRoot(long handle);

    /** Get the primary AT port path (e.g. "/dev/ttyAMA0"). */
    public static native String nativeDeviceAtPrimary(long handle);

    // ── HiSilicon AT Backend ────────────────────────────────────────────────

    /** Open HiSilicon Balong AT command port. Returns native handle. */
    public static native long nativeHisiliconOpen(String devicePath);

    /** Close HiSilicon AT port. */
    public static native void nativeHisiliconClose(long handle);

    /** Check if the AT port is responsive. */
    public static native boolean nativeHisiliconIsAlive(long handle);

    /** Send raw AT command and get response. */
    public static native String nativeHisiliconAtSend(long handle, String cmd);

    /** Register on a network by MCC/MNC via HiSilicon AT. */
    public static native boolean nativeHisiliconRegisterNetwork(long handle, int mcc, int mnc);

    /** Get signal strength in dBm via HiSilicon AT. */
    public static native int nativeHisiliconGetSignal(long handle);

    /** Make a voice call via HiSilicon AT. */
    public static native boolean nativeHisiliconMakeCall(long handle, String number);

    /** End current call via HiSilicon AT. */
    public static native boolean nativeHisiliconEndCall(long handle);

    /** Send SMS via HiSilicon AT. */
    public static native boolean nativeHisiliconSendSms(long handle, String recipient, String text);

    /** Start RF test mode (continuous Tx) via HiSilicon AT. */
    public static native boolean nativeHisiliconRfTestStart(long handle, int arfcn, int powerDbm);

    /** Stop RF test mode via HiSilicon AT. */
    public static native boolean nativeHisiliconRfTestStop(long handle);

    /** Scan for networks via HiSilicon AT. Returns count. */
    public static native int nativeHisiliconNetworkScan(long handle);
}
