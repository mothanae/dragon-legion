"""CellLink Native Bridge — Python ctypes wrapper for libcelllink_native.so.

Connects Dragon Legion's Python modules to CellLink's native C baseband library.
Two modes:
  1. DIRECT — libcelllink_native.so is available locally (Linux worker on rooted device)
  2. ADB — library runs on Android device, controlled via ADB shell + app intents

The bridge wraps all 70+ JNI functions and exposes Pythonic classes:
  DiagSession, BtsTower, UeClient, VirtualSIM, SecureBootBypass,
  RFScanner, CallRecorder, DTMFGenerator, GSMSniffer, BandScanner,
  PAPowerProtection, ModemLogger, DeviceInfo, HisiliconModem
"""

import os
import ctypes
import struct
import time
import logging
import subprocess
import json
from ctypes import (
    c_char_p, c_int, c_bool, c_long, c_float, c_double, c_void_p,
    POINTER, byref, create_string_buffer, cdll, CDLL,
)
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Native library loading
# ---------------------------------------------------------------------------

NATIVE_LIB_NAME = "libcelllink_native.so"
_native_lib = None


def _load_native() -> Optional[ctypes.CDLL]:
    """Load the native library if available."""
    global _native_lib
    if _native_lib is not None:
        return _native_lib

    search_paths = [
        # APK extracted libs
        os.path.join(os.path.dirname(__file__), "..", "..", "app", "build", "intermediates", "cxx"),
        # System path
        f"/data/local/tmp/{NATIVE_LIB_NAME}",
        # LD_LIBRARY_PATH
        NATIVE_LIB_NAME,
    ]

    for path in search_paths:
        try:
            lib = CDLL(path)
            logger.info("Loaded native library from: %s", path)
            _native_lib = lib
            return lib
        except OSError:
            continue

    logger.debug("Native library not found locally (will use ADB fallback)")
    return None


def is_native_available() -> bool:
    return _load_native() is not None


# ---------------------------------------------------------------------------
# ctypes function signature mapping (all 70+ JNI functions)
# ---------------------------------------------------------------------------

def _setup_signatures(lib: ctypes.CDLL) -> None:
    """Configure ctypes function signatures for all native methods."""

    # DIAG Port
    lib.nativeDiagOpen.argtypes = [c_char_p]
    lib.nativeDiagOpen.restype = c_long
    lib.nativeDiagClose.argtypes = [c_long]
    lib.nativeDiagClose.restype = None
    lib.nativeDiagIsReady.argtypes = [c_long]
    lib.nativeDiagIsReady.restype = c_bool
    lib.nativeDiagAtCommand.argtypes = [c_long, c_char_p]
    lib.nativeDiagAtCommand.restype = c_char_p
    lib.nativeDiagEnterFtm.argtypes = [c_long]
    lib.nativeDiagEnterFtm.restype = c_bool

    # BTS Tower
    lib.nativeBtsInit.argtypes = [c_long, c_int, c_int, c_int]
    lib.nativeBtsInit.restype = c_long
    lib.nativeBtsStart.argtypes = [c_long]
    lib.nativeBtsStart.restype = c_bool
    lib.nativeBtsStop.argtypes = [c_long]
    lib.nativeBtsStop.restype = c_bool
    lib.nativeBtsFree.argtypes = [c_long]
    lib.nativeBtsFree.restype = None
    lib.nativeBtsGetState.argtypes = [c_long]
    lib.nativeBtsGetState.restype = c_int
    lib.nativeBtsGetDlFrequency.argtypes = [c_long]
    lib.nativeBtsGetDlFrequency.restype = c_float
    lib.nativeBtsAcceptCall.argtypes = [c_long]
    lib.nativeBtsAcceptCall.restype = c_bool
    lib.nativeBtsEndCall.argtypes = [c_long]
    lib.nativeBtsEndCall.restype = c_bool

    # UE Client
    lib.nativeUeInit.argtypes = [c_long]
    lib.nativeUeInit.restype = c_long
    lib.nativeUeScanNetworks.argtypes = [c_long]
    lib.nativeUeScanNetworks.restype = c_int
    lib.nativeUeRegisterNetwork.argtypes = [c_long, c_int, c_int]
    lib.nativeUeRegisterNetwork.restype = c_bool
    lib.nativeUeMakeCall.argtypes = [c_long]
    lib.nativeUeMakeCall.restype = c_bool
    lib.nativeUeEndCall.argtypes = [c_long]
    lib.nativeUeEndCall.restype = c_bool
    lib.nativeUeAnswerCall.argtypes = [c_long]
    lib.nativeUeAnswerCall.restype = c_bool
    lib.nativeUeGetState.argtypes = [c_long]
    lib.nativeUeGetState.restype = c_int
    lib.nativeUeGetRssi.argtypes = [c_long]
    lib.nativeUeGetRssi.restype = c_int
    lib.nativeUeGetScanResults.argtypes = [c_long]
    lib.nativeUeGetScanResults.restype = c_char_p
    lib.nativeUeFree.argtypes = [c_long]
    lib.nativeUeFree.restype = None

    # SMS
    lib.nativeSmsSend.argtypes = [c_long, c_char_p, c_char_p]
    lib.nativeSmsSend.restype = c_bool

    # GPS Timing
    lib.nativeGpsTimingInit.argtypes = []
    lib.nativeGpsTimingInit.restype = c_long
    lib.nativeGpsTimingFree.argtypes = [c_long]
    lib.nativeGpsTimingFree.restype = None
    lib.nativeGpsFeedNmea.argtypes = [c_long, c_char_p]
    lib.nativeGpsFeedNmea.restype = None
    lib.nativeGpsGetState.argtypes = [c_long]
    lib.nativeGpsGetState.restype = c_int
    lib.nativeGpsStatusString.argtypes = [c_long]
    lib.nativeGpsStatusString.restype = c_char_p
    lib.nativeGpsFreqError.argtypes = [c_long]
    lib.nativeGpsFreqError.restype = c_double

    # Hexagon DSP
    lib.nativeHexagonOpen.argtypes = [c_char_p]
    lib.nativeHexagonOpen.restype = c_long
    lib.nativeHexagonClose.argtypes = [c_long]
    lib.nativeHexagonClose.restype = None
    lib.nativeHexagonEnableAudio.argtypes = [c_long]
    lib.nativeHexagonEnableAudio.restype = c_bool

    # Secure Boot
    lib.nativeSecureBootBypass.argtypes = [c_long]
    lib.nativeSecureBootBypass.restype = c_int

    # RF Spectrum
    lib.nativeSpectrumInit.argtypes = []
    lib.nativeSpectrumInit.restype = c_long
    lib.nativeSpectrumFree.argtypes = [c_long]
    lib.nativeSpectrumFree.restype = None
    lib.nativeSpectrumSweepAll.argtypes = [c_long, c_long]
    lib.nativeSpectrumSweepAll.restype = c_int
    lib.nativeSpectrumFindBest.argtypes = [c_long, c_int]
    lib.nativeSpectrumFindBest.restype = c_int
    lib.nativeSpectrumExportCsv.argtypes = [c_long]
    lib.nativeSpectrumExportCsv.restype = c_char_p

    # Virtual SIM
    lib.nativeVsimCreate.argtypes = [c_int, c_int, c_char_p, c_char_p, c_char_p]
    lib.nativeVsimCreate.restype = c_long
    lib.nativeVsimFree.argtypes = [c_long]
    lib.nativeVsimFree.restype = None
    lib.nativeVsimActivate.argtypes = [c_long, c_long]
    lib.nativeVsimActivate.restype = c_bool

    # Modem Recovery
    lib.nativeModemRecoveryInit.argtypes = [c_long]
    lib.nativeModemRecoveryInit.restype = c_long
    lib.nativeModemRecoveryFree.argtypes = [c_long]
    lib.nativeModemRecoveryFree.restype = None
    lib.nativeModemIsAlive.argtypes = [c_long]
    lib.nativeModemIsAlive.restype = c_bool
    lib.nativeModemRecover.argtypes = [c_long]
    lib.nativeModemRecover.restype = c_int
    lib.nativeModemCrashInfo.argtypes = [c_long]
    lib.nativeModemCrashInfo.restype = c_char_p

    # Call Recorder
    lib.nativeCallRecorderCreate.argtypes = [c_char_p]
    lib.nativeCallRecorderCreate.restype = c_long
    lib.nativeCallRecorderFree.argtypes = [c_long]
    lib.nativeCallRecorderFree.restype = None
    lib.nativeCallRecorderStart.argtypes = [c_long]
    lib.nativeCallRecorderStart.restype = c_bool
    lib.nativeCallRecorderStop.argtypes = [c_long]
    lib.nativeCallRecorderStop.restype = c_bool
    lib.nativeCallRecorderGetDuration.argtypes = [c_long]
    lib.nativeCallRecorderGetDuration.restype = c_double

    # DTMF
    lib.nativeDtmfSend.argtypes = [c_long, c_char]
    lib.nativeDtmfSend.restype = c_bool
    lib.nativeDtmfSendString.argtypes = [c_long, c_char_p]
    lib.nativeDtmfSendString.restype = c_bool

    # GSM Sniffer
    lib.nativeSnifferCreate.argtypes = [c_char_p]
    lib.nativeSnifferCreate.restype = c_long
    lib.nativeSnifferFree.argtypes = [c_long]
    lib.nativeSnifferFree.restype = None
    lib.nativeSnifferStart.argtypes = [c_long]
    lib.nativeSnifferStart.restype = c_bool
    lib.nativeSnifferStop.argtypes = [c_long]
    lib.nativeSnifferStop.restype = c_bool

    # Band Scanner
    lib.nativeBandScanCreate.argtypes = []
    lib.nativeBandScanCreate.restype = c_long
    lib.nativeBandScanFree.argtypes = [c_long]
    lib.nativeBandScanFree.restype = None
    lib.nativeBandScanFull.argtypes = [c_long, c_long]
    lib.nativeBandScanFull.restype = c_int
    lib.nativeBandScanExportCsv.argtypes = [c_long]
    lib.nativeBandScanExportCsv.restype = c_char_p

    # PA Protection
    lib.nativePaProtectInit.argtypes = []
    lib.nativePaProtectInit.restype = c_long
    lib.nativePaProtectFree.argtypes = [c_long]
    lib.nativePaProtectFree.restype = None
    lib.nativePaProtectTxStart.argtypes = [c_long, c_int, c_int]
    lib.nativePaProtectTxStart.restype = c_bool
    lib.nativePaProtectTxStop.argtypes = [c_long]
    lib.nativePaProtectTxStop.restype = c_bool
    lib.nativePaProtectUpdate.argtypes = [c_long, c_float, c_float, c_float]
    lib.nativePaProtectUpdate.restype = c_bool
    lib.nativePaProtectState.argtypes = [c_long]
    lib.nativePaProtectState.restype = c_char_p

    # Modem Logger
    lib.nativeModemLoggerCreate.argtypes = [c_char_p]
    lib.nativeModemLoggerCreate.restype = c_long
    lib.nativeModemLoggerFree.argtypes = [c_long]
    lib.nativeModemLoggerFree.restype = None
    lib.nativeModemLoggerStart.argtypes = [c_long]
    lib.nativeModemLoggerStart.restype = c_bool
    lib.nativeModemLoggerStop.argtypes = [c_long]
    lib.nativeModemLoggerStop.restype = c_bool
    lib.nativeModemLoggerExport.argtypes = [c_long, c_int]
    lib.nativeModemLoggerExport.restype = c_char_p

    # Device Detection
    lib.nativeDeviceDetect.argtypes = []
    lib.nativeDeviceDetect.restype = c_long
    lib.nativeDeviceFree.argtypes = [c_long]
    lib.nativeDeviceFree.restype = None
    lib.nativeDeviceGetChipset.argtypes = [c_long]
    lib.nativeDeviceGetChipset.restype = c_char_p
    lib.nativeDeviceGetModem.argtypes = [c_long]
    lib.nativeDeviceGetModem.restype = c_char_p
    lib.nativeDeviceIsRooted.argtypes = [c_long]
    lib.nativeDeviceIsRooted.restype = c_bool
    lib.nativeDeviceGetBackend.argtypes = [c_long]
    lib.nativeDeviceGetBackend.restype = c_int
    lib.nativeDeviceSelinuxEnforcing.argtypes = [c_long]
    lib.nativeDeviceSelinuxEnforcing.restype = c_bool
    lib.nativeDeviceBootloaderUnlocked.argtypes = [c_long]
    lib.nativeDeviceBootloaderUnlocked.restype = c_bool
    lib.nativeDeviceAttemptRoot.argtypes = [c_long]
    lib.nativeDeviceAttemptRoot.restype = c_bool
    lib.nativeDeviceAtPrimary.argtypes = [c_long]
    lib.nativeDeviceAtPrimary.restype = c_char_p

    # HiSilicon AT Backend
    lib.nativeHisiliconOpen.argtypes = [c_char_p]
    lib.nativeHisiliconOpen.restype = c_long
    lib.nativeHisiliconClose.argtypes = [c_long]
    lib.nativeHisiliconClose.restype = None
    lib.nativeHisiliconIsAlive.argtypes = [c_long]
    lib.nativeHisiliconIsAlive.restype = c_bool
    lib.nativeHisiliconAtSend.argtypes = [c_long, c_char_p]
    lib.nativeHisiliconAtSend.restype = c_char_p
    lib.nativeHisiliconRegisterNetwork.argtypes = [c_long, c_int, c_int]
    lib.nativeHisiliconRegisterNetwork.restype = c_bool
    lib.nativeHisiliconGetSignal.argtypes = [c_long]
    lib.nativeHisiliconGetSignal.restype = c_int
    lib.nativeHisiliconMakeCall.argtypes = [c_long, c_char_p]
    lib.nativeHisiliconMakeCall.restype = c_bool
    lib.nativeHisiliconEndCall.argtypes = [c_long]
    lib.nativeHisiliconEndCall.restype = c_bool
    lib.nativeHisiliconSendSms.argtypes = [c_long, c_char_p, c_char_p]
    lib.nativeHisiliconSendSms.restype = c_bool
    lib.nativeHisiliconRfTestStart.argtypes = [c_long, c_int, c_int]
    lib.nativeHisiliconRfTestStart.restype = c_bool
    lib.nativeHisiliconRfTestStop.argtypes = [c_long]
    lib.nativeHisiliconRfTestStop.restype = c_bool
    lib.nativeHisiliconNetworkScan.argtypes = [c_long]
    lib.nativeHisiliconNetworkScan.restype = c_int


# ---------------------------------------------------------------------------
# Pythonic Wrapper Classes
# ---------------------------------------------------------------------------

class NativeHandle:
    """Base class for native handle wrappers with automatic cleanup."""

    def __init__(self, handle: int = 0):
        self._handle = handle

    @property
    def handle(self) -> int:
        if self._handle == 0:
            raise RuntimeError(f"{type(self).__name__}: native handle is closed")
        return self._handle

    @property
    def is_valid(self) -> bool:
        return self._handle != 0


class DiagSession(NativeHandle):
    """Qualcomm DIAG diagnostic port session."""

    def __init__(self, device_path: str = "/dev/diag"):
        lib = _load_native()
        if lib:
            _setup_signatures(lib)
            handle = lib.nativeDiagOpen(device_path.encode())
            super().__init__(handle)
        else:
            super().__init__(0)
        self._path = device_path

    def close(self) -> None:
        if self._handle:
            lib = _load_native()
            if lib:
                lib.nativeDiagClose(self._handle)
            self._handle = 0

    def is_ready(self) -> bool:
        lib = _load_native()
        if lib:
            return lib.nativeDiagIsReady(self._handle)
        return False

    def at_command(self, cmd: str) -> str:
        lib = _load_native()
        if lib:
            result = lib.nativeDiagAtCommand(self._handle, cmd.encode())
            return result.decode() if result else ""
        return ""

    def enter_ftm(self) -> bool:
        lib = _load_native()
        if lib:
            return lib.nativeDiagEnterFtm(self._handle)
        return False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class BtsTower(NativeHandle):
    """GSM Base Transceiver Station (Tower Mode)."""

    BTS_STATES = {0: "OFF", 1: "INIT", 2: "BROADCASTING", 3: "CONNECTED", 4: "IN_CALL", 5: "ERROR"}

    def __init__(self, diag: DiagSession, arfcn: int, band: int, tx_power: int = 30):
        lib = _load_native()
        if lib:
            _setup_signatures(lib)
            handle = lib.nativeBtsInit(diag.handle, arfcn, band, tx_power)
            super().__init__(handle)
        else:
            super().__init__(0)

    def start(self) -> bool:
        lib = _load_native()
        return lib.nativeBtsStart(self._handle) if lib else False

    def stop(self) -> bool:
        lib = _load_native()
        return lib.nativeBtsStop(self._handle) if lib else False

    def close(self) -> None:
        if self._handle:
            lib = _load_native()
            if lib:
                lib.nativeBtsFree(self._handle)
            self._handle = 0

    @property
    def state(self) -> str:
        lib = _load_native()
        if lib:
            return self.BTS_STATES.get(lib.nativeBtsGetState(self._handle), "UNKNOWN")
        return "NATIVE_NOT_LOADED"

    @property
    def dl_frequency(self) -> float:
        lib = _load_native()
        return lib.nativeBtsGetDlFrequency(self._handle) if lib else 0.0

    def accept_call(self) -> bool:
        lib = _load_native()
        return lib.nativeBtsAcceptCall(self._handle) if lib else False

    def end_call(self) -> bool:
        lib = _load_native()
        return lib.nativeBtsEndCall(self._handle) if lib else False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class UeClient(NativeHandle):
    """GSM User Equipment (Client Mode)."""

    UE_STATES = {0: "IDLE", 1: "SCANNING", 2: "CONNECTING", 3: "REGISTERED", 4: "CALLING", 5: "IN_CALL", 6: "ERROR"}

    def __init__(self, diag: DiagSession):
        lib = _load_native()
        if lib:
            _setup_signatures(lib)
            handle = lib.nativeUeInit(diag.handle)
            super().__init__(handle)
        else:
            super().__init__(0)

    def scan_networks(self) -> int:
        lib = _load_native()
        return lib.nativeUeScanNetworks(self._handle) if lib else 0

    def register(self, mcc: int, mnc: int) -> bool:
        lib = _load_native()
        return lib.nativeUeRegisterNetwork(self._handle, mcc, mnc) if lib else False

    def make_call(self) -> bool:
        lib = _load_native()
        return lib.nativeUeMakeCall(self._handle) if lib else False

    def end_call(self) -> bool:
        lib = _load_native()
        return lib.nativeUeEndCall(self._handle) if lib else False

    def answer_call(self) -> bool:
        lib = _load_native()
        return lib.nativeUeAnswerCall(self._handle) if lib else False

    @property
    def state(self) -> str:
        lib = _load_native()
        if lib:
            return self.UE_STATES.get(lib.nativeUeGetState(self._handle), "UNKNOWN")
        return "NATIVE_NOT_LOADED"

    @property
    def rssi(self) -> int:
        lib = _load_native()
        return lib.nativeUeGetRssi(self._handle) if lib else -200

    @property
    def scan_results(self) -> str:
        lib = _load_native()
        if lib:
            result = lib.nativeUeGetScanResults(self._handle)
            return result.decode() if result else ""
        return ""

    def close(self) -> None:
        if self._handle:
            lib = _load_native()
            if lib:
                lib.nativeUeFree(self._handle)
            self._handle = 0

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class VirtualSIM(NativeHandle):
    """Virtual SIM card emulation."""

    def __init__(self, mcc: int = 901, mnc: int = 1,
                 imsi: str = "901010000000001", msisdn: str = "1234567890",
                 spn: str = "CellLink"):
        lib = _load_native()
        if lib:
            _setup_signatures(lib)
            handle = lib.nativeVsimCreate(mcc, mnc, imsi.encode(), msisdn.encode(), spn.encode())
            super().__init__(handle)
        else:
            super().__init__(0)

    def activate(self, diag: DiagSession) -> bool:
        lib = _load_native()
        return lib.nativeVsimActivate(self._handle, diag.handle) if lib else False

    def close(self) -> None:
        if self._handle:
            lib = _load_native()
            if lib:
                lib.nativeVsimFree(self._handle)
            self._handle = 0


class SecureBootBypass:
    """Secure boot bypass via live modem RAM patching."""

    @staticmethod
    def bypass(diag: DiagSession) -> int:
        """Apply all SIM/auth/PLMN bypass patches to modem RAM."""
        lib = _load_native()
        return lib.nativeSecureBootBypass(diag.handle) if lib else 0


class RFScanner(NativeHandle):
    """RF Spectrum analyzer for finding clear GSM channels."""

    def __init__(self):
        lib = _load_native()
        if lib:
            _setup_signatures(lib)
            handle = lib.nativeSpectrumInit()
            super().__init__(handle)
        else:
            super().__init__(0)

    def sweep_all(self, diag: DiagSession) -> int:
        lib = _load_native()
        return lib.nativeSpectrumSweepAll(diag.handle, self._handle) if lib else 0

    def find_best_channel(self, preferred_band: int = 0) -> int:
        lib = _load_native()
        return lib.nativeSpectrumFindBest(self._handle, preferred_band) if lib else 1

    def export_csv(self) -> str:
        lib = _load_native()
        if lib:
            result = lib.nativeSpectrumExportCsv(self._handle)
            return result.decode() if result else ""
        return ""

    def close(self) -> None:
        if self._handle:
            lib = _load_native()
            if lib:
                lib.nativeSpectrumFree(self._handle)
            self._handle = 0


class CallRecorder(NativeHandle):
    """WAV call audio recorder."""

    def __init__(self, filename: str = "call_recording.wav"):
        lib = _load_native()
        if lib:
            _setup_signatures(lib)
            handle = lib.nativeCallRecorderCreate(filename.encode())
            super().__init__(handle)
        else:
            super().__init__(0)

    def start(self) -> bool:
        lib = _load_native()
        return lib.nativeCallRecorderStart(self._handle) if lib else False

    def stop(self) -> bool:
        lib = _load_native()
        return lib.nativeCallRecorderStop(self._handle) if lib else False

    @property
    def duration_seconds(self) -> float:
        lib = _load_native()
        return lib.nativeCallRecorderGetDuration(self._handle) if lib else 0.0

    def close(self) -> None:
        if self._handle:
            lib = _load_native()
            if lib:
                lib.nativeCallRecorderFree(self._handle)
            self._handle = 0


class GSMSniffer(NativeHandle):
    """GSM L3 protocol sniffer."""

    def __init__(self, filename: str = "gsm_sniff.csv"):
        lib = _load_native()
        if lib:
            _setup_signatures(lib)
            handle = lib.nativeSnifferCreate(filename.encode())
            super().__init__(handle)
        else:
            super().__init__(0)

    def start(self) -> bool:
        lib = _load_native()
        return lib.nativeSnifferStart(self._handle) if lib else False

    def stop(self) -> bool:
        lib = _load_native()
        return lib.nativeSnifferStop(self._handle) if lib else False

    def close(self) -> None:
        if self._handle:
            lib = _load_native()
            if lib:
                lib.nativeSnifferFree(self._handle)
            self._handle = 0


class BandScanner(NativeHandle):
    """GSM band scanner for cell tower discovery."""

    def __init__(self):
        lib = _load_native()
        if lib:
            _setup_signatures(lib)
            handle = lib.nativeBandScanCreate()
            super().__init__(handle)
        else:
            super().__init__(0)

    def scan_full(self, diag: DiagSession) -> int:
        lib = _load_native()
        return lib.nativeBandScanFull(diag.handle, self._handle) if lib else 0

    def export_csv(self) -> str:
        lib = _load_native()
        if lib:
            result = lib.nativeBandScanExportCsv(self._handle)
            return result.decode() if result else ""
        return ""

    def close(self) -> None:
        if self._handle:
            lib = _load_native()
            if lib:
                lib.nativeBandScanFree(self._handle)
            self._handle = 0


class PAPowerProtection(NativeHandle):
    """Power amplifier thermal/power protection."""

    def __init__(self):
        lib = _load_native()
        if lib:
            _setup_signatures(lib)
            handle = lib.nativePaProtectInit()
            super().__init__(handle)
        else:
            super().__init__(0)

    def tx_start(self, power_dbm: int, arfcn: int) -> bool:
        lib = _load_native()
        return lib.nativePaProtectTxStart(self._handle, power_dbm, arfcn) if lib else False

    def tx_stop(self) -> bool:
        lib = _load_native()
        return lib.nativePaProtectTxStop(self._handle) if lib else False

    def update(self, temp_c: float, fwd_power: float, rev_power: float) -> bool:
        lib = _load_native()
        return lib.nativePaProtectUpdate(self._handle, temp_c, fwd_power, rev_power) if lib else False

    @property
    def state(self) -> str:
        lib = _load_native()
        if lib:
            result = lib.nativePaProtectState(self._handle)
            return result.decode() if result else ""
        return ""

    def close(self) -> None:
        if self._handle:
            lib = _load_native()
            if lib:
                lib.nativePaProtectFree(self._handle)
            self._handle = 0


class DeviceInfo(NativeHandle):
    """Device chipset, modem, and capability detection."""

    def __init__(self):
        lib = _load_native()
        if lib:
            _setup_signatures(lib)
            handle = lib.nativeDeviceDetect()
            super().__init__(handle)
        else:
            super().__init__(0)

    @property
    def chipset(self) -> str:
        lib = _load_native()
        if lib:
            result = lib.nativeDeviceGetChipset(self._handle)
            return result.decode() if result else ""
        return ""

    @property
    def modem(self) -> str:
        lib = _load_native()
        if lib:
            result = lib.nativeDeviceGetModem(self._handle)
            return result.decode() if result else ""
        return ""

    @property
    def is_rooted(self) -> bool:
        lib = _load_native()
        return lib.nativeDeviceIsRooted(self._handle) if lib else False

    @property
    def backend(self) -> int:
        lib = _load_native()
        return lib.nativeDeviceGetBackend(self._handle) if lib else -1

    @property
    def selinux_enforcing(self) -> bool:
        lib = _load_native()
        return lib.nativeDeviceSelinuxEnforcing(self._handle) if lib else False

    @property
    def bootloader_unlocked(self) -> bool:
        lib = _load_native()
        return lib.nativeDeviceBootloaderUnlocked(self._handle) if lib else False

    @property
    def at_primary_port(self) -> str:
        lib = _load_native()
        if lib:
            result = lib.nativeDeviceAtPrimary(self._handle)
            return result.decode() if result else ""
        return ""

    def attempt_root(self) -> bool:
        lib = _load_native()
        return lib.nativeDeviceAttemptRoot(self._handle) if lib else False

    @property
    def backend_name(self) -> str:
        names = {0: "DIAG/QMI", 1: "HiSilicon AT", 2: "MTK AT", 3: "Generic AT", 4: "RIL"}
        return names.get(self.backend, "UNKNOWN")

    def close(self) -> None:
        if self._handle:
            lib = _load_native()
            if lib:
                lib.nativeDeviceFree(self._handle)
            self._handle = 0


class HisiliconModem(NativeHandle):
    """HiSilicon Balong AT command modem."""

    def __init__(self, device_path: str = "/dev/ttyAMA0"):
        lib = _load_native()
        if lib:
            _setup_signatures(lib)
            handle = lib.nativeHisiliconOpen(device_path.encode())
            super().__init__(handle)
        else:
            super().__init__(0)

    def is_alive(self) -> bool:
        lib = _load_native()
        return lib.nativeHisiliconIsAlive(self._handle) if lib else False

    def at_send(self, cmd: str) -> str:
        lib = _load_native()
        if lib:
            result = lib.nativeHisiliconAtSend(self._handle, cmd.encode())
            return result.decode() if result else ""
        return ""

    def register_network(self, mcc: int, mnc: int) -> bool:
        lib = _load_native()
        return lib.nativeHisiliconRegisterNetwork(self._handle, mcc, mnc) if lib else False

    def get_signal(self) -> int:
        lib = _load_native()
        return lib.nativeHisiliconGetSignal(self._handle) if lib else -200

    def make_call(self, number: str) -> bool:
        lib = _load_native()
        return lib.nativeHisiliconMakeCall(self._handle, number.encode()) if lib else False

    def end_call(self) -> bool:
        lib = _load_native()
        return lib.nativeHisiliconEndCall(self._handle) if lib else False

    def send_sms(self, recipient: str, text: str) -> bool:
        lib = _load_native()
        return lib.nativeHisiliconSendSms(self._handle, recipient.encode(), text.encode()) if lib else False

    def rf_test_start(self, arfcn: int, power_dbm: int) -> bool:
        lib = _load_native()
        return lib.nativeHisiliconRfTestStart(self._handle, arfcn, power_dbm) if lib else False

    def rf_test_stop(self) -> bool:
        lib = _load_native()
        return lib.nativeHisiliconRfTestStop(self._handle) if lib else False

    def network_scan(self) -> int:
        lib = _load_native()
        return lib.nativeHisiliconNetworkScan(self._handle) if lib else 0

    def close(self) -> None:
        if self._handle:
            lib = _load_native()
            if lib:
                lib.nativeHisiliconClose(self._handle)
            self._handle = 0

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


# ---------------------------------------------------------------------------
# ADB Fallback Bridge (for when native lib is on-device, not local)
# ---------------------------------------------------------------------------

class ADBBridge:
    """Bridge to CellLink Android app via ADB.

    When libcelllink_native.so is not available locally (running on a Linux
    worker separate from the Android device), this bridge communicates
    with the CellLink app via ADB shell commands and broadcast intents.
    """

    @staticmethod
    def _adb(cmd: str, timeout: int = 10) -> tuple[int, str, str]:
        """Run ADB command. Returns (returncode, stdout, stderr)."""
        try:
            result = subprocess.run(
                ["adb"] + cmd.split(),
                capture_output=True, text=True, timeout=timeout,
            )
            return result.returncode, result.stdout, result.stderr
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            return -1, "", str(e)

    @classmethod
    def is_device_connected(cls) -> bool:
        rc, stdout, _ = cls._adb("devices")
        return "device" in stdout

    @classmethod
    def is_root_available(cls) -> bool:
        rc, stdout, _ = cls._adb("shell su -c 'id -u'")
        return "0" in stdout

    @classmethod
    def get_device_props(cls) -> dict:
        """Read Android system properties."""
        props = {}
        for prop in [
            "ro.product.manufacturer", "ro.product.model",
            "ro.board.platform", "ro.hardware",
            "ro.build.version.sdk", "ro.build.version.release",
            "ro.bootimage.build.fingerprint",
        ]:
            rc, stdout, _ = cls._adb(f"shell getprop {prop}")
            if rc == 0 and stdout.strip():
                props[prop.split(".")[-1]] = stdout.strip()
        return props

    @classmethod
    def check_diag_port(cls) -> list[str]:
        """Check for diag device files on the Android device."""
        ports = []
        for dev in ["/dev/diag", "/dev/ttyUSB0", "/dev/ttyUSB1", "/dev/ttyUSB2",
                     "/dev/ttyACM0", "/dev/ttyAMA0", "/dev/smd0", "/dev/smd7", "/dev/smd11"]:
            rc, _, _ = cls._adb(f"shell su -c 'test -e {dev} && echo EXISTS || echo MISSING'")
            if rc == 0:
                ports.append(dev)
        return ports

    @classmethod
    def start_bts_service(cls, arfcn: int = 1, band: int = 0, tx_power: int = 30) -> bool:
        """Start BTS tower service on the device via am start command."""
        cmd = (
            f"shell am start-foreground-service "
            f"-a com.celllink.action.START_BTS "
            f"--ei arfcn {arfcn} --ei band {band} --ei tx_power {tx_power} "
            f"com.celllink/.BtsTowerService"
        )
        rc, _, _ = cls._adb(cmd)
        return rc == 0

    @classmethod
    def start_ue_service(cls) -> bool:
        """Start UE client service on the device."""
        cmd = (
            f"shell am start-foreground-service "
            f"-a com.celllink.action.START_UE "
            f"com.celllink/.UeClientService"
        )
        rc, _, _ = cls._adb(cmd)
        return rc == 0

    @classmethod
    def stop_service(cls, service_name: str = "BtsTowerService") -> bool:
        cmd = (
            f"shell am stopservice com.celllink/.{service_name}"
        )
        rc, _, _ = cls._adb(cmd)
        return rc == 0

    @classmethod
    def push_native_lib(cls, local_path: str, remote_path: str = "/data/local/tmp/libcelllink_native.so") -> bool:
        """Push native library to device for direct loading."""
        rc, _, _ = cls._adb(f"push {local_path} {remote_path}")
        return rc == 0

    @classmethod
    def run_shell_root(cls, cmd: str) -> tuple[int, str, str]:
        """Run a shell command as root on the device."""
        return cls._adb(f"shell su -c '{cmd}'")


# ---------------------------------------------------------------------------
# High-Level Orchestration
# ---------------------------------------------------------------------------

class CellLinkOrchestrator:
    """High-level orchestrator that selects DIRECT or ADB mode automatically.

    Usage:
        orch = CellLinkOrchestrator()
        orch.connect()

        # Start a rogue GSM tower
        tower = orch.start_tower(arfcn=10, band=0, tx_power=33)

        # Run secure boot bypass
        bypass_count = orch.bypass_sim_auth()

        # Scan RF spectrum for clearest channel
        scanner = orch.scan_spectrum()
        best_channel = scanner.find_best_channel()
    """

    def __init__(self):
        self._mode = "direct" if is_native_available() else "adb"
        self._diag: Optional[DiagSession] = None
        self._device: Optional[DeviceInfo] = None

    @property
    def mode(self) -> str:
        return self._mode

    def connect(self) -> bool:
        """Establish connection to the device's modem."""
        if self._mode == "direct":
            self._device = DeviceInfo()
            if not self._device.is_valid:
                logger.warning("Device detection returned null handle")
                return False

            logger.info("Device: %s / %s (rooted=%s, backend=%s)",
                        self._device.chipset, self._device.modem,
                        self._device.is_rooted, self._device.backend_name)

            # Open DIAG port
            port = "/dev/diag"
            if self._device.backend == 1:
                port = self._device.at_primary_port or "/dev/ttyAMA0"

            self._diag = DiagSession(port)
            if not self._diag.is_ready():
                logger.warning("DIAG port not ready on %s", port)
                return False

            logger.info("DIAG port opened: %s", port)
            return True

        elif self._mode == "adb":
            if not ADBBridge.is_device_connected():
                logger.error("No ADB device connected")
                return False
            logger.info("ADB device connected")
            return True

        return False

    def disconnect(self) -> None:
        if self._diag:
            self._diag.close()
            self._diag = None
        if self._device:
            self._device.close()
            self._device = None

    def get_device_info(self) -> dict:
        """Get device information (chipset, modem, root status, capabilities)."""
        if self._mode == "direct" and self._device:
            return {
                "chipset": self._device.chipset,
                "modem": self._device.modem,
                "is_rooted": self._device.is_rooted,
                "backend": self._device.backend_name,
                "selinux_enforcing": self._device.selinux_enforcing,
                "bootloader_unlocked": self._device.bootloader_unlocked,
                "at_port": self._device.at_primary_port,
            }
        elif self._mode == "adb":
            props = ADBBridge.get_device_props()
            return {
                "chipset": props.get("platform", "unknown"),
                "modem": props.get("hardware", "unknown"),
                "is_rooted": ADBBridge.is_root_available(),
                "backend": "ADB Bridge",
                "selinux_enforcing": None,
                "bootloader_unlocked": None,
                "at_port": None,
            }
        return {}

    def start_tower(self, arfcn: int = 10, band: int = 0,
                    tx_power: int = 33) -> Optional[BtsTower]:
        """Start a rogue GSM BTS tower (MCC=901, MNC=01)."""
        if self._mode == "direct" and self._diag:
            # Bypass SIM auth first
            SecureBootBypass.bypass(self._diag)

            # Find clearest channel if ARFCN not specified
            if arfcn <= 0:
                scanner = RFScanner()
                scanner.sweep_all(self._diag)
                arfcn = scanner.find_best_channel(band)
                scanner.close()

            # Activate virtual SIM
            vsim = VirtualSIM(mcc=901, mnc=1)
            vsim.activate(self._diag)

            # Start tower
            tower = BtsTower(self._diag, arfcn, band, tx_power)
            tower.start()
            logger.info("Tower started: ARFCN=%d, Band=%d, State=%s", arfcn, band, tower.state)
            return tower

        elif self._mode == "adb":
            ADBBridge.start_bts_service(arfcn, band, tx_power)
            logger.info("Tower started via ADB: ARFCN=%d", arfcn)
            return None

        return None

    def scan_networks(self) -> list[dict]:
        """Scan for visible GSM networks (UE client mode)."""
        if self._mode == "direct" and self._diag:
            ue = UeClient(self._diag)
            count = ue.scan_networks()
            results = ue.scan_results
            ue.close()
            return self._parse_scan_results(results, count)
        return []

    def bypass_sim_auth(self) -> int:
        """Apply live RAM patches to bypass SIM authentication."""
        if self._mode == "direct" and self._diag:
            return SecureBootBypass.bypass(self._diag)
        return 0

    def scan_rf_spectrum(self) -> Optional[RFScanner]:
        """Scan RF spectrum for clearest channel."""
        if self._mode == "direct" and self._diag:
            scanner = RFScanner()
            scanner.sweep_all(self._diag)
            return scanner
        return None

    def start_call_recorder(self, filename: str = "call.wav") -> Optional[CallRecorder]:
        """Start recording a voice call."""
        if self._mode == "direct":
            recorder = CallRecorder(filename)
            recorder.start()
            return recorder
        return None

    def start_gsm_sniffer(self, filename: str = "gsm_sniff.csv") -> Optional[GSMSniffer]:
        """Start GSM L3 protocol sniffer."""
        if self._mode == "direct":
            sniffer = GSMSniffer(filename)
            sniffer.start()
            return sniffer
        return None

    @staticmethod
    def _parse_scan_results(raw: str, count: int) -> list[dict]:
        """Parse network scan results string into structured data."""
        results = []
        for line in raw.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.split(",")
            if len(parts) >= 3:
                results.append({
                    "operator": parts[0].strip(),
                    "mcc_mnc": parts[1].strip(),
                    "arfcn": parts[2].strip(),
                    "rssi": parts[3].strip() if len(parts) > 3 else "",
                })
        return results
