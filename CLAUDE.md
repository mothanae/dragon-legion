# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

| Command | What it does |
|---|---|
| `.\gradlew.bat assembleDebug` | Build debug APK (armeabi-v7a + arm64-v8a) |
| `.\gradlew.bat assembleRelease` | Build release APK |
| `.\gradlew.bat assembleDebug -Pabi=arm64-v8a` | Build for a single ABI |
| `.\scripts\build.ps1` | Build script wrapper (auto-detects SDK/NDK, finds APK path) |
| `.\scripts\build.ps1 -BuildType release` | Build release via script |
| `.\scripts\deploy.ps1` | Install APK to connected device via ADB |
| `.\scripts\deploy.ps1 -GrantPermissions` | Install + grant all required runtime permissions |
| `.\scripts\deploy.ps1 -UninstallFirst` | Clean install (uninstall then reinstall) |
| `.\scripts\adb_diag_setup.ps1` | Diagnostic script — checks device, SoC, root, DIAG port, SELinux |
| `adb shell am start -n com.celllink/.MainActivity` | Launch app on device |

**Prerequisites:** Android SDK, NDK (27.0.12077973), Java 17-21 (JDK 21 tested; Java 25+ incompatible with Gradle 8.7). Both `JAVA_HOME` and `ANDROID_HOME` must be set before building. The Gradle wrapper ships as 8.5 but AGP 8.4.0 requires 8.6+ — `gradle-wrapper.properties` has been updated to 8.7. Device must be rooted (Qualcomm/HiSilicon/MediaTek). Primary dev target: Huawei Mate 10 Pro (BLA-L29, Kirin 970).

## Architecture

### Two-Layer Design

The app is split into a **Kotlin UI/services layer** and a **native C baseband layer**, connected via JNI through `NativeBridge.java`.

**Kotlin layer** (`app/src/main/java/com/celllink/`):
- `MainActivity.kt` — Dual-mode UI: tower/client toggle, band selector, call controls. Uses `StateFlow` to observe service status.
- `BtsTowerService.kt` — Foreground service running the BTS tower (init → broadcast → poll state every 1s).
- `UeClientService.kt` — Foreground service running the UE client (scan → register → poll RSSI every 2s).
- `DiagManager.kt` — Singleton modem connection manager. `detectAndOpen()` auto-detects chipset, attempts root if needed, opens the correct backend (DIAG/QMI or HiSilicon AT), falls back to generic AT on failure.
- `RootChecker.kt` — Device/chipset detection, root verification, root-gain attempts via native exploits.
- `AudioRouter.kt` — Sets `MODE_IN_CALL`, manages speakerphone, Bluetooth SCO, audio focus for voice calls.
- `NativeBridge.java` — 70+ JNI native method declarations. All modem control goes through this class.

**Native C layer** (`app/src/main/cpp/`), compiled via CMake into `libcelllink_native.so`:

The 20 `.c`/`.h` files are organized by function:

| Category | Files | Purpose |
|---|---|---|
| Transport | `diag.c`, `qmi.c`, `crc16.c` | Qualcomm DIAG serial protocol (frame encode/decode, QMI messaging, NV read/write, AT commands, memory peek/poke) |
| GSM Protocol | `gsm_bts.c`, `gsm_ue.c`, `gsm_common.c` | BTS (broadcast SI messages, TDMA framing, RACH handling, call setup) and UE (network scan, registration, signal monitoring) |
| Device | `device_detect.c`, `hisilicon_at.c` | Auto-detect chipset (Qualcomm/HiSilicon/MTK/Samsung/Spreadtrum), enumerate modem ports, open correct backend |
| SIM/Auth | `virtual_sim.c`, `secure_boot.c` | Virtual SIM creation (IMSI/ICCID/Kc), live RAM patching to bypass SIM-auth and PLMN checks |
| RF | `rf_spectrum.c`, `band_scanner.c`, `pa_protect.c` | Spectrum scanning, channel quality, PA thermal/power protection |
| Audio/Call | `call_recorder.c`, `dtmf.c` | WAV call recording, DTMF generation |
| DSP | `hexagon_rpc.c` | Hexagon DSP FastRPC for L1 physical layer control |
| Timing | `gps_timing.c` | GPS-disciplined oscillator for TDMA synchronization |
| Monitoring | `gsm_sniffer.c`, `modem_logger.c`, `modem_recovery.c` | L3 protocol sniffer, structured modem logging, crash watchdog |
| Glue | `jni_bridge.c` | All JNI function implementations mapping Java `NativeBridge` to C modules |

### Multi-Backend Modem Access

The app supports four modem backends, selected by `device_detect.c` at runtime:

1. **DIAG/QMI** (Qualcomm) — `/dev/diag`, full QMI service access, preferred backend
2. **HiSilicon AT** — `/dev/ttyAMA0` on Kirin/Balong chipsets
3. **MediaTek AT** — MTK engineering mode AT port
4. **Generic AT** — Standard Hayes AT commands, fallback for unknown chipsets

`DiagManager.Backend` enum and `device_get_backend()` in the native layer select the backend. Each backend has its own open/close/send/scan/call functions in `NativeBridge.java`.

### Dual-Mode Operation

The app operates in one of two mutually exclusive modes:

**Tower Mode (BTS)** — `BtsTowerService`:
- State flow: `OFF → INIT → BROADCASTING → CONNECTED → IN_CALL` (ERROR from any state)
- Initializes BTS on a user-selected ARFCN/band, starts broadcasting GSM System Information messages
- Broadcasts as test network MCC=901 / MNC=01
- Accepts incoming UE connections and calls

**Client Mode (UE)** — `UeClientService`:
- State flow: `IDLE → SCANNING → CONNECTING → REGISTERED → CALLING → IN_CALL` (ERROR from any state)
- Scans for the CellLink tower (MCC 901 / MNC 01), registers, polls RSSI
- Call button appears once `REGISTERED`
- Both services are Android `LifecycleService` foreground services with ongoing notifications

### Key Design Decisions

- **Live memory patching over firmware flashing** (`secure_boot.c`): Instead of permanently modifying signed modem firmware (which would require bootloader unlock + NOP-ing signature checks), `secure_boot_bypass_all()` writes 4-byte ARM Thumb patches (`MOV R0, #1; BX LR`) directly to modem RAM via `diag_mem_write()`. These patches are volatile — reset on reboot, no brick risk. Targets: `mm_rr_authenticate_req`, `sim_present_check`, `plmn_allowed_check`, `imsi_attach_req`.

- **Virtual SIM** (`virtual_sim.c`): Creates a synthetic SIM identity (IMSI `901010000000001`, ICCID, MSISDN, Kc=all-zeros for no ciphering) and injects it via AT+CRSM or QMI UIM service so the modem believes a physical SIM is present.

- **Three-tier fail policy (intentional)**:
  - **Auth/SIM bypass**: FAIL-CLOSED — if patches can't be verified, the tower won't start (security-critical)
  - **Modem detection**: FAIL-OPEN with fallback — if DIAG fails, falls back to AT; if HiSilicon fails, falls back to generic AT
  - **Services**: FAIL-FAST — `BtsTowerService` and `UeClientService` stop themselves on error, transitioning to ERROR state with message

- **State management**: Both services expose Kotlin `StateFlow<Status>` data classes. `MainActivity` collects them in `lifecycleScope` to drive UI updates. The native side uses enums (e.g., `bts_state_t`, `ue_state_t`) with 1:1 Kotlin enum mapping via `fromCode()`.

- **Audio routing**: GSM narrowband (8 kHz, mono, 16-bit PCM). `AudioRouter` sets Android's `MODE_IN_CALL`, requests audio focus with `USAGE_VOICE_COMMUNICATION`, and manages Bluetooth SCO for the earpiece path. The modem handles actual audio transport over the GSM traffic channel.

- **GSM only** (no LTE/5G NR). Target bands: P-GSM-900, E-GSM-900, GSM-850, DCS-1800, PCS-1900. TDMA timing constants and L3 message structures are defined in `gsm_common.h`.


### Device Setup

The app requires root access to the modem diagnostic port (`/dev/ttyAMA0` on Kirin, `/dev/diag` on Qualcomm). Use standard bootloader unlock and Magisk rooting procedures for the target device.

### Environment

- **Java 17-21** (source/target compatibility `VERSION_17`, JVM target `17`; JDK 21 tested, Java 25+ unsupported)
- **Kotlin 1.9.23**, **AGP 8.4.0**, **NDK 27.0.12077973**, **CMake 3.22.1**
- **minSdk 26**, **targetSdk 34**, **compileSdk 34**
- **ABIs**: `arm64-v8a`, `armeabi-v7a` (Qualcomm/MTK/HiSilicon modems are ARM-only)
- **C++17** for native code with `c++_shared` STL, exceptions and RTTI enabled
- **Gradle JVM args** include `--enable-native-access=ALL-UNNAMED` for Java 17+ reflective access
