#ifndef CELLLINK_SECURE_BOOT_H
#define CELLLINK_SECURE_BOOT_H

#include "diag.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Secure Boot Bypass Methodology ────────────────────────────────────
 *
 * QUALCOMM:
 *   Verified Boot chain: PBL -> SBL1 -> TZ -> ABL -> boot.img
 *   The modem firmware (modem.img) is signed with SHA-256 + RSA-2048.
 *   The bootloader checks the signature before loading.
 *
 *   Known attack surfaces:
 *   1. CVE-2020-3696 — Heap overflow in the Qualcomm WLAN firmware download
 *      handler (SBL1). Allows arbitrary code execution in SBL1 context
 *      before signature verification begins. Triggered via EDL download mode.
 *      Used to disable sig checks on modem partition.
 *
 *   2. CVE-2020-0022 — BleedingTooth: Heap-based buffer overflow in the
 *      Bluetooth firmware download handler. If BT is unavailable on this
 *      device, use the WLAN equivalent CVE-2020-3696 instead.
 *
 *   3. CVE-2019-10581 — Use-after-free in Qualcomm DSP kernel driver
 *      (adsprpc). Allows Hexagon DSP code execution, which can then
 *      reconfigure the modem L1 without firmware patching.
 *
 *   4. CVE-2017-15846 — Out-of-bounds write in Qualcomm camera driver.
 *      Kernel privilege escalation to disable SELinux enforcing on /dev/diag.
 *
 *   5. Emergency Download Mode (EDL) — Qualcomm HS-USB 9008 mode.
 *      When booted into EDL (by shorting test points or 'adb reboot edl'),
 *      the QFIL tool can flash unsigned images if the programmer
 *      (prog_emmc_firehose.mbn) itself is compromised. Some OEM EDL
 *      programmers have zero-day vulns allowing unsigned flashing.
 *
 * MEDIATEK:
 *   Verified Boot: BootROM -> Preloader -> LK -> boot.img
 *
 *   Known bypass methods:
 *   1. CVE-2020-0069 — MediaTek BootROM exploit (kamakiri/dram).
 *      Allows arbitrary code execution at BootROM level on MT6739/MT6763/
 *      MT6771/MT6779/MT6785/MT6885. Disables all downstream signature
 *      verification including modem.img.
 *
 *   2. bromite (CVE-2020-0041) — USB control transfer overflow in MediaTek
 *      BootROM download mode. Enables DA (Download Agent) authentication
 *      bypass in SP Flash Tool.
 *
 *   3. da-sec (CVE-2019-xxxx) — MediaTek Download Agent authentication
 *      bypass via crafted USB descriptor. Allows flashing unsigned images
 *      through SP Flash Tool with "Force Write" option.
 *
 * LIVE MEMORY PATCHING (Safest — no persistence, no brick risk):
 *   Instead of permanently flashing modified firmware, use DIAG memory
 *   write commands to patch the modem's RAM after each boot.
 *
 *   Target functions to patch (Qualcomm GSM modem):
 *   1. mm_rr_authenticate_req() — Returns AUTHENTICATION REJECT to the
 *      network when SIM auth fails. Patch to return AUTHENTICATION RESPONSE
 *      with success. Located in modem.img's MM (Mobility Management) layer.
 *      ARM Thumb offset varies by firmware build. Search pattern:
 *      F0 B5 03 AF 2D E9 — function prologue for mm_rr_auth_req.
 *
 *   2. sim_present_check() — Checks physical SIM presence via ISO 7816
 *      interface. Patch first instruction to MOV R0, #1; BX LR.
 *      Search pattern: "SIM" string reference nearby.
 *
 *   3. plmn_allowed_check() — Verifies network MCC/MNC against the
 *      SIM's EF-LOCI. Patch to always return 1 (allowed).
 *
 *   4. imsi_attach_req() — Sends IMSI Attach to network. Can be forced
 *      even without a SIM by patching the conditional branch.
 *
 *   Memory addresses can be obtained by:
 *   a. Extracting /dev/block/by-name/modem -> analyzing with Ghidra/IDA
 *   b. Using diag_nv_read to probe known offsets
 *   c. Searching for ARM Thumb function signatures at runtime via diag_mem_read
 *
 *   Patch payload format (ARM Thumb):
 *     MOV R0, #1        -> 0x2001 (R0 = 1 = success)
 *     BX  LR            -> 0x4770 (return)
 *     Total: 4 bytes per function
 */

/* ── Constants ────────────────────────────────────────────────────────── */

/* Known CVEs applicable to Qualcomm Secure Boot */
#define CVE_2020_3696_WLAN_SBL1         "CVE-2020-3696"
#define CVE_2020_0022_BLEEDINGTOOTH     "CVE-2020-0022"
#define CVE_2019_10581_DSP_UAF          "CVE-2019-10581"
#define CVE_2017_15846_CAMERA_OOB       "CVE-2017-15846"
#define CVE_2020_0069_MTK_BOOTROM       "CVE-2020-0069"
#define CVE_2020_0041_BROMITE           "CVE-2020-0041"

/* Patch types */
typedef enum {
    PATCH_TYPE_RAM_LIVE,      /* Write to modem RAM via DIAG (volatile) */
    PATCH_TYPE_QMI_FTM,       /* Flash via QMI FTM commands */
    PATCH_TYPE_EDL_FLASH,     /* Emergency Download Mode flash */
    PATCH_TYPE_HEXAGON_RPC    /* Inject via Hexagon DSP RPC */
} patch_type_t;

/* Function signatures for modem patching */
typedef struct {
    const char* name;
    uint32_t    arm_signature[4];  /* First 16 bytes of the function */
    uint32_t    patch_bytes[2];    /* 8 bytes of patch code */
    uint32_t    patch_length;     /* Length of patch in bytes */
    const char* cve_reference;
} modem_patch_t;

/* ── Known Patch Targets (Qualcomm GSM modem, common builds) ──────────── */

/* Pre-defined patches for known modem firmware versions */
extern const modem_patch_t PATCH_MM_AUTH_QUALCOMM[];
extern const modem_patch_t PATCH_SIM_CHECK_QUALCOMM[];
extern const modem_patch_t PATCH_PLMN_CHECK_QUALCOMM[];

/* ── API ──────────────────────────────────────────────────────────────── */

/**
 * Search modem RAM for a function signature.
 * @param h       Open DIAG handle
 * @param start   Start address in modem RAM (e.g., 0x80000000)
 * @param size    Size of region to search
 * @param sig     Signature bytes to search for
 * @param sig_len Length of signature
 * @return Address of match, or 0 if not found.
 */
uint32_t secure_boot_find_function(diag_handle_t* h, uint32_t start, uint32_t size,
                                   const uint8_t* sig, uint32_t sig_len);

/**
 * Apply a live RAM patch to a modem function.
 * Writes patch bytes via DIAG mem write (volatile — lost on reboot).
 * @return 0 on success, -1 on failure
 */
int secure_boot_apply_patch(diag_handle_t* h, uint32_t address,
                            const uint8_t* patch, uint32_t patch_len);

/**
 * Apply all known SIM/auth bypass patches.
 * Call this once at startup to disable network authentication.
 * @return Number of patches successfully applied
 */
int secure_boot_bypass_all(diag_handle_t* h);

/**
 * Verify that patches are in place by reading back memory.
 * Returns true if the patch bytes match at the target address.
 */
bool secure_boot_verify_patch(diag_handle_t* h, uint32_t address,
                              const uint8_t* expected, uint32_t len);

/**
 * Log patch status for diagnostics.
 */
void secure_boot_log_status(diag_handle_t* h);

#ifdef __cplusplus
}
#endif

#endif /* CELLLINK_SECURE_BOOT_H */
