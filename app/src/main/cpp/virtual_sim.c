#include "virtual_sim.h"
#include "qmi.h"
#include "gsm_common.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <android/log.h>

#define LOG_TAG "CellLink-VSIM"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

/* ── AT+CRSM SIM Access ─────────────────────────────────────────────── */

int vsim_write_ef_at(diag_handle_t* h, uint16_t ef_id, const uint8_t* data, uint8_t len) {
    /* AT+CRSM=<command>,<fileid>,<P1>,<P2>,<P3>[,<data>]
     * command: 220 = UPDATE BINARY
     *          214 = UPDATE RECORD
     * fileid: EF ID in hex
     * P1,P2: offset or record number
     * P3: length */

    char hex_data[512];
    int hp = 0;
    for (uint8_t i = 0; i < len; i++) {
        hp += snprintf(hex_data + hp, sizeof(hex_data) - hp, "%02X", data[i]);
    }

    char cmd[640];
    snprintf(cmd, sizeof(cmd), "+CRSM=220,%04X,0,0,%d,%s", ef_id, len, hex_data);

    char rsp[256];
    int n = diag_at_command(h, cmd, rsp, sizeof(rsp));
    if (n < 0) {
        LOGE("AT+CRSM write failed for EF 0x%04X", ef_id);
        return -1;
    }

    /* Response: +CRSM: <sw1>,<sw2>[,<response>]
     * SW1=0x90 SW2=0x00 = success */
    if (strstr(rsp, "90,00") || strstr(rsp, "91,00")) {
        LOGD("EF 0x%04X written via AT+CRSM", ef_id);
        return 0;
    }

    LOGE("AT+CRSM write returned: %s", rsp);
    return -1;
}

int vsim_write_ef_qmi(diag_handle_t* h, uint16_t ef_id, const uint8_t* data, uint8_t len) {
    uint8_t req[DIAG_MAX_PAYLOAD];
    uint16_t rl = 0;

    /* TLV 0x01: session type (0x01 = primary GW) */
    rl += tlv_put_u8(req + rl, 0x01, 0x01);

    /* TLV 0x02: file ID */
    uint8_t fid_buf[2] = {(uint8_t)(ef_id & 0xFF), (uint8_t)((ef_id >> 8) & 0xFF)};
    rl += tlv_put(req + rl, 0x02, fid_buf, 2);

    /* TLV 0x03: data */
    rl += tlv_put(req + rl, 0x03, data, len);

    uint8_t rsp[DIAG_MAX_PAYLOAD];
    int n = qmi_request(h, QMI_SUBSYS_UIM, 0x0025, req, rl, rsp, sizeof(rsp), 5000);
    if (n >= 0 && qmi_response_ok(rsp, n)) {
        LOGD("EF 0x%04X written via QMI UIM", ef_id);
        return 0;
    }

    LOGD("QMI UIM write failed for EF 0x%04X, trying AT fallback", ef_id);
    return vsim_write_ef_at(h, ef_id, data, len);
}

/* ── IMSI Encoding ───────────────────────────────────────────────────── */

static uint8_t encode_imsi_ef(const char* imsi, uint8_t* out) {
    /* EF-IMSI format: length(1) + BCD digits
     * Byte 0: length of IMSI
     * Bytes 1..: BCD-encoded digits */
    size_t len = strlen(imsi);
    if (len > 15) len = 15;

    out[0] = (uint8_t)len;
    for (size_t i = 0; i < len; i += 2) {
        uint8_t lo = imsi[i] - '0';
        uint8_t hi = (i + 1 < len) ? (imsi[i + 1] - '0') : 0x0F;
        out[1 + i / 2] = (hi << 4) | lo;
    }

    return (uint8_t)((len + 1) / 2 + 1);
}

/* ── Public API ──────────────────────────────────────────────────────── */

virtual_sim_t* vsim_create(void) {
    return vsim_create_custom(VSIM_DEFAULT_MCC, VSIM_DEFAULT_MNC,
                              VSIM_DEFAULT_IMSI, VSIM_DEFAULT_MSISDN, VSIM_DEFAULT_SPN);
}

virtual_sim_t* vsim_create_custom(uint16_t mcc, uint16_t mnc, const char* imsi,
                                   const char* msisdn, const char* spn) {
    virtual_sim_t* sim = (virtual_sim_t*)calloc(1, sizeof(virtual_sim_t));
    if (!sim) return NULL;

    sim->mcc = mcc;
    sim->mnc = mnc;
    sim->lac = 0x0001;
    sim->ci = 0x0001;
    sim->acc = 0x00; /* All access classes allowed */
    sim->method = SIM_METHOD_QMI_UIM;
    memset(sim->kc, 0, 8); /* No ciphering by default */

    strncpy(sim->imsi, imsi, sizeof(sim->imsi) - 1);
    strncpy(sim->msisdn, msisdn, sizeof(sim->msisdn) - 1);
    strncpy(sim->spn, spn, sizeof(sim->spn) - 1);

    /* Generate ICCID from IMSI prefix */
    snprintf(sim->iccid, sizeof(sim->iccid), "89%02d%02d%s",
             mcc % 100, mnc % 100, "000000000001");

    LOGI("Virtual SIM created: IMSI=%s MCC=%d MNC=%d", sim->imsi, sim->mcc, sim->mnc);
    return sim;
}

void vsim_free(virtual_sim_t* sim) {
    free(sim);
}

int vsim_activate(virtual_sim_t* sim, diag_handle_t* h, uint8_t method) {
    if (!sim || !h) return -1;
    sim->method = method;

    LOGI("Activating virtual SIM via method %d...", method);

    int (*write_ef)(diag_handle_t*, uint16_t, const uint8_t*, uint8_t) =
        (method == SIM_METHOD_AT_CRSM) ? vsim_write_ef_at : vsim_write_ef_qmi;

    int ok = 0, fail = 0;

    /* Write IMSI (EF-IMSI) */
    uint8_t imsi_ef[16];
    uint8_t imsi_len = encode_imsi_ef(sim->imsi, imsi_ef);
    if (write_ef(h, EF_IMSI, imsi_ef, imsi_len) == 0) ok++; else fail++;

    /* Write LOCI (EF-LOCI) */
    /* TMSI(4) + LAI(5) + T3212(1) + status(1) = 11 bytes */
    uint8_t loci[11] = {0};
    loci[0] = 0xFF; loci[1] = 0xFF; loci[2] = 0xFF; loci[3] = 0xFF; /* No TMSI */
    gsm_build_lai(loci + 4, sim->mcc, sim->mnc, sim->lac);
    loci[9] = 0x00; /* T3212 = no periodic update */
    loci[10] = 0x01; /* Status = updated */
    if (write_ef(h, EF_LOCI, loci, 11) == 0) ok++; else fail++;

    /* Write Kc (all zeros = no ciphering) */
    if (write_ef(h, EF_Kc, sim->kc, 8) == 0) ok++; else fail++;

    /* Write Access Control Class (all classes) */
    uint8_t acc[2] = {sim->acc, 0xFF};
    if (write_ef(h, EF_ACC, acc, 2) == 0) ok++; else fail++;

    sim->is_active = (fail == 0);
    LOGI("Virtual SIM activation: %d OK, %d FAIL, ACTIVE=%s", ok, fail,
         sim->is_active ? "YES" : "NO");

    return sim->is_active ? 0 : -1;
}

int vsim_deactivate(virtual_sim_t* sim, diag_handle_t* h) {
    if (!sim || !h) return -1;

    /* Write empty LOCI to force detach */
    uint8_t empty_loci[11] = {0};
    empty_loci[10] = 0x00; /* Status = not updated */
    vsim_write_ef_qmi(h, EF_LOCI, empty_loci, 11);

    sim->is_active = false;
    LOGI("Virtual SIM deactivated");
    return 0;
}

int vsim_update_loci(virtual_sim_t* sim, diag_handle_t* h,
                     uint16_t lac, uint16_t ci) {
    sim->lac = lac;
    sim->ci = ci;

    uint8_t loci[11] = {0};
    loci[0] = 0xFF; loci[1] = 0xFF; loci[2] = 0xFF; loci[3] = 0xFF;
    gsm_build_lai(loci + 4, sim->mcc, sim->mnc, lac);
    gsm_build_ci(loci + 9, ci); /* Wait, LOCI doesn't store CI directly */
    /* Actually LOCI = TMSI(4) + LAI(5) + T3212(1) + LOCI status(1) */
    loci[9] = 0x00;
    loci[10] = 0x01; /* Updated */

    return vsim_write_ef_qmi(h, EF_LOCI, loci, 11);
}

int vsim_set_kc(virtual_sim_t* sim, const uint8_t kc[8]) {
    memcpy(sim->kc, kc, 8);
    return 0;
}

bool vsim_verify(virtual_sim_t* sim, diag_handle_t* h) {
    /* Try to read IMSI via AT+CIMI */
    char rsp[64];
    int n = diag_at_command(h, "+CIMI", rsp, sizeof(rsp));
    if (n > 0) {
        /* Strip whitespace */
        char* end = rsp + n;
        while (end > rsp && (*end < '0' || *end > '9')) *end-- = '\0';
        bool match = (strcmp(rsp, sim->imsi) == 0);
        LOGI("SIM verify: CIMI=%s (expected %s) -> %s", rsp, sim->imsi,
             match ? "OK" : "MISMATCH");
        return match;
    }
    return false;
}

void vsim_dump(virtual_sim_t* sim, char* buf, uint16_t max_len) {
    snprintf(buf, max_len,
        "Virtual SIM:\n"
        "  ICCID:  %s\n"
        "  IMSI:   %s\n"
        "  MSISDN: %s\n"
        "  SPN:    %s\n"
        "  MCC/MNC: %03d/%02d\n"
        "  LAC/CI:  %04X/%04X\n"
        "  Kc:      %s\n"
        "  Active:  %s\n",
        sim->iccid, sim->imsi, sim->msisdn, sim->spn,
        sim->mcc, sim->mnc, sim->lac, sim->ci,
        "0000000000000000", sim->is_active ? "YES" : "NO");
}
