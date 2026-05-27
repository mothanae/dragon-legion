#include "qmi.h"
#include <string.h>
#include <android/log.h>

#define LOG_TAG "CellLink-QMI"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

/* ── TLV Encoding ────────────────────────────────────────────────────── */

uint16_t tlv_put(uint8_t* buf, uint8_t type, const uint8_t* value, uint16_t len) {
    buf[0] = type;
    buf[1] = (uint8_t)(len & 0xFF);
    buf[2] = (uint8_t)((len >> 8) & 0xFF);
    memcpy(buf + 3, value, len);
    return len + 3;
}

uint16_t tlv_put_u8(uint8_t* buf, uint8_t type, uint8_t value) {
    return tlv_put(buf, type, &value, 1);
}

uint16_t tlv_put_u16(uint8_t* buf, uint8_t type, uint16_t value) {
    uint8_t data[2];
    data[0] = (uint8_t)(value & 0xFF);
    data[1] = (uint8_t)((value >> 8) & 0xFF);
    return tlv_put(buf, type, data, 2);
}

uint16_t tlv_put_u32(uint8_t* buf, uint8_t type, uint32_t value) {
    uint8_t data[4];
    data[0] = (uint8_t)(value & 0xFF);
    data[1] = (uint8_t)((value >> 8) & 0xFF);
    data[2] = (uint8_t)((value >> 16) & 0xFF);
    data[3] = (uint8_t)((value >> 24) & 0xFF);
    return tlv_put(buf, type, data, 4);
}

/* ── Low-Level QMI ───────────────────────────────────────────────────── */

int qmi_request(diag_handle_t* h, uint8_t subsystem, uint16_t command,
                const uint8_t* req, uint16_t req_len,
                uint8_t* rsp, uint16_t rsp_len, int timeout_ms) {
    if (diag_send_qmi(h, subsystem, command, req, req_len) < 0) return -1;

    uint8_t rsp_subsys;
    uint16_t rsp_cmd;
    return diag_recv_qmi(h, &rsp_subsys, &rsp_cmd, rsp, rsp_len, timeout_ms);
}

bool qmi_response_ok(const uint8_t* data, uint16_t len) {
    /* Parse TLVs looking for result code */
    uint16_t off = 0;
    while (off + 3 <= len) {
        uint8_t type = data[off];
        uint16_t vlen = (uint16_t)data[off + 1] | ((uint16_t)data[off + 2] << 8);
        if (off + 3 + vlen > len) break;

        if (type == TLV_TYPE_RESULT && vlen >= 2) {
            uint16_t result = (uint16_t)data[off + 3] | ((uint16_t)data[off + 4] << 8);
            return result == QMI_RESULT_SUCCESS;
        }
        off += 3 + vlen;
    }
    return false;
}

/* ── NAS Operations ──────────────────────────────────────────────────── */

int qmi_nas_network_scan(diag_handle_t* h, char* results, uint16_t max_len) {
    /* TLV 0x01: scan type (0x01 = full scan) */
    uint8_t req[3];
    uint16_t rl = tlv_put_u8(req, 0x01, 0x01);
    /* TLV 0x10: technology preference (0x02 = GERAN) */
    rl += tlv_put_u8(req + rl, 0x10, 0x02);

    uint8_t rsp[DIAG_MAX_PAYLOAD];
    int n = qmi_request(h, QMI_SUBSYS_NAS, QMI_NAS_NETWORK_SCAN, req, rl, rsp, sizeof(rsp), 30000);
    if (n < 0) return -1;

    if (max_len > 1) {
        uint16_t copy = n < max_len - 1 ? n : max_len - 1;
        memcpy(results, rsp, copy);
        results[copy] = '\0';
    }
    return n;
}

int qmi_nas_register_network(diag_handle_t* h, uint16_t mcc, uint16_t mnc) {
    /* Build PLMN: 3-digit MCC + 2/3-digit MNC stored as BCD */
    uint8_t plmn[3];
    uint16_t mcc_copy = mcc;
    uint16_t mnc_copy = mnc;

    plmn[0] = (uint8_t)((mcc_copy % 10) | (((mcc_copy / 10) % 10) << 4));
    plmn[1] = (uint8_t)(((mcc_copy / 100) % 10) | ((mnc_copy % 10) << 4));
    plmn[2] = (uint8_t)(((mnc_copy / 10) % 10) | 0xF0);

    /* TLV 0x01: register action (0x01 = automatic) */
    uint8_t req[64];
    uint16_t rl = tlv_put_u8(req, 0x01, 0x01);

    /* TLV 0x10: network selection mode (manual) + PLMN */
    uint8_t sel_data[5] = {0x01};
    memcpy(sel_data + 1, plmn, 3);
    sel_data[4] = 0x02;  /* GERAN radio access */
    rl += tlv_put(req + rl, 0x10, sel_data, 5);

    uint8_t rsp[DIAG_MAX_PAYLOAD];
    int n = qmi_request(h, QMI_SUBSYS_NAS, QMI_NAS_REGISTER_INDICATION, req, rl, rsp, sizeof(rsp), 15000);
    if (n < 0) return -1;
    return qmi_response_ok(rsp, n) ? 0 : -1;
}

int qmi_nas_set_gsm_only(diag_handle_t* h) {
    uint8_t req[8];
    uint16_t rl = tlv_put_u16(req, 0x01, 0x0002); /* 0x02 = GSM only */
    rl += tlv_put_u32(req + rl, 0x10, 0x02);     /* GERAN preference */

    uint8_t rsp[64];
    int n = qmi_request(h, QMI_SUBSYS_NAS, QMI_NAS_SET_TECHNOLOGY_PREF, req, rl, rsp, sizeof(rsp), 5000);
    if (n < 0) return -1;
    return qmi_response_ok(rsp, n) ? 0 : -1;
}

int qmi_nas_get_signal_strength(diag_handle_t* h, int16_t* rssi_out) {
    uint8_t req[3];
    uint16_t rl = tlv_put_u8(req, 0x01, 0x01);

    uint8_t rsp[DIAG_MAX_PAYLOAD];
    int n = qmi_request(h, QMI_SUBSYS_NAS, QMI_NAS_GET_SIGNAL_STRENGTH, req, rl, rsp, sizeof(rsp), 5000);
    if (n < 4) return -1;

    /* Parse result TLV for RSSI */
    uint16_t off = 0;
    while (off + 3 <= (uint16_t)n) {
        uint8_t type = rsp[off];
        uint16_t vlen = (uint16_t)rsp[off + 1] | ((uint16_t)rsp[off + 2] << 8);
        if (off + 3 + vlen > (uint16_t)n) break;

        if (type == 0x13 && vlen >= 2) { /* GSM RSSI TLV */
            int16_t rssi = (int16_t)rsp[off + 3] | ((int16_t)rsp[off + 4] << 8);
            *rssi_out = rssi;
            return 0;
        }
        off += 3 + vlen;
    }
    return -1;
}

/* ── DMS Operations ──────────────────────────────────────────────────── */

int qmi_dms_set_online(diag_handle_t* h) {
    uint8_t req[3];
    uint16_t rl = tlv_put_u8(req, 0x01, 0x00); /* 0x00 = online */

    uint8_t rsp[64];
    int n = qmi_request(h, QMI_SUBSYS_DMS, QMI_DMS_SET_OPERATING_MODE, req, rl, rsp, sizeof(rsp), 5000);
    if (n < 0) return -1;
    return qmi_response_ok(rsp, n) ? 0 : -1;
}

int qmi_dms_set_offline(diag_handle_t* h) {
    uint8_t req[3];
    uint16_t rl = tlv_put_u8(req, 0x01, 0x01); /* 0x01 = offline */

    uint8_t rsp[64];
    int n = qmi_request(h, QMI_SUBSYS_DMS, QMI_DMS_SET_OPERATING_MODE, req, rl, rsp, sizeof(rsp), 5000);
    if (n < 0) return -1;
    return qmi_response_ok(rsp, n) ? 0 : -1;
}

/* ── Test / FTM Operations ───────────────────────────────────────────── */

int qmi_test_set_continuous_tx(diag_handle_t* h, uint16_t arfcn, uint8_t power_level) {
    /* First set FTM mode */
    uint8_t ftm_req[3];
    uint16_t rl = tlv_put_u8(ftm_req, 0x01, 0x01); /* Enable FTM */

    uint8_t rsp[64];
    int n = qmi_request(h, QMI_SUBSYS_TEST, QMI_TEST_SET_FTM_MODE, ftm_req, rl, rsp, sizeof(rsp), 5000);
    if (n < 0 || !qmi_response_ok(rsp, n)) {
        LOGE("Failed to enter FTM mode");
        return -1;
    }

    /* Set channel / ARFCN */
    uint8_t chan_req[8];
    rl = tlv_put_u16(chan_req, 0x01, arfcn);
    rl += tlv_put_u8(chan_req + rl, 0x10, 0x00); /* Band: GSM-900 */

    n = qmi_request(h, QMI_SUBSYS_TEST, QMI_TEST_SET_CHANNEL, chan_req, rl, rsp, sizeof(rsp), 5000);
    if (n < 0 || !qmi_response_ok(rsp, n)) {
        LOGE("Failed to set channel %d", arfcn);
        return -1;
    }

    /* Set Tx power */
    uint8_t pwr_req[5];
    rl = tlv_put_u8(pwr_req, 0x01, power_level); /* 0-31, typ. 15 for ~33dBm GSM */
    rl += tlv_put_u16(pwr_req + rl, 0x10, arfcn);

    n = qmi_request(h, QMI_SUBSYS_TEST, QMI_TEST_SET_TX_POWER, pwr_req, rl, rsp, sizeof(rsp), 5000);
    if (n < 0 || !qmi_response_ok(rsp, n)) {
        LOGE("Failed to set Tx power, continuing anyway");
    }

    /* Start continuous Tx */
    uint8_t tx_req[4];
    rl = tlv_put_u8(tx_req, 0x01, 0x01); /* Mode: continuous wave */
    rl += tlv_put_u8(tx_req + rl, 0x10, 0x01); /* Pattern: all 1s */

    n = qmi_request(h, QMI_SUBSYS_TEST, QMI_TEST_CONTINUOUS_TX, tx_req, rl, rsp, sizeof(rsp), 5000);
    if (n < 0 || !qmi_response_ok(rsp, n)) {
        LOGE("Failed to start continuous Tx");
        return -1;
    }

    LOGI("Continuous Tx started: ARFCN=%d, power=%d", arfcn, power_level);
    return 0;
}

int qmi_test_stop_tx(diag_handle_t* h) {
    uint8_t req[3];
    uint16_t rl = tlv_put_u8(req, 0x01, 0x00); /* Stop Tx */

    uint8_t rsp[64];
    int n = qmi_request(h, QMI_SUBSYS_TEST, QMI_TEST_STOP_TX, req, rl, rsp, sizeof(rsp), 5000);
    if (n < 0) return -1;

    /* Exit FTM mode */
    uint8_t ftm_req[3];
    uint16_t rl2 = tlv_put_u8(ftm_req, 0x01, 0x00); /* Disable FTM */
    qmi_request(h, QMI_SUBSYS_TEST, QMI_TEST_SET_FTM_MODE, ftm_req, rl2, rsp, sizeof(rsp), 5000);

    LOGI("Continuous Tx stopped");
    return 0;
}

int qmi_test_set_frequency(diag_handle_t* h, uint16_t arfcn, uint8_t band) {
    /* Write NV item 0x0285 (GSM ARFCN) and related items */
    /* NV 441: GSM Band Preference */
    uint8_t band_data[8] = {0};
    band_data[0] = (uint8_t)(1 << band); /* Bitmask for band */
    if (diag_nv_write(h, 441, band_data, 8) != 0) {
        LOGE("Failed to write NV 441 (band preference)");
        return -1;
    }

    /* NV 6828: LTE to GSM IRAT — disable for GSM-only */
    uint8_t irat_data[1] = {0x00};
    diag_nv_write(h, 6828, irat_data, 1);

    /* NV 10: Preferred network type = GSM */
    uint8_t pref_data[1] = {0x01}; /* GSM only */
    if (diag_nv_write(h, 10, pref_data, 1) != 0) {
        LOGE("Failed to write NV 10 (network preference)");
        return -1;
    }

    LOGI("Frequency set: ARFCN=%d, band=%d", arfcn, band);
    return 0;
}
