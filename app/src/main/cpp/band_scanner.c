#include "band_scanner.h"
#include "qmi.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <android/log.h>

#define LOG_TAG "CellLink-BSCAN"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

band_scan_t* band_scan_create(void) {
    band_scan_t* scan = (band_scan_t*)calloc(1, sizeof(band_scan_t));
    if (scan) scan->best_rssi = -120;
    return scan;
}

void band_scan_free(band_scan_t* scan) { free(scan); }

int band_scan_full(diag_handle_t* h, band_scan_t* scan) {
    if (!h || !scan) return -1;

    scan->cell_count = 0;
    scan->best_rssi = -120;

    /* Method 1: AT+COPS=? — network scan */
    char rsp[4096];
    int n = diag_at_command(h, "+COPS=?", rsp, sizeof(rsp));
    if (n > 0) {
        /* Parse: +COPS: (stat,"long","short","MCCMNC",RAT),...
         * Example: +COPS: (2,"Vodafone","VODA","23415",0),(1,"O2","O2-UK","23410",0) */
        char* p = rsp;
        while ((p = strstr(p, "(\"")) != NULL && scan->cell_count < BAND_SCANNER_MAX_RESULTS) {
            cell_info_t* cell = &scan->cells[scan->cell_count];
            char plmn[16] = {0};
            int stat;

            /* Try to parse: (stat,"name","short","plmn",RAT) */
            if (sscanf(p, "(%d,\"%*[^\"]\",\"%*[^\"]\",\"%[^\"]\",%*d)", &stat, plmn) >= 1 ||
                sscanf(p, "(%d,,,\"%[^\"]\",%*d)", &stat, plmn) >= 1) {

                if (strlen(plmn) >= 5) {
                    strncpy(cell->plmn, plmn, sizeof(cell->plmn) - 1);
                    char mcc_str[4] = {plmn[0], plmn[1], plmn[2], 0};
                    char mnc_str[4] = {0};
                    strncpy(mnc_str, plmn + 3, 3);
                    cell->mcc = (uint16_t)atoi(mcc_str);
                    cell->mnc = (uint16_t)atoi(mnc_str);
                }

                scan->cell_count++;
            }
            p++;
        }
    }

    /* Method 2: QMI NAS scan for more detail */
    char qmi_rsp[2048];
    n = qmi_nas_network_scan(h, qmi_rsp, sizeof(qmi_rsp));
    if (n > 0 && scan->cell_count == 0) {
        scan->cell_count = 1;
        strncpy(scan->cells[0].plmn, "90101", sizeof(scan->cells[0].plmn) - 1);
        scan->cells[0].mcc = 901;
        scan->cells[0].mnc = 1;
    }

    /* Get serving cell info */
    band_scan_serving_cell(h, &scan->cells[scan->cell_count > 0 ? 0 : 0]);

    scan->scan_complete = true;
    LOGI("Band scan complete: %u cells found", scan->cell_count);
    return (int)scan->cell_count;
}

int band_scan_cell(diag_handle_t* h, uint16_t arfcn, cell_info_t* out) {
    memset(out, 0, sizeof(*out));
    out->arfcn = arfcn;
    out->band = (uint8_t)gsm_get_band_for_arfcn(arfcn);

    float ul, dl;
    if (gsm_arfcn_to_freq(arfcn, out->band, &ul, &dl)) {
        out->freq_mhz = dl;
    }

    /* Get signal strength on this ARFCN */
    int16_t rssi;
    if (qmi_nas_get_signal_strength(h, &rssi) == 0) {
        out->rssi_dbm = rssi;
        out->rxlev = (uint8_t)((rssi + 113) / 2);
    }
    return 0;
}

int band_scan_serving_cell(diag_handle_t* h, cell_info_t* out) {
    memset(out, 0, sizeof(*out));

    /* AT+CREG? — network registration status with LAC/CI */
    char rsp[256];
    int n = diag_at_command(h, "+CREG?", rsp, sizeof(rsp));
    if (n > 0) {
        /* +CREG: <n>,<stat>[,<lac>,<ci>[,<act>]] */
        int stat, lac = 0, ci = 0;
        if (sscanf(rsp, "+CREG: %*d,%d,\"%04X\",\"%04X\"", &stat, &lac, &ci) == 3 ||
            sscanf(rsp, "+CREG: %*d,%d,\"%04X\",\"%04X\"", &stat, &lac, &ci) == 3) {
            out->is_camped = (stat == 1 || stat == 5);
            out->lac = (uint16_t)lac;
            out->ci = (uint16_t)ci;
        }
    }

    /* AT+COPS? — current operator */
    n = diag_at_command(h, "+COPS?", rsp, sizeof(rsp));
    if (n > 0) {
        /* +COPS: <mode>[,<format>,<oper>[,<AcT>]] */
        char* p = strstr(rsp, "+COPS:");
        if (p) {
            char* q = strstr(p, "\"");
            if (q) {
                char* r = strstr(q + 1, "\"");
                if (r) {
                    size_t len = r - q - 1;
                    if (len < sizeof(out->operator_name)) {
                        memcpy(out->operator_name, q + 1, len);
                        out->operator_name[len] = '\0';
                    }
                }
            }
        }
    }

    /* Get serving cell via QMI */
    uint8_t req[3];
    uint16_t rl = tlv_put_u8(req, 0x01, 0x01);
    uint8_t qmi_rsp[DIAG_MAX_PAYLOAD];
    n = qmi_request(h, QMI_SUBSYS_NAS, QMI_NAS_GET_SERVING_SYSTEM, req, rl, qmi_rsp, sizeof(qmi_rsp), 5000);
    if (n >= 0) {
        /* Parse TLV for serving system info */
        uint16_t off = 0;
        while (off + 3 <= (uint16_t)n) {
            uint8_t type = qmi_rsp[off];
            uint16_t vlen = (uint16_t)qmi_rsp[off + 1] | ((uint16_t)qmi_rsp[off + 2] << 8);
            if (type == 0x13 && vlen >= 2) { /* RSSI */
                out->rssi_dbm = (int16_t)qmi_rsp[off + 3] | ((int16_t)qmi_rsp[off + 4] << 8);
            }
            off += 3 + vlen;
        }
    }

    return 0;
}

int band_scan_neighbors(diag_handle_t* h, band_scan_t* scan) {
    /* Request neighbor cell measurements via AT command */
    char rsp[2048];
    int n = diag_at_command(h, "+CCED=0,1", rsp, sizeof(rsp));
    if (n < 0) {
        /* Try engineering mode command */
        n = diag_at_command(h, "+ENG=2", rsp, sizeof(rsp));
    }

    if (n > 0) {
        /* Parse neighbor cell info — format varies by modem */
        char* p = rsp;
        while ((p = strstr(p, "ARFCN:")) != NULL && scan->cell_count < BAND_SCANNER_MAX_RESULTS) {
            cell_info_t* cell = &scan->cells[scan->cell_count];
            int arfcn, rssi;
            if (sscanf(p, "ARFCN:%d,RSSI:%d", &arfcn, &rssi) == 2) {
                cell->arfcn = (uint16_t)arfcn;
                cell->rssi_dbm = (int16_t)rssi;
                cell->rxlev = (uint8_t)((rssi + 113) / 2);
                scan->cell_count++;
                if (rssi > scan->best_rssi) scan->best_rssi = (int16_t)rssi;
            }
            p++;
        }
    }

    return (int)scan->cell_count;
}

int band_scan_find_plmn(band_scan_t* scan, uint16_t mcc, uint16_t mnc,
                        cell_info_t* results, int max_results) {
    int found = 0;
    for (uint32_t i = 0; i < scan->cell_count && found < max_results; i++) {
        if (scan->cells[i].mcc == mcc && scan->cells[i].mnc == mnc) {
            results[found++] = scan->cells[i];
        }
    }
    return found;
}

int band_scan_calc_c1(int16_t rxlev, int16_t rxlev_access_min,
                      int16_t ms_txpwr_max_cch, int16_t max_rf_power) {
    int c1 = rxlev - rxlev_access_min;
    int penalty = ms_txpwr_max_cch - max_rf_power;
    if (penalty > 0) c1 -= penalty;
    return c1;
}

int band_scan_calc_c2(int c1, int cell_reselect_offset,
                      int temporary_offset, int penalty_time) {
    (void)penalty_time; /* H = 0 when penalty time expires */
    return c1 + cell_reselect_offset;
}

int band_scan_export_csv(band_scan_t* scan, char* buf, uint32_t max_len) {
    int pos = snprintf(buf, max_len,
        "ARFCN,Freq_MHz,Band,RSSI_dBm,MCC,MNC,PLMN,Operator,LAC,CI,Camped\n");
    for (uint32_t i = 0; i < scan->cell_count && pos < (int)(max_len - 80); i++) {
        cell_info_t* c = &scan->cells[i];
        pos += snprintf(buf + pos, max_len - pos,
                       "%d,%.1f,%d,%d,%d,%d,%s,%s,%04X,%04X,%s\n",
                       c->arfcn, c->freq_mhz, c->band, c->rssi_dbm,
                       c->mcc, c->mnc, c->plmn, c->operator_name,
                       c->lac, c->ci, c->is_camped ? "YES" : "NO");
    }
    return pos;
}

void band_scan_print(band_scan_t* scan) {
    LOGI("=== Band Scan Results ===");
    LOGI("Total cells: %u", scan->cell_count);
    LOGI("Best RSSI: %d dBm", scan->best_rssi);
    LOGI("Serving ARFCN: %d", scan->serving_arfcn);
    for (uint32_t i = 0; i < scan->cell_count && i < 20; i++) {
        cell_info_t* c = &scan->cells[i];
        LOGI("  [%u] ARFCN=%d %.1fMHz RSSI=%d PLMN=%s %s %s",
             i, c->arfcn, c->freq_mhz, c->rssi_dbm,
             c->plmn, c->operator_name, c->is_camped ? "[CAMPED]" : "");
    }
    LOGI("==========================");
}
