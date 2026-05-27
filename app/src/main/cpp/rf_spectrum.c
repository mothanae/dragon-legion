#include "rf_spectrum.h"
#include "qmi.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <android/log.h>

#define LOG_TAG "CellLink-SPECTRUM"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

spectrum_scan_t* spectrum_init(void) {
    spectrum_scan_t* s = (spectrum_scan_t*)calloc(1, sizeof(spectrum_scan_t));
    if (!s) return NULL;
    s->system_noise_floor_dbm = -120.0f;
    s->best_arfcn = 0;
    return s;
}

void spectrum_free(spectrum_scan_t* scan) {
    free(scan);
}

int spectrum_measure_channel(diag_handle_t* h, uint16_t arfcn, uint8_t band,
                             spectrum_channel_t* out) {
    memset(out, 0, sizeof(*out));
    out->arfcn = arfcn;
    out->band = band;

    float ul, dl;
    if (!gsm_arfcn_to_freq(arfcn, (gsm_band_t)band, &ul, &dl)) {
        out->is_gsm_channel = false;
        return -1;
    }
    out->freq_mhz = dl;
    out->is_gsm_channel = true;

    int16_t rssi_sum = 0;
    int16_t rssi_min = 0;
    int16_t rssi_max = -120;
    int valid_readings = 0;

    for (int pass = 0; pass < SPECTRUM_SWEEP_PASSES; pass++) {
        /* Method 1: AT+CSQ on the current channel via engineering mode */
        /* AT+RXLEV=<channel> may work on some modems */
        char at_cmd[32];
        snprintf(at_cmd, sizeof(at_cmd), "+RXLEV=%d", arfcn);
        char rsp[64];
        int n = diag_at_command(h, at_cmd, rsp, sizeof(rsp));
        if (n > 0) {
            int rssi;
            if (sscanf(rsp, "+RXLEV: %d", &rssi) == 1) {
                rssi = -110 + rssi; /* Convert RXLEV to dBm approx */
                rssi_sum += rssi;
                if (rssi < rssi_min) rssi_min = rssi;
                if (rssi > rssi_max) rssi_max = rssi;
                valid_readings++;
            }
        }

        /* Method 2: QMI NAS signal strength on forced channel */
        int16_t qmi_rssi;
        if (qmi_nas_get_signal_strength(h, &qmi_rssi) == 0) {
            rssi_sum += qmi_rssi;
            if (qmi_rssi < rssi_min) rssi_min = qmi_rssi;
            if (qmi_rssi > rssi_max) rssi_max = qmi_rssi;
            valid_readings++;
        }

        usleep(50000); /* 50ms between passes */
    }

    if (valid_readings > 0) {
        out->rssi_dbm = rssi_sum / valid_readings;
        out->rssi_min_dbm = rssi_min;
        out->rssi_max_dbm = rssi_max;
    } else {
        out->rssi_dbm = -120;
        out->rssi_min_dbm = -120;
        out->rssi_max_dbm = -120;
    }

    /* Estimate noise floor: lowest reading across passes, with floor at -120 */
    out->noise_floor_dbm = (uint8_t)(-out->rssi_min_dbm > 120 ? 120 : (-out->rssi_min_dbm > 0 ? (uint8_t)(-out->rssi_min_dbm) : 120));

    /* Consider occupied if RSSI > -95 dBm */
    out->occupied = (out->rssi_dbm > -95);

    LOGD("CH %d (%.1f MHz): RSSI=%d dBm %s",
         arfcn, dl, out->rssi_dbm, out->occupied ? "[OCCUPIED]" : "[CLEAR]");
    return 0;
}

int spectrum_sweep_band(diag_handle_t* h, gsm_band_t band, spectrum_scan_t* scan) {
    if (!h || !scan) return -1;

    uint16_t arfcn_start, arfcn_end;
    switch (band) {
        case GSM_BAND_850:  arfcn_start = 128; arfcn_end = 251; break;
        case GSM_BAND_900:  arfcn_start = 1;   arfcn_end = 124; break;
        case GSM_BAND_1800: arfcn_start = 512; arfcn_end = 885; break;
        case GSM_BAND_1900: arfcn_start = 512; arfcn_end = 810; break;
        default: return -1;
    }

    LOGI("Sweeping band %d: ARFCN %d-%d", band, arfcn_start, arfcn_end);

    /* Also scan E-GSM extension */
    bool is_egsm = (band == GSM_BAND_900);
    uint16_t total_channels = (arfcn_end - arfcn_start + 1) + (is_egsm ? 50 : 0);

    if (scan->channel_count + total_channels > SPECTRUM_MAX_CHANNELS) {
        LOGE("Spectrum buffer full");
        return -1;
    }

    int measured = 0;
    for (uint16_t arfcn = arfcn_start; arfcn <= arfcn_end; arfcn++) {
        spectrum_channel_t* ch = &scan->channels[scan->channel_count];
        if (spectrum_measure_channel(h, arfcn, (uint8_t)band, ch) == 0) {
            scan->channel_count++;
            measured++;
        }
    }

    /* E-GSM extension */
    if (is_egsm) {
        for (uint16_t arfcn = 975; arfcn <= 1023; arfcn++) {
            spectrum_channel_t* ch = &scan->channels[scan->channel_count];
            if (spectrum_measure_channel(h, arfcn, (uint8_t)band, ch) == 0) {
                scan->channel_count++;
                measured++;
            }
        }
    }

    LOGI("Band sweep complete: %d channels measured", measured);
    return measured;
}

int spectrum_sweep_all_bands(diag_handle_t* h, spectrum_scan_t* scan) {
    int total = 0;
    gsm_band_t bands[] = {GSM_BAND_900, GSM_BAND_850, GSM_BAND_1800, GSM_BAND_1900};
    for (int i = 0; i < 4; i++) {
        total += spectrum_sweep_band(h, bands[i], scan);
    }
    scan->scan_timestamp = time(NULL);
    scan->scan_complete = true;
    return total;
}

uint16_t spectrum_find_clearest_channel(spectrum_scan_t* scan, gsm_band_t preferred_band) {
    uint16_t best = 0;
    int16_t best_rssi = 10; /* Start above any real signal */

    for (uint16_t i = 0; i < scan->channel_count; i++) {
        spectrum_channel_t* ch = &scan->channels[i];
        if (ch->occupied) continue;
        if (!ch->is_gsm_channel) continue;

        /* Score: prefer lower RSSI (quieter channel), bonus for preferred band */
        int16_t score = ch->rssi_dbm;
        if (ch->band == (uint8_t)preferred_band) score += 3; /* 3dB bonus */

        if (ch->rssi_dbm < best_rssi) {
            best_rssi = ch->rssi_dbm;
            best = ch->arfcn;
        }
    }

    scan->best_arfcn = best;
    if (best > 0) {
        gsm_arfcn_to_freq(best, preferred_band, NULL, &scan->best_freq_mhz);
    }
    return best;
}

int spectrum_rank_channels(spectrum_scan_t* scan, uint16_t* ranked_arcfns, int top_n) {
    int count = 0;

    /* Simple insertion sort by RSSI (quietest first) */
    typedef struct { uint16_t arfcn; int16_t rssi; } ranked_t;
    ranked_t ranked[SPECTRUM_MAX_CHANNELS];
    int n = 0;

    for (uint16_t i = 0; i < scan->channel_count && n < SPECTRUM_MAX_CHANNELS; i++) {
        if (!scan->channels[i].occupied && scan->channels[i].is_gsm_channel) {
            ranked[n].arfcn = scan->channels[i].arfcn;
            ranked[n].rssi = scan->channels[i].rssi_dbm;
            n++;
        }
    }

    /* Sort ascending by RSSI (more negative = quieter = better) */
    for (int i = 0; i < n - 1; i++) {
        for (int j = i + 1; j < n; j++) {
            if (ranked[j].rssi < ranked[i].rssi) {
                ranked_t tmp = ranked[i];
                ranked[i] = ranked[j];
                ranked[j] = tmp;
            }
        }
    }

    for (int i = 0; i < top_n && i < n; i++) {
        ranked_arcfns[i] = ranked[i].arfcn;
        count++;
    }

    return count;
}

bool spectrum_is_channel_clear(spectrum_scan_t* scan, uint16_t arfcn) {
    for (uint16_t i = 0; i < scan->channel_count; i++) {
        if (scan->channels[i].arfcn == arfcn) {
            return !scan->channels[i].occupied;
        }
    }
    return true; /* Not in scan, assume clear */
}

int16_t spectrum_adjacent_interference(spectrum_scan_t* scan, uint16_t arfcn) {
    int16_t worst = -120;
    for (uint16_t i = 0; i < scan->channel_count; i++) {
        uint16_t diff = (scan->channels[i].arfcn > arfcn)
            ? scan->channels[i].arfcn - arfcn
            : arfcn - scan->channels[i].arfcn;
        if (diff <= 2 && diff > 0) { /* Adjacent or next-adjacent */
            if (scan->channels[i].rssi_dbm > worst) {
                worst = scan->channels[i].rssi_dbm;
            }
        }
    }
    return worst;
}

int spectrum_export_csv(spectrum_scan_t* scan, char* buf, uint32_t max_len) {
    int pos = snprintf(buf, max_len, "ARFCN,Freq_MHz,Band,RSSI_dBm,NoiseFloor_dBm,Occupied\n");
    for (uint16_t i = 0; i < scan->channel_count && pos < max_len - 64; i++) {
        spectrum_channel_t* ch = &scan->channels[i];
        pos += snprintf(buf + pos, max_len - pos, "%d,%.1f,%d,%d,%d,%s\n",
                       ch->arfcn, ch->freq_mhz, ch->band, ch->rssi_dbm,
                       ch->noise_floor_dbm, ch->occupied ? "YES" : "NO");
    }
    return pos;
}

void spectrum_print_summary(spectrum_scan_t* scan) {
    LOGI("=== Spectrum Scan Summary ===");
    LOGI("Total channels: %d", scan->channel_count);
    LOGI("Best ARFCN: %d (%.1f MHz)", scan->best_arfcn, scan->best_freq_mhz);

    /* Count clear channels */
    int clear = 0;
    for (uint16_t i = 0; i < scan->channel_count; i++) {
        if (!scan->channels[i].occupied) clear++;
    }
    LOGI("Clear channels: %d / %d (%.0f%%)",
         clear, scan->channel_count, 100.0f * clear / scan->channel_count);
    LOGI("==============================");
}
