#include "gsm_common.h"
#include <string.h>
#include <stdio.h>

/* ── ARFCN to Frequency Conversion ───────────────────────────────────── */

bool gsm_arfcn_to_freq(uint16_t arfcn, gsm_band_t band, float* ul_mhz, float* dl_mhz) {
    switch (band) {
        case GSM_BAND_850:
            if (arfcn < 128 || arfcn > 251) return false;
            *ul_mhz = 824.2f + 0.2f * (arfcn - 128);
            *dl_mhz = *ul_mhz + 45.0f;
            return true;

        case GSM_BAND_900: {
            /* P-GSM: ARFCN 1-124 */
            if (arfcn >= 1 && arfcn <= 124) {
                *ul_mhz = 890.0f + 0.2f * arfcn;
                *dl_mhz = *ul_mhz + 45.0f;
                return true;
            }
            /* E-GSM: ARFCN 0, 975-1023 */
            if (arfcn == 0) {
                *ul_mhz = 890.0f;
                *dl_mhz = 935.0f;
                return true;
            }
            if (arfcn >= 975 && arfcn <= 1023) {
                *ul_mhz = 890.0f + 0.2f * (arfcn - 1024);
                *dl_mhz = *ul_mhz + 45.0f;
                return true;
            }
            return false;
        }

        case GSM_BAND_1800:
            if (arfcn < 512 || arfcn > 885) return false;
            *ul_mhz = 1710.2f + 0.2f * (arfcn - 512);
            *dl_mhz = *ul_mhz + 95.0f;
            return true;

        case GSM_BAND_1900:
            if (arfcn < 512 || arfcn > 810) return false;
            *ul_mhz = 1850.2f + 0.2f * (arfcn - 512);
            *dl_mhz = *ul_mhz + 80.0f;
            return true;

        default:
            return false;
    }
}

gsm_band_t gsm_get_band_for_arfcn(uint16_t arfcn) {
    if (arfcn >= 128 && arfcn <= 251) return GSM_BAND_850;
    if (arfcn >= 1 && arfcn <= 124)   return GSM_BAND_900;
    if (arfcn == 0 || (arfcn >= 975 && arfcn <= 1023)) return GSM_BAND_900;
    if (arfcn >= 512 && arfcn <= 885) return GSM_BAND_1800;
    if (arfcn >= 512 && arfcn <= 810) return GSM_BAND_1900;
    return GSM_BAND_900; /* Default fallback */
}

gsm_channel_t gsm_get_channel_info(uint16_t arfcn) {
    gsm_channel_t ch;
    memset(&ch, 0, sizeof(ch));
    ch.band = gsm_get_band_for_arfcn(ch.arfcn = arfcn);
    gsm_arfcn_to_freq(arfcn, ch.band, &ch.ul_freq_mhz, &ch.dl_freq_mhz);

    switch (ch.band) {
        case GSM_BAND_850:  ch.arfcn_range[0] = 128; ch.arfcn_range[1] = 251; break;
        case GSM_BAND_900:  ch.arfcn_range[0] = 1;   ch.arfcn_range[1] = 124; break;
        case GSM_BAND_1800: ch.arfcn_range[0] = 512; ch.arfcn_range[1] = 885; break;
        case GSM_BAND_1900: ch.arfcn_range[0] = 512; ch.arfcn_range[1] = 810; break;
    }

    return ch;
}

/* ── LAI / CI Builders ───────────────────────────────────────────────── */

void gsm_build_lai(uint8_t* out, uint16_t mcc, uint16_t mnc, uint16_t lac) {
    /* MCC: 3 BCD digits */
    out[0] = (uint8_t)((mcc % 10) | (((mcc / 10) % 10) << 4));
    out[1] = (uint8_t)(((mcc / 100) % 10) | 0xF0);

    /* MNC: 2 BCD digits */
    out[2] = (uint8_t)((mnc % 10) | (((mnc / 10) % 10) << 4));

    /* LAC: 2 bytes little-endian */
    out[3] = (uint8_t)(lac & 0xFF);
    out[4] = (uint8_t)((lac >> 8) & 0xFF);
}

void gsm_build_ci(uint8_t* out, uint16_t ci) {
    out[0] = (uint8_t)(ci & 0xFF);
    out[1] = (uint8_t)((ci >> 8) & 0xFF);
}

void gsm_build_chan_desc(uint8_t* out, uint16_t arfcn, uint8_t timeslot, uint8_t training_seq) {
    /* Channel Description IE (GSM 04.08 §10.5.2.5) */
    /* Byte 0: Channel type + TDMA offset */
    out[0] = 0x01;  /* SDCCH/4 + SACCH/C4 */
    /* Byte 1: TN(3) | TSC(3) | H(1) | ARFCN high(1) */
    out[1] = (uint8_t)((timeslot & 0x07) | ((training_seq & 0x07) << 3));
    /* Byte 2: ARFCN low 8 bits */
    out[2] = (uint8_t)(arfcn & 0xFF);
}

uint8_t gsm_imsi_to_bcd(const char* imsi_str, uint8_t* out) {
    size_t len = strlen(imsi_str);
    if (len > 15) len = 15;

    /* First byte: identity digit 1 | odd/even | type */
    bool odd = (len % 2 == 1);
    out[0] = (uint8_t)((imsi_str[0] - '0') | (odd ? 0x08 : 0x00) | 0x10); /* Type: IMSI (001) */

    uint8_t idx = 1;
    for (size_t i = 1; i < len; i += 2) {
        if (i + 1 < len) {
            out[idx++] = (uint8_t)((imsi_str[i + 1] - '0') << 4 | (imsi_str[i] - '0'));
        } else {
            out[idx++] = (uint8_t)(0xF0 | (imsi_str[i] - '0'));
        }
    }
    return idx;
}
