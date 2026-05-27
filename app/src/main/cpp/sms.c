#include "sms.h"
#include "qmi.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <android/log.h>

#define LOG_TAG "CellLink-SMS"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

/* ── GSM 7-bit Default Alphabet ──────────────────────────────────────── */
/* Characters 0x00-0x7F of the GSM 03.38 default alphabet */
static const uint16_t gsm7_chars[128] = {
    '@', 0xA3, '$', 0xA5, 0xE8, 0xE9, 0xF9, 0xEC, 0xF2, 0xC7, '\n', 0xD8, 0xF8, '\r', 0xC5, 0xE5,
    0x394, '_', 0x3A6, 0x393, 0x39B, 0x3A9, 0x3A0, 0x3A8, 0x3A3, 0x398, 0x39E, 0x1B, 0xC6, 0xE6, 0xDF, 0xC9,
    ' ', '!', '"', '#', 0xA4, '%', '&', '\'', '(', ')', '*', '+', ',', '-', '.', '/',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ':', ';', '<', '=', '>', '?',
    0xA1, 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
    'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 0xC4, 0xD6, 0xD1, 0xDC, 0xA7,
    0xBF, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
    'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 0xE4, 0xF6, 0xF1, 0xFC, 0xE0
};

/* Reverse lookup: char -> GSM7 septet value, 0xFF if not found */
static uint8_t char_to_gsm7(uint16_t ch) {
    if (ch == 0x000C) return 0x0A; /* Form feed -> LF mapping */
    if (ch == '^') return 0x14;    /* Caret -> diaeresis */
    for (int i = 0; i < 128; i++) {
        if (gsm7_chars[i] == ch) return (uint8_t)i;
    }
    return 0xFF;
}

/* Extension table (0x1B prefix) characters */
static uint16_t gsm7_ext[128] = {0};
static bool gsm7_ext_init = false;

static void init_gsm7_ext(void) {
    if (gsm7_ext_init) return;
    gsm7_ext[0x0A] = '\f';  /* Form feed */
    gsm7_ext[0x14] = '^';   /* Circumflex */
    gsm7_ext[0x28] = '{';
    gsm7_ext[0x29] = '}';
    gsm7_ext[0x2F] = '\\';
    gsm7_ext[0x3C] = '[';
    gsm7_ext[0x3D] = '~';
    gsm7_ext[0x3E] = ']';
    gsm7_ext[0x40] = '|';
    gsm7_ext[0x65] = 0x20AC; /* Euro sign */
    gsm7_ext_init = true;
}

/* ── 7-Bit Encoding / Decoding ───────────────────────────────────────── */

uint8_t sms_encode_7bit(const char* text, uint16_t text_len, uint8_t* out) {
    if (text_len > 160) text_len = 160;

    uint8_t septets[160];
    uint16_t s = 0;

    for (uint16_t i = 0; i < text_len; i++) {
        uint16_t ch = (uint8_t)text[i];
        uint8_t val = char_to_gsm7(ch);
        if (val == 0xFF) {
            /* Try extension table */
            init_gsm7_ext();
            for (int j = 0; j < 128; j++) {
                if (gsm7_ext[j] == ch) {
                    septets[s++] = 0x1B; /* ESC */
                    septets[s++] = (uint8_t)j;
                    break;
                }
            }
            if (val == 0xFF) { septets[s++] = 0x3F; } /* '?' fallback */
        } else {
            septets[s++] = val;
        }
    }

    /* Pack septets into octets */
    memset(out, 0, ((s * 7) + 7) / 8);
    for (uint16_t i = 0; i < s; i++) {
        uint16_t bit_pos = (i * 7) % 8;
        uint16_t byte_pos = (i * 7) / 8;
        uint8_t val = septets[i] & 0x7F;

        out[byte_pos] |= (val << bit_pos) & 0xFF;
        if (bit_pos > 1) {
            out[byte_pos + 1] |= (val >> (8 - bit_pos));
        }
    }

    return ((s * 7) + 7) / 8;
}

uint16_t sms_decode_7bit(const uint8_t* packed, uint8_t packed_len, uint16_t septet_count, char* out) {
    init_gsm7_ext();
    uint16_t s = 0;

    for (uint16_t i = 0; i < septet_count && s < 160; i++) {
        uint16_t bit_pos = (i * 7) % 8;
        uint16_t byte_pos = (i * 7) / 8;
        uint8_t val;

        if (byte_pos >= packed_len) break;
        val = (packed[byte_pos] >> bit_pos) & 0x7F;

        if (bit_pos > 1 && byte_pos + 1 < packed_len) {
            val |= (packed[byte_pos + 1] << (8 - bit_pos)) & 0x7F;
        }

        if (val == 0x1B) {
            /* Extension character — next septet is extended */
            i++;
            bit_pos = (i * 7) % 8;
            byte_pos = (i * 7) / 8;
            if (byte_pos >= packed_len) break;
            val = (packed[byte_pos] >> bit_pos) & 0x7F;
            if (bit_pos > 1 && byte_pos + 1 < packed_len) {
                val |= (packed[byte_pos + 1] << (8 - bit_pos)) & 0x7F;
            }
            uint16_t ext_ch = (val < 128 && gsm7_ext[val]) ? gsm7_ext[val] : '?';
            if (ext_ch <= 0x7F) {
                out[s++] = (char)ext_ch;
            } else if (ext_ch == 0x20AC) {
                /* Euro sign -> UTF-8 */
                out[s++] = (char)0xE2;
                out[s++] = (char)0x82;
                out[s++] = (char)0xAC;
            } else {
                /* Other unicode -> '?' */
                out[s++] = '?';
            }
        } else {
            uint16_t ch = (val < 128) ? gsm7_chars[val] : '?';
            if (ch <= 0x7F) {
                out[s++] = (char)ch;
            } else if (ch <= 0x7FF) {
                out[s++] = (char)(0xC0 | (ch >> 6));
                out[s++] = (char)(0x80 | (ch & 0x3F));
            } else {
                out[s++] = (char)(0xE0 | (ch >> 12));
                out[s++] = (char)(0x80 | ((ch >> 6) & 0x3F));
                out[s++] = (char)(0x80 | (ch & 0x3F));
            }
        }
    }

    out[s] = '\0';
    return s;
}

bool sms_needs_ucs2(const char* text, uint16_t len) {
    for (uint16_t i = 0; i < len; i++) {
        if ((uint8_t)text[i] > 0x7F) return true;
    }
    return false;
}

/* ── Address BCD Encoding ────────────────────────────────────────────── */

uint8_t sms_addr_to_bcd(const char* addr, uint8_t* out_bcd, uint8_t* out_type) {
    size_t len = strlen(addr);
    *out_type = 0x81; /* National number, ISDN/telephony numbering plan */

    /* If starts with +, it's international */
    if (addr[0] == '+') {
        *out_type = 0x91; /* International */
        addr++;
        len--;
    }

    memset(out_bcd, 0, 10);
    for (size_t i = 0; i < len && i < 20; i++) {
        uint8_t digit = addr[i] - '0';
        if (digit > 9) digit = 0;
        if (i % 2 == 0) {
            out_bcd[i / 2] = digit & 0x0F;
        } else {
            out_bcd[i / 2] |= (digit << 4) & 0xF0;
        }
    }
    if (len % 2 == 1) {
        out_bcd[len / 2] |= 0xF0;
    }

    return (uint8_t)len;
}

void sms_bcd_to_addr(const uint8_t* bcd, uint8_t bcd_len, uint8_t addr_type, char* out) {
    bool international = (addr_type == 0x91);
    uint16_t pos = 0;

    if (international) out[pos++] = '+';

    for (uint8_t i = 0; i < bcd_len; i++) {
        uint8_t lo = bcd[i / 2] & 0x0F;
        uint8_t hi = (bcd[i / 2] >> 4) & 0x0F;
        out[pos++] = (i % 2 == 0) ? (char)('0' + lo) : (char)('0' + hi);
    }
    out[pos] = '\0';
}

/* ── SMSC Address ────────────────────────────────────────────────────── */

static uint8_t put_sc_addr(uint8_t* out) {
    /* Empty SMSC address (use modem default) */
    out[0] = 0x00;
    return 1;
}

/* ── Build SMS-SUBMIT ────────────────────────────────────────────────── */

uint8_t sms_build_submit(const char* recipient, const char* text,
                         uint8_t msg_ref, sms_submit_t* out) {
    memset(out, 0, sizeof(*out));

    /* SMSC address (empty = use default) */
    uint8_t sca_offset = 1; /* Skip 0x00 SMSC len byte in TPDU context */

    /* First octet: SMS-SUBMIT, no flags */
    out->first_octet = SMS_MTI_SUBMIT;

    /* Message Reference */
    out->mr = msg_ref;

    /* Destination address */
    out->da_len = sms_addr_to_bcd(recipient, out->da_digits, &out->da_type);

    /* Protocol Identifier: SME-to-SME */
    out->pid = 0x00;

    /* Data Coding Scheme */
    uint16_t text_len = strlen(text);
    if (sms_needs_ucs2(text, text_len)) {
        out->dcs = 0x08; /* UCS-2 */
        uint8_t* ud = out->ud;
        for (uint16_t i = 0; i < text_len && i < 70; i++) {
            ud[i * 2] = (uint8_t)(text[i] >> 8);
            ud[i * 2 + 1] = (uint8_t)(text[i] & 0xFF);
        }
        out->udl = text_len * 2;
    } else {
        out->dcs = 0x00; /* GSM 7-bit default alphabet */
        out->udl = sms_encode_7bit(text, text_len, out->ud);
    }

    /* Validity Period: 24 hours (relative format) */
    out->vp = 0xA7; /* (VP + 1) * 5 minutes => 168 * 5 = 840 min = 14h... actually 167 = 835 min ~14h */
    /* For ~24h: 288 * 5 = 1440 min = 24h, VP = 287 = 0x11F... doesn't fit in 1 byte */
    /* Use enhanced format: 0xA0 + 0x07 = 24h */
    out->vp = 0xA7; /* Reasonable compromise */

    /* Compute total TPDU length (excluding SMSC prefix) */
    /* = 1(first) + 1(mr) + 1(da_len) + 1(da_type) + ceil(da_len/2) + 1(pid) + 1(dcs) + 1(vp) + 1(udl) + udl_bytes */
    uint8_t da_bcd_bytes = (out->da_len + 1) / 2;
    uint8_t ud_bytes = out->udl;
    return 1 + 1 + 1 + 1 + da_bcd_bytes + 1 + 1 + 1 + 1 + ud_bytes;
}

/* ── Parse SMS-DELIVER ───────────────────────────────────────────────── */

bool sms_parse_deliver(const uint8_t* tpdu, uint16_t len, sms_message_t* out) {
    if (!tpdu || len < 10) return false;
    memset(out, 0, sizeof(*out));
    out->is_incoming = true;

    uint16_t off = 0;

    /* SMSC address */
    uint8_t sca_len = tpdu[off++];
    if (sca_len > 0) {
        sms_bcd_to_addr(tpdu + off + 1, sca_len, tpdu[off] & 0x70, out->sender);
        off += 1 + sca_len;
    }

    /* First octet */
    uint8_t fo = tpdu[off++];

    /* Originating address */
    uint8_t oa_len = tpdu[off++];
    uint8_t oa_type = tpdu[off++];
    sms_bcd_to_addr(tpdu + off, oa_len, oa_type, out->sender);
    off += (oa_len + 1) / 2;

    /* PID */
    uint8_t pid = tpdu[off++];

    /* DCS */
    out->dcs = tpdu[off++];

    /* SCTS — 7 bytes: YY MM DD HH MM SS TZ */
    uint8_t scts[7];
    memcpy(scts, tpdu + off, 7);
    off += 7;

    /* Convert SCTS to Unix-ish timestamp (simplified) */
    struct tm tm_scts = {0};
    tm_scts.tm_year = ((scts[0] & 0x0F) * 10 + ((scts[0] >> 4) & 0x0F)) + 100; /* Years since 1900 */
    tm_scts.tm_mon  = ((scts[1] & 0x0F) * 10 + ((scts[1] >> 4) & 0x0F)) - 1;
    tm_scts.tm_mday = ((scts[2] & 0x0F) * 10 + ((scts[2] >> 4) & 0x0F));
    tm_scts.tm_hour = ((scts[3] & 0x0F) * 10 + ((scts[3] >> 4) & 0x0F));
    tm_scts.tm_min  = ((scts[4] & 0x0F) * 10 + ((scts[4] >> 4) & 0x0F));
    tm_scts.tm_sec  = ((scts[5] & 0x0F) * 10 + ((scts[5] >> 4) & 0x0F));
    out->timestamp = (uint64_t)mktime(&tm_scts);

    /* UDL */
    out->text_len = tpdu[off++];

    /* Decode user data */
    if (out->dcs == 0x00 || (out->dcs & 0x0C) == 0x00) {
        /* GSM 7-bit */
        uint16_t septets = (out->text_len * 8 + 6) / 7;
        out->text_len = sms_decode_7bit(tpdu + off, len - off, septets, out->text);
    } else if ((out->dcs & 0x0C) == 0x08) {
        /* UCS-2 — simple ASCII subset for now */
        uint8_t ud_len = out->text_len;
        if (ud_len > 160) ud_len = 160;
        for (uint16_t i = 0; i < ud_len; i++) {
            out->text[i] = (tpdu[off + i] >= 0x20 && tpdu[off + i] < 0x7F) ? (char)tpdu[off + i] : '?';
        }
        out->text[ud_len] = '\0';
        out->text_len = ud_len;
    }

    return true;
}

/* ── AT Command SMS Interface ────────────────────────────────────────── */

int sms_send_at(diag_handle_t* h, const char* recipient, const char* text) {
    /* Build SMS-SUBMIT PDU */
    sms_submit_t submit;
    static uint8_t msg_ref = 0;
    uint8_t tpdu_len = sms_build_submit(recipient, text, msg_ref++, &submit);

    /* AT+CMGS flow: set text mode, send PDU */
    /* Step 1: Set PDU mode */
    char rsp[512];
    diag_at_command(h, "+CMGF=0", rsp, sizeof(rsp)); /* PDU mode */

    /* Step 2: Send CMGS with PDU length */
    /* The PDU includes SMSC header (1 byte zero) + TPDU */
    char cmgs[64];
    snprintf(cmgs, sizeof(cmgs), "+CMGS=%d", tpdu_len);
    int n = diag_at_command(h, cmgs, rsp, sizeof(rsp));
    if (n < 0 || !strstr(rsp, ">")) {
        LOGE("AT+CMGS prompt not received");
        return -1;
    }

    /* Step 3: Send PDU bytes hex-encoded + CTRL-Z */
    char pdu_hex[SMS_MAX_CMGS_LENGTH];
    uint16_t hex_pos = 0;
    /* SMSC address length (zero = default) */
    pdu_hex[hex_pos++] = '0';
    pdu_hex[hex_pos++] = '0';

    /* Encode TPDU as hex */
    uint8_t* tpdu = (uint8_t*)&submit;
    for (uint8_t i = 0; i < tpdu_len; i++) {
        hex_pos += snprintf(pdu_hex + hex_pos, sizeof(pdu_hex) - hex_pos,
                           "%02X", tpdu[i]);
    }
    pdu_hex[hex_pos++] = 0x1A; /* CTRL-Z */

    /* Write the PDU directly (not via AT command parser) */
    diag_raw_write(h, (const uint8_t*)pdu_hex, hex_pos);

    /* Read response */
    uint8_t result[256] = {0};
    int rn = diag_raw_read(h, result, sizeof(result), 10000);
    if (rn > 0 && (strstr((char*)result, "+CMGS:") || strstr((char*)result, "OK"))) {
        LOGI("SMS sent via AT+CMGS to %s", recipient);
        return 0;
    }
    if (rn > 0) LOGD("CMGS response: %s", (char*)result);

    return -1;
}

int sms_send_qmi(diag_handle_t* h, const char* recipient, const char* text) {
    sms_submit_t submit;
    static uint8_t msg_ref = 0;
    sms_build_submit(recipient, text, msg_ref++, &submit);

    /* Build QMI WMS raw send request */
    uint8_t req[DIAG_MAX_PAYLOAD];
    uint16_t rl = 0;

    /* TLV 0x01: message format (0x02 = GSM 7-bit, 0x04 = UCS-2, 0x06 = 8-bit) */
    rl += tlv_put_u8(req + rl, 0x01, 0x02);

    /* TLV 0x02: CDMA service option (skip for GSM) */

    /* TLV 0x10: raw message data */
    uint8_t msg_data[512];
    uint16_t msg_len = 0;
    /* PDU: SMSC length (0) + TPDU */
    msg_data[msg_len++] = 0x00;
    uint8_t* tpdu_bytes = (uint8_t*)&submit;
    for (uint8_t i = 0; i < sizeof(sms_submit_t); i++) {
        msg_data[msg_len++] = tpdu_bytes[i];
    }
    rl += tlv_put(req + rl, 0x10, msg_data, msg_len);

    /* TLV 0x11: message length */
    rl += tlv_put_u16(req + rl, 0x11, msg_len);

    uint8_t rsp[DIAG_MAX_PAYLOAD];
    int n = qmi_request(h, QMI_SUBSYS_WMS, QMI_WMS_SEND_RAW, req, rl, rsp, sizeof(rsp), 15000);
    if (n < 0) {
        LOGE("QMI WMS send failed");
        return -1;
    }

    if (qmi_response_ok(rsp, n)) {
        LOGI("SMS sent via QMI WMS to %s", recipient);
        return 0;
    }
    return -1;
}

int sms_send(diag_handle_t* h, const char* recipient, const char* text) {
    /* Try AT command first (more reliable across modems) */
    if (sms_send_at(h, recipient, text) == 0) return 0;

    /* Fall back to QMI */
    LOGI("AT SMS failed, trying QMI WMS...");
    return sms_send_qmi(h, recipient, text);
}

/* ── SMS Reading ─────────────────────────────────────────────────────── */

int sms_list_received(diag_handle_t* h, sms_message_t* messages, uint8_t max_count) {
    char rsp[4096];
    /* AT+CMGL=4 lists all unread messages in PDU mode */
    diag_at_command(h, "+CMGF=0", rsp, sizeof(rsp)); /* PDU mode */

    int n = diag_at_command(h, "+CMGL=4", rsp, sizeof(rsp));
    if (n < 0) return -1;

    /* Parse CMGL response: +CMGL: <index>,<stat>,,<pdu_length>\r\n<PDU hex> */
    uint8_t count = 0;
    char* p = rsp;
    while (count < max_count && (p = strstr(p, "+CMGL:")) != NULL) {
        p += 6;
        int idx, stat, len;
        if (sscanf(p, "%d,%d,,%d", &idx, &stat, &len) != 3) continue;

        /* Find PDU hex string */
        p = strstr(p, "\n");
        if (!p) break;
        p++;
        /* Skip \r */
        if (*p == '\r') p++;
        /* Skip leading whitespace */
        while (*p == ' ' || *p == '\t') p++;

        /* Decode hex PDU to binary */
        uint8_t tpdu[SMS_MAX_TPDU_LENGTH];
        uint16_t tpdu_len = 0;
        for (int i = 0; i < len * 2 && p[i] && p[i] != '\r'; i += 2) {
            unsigned int byte;
            if (sscanf(p + i, "%02X", &byte) == 1 && tpdu_len < sizeof(tpdu)) {
                tpdu[tpdu_len++] = (uint8_t)byte;
            }
        }

        sms_parse_deliver(tpdu, tpdu_len, &messages[count]);
        count++;
        p += len * 2;
    }

    return count;
}

bool sms_read_at_index(diag_handle_t* h, uint8_t index, sms_message_t* out) {
    char cmgr[16];
    snprintf(cmgr, sizeof(cmgr), "+CMGR=%d", index);

    char rsp[2048];
    int n = diag_at_command(h, cmgr, rsp, sizeof(rsp));
    if (n < 0) return false;

    /* Parse +CMGR: <stat>,,<len>\r\n<PDU> */
    char* p = strstr(rsp, "+CMGR:");
    if (!p) return false;

    /* Find PDU hex */
    p = strstr(p + 6, "\n");
    if (!p) return false;
    p++;
    if (*p == '\r') p++;

    /* Decode */
    uint8_t tpdu[SMS_MAX_TPDU_LENGTH];
    uint16_t tpdu_len = 0;
    for (int i = 0; p[i] && p[i] != '\r' && p[i] != '\n' && tpdu_len < sizeof(tpdu); i += 2) {
        unsigned int byte;
        if (sscanf(p + i, "%02X", &byte) == 1) {
            tpdu[tpdu_len++] = (uint8_t)byte;
        }
    }

    return sms_parse_deliver(tpdu, tpdu_len, out);
}

int sms_set_sca(diag_handle_t* h, const char* sca) {
    char cmd[48];
    snprintf(cmd, sizeof(cmd), "+CSCA=\"%s\"", sca);
    char rsp[64];
    int n = diag_at_command(h, cmd, rsp, sizeof(rsp));
    return (n >= 0 && strstr(rsp, "OK")) ? 0 : -1;
}
