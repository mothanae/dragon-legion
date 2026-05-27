#include "gsm_sniffer.h"
#include "diag.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <android/log.h>

#define LOG_TAG "CellLink-SNIFF"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

/* ── Message Name Tables ─────────────────────────────────────────────── */

const char* GSM_RR_MSG_NAMES[256] = {
    [0x19] = "System Information Type 1",
    [0x1A] = "System Information Type 2",
    [0x1B] = "System Information Type 3",
    [0x1C] = "System Information Type 4",
    [0x1D] = "System Information Type 5",
    [0x1E] = "System Information Type 6",
    [0x05] = "System Information Type 13",
    [0x38] = "Channel Request",
    [0x3F] = "Immediate Assignment",
    [0x3A] = "Immediate Assignment Extended",
    [0x3B] = "Immediate Assignment Reject",
    [0x21] = "Paging Request Type 1",
    [0x22] = "Paging Request Type 2",
    [0x23] = "Paging Request Type 3",
    [0x27] = "Packet Downlink Assignment",
    [0x28] = "Packet Uplink Assignment",
    [0x29] = "Packet Downlink Ack/Nack",
    [0x2A] = "Packet Uplink Ack/Nack",
    [0x3C] = "Additional Assignment",
    [0x24] = "Notification/FACCH",
    [0x12] = "Assignment Command",
    [0x13] = "Assignment Complete",
    [0x14] = "Assignment Failure",
    [0x15] = "Handover Command",
    [0x16] = "Handover Complete",
    [0x17] = "Handover Failure",
    [0x18] = "Handover Access",
    [0x01] = "Channel Mode Modify",
    [0x02] = "Channel Mode Modify Acknowledge",
    [0x03] = "Frequency Redefinition",
    [0x04] = "Measurement Report",
    [0x06] = "Classmark Change",
    [0x07] = "Classmark Enquiry",
    [0x11] = "Ciphering Mode Command",
    [0x10] = "Ciphering Mode Complete",
    [0x35] = "Physical Information",
    [0x34] = "RR Status",
    [0x0F] = "Partial Release",
    [0x0E] = "Partial Release Complete",
    [0x08] = "GPRS Suspension Request",
    [0x09] = "GPRS Resumption",
    [0x25] = "PDCH Release",
    [0x26] = "Packet Cell Change Order",
    [0x2E] = "Packet Measurement Report",
    [0x2F] = "Packet Measurement Order",
    [0x30] = "Packet SI Status",
    [0x32] = "Packet TBF Release",
    [0x33] = "Packet Control Acknowledgement",
    [0x37] = "EGPRS Packet Downlink Ack/Nack",
    [0x39] = "EGPRS Packet Uplink Ack/Nack",
};

const char* GSM_MM_MSG_NAMES[256] = {
    [0x01] = "IMSI Detach Indication",
    [0x02] = "Location Updating Accept",
    [0x03] = "Location Updating Reject",
    [0x04] = "Location Updating Request",
    [0x08] = "Location Updating Request (periodic)",
    [0x11] = "Authentication Request",
    [0x12] = "Authentication Response",
    [0x13] = "Authentication Reject",
    [0x14] = "Authentication Failure",
    [0x18] = "Identity Request",
    [0x19] = "Identity Response",
    [0x21] = "TMSI Reallocation Command",
    [0x22] = "TMSI Reallocation Complete",
    [0x28] = "CM Service Accept",
    [0x29] = "CM Service Reject",
    [0x2A] = "CM Service Abort",
    [0x2B] = "CM Service Request",
    [0x2C] = "CM Service Prompt",
    [0x31] = "CM Re-establishment Request",
    [0x38] = "MM Status",
    [0x39] = "MM Information",
    [0x40] = "GPRS Attach Request",
    [0x41] = "GPRS Attach Accept",
    [0x42] = "GPRS Attach Complete",
    [0x43] = "GPRS Attach Reject",
    [0x44] = "GPRS Detach Request",
    [0x45] = "GPRS Detach Accept",
    [0x46] = "GPRS Detach Indication",
    [0x47] = "GPRS Routing Area Update Request",
    [0x48] = "GPRS Routing Area Update Accept",
    [0x49] = "GPRS Routing Area Update Complete",
    [0x4A] = "GPRS Routing Area Update Reject",
    [0x4B] = "GPRS Service Request",
    [0x4C] = "GPRS PTM SERVICE REQUEST",
};

const char* GSM_CC_MSG_NAMES[256] = {
    [0x01] = "Alerting",
    [0x02] = "Call Proceeding",
    [0x03] = "Progress",
    [0x05] = "Setup",
    [0x07] = "Connect",
    [0x08] = "Call Confirmed",
    [0x0F] = "Connect Acknowledge",
    [0x22] = "Modify",
    [0x23] = "Modify Complete",
    [0x24] = "Modify Reject",
    [0x25] = "Disconnect",
    [0x2D] = "Release",
    [0x2A] = "Release Complete",
    [0x34] = "Facility",
    [0x36] = "Hold",
    [0x31] = "Hold Acknowledge",
    [0x38] = "Hold Reject",
    [0x3A] = "Retrieve",
    [0x33] = "Retrieve Acknowledge",
    [0x3C] = "Retrieve Reject",
    [0x39] = "User Information",
    [0x0C] = "Congestion Control",
    [0x3D] = "Notify",
    [0x3E] = "Status",
    [0x3F] = "Status Enquiry",
    [0x11] = "Start DTMF",
    [0x12] = "Stop DTMF",
    [0x13] = "Start DTMF Acknowledge",
    [0x14] = "Stop DTMF Acknowledge",
    [0x15] = "Start DTMF Reject",
};

/* ── Public API ───────────────────────────────────────────────────────── */

static uint64_t get_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

const char* sniffer_msg_name(uint8_t pd, uint8_t msg_type) {
    const char* name = NULL;
    switch (pd) {
        case GSM_PD_RR: name = GSM_RR_MSG_NAMES[msg_type]; break;
        case GSM_PD_MM: name = GSM_MM_MSG_NAMES[msg_type]; break;
        case GSM_PD_CC: name = GSM_CC_MSG_NAMES[msg_type]; break;
    }
    return name ? name : "Unknown";
}

gsm_sniffer_t* sniffer_create(const char* filename) {
    gsm_sniffer_t* sn = (gsm_sniffer_t*)calloc(1, sizeof(gsm_sniffer_t));
    if (!sn) return NULL;

    if (filename) {
        strncpy(sn->filename, filename, sizeof(sn->filename) - 1);
    } else {
        time_t now = time(NULL);
        snprintf(sn->filename, sizeof(sn->filename),
                "/sdcard/CellLink/gsm_sniff_%lld.pcap", (long long)now);
    }
    return sn;
}

void sniffer_free(gsm_sniffer_t* sn) {
    if (!sn) return;
    if (sn->is_running) sniffer_stop(sn);
    free(sn);
}

int sniffer_start(gsm_sniffer_t* sn) {
    if (!sn) return -1;
    sn->log_file = fopen(sn->filename, "wb");
    if (!sn->log_file) return -1;

    /* Write GSM sniff log header */
    fprintf(sn->log_file, "# CellLink GSM Sniffer Log\n");
    fprintf(sn->log_file, "# Format: timestamp_ms,ARFCN,TS,PD,MsgType,Name,HexData\n");
    fflush(sn->log_file);

    sn->is_running = true;
    sn->packet_count = 0;
    LOGI("GSM sniffer started: %s", sn->filename);
    return 0;
}

int sniffer_stop(gsm_sniffer_t* sn) {
    if (!sn || !sn->is_running) return -1;
    sn->is_running = false;

    if (sn->log_file) {
        fprintf(sn->log_file, "# Total packets: %u (RR=%u MM=%u CC=%u SI=%u)\n",
                sn->packet_count, sn->rr_count, sn->mm_count,
                sn->cc_count, sn->si_count);
        fclose(sn->log_file);
        sn->log_file = NULL;
    }

    LOGI("GSM sniffer stopped: %u packets", sn->packet_count);
    return 0;
}

sniffer_packet_t* sniffer_feed(gsm_sniffer_t* sn, const uint8_t* data, uint16_t len,
                               uint16_t arfcn, uint8_t timeslot) {
    if (!sn || !data || len < 3) return NULL;

    /* Parse L3 header */
    uint8_t pd = data[1] & 0x0F; /* Protocol discriminator (skip L2 pseudo-length) */
    uint8_t msg_type = data[2] & 0xFF;

    /* Store in ring buffer */
    sniffer_packet_t* pkt = &sn->ring[sn->ring_pos];
    sn->ring_pos = (sn->ring_pos + 1) % 256;

    pkt->timestamp_ms = get_ms();
    pkt->pd = pd;
    pkt->msg_type = msg_type;
    pkt->arfcn = arfcn;
    pkt->timeslot = timeslot;
    pkt->raw_len = len < SNIFFER_MAX_PACKET ? len : SNIFFER_MAX_PACKET;
    memcpy(pkt->raw, data, pkt->raw_len);

    /* Get message name */
    const char* name = sniffer_msg_name(pd, msg_type);
    snprintf(pkt->msg_name, sizeof(pkt->msg_name), "[%s] %s",
             (pd == GSM_PD_RR) ? "RR" : (pd == GSM_PD_MM) ? "MM" : (pd == GSM_PD_CC) ? "CC" : "??",
             name);

    /* Decode to text */
    sniffer_decode_l3(data, len, pkt->decoded_text, sizeof(pkt->decoded_text));

    /* Update stats */
    sn->packet_count++;
    switch (pd) {
        case GSM_PD_RR:
            sn->rr_count++;
            if (msg_type >= 0x19 && msg_type <= 0x1E) {
                sn->si_count++;
                sn->last_si_type = msg_type;
            }
            break;
        case GSM_PD_MM: sn->mm_count++; break;
        case GSM_PD_CC: sn->cc_count++; break;
    }

    /* Log to file */
    if (sn->log_file) {
        fprintf(sn->log_file, "%llu,%u,%u,%u,%u,%s,",
                (unsigned long long)pkt->timestamp_ms, arfcn, timeslot,
                pd, msg_type, name);
        for (uint16_t i = 0; i < pkt->raw_len && i < 64; i++) {
            fprintf(sn->log_file, "%02X", pkt->raw[i]);
        }
        fprintf(sn->log_file, "\n");
        fflush(sn->log_file);
    }

    LOGD("Sniff: ARFCN=%d TS=%d PD=%d Type=0x%02X %s",
         arfcn, timeslot, pd, msg_type, name);
    return pkt;
}

int sniffer_decode_l3(const uint8_t* data, uint16_t len, char* out, uint16_t max_len) {
    if (len < 3) return snprintf(out, max_len, "Too short (%d bytes)", len);

    uint8_t pd = data[1] & 0x0F;
    uint8_t mt = data[2] & 0xFF;
    const char* name = sniffer_msg_name(pd, mt);

    int pos = snprintf(out, max_len, "PD=%d (%s) MT=0x%02X (%s) ",
                       pd,
                       (pd == GSM_PD_RR) ? "RR" : (pd == GSM_PD_MM) ? "MM" : (pd == GSM_PD_CC) ? "CC" : "?",
                       mt, name);

    /* Add hex dump */
    pos += snprintf(out + pos, max_len - pos, "Raw[%d]: ", len);
    for (uint16_t i = 0; i < len && pos < max_len - 4; i++) {
        pos += snprintf(out + pos, max_len - pos, "%02X ", data[i]);
    }

    return pos;
}

int sniffer_capture_from_modem(gsm_sniffer_t* sn, diag_handle_t* h) {
    if (!sn || !h || !sn->is_running) return 0;

    /* Poll for GSM L3 DIAG log packets */
    /* Qualcomm DIAG log code 0x1B0C: GSM Signaling messages */
    uint8_t buf[DIAG_MAX_PAYLOAD];
    uint8_t cmd;
    int n = diag_recv(h, &cmd, buf, sizeof(buf), 50);
    if (n < 10) return 0;

    if (cmd == DIAG_CMD_EVENT_REPORT_F) {
        uint16_t log_code = (uint16_t)buf[0] | ((uint16_t)buf[1] << 8);

        /* GSM L3 signaling log codes */
        if (log_code == 0x1B0C || log_code == 0x1B0D || log_code == 0x1B0E ||
            log_code == 0x1526 || log_code == 0x1527) {

            /* Extract GSM frame info */
            uint16_t arfcn = (uint16_t)buf[4] | ((uint16_t)buf[5] << 8);
            uint8_t ts = buf[6] & 0x07;

            /* L3 message starts at offset 10 */
            sniffer_feed(sn, buf + 10, (uint16_t)(n - 10), arfcn, ts);
            return 1;
        }
    }

    return 0;
}

void sniffer_stats(gsm_sniffer_t* sn, uint32_t* total, uint32_t* rr, uint32_t* mm,
                   uint32_t* cc, uint32_t* si) {
    if (!sn) return;
    if (total) *total = sn->packet_count;
    if (rr) *rr = sn->rr_count;
    if (mm) *mm = sn->mm_count;
    if (cc) *cc = sn->cc_count;
    if (si) *si = sn->si_count;
}
