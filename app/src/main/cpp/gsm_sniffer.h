#ifndef CELLLINK_GSM_SNIFFER_H
#define CELLLINK_GSM_SNIFFER_H

#include "diag.h"
#include "gsm_common.h"
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SNIFFER_MAX_PACKET        256
#define SNIFFER_MAX_DECODED       4096
#define SNIFFER_LOG_BUFFER_SIZE   (64 * 1024)

/* ── Decoded GSM L3 Message ──────────────────────────────────────────── */

typedef struct {
    uint64_t timestamp_ms;
    uint8_t  pd;            /* Protocol Discriminator */
    uint8_t  msg_type;      /* Message type */
    char     msg_name[48];  /* Human-readable message name */
    uint16_t arfcn;
    uint8_t  timeslot;
    uint16_t raw_len;
    uint8_t  raw[SNIFFER_MAX_PACKET];
    char     decoded_text[512]; /* Human-readable decode */
} sniffer_packet_t;

typedef struct {
    FILE*           log_file;
    char            filename[256];
    bool            is_running;
    uint32_t        packet_count;
    uint32_t        rr_count;     /* Radio Resource messages */
    uint32_t        mm_count;     /* Mobility Management messages */
    uint32_t        cc_count;     /* Call Control messages */
    uint32_t        si_count;     /* System Information messages */
    uint8_t         last_si_type; /* Last SI message type seen */

    /* Ring buffer for recent packets */
    sniffer_packet_t ring[256];
    uint32_t         ring_pos;
} gsm_sniffer_t;

/* ── Message Type Names ──────────────────────────────────────────────── */

extern const char* GSM_RR_MSG_NAMES[];
extern const char* GSM_MM_MSG_NAMES[];
extern const char* GSM_CC_MSG_NAMES[];

/* ── API ─────────────────────────────────────────────────────────────── */

/** Create a GSM sniffer that logs to a file. */
gsm_sniffer_t* sniffer_create(const char* filename);

/** Free sniffer resources. */
void sniffer_free(gsm_sniffer_t* sn);

/** Start sniffing (opens log file). */
int sniffer_start(gsm_sniffer_t* sn);

/** Stop sniffing (closes log file). */
int sniffer_stop(gsm_sniffer_t* sn);

/**
 * Feed a raw GSM L3 message to the sniffer for decoding.
 * Returns the decoded packet, or NULL if decoding fails.
 */
sniffer_packet_t* sniffer_feed(gsm_sniffer_t* sn, const uint8_t* data, uint16_t len,
                               uint16_t arfcn, uint8_t timeslot);

/**
 * Decode a single GSM L3 message into human-readable text.
 */
int sniffer_decode_l3(const uint8_t* data, uint16_t len, char* out, uint16_t max_len);

/**
 * Get message type name for a protocol discriminator + message type.
 */
const char* sniffer_msg_name(uint8_t pd, uint8_t msg_type);

/**
 * Capture raw L3 messages from the modem's DIAG log stream.
 * Qualcomm DIAG log code 0x1B0C = GSM L3 signaling.
 * Returns number of packets captured.
 */
int sniffer_capture_from_modem(gsm_sniffer_t* sn, diag_handle_t* h);

/**
 * Get packet count statistics.
 */
void sniffer_stats(gsm_sniffer_t* sn, uint32_t* total, uint32_t* rr, uint32_t* mm,
                   uint32_t* cc, uint32_t* si);

#ifdef __cplusplus
}
#endif

#endif /* CELLLINK_GSM_SNIFFER_H */
