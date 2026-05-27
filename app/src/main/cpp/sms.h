#ifndef CELLLINK_SMS_H
#define CELLLINK_SMS_H

#include "diag.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── SMS PDU Constants ───────────────────────────────────────────────── */

#define SMS_MAX_UD_LENGTH       160   /* 7-bit encoded max chars */
#define SMS_MAX_UD_LENGTH_UCS2  70    /* UCS-2 encoded max chars */
#define SMS_MAX_TPDU_LENGTH     256   /* Max TPDU bytes */
#define SMS_MAX_CMGS_LENGTH     512   /* Max AT+CMGS command length */

/* SMS TPDU Message Type Indicators (first octet bits 0-1) */
#define SMS_MTI_DELIVER         0x00  /* SMS-DELIVER (network -> MS) */
#define SMS_MTI_SUBMIT          0x01  /* SMS-SUBMIT (MS -> network) */
#define SMS_MTI_STATUS_REPORT   0x02
#define SMS_MTI_COMMAND         0x03

/* SMS TPDU flags for SMS-SUBMIT (first octet) */
#define SMS_SUBMIT_RD           0x04  /* Reject Duplicates */
#define SMS_SUBMIT_VPF          0x10  /* Validity Period Format */
#define SMS_SUBMIT_SRR          0x20  /* Status Report Request */
#define SMS_SUBMIT_UDHI         0x40  /* User Data Header Indicator */
#define SMS_SUBMIT_RP           0x80  /* Reply Path */

/* SMS TPDU flags for SMS-DELIVER */
#define SMS_DELIVER_MMS         0x04  /* More Messages to Send */
#define SMS_DELIVER_SRI         0x20  /* Status Report Indication */
#define SMS_DELIVER_UDHI        0x40
#define SMS_DELIVER_RP          0x80

/* TP-Status values for SMS-DELIVER */
#define TP_STATUS_COMPLETED     0x00
#define TP_STATUS_PENDING       0x20
#define TP_STATUS_UNABLE        0x40

/* QMI WMS (Wireless Messaging Service) command IDs */
#define QMI_WMS_SEND_RAW        0x0020
#define QMI_WMS_GET_RAW         0x0021
#define QMI_WMS_SET_EVENT       0x0022
#define QMI_WMS_GET_ROUTE       0x0023
#define QMI_WMS_SET_ROUTE       0x0024
#define QMI_WMS_GET_CONFIG      0x0025

/* ── SMS Data Structures ──────────────────────────────────────────────── */

/** SMS-DELIVER TPDU (from network to UE) */
typedef struct __attribute__((packed)) {
    uint8_t  sc_addr_len;      /* SMSC address length */
    uint8_t  sc_addr[12];      /* SMSC address (BCD) */
    uint8_t  first_octet;      /* MTI + flags */
    uint8_t  oa_len;           /* Originating address length */
    uint8_t  oa_type;          /* Type of address */
    uint8_t  oa_digits[10];    /* Originating address digits (BCD) */
    uint8_t  pid;              /* Protocol Identifier */
    uint8_t  dcs;              /* Data Coding Scheme */
    uint8_t  scts[7];          /* Service Centre Time Stamp */
    uint8_t  udl;              /* User Data Length */
    uint8_t  ud[160];          /* User Data */
} sms_deliver_t;

/** SMS-SUBMIT TPDU (from UE to network) */
typedef struct __attribute__((packed)) {
    uint8_t  first_octet;      /* MTI + flags */
    uint8_t  mr;               /* Message Reference */
    uint8_t  da_len;           /* Destination address length */
    uint8_t  da_type;          /* Type of address */
    uint8_t  da_digits[10];    /* Destination address digits */
    uint8_t  pid;              /* Protocol Identifier */
    uint8_t  dcs;              /* Data Coding Scheme */
    uint8_t  vp;               /* Validity Period (relative) */
    uint8_t  udl;              /* User Data Length */
    uint8_t  ud[160];          /* User Data */
} sms_submit_t;

/** Parsed SMS message (decoded from PDU) */
typedef struct {
    char     sender[20];       /* Originating address as string */
    char     recipient[20];    /* Destination address as string */
    char     text[161];        /* Decoded message text */
    uint8_t  text_len;         /* Length of decoded text */
    uint8_t  dcs;              /* Data Coding Scheme */
    uint64_t timestamp;        /* Unix timestamp from SCTS */
    bool     is_incoming;      /* true = SMS-DELIVER, false = SMS-SUBMIT */
} sms_message_t;

/* ── API ──────────────────────────────────────────────────────────────── */

/** Encode a text string into 7-bit GSM alphabet packed bytes. Returns byte count. */
uint8_t sms_encode_7bit(const char* text, uint16_t text_len, uint8_t* out);

/** Decode 7-bit GSM alphabet packed bytes into a text string. */
uint16_t sms_decode_7bit(const uint8_t* packed, uint8_t packed_len, uint16_t septet_count, char* out);

/** Check if text requires UCS-2 encoding (contains non-GSM-7 chars). */
bool sms_needs_ucs2(const char* text, uint16_t len);

/** Build an SMS-SUBMIT TPDU. Returns total TPDU byte count (without SMSC header). */
uint8_t sms_build_submit(const char* recipient, const char* text,
                         uint8_t msg_ref, sms_submit_t* out);

/** Parse an SMS-DELIVER PDU. Returns decoded sms_message_t. */
bool sms_parse_deliver(const uint8_t* tpdu, uint16_t len, sms_message_t* out);

/** Send SMS via AT+CMGS. Returns 0 on success. */
int sms_send_at(diag_handle_t* h, const char* recipient, const char* text);

/** Send SMS via QMI WMS. Returns 0 on success. */
int sms_send_qmi(diag_handle_t* h, const char* recipient, const char* text);

/** Send SMS using best available method. */
int sms_send(diag_handle_t* h, const char* recipient, const char* text);

/** Check for new SMS messages via AT+CMGL. Returns message count or -1. */
int sms_list_received(diag_handle_t* h, sms_message_t* messages, uint8_t max_count);

/** Read a specific SMS at the given index via AT+CMGR. */
bool sms_read_at_index(diag_handle_t* h, uint8_t index, sms_message_t* out);

/** Configure SMS service center address. Usually not needed in direct link. */
int sms_set_sca(diag_handle_t* h, const char* sca);

/** Convert phone number to SMS BCD address format. Returns byte count. */
uint8_t sms_addr_to_bcd(const char* addr, uint8_t* out_bcd, uint8_t* out_type);

/** Convert BCD SMS address to string. */
void sms_bcd_to_addr(const uint8_t* bcd, uint8_t bcd_len, uint8_t addr_type, char* out);

#ifdef __cplusplus
}
#endif

#endif /* CELLLINK_SMS_H */
