#ifndef CELLLINK_GSM_COMMON_H
#define CELLLINK_GSM_COMMON_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── GSM Bands and Frequencies ───────────────────────────────────────── */

typedef enum {
    GSM_BAND_850  = 0,  /* GSM-850:  UL 824-849 MHz,  DL 869-894 MHz */
    GSM_BAND_900  = 1,  /* P-GSM-900: UL 890-915 MHz,  DL 935-960 MHz */
    GSM_BAND_1800 = 2,  /* DCS-1800:  UL 1710-1785 MHz, DL 1805-1880 MHz */
    GSM_BAND_1900 = 3,  /* PCS-1900:  UL 1850-1910 MHz, DL 1930-1990 MHz */
} gsm_band_t;

typedef struct {
    gsm_band_t band;
    uint16_t   arfcn;         /* Absolute Radio Frequency Channel Number */
    float      ul_freq_mhz;   /* Uplink frequency in MHz */
    float      dl_freq_mhz;   /* Downlink frequency in MHz */
    uint16_t   arfcn_range[2]; /* [min, max] ARFCN range for this band */
} gsm_channel_t;

/** Convert ARFCN to frequency info. Returns true if valid. */
bool gsm_arfcn_to_freq(uint16_t arfcn, gsm_band_t band, float* ul_mhz, float* dl_mhz);

/** Get band info for a given ARFCN (auto-detect band). */
gsm_channel_t gsm_get_channel_info(uint16_t arfcn);

/** Get the default band based on ARFCN */
gsm_band_t gsm_get_band_for_arfcn(uint16_t arfcn);

/* ── GSM L3 Protocol Constants ───────────────────────────────────────── */

/* Protocol Discriminators */
#define GSM_PD_RR          0x06  /* Radio Resource Management */
#define GSM_PD_MM          0x05  /* Mobility Management */
#define GSM_PD_CC          0x03  /* Call Control */

/* Radio Resource Message Types */
#define GSM_RR_SYS_INFO_1       0x19
#define GSM_RR_SYS_INFO_2       0x1A
#define GSM_RR_SYS_INFO_3       0x1B
#define GSM_RR_SYS_INFO_4       0x1C
#define GSM_RR_SYS_INFO_5       0x1D
#define GSM_RR_SYS_INFO_6       0x1E
#define GSM_RR_SYS_INFO_13      0x05
#define GSM_RR_CHAN_REQ         0x38
#define GSM_RR_IMM_ASSIGN       0x3F
#define GSM_RR_PAGING_REQ_TYPE1 0x21
#define GSM_RR_PAGING_REQ_TYPE2 0x22

/* ── System Information Constants ────────────────────────────────────── */

#define GSM_MCC           901    /* Test MCC */
#define GSM_MNC           1      /* Test MNC */
#define GSM_LAC           0x0001 /* Location Area Code */
#define GSM_CI            0x0001 /* Cell Identity */

/* SIM / IMSI constants for fake SIM */
#define FAKE_IMSI_DIGITS  15
#define FAKE_IMSI_STR     "901010000000001"

/* ── Timing ──────────────────────────────────────────────────────────── */

#define GSM_TDMA_FRAME_MS      4.615f   /* TDMA frame duration in ms */
#define GSM_MULTIFRAME_51      51       /* 51-frame multiframe for control */
#define GSM_MULTIFRAME_26      26       /* 26-frame multiframe for traffic */
#define GSM_SUPERFRAME         1326     /* 1326 TDMA frames = 6.12s */
#define GSM_HYPERFRAME         2715648  /* Hyperframe = ~3h28m */

/* ── Data Structures ─────────────────────────────────────────────────── */

/** System Information Type 1 message (GSM 04.08 §9.1.31) */
typedef struct __attribute__((packed)) {
    uint8_t  l2_pseudo_len;    /* 0x00 */
    uint8_t  pd;               /* 0x06 = RR */
    uint8_t  msg_type;         /* 0x19 = System Information 1 */
    uint8_t  cell_chan_desc[16]; /* Cell Channel Description */
    uint8_t  rach_control[3];    /* RACH Control Parameters */
    uint8_t  si1_rest[4];        /* SI 1 Rest Octets */
} gsm_si1_t;

/** System Information Type 3 message */
typedef struct __attribute__((packed)) {
    uint8_t  l2_pseudo_len;
    uint8_t  pd;
    uint8_t  msg_type;         /* 0x1B = System Information 3 */
    uint8_t  ci[2];            /* Cell Identity */
    uint8_t  lai[5];           /* Location Area Identification */
    uint8_t  control_chan_desc[3];
    uint8_t  cell_options[1];
    uint8_t  cell_sel_params[2];
    uint8_t  rach_control[3];
    uint8_t  si3_rest[4];
} gsm_si3_t;

/** Immediate Assignment message */
typedef struct __attribute__((packed)) {
    uint8_t  l2_pseudo_len;
    uint8_t  pd;               /* 0x06 = RR */
    uint8_t  msg_type;         /* 0x3F = Immediate Assignment */
    uint8_t  page_mode[1];
    uint8_t  chan_desc[3];     /* Channel Description */
    uint8_t  packet_chan_desc[4];
    uint8_t  timing_advance;
    uint8_t  mobile_alloc[0];
} gsm_imm_assign_t;

/** Paging Request Type 1 */
typedef struct __attribute__((packed)) {
    uint8_t  l2_pseudo_len;
    uint8_t  pd;               /* 0x06 = RR */
    uint8_t  msg_type;         /* 0x21 = Paging Request Type 1 */
    uint8_t  page_mode[1];
    uint8_t  chan_needed[2];
    uint8_t  mobile_id[8];     /* TMSI or IMSI */
    uint8_t  p1_rest[3];
} gsm_paging_req_t;

/* ── Helper Functions ────────────────────────────────────────────────── */

/** Build a Location Area Identification (LAI) byte array from MCC/MNC/LAC. */
void gsm_build_lai(uint8_t* out, uint16_t mcc, uint16_t mnc, uint16_t lac);

/** Build a Cell Identity byte array. */
void gsm_build_ci(uint8_t* out, uint16_t ci);

/** Build a Channel Description for SDCCH. */
void gsm_build_chan_desc(uint8_t* out, uint16_t arfcn, uint8_t timeslot, uint8_t training_seq);

/** Convert IMSI string to BCD digits for mobile identity. */
uint8_t gsm_imsi_to_bcd(const char* imsi_str, uint8_t* out);

#ifdef __cplusplus
}
#endif

#endif /* CELLLINK_GSM_COMMON_H */
