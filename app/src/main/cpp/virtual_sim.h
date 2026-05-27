#ifndef CELLLINK_VIRTUAL_SIM_H
#define CELLLINK_VIRTUAL_SIM_H

#include "diag.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Virtual SIM Card Constants ──────────────────────────────────────── */

/* SIM Elementary Files (EF) we emulate */
#define EF_ICCID        0x2FE2   /* ICC Identification */
#define EF_IMSI         0x6F07   /* IMSI */
#define EF_LOCI         0x6F7E   /* Location Information */
#define EF_Kc           0x6F20   /* Ciphering Key Kc */
#define EF_AD           0x6FAD   /* Administrative Data */
#define EF_SPN          0x6F46   /* Service Provider Name */
#define EF_MSISDN       0x6F40   /* MSISDN (phone number) */
#define EF_SMS          0x6F3C   /* Short Messages */
#define EF_ACC          0x6F78   /* Access Control Class */
#define EF_FPLMN        0x6F7B   /* Forbidden PLMN */
#define EF_HPPLMN       0x6F31   /* Higher Priority PLMN */

/* SIM file access methods */
#define SIM_METHOD_AT_CRSM       0  /* AT+CRSM command */
#define SIM_METHOD_QMI_UIM       1  /* QMI UIM service */
#define SIM_METHOD_MEM_PATCH     2  /* Direct memory patch */

/* Default virtual SIM values */
#define VSIM_DEFAULT_MCC    901
#define VSIM_DEFAULT_MNC    1
#define VSIM_DEFAULT_IMSI   "901010000000001"
#define VSIM_DEFAULT_ICCID  "89901123450000000001"
#define VSIM_DEFAULT_MSISDN "1234567890"
#define VSIM_DEFAULT_SPN    "CellLink Direct"

/* ── Data Structures ─────────────────────────────────────────────────── */

typedef struct {
    char     iccid[21];       /* 20 digits */
    char     imsi[16];        /* 15 digits */
    char     msisdn[16];      /* Phone number */
    char     spn[32];         /* Service Provider Name */
    uint8_t  acc;             /* Access Control Class */
    uint16_t mcc;             /* Mobile Country Code */
    uint16_t mnc;             /* Mobile Network Code */
    uint16_t lac;             /* Location Area Code */
    uint16_t ci;              /* Cell Identity */
    uint8_t  kc[8];           /* Ciphering Key (all zeros = no cipher) */
    bool     is_active;
    uint8_t  method;          /* SIM_METHOD_* */
} virtual_sim_t;

/* ── API ──────────────────────────────────────────────────────────────── */

/** Create a new virtual SIM with default test identity. */
virtual_sim_t* vsim_create(void);

/** Create a virtual SIM with custom identity. */
virtual_sim_t* vsim_create_custom(uint16_t mcc, uint16_t mnc, const char* imsi,
                                   const char* msisdn, const char* spn);

/** Free virtual SIM resources. */
void vsim_free(virtual_sim_t* sim);

/**
 * Write the virtual SIM identity into the modem's SIM interface.
 * This patches the modem's SIM cache so it thinks a SIM is present.
 * Method depends on modem type:
 *   - AT+CRSM: Standard GSM command (most compatible)
 *   - QMI UIM: Qualcomm UIM service (more reliable on Qualcomm)
 *   - MEM_PATCH: Direct modem RAM write (requires known addresses)
 *
 * @return 0 on success, -1 on failure
 */
int vsim_activate(virtual_sim_t* sim, diag_handle_t* h, uint8_t method);

/**
 * Deactivate the virtual SIM.
 */
int vsim_deactivate(virtual_sim_t* sim, diag_handle_t* h);

/**
 * Write a specific SIM EF file using AT+CRSM.
 */
int vsim_write_ef_at(diag_handle_t* h, uint16_t ef_id, const uint8_t* data, uint8_t len);

/**
 * Write a SIM EF using QMI UIM service.
 */
int vsim_write_ef_qmi(diag_handle_t* h, uint16_t ef_id, const uint8_t* data, uint8_t len);

/**
 * Update the LOCI (Location Information) on the virtual SIM.
 */
int vsim_update_loci(virtual_sim_t* sim, diag_handle_t* h,
                     uint16_t lac, uint16_t ci);

/**
 * Set the ciphering key Kc (all zeros = no encryption).
 */
int vsim_set_kc(virtual_sim_t* sim, const uint8_t kc[8]);

/**
 * Verify the virtual SIM is readable by the modem.
 */
bool vsim_verify(virtual_sim_t* sim, diag_handle_t* h);

/**
 * Export SIM data as a human-readable string.
 */
void vsim_dump(virtual_sim_t* sim, char* buf, uint16_t max_len);

#ifdef __cplusplus
}
#endif

#endif /* CELLLINK_VIRTUAL_SIM_H */
