#ifndef CELLLINK_BAND_SCANNER_H
#define CELLLINK_BAND_SCANNER_H

#include "diag.h"
#include "gsm_common.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BAND_SCANNER_MAX_RESULTS    2048

typedef struct {
    uint16_t arfcn;
    float    freq_mhz;
    int16_t  rssi_dbm;
    char     operator_name[32];  /* Network name if found */
    char     plmn[8];            /* MCCMNC string */
    uint16_t mcc;
    uint16_t mnc;
    uint16_t lac;
    uint16_t ci;
    uint8_t  band;
    bool     is_camped;          /* Currently camped on this cell */
    bool     is_forbidden;       /* In forbidden PLMN list */
    uint8_t  rxlev;              /* 0-63 RXLEV */
    uint8_t  c1;                 /* C1 path loss criterion */
    uint8_t  c2;                 /* C2 cell reselection criterion */
} cell_info_t;

typedef struct {
    cell_info_t cells[BAND_SCANNER_MAX_RESULTS];
    uint32_t    cell_count;
    int16_t     best_rssi;
    uint16_t    serving_arfcn;
    bool        scan_complete;
} band_scan_t;

/* ── API ─────────────────────────────────────────────────────────────── */

/** Create a new band scan context. */
band_scan_t* band_scan_create(void);

/** Free scan context. */
void band_scan_free(band_scan_t* scan);

/**
 * Scan all GSM bands for visible cells.
 * Uses AT+COPS=? (network scan) and AT+CREG? (registration info).
 */
int band_scan_full(diag_handle_t* h, band_scan_t* scan);

/**
 * Scan a single ARFCN for cell identity.
 */
int band_scan_cell(diag_handle_t* h, uint16_t arfcn, cell_info_t* out);

/**
 * Get serving cell information.
 */
int band_scan_serving_cell(diag_handle_t* h, cell_info_t* out);

/**
 * Get neighbor cell measurements (from the modem's neighbor list).
 */
int band_scan_neighbors(diag_handle_t* h, band_scan_t* scan);

/**
 * Find cells matching a specific PLMN.
 */
int band_scan_find_plmn(band_scan_t* scan, uint16_t mcc, uint16_t mnc,
                        cell_info_t* results, int max_results);

/**
 * Calculate GSM path loss criterion C1.
 * C1 = (RXLEV - RXLEV_ACCESS_MIN) - max(MS_TXPWR_MAX_CCH - P, 0)
 */
int band_scan_calc_c1(int16_t rxlev, int16_t rxlev_access_min,
                      int16_t ms_txpwr_max_cch, int16_t max_rf_power);

/**
 * Calculate GSM cell reselection criterion C2.
 * C2 = C1 + CELL_RESELECT_OFFSET - TEMPORARY_OFFSET * H
 */
int band_scan_calc_c2(int c1, int cell_reselect_offset,
                      int temporary_offset, int penalty_time);

/**
 * Export scan results as CSV.
 */
int band_scan_export_csv(band_scan_t* scan, char* buf, uint32_t max_len);

/**
 * Pretty-print scan results.
 */
void band_scan_print(band_scan_t* scan);

#ifdef __cplusplus
}
#endif

#endif /* CELLLINK_BAND_SCANNER_H */
