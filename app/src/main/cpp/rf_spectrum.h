#ifndef CELLLINK_RF_SPECTRUM_H
#define CELLLINK_RF_SPECTRUM_H

#include "diag.h"
#include "gsm_common.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SPECTRUM_MAX_CHANNELS    1024
#define SPECTRUM_SWEEP_PASSES    3       /* Averaging passes per channel */
#define SPECTRUM_SCAN_TIMEOUT_MS 1000    /* Per-channel measurement time */

typedef struct {
    uint16_t arfcn;
    float    freq_mhz;
    int16_t  rssi_dbm;           /* Average RSSI */
    int16_t  rssi_min_dbm;       /* Minimum observed */
    int16_t  rssi_max_dbm;       /* Maximum observed */
    uint8_t  noise_floor_dbm;    /* Estimated noise floor (absolute value) */
    bool     occupied;           /* Channel appears to be in use */
    bool     is_gsm_channel;     /* Valid ARFCN for the scanned band */
    uint8_t  band;               /* GSM band */
} spectrum_channel_t;

typedef struct {
    spectrum_channel_t channels[SPECTRUM_MAX_CHANNELS];
    uint16_t           channel_count;
    float              system_noise_floor_dbm;  /* Overall noise floor */
    uint16_t           best_arfcn;              /* Clearest channel */
    float              best_freq_mhz;
    uint64_t           scan_timestamp;
    bool               scan_complete;
} spectrum_scan_t;

/* ── API ─────────────────────────────────────────────────────────────── */

/** Initialize a spectrum scan context. */
spectrum_scan_t* spectrum_init(void);

/** Free scan resources. */
void spectrum_free(spectrum_scan_t* scan);

/**
 * Scan a single channel for RSSI and noise floor.
 * Uses AT+CRSM or QMI NAS to measure signal on a specific ARFCN.
 */
int spectrum_measure_channel(diag_handle_t* h, uint16_t arfcn, uint8_t band,
                             spectrum_channel_t* out);

/**
 * Full band sweep — scan all channels in a GSM band.
 * Returns number of channels successfully measured.
 */
int spectrum_sweep_band(diag_handle_t* h, gsm_band_t band, spectrum_scan_t* scan);

/**
 * Multi-band sweep — scan all GSM bands.
 * Returns total channels measured.
 */
int spectrum_sweep_all_bands(diag_handle_t* h, spectrum_scan_t* scan);

/**
 * Find the clearest channel in a scan.
 * Considers: not occupied, lowest noise floor, highest margin from neighbors.
 */
uint16_t spectrum_find_clearest_channel(spectrum_scan_t* scan, gsm_band_t preferred_band);

/**
 * Rank channels by quality. Returns the top N ARFCNs in ranked_arcfns.
 */
int spectrum_rank_channels(spectrum_scan_t* scan, uint16_t* ranked_arcfns, int top_n);

/**
 * Check if a specific ARFCN is clear (no detected occupancy, noise floor < threshold).
 */
bool spectrum_is_channel_clear(spectrum_scan_t* scan, uint16_t arfcn);

/**
 * Measure adjacent channel interference for a given ARFCN.
 * Returns the worst-case adjacent channel RSSI in dBm.
 */
int16_t spectrum_adjacent_interference(spectrum_scan_t* scan, uint16_t arfcn);

/**
 * Export scan results as CSV-formatted string.
 */
int spectrum_export_csv(spectrum_scan_t* scan, char* buf, uint32_t max_len);

/**
 * Pretty-print scan summary for log output.
 */
void spectrum_print_summary(spectrum_scan_t* scan);

#ifdef __cplusplus
}
#endif

#endif /* CELLLINK_RF_SPECTRUM_H */
