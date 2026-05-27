#ifndef CELLLINK_GSM_BTS_H
#define CELLLINK_GSM_BTS_H

#include "diag.h"
#include "gsm_common.h"
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── BTS State ────────────────────────────────────────────────────────── */

typedef enum {
    BTS_STATE_OFF,
    BTS_STATE_INIT,
    BTS_STATE_BROADCASTING,
    BTS_STATE_CONNECTED,
    BTS_STATE_IN_CALL,
    BTS_STATE_ERROR
} bts_state_t;

typedef struct {
    bts_state_t    state;
    diag_handle_t* diag;
    uint16_t       arfcn;
    uint8_t        band;
    uint8_t        tx_power;
    float          dl_freq_mhz;
    float          ul_freq_mhz;
    bool           running;
    pthread_t      broadcast_thread;
    pthread_mutex_t mutex;

    /* Connected UE info */
    char           connected_imsi[16];
    bool           call_active;

    /* Error message */
    char           error_msg[256];
} bts_context_t;

/* ── BTS API ──────────────────────────────────────────────────────────── */

/**
 * Initialize the BTS tower mode.
 * @param diag  Open DIAG handle (must be ready)
 * @param arfcn ARFCN to broadcast on (default: 1 = 890.2 MHz uplink)
 * @param band  GSM band (default: GSM_BAND_900)
 * @param tx_power Tx power level 0-31 (default: 15 = ~33dBm)
 * @return BTS context or NULL on failure.
 */
bts_context_t* bts_init(diag_handle_t* diag, uint16_t arfcn, uint8_t band, uint8_t tx_power);

/**
 * Start broadcasting (system information, paging, etc.)
 * Spawns a background thread for periodic broadcasts.
 */
int bts_start(bts_context_t* ctx);

/**
 * Stop broadcasting and clean up.
 */
int bts_stop(bts_context_t* ctx);

/**
 * Free the BTS context. Must call bts_stop() first.
 */
void bts_free(bts_context_t* ctx);

/**
 * Get current BTS state.
 */
bts_state_t bts_get_state(bts_context_t* ctx);

/**
 * Accept an incoming call request from a UE.
 * Sets up the traffic channel and routes audio.
 * Returns 0 on success.
 */
int bts_accept_call(bts_context_t* ctx);

/**
 * End the active call.
 */
int bts_end_call(bts_context_t* ctx);

/**
 * Get the frequency in MHz for display.
 */
float bts_get_dl_frequency(bts_context_t* ctx);

#ifdef __cplusplus
}
#endif

#endif /* CELLLINK_GSM_BTS_H */
