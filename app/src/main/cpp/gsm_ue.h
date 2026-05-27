#ifndef CELLLINK_GSM_UE_H
#define CELLLINK_GSM_UE_H

#include "diag.h"
#include "gsm_common.h"
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── UE State ─────────────────────────────────────────────────────────── */

typedef enum {
    UE_STATE_IDLE,
    UE_STATE_SCANNING,
    UE_STATE_CONNECTING,
    UE_STATE_REGISTERED,
    UE_STATE_CALLING,
    UE_STATE_IN_CALL,
    UE_STATE_ERROR
} ue_state_t;

typedef struct {
    ue_state_t     state;
    diag_handle_t* diag;
    int            fd;            /* File descriptor for AT command port */

    /* Network info */
    uint16_t       target_mcc;
    uint16_t       target_mnc;
    uint16_t       current_arfcn;
    int16_t        rssi_dbm;

    /* Found towers */
    char           scan_results[1024];
    int            scan_count;

    /* Call state */
    bool           call_active;
    bool           ringing;

    /* Threading and callbacks */
    bool           running;
    pthread_t      signal_thread;
    pthread_mutex_t mutex;

    /* Error message */
    char           error_msg[256];

    /* Callbacks (called from native thread) */
    void (*on_registered)(void* userdata);
    void (*on_incoming_call)(void* userdata);
    void (*on_call_connected)(void* userdata);
    void (*on_call_ended)(void* userdata);
    void (*on_signal_update)(void* userdata, int16_t rssi);
    void* userdata;
} ue_context_t;

/* ── UE API ───────────────────────────────────────────────────────────── */

/**
 * Initialize UE client mode.
 * @param diag  Open DIAG handle
 * @return UE context or NULL on failure.
 */
ue_context_t* ue_init(diag_handle_t* diag);

/**
 * Scan for available networks. Returns number of networks found.
 * Result string stored in ctx->scan_results.
 */
int ue_scan_networks(ue_context_t* ctx);

/**
 * Register on the target network (default: 901/01 test network).
 */
int ue_register_network(ue_context_t* ctx, uint16_t mcc, uint16_t mnc);

/**
 * Start monitoring signal strength (background thread).
 */
int ue_start_signal_monitor(ue_context_t* ctx);

/**
 * Stop signal monitoring thread.
 */
int ue_stop_signal_monitor(ue_context_t* ctx);

/**
 * Initiate a call to the tower.
 * In this direct link, any call goes to the BTS.
 */
int ue_make_call(ue_context_t* ctx);

/**
 * End the active call.
 */
int ue_end_call(ue_context_t* ctx);

/**
 * Answer an incoming call.
 */
int ue_answer_call(ue_context_t* ctx);

/**
 * Get current state.
 */
ue_state_t ue_get_state(ue_context_t* ctx);

/**
 * Get current signal strength in dBm.
 */
int16_t ue_get_rssi(ue_context_t* ctx);

/**
 * Disconnect from network and clean up.
 */
int ue_disconnect(ue_context_t* ctx);

/**
 * Free the UE context.
 */
void ue_free(ue_context_t* ctx);

/**
 * Set callback for when registration succeeds.
 */
void ue_set_callbacks(ue_context_t* ctx,
                      void (*on_registered)(void*),
                      void (*on_incoming_call)(void*),
                      void (*on_call_connected)(void*),
                      void (*on_call_ended)(void*),
                      void (*on_signal_update)(void*, int16_t),
                      void* userdata);

#ifdef __cplusplus
}
#endif

#endif /* CELLLINK_GSM_UE_H */
