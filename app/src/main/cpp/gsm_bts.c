#include "gsm_bts.h"
#include "qmi.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <math.h>
#include <android/log.h>

#define LOG_TAG "CellLink-BTS"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

/* ── System Information Message Buffers ──────────────────────────────── */

/* SI 1: Cell channel allocation + RACH control */
static const uint8_t SI1_TEMPLATE[] = {
    0x00,                           /* L2 pseudo-length */
    0x06,                           /* RR protocol */
    0x19,                           /* System Information Type 1 */
    /* Cell Channel Description (16 bytes) — all P-GSM channels */
    0x00,                           /* Channel 0 not used */
    /* Bitmap: ARFCN 1-124 */
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    /* RACH Control Parameters (3 bytes) */
    0xC8,                           /* Max 8 retransmissions, 4 slots spread */
    0x02,                           /* Tx-integer = 14, Cell barred = no */
    0x00,                           /* Access control class = all */
    /* SI 1 Rest Octets (4 bytes) */
    0x2B, 0x2B, 0x2B, 0x2B
};

/* SI 3: Cell Identity, LAI, cell options */
static const uint8_t SI3_TEMPLATE[] = {
    0x00,                           /* L2 pseudo-length */
    0x06,                           /* RR protocol */
    0x1B,                           /* System Information Type 3 */
    /* Cell Identity (2 bytes) */
    0x01, 0x00,                     /* CI = 1 */
    /* Location Area Identification (5 bytes) */
    0x10, 0x0F, 0x01, 0x01, 0x00,   /* MCC=901, MNC=01, LAC=1 */
    /* Control Channel Description (3 bytes) */
    0x00,                           /* BS_AG_BLKS_RES=0, CCCH_CONF=1 CCCH */
    0x00,                           /* BS_PA_MFRMS=2, ATT=no */
    0x00,                           /* T3212 timeout = 0 (no periodic update) */
    /* Cell Options (1 byte) */
    0x00,                           /* PWRC=no, DTX=yes, Radio link timeout=4 */
    /* Cell Selection Parameters (2 bytes) */
    0xC0, 0x0E,                     /* RXLEV_ACCESS_MIN = -110dBm, MS_TXPWR_MAX_CCH = 33dBm */
    /* RACH Control Parameters (3 bytes) */
    0xC8, 0x02, 0x00,
    /* SI 3 Rest Octets (4 bytes) */
    0x2B, 0x2B, 0x2B, 0x2B
};

/* ── Broadcast Thread ─────────────────────────────────────────────────── */

static void bts_build_si1(const bts_context_t* ctx, uint8_t* buf, uint16_t* len) {
    memcpy(buf, SI1_TEMPLATE, sizeof(SI1_TEMPLATE));
    *len = sizeof(SI1_TEMPLATE);
}

static void bts_build_si3(const bts_context_t* ctx, uint8_t* buf, uint16_t* len) {
    memcpy(buf, SI3_TEMPLATE, sizeof(SI3_TEMPLATE));
    *len = sizeof(SI3_TEMPLATE);
}

typedef struct {
    uint8_t  data[256];
    uint16_t len;
    uint32_t interval_ms;  /* Broadcast interval */
} si_message_t;

static void* broadcast_thread_fn(void* arg) {
    bts_context_t* ctx = (bts_context_t*)arg;
    LOGI("Broadcast thread started for ARFCN %d", ctx->arfcn);

    /* Prepare the fixed SI messages */
    si_message_t si1, si3;
    bts_build_si1(ctx, si1.data, &si1.len);
    si1.interval_ms = 500;  /* Every ~0.5s (on BCCH Norm in 51-multiframe) */

    bts_build_si3(ctx, si3.data, &si3.len);
    si3.interval_ms = 1000; /* Every ~1s */

    uint32_t si1_counter = 0;
    uint32_t si3_counter = 0;
    const uint32_t tick_ms = 100; /* 100ms tick */

    while (true) {
        pthread_mutex_lock(&ctx->mutex);
        bool running = ctx->running;
        pthread_mutex_unlock(&ctx->mutex);

        if (!running) break;

        si1_counter += tick_ms;
        si3_counter += tick_ms;

        /* Send SI1 on its interval */
        if (si1_counter >= si1.interval_ms) {
            si1_counter = 0;
            /* Send SI1 via DIAG as a raw L1 frame */
            uint8_t l1_hdr[4] = {
                0x00,       /* Channel type: BCCH */
                0x00,       /* Frame number (high) */
                0x00,       /* Frame number (low) */
                (uint8_t)(si1.len & 0xFF)
            };
            uint8_t si1_frame[260];
            memcpy(si1_frame, l1_hdr, 4);
            memcpy(si1_frame + 4, si1.data, si1.len);

            /* Send via DIAG loopback/test path for transmission */
            diag_send(ctx->diag, DIAG_CMD_EXT_LOOPBACK, si1_frame, 4 + si1.len);
            LOGD("Broadcast SI1: %d bytes on ARFCN %d", si1.len, ctx->arfcn);
        }

        /* Send SI3 on its interval */
        if (si3_counter >= si3.interval_ms) {
            si3_counter = 0;
            uint8_t l1_hdr[4] = {
                0x00,       /* Channel type: BCCH */
                0x08,       /* Frame number offset for SI3 in 51-multiframe */
                0x00,
                (uint8_t)(si3.len & 0xFF)
            };
            uint8_t si3_frame[260];
            memcpy(si3_frame, l1_hdr, 4);
            memcpy(si3_frame + 4, si3.data, si3.len);

            diag_send(ctx->diag, DIAG_CMD_EXT_LOOPBACK, si3_frame, 4 + si3.len);
            LOGD("Broadcast SI3: %d bytes", si3.len);
        }

        usleep(tick_ms * 1000);
    }

    LOGI("Broadcast thread stopped");
    return NULL;
}

/* ── Public API ───────────────────────────────────────────────────────── */

bts_context_t* bts_init(diag_handle_t* diag, uint16_t arfcn, uint8_t band, uint8_t tx_power) {
    if (!diag || !diag_is_ready(diag)) return NULL;

    bts_context_t* ctx = (bts_context_t*)calloc(1, sizeof(bts_context_t));
    if (!ctx) return NULL;

    ctx->diag = diag;
    ctx->arfcn = arfcn;
    ctx->band = band;
    ctx->tx_power = tx_power;
    ctx->state = BTS_STATE_INIT;

    if (pthread_mutex_init(&ctx->mutex, NULL) != 0) {
        free(ctx);
        return NULL;
    }

    /* Calculate frequencies */
    gsm_arfcn_to_freq(arfcn, (gsm_band_t)band, &ctx->ul_freq_mhz, &ctx->dl_freq_mhz);

    LOGI("BTS initialized: ARFCN=%d, UL=%.1f MHz, DL=%.1f MHz", arfcn, ctx->ul_freq_mhz, ctx->dl_freq_mhz);
    return ctx;
}

int bts_start(bts_context_t* ctx) {
    if (!ctx || ctx->state == BTS_STATE_ERROR) return -1;

    LOGI("Starting BTS on ARFCN %d...", ctx->arfcn);

    /* Step 1: Set modem to offline mode first */
    qmi_dms_set_offline(ctx->diag);

    /* Step 2: Configure frequency with NV items */
    if (qmi_test_set_frequency(ctx->diag, ctx->arfcn, ctx->band) != 0) {
        LOGE("Failed to set frequency NV items");
        ctx->state = BTS_STATE_ERROR;
        snprintf(ctx->error_msg, sizeof(ctx->error_msg), "NV config failed");
        return -1;
    }

    /* Step 3: Set to GSM-only mode */
    qmi_nas_set_gsm_only(ctx->diag);

    /* Step 4: Start continuous Tx in test mode */
    if (qmi_test_set_continuous_tx(ctx->diag, ctx->arfcn, ctx->tx_power) != 0) {
        LOGE("Failed to start continuous Tx — attempting AT command fallback");
        /* Try AT command fallback */
        char rsp[256];
        char at_cmd[64];
        snprintf(at_cmd, sizeof(at_cmd), "+DRX=0");
        if (diag_at_command(ctx->diag, at_cmd, rsp, sizeof(rsp)) < 0) {
            LOGE("AT fallback also failed");
            ctx->state = BTS_STATE_ERROR;
            snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Tx init failed");
            return -1;
        }
    }

    /* Step 5: Set modem online so it can transmit */
    qmi_dms_set_online(ctx->diag);

    /* Step 6: Start broadcast thread */
    ctx->running = true;
    if (pthread_create(&ctx->broadcast_thread, NULL, broadcast_thread_fn, ctx) != 0) {
        LOGE("Failed to create broadcast thread");
        qmi_test_stop_tx(ctx->diag);
        ctx->state = BTS_STATE_ERROR;
        snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Thread creation failed");
        return -1;
    }

    ctx->state = BTS_STATE_BROADCASTING;
    LOGI("BTS broadcasting: ARFCN=%d, DL=%.1f MHz, MCC=%d, MNC=%02d",
         ctx->arfcn, ctx->dl_freq_mhz, GSM_MCC, GSM_MNC);
    return 0;
}

int bts_stop(bts_context_t* ctx) {
    if (!ctx) return -1;

    LOGI("Stopping BTS...");
    ctx->running = false;

    /* Wait for broadcast thread */
    pthread_join(ctx->broadcast_thread, NULL);

    /* Stop Tx */
    qmi_test_stop_tx(ctx->diag);

    /* Go offline */
    qmi_dms_set_offline(ctx->diag);

    ctx->state = BTS_STATE_OFF;
    LOGI("BTS stopped");
    return 0;
}

void bts_free(bts_context_t* ctx) {
    if (!ctx) return;
    pthread_mutex_destroy(&ctx->mutex);
    free(ctx);
}

bts_state_t bts_get_state(bts_context_t* ctx) {
    if (!ctx) return BTS_STATE_OFF;
    return ctx->state;
}

int bts_accept_call(bts_context_t* ctx) {
    if (!ctx || ctx->state != BTS_STATE_CONNECTED) return -1;

    /* Send connect acknowledgment */
    char rsp[256];
    if (diag_at_command(ctx->diag, "ATA", rsp, sizeof(rsp)) < 0) {
        /* Try via QMI */
        uint8_t req[3] = {0x01, 0x00}; /* Accept call */
        qmi_request(ctx->diag, QMI_SUBSYS_VS, 0x0021, req, 2, (uint8_t*)rsp, sizeof(rsp), 5000);
    }

    ctx->state = BTS_STATE_IN_CALL;
    ctx->call_active = true;
    LOGI("Call accepted");
    return 0;
}

int bts_end_call(bts_context_t* ctx) {
    if (!ctx || !ctx->call_active) return -1;

    char rsp[256];
    diag_at_command(ctx->diag, "CHUP", rsp, sizeof(rsp));

    ctx->state = BTS_STATE_BROADCASTING;
    ctx->call_active = false;
    LOGI("Call ended");
    return 0;
}

float bts_get_dl_frequency(bts_context_t* ctx) {
    if (!ctx) return 0.0f;
    return ctx->dl_freq_mhz;
}
