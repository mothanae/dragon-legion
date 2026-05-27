#include "gsm_ue.h"
#include "qmi.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <android/log.h>

#define LOG_TAG "CellLink-UE"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

/* ── Static Helpers ──────────────────────────────────────────────────── */

/**
 * Send AT command and wait for "OK" response.
 * Returns 0 on success (response contains "OK"), -1 on failure.
 */
static int at_ok(diag_handle_t* diag, const char* cmd) {
    char rsp[512];
    int n = diag_at_command(diag, cmd, rsp, sizeof(rsp));
    if (n < 0) return -1;
    if (strstr(rsp, "OK") || strstr(rsp, "CONNECT")) return 0;

    LOGD("AT %s -> %s", cmd, rsp);
    return -1;
}

/**
 * Send AT command and return response text.
 */
static char* at_query(diag_handle_t* diag, const char* cmd, char* buf, uint16_t buf_len) {
    int n = diag_at_command(diag, cmd, buf, buf_len);
    if (n < 0) {
        buf[0] = '\0';
        return buf;
    }
    return buf;
}

/* ── Signal Monitoring Thread ────────────────────────────────────────── */

static void* signal_thread_fn(void* arg) {
    ue_context_t* ctx = (ue_context_t*)arg;

    while (true) {
        pthread_mutex_lock(&ctx->mutex);
        bool running = ctx->running && (ctx->state == UE_STATE_REGISTERED ||
                                         ctx->state == UE_STATE_CALLING ||
                                         ctx->state == UE_STATE_IN_CALL);
        pthread_mutex_unlock(&ctx->mutex);

        if (!running) break;

        /* Query signal strength via AT+CSQ */
        char rsp[128];
        at_query(ctx->diag, "+CSQ", rsp, sizeof(rsp));

        /* Parse "+CSQ: <rssi>,<ber>" */
        char* csq = strstr(rsp, "+CSQ:");
        if (csq) {
            int rssi_raw = 0;
            if (sscanf(csq, "+CSQ: %d", &rssi_raw) == 1) {
                /* Convert RSSI (0-31,99) to dBm: -113 + rssi*2 */
                int16_t dbm = (rssi_raw >= 0 && rssi_raw <= 31) ? (-113 + rssi_raw * 2) : -120;

                pthread_mutex_lock(&ctx->mutex);
                ctx->rssi_dbm = dbm;
                pthread_mutex_unlock(&ctx->mutex);

                if (ctx->on_signal_update) {
                    ctx->on_signal_update(ctx->userdata, dbm);
                }
            }
        }

        /* Also query via QMI for more detail */
        int16_t qmi_rssi;
        if (qmi_nas_get_signal_strength(ctx->diag, &qmi_rssi) == 0) {
            pthread_mutex_lock(&ctx->mutex);
            ctx->rssi_dbm = qmi_rssi;
            pthread_mutex_unlock(&ctx->mutex);
        }

        sleep(2); /* Poll every 2 seconds */
    }
    return NULL;
}

/* ── Public API ───────────────────────────────────────────────────────── */

ue_context_t* ue_init(diag_handle_t* diag) {
    if (!diag || !diag_is_ready(diag)) return NULL;

    ue_context_t* ctx = (ue_context_t*)calloc(1, sizeof(ue_context_t));
    if (!ctx) return NULL;

    ctx->diag = diag;
    ctx->fd = -1;
    ctx->state = UE_STATE_IDLE;
    ctx->target_mcc = GSM_MCC;
    ctx->target_mnc = GSM_MNC;
    ctx->rssi_dbm = -120;

    if (pthread_mutex_init(&ctx->mutex, NULL) != 0) {
        free(ctx);
        return NULL;
    }

    /* Set modem to GSM-only */
    qmi_nas_set_gsm_only(diag);

    /* Put modem online */
    qmi_dms_set_online(diag);

    LOGI("UE initialized, searching for MCC=%d MNC=%02d", GSM_MCC, GSM_MNC);
    return ctx;
}

int ue_scan_networks(ue_context_t* ctx) {
    if (!ctx) return -1;

    pthread_mutex_lock(&ctx->mutex);
    ctx->state = UE_STATE_SCANNING;
    ctx->scan_count = 0;
    memset(ctx->scan_results, 0, sizeof(ctx->scan_results));
    pthread_mutex_unlock(&ctx->mutex);

    /* Try AT+COPS=? first (standard network scan) */
    char at_rsp[1024];
    int n = diag_at_command(ctx->diag, "+COPS=?", at_rsp, sizeof(at_rsp));
    if (n > 0) {
        LOGD("AT+COPS=? response: %s", at_rsp);
        /* Parse: +COPS: (2,"NAME","SHORT","MCCMNC",0),... */
        char* p = strstr(at_rsp, "+COPS:");
        if (p) {
            /* Count and store results */
            char* save = p;
            while ((p = strstr(p, "\"MCCMNC\"")) || (p = strstr(p, "\","))) {
                if (ctx->scan_count < 64 && p > save) {
                    char* start = save;
                    while (*start && *start != '(') start++;
                    char* end = p + 1;
                    while (*end && *end != ')') end++;
                    uint16_t copy = (end - start) < 200 ? (end - start) : 199;
                    memcpy(ctx->scan_results + ctx->scan_count * 200, start, copy);
                    ctx->scan_count++;
                }
                save = p + 1;
                if (!*p) break;
                p++;
            }
        }
    }

    /* If AT scan failed or found nothing, try QMI scan */
    if (ctx->scan_count == 0) {
        char qmi_rsp[1024];
        int qmi_count = qmi_nas_network_scan(ctx->diag, qmi_rsp, sizeof(qmi_rsp));
        if (qmi_count > 0) {
            strncpy(ctx->scan_results, qmi_rsp, sizeof(ctx->scan_results) - 1);
            /* Count PLMN entries in raw QMI response */
            ctx->scan_count = 1; /* At least one if we got a response */
            LOGI("QMI scan found networks: %d bytes", qmi_count);
        }
    }

    /* Check if our target network is in the results */
    char target[16];
    snprintf(target, sizeof(target), "%03d%02d", ctx->target_mcc, ctx->target_mnc);
    bool found = (strstr(ctx->scan_results, target) != NULL);

    pthread_mutex_lock(&ctx->mutex);
    ctx->state = UE_STATE_IDLE;
    pthread_mutex_unlock(&ctx->mutex);

    LOGI("Scan complete: %d networks found, target %s %s",
         ctx->scan_count, target, found ? "FOUND" : "not found");
    return ctx->scan_count;
}

int ue_register_network(ue_context_t* ctx, uint16_t mcc, uint16_t mnc) {
    if (!ctx) return -1;

    ctx->target_mcc = mcc;
    ctx->target_mnc = mnc;

    pthread_mutex_lock(&ctx->mutex);
    ctx->state = UE_STATE_CONNECTING;
    pthread_mutex_unlock(&ctx->mutex);

    char plmn_str[8];
    snprintf(plmn_str, sizeof(plmn_str), "%03d%02d", mcc, mnc);

    /* Method 1: AT command registration */
    char at_cmd[64];
    snprintf(at_cmd, sizeof(at_cmd), "+COPS=1,2,\"%s\"", plmn_str);
    char rsp[256];
    int ret = diag_at_command(ctx->diag, at_cmd, rsp, sizeof(rsp));
    if (ret >= 0 && strstr(rsp, "OK")) {
        LOGI("Registered on %s via AT+COPS", plmn_str);
        pthread_mutex_lock(&ctx->mutex);
        ctx->state = UE_STATE_REGISTERED;
        pthread_mutex_unlock(&ctx->mutex);

        if (ctx->on_registered) ctx->on_registered(ctx->userdata);

        /* Start signal monitoring */
        ue_start_signal_monitor(ctx);
        return 0;
    }

    /* Method 2: QMI registration (more reliable on Qualcomm) */
    LOGI("AT registration failed, trying QMI...");
    ret = qmi_nas_register_network(ctx->diag, mcc, mnc);
    if (ret == 0) {
        LOGI("Registered on %s via QMI", plmn_str);
        pthread_mutex_lock(&ctx->mutex);
        ctx->state = UE_STATE_REGISTERED;
        pthread_mutex_unlock(&ctx->mutex);

        if (ctx->on_registered) ctx->on_registered(ctx->userdata);
        ue_start_signal_monitor(ctx);
        return 0;
    }

    /* Method 3: Try COPS=0 (automatic registration) */
    ret = diag_at_command(ctx->diag, "+COPS=0", rsp, sizeof(rsp));
    if (ret >= 0 && strstr(rsp, "OK")) {
        LOGI("Automatic registration attempt...");
        /* Check what we connected to */
        at_query(ctx->diag, "+COPS?", rsp, sizeof(rsp));
        LOGD("Current operator: %s", rsp);

        if (strstr(rsp, plmn_str)) {
            pthread_mutex_lock(&ctx->mutex);
            ctx->state = UE_STATE_REGISTERED;
            pthread_mutex_unlock(&ctx->mutex);
            if (ctx->on_registered) ctx->on_registered(ctx->userdata);
            ue_start_signal_monitor(ctx);
            return 0;
        }
    }

    LOGE("Failed to register on %s", plmn_str);
    pthread_mutex_lock(&ctx->mutex);
    ctx->state = UE_STATE_ERROR;
    snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Registration failed for %s", plmn_str);
    pthread_mutex_unlock(&ctx->mutex);
    return -1;
}

int ue_start_signal_monitor(ue_context_t* ctx) {
    if (!ctx) return -1;

    ctx->running = true;
    if (pthread_create(&ctx->signal_thread, NULL, signal_thread_fn, ctx) != 0) {
        LOGE("Failed to create signal monitor thread");
        ctx->running = false;
        return -1;
    }
    return 0;
}

int ue_stop_signal_monitor(ue_context_t* ctx) {
    if (!ctx) return -1;
    ctx->running = false;
    pthread_join(ctx->signal_thread, NULL);
    return 0;
}

int ue_make_call(ue_context_t* ctx) {
    if (!ctx) return -1;
    if (ctx->state != UE_STATE_REGISTERED && ctx->state != UE_STATE_IDLE) {
        LOGE("Cannot make call: not registered");
        return -1;
    }

    pthread_mutex_lock(&ctx->mutex);
    ctx->state = UE_STATE_CALLING;
    pthread_mutex_unlock(&ctx->mutex);

    /* Dial number 1 — in direct link mode, any number reaches the BTS */
    char rsp[256];
    int ret = diag_at_command(ctx->diag, "D1;", rsp, sizeof(rsp));
    if (ret >= 0 && (strstr(rsp, "OK") || strstr(rsp, "CONNECT"))) {
        LOGI("Call initiated");
        pthread_mutex_lock(&ctx->mutex);
        ctx->state = UE_STATE_IN_CALL;
        ctx->call_active = true;
        pthread_mutex_unlock(&ctx->mutex);

        if (ctx->on_call_connected) ctx->on_call_connected(ctx->userdata);
        return 0;
    }

    /* Try emergency call path */
    ret = diag_at_command(ctx->diag, "D112;", rsp, sizeof(rsp));
    if (ret >= 0 && (strstr(rsp, "OK") || strstr(rsp, "CONNECT"))) {
        LOGI("Emergency call path succeeded");
        pthread_mutex_lock(&ctx->mutex);
        ctx->state = UE_STATE_IN_CALL;
        ctx->call_active = true;
        pthread_mutex_unlock(&ctx->mutex);

        if (ctx->on_call_connected) ctx->on_call_connected(ctx->userdata);
        return 0;
    }

    /* Try via QMI Voice Service */
    uint8_t req[16];
    uint16_t rl = tlv_put_u8(req, 0x01, 0x01); /* Call type: voice */
    /* Dial string */
    uint8_t dial_str[] = {'1', 0x00};
    rl += tlv_put(req + rl, 0x02, dial_str, 2);

    uint8_t qmi_rsp[DIAG_MAX_PAYLOAD];
    int n = qmi_request(ctx->diag, QMI_SUBSYS_VS, 0x0020, req, rl, qmi_rsp, sizeof(qmi_rsp), 10000);
    if (n >= 0 && qmi_response_ok(qmi_rsp, n)) {
        LOGI("QMI voice call initiated");
        pthread_mutex_lock(&ctx->mutex);
        ctx->state = UE_STATE_IN_CALL;
        ctx->call_active = true;
        pthread_mutex_unlock(&ctx->mutex);

        if (ctx->on_call_connected) ctx->on_call_connected(ctx->userdata);
        return 0;
    }

    LOGE("Failed to initiate call");
    pthread_mutex_lock(&ctx->mutex);
    ctx->state = UE_STATE_REGISTERED;
    pthread_mutex_unlock(&ctx->mutex);
    return -1;
}

int ue_end_call(ue_context_t* ctx) {
    if (!ctx || !ctx->call_active) return -1;

    char rsp[256];
    diag_at_command(ctx->diag, "CHUP", rsp, sizeof(rsp));

    pthread_mutex_lock(&ctx->mutex);
    ctx->state = UE_STATE_REGISTERED;
    ctx->call_active = false;
    pthread_mutex_unlock(&ctx->mutex);

    if (ctx->on_call_ended) ctx->on_call_ended(ctx->userdata);
    LOGI("Call ended");
    return 0;
}

int ue_answer_call(ue_context_t* ctx) {
    if (!ctx) return -1;

    char rsp[256];
    int ret = diag_at_command(ctx->diag, "ATA", rsp, sizeof(rsp));
    if (ret >= 0 && strstr(rsp, "OK")) {
        pthread_mutex_lock(&ctx->mutex);
        ctx->state = UE_STATE_IN_CALL;
        ctx->call_active = true;
        ctx->ringing = false;
        pthread_mutex_unlock(&ctx->mutex);

        if (ctx->on_call_connected) ctx->on_call_connected(ctx->userdata);
        return 0;
    }
    return -1;
}

ue_state_t ue_get_state(ue_context_t* ctx) {
    if (!ctx) return UE_STATE_IDLE;
    return ctx->state;
}

int16_t ue_get_rssi(ue_context_t* ctx) {
    if (!ctx) return -120;
    return ctx->rssi_dbm;
}

int ue_disconnect(ue_context_t* ctx) {
    if (!ctx) return -1;

    ue_stop_signal_monitor(ctx);

    if (ctx->call_active) {
        ue_end_call(ctx);
    }

    /* Detach from network */
    char rsp[256];
    diag_at_command(ctx->diag, "+COPS=2", rsp, sizeof(rsp)); /* Deregister */

    qmi_dms_set_offline(ctx->diag);

    ctx->state = UE_STATE_IDLE;
    LOGI("UE disconnected");
    return 0;
}

void ue_free(ue_context_t* ctx) {
    if (!ctx) return;
    pthread_mutex_destroy(&ctx->mutex);
    free(ctx);
}

void ue_set_callbacks(ue_context_t* ctx,
                      void (*on_registered)(void*),
                      void (*on_incoming_call)(void*),
                      void (*on_call_connected)(void*),
                      void (*on_call_ended)(void*),
                      void (*on_signal_update)(void*, int16_t),
                      void* userdata) {
    if (!ctx) return;
    ctx->on_registered = on_registered;
    ctx->on_incoming_call = on_incoming_call;
    ctx->on_call_connected = on_call_connected;
    ctx->on_call_ended = on_call_ended;
    ctx->on_signal_update = on_signal_update;
    ctx->userdata = userdata;
}
