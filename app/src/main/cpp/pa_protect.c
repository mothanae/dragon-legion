#include "pa_protect.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <math.h>
#include <android/log.h>

#define LOG_TAG "CellLink-PA"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

static uint64_t pa_get_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

/* ── Public API ───────────────────────────────────────────────────────── */

pa_protect_t* pa_protect_init(void) {
    pa_protect_t* pa = (pa_protect_t*)calloc(1, sizeof(pa_protect_t));
    if (!pa) return NULL;

    pa->state = PA_STATE_IDLE;
    pa->current_power_dbm = PA_DEFAULT_POWER_DBM;
    pa->current_temp_c = 25.0f; /* Assume room temp at startup */

    if (pthread_mutex_init(&pa->lock, NULL) != 0) {
        free(pa); return NULL;
    }

    LOGI("PA protection initialized (max duty=%d%%, max temp=%.0fC, max SWR=%.1f)",
         PA_MAX_DUTY_CYCLE_PCT, PA_MAX_TEMP_C, PA_MAX_SWR);
    return pa;
}

void pa_protect_free(pa_protect_t* pa) {
    if (!pa) return;
    pthread_mutex_destroy(&pa->lock);
    free(pa);
}

int pa_protect_tx_start(pa_protect_t* pa, uint8_t power_dbm, uint16_t arfcn) {
    if (!pa) return -1;
    pthread_mutex_lock(&pa->lock);

    /* Check if Tx is allowed */
    switch (pa->state) {
        case PA_STATE_OVERHEAT:
            pthread_mutex_unlock(&pa->lock);
            LOGI("Tx blocked: PA overheated (%.1fC)", pa->current_temp_c);
            return -1;
        case PA_STATE_COOLING: {
            uint64_t elapsed = pa_get_ms() - pa->cooldown_start_ms;
            if (elapsed < PA_COOLDOWN_MS) {
                pthread_mutex_unlock(&pa->lock);
                LOGI("Tx blocked: cooling down (%llu ms remaining)",
                     (unsigned long long)(PA_COOLDOWN_MS - elapsed));
                return -1;
            }
            break;
        }
        case PA_STATE_EMERGENCY_STOP:
            pthread_mutex_unlock(&pa->lock);
            LOGI("Tx blocked: emergency stop active");
            return -1;
        default:
            break;
    }

    /* Clamp power to safe range */
    if (power_dbm > PA_MAX_POWER_DBM) power_dbm = PA_MAX_POWER_DBM;
    if (power_dbm < PA_MIN_POWER_DBM) power_dbm = PA_MIN_POWER_DBM;

    pa->requested_power_dbm = power_dbm;
    pa->current_power_dbm = power_dbm;
    pa->current_arfcn = arfcn;
    pa->tx_started_ms = pa_get_ms();
    pa->state = PA_STATE_TX_ACTIVE;

    /* Check continuous Tx limit and apply backoff */
    if (pa->total_tx_ms > 0) {
        uint64_t session_duration = pa_get_ms() - pa->tx_started_ms + pa->total_tx_ms;

        /* If we've been transmitting too long, force cooldown */
        if (session_duration > PA_MAX_CONTINUOUS_TX_MS * 2) {
            pa->state = PA_STATE_COOLING;
            pa->cooldown_start_ms = pa_get_ms();
            pa->total_tx_ms = 0;
            pthread_mutex_unlock(&pa->lock);
            LOGI("Tx blocked: exceeded max session duration");
            return -1;
        }

        /* Apply duty cycle power reduction */
        float duty = (float)session_duration / (float)(session_duration + PA_COOLDOWN_MS);
        if (duty * 100.0f > PA_MAX_DUTY_CYCLE_PCT) {
            /* Reduce power proportionally to maintain duty cycle */
            float reduction = PA_MAX_DUTY_CYCLE_PCT / (duty * 100.0f);
            int8_t power_reduction_db = (int8_t)(-10.0f * log10f(reduction));
            if (pa->current_power_dbm + power_reduction_db > PA_MIN_POWER_DBM) {
                pa->current_power_dbm += power_reduction_db;
            }
            LOGD("PA power reduced to %d dBm for duty cycle protection", pa->current_power_dbm);
        }
    }

    pa->tx_cycles++;
    LOGD("PA Tx started: ARFCN=%d, power=%d dBm", arfcn, pa->current_power_dbm);
    pthread_mutex_unlock(&pa->lock);
    return 0;
}

int pa_protect_tx_stop(pa_protect_t* pa) {
    if (!pa) return -1;
    pthread_mutex_lock(&pa->lock);

    if (pa->state == PA_STATE_TX_ACTIVE) {
        uint64_t tx_duration = pa_get_ms() - pa->tx_started_ms;
        pa->total_tx_ms += tx_duration;
        pa->state = PA_STATE_IDLE;

        LOGD("PA Tx stopped: duration=%llu ms, total=%llu ms",
             (unsigned long long)tx_duration, (unsigned long long)pa->total_tx_ms);

        /* Check if cooling period needed */
        float duty_pct = (float)pa->total_tx_ms /
                         (float)(pa->total_tx_ms + (pa_get_ms() - pa->tx_started_ms - tx_duration) + 1);
        if (duty_pct * 100.0f > PA_MAX_DUTY_CYCLE_PCT * 2) {
            pa->state = PA_STATE_COOLING;
            pa->cooldown_start_ms = pa_get_ms();
            LOGI("PA entering cooldown (duty cycle %.1f%% exceeded)", duty_pct * 100.0f);
        }
    }

    pthread_mutex_unlock(&pa->lock);
    return 0;
}

bool pa_protect_update(pa_protect_t* pa, float temp_c,
                       float fwd_power_dbm, float rev_power_dbm) {
    if (!pa) return false;
    pthread_mutex_lock(&pa->lock);

    /* Update temperature */
    pa->current_temp_c = temp_c;
    pa->last_temp_read_ms = pa_get_ms();
    if (temp_c > pa->peak_temp_c) pa->peak_temp_c = temp_c;

    /* Update power measurements */
    pa->forward_power_dbm = fwd_power_dbm;
    pa->reflected_power_dbm = rev_power_dbm;

    /* Calculate VSWR from reflected/forward power */
    if (fwd_power_dbm > -100.0f && rev_power_dbm < fwd_power_dbm) {
        float reflection_coeff = powf(10.0f, (rev_power_dbm - fwd_power_dbm) / 20.0f);
        if (reflection_coeff < 1.0f) {
            pa->estimated_swr = (1.0f + reflection_coeff) / (1.0f - reflection_coeff);
        } else {
            pa->estimated_swr = 99.0f; /* Total reflection */
        }
    }

    bool can_tx = true;

    /* Check temperature limits */
    if (temp_c >= PA_MAX_TEMP_C) {
        LOGE("PA OVERHEAT: %.1fC > %.1fC limit", temp_c, PA_MAX_TEMP_C);
        pa->state = PA_STATE_OVERHEAT;
        snprintf(pa->fault_reason, sizeof(pa->fault_reason),
                "Overheating: %.1fC (limit %.1fC)", temp_c, PA_MAX_TEMP_C);
        can_tx = false;
        if (pa->on_fault) pa->on_fault(pa->userdata, pa->fault_reason);
    } else if (temp_c >= PA_TEMP_WARNING_C) {
        LOGD("PA temp warning: %.1fC", temp_c);
        if (pa->on_temp_warning) pa->on_temp_warning(pa->userdata, temp_c);
        /* Continue transmitting but with reduced power */
        if (pa->current_power_dbm > (PA_DEFAULT_POWER_DBM - 6)) {
            pa->current_power_dbm = PA_DEFAULT_POWER_DBM - 6;
        }
    }

    /* Check SWR limit (antenna fault) */
    if (pa->estimated_swr > PA_MAX_SWR) {
        LOGE("PA SWR FAULT: %.1f > %.1f limit", pa->estimated_swr, PA_MAX_SWR);
        pa->state = PA_STATE_FAULT;
        snprintf(pa->fault_reason, sizeof(pa->fault_reason),
                "Antenna fault: SWR=%.1f (limit %.1f)", pa->estimated_swr, PA_MAX_SWR);
        can_tx = false;
        pa->emergency_stops++;
        if (pa->on_fault) pa->on_fault(pa->userdata, pa->fault_reason);
    }

    /* Allow cooling if temperature drops */
    if (pa->state == PA_STATE_OVERHEAT && temp_c < PA_TEMP_WARNING_C) {
        pa->state = PA_STATE_COOLING;
        pa->cooldown_start_ms = pa_get_ms();
        LOGI("PA cooling down (%.1fC < %.1fC)", temp_c, PA_TEMP_WARNING_C);
    }

    pthread_mutex_unlock(&pa->lock);
    return can_tx;
}

bool pa_protect_can_transmit(pa_protect_t* pa) {
    if (!pa) return false;
    return (pa->state == PA_STATE_IDLE ||
            pa->state == PA_STATE_TX_ACTIVE);
}

uint32_t pa_protect_cooldown_remaining(pa_protect_t* pa) {
    if (!pa || pa->state != PA_STATE_COOLING) return 0;
    uint64_t elapsed = pa_get_ms() - pa->cooldown_start_ms;
    if (elapsed >= PA_COOLDOWN_MS) return 0;
    return (uint32_t)(PA_COOLDOWN_MS - elapsed);
}

const char* pa_protect_state_string(pa_protect_t* pa) {
    if (!pa) return "UNKNOWN";
    switch (pa->state) {
        case PA_STATE_IDLE:           return "IDLE";
        case PA_STATE_TX_ACTIVE:      return "TX_ACTIVE";
        case PA_STATE_COOLING:        return "COOLING";
        case PA_STATE_OVERHEAT:       return "OVERHEAT";
        case PA_STATE_FAULT:          return "FAULT";
        case PA_STATE_EMERGENCY_STOP: return "EMERGENCY_STOP";
        default:                      return "???";
    }
}

void pa_protect_set_callbacks(pa_protect_t* pa,
                               void (*on_fault)(void*, const char*),
                               void (*on_temp)(void*, float),
                               void* userdata) {
    if (!pa) return;
    pa->on_fault = on_fault;
    pa->on_temp_warning = on_temp;
    pa->userdata = userdata;
}
