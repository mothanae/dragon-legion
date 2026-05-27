#include "modem_recovery.h"
#include "qmi.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <android/log.h>

#define LOG_TAG "CellLink-RECOVER"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

/* NV items critical for modem operation (partial list) */
static const uint16_t CRITICAL_NV_ITEMS[] = {
    10,     /* Preferred network type */
    441,    /* Band preference */
    550,    /* IMSI */
    6828,   /* IRAT LTE->GSM */
    453,    /* Subsidy lock */
    0       /* Sentinel */
};

/* ── Watchdog Thread ─────────────────────────────────────────────────── */

static void* watchdog_thread_fn(void* arg) {
    modem_recovery_t* rec = (modem_recovery_t*)arg;
    LOGI("Modem watchdog started (interval=%u sec)", rec->uptime_seconds);

    while (true) {
        pthread_mutex_lock(&rec->lock);
        bool running = rec->watchdog_running;
        pthread_mutex_unlock(&rec->lock);
        if (!running) break;

        sleep(rec->uptime_seconds > 0 ? rec->uptime_seconds : 5);

        if (!modem_is_alive(rec)) {
            LOGE("Watchdog: modem not responding!");
            pthread_mutex_lock(&rec->lock);
            rec->last_crash = MODEM_CRASH_WDOG_BITE;
            rec->last_crash_time = time(NULL);
            rec->crash_count++;
            rec->state = MODEM_STATE_CRASHED;
            pthread_mutex_unlock(&rec->lock);

            LOGI("Watchdog: attempting recovery...");
            modem_recover(rec);
        }
    }

    LOGI("Watchdog stopped");
    return NULL;
}

/* ── Modem State Detection ───────────────────────────────────────────── */

modem_state_t modem_detect_state(diag_handle_t* h) {
    if (!h) return MODEM_STATE_UNKNOWN;

    /* Check DIAG port responsiveness */
    if (!diag_is_ready(h)) {
        /* Try AT command via raw write */
        uint8_t at_req[] = "AT\r\n";
        if (diag_raw_write(h, at_req, 4) > 0) {
            uint8_t rsp[64];
            if (diag_raw_read(h, rsp, sizeof(rsp), 2000) > 0) {
                if (strstr((char*)rsp, "OK")) return MODEM_STATE_ONLINE;
            }
        }
        return MODEM_STATE_OFFLINE;
    }

    /* Check operating mode via QMI DMS */
    uint8_t req[3];
    uint16_t rl = tlv_put_u8(req, 0x01, 0x00);
    uint8_t rsp[64];
    int n = qmi_request(h, QMI_SUBSYS_DMS, QMI_DMS_GET_OPERATING_MODE, req, rl, rsp, sizeof(rsp), 2000);

    if (n >= 0 && qmi_response_ok(rsp, n)) {
        return MODEM_STATE_ONLINE;
    }

    /* Check via AT */
    char at_rsp[64];
    n = diag_at_command(h, "+CFUN?", at_rsp, sizeof(at_rsp));
    if (n > 0) {
        int fun;
        if (sscanf(at_rsp, "+CFUN: %d", &fun) == 1) {
            return (fun >= 1) ? MODEM_STATE_ONLINE : MODEM_STATE_OFFLINE;
        }
    }

    /* Try AT basic */
    n = diag_at_command(h, "", at_rsp, sizeof(at_rsp));
    if (n >= 0 && strstr(at_rsp, "OK")) return MODEM_STATE_ONLINE;

    return MODEM_STATE_OFFLINE;
}

/* ── Reset Operations ────────────────────────────────────────────────── */

int modem_warm_reset(diag_handle_t* h) {
    LOGI("Initiating modem warm reset...");

    /* Method 1: AT+CFUN=1,1 (full functionality + reset) */
    char rsp[64];
    int n = diag_at_command(h, "+CFUN=1,1", rsp, sizeof(rsp));
    if (n >= 0 && strstr(rsp, "OK")) {
        LOGI("Modem warm reset via AT+CFUN");
        sleep(10); /* Wait for modem to restart */
        return 0;
    }

    /* Method 2: QMI DMS reset */
    uint8_t req[3];
    uint16_t rl = tlv_put_u8(req, 0x01, 0x01); /* Reset mode: warm */
    uint8_t qmi_rsp[64];
    n = qmi_request(h, QMI_SUBSYS_DMS, 0x002B, req, rl, qmi_rsp, sizeof(qmi_rsp), 10000);
    if (n >= 0 && qmi_response_ok(qmi_rsp, n)) {
        LOGI("Modem warm reset via QMI DMS");
        sleep(10);
        return 0;
    }

    LOGE("Warm reset failed");
    return -1;
}

int modem_cold_reset(diag_handle_t* h) {
    LOGI("Initiating modem cold reset...");

    /* Try to toggle modem power via GPIO sysfs (device-specific) */
    const char* gpio_paths[] = {
        "/sys/class/gpio/modem_reset/value",
        "/sys/kernel/modem_power/reset",
        "/sys/devices/platform/msm_hsic_host/modem_reset",
        NULL
    };

    for (int i = 0; gpio_paths[i]; i++) {
        int fd = open(gpio_paths[i], O_WRONLY);
        if (fd >= 0) {
            /* Toggle: assert reset (0), wait, deassert (1) */
            write(fd, "0", 1);
            usleep(500000); /* 500ms */
            write(fd, "1", 1);
            close(fd);
            LOGI("Modem cold reset via %s", gpio_paths[i]);
            sleep(15); /* Wait for full modem reboot */
            return 0;
        }
    }

    /* Fallback: AT+CFUN=0 (offline), then AT+CFUN=1 (online with reset) */
    char rsp[64];
    diag_at_command(h, "+CFUN=0", rsp, sizeof(rsp));
    sleep(3);
    diag_at_command(h, "+CFUN=1,1", rsp, sizeof(rsp));
    sleep(10);

    LOGI("Modem cold reset via AT+CFUN cycle");
    return 0;
}

int modem_enter_edl(diag_handle_t* h) {
    /* Send QMI command to enter EDL mode */
    uint8_t req[1] = {0x01};
    uint8_t rsp[32];
    int n = qmi_request(h, QMI_SUBSYS_DMS, 0x002E, req, 1, rsp, sizeof(rsp), 5000);
    if (n >= 0) {
        LOGI("Modem entering EDL mode...");
        return 0;
    }

    /* Fallback: AT command (rarely supported) */
    char at_rsp[32];
    diag_at_command(h, "+EDL=1", at_rsp, sizeof(at_rsp));
    return -1;
}

/* ── Recovery ────────────────────────────────────────────────────────── */

modem_state_t modem_recover(modem_recovery_t* rec) {
    LOGI("=== Modem Recovery Sequence ===");

    /* Step 1: Detect current state */
    rec->state = modem_detect_state(rec->diag);
    LOGI("Current state: %d", rec->state);

    if (rec->state == MODEM_STATE_ONLINE) {
        LOGI("Modem is online, no recovery needed");
        return MODEM_STATE_ONLINE;
    }

    /* Step 2: Warm reset */
    LOGI("Attempting warm reset...");
    if (modem_warm_reset(rec->diag) == 0) {
        rec->state = modem_detect_state(rec->diag);
        if (rec->state == MODEM_STATE_ONLINE) {
            LOGI("Warm reset successful — modem online");
            return MODEM_STATE_ONLINE;
        }
    }

    /* Step 3: Cold reset */
    LOGI("Attempting cold reset...");
    if (modem_cold_reset(rec->diag) == 0) {
        rec->state = modem_detect_state(rec->diag);
        if (rec->state == MODEM_STATE_ONLINE) {
            LOGI("Cold reset successful — modem online");
            return MODEM_STATE_ONLINE;
        }
    }

    /* Step 4: Last resort — NV restore */
    if (rec->nv_backup) {
        LOGI("Attempting NV restore...");
        modem_nv_restore(rec);
        sleep(5);
        rec->state = modem_detect_state(rec->diag);
    }

    LOGE("Recovery failed — modem remains offline");
    return rec->state;
}

/* ── NV Backup/Restore ───────────────────────────────────────────────── */

int modem_nv_backup(modem_recovery_t* rec) {
    if (!rec || !rec->diag) return 0;

    /* Allocate backup buffer */
    size_t buf_size = 16384; /* 16KB should cover critical NV items */
    rec->nv_backup = (uint8_t*)malloc(buf_size);
    if (!rec->nv_backup) return -1;

    uint32_t offset = 0;
    int backed_up = 0;

    for (int i = 0; CRITICAL_NV_ITEMS[i] != 0; i++) {
        uint16_t nv_id = CRITICAL_NV_ITEMS[i];
        int n = diag_nv_read(rec->diag, nv_id,
                             rec->nv_backup + offset + 2,
                             (uint16_t)(buf_size - offset - 4));
        if (n > 0) {
            /* Store: [nv_id(2)] [len(2)] [data(n)] */
            rec->nv_backup[offset]     = (uint8_t)(nv_id & 0xFF);
            rec->nv_backup[offset + 1] = (uint8_t)((nv_id >> 8) & 0xFF);
            rec->nv_backup[offset + 2] = (uint8_t)(n & 0xFF);
            rec->nv_backup[offset + 3] = (uint8_t)((n >> 8) & 0xFF);
            offset += 4 + n;
            backed_up++;
        }
    }

    rec->nv_backup_size = offset;
    LOGI("NV backup: %d items, %d bytes", backed_up, offset);
    return backed_up;
}

int modem_nv_restore(modem_recovery_t* rec) {
    if (!rec || !rec->nv_backup || !rec->nv_backup_size) return 0;

    int restored = 0;
    uint32_t offset = 0;

    while (offset + 4 <= rec->nv_backup_size) {
        uint16_t nv_id = (uint16_t)rec->nv_backup[offset] |
                         ((uint16_t)rec->nv_backup[offset + 1] << 8);
        uint16_t len   = (uint16_t)rec->nv_backup[offset + 2] |
                         ((uint16_t)rec->nv_backup[offset + 3] << 8);

        if (len == 0 || offset + 4 + len > rec->nv_backup_size) break;

        if (diag_nv_write(rec->diag, nv_id, rec->nv_backup + offset + 4, len) == 0) {
            restored++;
        }

        offset += 4 + len;
    }

    LOGI("NV restore: %d items restored", restored);
    return restored;
}

/* ── Heartbeat ───────────────────────────────────────────────────────── */

bool modem_is_alive(modem_recovery_t* rec) {
    if (!rec || !rec->diag) return false;
    return diag_is_ready(rec->diag);
}

modem_recovery_t* modem_recovery_init(diag_handle_t* h) {
    modem_recovery_t* rec = (modem_recovery_t*)calloc(1, sizeof(modem_recovery_t));
    if (!rec) return NULL;

    rec->diag = h;
    rec->state = MODEM_STATE_UNKNOWN;
    rec->uptime_seconds = 5; /* Default watchdog interval */

    if (pthread_mutex_init(&rec->lock, NULL) != 0) {
        free(rec);
        return NULL;
    }

    /* Backup NV on init */
    modem_nv_backup(rec);

    LOGI("Modem recovery initialized");
    return rec;
}

void modem_recovery_free(modem_recovery_t* rec) {
    if (!rec) return;
    modem_watchdog_stop(rec);
    free(rec->nv_backup);
    pthread_mutex_destroy(&rec->lock);
    free(rec);
}

int modem_watchdog_start(modem_recovery_t* rec, uint32_t interval_sec) {
    if (!rec) return -1;
    rec->uptime_seconds = interval_sec;
    rec->watchdog_running = true;

    if (pthread_create(&rec->watchdog_thread, NULL, watchdog_thread_fn, rec) != 0) {
        rec->watchdog_running = false;
        return -1;
    }
    return 0;
}

int modem_watchdog_stop(modem_recovery_t* rec) {
    if (!rec) return -1;
    rec->watchdog_running = false;
    pthread_join(rec->watchdog_thread, NULL);
    return 0;
}

const char* modem_crash_info(modem_recovery_t* rec) {
    if (!rec) return "N/A";
    snprintf(rec->crash_log, sizeof(rec->crash_log),
        "Last crash: type=%d, count=%u, timestamp=%llu, state=%d",
        rec->last_crash, rec->crash_count,
        (unsigned long long)rec->last_crash_time, rec->state);
    return rec->crash_log;
}

int modem_full_recovery(modem_recovery_t* rec) {
    modem_nv_backup(rec);
    modem_state_t result = modem_recover(rec);
    if (result != MODEM_STATE_ONLINE) {
        modem_nv_restore(rec);
    }
    return (result == MODEM_STATE_ONLINE) ? 0 : -1;
}
