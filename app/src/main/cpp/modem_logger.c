#include "modem_logger.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <android/log.h>

#define LOG_TAG "CellLink-MLOG"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

static uint64_t mlog_get_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

const char* modem_log_category_name(modem_log_category_t cat) {
    static const char* names[] = {"DIAG","QMI","NAS","AS","SIM","AUDIO","RF","CRASH","CUSTOM"};
    return (cat < 9) ? names[cat] : "???";
}

const char* modem_log_level_name(modem_log_level_t level) {
    static const char* names[] = {"DEBUG","INFO","WARN","ERROR","FATAL"};
    return (level < 5) ? names[level] : "???";
}

/* ── Public API ───────────────────────────────────────────────────────── */

modem_logger_t* modem_logger_create(const char* filename, uint32_t ring_entries) {
    modem_logger_t* log = (modem_logger_t*)calloc(1, sizeof(modem_logger_t));
    if (!log) return NULL;

    if (filename) {
        strncpy(log->filename, filename, sizeof(log->filename) - 1);
    } else {
        time_t now = time(NULL);
        snprintf(log->filename, sizeof(log->filename),
                "/sdcard/CellLink/modem_%lld.log", (long long)now);
    }

    log->ring_size = ring_entries > 0 ? ring_entries : 4096;
    log->ring = (modog_entry_t*)calloc(log->ring_size, sizeof(modog_entry_t));
    if (!log->ring) { free(log); return NULL; }

    log->min_level = LOG_LEVEL_DEBUG;
    log->category_mask = 0xFFFF; /* All categories */

    if (pthread_mutex_init(&log->lock, NULL) != 0) {
        free(log->ring); free(log); return NULL;
    }

    LOGI("Modem logger created: %s (%u entries)", log->filename, log->ring_size);
    return log;
}

void modem_logger_free(modem_logger_t* log) {
    if (!log) return;
    if (log->is_running) modem_logger_stop(log);
    free(log->ring);
    pthread_mutex_destroy(&log->lock);
    free(log);
}

int modem_logger_start(modem_logger_t* log) {
    if (!log) return -1;
    log->file = fopen(log->filename, "ab");
    if (!log->file) return -1;

    log->is_running = true;
    fprintf(log->file, "=== CellLink Modem Log Start ===\n");
    fflush(log->file);
    return 0;
}

int modem_logger_stop(modem_logger_t* log) {
    if (!log || !log->is_running) return -1;
    log->is_running = false;

    modem_logger_flush(log);

    if (log->file) {
        fprintf(log->file, "=== Log End: %u entries, %u dropped ===\n",
                log->entries_logged, log->entries_dropped);
        fclose(log->file);
        log->file = NULL;
    }
    return 0;
}

void modem_logger_set_level(modem_logger_t* log, modem_log_level_t level) {
    if (log) log->min_level = level;
}

void modem_logger_set_categories(modem_logger_t* log, uint16_t mask) {
    if (log) log->category_mask = mask;
}

int modem_log_write(modem_logger_t* log, modem_log_level_t level,
                    modem_log_category_t cat, const char* fmt, ...) {
    if (!log || !log->ring) return -1;

    /* Filter by level and category */
    if (level < log->min_level) return 0;
    if (!(log->category_mask & (1 << cat))) return 0;

    pthread_mutex_lock(&log->lock);

    modog_entry_t* entry = &log->ring[log->ring_pos];
    entry->timestamp_ms = mlog_get_ms();
    entry->level = level;
    entry->category = cat;

    va_list args;
    va_start(args, fmt);
    vsnprintf(entry->message, MODEM_LOG_LINE_MAX, fmt, args);
    va_end(args);

    log->ring_pos = (log->ring_pos + 1) % log->ring_size;
    if (log->ring_count < log->ring_size) log->ring_count++;
    else log->entries_dropped++;

    log->entries_logged++;

    /* Write to file if open */
    if (log->file) {
        fprintf(log->file, "[%llu] %s/%s: %s\n",
                (unsigned long long)entry->timestamp_ms,
                modem_log_level_name(level),
                modem_log_category_name(cat),
                entry->message);
        log->bytes_written += strlen(entry->message) + 40;
    }

    pthread_mutex_unlock(&log->lock);
    return 0;
}

int modem_logger_capture(modem_logger_t* log, diag_handle_t* h) {
    if (!log || !h) return 0;

    /* Poll for DIAG log/event packets */
    uint8_t buf[DIAG_MAX_PAYLOAD];
    uint8_t cmd;
    int n = diag_recv(h, &cmd, buf, sizeof(buf), 30);
    if (n < 4) return 0;

    /* Log the raw DIAG event */
    char hex[256];
    int hp = 0;
    for (int i = 0; i < n && i < 120; i++) {
        hp += snprintf(hex + hp, sizeof(hex) - hp, "%02X", buf[i]);
    }

    modem_log_write(log, LOG_LEVEL_DEBUG, LOG_CATEGORY_DIAG,
                    "cmd=0x%02X len=%d data=%s", cmd, n, hex);
    return 1;
}

int modem_logger_flush(modem_logger_t* log) {
    if (!log || !log->file) return -1;

    pthread_mutex_lock(&log->lock);

    /* Write all buffered entries */
    uint32_t pos = (log->ring_pos + log->ring_size - log->ring_count) % log->ring_size;
    for (uint32_t i = 0; i < log->ring_count; i++) {
        modog_entry_t* e = &log->ring[(pos + i) % log->ring_size];
        fprintf(log->file, "[%llu] %s/%s: %s\n",
                (unsigned long long)e->timestamp_ms,
                modem_log_level_name(e->level),
                modem_log_category_name(e->category),
                e->message);
    }

    fflush(log->file);
    pthread_mutex_unlock(&log->lock);
    return 0;
}

int modem_logger_export(modem_logger_t* log, char* out, uint32_t max_len,
                        uint32_t last_n) {
    if (!log || !out || max_len == 0) return 0;

    pthread_mutex_lock(&log->lock);

    uint32_t available = log->ring_count;
    uint32_t to_export = (last_n < available) ? last_n : available;
    uint32_t start_pos = (log->ring_pos + log->ring_size - to_export) % log->ring_size;

    int pos = 0;
    for (uint32_t i = 0; i < to_export && pos < (int)(max_len - 128); i++) {
        modog_entry_t* e = &log->ring[(start_pos + i) % log->ring_size];
        pos += snprintf(out + pos, max_len - pos, "[%llu] %s/%s: %s\n",
                       (unsigned long long)e->timestamp_ms,
                       modem_log_level_name(e->level),
                       modem_log_category_name(e->category),
                       e->message);
    }

    pthread_mutex_unlock(&log->lock);
    return pos;
}
