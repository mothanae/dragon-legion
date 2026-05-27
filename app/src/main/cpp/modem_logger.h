#ifndef CELLLINK_MODEM_LOGGER_H
#define CELLLINK_MODEM_LOGGER_H

#include "diag.h"
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MODEM_LOG_RING_SIZE       (256 * 1024)  /* 256KB ring buffer */
#define MODEM_LOG_MAX_FILE_SIZE   (10 * 1024 * 1024) /* 10MB max log file */
#define MODEM_LOG_LINE_MAX        512

typedef enum {
    LOG_LEVEL_DEBUG   = 0,
    LOG_LEVEL_INFO    = 1,
    LOG_LEVEL_WARN    = 2,
    LOG_LEVEL_ERROR   = 3,
    LOG_LEVEL_FATAL   = 4,
} modem_log_level_t;

typedef enum {
    LOG_CATEGORY_DIAG     = 0,  /* DIAG protocol messages */
    LOG_CATEGORY_QMI      = 1,  /* QMI service messages */
    LOG_CATEGORY_NAS      = 2,  /* NAS layer (registration, mobility) */
    LOG_CATEGORY_AS       = 3,  /* AS layer (RRC, MAC, PHY) */
    LOG_CATEGORY_SIM      = 4,  /* SIM/USIM operations */
    LOG_CATEGORY_AUDIO    = 5,  /* Voice/audio path */
    LOG_CATEGORY_RF       = 6,  /* RF frontend */
    LOG_CATEGORY_CRASH    = 7,  /* Crash/exception logs */
    LOG_CATEGORY_CUSTOM   = 8,
} modem_log_category_t;

typedef struct {
    uint64_t             timestamp_ms;
    modem_log_level_t    level;
    modem_log_category_t category;
    char                 message[MODEM_LOG_LINE_MAX];
} modog_entry_t;

typedef struct {
    FILE*                file;
    char                 filename[256];
    bool                 is_running;
    pthread_t            capture_thread;
    pthread_mutex_t      lock;

    /* Ring buffer */
    modog_entry_t*       ring;
    uint32_t             ring_pos;
    uint32_t             ring_count;
    uint32_t             ring_size;

    /* Filter */
    modem_log_level_t    min_level;
    uint16_t             category_mask; /* Bitmask of enabled categories */

    /* Stats */
    uint32_t             entries_logged;
    uint32_t             entries_dropped;
    uint64_t             bytes_written;
} modem_logger_t;

/* ── API ─────────────────────────────────────────────────────────────── */

/** Create a modem logger. */
modem_logger_t* modem_logger_create(const char* filename, uint32_t ring_entries);

/** Free logger resources. */
void modem_logger_free(modem_logger_t* logger);

/** Start logging to file. */
int modem_logger_start(modem_logger_t* logger);

/** Stop logging. */
int modem_logger_stop(modem_logger_t* logger);

/** Set minimum log level filter. */
void modem_logger_set_level(modem_logger_t* logger, modem_log_level_t level);

/** Enable/disable log categories via bitmask. */
void modem_logger_set_categories(modem_logger_t* logger, uint16_t mask);

/** Write a log entry. Thread-safe. */
int modem_log_write(modem_logger_t* logger, modem_log_level_t level,
                    modem_log_category_t cat, const char* fmt, ...);

/** Capture DIAG log packets from the modem and store them. */
int modem_logger_capture(modem_logger_t* logger, diag_handle_t* h);

/** Dump the ring buffer to file. */
int modem_logger_flush(modem_logger_t* logger);

/** Export ring buffer entries as text. */
int modem_logger_export(modem_logger_t* logger, char* out, uint32_t max_len,
                        uint32_t last_n);

/** Get the category name as a string. */
const char* modem_log_category_name(modem_log_category_t cat);

/** Get the level name as a string. */
const char* modem_log_level_name(modem_log_level_t level);

#ifdef __cplusplus
}
#endif

#endif /* CELLLINK_MODEM_LOGGER_H */
