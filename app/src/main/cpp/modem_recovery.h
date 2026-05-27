#ifndef CELLLINK_MODEM_RECOVERY_H
#define CELLLINK_MODEM_RECOVERY_H

#include "diag.h"
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Modem Crash Types ───────────────────────────────────────────────── */

typedef enum {
    MODEM_CRASH_NONE,
    MODEM_CRASH_WDOG_BITE,      /* Watchdog timeout */
    MODEM_CRASH_DSP_FAULT,      /* Hexagon DSP exception */
    MODEM_CRASH_RAM_DUMP,       /* Full RAM dump triggered */
    MODEM_CRASH_ASSERT,         /* Firmware assertion failure */
    MODEM_CRASH_SILENT_REBOOT,  /* Modem restarted without notification */
    MODEM_CRASH_MODEM_OFFLINE   /* Modem went offline / in airplane mode */
} modem_crash_type_t;

typedef enum {
    MODEM_STATE_UNKNOWN,
    MODEM_STATE_ONLINE,
    MODEM_STATE_OFFLINE,
    MODEM_STATE_RESETTING,
    MODEM_STATE_CRASHED,
    MODEM_STATE_EDL_MODE,       /* Emergency Download Mode */
    MODEM_STATE_DLOAD_MODE      /* Download mode */
} modem_state_t;

typedef struct {
    modem_state_t     state;
    modem_crash_type_t last_crash;
    uint64_t          last_crash_time;
    uint32_t          crash_count;
    uint32_t          uptime_seconds;
    bool              watchdog_running;
    pthread_t         watchdog_thread;
    pthread_mutex_t   lock;
    diag_handle_t*    diag;

    /* NV backup */
    uint8_t*          nv_backup;
    uint32_t          nv_backup_size;

    /* Crash log */
    char              crash_log[4096];
} modem_recovery_t;

/* ── API ─────────────────────────────────────────────────────────────── */

/** Initialize modem recovery system. */
modem_recovery_t* modem_recovery_init(diag_handle_t* h);

/** Free recovery resources. */
void modem_recovery_free(modem_recovery_t* recovery);

/**
 * Start watchdog heartbeat monitoring.
 * Sends periodic DIAG VERSION_F commands to verify modem responsiveness.
 * If modem stops responding, triggers recovery sequence.
 */
int modem_watchdog_start(modem_recovery_t* rec, uint32_t interval_sec);

/** Stop watchdog. */
int modem_watchdog_stop(modem_recovery_t* rec);

/**
 * Detect current modem state.
 */
modem_state_t modem_detect_state(diag_handle_t* h);

/**
 * Force modem warm reset (reboot baseband only).
 * Uses QMI DMS reset or AT+CFUN sequence.
 */
int modem_warm_reset(diag_handle_t* h);

/**
 * Force modem cold reset (full power cycle).
 * Toggles modem power via GPIO/sysfs if available.
 */
int modem_cold_reset(diag_handle_t* h);

/**
 * Boot modem into EDL (Emergency Download Mode) for firmware recovery.
 * DANGER: This disables normal modem operation.
 */
int modem_enter_edl(diag_handle_t* h);

/**
 * Recover from a modem crash. Attempts warm reset first, then cold reset.
 * Returns final modem state after recovery attempt.
 */
modem_state_t modem_recover(modem_recovery_t* rec);

/**
 * Backup critical NV items before performing dangerous operations.
 * Returns number of NV items backed up.
 */
int modem_nv_backup(modem_recovery_t* rec);

/**
 * Restore NV items from backup.
 * Returns number of NV items restored.
 */
int modem_nv_restore(modem_recovery_t* rec);

/**
 * Check if modem is responsive via heartbeat.
 */
bool modem_is_alive(modem_recovery_t* rec);

/**
 * Get last crash information as human-readable string.
 */
const char* modem_crash_info(modem_recovery_t* rec);

/**
 * Full recovery sequence: detect, backup, reset, restore, reinit.
 * Returns 0 if modem is operational after recovery.
 */
int modem_full_recovery(modem_recovery_t* rec);

#ifdef __cplusplus
}
#endif

#endif /* CELLLINK_MODEM_RECOVERY_H */
