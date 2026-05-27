#ifndef CELLLINK_PA_PROTECT_H
#define CELLLINK_PA_PROTECT_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Power Amplifier Protection Limits ───────────────────────────────── */

#define PA_MAX_DUTY_CYCLE_PCT      30     /* Max Tx duty cycle: 30% */
#define PA_MAX_CONTINUOUS_TX_MS    5000   /* Max continuous Tx: 5 seconds */
#define PA_COOLDOWN_MS             30000  /* Cooldown period: 30 seconds */
#define PA_MAX_TEMP_C              85.0f  /* Max PA temperature (Celsius) */
#define PA_TEMP_WARNING_C          70.0f  /* Warning threshold */
#define PA_MAX_SWR                  3.0f  /* Max VSWR before shutdown */
#define PA_DEFAULT_POWER_DBM       33     /* Default Tx power: 33 dBm (2W GSM) */
#define PA_MIN_POWER_DBM           5      /* Minimum Tx power: 5 dBm */
#define PA_MAX_POWER_DBM           39     /* Maximum Tx power: 39 dBm (8W GSM max) */

/* ── PA State ────────────────────────────────────────────────────────── */

typedef enum {
    PA_STATE_IDLE,
    PA_STATE_TX_ACTIVE,
    PA_STATE_COOLING,
    PA_STATE_OVERHEAT,
    PA_STATE_FAULT,
    PA_STATE_EMERGENCY_STOP
} pa_state_t;

typedef struct {
    pa_state_t state;
    pthread_mutex_t lock;

    /* Thermal tracking */
    float    current_temp_c;
    float    peak_temp_c;
    uint64_t last_temp_read_ms;

    /* Tx duty cycle tracking */
    uint64_t tx_started_ms;
    uint64_t total_tx_ms;       /* Total Tx time this cycle */
    uint64_t cooldown_start_ms;
    uint32_t tx_cycles;

    /* Power tracking */
    uint8_t  current_power_dbm;
    uint8_t  requested_power_dbm;
    uint16_t current_arfcn;

    /* SWR / antenna monitoring */
    float    estimated_swr;
    float    reflected_power_dbm;
    float    forward_power_dbm;

    /* Emergency stop counter */
    uint32_t emergency_stops;
    char     fault_reason[128];

    /* Callbacks */
    void (*on_fault)(void* userdata, const char* reason);
    void (*on_temp_warning)(void* userdata, float temp);
    void*    userdata;
} pa_protect_t;

/* ── API ─────────────────────────────────────────────────────────────── */

/** Initialize PA protection system. */
pa_protect_t* pa_protect_init(void);

/** Free PA protection resources. */
void pa_protect_free(pa_protect_t* pa);

/**
 * Called when Tx starts. Begins duty cycle tracking.
 * Returns 0 if Tx is allowed, -1 if blocked (overheat/cooldown).
 */
int pa_protect_tx_start(pa_protect_t* pa, uint8_t power_dbm, uint16_t arfcn);

/**
 * Called when Tx stops. Updates duty cycle counters.
 */
int pa_protect_tx_stop(pa_protect_t* pa);

/**
 * Called periodically (every ~1s) to update thermal state.
 * @param temp_c Current PA temperature in Celsius (from thermistor/ADC)
 * @param fwd_power_dbm Forward power in dBm
 * @param rev_power_dbm Reflected power in dBm
 * @return true if Tx should continue, false if Tx must stop
 */
bool pa_protect_update(pa_protect_t* pa, float temp_c,
                       float fwd_power_dbm, float rev_power_dbm);

/**
 * Check if Tx is currently allowed.
 */
bool pa_protect_can_transmit(pa_protect_t* pa);

/**
 * Get remaining cooldown time in ms.
 */
uint32_t pa_protect_cooldown_remaining(pa_protect_t* pa);

/**
 * Get current PA state as a string.
 */
const char* pa_protect_state_string(pa_protect_t* pa);

/**
 * Set fault callback.
 */
void pa_protect_set_callbacks(pa_protect_t* pa,
                               void (*on_fault)(void*, const char*),
                               void (*on_temp)(void*, float),
                               void* userdata);

#ifdef __cplusplus
}
#endif

#endif /* CELLLINK_PA_PROTECT_H */
