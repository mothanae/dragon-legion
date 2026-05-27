#ifndef CELLLINK_GPS_TIMING_H
#define CELLLINK_GPS_TIMING_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── GPS Timing Constants ────────────────────────────────────────────── */

/* GPS PPS (Pulse Per Second) has 50ns RMS accuracy.
 * GSM TDMA requires frame timing within 2-3µs for camping.
 * GPS-disciplined oscillators can achieve <100ns stability. */

#define GPS_TIMING_NS_PER_FRAME   4615000  /* 4.615ms = TDMA frame */
#define GPS_TIMING_NS_PER_TN      576900   /* 576.9µs = timeslot */
#define GPS_TIMING_FRAMES_PER_51  51
#define GPS_TIMING_FRAMES_PER_26  26

/* GPS week seconds */
#define GPS_SECONDS_PER_WEEK      604800
#define GPS_EPOCH_DELTA           315964800  /* GPS epoch (Jan 6 1980) - Unix epoch delta */

/* ── GPS Timing State ────────────────────────────────────────────────── */

typedef enum {
    GPS_TIMING_FREE_RUNNING,    /* No GPS lock, internal oscillator */
    GPS_TIMING_3D_FIX,          /* Position fix acquired, time valid */
    GPS_TIMING_DISCIPLINED,     /* PPS lock active, high precision */
    GPS_TIMING_HOLDOVER         /* GPS lost, holding last good value */
} gps_timing_state_t;

typedef struct {
    gps_timing_state_t state;
    pthread_mutex_t     lock;

    /* Last known GPS time */
    uint64_t gps_tow_ms;        /* GPS Time of Week in ms */
    uint64_t gps_week;          /* GPS week number */
    uint64_t last_update_us;    /* monotonic time of last GPS update */

    /* PPS timing */
    bool     pps_available;
    uint64_t pps_count;         /* Number of PPS pulses received */
    int64_t  pps_offset_ns;     /* Measured offset from ideal */

    /* Oscillator discipline */
    double   freq_error_ppb;    /* Parts per billion frequency error */
    int64_t  phase_error_ns;    /* Phase error in nanoseconds */
    double   disciplining_tc;   /* Time constant for PLL */

    /* Latest NMEA data */
    char     nmea_rmc[128];     /* Last $GPRMC sentence */
    char     nmea_gga[128];     /* Last $GPGGA sentence */
    double   latitude;
    double   longitude;
    double   altitude_m;
    uint8_t  satellites_used;

    /* Synthesized frame clock */
    uint64_t frame_number;      /* Current TDMA frame number */
    uint64_t frame_start_ns;    /* Monotonic time of current frame start */
} gps_timing_t;

/* ── API ──────────────────────────────────────────────────────────────── */

/** Initialize GPS timing system. Returns NULL on failure. */
gps_timing_t* gps_timing_init(void);

/** Free GPS timing resources. */
void gps_timing_free(gps_timing_t* gt);

/**
 * Feed an NMEA sentence for parsing.
 * Handles $GPRMC, $GPGGA, $GPZDA sentences.
 */
void gps_timing_feed_nmea(gps_timing_t* gt, const char* nmea);

/**
 * Signal a PPS (Pulse Per Second) event.
 * Called from a high-priority thread or interrupt handler.
 */
void gps_timing_pps_pulse(gps_timing_t* gt);

/**
 * Get the current TDMA frame number based on GPS time.
 * Falls back to free-running if GPS is not available.
 */
uint64_t gps_timing_get_frame_number(gps_timing_t* gt);

/**
 * Sleep until the start of the next TDMA frame boundary.
 * Returns actual delay in microseconds for diagnostics.
 */
int64_t gps_timing_wait_frame_boundary(gps_timing_t* gt);

/**
 * Get current timing state.
 */
gps_timing_state_t gps_timing_get_state(gps_timing_t* gt);

/**
 * Get estimated frequency error in parts-per-billion.
 */
double gps_timing_get_freq_error(gps_timing_t* gt);

/**
 * Get human-readable status string.
 */
const char* gps_timing_status_string(gps_timing_t* gt);

#ifdef __cplusplus
}
#endif

#endif /* CELLLINK_GPS_TIMING_H */
