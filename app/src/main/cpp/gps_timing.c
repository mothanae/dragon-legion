#include "gps_timing.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <android/log.h>

#define LOG_TAG "CellLink-GPS"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

/* ── Monotonic Clock Helper ──────────────────────────────────────────── */

static uint64_t monotonic_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;
}

/* ── NMEA Parser ─────────────────────────────────────────────────────── */

static int nmea_checksum_ok(const char* nmea) {
    if (!nmea || nmea[0] != '$') return 0;
    uint8_t cs = 0;
    const char* p = nmea + 1;
    while (*p && *p != '*') {
        cs ^= (uint8_t)*p++;
    }
    if (*p == '*') {
        unsigned int expected;
        if (sscanf(p + 1, "%02X", &expected) == 1) {
            return cs == (uint8_t)expected;
        }
    }
    return 0; /* No checksum present, accept anyway for simplicity */
}

static bool parse_rmc(const char* nmea, double* lat, double* lon, uint64_t* tow_ms) {
    /* $GPRMC,hhmmss.ss,A,llll.ll,N,yyyyy.yy,E,speed,course,DDMMYY,mv,mvE,A*cs */
    char time_str[16] = {0}, status, lat_str[16] = {0}, ns, lon_str[16] = {0}, ew;
    char date_str[16] = {0};

    if (sscanf(nmea, "$GPRMC,%[^,],%c,%[^,],%c,%[^,],%c,,,,,%[^,]",
               time_str, &status, lat_str, &ns, lon_str, &ew, date_str) < 4) {
        return false;
    }

    if (status != 'A') return false; /* Not valid */

    /* Parse time */
    int hh = 0, mm = 0, ss = 0;
    if (sscanf(time_str, "%02d%02d%02d", &hh, &mm, &ss) == 3) {
        *tow_ms = ((hh * 3600 + mm * 60 + ss) * 1000ULL) % GPS_SECONDS_PER_WEEK;
    }

    /* Parse lat/lon */
    double lat_deg = 0, lon_deg = 0;
    if (sscanf(lat_str, "%lf", &lat_deg) == 1) {
        int deg = (int)(lat_deg / 100.0);
        *lat = deg + (lat_deg - deg * 100.0) / 60.0;
        if (ns == 'S') *lat = -*lat;
    }
    if (sscanf(lon_str, "%lf", &lon_deg) == 1) {
        int deg = (int)(lon_deg / 100.0);
        *lon = deg + (lon_deg - deg * 100.0) / 60.0;
        if (ew == 'W') *lon = -*lon;
    }

    return true;
}

static bool parse_gga(const char* nmea, uint8_t* sats_used) {
    char time_str[16] = {0}, qual_str[4] = {0}, sats_str[4] = {0};
    if (sscanf(nmea, "$GPGGA,%[^,],%*[^,],%*[^,],%*[^,],%*[^,],%*[^,],%[^,],%[^,],",
               time_str, qual_str, sats_str) >= 2) {
        int qual;
        if (sscanf(qual_str, "%d", &qual) == 1 && qual > 0) {
            if (sats_used && sscanf(sats_str, "%hhu", sats_used) != 1) {
                *sats_used = 0;
            }
            return true;
        }
    }
    return false;
}

static bool parse_zda(const char* nmea, uint64_t* tow_ms) {
    /* $GPZDA,hhmmss.ss,DD,MM,YYYY,,*cs */
    char time_str[16] = {0};
    int hh, mm;
    float ss;
    if (sscanf(nmea, "$GPZDA,%[^,]", time_str) == 1) {
        if (sscanf(time_str, "%02d%02d%f", &hh, &mm, &ss) == 3) {
            *tow_ms = (uint64_t)((hh * 3600 + mm * 60 + ss) * 1000.0);
            return true;
        }
    }
    return false;
}

/* ── PLL (Phase-Locked Loop) for Oscillator Discipline ───────────────── */

static void update_pll(gps_timing_t* gt, int64_t measured_error_ns) {
    /* Second-order PLL to discipline the local oscillator */
    double tc = gt->disciplining_tc;
    if (tc <= 0.0) tc = 100.0; /* Default 100s time constant */

    /* Low-pass filter the phase error */
    gt->phase_error_ns += (measured_error_ns - gt->phase_error_ns) * 0.1;

    /* Estimate frequency error (first derivative of phase) */
    gt->freq_error_ppb = gt->phase_error_ns / (tc * 1e9) * 1e9;

    /* Clamp to reasonable range */
    if (gt->freq_error_ppb > 10000.0) gt->freq_error_ppb = 10000.0;
    if (gt->freq_error_ppb < -10000.0) gt->freq_error_ppb = -10000.0;
}

/* ── Public API ───────────────────────────────────────────────────────── */

gps_timing_t* gps_timing_init(void) {
    gps_timing_t* gt = (gps_timing_t*)calloc(1, sizeof(gps_timing_t));
    if (!gt) return NULL;

    gt->state = GPS_TIMING_FREE_RUNNING;
    gt->disciplining_tc = 100.0;
    gt->last_update_us = monotonic_us();
    gt->frame_start_ns = monotonic_us() * 1000ULL;

    if (pthread_mutex_init(&gt->lock, NULL) != 0) {
        free(gt);
        return NULL;
    }

    LOGI("GPS timing initialized: FREE_RUNNING mode");
    return gt;
}

void gps_timing_free(gps_timing_t* gt) {
    if (!gt) return;
    pthread_mutex_destroy(&gt->lock);
    free(gt);
}

void gps_timing_feed_nmea(gps_timing_t* gt, const char* nmea) {
    if (!gt || !nmea) return;

    pthread_mutex_lock(&gt->lock);

    uint64_t tow_ms = 0;
    double lat = 0, lon = 0;
    uint8_t sats = 0;
    bool valid = false;

    if (strstr(nmea, "$GPRMC")) {
        strncpy(gt->nmea_rmc, nmea, sizeof(gt->nmea_rmc) - 1);
        valid = parse_rmc(nmea, &lat, &lon, &tow_ms);
        if (valid) {
            gt->latitude = lat;
            gt->longitude = lon;
        }
    } else if (strstr(nmea, "$GPGGA")) {
        strncpy(gt->nmea_gga, nmea, sizeof(gt->nmea_gga) - 1);
        valid = parse_gga(nmea, &sats);
        if (valid) gt->satellites_used = sats;
    } else if (strstr(nmea, "$GPZDA")) {
        valid = parse_zda(nmea, &tow_ms);
    }

    if (valid && tow_ms > 0 && gt->state < GPS_TIMING_3D_FIX) {
        gt->state = GPS_TIMING_3D_FIX;
        gt->gps_tow_ms = tow_ms;
        gt->last_update_us = monotonic_us();
        LOGI("GPS 3D FIX acquired: TOW=%llu ms, %.6f %.6f",
             (unsigned long long)tow_ms, gt->latitude, gt->longitude);
    }

    pthread_mutex_unlock(&gt->lock);
}

void gps_timing_pps_pulse(gps_timing_t* gt) {
    if (!gt) return;

    pthread_mutex_lock(&gt->lock);

    uint64_t now = monotonic_us();
    gt->pps_count++;

    if (gt->state >= GPS_TIMING_3D_FIX) {
        /* Calculate expected PPS time from GPS TOW */
        uint64_t elapsed_ms = (now - gt->last_update_us) / 1000;
        uint64_t current_tow_ms = (gt->gps_tow_ms + elapsed_ms) % GPS_SECONDS_PER_WEEK;
        uint64_t next_second_ms = ((current_tow_ms / 1000) + 1) * 1000;

        /* Measure timing error */
        int64_t expected_us = gt->last_update_us + (next_second_ms - gt->gps_tow_ms) * 1000;
        gt->pps_offset_ns = (int64_t)((now - expected_us) * 1000);

        update_pll(gt, gt->pps_offset_ns);

        gt->state = GPS_TIMING_DISCIPLINED;
    }

    pthread_mutex_unlock(&gt->lock);
}

uint64_t gps_timing_get_frame_number(gps_timing_t* gt) {
    if (!gt) return 0;

    pthread_mutex_lock(&gt->lock);

    uint64_t frameno;
    if (gt->state >= GPS_TIMING_3D_FIX) {
        uint64_t now_us = monotonic_us();
        uint64_t elapsed_ms = (now_us - gt->last_update_us) / 1000;
        uint64_t current_tow_ms = (gt->gps_tow_ms + elapsed_ms) % GPS_SECONDS_PER_WEEK;
        uint64_t total_frames = (current_tow_ms * 1000000ULL) / GPS_TIMING_NS_PER_FRAME;

        /* Apply frequency correction */
        int64_t corr_frames = (int64_t)(elapsed_ms * gt->freq_error_ppb / 1000.0);
        frameno = total_frames + corr_frames;
    } else {
        /* Free-running: count from startup */
        uint64_t now_ns = monotonic_us() * 1000ULL;
        frameno = (now_ns - gt->frame_start_ns) / GPS_TIMING_NS_PER_FRAME;
    }

    pthread_mutex_unlock(&gt->lock);
    return frameno;
}

int64_t gps_timing_wait_frame_boundary(gps_timing_t* gt) {
    if (!gt) return -1;

    uint64_t start_us = monotonic_us();
    uint64_t current_frame = gps_timing_get_frame_number(gt);
    uint64_t next_frame_start;

    pthread_mutex_lock(&gt->lock);
    if (gt->state >= GPS_TIMING_3D_FIX) {
        /* Calculate next frame start in monotonic time */
        uint64_t now_us = monotonic_us();
        uint64_t elapsed_ms = (now_us - gt->last_update_us) / 1000;
        uint64_t current_tow_ms = (gt->gps_tow_ms + elapsed_ms) % GPS_SECONDS_PER_WEEK;
        uint64_t frames_since_tow = (current_tow_ms * 1000000ULL) / GPS_TIMING_NS_PER_FRAME;

        uint64_t next_frame_tow_ns = (frames_since_tow + 1) * GPS_TIMING_NS_PER_FRAME;
        uint64_t next_frame_tow_ms = next_frame_tow_ns / 1000000ULL;

        int64_t wait_ms = (int64_t)(next_frame_tow_ms - current_tow_ms);
        if (wait_ms < 0) wait_ms += GPS_SECONDS_PER_WEEK * 1000;
        if (wait_ms > 100) wait_ms = 5; /* Safety clamp */

        pthread_mutex_unlock(&gt->lock);
        if (wait_ms > 0) usleep((useconds_t)(wait_ms * 1000));
    } else {
        /* Free-running: use 4.615ms period */
        pthread_mutex_unlock(&gt->lock);
        uint64_t now_ns = monotonic_us() * 1000ULL;
        uint64_t frame_pos = (now_ns - gt->frame_start_ns) % GPS_TIMING_NS_PER_FRAME;
        uint64_t wait_ns = GPS_TIMING_NS_PER_FRAME - frame_pos;
        usleep((useconds_t)(wait_ns / 1000));
    }

    return (int64_t)(monotonic_us() - start_us);
}

gps_timing_state_t gps_timing_get_state(gps_timing_t* gt) {
    if (!gt) return GPS_TIMING_FREE_RUNNING;
    return gt->state;
}

double gps_timing_get_freq_error(gps_timing_t* gt) {
    if (!gt) return 0.0;
    return gt->freq_error_ppb;
}

const char* gps_timing_status_string(gps_timing_t* gt) {
    if (!gt) return "OFF";
    switch (gt->state) {
        case GPS_TIMING_FREE_RUNNING:  return "FREE_RUNNING";
        case GPS_TIMING_3D_FIX:        return "3D_FIX";
        case GPS_TIMING_DISCIPLINED:   return "DISCIPLINED";
        case GPS_TIMING_HOLDOVER:      return "HOLDOVER";
        default:                       return "UNKNOWN";
    }
}
