#ifndef CELLLINK_CALL_RECORDER_H
#define CELLLINK_CALL_RECORDER_H

#include "diag.h"
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* GSM voice codec: 8kHz sample rate, 13-bit linear PCM (FR codec output) */
#define CALL_RECORDER_SAMPLE_RATE    8000
#define CALL_RECORDER_BITS_PER_SAMPLE 16
#define CALL_RECORDER_CHANNELS        1
#define CALL_RECORDER_MAX_SECONDS     3600  /* 1 hour max recording */
#define CALL_RECORDER_BUFFER_SIZE     (CALL_RECORDER_SAMPLE_RATE * \
                                       CALL_RECORDER_BITS_PER_SAMPLE / 8 * \
                                       CALL_RECORDER_MAX_SECONDS)

typedef struct {
    FILE*   file;
    char    filename[256];
    bool    is_recording;
    bool    is_paused;
    int64_t bytes_written;
    int64_t start_time_ms;

    /* Direct PCM capture buffer (ring buffer) */
    int16_t ring_buffer[CALL_RECORDER_SAMPLE_RATE * 10]; /* 10 seconds ring */
    uint32_t ring_write_pos;
    uint32_t ring_read_pos;

    /* Statistics */
    int32_t peak_level;      /* Peak audio level */
    double  avg_level;       /* Running average */
    int64_t total_samples;
} call_recorder_t;

/* ── API ─────────────────────────────────────────────────────────────── */

/** Create a new call recorder. */
call_recorder_t* call_recorder_create(const char* filename);

/** Free recorder resources. */
void call_recorder_free(call_recorder_t* rec);

/** Start recording. Opens file and writes WAV header. */
int call_recorder_start(call_recorder_t* rec);

/** Stop recording. Finishes WAV header and closes file. */
int call_recorder_stop(call_recorder_t* rec);

/** Pause/resume recording without closing the file. */
void call_recorder_pause(call_recorder_t* rec, bool pause);

/**
 * Write a buffer of PCM audio samples to the recording.
 * Samples should be 16-bit PCM at 8kHz, mono.
 */
int call_recorder_write(call_recorder_t* rec, const int16_t* samples, int count);

/**
 * Capture audio from the modem's voice path directly.
 * Uses Qualcomm audio DIAG logging to capture PCM samples.
 * Returns number of samples captured.
 */
int call_recorder_capture_from_modem(call_recorder_t* rec, diag_handle_t* h);

/**
 * Get recording duration in seconds.
 */
double call_recorder_get_duration(call_recorder_t* rec);

/**
 * Get peak audio level (for VU meter display).
 */
int32_t call_recorder_get_peak(call_recorder_t* rec);

/**
 * Write a WAV file header.
 */
int wav_write_header(FILE* f, int32_t sample_rate, int16_t bits_per_sample,
                     int16_t channels, int32_t data_size);

/**
 * Update WAV header with final data size.
 */
int wav_update_header(call_recorder_t* rec);

#ifdef __cplusplus
}
#endif

#endif /* CELLLINK_CALL_RECORDER_H */
