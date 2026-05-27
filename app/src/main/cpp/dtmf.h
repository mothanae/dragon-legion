#ifndef CELLLINK_DTMF_H
#define CELLLINK_DTMF_H

#include "diag.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* DTMF tone frequencies (Hz) — row + column */
#define DTMF_ROW_697    697
#define DTMF_ROW_770    770
#define DTMF_ROW_852    852
#define DTMF_ROW_941    941
#define DTMF_COL_1209   1209
#define DTMF_COL_1336   1336
#define DTMF_COL_1477   1477
#define DTMF_COL_1633   1633

/* DTMF timing (ms) */
#define DTMF_TONE_DURATION_MS   70    /* Standard tone duration */
#define DTMF_SILENCE_MS         50    /* Inter-digit silence */
#define DTMF_DETECT_THRESHOLD   0.85f /* Goertzel correlation threshold */

/* DTMF digit mapping: [row][col] */
extern const char DTMF_DIGITS[4][4];

/* ── API ─────────────────────────────────────────────────────────────── */

/**
 * Generate DTMF tone samples for a given digit.
 * @param digit    '0'-'9', '*', '#', 'A'-'D'
 * @param samples  Output buffer for 16-bit PCM samples
 * @param max_samples Max samples to generate
 * @param sample_rate Sample rate in Hz (typically 8000)
 * @return Number of samples generated
 */
int dtmf_generate(char digit, int16_t* samples, int max_samples, int sample_rate);

/**
 * Send a DTMF digit via the modem (AT+VTS).
 */
int dtmf_send_at(diag_handle_t* h, char digit, int duration_ms);

/**
 * Send a DTMF string via the modem.
 */
int dtmf_send_string_at(diag_handle_t* h, const char* digits, int duration_ms);

/**
 * Detect DTMF tones in an audio buffer using Goertzel algorithm.
 * Returns the detected digit, or 0 if none detected.
 */
char dtmf_detect(const int16_t* samples, int count, int sample_rate);

/**
 * Continuously monitor audio for DTMF digits (ring buffer).
 * Call periodically with new audio samples.
 * Returns any newly detected digits in the output buffer.
 */
int dtmf_monitor(const int16_t* samples, int count, int sample_rate,
                char* detected_digits, int max_digits);

/**
 * Generate a DTMF tone as a raw audio file (WAV).
 * Useful for testing the audio path.
 */
int dtmf_generate_wav(const char* digits, const char* filename, int sample_rate);

#ifdef __cplusplus
}
#endif

#endif /* CELLLINK_DTMF_H */
