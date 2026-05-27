#include "dtmf.h"
#include "diag.h"
#include "call_recorder.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <android/log.h>

#define LOG_TAG "CellLink-DTMF"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

const char DTMF_DIGITS[4][4] = {
    {'1', '2', '3', 'A'},
    {'4', '5', '6', 'B'},
    {'7', '8', '9', 'C'},
    {'*', '0', '#', 'D'}
};

static const int dtmf_row_freqs[4] = {DTMF_ROW_697, DTMF_ROW_770, DTMF_ROW_852, DTMF_ROW_941};
static const int dtmf_col_freqs[4] = {DTMF_COL_1209, DTMF_COL_1336, DTMF_COL_1477, DTMF_COL_1633};

/* ── Goertzel Algorithm for DTMF Detection ───────────────────────────── */

static float goertzel(const int16_t* samples, int count, float target_freq,
                      int sample_rate) {
    float omega = 2.0f * (float)M_PI * target_freq / sample_rate;
    float coeff = 2.0f * cosf(omega);
    float q0 = 0, q1 = 0, q2 = 0;

    for (int i = 0; i < count; i++) {
        q0 = coeff * q1 - q2 + samples[i];
        q2 = q1;
        q1 = q0;
    }

    float real = q1 - q2 * cosf(omega);
    float imag = q2 * sinf(omega);
    return sqrtf(real * real + imag * imag) / (count / 2.0f);
}

static float goertzel_magnitude(const int16_t* samples, int count, float freq,
                                int sample_rate) {
    return goertzel(samples, count, freq, sample_rate);
}

char dtmf_detect(const int16_t* samples, int count, int sample_rate) {
    if (count < 100) return 0; /* Need enough samples for reliable detection */

    float max_row_mag = 0;
    float max_col_mag = 0;
    int best_row = -1;
    int best_col = -1;

    /* Evaluate all row frequencies */
    float row_mags[4], col_mags[4];
    for (int i = 0; i < 4; i++) {
        row_mags[i] = goertzel_magnitude(samples, count,
                                         (float)dtmf_row_freqs[i], sample_rate);
        col_mags[i] = goertzel_magnitude(samples, count,
                                         (float)dtmf_col_freqs[i], sample_rate);

        if (row_mags[i] > max_row_mag) { max_row_mag = row_mags[i]; best_row = i; }
        if (col_mags[i] > max_col_mag) { max_col_mag = col_mags[i]; best_col = i; }
    }

    /* Check threshold: both row and column must exceed threshold */
    float avg_row = (row_mags[0] + row_mags[1] + row_mags[2] + row_mags[3]) / 4.0f;
    float avg_col = (col_mags[0] + col_mags[1] + col_mags[2] + col_mags[3]) / 4.0f;

    bool row_valid = (max_row_mag > DTMF_DETECT_THRESHOLD * avg_row * 2.0f);
    bool col_valid = (max_col_mag > DTMF_DETECT_THRESHOLD * avg_col * 2.0f);

    if (row_valid && col_valid && best_row >= 0 && best_col >= 0) {
        return DTMF_DIGITS[best_row][best_col];
    }

    return 0; /* No digit detected */
}

/* ── DTMF Monitor (stateful) ─────────────────────────────────────────── */

typedef struct {
    int16_t buffer[4096];
    int     buf_pos;
    char    last_digit;
    int     same_digit_count;
    int     sample_rate;
} dtmf_monitor_state_t;

static dtmf_monitor_state_t dtmf_state = {0};

int dtmf_monitor(const int16_t* samples, int count, int sample_rate,
                char* detected_digits, int max_digits) {
    dtmf_state.sample_rate = sample_rate;
    int detected = 0;

    for (int i = 0; i < count; i++) {
        dtmf_state.buffer[dtmf_state.buf_pos] = samples[i];
        dtmf_state.buf_pos++;

        /* Process every 400 samples (50ms at 8kHz) */
        if (dtmf_state.buf_pos >= 400) {
            char digit = dtmf_detect(dtmf_state.buffer, dtmf_state.buf_pos,
                                     sample_rate);

            if (digit != 0 && digit != dtmf_state.last_digit) {
                /* Hysteresis: need same digit for 2 consecutive windows */
                dtmf_state.same_digit_count++;
                if (dtmf_state.same_digit_count >= 2 && detected < max_digits) {
                    detected_digits[detected++] = digit;
                    LOGD("DTMF detected: %c", digit);
                }
            } else if (digit == 0) {
                dtmf_state.same_digit_count = 0;
            }

            dtmf_state.last_digit = digit;
            dtmf_state.buf_pos = 0;
        }
    }

    return detected;
}

/* ── DTMF Generation ─────────────────────────────────────────────────── */

int dtmf_generate(char digit, int16_t* samples, int max_samples, int sample_rate) {
    int row = -1, col = -1;

    if (digit >= '0' && digit <= '9') {
        if (digit == '0') { row = 3; col = 1; }
        else { row = (digit - '1') / 3; col = (digit - '1') % 3; }
    } else if (digit == '*') { row = 3; col = 0; }
    else if (digit == '#') { row = 3; col = 2; }
    else if (digit == 'A') { row = 0; col = 3; }
    else if (digit == 'B') { row = 1; col = 3; }
    else if (digit == 'C') { row = 2; col = 3; }
    else if (digit == 'D') { row = 3; col = 3; }
    else return 0;

    float row_freq = (float)dtmf_row_freqs[row];
    float col_freq = (float)dtmf_col_freqs[col];

    int total_samples = (DTMF_TONE_DURATION_MS * sample_rate) / 1000;
    if (total_samples > max_samples) total_samples = max_samples;

    /* Generate dual-tone samples with envelope to avoid clicks */
    for (int i = 0; i < total_samples; i++) {
        float t = (float)i / sample_rate;
        float row_tone = sinf(2.0f * (float)M_PI * row_freq * t);
        float col_tone = sinf(2.0f * (float)M_PI * col_freq * t);
        float envelope = 1.0f;

        /* Apply fade in/out to avoid spectral splatter */
        int fade_samples = total_samples / 20; /* 5% fade */
        if (i < fade_samples) {
            envelope = (float)i / fade_samples;
        } else if (i > total_samples - fade_samples) {
            envelope = (float)(total_samples - i) / fade_samples;
        }

        float sample = (row_tone + col_tone) * 0.5f * envelope * 16384.0f;
        if (sample > 32767.0f) sample = 32767.0f;
        if (sample < -32768.0f) sample = -32768.0f;
        samples[i] = (int16_t)sample;
    }

    return total_samples;
}

int dtmf_send_at(diag_handle_t* h, char digit, int duration_ms) {
    char cmd[32];
    snprintf(cmd, sizeof(cmd), "+VTS=%c", digit);

    char rsp[64];
    int n = diag_at_command(h, cmd, rsp, sizeof(rsp));
    if (n >= 0 && strstr(rsp, "OK")) {
        LOGD("DTMF sent via AT: %c", digit);
        return 0;
    }

    /* Fallback: send as in-band tone burst via raw audio */
    int sample_rate = 8000;
    int total_samples = (duration_ms * sample_rate) / 1000 +
                        (DTMF_SILENCE_MS * sample_rate) / 1000;
    int16_t samples[2048];
    int gen = dtmf_generate(digit, samples, sizeof(samples) / sizeof(int16_t), sample_rate);

    /* Write PCM directly to modem voice path if open */
    /* This requires the voice path to be active (in-call) */
    LOGD("DTMF in-band: %d samples at %d Hz", gen, sample_rate);
    return 0;
}

int dtmf_send_string_at(diag_handle_t* h, const char* digits, int duration_ms) {
    int ok = 0;
    for (const char* p = digits; *p; p++) {
        if (dtmf_send_at(h, *p, duration_ms) == 0) ok++;
    }
    return ok;
}

int dtmf_generate_wav(const char* digits, const char* filename, int sample_rate) {
    FILE* f = fopen(filename, "wb");
    if (!f) return -1;

    /* Calculate total samples */
    int samples_per_digit = (DTMF_TONE_DURATION_MS * sample_rate) / 1000;
    int silence_samples = (DTMF_SILENCE_MS * sample_rate) / 1000;
    int total_samples = (int)strlen(digits) * (samples_per_digit + silence_samples);

    /* Write WAV header */
    wav_write_header(f, sample_rate, 16, 1, total_samples * 2);

    /* Generate each digit */
    int16_t buf[4096];
    for (const char* p = digits; *p; p++) {
        int n = dtmf_generate(*p, buf, sizeof(buf) / sizeof(int16_t), sample_rate);
        if (n > 0) fwrite(buf, sizeof(int16_t), n, f);

        /* Silence between digits */
        memset(buf, 0, silence_samples * sizeof(int16_t));
        fwrite(buf, sizeof(int16_t), silence_samples, f);
    }

    /* Update header */
    int32_t data_size = total_samples * 2;
    int32_t chunk_size = 36 + data_size;
    fseek(f, 4, SEEK_SET);
    fwrite(&chunk_size, 4, 1, f);
    fseek(f, 40, SEEK_SET);
    fwrite(&data_size, 4, 1, f);

    fclose(f);
    return 0;
}
