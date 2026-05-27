#include "call_recorder.h"
#include "diag.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <android/log.h>

#define LOG_TAG "CellLink-RECORD"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

/* WAV format constants */
#define WAV_RIFF_CHUNK_ID   0x46464952  /* "RIFF" */
#define WAV_FORMAT           0x45564157  /* "WAVE" */
#define WAV_FMT_CHUNK_ID    0x20746D66  /* "fmt " */
#define WAV_DATA_CHUNK_ID   0x61746164  /* "data" */
#define WAV_FMT_PCM          1

static uint64_t get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

int wav_write_header(FILE* f, int32_t sample_rate, int16_t bits_per_sample,
                     int16_t channels, int32_t data_size) {
    int16_t block_align = channels * (bits_per_sample / 8);
    int32_t byte_rate = sample_rate * block_align;
    int32_t chunk_size = 36 + data_size;

    uint8_t header[44];
    memset(header, 0, sizeof(header));

    /* RIFF header */
    memcpy(header + 0, "RIFF", 4);
    header[4] = (uint8_t)(chunk_size & 0xFF);
    header[5] = (uint8_t)((chunk_size >> 8) & 0xFF);
    header[6] = (uint8_t)((chunk_size >> 16) & 0xFF);
    header[7] = (uint8_t)((chunk_size >> 24) & 0xFF);
    memcpy(header + 8, "WAVE", 4);

    /* fmt chunk */
    memcpy(header + 12, "fmt ", 4);
    header[16] = 16; header[17] = 0; header[18] = 0; header[19] = 0; /* Subchunk1Size */
    header[20] = 1;  header[21] = 0; /* AudioFormat = PCM */
    header[22] = (uint8_t)(channels & 0xFF);
    header[23] = (uint8_t)((channels >> 8) & 0xFF);
    header[24] = (uint8_t)(sample_rate & 0xFF);
    header[25] = (uint8_t)((sample_rate >> 8) & 0xFF);
    header[26] = (uint8_t)((sample_rate >> 16) & 0xFF);
    header[27] = (uint8_t)((sample_rate >> 24) & 0xFF);
    header[28] = (uint8_t)(byte_rate & 0xFF);
    header[29] = (uint8_t)((byte_rate >> 8) & 0xFF);
    header[30] = (uint8_t)((byte_rate >> 16) & 0xFF);
    header[31] = (uint8_t)((byte_rate >> 24) & 0xFF);
    header[32] = (uint8_t)(block_align & 0xFF);
    header[33] = (uint8_t)((block_align >> 8) & 0xFF);
    header[34] = (uint8_t)(bits_per_sample & 0xFF);
    header[35] = (uint8_t)((bits_per_sample >> 8) & 0xFF);

    /* data chunk */
    memcpy(header + 36, "data", 4);
    header[40] = (uint8_t)(data_size & 0xFF);
    header[41] = (uint8_t)((data_size >> 8) & 0xFF);
    header[42] = (uint8_t)((data_size >> 16) & 0xFF);
    header[43] = (uint8_t)((data_size >> 24) & 0xFF);

    return (int)fwrite(header, 1, 44, f) == 44 ? 0 : -1;
}

int wav_update_header(call_recorder_t* rec) {
    if (!rec || !rec->file) return -1;

    /* Update RIFF and data chunk sizes */
    fseek(rec->file, 4, SEEK_SET);
    int32_t chunk_size = 36 + (int32_t)rec->bytes_written;
    fwrite(&chunk_size, 4, 1, rec->file);

    fseek(rec->file, 40, SEEK_SET);
    int32_t data_size = (int32_t)rec->bytes_written;
    fwrite(&data_size, 4, 1, rec->file);

    fseek(rec->file, 0, SEEK_END);
    return 0;
}

/* ── Public API ───────────────────────────────────────────────────────── */

call_recorder_t* call_recorder_create(const char* filename) {
    call_recorder_t* rec = (call_recorder_t*)calloc(1, sizeof(call_recorder_t));
    if (!rec) return NULL;

    if (filename) {
        strncpy(rec->filename, filename, sizeof(rec->filename) - 1);
    } else {
        time_t now = time(NULL);
        snprintf(rec->filename, sizeof(rec->filename),
                "/sdcard/CellLink/call_%lld.wav", (long long)now);
    }
    return rec;
}

void call_recorder_free(call_recorder_t* rec) {
    if (!rec) return;
    if (rec->is_recording) call_recorder_stop(rec);
    free(rec);
}

int call_recorder_start(call_recorder_t* rec) {
    if (!rec) return -1;

    rec->file = fopen(rec->filename, "wb");
    if (!rec->file) {
        LOGE("Cannot create recording file: %s", rec->filename);
        return -1;
    }

    /* Write placeholder WAV header */
    wav_write_header(rec->file, CALL_RECORDER_SAMPLE_RATE,
                     CALL_RECORDER_BITS_PER_SAMPLE, CALL_RECORDER_CHANNELS, 0);

    rec->is_recording = true;
    rec->is_paused = false;
    rec->bytes_written = 0;
    rec->start_time_ms = get_time_ms();
    rec->peak_level = 0;
    rec->avg_level = 0;
    rec->total_samples = 0;

    LOGI("Recording started: %s", rec->filename);
    return 0;
}

int call_recorder_stop(call_recorder_t* rec) {
    if (!rec || !rec->is_recording) return -1;

    rec->is_recording = false;

    if (rec->file) {
        wav_update_header(rec);
        fclose(rec->file);
        rec->file = NULL;
    }

    double duration = (get_time_ms() - rec->start_time_ms) / 1000.0;
    LOGI("Recording stopped: %.1f sec, peak=%d, size=%lld bytes",
         duration, rec->peak_level, (long long)rec->bytes_written);
    return 0;
}

void call_recorder_pause(call_recorder_t* rec, bool pause) {
    if (!rec) return;
    rec->is_paused = pause;
    LOGD("Recording %s", pause ? "paused" : "resumed");
}

int call_recorder_write(call_recorder_t* rec, const int16_t* samples, int count) {
    if (!rec || !rec->is_recording || rec->is_paused || !rec->file) return 0;

    /* Write to file */
    size_t written = fwrite(samples, sizeof(int16_t), count, rec->file);

    /* Update ring buffer */
    for (int i = 0; i < count && i < (int)(sizeof(rec->ring_buffer) / sizeof(int16_t)); i++) {
        rec->ring_buffer[rec->ring_write_pos] = samples[i];
        rec->ring_write_pos = (rec->ring_write_pos + 1) % (sizeof(rec->ring_buffer) / sizeof(int16_t));
    }

    /* Update levels */
    for (int i = 0; i < count; i++) {
        int32_t abs_sample = (samples[i] < 0) ? -samples[i] : samples[i];
        if (abs_sample > rec->peak_level) rec->peak_level = abs_sample;
        rec->avg_level = rec->avg_level * 0.999 + abs_sample * 0.001;
    }

    rec->bytes_written += (int64_t)written * sizeof(int16_t);
    rec->total_samples += count;
    return (int)written;
}

int call_recorder_capture_from_modem(call_recorder_t* rec, diag_handle_t* h) {
    /* Capture audio PCM from modem DIAG logging
     * Qualcomm modems can output voice path PCM via DIAG log codes
     * Log code 0x1571 = Voice downlink PCM
     * Log code 0x1572 = Voice uplink PCM
     */
    if (!rec || !h || !rec->is_recording || rec->is_paused) return 0;

    /* Read audio DIAG log packets */
    uint8_t buf[DIAG_MAX_PAYLOAD];
    uint8_t cmd;
    int n = diag_recv(h, &cmd, buf, sizeof(buf), 100);
    if (n < 16) return 0; /* Voice PCM packets are at least 16 bytes */

    /* Check for voice PCM log codes (DIAG log subsystem 0x15) */
    if (cmd == DIAG_CMD_EVENT_REPORT_F) {
        /* Parse DIAG event for voice PCM */
        /* Header: [log_code:2] [timestamp:8] [data:N] */
        uint16_t log_code = (uint16_t)buf[0] | ((uint16_t)buf[1] << 8);
        if (log_code == 0x1571 || log_code == 0x1572) {
            /* PCM data starts at offset 10 */
            int pcm_samples = (n - 10) / 2;
            int16_t* samples = (int16_t*)(buf + 10);
            return call_recorder_write(rec, samples, pcm_samples);
        }
    }

    return 0;
}

double call_recorder_get_duration(call_recorder_t* rec) {
    if (!rec) return 0.0;
    return rec->total_samples / (double)CALL_RECORDER_SAMPLE_RATE;
}

int32_t call_recorder_get_peak(call_recorder_t* rec) {
    if (!rec) return 0;
    int32_t peak = rec->peak_level;
    rec->peak_level = 0; /* Reset peak after reading (VU meter semantics) */
    return peak;
}
