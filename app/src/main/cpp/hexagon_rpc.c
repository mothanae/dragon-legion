#include "hexagon_rpc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <android/log.h>

#define LOG_TAG "CellLink-DSP"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

/* Hexagon FastRPC ioctl commands */
#define FASTRPC_IOCTL_INVOKE  0xC0046901
#define FASTRPC_IOCTL_INIT    0xC0046902
#define FASTRPC_IOCTL_MMAP    0xC0046903
#define FASTRPC_IOCTL_MUNMAP  0xC0046904

struct hexagon_rpc_handle {
    int  fd;
    char device_path[256];
    bool is_open;
};

/* ── Public API ───────────────────────────────────────────────────────── */

hexagon_rpc_handle_t* hexagon_rpc_open(const char* device_path) {
    hexagon_rpc_handle_t* h = (hexagon_rpc_handle_t*)calloc(1, sizeof(hexagon_rpc_handle_t));
    if (!h) return NULL;

    const char* paths[] = { device_path, HEXAGON_RPC_DEVICE, HEXAGON_RPC_DEVICE_ALT, NULL };
    int fd = -1;

    for (int i = 0; paths[i] != NULL; i++) {
        if (!paths[i]) continue;
        fd = open(paths[i], O_RDWR);
        if (fd >= 0) {
            strncpy(h->device_path, paths[i], sizeof(h->device_path) - 1);
            break;
        }
    }

    if (fd < 0) {
        LOGE("Hexagon RPC device not found: %s", strerror(errno));
        free(h);
        return NULL;
    }

    h->fd = fd;
    h->is_open = true;

    /* Initialize FastRPC session */
    if (ioctl(fd, FASTRPC_IOCTL_INIT, NULL) < 0) {
        LOGD("FASTRPC init ioctl not supported, continuing: %s", strerror(errno));
        /* Not all kernel versions support the init ioctl — that's OK */
    }

    LOGI("Hexagon RPC opened: %s", h->device_path);
    return h;
}

void hexagon_rpc_close(hexagon_rpc_handle_t* h) {
    if (!h) return;
    if (h->fd >= 0) close(h->fd);
    LOGI("Hexagon RPC closed: %s", h->device_path);
    free(h);
}

int hexagon_rpc_call(hexagon_rpc_handle_t* h, uint32_t pid, uint32_t method,
                     const uint8_t* req, uint32_t req_len,
                     uint8_t* rsp, uint32_t rsp_len) {
    if (!h || h->fd < 0) return -1;

    /* Build RPC message */
    uint8_t msg[HEXAGON_RPC_MAX_MSG];
    memset(msg, 0, sizeof(msg));

    hexagon_rpc_header_t* hdr = (hexagon_rpc_header_t*)msg;
    hdr->pid = pid;
    hdr->method = method;
    hdr->flags = 0;
    hdr->in_len = req_len;
    hdr->out_len = rsp_len;

    if (req && req_len > 0) {
        memcpy(msg + sizeof(hexagon_rpc_header_t), req, req_len);
    }

    /* Invoke RPC */
    int ret = ioctl(h->fd, FASTRPC_IOCTL_INVOKE, msg);
    if (ret < 0) {
        LOGE("FASTRPC invoke failed: %s (pid=0x%X method=%d)",
             strerror(errno), pid, method);
        return -1;
    }

    /* Copy response */
    uint32_t out_len = hdr->out_len;
    if (out_len > rsp_len) out_len = rsp_len;
    if (out_len > 0) {
        memcpy(rsp, msg + sizeof(hexagon_rpc_header_t), out_len);
    }

    return (int)out_len;
}

/* ── Audio Path Control ──────────────────────────────────────────────── */

int hexagon_audio_enable_mic_path(hexagon_rpc_handle_t* h) {
    /* Method 0x1000: Route MIC1 -> voice encoder input */
    uint8_t req[16] = {0};

    /* Audio path config:
     * Byte 0: source (0x01 = MIC1, 0x02 = MIC2, 0x03 = DMIC)
     * Byte 1: destination (0x01 = VoLTE encoder, 0x02 = GSM encoder)
     * Byte 2: sample rate (0x00 = 8kHz GSM, 0x01 = 16kHz WB)
     * Byte 3: gain (0-255, 128 = 0dB)
     */
    req[0] = 0x01;  /* MIC1 */
    req[1] = 0x02;  /* GSM voice encoder */
    req[2] = 0x00;  /* 8 kHz narrowband */
    req[3] = 0x80;  /* 0 dB gain */

    uint8_t rsp[HEXAGON_RPC_MAX_MSG];
    int n = hexagon_rpc_call(h, HEXAGON_PID_MODEM_AUDIO, 0x1000, req, 4, rsp, sizeof(rsp));

    if (n >= 0) {
        LOGI("Mic-to-DSP audio path enabled (8kHz NB)");
        return 0;
    }

    /* Fallback: try via /dev/msm_audio_ctl sysfs */
    LOGD("Hexagon audio mic path failed, trying sysfs fallback");
    return -1;
}

int hexagon_audio_enable_spkr_path(hexagon_rpc_handle_t* h) {
    uint8_t req[16] = {0};

    /* Audio path config:
     * Byte 0: source (0x01 = GSM decoder, 0x02 = VoLTE decoder)
     * Byte 1: destination (0x01 = EARPIECE, 0x02 = SPEAKER, 0x03 = HEADPHONE)
     * Byte 2: sample rate
     * Byte 3: gain
     */
    req[0] = 0x01;  /* GSM voice decoder */
    req[1] = 0x01;  /* Earpiece */
    req[2] = 0x00;  /* 8 kHz narrowband */
    req[3] = 0x80;  /* 0 dB gain */

    uint8_t rsp[HEXAGON_RPC_MAX_MSG];
    int n = hexagon_rpc_call(h, HEXAGON_PID_MODEM_AUDIO, 0x1001, req, 4, rsp, sizeof(rsp));

    if (n >= 0) {
        LOGI("DSP-to-speaker audio path enabled (8kHz NB)");
        return 0;
    }
    return -1;
}

int hexagon_voice_set_codec(hexagon_rpc_handle_t* h, uint8_t codec_type, uint16_t bitrate) {
    uint8_t req[8] = {0};
    req[0] = codec_type;    /* 0x00=GSM-FR, 0x01=GSM-HR, 0x02=GSM-EFR, 0x03=AMR-NB, 0x04=AMR-WB */
    req[1] = (uint8_t)(bitrate & 0xFF);
    req[2] = (uint8_t)((bitrate >> 8) & 0xFF);

    uint8_t rsp[64];
    int n = hexagon_rpc_call(h, HEXAGON_PID_MODEM_VOICE, 0x1000, req, 3, rsp, sizeof(rsp));
    return (n >= 0) ? 0 : -1;
}

/* ── RF / L1 Control via DSP ──────────────────────────────────────────── */

int hexagon_rf_send_frame(hexagon_rpc_handle_t* h, const uint8_t* frame, uint16_t len) {
    if (!h || !frame || len == 0) return -1;

    uint8_t req[HEXAGON_RPC_MAX_MSG];
    uint8_t* p = req;
    *p++ = (uint8_t)(len & 0xFF);
    *p++ = (uint8_t)((len >> 8) & 0xFF);
    memcpy(p, frame, len);
    p += len;

    uint8_t rsp[64];
    int n = hexagon_rpc_call(h, HEXAGON_PID_MODEM_RF, 0x1000, req, (uint32_t)(p - req), rsp, sizeof(rsp));

    LOGD("RF frame sent: %d bytes, result=%d", len, n);
    return (n >= 0) ? 0 : -1;
}

int hexagon_l1_configure(hexagon_rpc_handle_t* h, uint16_t arfcn, uint8_t timeslot,
                         uint8_t training_seq, uint8_t tx_power) {
    uint8_t req[16] = {0};
    req[0] = (uint8_t)(arfcn & 0xFF);
    req[1] = (uint8_t)((arfcn >> 8) & 0xFF);
    req[2] = timeslot & 0x07;
    req[3] = training_seq & 0x07;
    req[4] = tx_power;
    req[5] = 0x00; /* Band: GSM-900 */
    req[6] = 0x01; /* Mode: BTS (transmit) */

    uint8_t rsp[64];
    int n = hexagon_rpc_call(h, HEXAGON_PID_MODEM_L1, 0x1000, req, 7, rsp, sizeof(rsp));

    LOGI("L1 configured: ARFCN=%d TS=%d TSC=%d PWR=%d -> %s",
         arfcn, timeslot, training_seq, tx_power, (n >= 0) ? "OK" : "FAIL");
    return (n >= 0) ? 0 : -1;
}

int hexagon_l1_start_tx(hexagon_rpc_handle_t* h) {
    uint8_t req[4] = {0x01, 0x00, 0x00, 0x00}; /* Start Tx */
    uint8_t rsp[64];
    int n = hexagon_rpc_call(h, HEXAGON_PID_MODEM_L1, 0x1001, req, 4, rsp, sizeof(rsp));
    LOGI("L1 Tx start: %s", (n >= 0) ? "OK" : "FAIL");
    return (n >= 0) ? 0 : -1;
}

int hexagon_l1_stop_tx(hexagon_rpc_handle_t* h) {
    uint8_t req[4] = {0x00, 0x00, 0x00, 0x00}; /* Stop Tx */
    uint8_t rsp[64];
    int n = hexagon_rpc_call(h, HEXAGON_PID_MODEM_L1, 0x1001, req, 4, rsp, sizeof(rsp));
    LOGI("L1 Tx stop: %s", (n >= 0) ? "OK" : "FAIL");
    return (n >= 0) ? 0 : -1;
}
