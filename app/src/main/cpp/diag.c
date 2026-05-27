#include "diag.h"
#include "crc16.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <android/log.h>

#define LOG_TAG "CellLink-DIAG"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

/* Default device paths to try for the DIAG port */
const char* DIAG_DEVICE_PATHS[] = {
    "/dev/diag",
    "/dev/ttyUSB0",
    "/dev/ttyUSB1",
    "/dev/ttyUSB2",
    "/dev/ttyACM0",
    "/dev/ttyACM1",
    "/dev/smd0",
    "/dev/smd11",
    "/dev/smd7",
    NULL
};

struct diag_handle {
    int fd;
    char device_path[256];
    uint16_t txn_id;
};

/* ── Static Helpers ──────────────────────────────────────────────────── */

static uint16_t crc16_diag(const uint8_t* data, size_t len) {
    uint16_t crc = crc16_compute(data, len);
    return crc ^ 0xFFFF;
}

static int serial_configure(int fd, speed_t baud) {
    struct termios tty;
    if (tcgetattr(fd, &tty) != 0) {
        LOGE("tcgetattr failed: %s", strerror(errno));
        return -1;
    }

    cfsetospeed(&tty, baud);
    cfsetispeed(&tty, baud);

    tty.c_cflag &= ~PARENB;            /* No parity */
    tty.c_cflag &= ~CSTOPB;            /* 1 stop bit */
    tty.c_cflag &= ~CSIZE;
    tty.c_cflag |= CS8;                /* 8 data bits */
    tty.c_cflag &= ~CRTSCTS;           /* No hardware flow control */
    tty.c_cflag |= CREAD | CLOCAL;     /* Enable receiver, ignore modem lines */

    tty.c_lflag &= ~(ICANON | ECHO | ECHOE | ECHONL | ISIG); /* Raw input */
    tty.c_iflag &= ~(IXON | IXOFF | IXANY);                   /* No software flow control */
    tty.c_iflag &= ~(INLCR | ICRNL | IGNCR);                  /* No CR/NL translation */
    tty.c_oflag &= ~OPOST;                                     /* Raw output */
    tty.c_oflag &= ~(ONLCR | OCRNL);                          /* No NL/CR translation */

    tty.c_cc[VMIN]  = 0;
    tty.c_cc[VTIME] = 5;               /* 500ms inter-character timeout */

    if (tcsetattr(fd, TCSANOW, &tty) != 0) {
        LOGE("tcsetattr failed: %s", strerror(errno));
        return -1;
    }
    return 0;
}

/** Escape 0x7E and 0x7D bytes in the payload for transparency */
static uint16_t escape_payload(const uint8_t* src, uint16_t src_len, uint8_t* dst) {
    uint16_t d = 0;
    for (uint16_t s = 0; s < src_len; s++) {
        if (src[s] == DIAG_START_BYTE || src[s] == DIAG_ESCAPE_BYTE) {
            dst[d++] = DIAG_ESCAPE_BYTE;
            dst[d++] = src[s] ^ DIAG_ESCAPE_MASK;
        } else {
            dst[d++] = src[s];
        }
    }
    return d;
}

/** Build a DIAG frame with CRC and byte-stuffing. Returns frame length. */
static uint16_t build_frame(uint8_t cmd, const uint8_t* payload, uint16_t len, uint8_t* frame) {
    /* Header: start byte + cmd + length(LE) + payload */
    uint8_t header[4];
    header[0] = cmd;
    header[1] = (uint8_t)(len & 0xFF);
    header[2] = (uint8_t)((len >> 8) & 0xFF);
    memcpy(header + 3, payload, len > 252 ? 252 : len); /* For CRC calc, just use first part */

    /* Compute CRC over [cmd, len_lo, len_hi, payload...] */
    uint8_t crc_buf[DIAG_MAX_FRAME];
    crc_buf[0] = cmd;
    crc_buf[1] = (uint8_t)(len & 0xFF);
    crc_buf[2] = (uint8_t)((len >> 8) & 0xFF);
    memcpy(crc_buf + 3, payload, len);
    uint16_t crc = crc16_diag(crc_buf, len + 3);

    /* Assemble frame: start_byte + escaped_[cmd+len+payload] + crc_lo + crc_hi + end_byte */
    uint8_t raw[DIAG_MAX_FRAME];
    raw[0] = cmd;
    raw[1] = (uint8_t)(len & 0xFF);
    raw[2] = (uint8_t)((len >> 8) & 0xFF);
    memcpy(raw + 3, payload, len);

    uint16_t raw_len = len + 3;
    uint8_t escaped[DIAG_MAX_FRAME * 2];
    uint16_t escaped_len = escape_payload(raw, raw_len, escaped);

    frame[0] = DIAG_START_BYTE;
    memcpy(frame + 1, escaped, escaped_len);
    frame[1 + escaped_len]     = (uint8_t)(crc & 0xFF);
    frame[1 + escaped_len + 1] = (uint8_t)((crc >> 8) & 0xFF);
    frame[1 + escaped_len + 2] = DIAG_END_BYTE;

    return escaped_len + 4;
}

/* ── Public API ───────────────────────────────────────────────────────── */

diag_handle_t* diag_open(const char* device_path) {
    diag_handle_t* h = (diag_handle_t*)calloc(1, sizeof(diag_handle_t));
    if (!h) return NULL;

    int fd = -1;

    if (device_path) {
        fd = open(device_path, O_RDWR | O_NOCTTY | O_NONBLOCK);
        if (fd >= 0) {
            strncpy(h->device_path, device_path, sizeof(h->device_path) - 1);
        }
    } else {
        /* Try default paths */
        for (int i = 0; DIAG_DEVICE_PATHS[i] != NULL; i++) {
            fd = open(DIAG_DEVICE_PATHS[i], O_RDWR | O_NOCTTY | O_NONBLOCK);
            if (fd >= 0) {
                strncpy(h->device_path, DIAG_DEVICE_PATHS[i], sizeof(h->device_path) - 1);
                break;
            }
        }
    }

    if (fd < 0) {
        LOGE("Failed to open DIAG port: %s", strerror(errno));
        free(h);
        return NULL;
    }

    /* Clear O_NONBLOCK for normal operation */
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
    }

    if (serial_configure(fd, B115200) != 0) {
        /* Try 921600 for newer devices */
        if (serial_configure(fd, B921600) != 0) {
            close(fd);
            free(h);
            return NULL;
        }
    }

    h->fd = fd;
    h->txn_id = 1;
    LOGI("DIAG port opened: %s", h->device_path);
    return h;
}

void diag_close(diag_handle_t* h) {
    if (!h) return;
    if (h->fd >= 0) {
        close(h->fd);
    }
    LOGI("DIAG port closed: %s", h->device_path);
    free(h);
}

int diag_send(diag_handle_t* h, uint8_t cmd, const uint8_t* data, uint16_t len) {
    if (!h || h->fd < 0) return -1;

    uint8_t frame[DIAG_MAX_FRAME * 2];
    uint16_t frame_len = build_frame(cmd, data, len, frame);

    ssize_t written = write(h->fd, frame, frame_len);
    if (written < 0) {
        LOGE("diag_send write error: %s", strerror(errno));
        return -1;
    }

    tcdrain(h->fd);
    LOGD("diag_send: cmd=0x%02X len=%d written=%zd", cmd, len, written);
    return (int)written;
}

int diag_recv(diag_handle_t* h, uint8_t* cmd_out, uint8_t* buf, uint16_t buf_len, int timeout_ms) {
    if (!h || h->fd < 0) return -1;

    uint8_t raw[DIAG_MAX_FRAME * 2];
    uint16_t pos = 0;
    bool in_frame = false;
    bool escaped = false;

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(h->fd, &rfds);

    int ret = select(h->fd + 1, &rfds, NULL, NULL, &tv);
    if (ret <= 0) {
        if (ret == 0) LOGD("diag_recv timeout");
        return -1;
    }

    /* Read available data */
    uint8_t chunk[256];
    ssize_t n;
    while ((n = read(h->fd, chunk, sizeof(chunk))) > 0) {
        for (ssize_t i = 0; i < n && pos < sizeof(raw); i++) {
            uint8_t b = chunk[i];

            if (!in_frame) {
                if (b == DIAG_START_BYTE) {
                    in_frame = true;
                    pos = 0;
                    escaped = false;
                }
                continue;
            }

            if (escaped) {
                raw[pos++] = b ^ DIAG_ESCAPE_MASK;
                escaped = false;
                continue;
            }

            if (b == DIAG_ESCAPE_BYTE) {
                escaped = true;
                continue;
            }

            if (b == DIAG_END_BYTE) {
                /* Frame complete. Parse: cmd + len_lo + len_hi + payload + crc_lo + crc_hi */
                if (pos < 5) {
                    LOGD("diag_recv: frame too short (%d bytes)", pos);
                    in_frame = false;
                    pos = 0;
                    continue;
                }

                /* Verify CRC over [raw[0..pos-3]] (pos-3 = data including crc bytes) */
                if (!crc16_verify(raw, pos)) {
                    LOGD("diag_recv: CRC mismatch");
                    in_frame = false;
                    pos = 0;
                    continue;
                }

                *cmd_out = raw[0];
                uint16_t payload_len = (uint16_t)raw[1] | ((uint16_t)raw[2] << 8);
                uint16_t copy_len = payload_len < (pos - 5) ? payload_len : (pos - 5);
                if (copy_len > buf_len) copy_len = buf_len;
                memcpy(buf, raw + 3, copy_len);

                LOGD("diag_recv: cmd=0x%02X payload_len=%d", *cmd_out, copy_len);
                return (int)copy_len;
            }

            raw[pos++] = b;
        }
    }

    return -1;
}

int diag_transact(diag_handle_t* h, uint8_t cmd, const uint8_t* req, uint16_t req_len,
                  uint8_t* rsp, uint16_t rsp_len, int timeout_ms) {
    if (diag_send(h, cmd, req, req_len) < 0) return -1;

    uint8_t rsp_cmd;
    return diag_recv(h, &rsp_cmd, rsp, rsp_len, timeout_ms);
}

/* ── QMI over DIAG ───────────────────────────────────────────────────── */

int diag_send_qmi(diag_handle_t* h, uint8_t subsystem, uint16_t command,
                  const uint8_t* data, uint16_t len) {
    uint16_t txn = h->txn_id++;
    if (h->txn_id == 0) h->txn_id = 1;

    uint8_t buf[DIAG_MAX_PAYLOAD];
    uint16_t pos = 0;

    buf[pos++] = subsystem;
    buf[pos++] = (uint8_t)(command & 0xFF);
    buf[pos++] = (uint8_t)((command >> 8) & 0xFF);
    buf[pos++] = (uint8_t)(txn & 0xFF);
    buf[pos++] = (uint8_t)((txn >> 8) & 0xFF);
    if (data && len > 0) {
        memcpy(buf + pos, data, len);
        pos += len;
    }

    return diag_send(h, DIAG_CMD_EXT_MESSAGE_F, buf, pos);
}

int diag_recv_qmi(diag_handle_t* h, uint8_t* subsystem_out, uint16_t* command_out,
                  uint8_t* buf, uint16_t buf_len, int timeout_ms) {
    uint8_t cmd;
    uint8_t raw[DIAG_MAX_PAYLOAD];
    int n = diag_recv(h, &cmd, raw, sizeof(raw), timeout_ms);
    if (n < 5) return -1;  /* min: subsystem + cmd(2) + txn(2) */
    if (cmd != DIAG_CMD_EXT_MESSAGE_F) {
        LOGD("diag_recv_qmi: unexpected cmd 0x%02X, expected 0x7B", cmd);
        return -1;
    }

    *subsystem_out = raw[0];
    *command_out = (uint16_t)raw[1] | ((uint16_t)raw[2] << 8);
    uint16_t copy = n - 5;
    if (copy > buf_len) copy = buf_len;
    memcpy(buf, raw + 5, copy);
    return (int)copy;
}

/* ── NV Item Access ──────────────────────────────────────────────────── */

int diag_nv_read(diag_handle_t* h, uint16_t nv_item_id, uint8_t* buf, uint16_t buf_len) {
    uint8_t req[2];
    req[0] = (uint8_t)(nv_item_id & 0xFF);
    req[1] = (uint8_t)((nv_item_id >> 8) & 0xFF);

    uint8_t rsp[DIAG_MAX_PAYLOAD];
    int n = diag_transact(h, DIAG_CMD_NV_READ_F, req, 2, rsp, sizeof(rsp), 2000);
    if (n < 0) return -1;

    /* Response: status(1) + NV item data */
    if (rsp[0] != 0) {
        LOGE("NV read failed for item 0x%04X: status=%d", nv_item_id, rsp[0]);
        return -1;
    }

    uint16_t copy = n - 1;
    if (copy > buf_len) copy = buf_len;
    memcpy(buf, rsp + 1, copy);
    return (int)copy;
}

int diag_nv_write(diag_handle_t* h, uint16_t nv_item_id, const uint8_t* data, uint16_t len) {
    uint8_t req[DIAG_MAX_PAYLOAD];
    req[0] = (uint8_t)(nv_item_id & 0xFF);
    req[1] = (uint8_t)((nv_item_id >> 8) & 0xFF);
    memcpy(req + 2, data, len);

    uint8_t rsp[16];
    int n = diag_transact(h, DIAG_CMD_NV_WRITE_F, req, len + 2, rsp, sizeof(rsp), 3000);
    if (n < 0) return -1;

    return (rsp[0] == 0) ? 0 : -1;
}

/* ── Memory Access (Live Patching) ───────────────────────────────────── */

int diag_mem_write(diag_handle_t* h, uint32_t address, const uint8_t* data, uint16_t len) {
    uint8_t req[DIAG_MAX_PAYLOAD];
    req[0] = (uint8_t)(address & 0xFF);
    req[1] = (uint8_t)((address >> 8) & 0xFF);
    req[2] = (uint8_t)((address >> 16) & 0xFF);
    req[3] = (uint8_t)((address >> 24) & 0xFF);
    req[4] = (uint8_t)(len & 0xFF);
    req[5] = (uint8_t)((len >> 8) & 0xFF);
    memcpy(req + 6, data, len);

    uint8_t rsp[4];
    int n = diag_transact(h, DIAG_CMD_EXT_MEM_POKE_F, req, len + 6, rsp, sizeof(rsp), 5000);
    if (n < 0) return -1;
    return (rsp[0] == 0) ? 0 : -1;
}

int diag_mem_read(diag_handle_t* h, uint32_t address, uint8_t* buf, uint16_t len) {
    uint8_t req[6];
    req[0] = (uint8_t)(address & 0xFF);
    req[1] = (uint8_t)((address >> 8) & 0xFF);
    req[2] = (uint8_t)((address >> 16) & 0xFF);
    req[3] = (uint8_t)((address >> 24) & 0xFF);
    req[4] = (uint8_t)(len & 0xFF);
    req[5] = (uint8_t)((len >> 8) & 0xFF);

    uint8_t rsp[DIAG_MAX_PAYLOAD];
    int n = diag_transact(h, DIAG_CMD_EXT_MEM_PEEK_F, req, 6, rsp, sizeof(rsp), 5000);
    if (n < 4) return -1;

    uint16_t copy = n - 2;
    if (copy > len) copy = len;
    memcpy(buf, rsp + 2, copy);
    return (int)copy;
}

/* ── AT Commands ─────────────────────────────────────────────────────── */

int diag_at_command(diag_handle_t* h, const char* cmd, char* response, uint16_t max_len) {
    if (!h || h->fd < 0 || !cmd) return -1;

    /* Send AT command terminated with \r\n */
    size_t cmd_len = strlen(cmd);
    char full_cmd[512];
    int written = snprintf(full_cmd, sizeof(full_cmd), "AT%s\r\n", cmd);
    if (written < 0) return -1;

    write(h->fd, full_cmd, written);
    tcdrain(h->fd);

    memset(response, 0, max_len);

    /* Read response with timeout */
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;

    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(h->fd, &rfds);

    int ret = select(h->fd + 1, &rfds, NULL, NULL, &tv);
    if (ret <= 0) return -1;

    usleep(200000); /* Allow more data to accumulate */
    ssize_t n = read(h->fd, response, max_len - 1);
    if (n > 0) {
        response[n] = '\0';
        /* Strip trailing \r\nOK\r\n or \r\nERROR\r\n */
        char* end = response + n;
        while (end > response && (*end == '\0' || *end == '\n' || *end == '\r')) {
            *end-- = '\0';
        }
        return (int)n;
    }
    return -1;
}

/* ── Factory Test Mode ────────────────────────────────────────────────── */

int diag_enter_ftm(diag_handle_t* h) {
    uint8_t req[4] = {0x01, 0x00, 0x00, 0x00};
    uint8_t rsp[16];
    return diag_transact(h, DIAG_CMD_FTM_MODE, req, 4, rsp, sizeof(rsp), 3000);
}

bool diag_is_ready(diag_handle_t* h) {
    if (!h || h->fd < 0) return false;

    uint8_t req = 0x00;
    uint8_t rsp[64];
    int n = diag_transact(h, DIAG_CMD_VERSION_F, &req, 1, rsp, sizeof(rsp), 1000);
    return n > 0;
}

/* ── Raw Port Access ─────────────────────────────────────────────────── */

int diag_raw_write(diag_handle_t* h, const uint8_t* data, uint16_t len) {
    if (!h || h->fd < 0 || !data) return -1;
    ssize_t n = write(h->fd, data, len);
    if (n < 0) {
        LOGE("diag_raw_write error: %s", strerror(errno));
        return -1;
    }
    tcdrain(h->fd);
    return (int)n;
}

int diag_raw_read(diag_handle_t* h, uint8_t* buf, uint16_t buf_len, int timeout_ms) {
    if (!h || h->fd < 0 || !buf) return -1;

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(h->fd, &rfds);

    int ret = select(h->fd + 1, &rfds, NULL, NULL, &tv);
    if (ret <= 0) return -1;

    usleep(100000); /* Wait for more data */
    ssize_t n = read(h->fd, buf, buf_len - 1);
    if (n > 0) {
        buf[n] = '\0';
        return (int)n;
    }
    return -1;
}
