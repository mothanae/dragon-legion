#include "hisilicon_at.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <errno.h>
#include <sys/select.h>
#include <android/log.h>

#define LOG_TAG "CellLink-HISI"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

/* ── Serial Port Config ──────────────────────────────────────────────── */

static int serial_open(const char* path, speed_t baud) {
    int fd = open(path, O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (fd < 0) {
        LOGE("Cannot open %s: %s", path, strerror(errno));
        return -1;
    }

    struct termios tty;
    if (tcgetattr(fd, &tty) != 0) {
        LOGE("tcgetattr failed: %s", strerror(errno));
        close(fd); return -1;
    }

    cfsetospeed(&tty, baud);
    cfsetispeed(&tty, baud);

    tty.c_cflag &= ~PARENB;     /* No parity */
    tty.c_cflag &= ~CSTOPB;     /* 1 stop bit */
    tty.c_cflag &= ~CSIZE;
    tty.c_cflag |= CS8;         /* 8 data bits */
    tty.c_cflag &= ~CRTSCTS;    /* No HW flow control */
    tty.c_cflag |= CREAD | CLOCAL;

    tty.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);
    tty.c_iflag &= ~(IXON | IXOFF | IXANY | INLCR | ICRNL | IGNCR);
    tty.c_oflag &= ~(OPOST | ONLCR | OCRNL);

    tty.c_cc[VMIN]  = 0;
    tty.c_cc[VTIME] = 10; /* 1 second inter-char timeout */

    if (tcsetattr(fd, TCSANOW, &tty) != 0) {
        LOGE("tcsetattr failed: %s", strerror(errno));
        close(fd); return -1;
    }

    /* Clear O_NONBLOCK */
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);

    return fd;
}

/* ── AT Command Send/Receive ─────────────────────────────────────────── */

static int at_read_response(int fd, char* buf, int max_len, int timeout_ms) {
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);

    int total = 0;
    uint64_t deadline_ms = (uint64_t)timeout_ms;

    while (total < max_len - 1) {
        int ret = select(fd + 1, &rfds, NULL, NULL, &tv);
        if (ret <= 0) break;

        uint8_t chunk[128];
        ssize_t n = read(fd, chunk, sizeof(chunk));
        if (n <= 0) break;

        for (ssize_t i = 0; i < n && total < max_len - 1; i++) {
            buf[total++] = chunk[i];
        }

        /* Check if we got a final response code */
        buf[total] = '\0';
        if (strstr(buf, "OK\r\n") || strstr(buf, "ERROR\r\n") ||
            strstr(buf, "CME ERROR") || strstr(buf, "CMS ERROR") ||
            strstr(buf, "NO CARRIER\r\n") || strstr(buf, "BUSY\r\n")) {
            break;
        }

        tv.tv_sec = 0;
        tv.tv_usec = 200000; /* 200ms more for trailing data */
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
    }

    buf[total] = '\0';
    return total;
}

/* ── Public API ───────────────────────────────────────────────────────── */

hisilicon_at_t* hisilicon_open(const char* device_path) {
    hisilicon_at_t* at = (hisilicon_at_t*)calloc(1, sizeof(hisilicon_at_t));
    if (!at) return NULL;

    const char* path = device_path ? device_path : HISILICON_AT_PORT_DEFAULT;

    at->fd = serial_open(path, HISILICON_AT_BAUD_RATE);
    if (at->fd < 0) {
        /* Try alternate path */
        path = HISILICON_AT_PORT_ALT;
        at->fd = serial_open(path, HISILICON_AT_BAUD_RATE);
        if (at->fd < 0) {
            free(at);
            return NULL;
        }
    }

    strncpy(at->device_path, path, sizeof(at->device_path) - 1);
    at->is_open = true;
    at->timeout_ms = 5000;

    if (pthread_mutex_init(&at->lock, NULL) != 0) {
        close(at->fd); free(at); return NULL;
    }

    /* Test basic AT communication */
    char rsp[256];
    if (hisilicon_at_send(at, "", rsp, sizeof(rsp)) < 0) {
        LOGD("Basic AT test failed, trying sync...");
        /* Some modems need baud sync first */
        const char* sync_cmd = "AT\r\n";
        write(at->fd, sync_cmd, 4);
        usleep(200000);
        at_read_response(at->fd, rsp, sizeof(rsp), 1000);
        if (!strstr(rsp, "OK")) {
            hisilicon_close(at);
            return NULL;
        }
    }

    /* Disable echo */
    hisilicon_at_send(at, "E0", rsp, sizeof(rsp));

    LOGI("HiSilicon AT port opened: %s", at->device_path);
    return at;
}

void hisilicon_close(hisilicon_at_t* at) {
    if (!at) return;
    if (at->eng_mode_active) hisilicon_eng_mode_exit(at);
    if (at->fd >= 0) close(at->fd);
    pthread_mutex_destroy(&at->lock);
    LOGI("HiSilicon AT port closed");
    free(at);
}

int hisilicon_at_send(hisilicon_at_t* at, const char* cmd, char* response, int max_len) {
    if (!at || at->fd < 0 || !response) return -1;

    pthread_mutex_lock(&at->lock);

    /* Build command: AT<cmd>\r\n */
    char full[512];
    int len = snprintf(full, sizeof(full), "AT%s\r\n", cmd);

    /* Flush input buffer */
    usleep(50000);
    char discard[256];
    while (read(at->fd, discard, sizeof(discard)) > 0);

    /* Send */
    ssize_t written = write(at->fd, full, len);
    if (written < 0) {
        LOGE("AT write error: %s", strerror(errno));
        pthread_mutex_unlock(&at->lock);
        return -1;
    }
    tcdrain(at->fd);

    /* Read response */
    int n = at_read_response(at->fd, response, max_len, at->timeout_ms);
    if (n >= 0) {
        /* Strip echo */
        char* data = response;
        if (strncmp(data, full, strlen(full)) == 0) {
            data += strlen(full);
        }
        /* Move data to start of buffer */
        if (data != response) {
            memmove(response, data, strlen(data) + 1);
        }
        /* Store last response */
        strncpy(at->last_response, response, sizeof(at->last_response) - 1);
        LOGD("AT%s -> %s", cmd[0] ? cmd : "[empty]", response[0] ? response : "(empty)");
    }

    pthread_mutex_unlock(&at->lock);
    return n;
}

int hisilicon_at_ok(hisilicon_at_t* at, const char* cmd) {
    char rsp[1024];
    int n = hisilicon_at_send(at, cmd, rsp, sizeof(rsp));
    if (n < 0) return -1;
    return (strstr(rsp, "OK")) ? 0 : -1;
}

/* ── Engineering Mode ────────────────────────────────────────────────── */

int hisilicon_eng_mode_enter(hisilicon_at_t* at) {
    if (at->eng_mode_active) return 0;
    if (hisilicon_at_ok(at, "^ENG=1") == 0 ||
        hisilicon_at_ok(at, "^SYSINFO") == 0) {
        at->eng_mode_active = true;
        LOGI("HiSilicon engineering mode enabled");
        return 0;
    }
    return -1;
}

int hisilicon_eng_mode_exit(hisilicon_at_t* at) {
    hisilicon_at_ok(at, "^ENG=0");
    at->eng_mode_active = false;
    return 0;
}

/* ── Network Operations ──────────────────────────────────────────────── */

int hisilicon_network_scan(hisilicon_at_t* at, char* results, int max_len) {
    /* AT+COPS=? returns list of operators */
    char rsp[4096];
    int n = hisilicon_at_send(at, "+COPS=?", rsp, sizeof(rsp));
    if (n < 0) return -1;

    strncpy(results, rsp, max_len - 1);
    results[max_len - 1] = '\0';

    /* Count networks */
    int count = 0;
    char* p = rsp;
    while ((p = strstr(p, "(2,")) || (p = strstr(p, "(1,"))) {
        count++;
        p++;
    }
    return count > 0 ? count : (n > 0 ? 1 : -1);
}

int hisilicon_register_network(hisilicon_at_t* at, int mcc, int mnc) {
    char plmn[8];
    snprintf(plmn, sizeof(plmn), "%03d%02d", mcc, mnc);

    /* Set to manual network selection */
    char cmd[64];
    snprintf(cmd, sizeof(cmd), "+COPS=1,2,\"%s\"", plmn);

    if (hisilicon_at_ok(at, cmd) == 0) {
        LOGI("Registered on %s via AT+COPS", plmn);
        return 0;
    }

    /* HiSilicon fallback: use ^CPSEL */
    snprintf(cmd, sizeof(cmd), "^CPSEL=1,\"%s\"", plmn);
    if (hisilicon_at_ok(at, cmd) == 0) {
        LOGI("Registered on %s via AT^CPSEL", plmn);
        return 0;
    }

    /* Try automatic registration */
    if (hisilicon_at_ok(at, "+COPS=0") == 0) {
        /* Check what we got */
        char rsp[256];
        hisilicon_at_send(at, "+COPS?", rsp, sizeof(rsp));
        if (strstr(rsp, plmn)) {
            LOGI("Auto-registered on %s", plmn);
            return 0;
        }
    }

    return -1;
}

int hisilicon_get_signal(hisilicon_at_t* at, int* rssi_dbm) {
    char rsp[64];
    if (hisilicon_at_send(at, "+CSQ", rsp, sizeof(rsp)) < 0) return -1;

    int csq;
    if (sscanf(rsp, "+CSQ: %d", &csq) == 1) {
        *rssi_dbm = (csq >= 0 && csq <= 31) ? (-113 + csq * 2) : -120;
        return 0;
    }

    /* HiSilicon HRSSI engineering command */
    if (hisilicon_at_send(at, "^HRSSI", rsp, sizeof(rsp)) >= 0) {
        if (sscanf(rsp, "^HRSSI: %d", &csq) == 1) {
            *rssi_dbm = -csq; /* ^HRSSI reports absolute dBm value */
            return 0;
        }
    }

    return -1;
}

int hisilicon_get_cell_info(hisilicon_at_t* at, char* info, int max_len) {
    /* HiSilicon ^CELLINFO provides detailed cell info */
    int n = hisilicon_at_send(at, "^CELLINFO", info, max_len);
    if (n >= 0) return n;

    /* Fallback to standard AT+CREG? */
    return hisilicon_at_send(at, "+CREG?", info, max_len);
}

/* ── Call Operations ─────────────────────────────────────────────────── */

int hisilicon_make_call(hisilicon_at_t* at, const char* number) {
    char cmd[32];
    snprintf(cmd, sizeof(cmd), "D%s;", number);

    char rsp[256];
    int n = hisilicon_at_send(at, cmd, rsp, sizeof(rsp));
    if (n >= 0 && (strstr(rsp, "OK") || strstr(rsp, "CONNECT"))) {
        LOGI("Call initiated to %s", number);
        return 0;
    }

    /* Try emergency call path */
    if (hisilicon_at_send(at, "D112;", rsp, sizeof(rsp)) >= 0 &&
        (strstr(rsp, "OK") || strstr(rsp, "CONNECT"))) {
        LOGI("Call initiated via emergency path");
        return 0;
    }

    return -1;
}

int hisilicon_end_call(hisilicon_at_t* at) {
    return hisilicon_at_ok(at, "CHUP");
}

int hisilicon_answer_call(hisilicon_at_t* at) {
    return hisilicon_at_ok(at, "ATA");
}

/* ── SMS Operations ──────────────────────────────────────────────────── */

int hisilicon_send_sms(hisilicon_at_t* at, const char* recipient, const char* text) {
    /* Set text mode */
    hisilicon_at_ok(at, "+CMGF=1");

    /* Start SMS */
    char cmd[64];
    snprintf(cmd, sizeof(cmd), "+CMGS=\"%s\"", recipient);

    char rsp[1024];
    int n = hisilicon_at_send(at, cmd, rsp, sizeof(rsp));
    if (n < 0 || !strstr(rsp, ">")) {
        /* Try PDU mode */
        hisilicon_at_ok(at, "+CMGF=0");
        snprintf(cmd, sizeof(cmd), "+CMGS=%d", (int)strlen(text) + 10);
        n = hisilicon_at_send(at, cmd, rsp, sizeof(rsp));
        if (n < 0) return -1;
    }

    /* Send message body + CTRL-Z */
    char body[512];
    int len = snprintf(body, sizeof(body), "%s\x1A", text);
    write(at->fd, body, len);

    /* Wait for +CMGS: or OK */
    char result[256];
    at_read_response(at->fd, result, sizeof(result), 10000);
    if (strstr(result, "+CMGS:") || strstr(result, "OK")) {
        LOGI("SMS sent to %s", recipient);
        return 0;
    }

    return -1;
}

int hisilicon_read_sms(hisilicon_at_t* at, char* messages, int max_len) {
    /* List all SMS messages in text mode */
    hisilicon_at_ok(at, "+CMGF=1");
    return hisilicon_at_send(at, "+CMGL=\"ALL\"", messages, max_len);
}

/* ── RF / Engineering ────────────────────────────────────────────────── */

int hisilicon_set_band(hisilicon_at_t* at, int band) {
    /* AT^SYSCFG=<mode>,<acqorder>,<band>,<roam>,<srvdomain>
     * mode: 2=automatic, 13=GSM only, 14=WCDMA only, 16=LTE only
     * band: hex bitmask (0x80=GSM900, 0x100=DCS1800, etc.) */
    char cmd[64];
    snprintf(cmd, sizeof(cmd), "^SYSCFG=13,1,%d,1,2", band);
    return hisilicon_at_ok(at, cmd);
}

int hisilicon_lock_arfcn(hisilicon_at_t* at, int arfcn) {
    char cmd[32];
    snprintf(cmd, sizeof(cmd), "^ARFCN=%d", arfcn);
    return hisilicon_at_ok(at, cmd);
}

int hisilicon_set_tx_power(hisilicon_at_t* at, int power_dbm) {
    char cmd[32];
    snprintf(cmd, sizeof(cmd), "^TXPWR=%d", power_dbm);
    return hisilicon_at_ok(at, cmd);
}

int hisilicon_rf_test_start(hisilicon_at_t* at, int arfcn, int power_dbm) {
    /* Enter RF test mode on HiSilicon:
     * AT^RFTM=<mode>,<arfcn>,<band>,<power>,<slot> */
    char cmd[64];
    snprintf(cmd, sizeof(cmd), "^RFTM=1,%d,0,%d,0", arfcn, power_dbm);
    if (hisilicon_at_ok(at, cmd) == 0) {
        LOGI("RF test mode: ARFCN=%d, PWR=%d dBm", arfcn, power_dbm);
        return 0;
    }

    /* Alternative: use AT+CRFM (Continuous RF Mode) */
    snprintf(cmd, sizeof(cmd), "+CRFM=1,%d,%d", arfcn, power_dbm);
    return hisilicon_at_ok(at, cmd);
}

int hisilicon_rf_test_stop(hisilicon_at_t* at) {
    hisilicon_at_ok(at, "^RFTM=0");
    hisilicon_at_ok(at, "+CRFM=0");
    return 0;
}

/* ── Modem Management ────────────────────────────────────────────────── */

int hisilicon_modem_reset(hisilicon_at_t* at) {
    /* AT+CFUN=1,1 resets the modem */
    if (hisilicon_at_ok(at, "+CFUN=1,1") == 0) {
        LOGI("Modem reset initiated");
        return 0;
    }
    /* HiSilicon-specific reset */
    return hisilicon_at_ok(at, "^RESET");
}

int hisilicon_get_firmware_version(hisilicon_at_t* at, char* version, int max_len) {
    int n = hisilicon_at_send(at, "+CGMR", version, max_len);
    if (n >= 0) {
        /* Strip AT prefix and OK suffix */
        char* p = version;
        while (*p && (*p == '\r' || *p == '\n')) p++;
        char* end = p + strlen(p);
        while (end > p && (*end == '\r' || *end == '\n' || *end == ' ')) end--;
        *(end + 1) = '\0';
        if (end > p) {
            memmove(version, p, end - p + 1);
            return (int)(end - p + 1);
        }
    }

    /* Fallback: ATI */
    return hisilicon_at_send(at, "I", version, max_len);
}

bool hisilicon_is_alive(hisilicon_at_t* at) {
    if (!at || at->fd < 0) return false;
    char rsp[64];
    return hisilicon_at_send(at, "", rsp, sizeof(rsp)) >= 0 && strstr(rsp, "OK");
}
