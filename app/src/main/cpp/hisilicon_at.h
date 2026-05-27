#ifndef CELLLINK_HISILICON_AT_H
#define CELLLINK_HISILICON_AT_H

#include "device_detect.h"
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── HiSilicon Balong AT Port Constants ──────────────────────────────── */

#define HISILICON_AT_PORT_DEFAULT    "/dev/ttyAMA0"
#define HISILICON_AT_PORT_ALT        "/dev/ttyACM0"
#define HISILICON_AT_BAUD_RATE       B115200

/* HiSilicon-specific engineering commands */
#define HISI_ENG_MODE_START     "AT^ENG=1"       /* Enter engineering mode */
#define HISI_ENG_MODE_STOP      "AT^ENG=0"       /* Exit engineering mode */
#define HISI_BAND_CONFIG        "AT^SYSCFG="     /* System config / band */
#define HISI_FREQ_LOCK          "AT^FREQLOCK="   /* Lock to specific ARFCN */
#define HISI_CELL_INFO          "AT^CELLINFO"    /* Detailed cell info */
#define HISI_SET_TX_POWER       "AT^TXPWR="      /* Set Tx power */
#define HISI_FORCE_NETWORK      "AT^CPSEL="      /* Force network selection */
#define HISI_RF_TEST_MODE       "AT^RFTM="       /* RF test mode */
#define HISI_MODEM_LOG          "AT^MLOG="       /* Modem logging */
#define HISI_SET_ARFCN          "AT^ARFCN="      /* Set ARFCN for manual mode */

/* ── AT Handle ───────────────────────────────────────────────────────── */

typedef struct {
    int             fd;
    char            device_path[256];
    pthread_mutex_t lock;
    bool            is_open;
    bool            eng_mode_active;
    char            last_response[4096];
    uint32_t        timeout_ms;
} hisilicon_at_t;

/* ── Modem Operations Handle (unified interface) ─────────────────────── */

typedef enum {
    MODEM_OP_REGISTER_NETWORK,
    MODEM_OP_SCAN_NETWORKS,
    MODEM_OP_GET_SIGNAL,
    MODEM_OP_MAKE_CALL,
    MODEM_OP_END_CALL,
    MODEM_OP_ANSWER_CALL,
    MODEM_OP_SEND_SMS,
    MODEM_OP_READ_SMS,
    MODEM_OP_SET_BAND,
    MODEM_OP_SET_ARFCN,
    MODEM_OP_SET_TX_POWER,
    MODEM_OP_START_TX,
    MODEM_OP_STOP_TX,
    MODEM_OP_GET_OPERATOR,
    MODEM_OP_GET_CELL_INFO,
} modem_operation_t;

/* ── API ──────────────────────────────────────────────────────────────── */

/** Open the HiSilicon AT command port. Returns NULL on failure. */
hisilicon_at_t* hisilicon_open(const char* device_path);

/** Close the AT port. */
void hisilicon_close(hisilicon_at_t* at);

/** Send an AT command and get the response. Returns response length or -1. */
int hisilicon_at_send(hisilicon_at_t* at, const char* cmd, char* response, int max_len);

/** Send an AT command and check for "OK" response. Returns 0 on success. */
int hisilicon_at_ok(hisilicon_at_t* at, const char* cmd);

/** Enter engineering mode (required for advanced commands). */
int hisilicon_eng_mode_enter(hisilicon_at_t* at);

/** Exit engineering mode. */
int hisilicon_eng_mode_exit(hisilicon_at_t* at);

/** ── Network Operations ─────────────────────────────────────────────── */

/** Scan for visible networks. Returns network list as text. */
int hisilicon_network_scan(hisilicon_at_t* at, char* results, int max_len);

/** Register on a specific network by MCC/MNC. */
int hisilicon_register_network(hisilicon_at_t* at, int mcc, int mnc);

/** Get current signal strength (RSSI in dBm). */
int hisilicon_get_signal(hisilicon_at_t* at, int* rssi_dbm);

/** Get serving cell information. */
int hisilicon_get_cell_info(hisilicon_at_t* at, char* info, int max_len);

/** ── Call Operations ────────────────────────────────────────────────── */

/** Make a voice call. */
int hisilicon_make_call(hisilicon_at_t* at, const char* number);

/** End current call. */
int hisilicon_end_call(hisilicon_at_t* at);

/** Answer incoming call. */
int hisilicon_answer_call(hisilicon_at_t* at);

/** ── SMS Operations ─────────────────────────────────────────────────── */

/** Send an SMS via AT+CMGS. */
int hisilicon_send_sms(hisilicon_at_t* at, const char* recipient, const char* text);

/** Read received SMS messages. */
int hisilicon_read_sms(hisilicon_at_t* at, char* messages, int max_len);

/** ── RF / Engineering Operations ────────────────────────────────────── */

/** Configure the GSM band (GSM900, DCS1800, etc.). */
int hisilicon_set_band(hisilicon_at_t* at, int band);

/** Lock to a specific ARFCN. */
int hisilicon_lock_arfcn(hisilicon_at_t* at, int arfcn);

/** Set transmitter power level in dBm. */
int hisilicon_set_tx_power(hisilicon_at_t* at, int power_dbm);

/** Enter RF test mode and start continuous transmission. */
int hisilicon_rf_test_start(hisilicon_at_t* at, int arfcn, int power_dbm);

/** Stop RF test mode. */
int hisilicon_rf_test_stop(hisilicon_at_t* at);

/** ── Modem Management ───────────────────────────────────────────────── */

/** Reset the modem. */
int hisilicon_modem_reset(hisilicon_at_t* at);

/** Get modem firmware version. */
int hisilicon_get_firmware_version(hisilicon_at_t* at, char* version, int max_len);

/** Check if the AT port is responsive. */
bool hisilicon_is_alive(hisilicon_at_t* at);

#ifdef __cplusplus
}
#endif

#endif /* CELLLINK_HISILICON_AT_H */
