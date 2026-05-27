#ifndef CELLLINK_DIAG_H
#define CELLLINK_DIAG_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── DIAG Protocol Constants ─────────────────────────────────────────── */

#define DIAG_START_BYTE       0x7E
#define DIAG_END_BYTE         0x7E
#define DIAG_ESCAPE_BYTE      0x7D
#define DIAG_ESCAPE_MASK      0x20

#define DIAG_MAX_PAYLOAD      2048
#define DIAG_MAX_FRAME        (DIAG_MAX_PAYLOAD + 8)

/* Command codes */
#define DIAG_CMD_VERSION_F        0x00
#define DIAG_CMD_EXT_MESSAGE_F    0x7B
#define DIAG_CMD_EXT_BUILD_ID_F   0x7C
#define DIAG_CMD_LOG_CONFIG_F     0x73
#define DIAG_CMD_EVENT_REPORT_F   0x60
#define DIAG_CMD_GET_EVENT_MASK   0x81
#define DIAG_CMD_SET_EVENT_MASK   0x82
#define DIAG_CMD_STATUS_SNAPSHOT  0x13
#define DIAG_CMD_NV_READ_F        0x26
#define DIAG_CMD_NV_WRITE_F       0x27
#define DIAG_CMD_EXT_LOOPBACK     0x6C
#define DIAG_CMD_EXT_MEM_PEEK_F   0x3B
#define DIAG_CMD_EXT_MEM_POKE_F   0x3C
#define DIAG_CMD_FTM_MODE          0x4B

/* QMI subsystem IDs inside DIAG_EXT_MESSAGE_F */
#define QMI_SUBSYS_CTL      0x00
#define QMI_SUBSYS_WDS      0x01
#define QMI_SUBSYS_DMS      0x02
#define QMI_SUBSYS_NAS      0x03
#define QMI_SUBSYS_WMS      0x05
#define QMI_SUBSYS_PDS      0x06
#define QMI_SUBSYS_VS       0x09
#define QMI_SUBSYS_UIM      0x0B
#define QMI_SUBSYS_CAT      0x0C
#define QMI_SUBSYS_RMS      0x0D
#define QMI_SUBSYS_OMA      0x0E
#define QMI_SUBSYS_TEST     0xFF

/* ── DIAG Frame Structure ────────────────────────────────────────────── */

typedef struct {
    uint8_t  cmd;
    uint16_t len;
    uint8_t  payload[DIAG_MAX_PAYLOAD];
} diag_frame_t;

typedef struct {
    uint8_t  subsystem;
    uint16_t command;
    uint16_t txn_id;
    uint8_t  data[DIAG_MAX_PAYLOAD - 5];
    uint16_t data_len;
} qmi_message_t;

/* ── DIAG Port Handle ────────────────────────────────────────────────── */

typedef struct diag_handle diag_handle_t;

/* ── API ──────────────────────────────────────────────────────────────── */

/** Open the DIAG diagnostic serial port. Returns NULL on failure. */
diag_handle_t* diag_open(const char* device_path);

/** Close and free the DIAG handle. */
void diag_close(diag_handle_t* h);

/** Send a DIAG command frame. Returns bytes written or -1 on error. */
int diag_send(diag_handle_t* h, uint8_t cmd, const uint8_t* data, uint16_t len);

/** Receive a DIAG response frame (blocking with timeout_ms). Returns payload len or -1. */
int diag_recv(diag_handle_t* h, uint8_t* cmd_out, uint8_t* buf, uint16_t buf_len, int timeout_ms);

/** Combined send-and-receive. Returns response payload len or -1. */
int diag_transact(diag_handle_t* h, uint8_t cmd, const uint8_t* req, uint16_t req_len,
                  uint8_t* rsp, uint16_t rsp_len, int timeout_ms);

/** Send a QMI message over DIAG. Returns bytes written or -1. */
int diag_send_qmi(diag_handle_t* h, uint8_t subsystem, uint16_t command,
                  const uint8_t* data, uint16_t len);

/** Receive a QMI message over DIAG. Returns payload len or -1. */
int diag_recv_qmi(diag_handle_t* h, uint8_t* subsystem_out, uint16_t* command_out,
                  uint8_t* buf, uint16_t buf_len, int timeout_ms);

/** Read an NV item by its ID. Returns length or -1. */
int diag_nv_read(diag_handle_t* h, uint16_t nv_item_id, uint8_t* buf, uint16_t buf_len);

/** Write an NV item by its ID. Returns 0 on success, -1 on failure. */
int diag_nv_write(diag_handle_t* h, uint16_t nv_item_id, const uint8_t* data, uint16_t len);

/** Write to modem memory at the given address. For live memory patching. */
int diag_mem_write(diag_handle_t* h, uint32_t address, const uint8_t* data, uint16_t len);

/** Read from modem memory at the given address. */
int diag_mem_read(diag_handle_t* h, uint32_t address, uint8_t* buf, uint16_t len);

/** Send a raw AT command to the modem and get response. */
int diag_at_command(diag_handle_t* h, const char* cmd, char* response, uint16_t max_len);

/** Set the modem into FTM (Factory Test Mode). */
int diag_enter_ftm(diag_handle_t* h);

/** Check if the DIAG port is open and responsive. */
bool diag_is_ready(diag_handle_t* h);

/** Write raw bytes directly to the DIAG port (bypasses DIAG framing).
 *  Used for AT+CMGS PDU flow and other raw protocols. */
int diag_raw_write(diag_handle_t* h, const uint8_t* data, uint16_t len);

/** Read raw bytes from the DIAG port with timeout. */
int diag_raw_read(diag_handle_t* h, uint8_t* buf, uint16_t buf_len, int timeout_ms);

/** Default DIAG device paths to try */
extern const char* DIAG_DEVICE_PATHS[];

#ifdef __cplusplus
}
#endif

#endif /* CELLLINK_DIAG_H */
