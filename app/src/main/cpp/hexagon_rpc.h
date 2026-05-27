#ifndef CELLLINK_HEXAGON_RPC_H
#define CELLLINK_HEXAGON_RPC_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Hexagon DSP RPC Constants ───────────────────────────────────────── */

/* FastRPC on Qualcomm: communicates with the Hexagon DSP (aDSP/cDSP/mDSP)
 * via the dspserver process. The kernel driver is /dev/adsprpc-smd or
 * /dev/fastrpc-adsprpc-smd. */

#define HEXAGON_RPC_DEVICE          "/dev/adsprpc-smd"
#define HEXAGON_RPC_DEVICE_ALT      "/dev/fastrpc-adsprpc-smd"
#define HEXAGON_RPC_MAX_MSG         4096
#define HEXAGON_RPC_TIMEOUT_MS      5000

/* Known Hexagon DSP PIDs for modem functions */
#define HEXAGON_PID_MODEM_VOICE     0x00000004  /* Voice encoder/decoder */
#define HEXAGON_PID_MODEM_AUDIO     0x00000005  /* Audio path */
#define HEXAGON_PID_MODEM_L1        0x00000006  /* Layer 1 (physical) */
#define HEXAGON_PID_MODEM_RF        0x00000007  /* RF frontend control */
#define HEXAGON_PID_USER_DEFINED    0xFFFFFFFF  /* User-defined service */

/* CVEs for Hexagon DSP elevation */
#define CVE_2020_3696_HEXAGON_OVERFLOW    "CVE-2020-3696"
#define CVE_2020_0022_HEXAGON_DSP         "CVE-2020-0022"
#define CVE_2019_10581_HEXAGON_USE_AFTER_FREE "CVE-2019-10581"
#define CVE_2018_11982_HEXAGON_INFINITE_LOOP  "CVE-2018-11982"
#define CVE_2017_15846_HEXAGON_OOB_ACCESS "CVE-2017-15846"

/* ── Hexagon RPC Message Structures ──────────────────────────────────── */

typedef struct __attribute__((packed)) {
    uint32_t pid;       /* Program/domain ID */
    uint32_t method;    /* RPC method number */
    uint32_t flags;     /* Control flags */
    uint32_t in_len;    /* Input buffer length */
    uint32_t out_len;   /* Output buffer length */
} hexagon_rpc_header_t;

typedef struct __attribute__((packed)) {
    hexagon_rpc_header_t hdr;
    uint8_t  data[HEXAGON_RPC_MAX_MSG - sizeof(hexagon_rpc_header_t)];
} hexagon_rpc_msg_t;

/* ── Hexagon RPC Handle ──────────────────────────────────────────────── */

typedef struct hexagon_rpc_handle hexagon_rpc_handle_t;

/* ── API ──────────────────────────────────────────────────────────────── */

/** Open a FastRPC channel to the Hexagon DSP. Returns NULL on failure. */
hexagon_rpc_handle_t* hexagon_rpc_open(const char* device_path);

/** Close the RPC channel. */
void hexagon_rpc_close(hexagon_rpc_handle_t* h);

/**
 * Send an RPC message to the Hexagon DSP and get response.
 * @param pid    Program ID (which DSP subsystem to target)
 * @param method Method number within that subsystem
 * @param req    Request data
 * @param req_len Request length
 * @param rsp    Response buffer
 * @param rsp_len Max response length
 * @return Bytes received or -1 on error.
 */
int hexagon_rpc_call(hexagon_rpc_handle_t* h, uint32_t pid, uint32_t method,
                     const uint8_t* req, uint32_t req_len,
                     uint8_t* rsp, uint32_t rsp_len);

/**
 * Enable direct microphone-to-modem-DSP audio path.
 * Routes mic input to the voice encoder DSP, bypassing Android audio stack.
 * Returns 0 on success.
 */
int hexagon_audio_enable_mic_path(hexagon_rpc_handle_t* h);

/**
 * Enable direct modem-DSP-to-speaker audio path.
 * Routes decoded voice from DSP to speaker, bypassing Android audio stack.
 * Returns 0 on success.
 */
int hexagon_audio_enable_spkr_path(hexagon_rpc_handle_t* h);

/**
 * Configure the voice encoder parameters (codec, bitrate).
 */
int hexagon_voice_set_codec(hexagon_rpc_handle_t* h, uint8_t codec_type, uint16_t bitrate);

/**
 * Query DSP version and capabilities.
 */

/**
 * Send a raw modem L1 frame through the DSP for transmission.
 * This is the alternative path when DIAG_CMD_EXT_LOOPBACK doesn't trigger RF Tx.
 */
int hexagon_rf_send_frame(hexagon_rpc_handle_t* h, const uint8_t* frame, uint16_t len);

/**
 * Configure L1 channel parameters (ARFCN, timeslot, training sequence).
 */
int hexagon_l1_configure(hexagon_rpc_handle_t* h, uint16_t arfcn, uint8_t timeslot,
                         uint8_t training_seq, uint8_t tx_power);

/**
 * Start the L1 transmitter on configured channel.
 */
int hexagon_l1_start_tx(hexagon_rpc_handle_t* h);

/**
 * Stop the L1 transmitter.
 */
int hexagon_l1_stop_tx(hexagon_rpc_handle_t* h);

#ifdef __cplusplus
}
#endif

#endif /* CELLLINK_HEXAGON_RPC_H */
