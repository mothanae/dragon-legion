#ifndef CELLLINK_QMI_H
#define CELLLINK_QMI_H

#include "diag.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── QMI Message Types ───────────────────────────────────────────────── */

#define QMI_CTL_REQUEST          0x00
#define QMI_CTL_RESPONSE         0x02
#define QMI_CTL_INDICATION       0x04

#define QMI_RESULT_SUCCESS       0x00
#define QMI_RESULT_FAILURE       0x01

/* ── NAS (Network Access Service) QMI Commands ───────────────────────── */

#define QMI_NAS_GET_SERVING_SYSTEM        0x0024
#define QMI_NAS_REGISTER_INDICATION       0x0025
#define QMI_NAS_SET_SYSTEM_SELECTION      0x003A
#define QMI_NAS_GET_SYSTEM_SELECTION      0x003B
#define QMI_NAS_SET_PLMN_MODE             0x003C
#define QMI_NAS_GET_SIGNAL_STRENGTH       0x0020
#define QMI_NAS_NETWORK_SCAN              0x003D
#define QMI_NAS_FORCE_NETWORK_SEARCH      0x0073
#define QMI_NAS_SET_TECHNOLOGY_PREF       0x003E
#define QMI_NAS_GET_CELL_LOCATION         0x001F
#define QMI_NAS_SERVICE_DOMAIN_PREF       0x0058

/* ── WDS (Wireless Data Service) Commands ────────────────────────────── */

#define QMI_WDS_START_NETWORK            0x0020
#define QMI_WDS_STOP_NETWORK             0x0021
#define QMI_WDS_GET_PKT_SRVC_STATUS      0x0022

/* ── DMS (Device Management Service) Commands ────────────────────────── */

#define QMI_DMS_GET_DEVICE_SERIAL        0x0025
#define QMI_DMS_GET_DEVICE_MODEL         0x0026
#define QMI_DMS_SET_OPERATING_MODE       0x0029
#define QMI_DMS_GET_OPERATING_MODE       0x002A
#define QMI_DMS_SET_EVENT_REPORT         0x002C

/* ── FTM / Test Mode Commands ────────────────────────────────────────── */

#define QMI_TEST_SET_FTM_MODE            0x0001
#define QMI_TEST_SET_TX_MODE             0x0002
#define QMI_TEST_SET_RX_MODE             0x0003
#define QMI_TEST_SET_FREQUENCY           0x0004
#define QMI_TEST_SET_TX_POWER            0x0005
#define QMI_TEST_CONTINUOUS_TX           0x0006
#define QMI_TEST_STOP_TX                 0x0007
#define QMI_TEST_SET_CHANNEL             0x0008
#define QMI_TEST_GET_TEST_CONFIG         0x0009

/* ── TLV Encoding Helpers ────────────────────────────────────────────── */

#define TLV_TYPE_RESULT          0x02
#define TLV_TYPE_ERROR           0x01

/** Write a TLV (Type-Length-Value) entry into buf. Returns bytes written. */
uint16_t tlv_put(uint8_t* buf, uint8_t type, const uint8_t* value, uint16_t len);

/** Write a TLV with a 1-byte value. */
uint16_t tlv_put_u8(uint8_t* buf, uint8_t type, uint8_t value);

/** Write a TLV with a 2-byte value (LE). */
uint16_t tlv_put_u16(uint8_t* buf, uint8_t type, uint16_t value);

/** Write a TLV with a 4-byte value (LE). */
uint16_t tlv_put_u32(uint8_t* buf, uint8_t type, uint32_t value);

/* ── High-Level QMI API ──────────────────────────────────────────────── */

/** Send a QMI request and wait for response. Returns response data len or -1. */
int qmi_request(diag_handle_t* h, uint8_t subsystem, uint16_t command,
                const uint8_t* req, uint16_t req_len,
                uint8_t* rsp, uint16_t rsp_len, int timeout_ms);

/** Check if the response TLV indicates success. */
bool qmi_response_ok(const uint8_t* data, uint16_t len);

/** Send a NAS network scan request. Returns number of networks found. */
int qmi_nas_network_scan(diag_handle_t* h, char* results, uint16_t max_len);

/** Register on a network by MCC/MNC. Returns 0 on success. */
int qmi_nas_register_network(diag_handle_t* h, uint16_t mcc, uint16_t mnc);

/** Set technology preference to GSM only. */
int qmi_nas_set_gsm_only(diag_handle_t* h);

/** Get current signal strength in dBm. */
int qmi_nas_get_signal_strength(diag_handle_t* h, int16_t* rssi_out);

/** Put modem into online mode. */
int qmi_dms_set_online(diag_handle_t* h);

/** Put modem into low-power/offline mode. */
int qmi_dms_set_offline(diag_handle_t* h);

/** Set continuous Tx mode for BTS operation. Channel is ARFCN. */
int qmi_test_set_continuous_tx(diag_handle_t* h, uint16_t arfcn, uint8_t power_level);

/** Stop continuous Tx. */
int qmi_test_stop_tx(diag_handle_t* h);

/** Set the operating frequency via NV items. */
int qmi_test_set_frequency(diag_handle_t* h, uint16_t arfcn, uint8_t band);

#ifdef __cplusplus
}
#endif

#endif /* CELLLINK_QMI_H */
