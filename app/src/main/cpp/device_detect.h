#ifndef CELLLINK_DEVICE_DETECT_H
#define CELLLINK_DEVICE_DETECT_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Chipset / Modem Types ───────────────────────────────────────────── */

typedef enum {
    CHIPSET_UNKNOWN,
    CHIPSET_QUALCOMM_SNAPDRAGON,    /* MSM/SDM/SMxxxx */
    CHIPSET_HISILICON_KIRIN,        /* Kirin 970/980/990/9000 etc */
    CHIPSET_MEDIATEK_HELIO,         /* MT67xx/MT68xx/Dimensity */
    CHIPSET_SAMSUNG_EXYNOS,         /* Exynos */
    CHIPSET_GOOGLE_TENSOR,          /* Tensor G1/G2 */
    CHIPSET_SPREADTRUM,             /* Unisoc SCxxxx */
    CHIPSET_GENERIC_ARM             /* Unknown ARM SoC */
} chipset_type_t;

typedef enum {
    MODEM_INTERNAL_UNKNOWN,
    MODEM_QUALCOMM_X_SERIES,        /* X5/X7/X12/X16/X20/X50 etc */
    MODEM_HISILICON_BALONG,         /* Balong 750/765/5000 */
    MODEM_MEDIATEK_HELIO_M,         /* MTK integrated modem */
    MODEM_SAMSUNG_SHANNON,          /* Shannon modem */
    MODEM_GENERIC_AT                /* Any AT-command modem */
} modem_type_t;

typedef struct {
    chipset_type_t chipset;
    modem_type_t   modem;
    char           chipset_name[64];
    char           modem_name[64];
    char           baseband_version[128];
    uint32_t       android_sdk;
    char           android_release[8];

    /* Detected modem device paths */
    char           diag_path[256];      /* Qualcomm DIAG (/dev/diag) */
    char           at_primary[256];     /* Primary AT port */
    char           at_secondary[256];   /* Secondary AT port */
    char           qmi_path[256];       /* QMI device */
    int            at_port_count;

    /* Capability flags */
    bool           has_diag;
    bool           has_qmi;
    bool           has_at_commands;
    bool           has_ftm;
    bool           has_eng_mode;        /* Engineering mode available */

    /* Root / security */
    bool           is_rooted;
    bool           selinux_enforcing;
    bool           bootloader_unlocked;

    /* Preferred backend */
    int            preferred_backend;   /* 0=DIAG/QMI, 1=AT, 2=RIL */
} device_info_t;

/* ── Modem Backend Interface ──────────────────────────────────────────── */

typedef enum {
    BACKEND_DIAG_QMI,     /* Qualcomm DIAG + QMI */
    BACKEND_HISILICON_AT, /* HiSilicon AT commands */
    BACKEND_MEDIATEK_AT,  /* MediaTek AT commands */
    BACKEND_GENERIC_AT,   /* Generic Hayes AT */
    BACKEND_RIL_PROXY      /* Android RIL proxy (non-root) */
} backend_type_t;

/* ── API ──────────────────────────────────────────────────────────────── */

/** Detect the current device's chipset, modem, and available interfaces. */
device_info_t* device_detect(void);

/** Free device info. */
void device_free(device_info_t* info);

/** Get the recommended backend for this device. */
backend_type_t device_get_backend(device_info_t* info);

/** Print device info to log. */
void device_print_info(device_info_t* info);

/** Get a human-readable chipset name. */
const char* chipset_name(chipset_type_t t);

/** Get a human-readable modem name. */
const char* modem_name_str(modem_type_t t);

/** Try to gain temporary root access via known exploits for this device. */
bool device_attempt_root(device_info_t* info);

/** Check if root is available. */
bool device_check_root(void);

/** List all accessible modem serial ports. Returns count. */
int device_list_modem_ports(char ports[][256], int max_ports);

#ifdef __cplusplus
}
#endif

#endif /* CELLLINK_DEVICE_DETECT_H */
