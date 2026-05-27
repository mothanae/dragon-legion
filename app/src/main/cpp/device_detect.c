#include "device_detect.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/system_properties.h>
#include <android/log.h>

#define LOG_TAG "CellLink-DETECT"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

/* ── Chipset Detection ───────────────────────────────────────────────── */

static chipset_type_t detect_chipset(void) {
    char platform[PROP_VALUE_MAX] = {0};
    char hardware[PROP_VALUE_MAX] = {0};
    char chipname[PROP_VALUE_MAX] = {0};

    __system_property_get("ro.board.platform", platform);
    __system_property_get("ro.hardware", hardware);
    __system_property_get("ro.chipname", chipname);

    /* Qualcomm: msmXXXX, sdmXXX, smXXXX */
    if (strstr(platform, "msm") || strstr(platform, "sdm") ||
        strstr(platform, "sm")  || strstr(platform, "qcom") ||
        strstr(hardware, "qcom")) {
        return CHIPSET_QUALCOMM_SNAPDRAGON;
    }

    /* HiSilicon Kirin */
    if (strstr(platform, "kirin") || strstr(hardware, "kirin") ||
        strstr(chipname, "kirin")) {
        return CHIPSET_HISILICON_KIRIN;
    }

    /* MediaTek: mtXXXX */
    if (strstr(platform, "mt") || strstr(hardware, "mt") ||
        strstr(platform, "mediatek")) {
        return CHIPSET_MEDIATEK_HELIO;
    }

    /* Samsung Exynos: universalXXXX, exynosXXXX */
    if (strstr(platform, "universal") || strstr(platform, "exynos") ||
        strstr(hardware, "exynos")) {
        return CHIPSET_SAMSUNG_EXYNOS;
    }

    /* Google Tensor: gsXXX */
    if (strstr(platform, "gs1") || strstr(platform, "gs2")) {
        return CHIPSET_GOOGLE_TENSOR;
    }

    /* Unisoc / Spreadtrum: sprd, scXXXX, umsXXX */
    if (strstr(platform, "sprd") || strstr(platform, "sc") ||
        strstr(platform, "ums")) {
        return CHIPSET_SPREADTRUM;
    }

    return CHIPSET_GENERIC_ARM;
}

static modem_type_t detect_modem(chipset_type_t chipset) {
    switch (chipset) {
        case CHIPSET_QUALCOMM_SNAPDRAGON:
            return MODEM_QUALCOMM_X_SERIES;
        case CHIPSET_HISILICON_KIRIN:
            return MODEM_HISILICON_BALONG;
        case CHIPSET_MEDIATEK_HELIO:
            return MODEM_MEDIATEK_HELIO_M;
        case CHIPSET_SAMSUNG_EXYNOS:
            return MODEM_SAMSUNG_SHANNON;
        default:
            return MODEM_GENERIC_AT;
    }
}

/* ── Port Detection ──────────────────────────────────────────────────── */

static bool check_port(const char* path) {
    if (access(path, F_OK) == 0) return true;
    return false;
}

static bool check_port_readable(const char* path) {
    int fd = open(path, O_RDONLY | O_NONBLOCK);
    if (fd >= 0) { close(fd); return true; }
    return false;
}

static void scan_modem_ports(device_info_t* info) {
    const char* qualcomm_ports[] = {
        "/dev/diag", "/dev/ttyUSB0", "/dev/ttyUSB1", "/dev/ttyUSB2",
        "/dev/smd0", "/dev/smd7", "/dev/smd11", NULL
    };

    const char* hisilicon_ports[] = {
        "/dev/ttyAMA0", "/dev/ttyAMA1", "/dev/ttyAMA2",
        "/dev/ttyACM0", "/dev/ttyACM1", NULL
    };

    const char* generic_ports[] = {
        "/dev/ttyACM0", "/dev/ttyACM1", "/dev/ttyACM2",
        "/dev/ttyUSB0", "/dev/ttyUSB1",
        "/dev/ttyHS0", "/dev/ttyHS1",
        NULL
    };

    const char** port_lists[3] = {qualcomm_ports, hisilicon_ports, generic_ports};
    int idx = (info->chipset == CHIPSET_QUALCOMM_SNAPDRAGON) ? 0 :
              (info->chipset == CHIPSET_HISILICON_KIRIN) ? 1 : 2;

    /* Scan all lists, preferring the chipset-specific one */
    for (int list = 0; list < 3; list++) {
        int actual = (idx + list) % 3;
        for (int i = 0; port_lists[actual][i] != NULL; i++) {
            const char* path = port_lists[actual][i];
            if (check_port(path)) {
                if (info->at_port_count == 0) {
                    strncpy(info->at_primary, path, sizeof(info->at_primary) - 1);
                } else if (info->at_port_count == 1) {
                    strncpy(info->at_secondary, path, sizeof(info->at_secondary) - 1);
                }
                info->at_port_count++;
            }

            /* Check for DIAG specifically */
            if (strstr(path, "diag") && check_port(path)) {
                strncpy(info->diag_path, path, sizeof(info->diag_path) - 1);
                info->has_diag = true;
            }

            /* Check for QMI */
            if (strstr(path, "smd7") || strstr(path, "qmux")) {
                strncpy(info->qmi_path, path, sizeof(info->qmi_path) - 1);
                info->has_qmi = true;
            }
        }
    }

    /* Additional chipset-specific checks */
    if (info->chipset == CHIPSET_HISILICON_KIRIN) {
        /* HiSilicon: ttyAMA0 is the main modem AT port */
        if (info->at_port_count > 0) {
            info->has_at_commands = true;
        }
        /* Check engineering mode via sysfs */
        info->has_eng_mode = check_port("/sys/kernel/debug/modem");
    }

    if (info->chipset == CHIPSET_QUALCOMM_SNAPDRAGON) {
        info->has_at_commands = (info->at_port_count > 0);
        info->has_ftm = check_port("/dev/diag");
    }

    /* Generic: any AT port found */
    if (info->at_port_count > 0) {
        info->has_at_commands = true;
    }
}

/* ── Public API ──────────────────────────────────────────────────────── */

device_info_t* device_detect(void) {
    device_info_t* info = (device_info_t*)calloc(1, sizeof(device_info_t));
    if (!info) return NULL;

    /* Detect chipset and modem */
    info->chipset = detect_chipset();
    info->modem = detect_modem(info->chipset);
    snprintf(info->chipset_name, sizeof(info->chipset_name), "%s", chipset_name(info->chipset));
    snprintf(info->modem_name, sizeof(info->modem_name), "%s", modem_name_str(info->modem));

    /* Android version */
    char sdk[PROP_VALUE_MAX] = {0};
    __system_property_get("ro.build.version.sdk", sdk);
    info->android_sdk = (uint32_t)atoi(sdk);
    __system_property_get("ro.build.version.release", info->android_release);

    /* Baseband version */
    __system_property_get("gsm.version.baseband", info->baseband_version);

    /* Root check */
    info->is_rooted = device_check_root();

    /* SELinux */
    FILE* f = fopen("/sys/fs/selinux/enforce", "r");
    if (f) {
        char enf = '1';
        fread(&enf, 1, 1, f);
        fclose(f);
        info->selinux_enforcing = (enf == '1');
    } else {
        info->selinux_enforcing = true; /* Assume enforcing */
    }

    /* Bootloader unlock check */
    char locked[PROP_VALUE_MAX] = {0};
    __system_property_get("ro.boot.flash.locked", locked);
    info->bootloader_unlocked = (atoi(locked) == 0);

    /* Scan for modem ports */
    scan_modem_ports(info);

    /* Determine preferred backend */
    info->preferred_backend = device_get_backend(info);

    LOGI("Device: %s / %s (Android %s SDK %u)",
         info->chipset_name, info->modem_name,
         info->android_release, info->android_sdk);
    LOGI("Modem backend: %d, Root: %s, SELinux: %s, Bootloader: %s",
         info->preferred_backend,
         info->is_rooted ? "YES" : "NO",
         info->selinux_enforcing ? "Enforcing" : "Permissive",
         info->bootloader_unlocked ? "Unlocked" : "Locked");

    return info;
}

void device_free(device_info_t* info) { free(info); }

backend_type_t device_get_backend(device_info_t* info) {
    if (!info) return BACKEND_GENERIC_AT;

    /* Qualcomm: prefer DIAG+QMI if DIAG port exists and we have root */
    if (info->chipset == CHIPSET_QUALCOMM_SNAPDRAGON && info->has_diag && info->is_rooted) {
        return BACKEND_DIAG_QMI;
    }

    /* HiSilicon Kirin: use AT commands on ttyAMA0 */
    if (info->chipset == CHIPSET_HISILICON_KIRIN && info->has_at_commands) {
        return BACKEND_HISILICON_AT;
    }

    /* MediaTek: use MediaTek-extended AT commands */
    if (info->chipset == CHIPSET_MEDIATEK_HELIO && info->has_at_commands) {
        return BACKEND_MEDIATEK_AT;
    }

    /* Any device with AT port: use generic AT */
    if (info->has_at_commands) {
        return BACKEND_GENERIC_AT;
    }

    /* Fallback: Android RIL proxy (non-root, limited) */
    return BACKEND_RIL_PROXY;
}

bool device_check_root(void) {
    /* Method 1: check if su binary exists and works */
    FILE* f = popen("su -c 'id -u' 2>/dev/null", "r");
    if (f) {
        char buf[16] = {0};
        if (fgets(buf, sizeof(buf), f) && strstr(buf, "0")) {
            pclose(f);
            return true;
        }
        pclose(f);
    }

    /* Method 2: check common su paths */
    const char* su_paths[] = {
        "/system/xbin/su", "/system/bin/su", "/sbin/su",
        "/su/bin/su", "/data/local/su"
    };
    for (int i = 0; i < 5; i++) {
        if (access(su_paths[i], X_OK) == 0) return true;
    }

    /* Method 3: check if UID is 0 directly */
    if (getuid() == 0) return true;

    return false;
}

bool device_attempt_root(device_info_t* info) {
    if (!info || info->is_rooted) return info->is_rooted;

    LOGI("Attempting temporary root for %s...", info->chipset_name);

    /* Try 'adb root' first (only works on eng/userdebug builds) */
    FILE* f = popen("adb root 2>/dev/null", "r");
    if (f) {
        char buf[128];
        while (fgets(buf, sizeof(buf), f)) {
            if (strstr(buf, "restarting") || strstr(buf, "already running")) {
                pclose(f);
                sleep(2);
                info->is_rooted = device_check_root();
                if (info->is_rooted) return true;
            }
        }
        pclose(f);
    }

    /* CVE-2019-2215: Android binder UAF (kernel 4.4-4.14, Android 8-10)
     * Huawei Mate 10 Pro (Android 10, patch 2020-04) — likely patched */
    /* CVE-2020-0041: MTK/Kirin bootrom — requires USB download mode, not runtime */

    /* For HiSilicon: try to access modem port via media group
     * The ttyAMA0 port is owned by media:media (crw-rw----)
     * We can try to use run-as or other tricks */
    if (info->chipset == CHIPSET_HISILICON_KIRIN) {
        /* Check if we're in media group */
        gid_t groups[32];
        int ngroups = getgroups(32, groups);
        for (int i = 0; i < ngroups; i++) {
            if (groups[i] == 1005) { /* media gid on Huawei */
                LOGI("Already in media group — modem port accessible without root");
                return true; /* Not really root, but we can access modem */
            }
        }
    }

    LOGE("Automatic root failed — manual root required");
    return false;
}

int device_list_modem_ports(char ports[][256], int max_ports) {
    const char* all_ports[] = {
        "/dev/diag", "/dev/ttyUSB0", "/dev/ttyUSB1", "/dev/ttyUSB2",
        "/dev/ttyAMA0", "/dev/ttyAMA1", "/dev/ttyAMA2",
        "/dev/ttyACM0", "/dev/ttyACM1", "/dev/ttyACM2",
        "/dev/smd0", "/dev/smd7", "/dev/smd11",
        "/dev/ttyHS0", "/dev/ttyHS1", NULL
    };

    int count = 0;
    for (int i = 0; all_ports[i] && count < max_ports; i++) {
        if (check_port(all_ports[i])) {
            strncpy(ports[count], all_ports[i], 255);
            count++;
        }
    }
    return count;
}

const char* chipset_name(chipset_type_t t) {
    switch (t) {
        case CHIPSET_QUALCOMM_SNAPDRAGON: return "Qualcomm Snapdragon";
        case CHIPSET_HISILICON_KIRIN:     return "HiSilicon Kirin";
        case CHIPSET_MEDIATEK_HELIO:      return "MediaTek Helio/Dimensity";
        case CHIPSET_SAMSUNG_EXYNOS:      return "Samsung Exynos";
        case CHIPSET_GOOGLE_TENSOR:       return "Google Tensor";
        case CHIPSET_SPREADTRUM:          return "Unisoc Spreadtrum";
        default:                          return "Unknown SoC";
    }
}

const char* modem_name_str(modem_type_t t) {
    switch (t) {
        case MODEM_QUALCOMM_X_SERIES: return "Qualcomm Snapdragon X";
        case MODEM_HISILICON_BALONG:  return "HiSilicon Balong";
        case MODEM_MEDIATEK_HELIO_M:  return "MediaTek Helio M";
        case MODEM_SAMSUNG_SHANNON:   return "Samsung Shannon";
        default:                      return "Generic AT Modem";
    }
}

void device_print_info(device_info_t* info) {
    if (!info) return;
    LOGI("=== Device Detection ===");
    LOGI("  Chipset: %s", info->chipset_name);
    LOGI("  Modem: %s", info->modem_name);
    LOGI("  Baseband: %s", info->baseband_version);
    LOGI("  Android: %s (SDK %u)", info->android_release, info->android_sdk);
    LOGI("  Root: %s", info->is_rooted ? "YES" : "NO");
    LOGI("  SELinux: %s", info->selinux_enforcing ? "Enforcing" : "Permissive");
    LOGI("  Bootloader: %s", info->bootloader_unlocked ? "Unlocked" : "Locked");
    LOGI("  DIAG port: %s", info->has_diag ? info->diag_path : "NONE");
    LOGI("  AT port: %s", info->has_at_commands ? info->at_primary : "NONE");
    LOGI("  Backend: %d", info->preferred_backend);
    LOGI("========================");
}
