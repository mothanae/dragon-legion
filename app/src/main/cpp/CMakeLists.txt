cmake_minimum_required(VERSION 3.22.1)
project("celllink_native")

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

# Native library sources
add_library(celllink_native SHARED
    # DIAG layer
    diag.c
    crc16.c

    # QMI layer
    qmi.c

    # GSM protocol layer
    gsm_bts.c
    gsm_ue.c
    gsm_common.c

    # Device detection + multi-modem support
    device_detect.c
    hisilicon_at.c

    # Messaging
    sms.c

    # Timing
    gps_timing.c

    # Hexagon DSP access
    hexagon_rpc.c

    # Secure boot / firmware patching
    secure_boot.c

    # RF tools
    rf_spectrum.c
    band_scanner.c
    pa_protect.c

    # SIM + Recovery
    virtual_sim.c
    modem_recovery.c

    # Audio / Call tools
    call_recorder.c
    dtmf.c

    # Monitoring
    gsm_sniffer.c
    modem_logger.c

    # JNI bridge
    jni_bridge.c
)

target_include_directories(celllink_native PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# Link system libraries
target_link_libraries(celllink_native
    android
    log
    EGL
    GLESv2
    OpenSLES
    m
)
