#include <jni.h>
#include <android/log.h>
#include <string.h>
#include <pthread.h>

#include "diag.h"
#include "qmi.h"
#include "gsm_bts.h"
#include "gsm_ue.h"
#include "gsm_common.h"

#define LOG_TAG "CellLink-JNI"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

/* Global references for callback threads */
static JavaVM* g_jvm = NULL;
static jobject g_bts_listener = NULL;
static jobject g_ue_listener = NULL;
static jclass g_bts_listener_class = NULL;
static jclass g_ue_listener_class = NULL;

/* ── DIAG JNI Methods ────────────────────────────────────────────────── */

JNIEXPORT jlong JNICALL
Java_com_celllink_NativeBridge_nativeDiagOpen(JNIEnv* env, jclass cls, jstring devicePath) {
    const char* path = devicePath ? (*env)->GetStringUTFChars(env, devicePath, NULL) : NULL;
    diag_handle_t* h = diag_open(path);
    if (path) (*env)->ReleaseStringUTFChars(env, devicePath, path);
    return (jlong)(intptr_t)h;
}

JNIEXPORT void JNICALL
Java_com_celllink_NativeBridge_nativeDiagClose(JNIEnv* env, jclass cls, jlong handle) {
    diag_close((diag_handle_t*)(intptr_t)handle);
}

JNIEXPORT jboolean JNICALL
Java_com_celllink_NativeBridge_nativeDiagIsReady(JNIEnv* env, jclass cls, jlong handle) {
    return diag_is_ready((diag_handle_t*)(intptr_t)handle) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jstring JNICALL
Java_com_celllink_NativeBridge_nativeDiagAtCommand(JNIEnv* env, jclass cls, jlong handle, jstring cmd) {
    const char* at_cmd = (*env)->GetStringUTFChars(env, cmd, NULL);
    char response[1024];
    int n = diag_at_command((diag_handle_t*)(intptr_t)handle, at_cmd, response, sizeof(response));
    (*env)->ReleaseStringUTFChars(env, cmd, at_cmd);

    if (n < 0) return NULL;
    return (*env)->NewStringUTF(env, response);
}

JNIEXPORT jboolean JNICALL
Java_com_celllink_NativeBridge_nativeDiagEnterFtm(JNIEnv* env, jclass cls, jlong handle) {
    return diag_enter_ftm((diag_handle_t*)(intptr_t)handle) == 0 ? JNI_TRUE : JNI_FALSE;
}

/* ── BTS JNI Methods ─────────────────────────────────────────────────── */

JNIEXPORT jlong JNICALL
Java_com_celllink_NativeBridge_nativeBtsInit(JNIEnv* env, jclass cls,
                                              jlong diagHandle,
                                              jint arfcn,
                                              jint band,
                                              jint txPower) {
    bts_context_t* ctx = bts_init((diag_handle_t*)(intptr_t)diagHandle,
                                  (uint16_t)arfcn, (uint8_t)band, (uint8_t)txPower);
    return (jlong)(intptr_t)ctx;
}

JNIEXPORT jboolean JNICALL
Java_com_celllink_NativeBridge_nativeBtsStart(JNIEnv* env, jclass cls, jlong handle) {
    return bts_start((bts_context_t*)(intptr_t)handle) == 0 ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_celllink_NativeBridge_nativeBtsStop(JNIEnv* env, jclass cls, jlong handle) {
    return bts_stop((bts_context_t*)(intptr_t)handle) == 0 ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT void JNICALL
Java_com_celllink_NativeBridge_nativeBtsFree(JNIEnv* env, jclass cls, jlong handle) {
    bts_free((bts_context_t*)(intptr_t)handle);
}

JNIEXPORT jint JNICALL
Java_com_celllink_NativeBridge_nativeBtsGetState(JNIEnv* env, jclass cls, jlong handle) {
    return (jint)bts_get_state((bts_context_t*)(intptr_t)handle);
}

JNIEXPORT jfloat JNICALL
Java_com_celllink_NativeBridge_nativeBtsGetDlFrequency(JNIEnv* env, jclass cls, jlong handle) {
    return (jfloat)bts_get_dl_frequency((bts_context_t*)(intptr_t)handle);
}

JNIEXPORT jboolean JNICALL
Java_com_celllink_NativeBridge_nativeBtsAcceptCall(JNIEnv* env, jclass cls, jlong handle) {
    return bts_accept_call((bts_context_t*)(intptr_t)handle) == 0 ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_celllink_NativeBridge_nativeBtsEndCall(JNIEnv* env, jclass cls, jlong handle) {
    return bts_end_call((bts_context_t*)(intptr_t)handle) == 0 ? JNI_TRUE : JNI_FALSE;
}

/* ── UE JNI Methods ──────────────────────────────────────────────────── */

JNIEXPORT jlong JNICALL
Java_com_celllink_NativeBridge_nativeUeInit(JNIEnv* env, jclass cls, jlong diagHandle) {
    ue_context_t* ctx = ue_init((diag_handle_t*)(intptr_t)diagHandle);
    return (jlong)(intptr_t)ctx;
}

JNIEXPORT jint JNICALL
Java_com_celllink_NativeBridge_nativeUeScanNetworks(JNIEnv* env, jclass cls, jlong handle) {
    return (jint)ue_scan_networks((ue_context_t*)(intptr_t)handle);
}

JNIEXPORT jboolean JNICALL
Java_com_celllink_NativeBridge_nativeUeRegisterNetwork(JNIEnv* env, jclass cls,
                                                        jlong handle,
                                                        jint mcc,
                                                        jint mnc) {
    return ue_register_network((ue_context_t*)(intptr_t)handle,
                               (uint16_t)mcc, (uint16_t)mnc) == 0 ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_celllink_NativeBridge_nativeUeMakeCall(JNIEnv* env, jclass cls, jlong handle) {
    return ue_make_call((ue_context_t*)(intptr_t)handle) == 0 ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_celllink_NativeBridge_nativeUeEndCall(JNIEnv* env, jclass cls, jlong handle) {
    return ue_end_call((ue_context_t*)(intptr_t)handle) == 0 ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_celllink_NativeBridge_nativeUeAnswerCall(JNIEnv* env, jclass cls, jlong handle) {
    return ue_answer_call((ue_context_t*)(intptr_t)handle) == 0 ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jint JNICALL
Java_com_celllink_NativeBridge_nativeUeGetState(JNIEnv* env, jclass cls, jlong handle) {
    return (jint)ue_get_state((ue_context_t*)(intptr_t)handle);
}

JNIEXPORT jint JNICALL
Java_com_celllink_NativeBridge_nativeUeGetRssi(JNIEnv* env, jclass cls, jlong handle) {
    return (jint)ue_get_rssi((ue_context_t*)(intptr_t)handle);
}

JNIEXPORT jstring JNICALL
Java_com_celllink_NativeBridge_nativeUeGetScanResults(JNIEnv* env, jclass cls, jlong handle) {
    ue_context_t* ctx = (ue_context_t*)(intptr_t)handle;
    if (!ctx || ctx->scan_count == 0) return NULL;
    return (*env)->NewStringUTF(env, ctx->scan_results);
}

JNIEXPORT void JNICALL
Java_com_celllink_NativeBridge_nativeUeFree(JNIEnv* env, jclass cls, jlong handle) {
    ue_free((ue_context_t*)(intptr_t)handle);
}

/* ── GSM Utility JNI Methods ─────────────────────────────────────────── */

JNIEXPORT jfloat JNICALL
Java_com_celllink_NativeBridge_nativeArfcnToDlFreq(JNIEnv* env, jclass cls, jint arfcn, jint band) {
    float ul, dl;
    if (gsm_arfcn_to_freq((uint16_t)arfcn, (gsm_band_t)band, &ul, &dl)) {
        return (jfloat)dl;
    }
    return 0.0f;
}

/* ── SMS JNI Methods ─────────────────────────────────────────────────── */

#include "sms.h"

JNIEXPORT jboolean JNICALL
Java_com_celllink_NativeBridge_nativeSmsSend(JNIEnv* env, jclass cls, jlong diagHandle,
                                              jstring recipient, jstring text) {
    const char* rec = (*env)->GetStringUTFChars(env, recipient, NULL);
    const char* txt = (*env)->GetStringUTFChars(env, text, NULL);
    int ret = sms_send((diag_handle_t*)(intptr_t)diagHandle, rec, txt);
    (*env)->ReleaseStringUTFChars(env, recipient, rec);
    (*env)->ReleaseStringUTFChars(env, text, txt);
    return ret == 0 ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jint JNICALL
Java_com_celllink_NativeBridge_nativeSmsListReceived(JNIEnv* env, jclass cls,
                                                      jlong diagHandle, jobjectArray outArray) {
    sms_message_t msgs[32];
    int count = sms_list_received((diag_handle_t*)(intptr_t)diagHandle, msgs, 32);
    if (count <= 0) return 0;

    jclass smsClass = (*env)->FindClass(env, "com/celllink/SmsMessage");
    if (!smsClass) return 0;

    jmethodID init = (*env)->GetMethodID(env, smsClass, "<init>",
        "(Ljava/lang/String;Ljava/lang/String;JZ)V");

    for (int i = 0; i < count && i < 32; i++) {
        jstring sender = (*env)->NewStringUTF(env, msgs[i].sender);
        jstring text = (*env)->NewStringUTF(env, msgs[i].text);
        jobject obj = (*env)->NewObject(env, smsClass, init,
            sender, text, (jlong)msgs[i].timestamp, (jboolean)msgs[i].is_incoming);
        (*env)->SetObjectArrayElement(env, outArray, i, obj);
        (*env)->DeleteLocalRef(env, sender);
        (*env)->DeleteLocalRef(env, text);
        (*env)->DeleteLocalRef(env, obj);
    }
    (*env)->DeleteLocalRef(env, smsClass);
    return count;
}

/* ── GPS Timing JNI Methods ──────────────────────────────────────────── */

#include "gps_timing.h"

JNIEXPORT jlong JNICALL
Java_com_celllink_NativeBridge_nativeGpsTimingInit(JNIEnv* env, jclass cls) {
    gps_timing_t* gt = gps_timing_init();
    return (jlong)(intptr_t)gt;
}

JNIEXPORT void JNICALL
Java_com_celllink_NativeBridge_nativeGpsTimingFree(JNIEnv* env, jclass cls, jlong handle) {
    gps_timing_free((gps_timing_t*)(intptr_t)handle);
}

JNIEXPORT void JNICALL
Java_com_celllink_NativeBridge_nativeGpsFeedNmea(JNIEnv* env, jclass cls, jlong handle, jstring nmea) {
    const char* s = (*env)->GetStringUTFChars(env, nmea, NULL);
    gps_timing_feed_nmea((gps_timing_t*)(intptr_t)handle, s);
    (*env)->ReleaseStringUTFChars(env, nmea, s);
}

JNIEXPORT jint JNICALL
Java_com_celllink_NativeBridge_nativeGpsGetState(JNIEnv* env, jclass cls, jlong handle) {
    return (jint)gps_timing_get_state((gps_timing_t*)(intptr_t)handle);
}

JNIEXPORT jstring JNICALL
Java_com_celllink_NativeBridge_nativeGpsStatusString(JNIEnv* env, jclass cls, jlong handle) {
    return (*env)->NewStringUTF(env, gps_timing_status_string((gps_timing_t*)(intptr_t)handle));
}

JNIEXPORT jdouble JNICALL
Java_com_celllink_NativeBridge_nativeGpsFreqError(JNIEnv* env, jclass cls, jlong handle) {
    return (jdouble)gps_timing_get_freq_error((gps_timing_t*)(intptr_t)handle);
}

/* ── Hexagon DSP JNI Methods ─────────────────────────────────────────── */

#include "hexagon_rpc.h"

JNIEXPORT jlong JNICALL
Java_com_celllink_NativeBridge_nativeHexagonOpen(JNIEnv* env, jclass cls, jstring devicePath) {
    const char* path = devicePath ? (*env)->GetStringUTFChars(env, devicePath, NULL) : NULL;
    hexagon_rpc_handle_t* h = hexagon_rpc_open(path);
    if (path) (*env)->ReleaseStringUTFChars(env, devicePath, path);
    return (jlong)(intptr_t)h;
}

JNIEXPORT void JNICALL
Java_com_celllink_NativeBridge_nativeHexagonClose(JNIEnv* env, jclass cls, jlong handle) {
    hexagon_rpc_close((hexagon_rpc_handle_t*)(intptr_t)handle);
}

JNIEXPORT jboolean JNICALL
Java_com_celllink_NativeBridge_nativeHexagonEnableAudio(JNIEnv* env, jclass cls, jlong handle) {
    hexagon_rpc_handle_t* h = (hexagon_rpc_handle_t*)(intptr_t)handle;
    int mic = hexagon_audio_enable_mic_path(h);
    int spk = hexagon_audio_enable_spkr_path(h);
    return (mic == 0 && spk == 0) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_celllink_NativeBridge_nativeHexagonL1Configure(JNIEnv* env, jclass cls, jlong handle,
                                                         jint arfcn, jint timeslot,
                                                         jint trainingSeq, jint txPower) {
    return hexagon_l1_configure((hexagon_rpc_handle_t*)(intptr_t)handle,
        (uint16_t)arfcn, (uint8_t)timeslot, (uint8_t)trainingSeq, (uint8_t)txPower) == 0
        ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_celllink_NativeBridge_nativeHexagonL1StartTx(JNIEnv* env, jclass cls, jlong handle) {
    return hexagon_l1_start_tx((hexagon_rpc_handle_t*)(intptr_t)handle) == 0 ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_celllink_NativeBridge_nativeHexagonL1StopTx(JNIEnv* env, jclass cls, jlong handle) {
    return hexagon_l1_stop_tx((hexagon_rpc_handle_t*)(intptr_t)handle) == 0 ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_celllink_NativeBridge_nativeHexagonRfSendFrame(JNIEnv* env, jclass cls, jlong handle,
                                                         jbyteArray frameArray) {
    jbyte* frame = (*env)->GetByteArrayElements(env, frameArray, NULL);
    jsize len = (*env)->GetArrayLength(env, frameArray);
    int ret = hexagon_rf_send_frame((hexagon_rpc_handle_t*)(intptr_t)handle,
                                    (const uint8_t*)frame, (uint16_t)len);
    (*env)->ReleaseByteArrayElements(env, frameArray, frame, JNI_ABORT);
    return ret == 0 ? JNI_TRUE : JNI_FALSE;
}

/* ── Secure Boot JNI Methods ─────────────────────────────────────────── */

#include "secure_boot.h"

JNIEXPORT jint JNICALL
Java_com_celllink_NativeBridge_nativeSecureBootBypass(JNIEnv* env, jclass cls, jlong diagHandle) {
    return (jint)secure_boot_bypass_all((diag_handle_t*)(intptr_t)diagHandle);
}

/* ── RF Spectrum JNI Methods ──────────────────────────────────────────── */

#include "rf_spectrum.h"

JNIEXPORT jlong JNICALL
Java_com_celllink_NativeBridge_nativeSpectrumInit(JNIEnv* env, jclass cls) {
    return (jlong)(intptr_t)spectrum_init();
}

JNIEXPORT void JNICALL
Java_com_celllink_NativeBridge_nativeSpectrumFree(JNIEnv* env, jclass cls, jlong handle) {
    spectrum_free((spectrum_scan_t*)(intptr_t)handle);
}

JNIEXPORT jint JNICALL
Java_com_celllink_NativeBridge_nativeSpectrumSweepAll(JNIEnv* env, jclass cls, jlong diagHandle, jlong scanHandle) {
    return (jint)spectrum_sweep_all_bands((diag_handle_t*)(intptr_t)diagHandle,
                                           (spectrum_scan_t*)(intptr_t)scanHandle);
}

JNIEXPORT jint JNICALL
Java_com_celllink_NativeBridge_nativeSpectrumFindBest(JNIEnv* env, jclass cls, jlong scanHandle, jint band) {
    return (jint)spectrum_find_clearest_channel((spectrum_scan_t*)(intptr_t)scanHandle, (gsm_band_t)band);
}

JNIEXPORT jstring JNICALL
Java_com_celllink_NativeBridge_nativeSpectrumExportCsv(JNIEnv* env, jclass cls, jlong scanHandle) {
    char buf[65536];
    spectrum_scan_t* s = (spectrum_scan_t*)(intptr_t)scanHandle;
    spectrum_export_csv(s, buf, sizeof(buf));
    return (*env)->NewStringUTF(env, buf);
}

/* ── Virtual SIM JNI Methods ──────────────────────────────────────────── */

#include "virtual_sim.h"

JNIEXPORT jlong JNICALL
Java_com_celllink_NativeBridge_nativeVsimCreate(JNIEnv* env, jclass cls,
                                                  jint mcc, jint mnc,
                                                  jstring imsi, jstring msisdn, jstring spn) {
    const char* i = (*env)->GetStringUTFChars(env, imsi, NULL);
    const char* m = (*env)->GetStringUTFChars(env, msisdn, NULL);
    const char* s = (*env)->GetStringUTFChars(env, spn, NULL);
    virtual_sim_t* vsim = vsim_create_custom((uint16_t)mcc, (uint16_t)mnc, i, m, s);
    (*env)->ReleaseStringUTFChars(env, imsi, i);
    (*env)->ReleaseStringUTFChars(env, msisdn, m);
    (*env)->ReleaseStringUTFChars(env, spn, s);
    return (jlong)(intptr_t)vsim;
}

JNIEXPORT void JNICALL
Java_com_celllink_NativeBridge_nativeVsimFree(JNIEnv* env, jclass cls, jlong handle) {
    vsim_free((virtual_sim_t*)(intptr_t)handle);
}

JNIEXPORT jboolean JNICALL
Java_com_celllink_NativeBridge_nativeVsimActivate(JNIEnv* env, jclass cls, jlong simHandle, jlong diagHandle) {
    return vsim_activate((virtual_sim_t*)(intptr_t)simHandle, (diag_handle_t*)(intptr_t)diagHandle,
                         SIM_METHOD_QMI_UIM) == 0 ? JNI_TRUE : JNI_FALSE;
}

/* ── Modem Recovery JNI Methods ───────────────────────────────────────── */

#include "modem_recovery.h"

JNIEXPORT jlong JNICALL
Java_com_celllink_NativeBridge_nativeModemRecoveryInit(JNIEnv* env, jclass cls, jlong diagHandle) {
    return (jlong)(intptr_t)modem_recovery_init((diag_handle_t*)(intptr_t)diagHandle);
}

JNIEXPORT void JNICALL
Java_com_celllink_NativeBridge_nativeModemRecoveryFree(JNIEnv* env, jclass cls, jlong handle) {
    modem_recovery_free((modem_recovery_t*)(intptr_t)handle);
}

JNIEXPORT jboolean JNICALL
Java_com_celllink_NativeBridge_nativeModemIsAlive(JNIEnv* env, jclass cls, jlong handle) {
    return modem_is_alive((modem_recovery_t*)(intptr_t)handle) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jint JNICALL
Java_com_celllink_NativeBridge_nativeModemRecover(JNIEnv* env, jclass cls, jlong handle) {
    return (jint)modem_recover((modem_recovery_t*)(intptr_t)handle);
}

JNIEXPORT jstring JNICALL
Java_com_celllink_NativeBridge_nativeModemCrashInfo(JNIEnv* env, jclass cls, jlong handle) {
    return (*env)->NewStringUTF(env, modem_crash_info((modem_recovery_t*)(intptr_t)handle));
}

/* ── Call Recorder JNI Methods ────────────────────────────────────────── */

#include "call_recorder.h"

JNIEXPORT jlong JNICALL
Java_com_celllink_NativeBridge_nativeCallRecorderCreate(JNIEnv* env, jclass cls, jstring filename) {
    const char* fn = filename ? (*env)->GetStringUTFChars(env, filename, NULL) : NULL;
    call_recorder_t* rec = call_recorder_create(fn);
    if (fn) (*env)->ReleaseStringUTFChars(env, filename, fn);
    return (jlong)(intptr_t)rec;
}

JNIEXPORT void JNICALL
Java_com_celllink_NativeBridge_nativeCallRecorderFree(JNIEnv* env, jclass cls, jlong handle) {
    call_recorder_free((call_recorder_t*)(intptr_t)handle);
}

JNIEXPORT jboolean JNICALL
Java_com_celllink_NativeBridge_nativeCallRecorderStart(JNIEnv* env, jclass cls, jlong handle) {
    return call_recorder_start((call_recorder_t*)(intptr_t)handle) == 0 ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_celllink_NativeBridge_nativeCallRecorderStop(JNIEnv* env, jclass cls, jlong handle) {
    return call_recorder_stop((call_recorder_t*)(intptr_t)handle) == 0 ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jdouble JNICALL
Java_com_celllink_NativeBridge_nativeCallRecorderGetDuration(JNIEnv* env, jclass cls, jlong handle) {
    return (jdouble)call_recorder_get_duration((call_recorder_t*)(intptr_t)handle);
}

/* ── DTMF JNI Methods ─────────────────────────────────────────────────── */

#include "dtmf.h"

JNIEXPORT jboolean JNICALL
Java_com_celllink_NativeBridge_nativeDtmfSend(JNIEnv* env, jclass cls, jlong diagHandle, jchar digit) {
    return dtmf_send_at((diag_handle_t*)(intptr_t)diagHandle, (char)digit, 70) == 0 ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_celllink_NativeBridge_nativeDtmfSendString(JNIEnv* env, jclass cls, jlong diagHandle, jstring digits) {
    const char* d = (*env)->GetStringUTFChars(env, digits, NULL);
    int ret = dtmf_send_string_at((diag_handle_t*)(intptr_t)diagHandle, d, 70);
    (*env)->ReleaseStringUTFChars(env, digits, d);
    return ret > 0 ? JNI_TRUE : JNI_FALSE;
}

/* ── GSM Sniffer JNI Methods ──────────────────────────────────────────── */

#include "gsm_sniffer.h"

JNIEXPORT jlong JNICALL
Java_com_celllink_NativeBridge_nativeSnifferCreate(JNIEnv* env, jclass cls, jstring filename) {
    const char* fn = filename ? (*env)->GetStringUTFChars(env, filename, NULL) : NULL;
    gsm_sniffer_t* sn = sniffer_create(fn);
    if (fn) (*env)->ReleaseStringUTFChars(env, filename, fn);
    return (jlong)(intptr_t)sn;
}

JNIEXPORT void JNICALL
Java_com_celllink_NativeBridge_nativeSnifferFree(JNIEnv* env, jclass cls, jlong handle) {
    sniffer_free((gsm_sniffer_t*)(intptr_t)handle);
}

JNIEXPORT jboolean JNICALL
Java_com_celllink_NativeBridge_nativeSnifferStart(JNIEnv* env, jclass cls, jlong handle) {
    return sniffer_start((gsm_sniffer_t*)(intptr_t)handle) == 0 ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_celllink_NativeBridge_nativeSnifferStop(JNIEnv* env, jclass cls, jlong handle) {
    return sniffer_stop((gsm_sniffer_t*)(intptr_t)handle) == 0 ? JNI_TRUE : JNI_FALSE;
}

/* ── Band Scanner JNI Methods ─────────────────────────────────────────── */

#include "band_scanner.h"

JNIEXPORT jlong JNICALL
Java_com_celllink_NativeBridge_nativeBandScanCreate(JNIEnv* env, jclass cls) {
    return (jlong)(intptr_t)band_scan_create();
}

JNIEXPORT void JNICALL
Java_com_celllink_NativeBridge_nativeBandScanFree(JNIEnv* env, jclass cls, jlong handle) {
    band_scan_free((band_scan_t*)(intptr_t)handle);
}

JNIEXPORT jint JNICALL
Java_com_celllink_NativeBridge_nativeBandScanFull(JNIEnv* env, jclass cls, jlong diagHandle, jlong scanHandle) {
    return (jint)band_scan_full((diag_handle_t*)(intptr_t)diagHandle, (band_scan_t*)(intptr_t)scanHandle);
}

JNIEXPORT jstring JNICALL
Java_com_celllink_NativeBridge_nativeBandScanExportCsv(JNIEnv* env, jclass cls, jlong handle) {
    char buf[32768];
    band_scan_export_csv((band_scan_t*)(intptr_t)handle, buf, sizeof(buf));
    return (*env)->NewStringUTF(env, buf);
}

/* ── PA Protection JNI Methods ────────────────────────────────────────── */

#include "pa_protect.h"

JNIEXPORT jlong JNICALL
Java_com_celllink_NativeBridge_nativePaProtectInit(JNIEnv* env, jclass cls) {
    return (jlong)(intptr_t)pa_protect_init();
}

JNIEXPORT void JNICALL
Java_com_celllink_NativeBridge_nativePaProtectFree(JNIEnv* env, jclass cls, jlong handle) {
    pa_protect_free((pa_protect_t*)(intptr_t)handle);
}

JNIEXPORT jboolean JNICALL
Java_com_celllink_NativeBridge_nativePaProtectTxStart(JNIEnv* env, jclass cls, jlong handle, jint powerDbm, jint arfcn) {
    return pa_protect_tx_start((pa_protect_t*)(intptr_t)handle, (uint8_t)powerDbm, (uint16_t)arfcn) == 0 ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_celllink_NativeBridge_nativePaProtectTxStop(JNIEnv* env, jclass cls, jlong handle) {
    return pa_protect_tx_stop((pa_protect_t*)(intptr_t)handle) == 0 ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_celllink_NativeBridge_nativePaProtectUpdate(JNIEnv* env, jclass cls, jlong handle,
                                                       jfloat tempC, jfloat fwdPower, jfloat revPower) {
    return pa_protect_update((pa_protect_t*)(intptr_t)handle, (float)tempC, (float)fwdPower, (float)revPower) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jstring JNICALL
Java_com_celllink_NativeBridge_nativePaProtectState(JNIEnv* env, jclass cls, jlong handle) {
    return (*env)->NewStringUTF(env, pa_protect_state_string((pa_protect_t*)(intptr_t)handle));
}

/* ── Modem Logger JNI Methods ─────────────────────────────────────────── */

#include "modem_logger.h"

JNIEXPORT jlong JNICALL
Java_com_celllink_NativeBridge_nativeModemLoggerCreate(JNIEnv* env, jclass cls, jstring filename) {
    const char* fn = filename ? (*env)->GetStringUTFChars(env, filename, NULL) : NULL;
    modem_logger_t* log = modem_logger_create(fn, 4096);
    if (fn) (*env)->ReleaseStringUTFChars(env, filename, fn);
    return (jlong)(intptr_t)log;
}

JNIEXPORT void JNICALL
Java_com_celllink_NativeBridge_nativeModemLoggerFree(JNIEnv* env, jclass cls, jlong handle) {
    modem_logger_free((modem_logger_t*)(intptr_t)handle);
}

JNIEXPORT jboolean JNICALL
Java_com_celllink_NativeBridge_nativeModemLoggerStart(JNIEnv* env, jclass cls, jlong handle) {
    return modem_logger_start((modem_logger_t*)(intptr_t)handle) == 0 ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_celllink_NativeBridge_nativeModemLoggerStop(JNIEnv* env, jclass cls, jlong handle) {
    return modem_logger_stop((modem_logger_t*)(intptr_t)handle) == 0 ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jstring JNICALL
Java_com_celllink_NativeBridge_nativeModemLoggerExport(JNIEnv* env, jclass cls, jlong handle, jint lastN) {
    char buf[65536];
    modem_logger_export((modem_logger_t*)(intptr_t)handle, buf, sizeof(buf), (uint32_t)lastN);
    return (*env)->NewStringUTF(env, buf);
}

/* ── Device Detection JNI Methods ────────────────────────────────────── */

#include "device_detect.h"

JNIEXPORT jlong JNICALL
Java_com_celllink_NativeBridge_nativeDeviceDetect(JNIEnv* env, jclass cls) {
    return (jlong)(intptr_t)device_detect();
}

JNIEXPORT void JNICALL
Java_com_celllink_NativeBridge_nativeDeviceFree(JNIEnv* env, jclass cls, jlong handle) {
    device_free((device_info_t*)(intptr_t)handle);
}

JNIEXPORT jstring JNICALL
Java_com_celllink_NativeBridge_nativeDeviceGetChipset(JNIEnv* env, jclass cls, jlong handle) {
    device_info_t* info = (device_info_t*)(intptr_t)handle;
    return (*env)->NewStringUTF(env, info ? info->chipset_name : "Unknown");
}

JNIEXPORT jstring JNICALL
Java_com_celllink_NativeBridge_nativeDeviceGetModem(JNIEnv* env, jclass cls, jlong handle) {
    device_info_t* info = (device_info_t*)(intptr_t)handle;
    return (*env)->NewStringUTF(env, info ? info->modem_name : "Unknown");
}

JNIEXPORT jboolean JNICALL
Java_com_celllink_NativeBridge_nativeDeviceIsRooted(JNIEnv* env, jclass cls, jlong handle) {
    device_info_t* info = (device_info_t*)(intptr_t)handle;
    return info && info->is_rooted ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jint JNICALL
Java_com_celllink_NativeBridge_nativeDeviceGetBackend(JNIEnv* env, jclass cls, jlong handle) {
    device_info_t* info = (device_info_t*)(intptr_t)handle;
    return info ? (jint)info->preferred_backend : -1;
}

JNIEXPORT jboolean JNICALL
Java_com_celllink_NativeBridge_nativeDeviceSelinuxEnforcing(JNIEnv* env, jclass cls, jlong handle) {
    device_info_t* info = (device_info_t*)(intptr_t)handle;
    return info && info->selinux_enforcing ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_celllink_NativeBridge_nativeDeviceBootloaderUnlocked(JNIEnv* env, jclass cls, jlong handle) {
    device_info_t* info = (device_info_t*)(intptr_t)handle;
    return info && info->bootloader_unlocked ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_celllink_NativeBridge_nativeDeviceAttemptRoot(JNIEnv* env, jclass cls, jlong handle) {
    return device_attempt_root((device_info_t*)(intptr_t)handle) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jstring JNICALL
Java_com_celllink_NativeBridge_nativeDeviceAtPrimary(JNIEnv* env, jclass cls, jlong handle) {
    device_info_t* info = (device_info_t*)(intptr_t)handle;
    return (*env)->NewStringUTF(env, info && info->has_at_commands ? info->at_primary : "");
}

/* ── HiSilicon AT JNI Methods ────────────────────────────────────────── */

#include "hisilicon_at.h"

JNIEXPORT jlong JNICALL
Java_com_celllink_NativeBridge_nativeHisiliconOpen(JNIEnv* env, jclass cls, jstring devicePath) {
    const char* path = devicePath ? (*env)->GetStringUTFChars(env, devicePath, NULL) : NULL;
    hisilicon_at_t* at = hisilicon_open(path);
    if (path) (*env)->ReleaseStringUTFChars(env, devicePath, path);
    return (jlong)(intptr_t)at;
}

JNIEXPORT void JNICALL
Java_com_celllink_NativeBridge_nativeHisiliconClose(JNIEnv* env, jclass cls, jlong handle) {
    hisilicon_close((hisilicon_at_t*)(intptr_t)handle);
}

JNIEXPORT jboolean JNICALL
Java_com_celllink_NativeBridge_nativeHisiliconIsAlive(JNIEnv* env, jclass cls, jlong handle) {
    return hisilicon_is_alive((hisilicon_at_t*)(intptr_t)handle) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jstring JNICALL
Java_com_celllink_NativeBridge_nativeHisiliconAtSend(JNIEnv* env, jclass cls, jlong handle, jstring cmd) {
    const char* c = (*env)->GetStringUTFChars(env, cmd, NULL);
    char rsp[4096];
    int n = hisilicon_at_send((hisilicon_at_t*)(intptr_t)handle, c, rsp, sizeof(rsp));
    (*env)->ReleaseStringUTFChars(env, cmd, c);
    return (n >= 0) ? (*env)->NewStringUTF(env, rsp) : NULL;
}

JNIEXPORT jboolean JNICALL
Java_com_celllink_NativeBridge_nativeHisiliconRegisterNetwork(JNIEnv* env, jclass cls, jlong handle, jint mcc, jint mnc) {
    return hisilicon_register_network((hisilicon_at_t*)(intptr_t)handle, mcc, mnc) == 0 ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jint JNICALL
Java_com_celllink_NativeBridge_nativeHisiliconGetSignal(JNIEnv* env, jclass cls, jlong handle) {
    int rssi = -120;
    hisilicon_get_signal((hisilicon_at_t*)(intptr_t)handle, &rssi);
    return (jint)rssi;
}

JNIEXPORT jboolean JNICALL
Java_com_celllink_NativeBridge_nativeHisiliconMakeCall(JNIEnv* env, jclass cls, jlong handle, jstring number) {
    const char* n = (*env)->GetStringUTFChars(env, number, NULL);
    int ret = hisilicon_make_call((hisilicon_at_t*)(intptr_t)handle, n);
    (*env)->ReleaseStringUTFChars(env, number, n);
    return ret == 0 ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_celllink_NativeBridge_nativeHisiliconEndCall(JNIEnv* env, jclass cls, jlong handle) {
    return hisilicon_end_call((hisilicon_at_t*)(intptr_t)handle) == 0 ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_celllink_NativeBridge_nativeHisiliconSendSms(JNIEnv* env, jclass cls, jlong handle, jstring recipient, jstring text) {
    const char* r = (*env)->GetStringUTFChars(env, recipient, NULL);
    const char* t = (*env)->GetStringUTFChars(env, text, NULL);
    int ret = hisilicon_send_sms((hisilicon_at_t*)(intptr_t)handle, r, t);
    (*env)->ReleaseStringUTFChars(env, recipient, r);
    (*env)->ReleaseStringUTFChars(env, text, t);
    return ret == 0 ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_celllink_NativeBridge_nativeHisiliconRfTestStart(JNIEnv* env, jclass cls, jlong handle, jint arfcn, jint powerDbm) {
    return hisilicon_rf_test_start((hisilicon_at_t*)(intptr_t)handle, arfcn, powerDbm) == 0 ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_celllink_NativeBridge_nativeHisiliconRfTestStop(JNIEnv* env, jclass cls, jlong handle) {
    return hisilicon_rf_test_stop((hisilicon_at_t*)(intptr_t)handle) == 0 ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jint JNICALL
Java_com_celllink_NativeBridge_nativeHisiliconNetworkScan(JNIEnv* env, jclass cls, jlong handle) {
    char rsp[4096];
    return (jint)hisilicon_network_scan((hisilicon_at_t*)(intptr_t)handle, rsp, sizeof(rsp));
}
