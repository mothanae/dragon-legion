package com.celllink

import android.content.Context
import android.media.AudioAttributes
import android.media.AudioDeviceInfo
import android.media.AudioFocusRequest
import android.media.AudioFormat
import android.media.AudioManager
import android.media.AudioRecord
import android.media.AudioTrack
import android.media.MediaRecorder
import android.os.Build
import android.util.Log

/**
 * Manages audio routing for direct cellular calls.
 *
 * On each device:
 * - Tower mode: play incoming audio + capture mic for outgoing
 * - UE mode: play incoming audio + capture mic for outgoing
 *
 * In a direct cellular link, both sides do the same thing:
 * The modem handles the actual audio transport over the GSM channel;
 * this class ensures the Android audio system routes correctly.
 */
class AudioRouter(private val context: Context) {

    companion object {
        private const val TAG = "CellLink-Audio"
        private const val SAMPLE_RATE = 8000  // GSM narrowband
        private const val CHANNEL_CONFIG = AudioFormat.CHANNEL_IN_MONO
        private const val AUDIO_FORMAT = AudioFormat.ENCODING_PCM_16BIT
    }

    private val audioManager: AudioManager =
        context.getSystemService(Context.AUDIO_SERVICE) as AudioManager

    @Volatile
    var isActive: Boolean = false
        private set

    /**
     * Configure audio for a voice call:
     * - Switch to earpiece (or speaker if requested)
     * - Request audio focus
     * - Set mode to IN_CALL
     */
    fun startVoiceCall(useSpeaker: Boolean = false) {
        if (isActive) return

        try {
            // Set audio mode to in-call
            audioManager.mode = AudioManager.MODE_IN_CALL

            // Enable speaker if requested
            audioManager.isSpeakerphoneOn = useSpeaker

            // Request audio focus
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                val focusRequest = AudioFocusRequest.Builder(AudioManager.AUDIOFOCUS_GAIN_TRANSIENT_EXCLUSIVE)
                    .setAudioAttributes(
                        AudioAttributes.Builder()
                            .setUsage(AudioAttributes.USAGE_VOICE_COMMUNICATION)
                            .setContentType(AudioAttributes.CONTENT_TYPE_SPEECH)
                            .build()
                    )
                    .setOnAudioFocusChangeListener { focusChange ->
                        Log.d(TAG, "Audio focus changed: $focusChange")
                    }
                    .build()
                audioManager.requestAudioFocus(focusRequest)
            } else {
                @Suppress("DEPRECATION")
                audioManager.requestAudioFocus(
                    null,
                    AudioManager.STREAM_VOICE_CALL,
                    AudioManager.AUDIOFOCUS_GAIN_TRANSIENT_EXCLUSIVE
                )
            }

            // Route to earpiece for handset mode
            if (!useSpeaker) {
                audioManager.setSpeakerphoneOn(false)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                    val availableDevices = audioManager.getDevices(AudioManager.GET_DEVICES_OUTPUTS)
                    // Prefer built-in earpiece
                    for (device in availableDevices) {
                        if (device.type == AudioDeviceInfo.TYPE_BUILTIN_EARPIECE) {
                            // On Android 13+, can set preferred device
                            // audioManager.setPreferredDeviceForStrategy(...)
                            break
                        }
                    }
                }
            }

            // Enable Bluetooth SCO if available
            if (audioManager.isBluetoothScoAvailableOffCall) {
                audioManager.startBluetoothSco()
            }

            isActive = true
            Log.i(TAG, "Voice call audio started (speaker=$useSpeaker)")

        } catch (e: Exception) {
            Log.e(TAG, "Failed to start voice call audio", e)
        }
    }

    /**
     * Restore normal audio configuration.
     */
    fun stopVoiceCall() {
        if (!isActive) return

        try {
            audioManager.mode = AudioManager.MODE_NORMAL
            audioManager.isSpeakerphoneOn = false
            audioManager.abandonAudioFocus(null)

            if (audioManager.isBluetoothScoOn) {
                audioManager.stopBluetoothSco()
            }

            isActive = false
            Log.i(TAG, "Voice call audio stopped")

        } catch (e: Exception) {
            Log.e(TAG, "Failed to stop voice call audio", e)
        }
    }

    /**
     * Toggle speakerphone during an active call.
     */
    fun toggleSpeakerphone(): Boolean {
        val newState = !audioManager.isSpeakerphoneOn
        audioManager.isSpeakerphoneOn = newState
        return newState
    }

    /**
     * Mute / unmute the microphone.
     * Only mutes the Android-side mic routing; does not stop modem capture.
     */
    fun setMuted(muted: Boolean) {
        audioManager.setMicrophoneMute(muted)
    }

    fun isMuted(): Boolean = audioManager.isMicrophoneMute
}
