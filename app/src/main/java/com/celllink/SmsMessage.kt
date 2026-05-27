package com.celllink

/**
 * Parsed SMS message from the native SMS layer.
 */
data class SmsMessage(
    val sender: String,
    val text: String,
    val timestamp: Long,
    val isIncoming: Boolean
) {
    val formattedTime: String
        get() {
            val sdf = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US)
            return sdf.format(java.util.Date(timestamp * 1000))
        }
}
