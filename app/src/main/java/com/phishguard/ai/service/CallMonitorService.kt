package com.phishguard.ai.service

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.IBinder
import android.telephony.PhoneStateListener
import android.telephony.TelephonyManager
import android.util.Log
import androidx.core.content.ContextCompat
import com.phishguard.ai.R
import com.phishguard.ai.core.ai.CallFraudDetector
import com.phishguard.ai.data.AppPreferences

/**
 * ForegroundService untuk memantau panggilan telepon masuk.
 * Ketika ada panggilan, CallFraudDetector mulai menganalisis.
 *
 * INTEGRASI:
 * - Dipanggil oleh ProtectionFragment saat user mengaktifkan Call Protection.
 * - CallFraudDetector (Tim AI) melakukan analisis real-time.
 */
class CallMonitorService : Service() {

    private val TAG = "CallMonitorService"
    private lateinit var callFraudDetector: CallFraudDetector
    private lateinit var telephonyManager: TelephonyManager

    private val phoneStateListener = object : PhoneStateListener() {
        @Deprecated("Deprecated for API 31+, use TelephonyCallback instead")
        override fun onCallStateChanged(state: Int, phoneNumber: String?) {
            when (state) {
                TelephonyManager.CALL_STATE_RINGING -> {
                    val number = phoneNumber ?: "Unknown"
                    Log.d(TAG, "Incoming call from: $number")
                    sendLogToUI("📞 Panggilan masuk dari $number", "Phone", "CALL")
                }
                TelephonyManager.CALL_STATE_OFFHOOK -> {
                    Log.d(TAG, "Call answered, starting real-time STT analysis...")
                    sendLogToUI("🎤 Memulai analisis percakapan real-time...", "Phone", "CALL")

                    // Start real-time voice fraud detection
                    callFraudDetector.onPartialTranscription = { partial ->
                        // Optional: log partial results for debugging
                        Log.v(TAG, "Partial: $partial")
                    }
                    
                    callFraudDetector.startAnalyzing()
                }
                TelephonyManager.CALL_STATE_IDLE -> {
                    Log.d(TAG, "Call ended")
                    callFraudDetector.stopAnalyzing()
                    
                    val transcript = callFraudDetector.getCurrentTranscription()
                    if (transcript.isNotEmpty()) {
                        sendLogToUI("📝 Transkripsi: ${transcript.take(100)}...", "Phone", "SYSTEM")
                    }
                    sendLogToUI("✅ Analisis selesai, panggilan berakhir.", "Phone", "SYSTEM")
                }
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        callFraudDetector = CallFraudDetector(this)
        telephonyManager = getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager

        // Setup fraud detection callback
        callFraudDetector.onFraudDetected = { confidence, reason ->
            val confidencePercent = "%.0f".format(confidence * 100)
            sendLogToUI("🚨 PANGGILAN PENIPUAN TERDETEKSI! ($reason) Tingkat keyakinan: $confidencePercent%", "Phone", "PHISHING")
            
            // Show warning notification
            showFraudWarning(reason, confidence)
        }

        createNotificationChannel()

        // Android 14+ menolak foreground service bertipe "microphone" bila
        // izin mikrofon belum diberikan ATAU FOREGROUND_SERVICE_MICROPHONE
        // tidak dideklarasikan. Dulu kegagalannya berupa SecurityException
        // yang mematikan aplikasi — dan karena ProtectionFragment menyalakan
        // ulang service ini tiap aplikasi dibuka, aplikasi jadi tidak bisa
        // dibuka sama sekali. Sekarang gagal dengan tenang: matikan
        // togglenya, beri tahu pengguna, lalu berhenti.
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.RECORD_AUDIO)
            != PackageManager.PERMISSION_GRANTED
        ) {
            Log.w(TAG, "Izin mikrofon belum diberikan — Call Protection dimatikan.")
            disableAndStop("Call Protection butuh izin mikrofon.")
            return
        }

        try {
            startForeground(NOTIFICATION_ID, createNotification())
        } catch (e: Exception) {
            Log.e(TAG, "Gagal memulai foreground service", e)
            disableAndStop("Call Protection tidak didukung di perangkat ini.")
            return
        }

        @Suppress("DEPRECATION")
        telephonyManager.listen(phoneStateListener, PhoneStateListener.LISTEN_CALL_STATE)

        sendLogToUI("Call Protection service started.", "Phone", "SYSTEM")
    }

    /**
     * Matikan preferensinya sebelum berhenti. Tanpa ini toggle tetap
     * menyala dan service dicoba lagi setiap aplikasi dibuka.
     */
    private fun disableAndStop(alasan: String) {
        try {
            AppPreferences(this).callProtectionEnabled = false
            sendLogToUI("⚠️ $alasan", "Phone", "SYSTEM")
        } catch (e: Exception) {
            Log.e(TAG, "disableAndStop error", e)
        }
        stopSelf()
    }

    override fun onDestroy() {
        super.onDestroy()
        @Suppress("DEPRECATION")
        telephonyManager.listen(phoneStateListener, PhoneStateListener.LISTEN_NONE)
        callFraudDetector.stopAnalyzing()
        sendLogToUI("Call Protection service stopped.", "Phone", "SYSTEM")
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Call Protection",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Monitoring incoming calls for fraud detection"
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    private fun createNotification(): Notification {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
                .setContentTitle("Save Me — Call Protection")
                .setContentText("Monitoring incoming calls for fraud")
                .setSmallIcon(android.R.drawable.ic_menu_call)
                .build()
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
                .setContentTitle("Save Me — Call Protection")
                .setContentText("Monitoring incoming calls for fraud")
                .setSmallIcon(android.R.drawable.ic_menu_call)
                .build()
        }
    }

    private fun sendLogToUI(message: String, source: String, type: String) {
        val intent = Intent("com.phishguard.ai.LOG_UPDATE").apply {
            setPackage(packageName)
            putExtra("message", message)
            putExtra("source", source)
            putExtra("type", type)
        }
        sendBroadcast(intent)
    }

    private fun showFraudWarning(reason: String, confidence: Float) {
        val notificationManager = getSystemService(NotificationManager::class.java)
        
        // Create high-priority warning channel
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val warningChannel = NotificationChannel(
                "fraud_warning_channel",
                "Peringatan Penipuan",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Notifikasi peringatan panggilan penipuan"
                enableVibration(true)
                enableLights(true)
            }
            notificationManager.createNotificationChannel(warningChannel)
        }

        val confidencePercent = "%.0f".format(confidence * 100)
        val notification = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, "fraud_warning_channel")
                .setContentTitle("🚨 PERINGATAN: Panggilan Penipuan!")
                .setContentText("Keyakinan: $confidencePercent% - $reason")
                .setStyle(Notification.BigTextStyle().bigText("Terdeteksi pola penipuan dalam percakapan.\n\nAlasan: $reason\n\nTingkat keyakinan: $confidencePercent%\n\nSegera akhiri panggilan jika Anda diminta transfer uang atau memberikan OTP/PIN."))
                .setSmallIcon(android.R.drawable.ic_dialog_alert)
                .setAutoCancel(true)
                .setPriority(Notification.PRIORITY_HIGH)
                .setVibrate(longArrayOf(0, 500, 200, 500))
                .build()
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
                .setContentTitle("🚨 PERINGATAN: Panggilan Penipuan!")
                .setContentText("Keyakinan: $confidencePercent% - $reason")
                .setStyle(Notification.BigTextStyle().bigText("Terdeteksi pola penipuan dalam percakapan.\n\nAlasan: $reason\n\nTingkat keyakinan: $confidencePercent%\n\nSegera akhiri panggilan jika Anda diminta transfer uang atau memberikan OTP/PIN."))
                .setSmallIcon(android.R.drawable.ic_dialog_alert)
                .setAutoCancel(true)
                .setPriority(Notification.PRIORITY_HIGH)
                .setVibrate(longArrayOf(0, 500, 200, 500))
                .build()
        }

        notificationManager.notify(9999, notification)
    }

    companion object {
        private const val CHANNEL_ID = "call_protection_channel"
        private const val NOTIFICATION_ID = 1001
    }
}
