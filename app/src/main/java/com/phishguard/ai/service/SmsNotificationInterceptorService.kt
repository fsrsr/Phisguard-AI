package com.phishguard.ai.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.os.Build
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.util.Log
import androidx.core.app.NotificationCompat
import com.phishguard.ai.R
import com.phishguard.ai.core.ai.MessageAnalyzer
import com.phishguard.ai.ui.WarningActivity

/**
 * SMS & Chat Notification Interceptor Service.
 *
 * ARSITEKTUR:
 * - Menggunakan NotificationListenerService untuk menangkap SEMUA notifikasi masuk.
 * - Filter package SMS/Chat yang sedang dimonitor.
 * - Kirim teks notifikasi ke TFLite NLP Analyzer.
 * - Jika skor penipuan tinggi:
 *     1. Sembunyikan notifikasi asli (cancelNotification).
 *     2. Tampilkan notifikasi kustom: "🚨 SMS Penipuan Disembunyikan"
 *
 * SETUP:
 * - Harus ditambahkan ke AndroidManifest.xml sebagai service.
 * - User harus grant "Notification Access" di Settings > Notification Access.
 */
class SmsNotificationInterceptorService : NotificationListenerService() {

    private val TAG = "SmsInterceptor"
    private var messageAnalyzer: MessageAnalyzer? = null

    // Package SMS/Chat yang akan dimonitor
    private val monitoredPackages = setOf(
        "com.google.android.apps.messaging",  // Google Messages
        "com.samsung.android.messaging",       // Samsung Messages
        "com.android.mms",                     // AOSP Messages
        "org.telegram.messenger",              // Telegram
        "org.thunderdog.challegram",           // Telegram X
        "com.whatsapp",                        // WhatsApp
        "com.whatsapp.w4b",                    // WhatsApp Business — terpasang
                                               // di banyak HP dan sebelumnya
                                               // terlewat sama sekali
        "com.facebook.orca",                   // Facebook Messenger
        "com.instagram.android",               // Instagram DM
        "com.instagram.barcelona",             // Threads
        "com.google.android.gm",               // Gmail
        "com.microsoft.office.outlook",        // Outlook
        "com.linkedin.android"                 // LinkedIn InMail
    )

    // ID notifikasi yang sudah di-flag phishing (hindari loop)
    private val flaggedNotifIds = mutableSetOf<String>()

    companion object {
        const val PHISHING_CHANNEL_ID = "phishing_alert_channel"
        const val PHISHING_CHANNEL_NAME = "PhishGuard Peringatan"
    }

    override fun onCreate() {
        super.onCreate()
        messageAnalyzer = MessageAnalyzer(applicationContext)
        createNotificationChannel()
        Log.d(TAG, "SmsNotificationInterceptorService started.")
    }

    override fun onDestroy() {
        super.onDestroy()
        messageAnalyzer?.release()
    }

    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        sbn ?: return

        val packageName = sbn.packageName ?: return

        // Hanya proses paket yang dimonitor
        if (!monitoredPackages.contains(packageName)) return

        // Skip notifikasi yang sudah kita buat sendiri (hindari infinite loop)
        val uniqueKey = "${sbn.key}:${sbn.postTime}"
        if (flaggedNotifIds.contains(uniqueKey)) return

        // Ambil teks dari notifikasi
        val extras = sbn.notification?.extras ?: return
        val title = extras.getCharSequence(Notification.EXTRA_TITLE)?.toString() ?: ""
        val text = extras.getCharSequence(Notification.EXTRA_TEXT)?.toString() ?: ""
        val bigText = extras.getCharSequence(Notification.EXTRA_BIG_TEXT)?.toString() ?: ""

        val fullMessage = "$title $text $bigText".trim()
        if (fullMessage.length < 10) return // Abaikan notifikasi kosong/singkat

        // JANGAN cetak isi pesan ke log. Ini notifikasi pribadi pengguna —
        // siapa pun yang bisa membaca logcat (adb, alat diagnostik pabrikan)
        // akan ikut membaca percakapannya. Cukup catat panjangnya.
        Log.d(TAG, "Notifikasi dari $packageName (${fullMessage.length} karakter)")

        // Analisis dengan TFLite NLP
        messageAnalyzer?.analyzeMessage(fullMessage, packageName) { isThreat, confidence, reason ->
            if (isThreat && confidence >= 0.65f) {
                Log.w(TAG, "🚨 Notifikasi penipuan terdeteksi dari $packageName (keyakinan=$confidence)")

                // 1. Sembunyikan notifikasi asli
                try {
                    cancelNotification(sbn.key)
                    flaggedNotifIds.add(uniqueKey)
                    Log.d(TAG, "Notifikasi asli disembunyikan: ${sbn.key}")
                } catch (e: Exception) {
                    Log.e(TAG, "Gagal menyembunyikan notif: ${e.message}")
                }

                // 2. Tampilkan notifikasi peringatan kustom
                showPhishingWarningNotification(
                    originalPackage = packageName,
                    message = fullMessage,
                    reason = reason
                )
            }
        }
    }

    override fun onNotificationRemoved(sbn: StatusBarNotification?) {
        // Bersihkan tracking jika notif sudah dihapus
        sbn?.let { flaggedNotifIds.remove("${it.key}:${it.postTime}") }
    }

    /**
     * Tampilkan notifikasi peringatan pengganti SMS phishing.
     * User bisa tap untuk melihat detail pesan penipuan.
     */
    private fun showPhishingWarningNotification(
        originalPackage: String,
        message: String,
        reason: String
    ) {
        val notifManager = getSystemService(NOTIFICATION_SERVICE) as NotificationManager

        // Intent ke WarningActivity untuk detail
        val detailIntent = Intent(this, WarningActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            putExtra(WarningActivity.EXTRA_PHISHING_URL, message.take(150))
            putExtra(WarningActivity.EXTRA_REASON, reason)
            putExtra(WarningActivity.EXTRA_SOURCE, getAppLabel(originalPackage))
            putExtra("is_sms_mode", true)
            putExtra("phone_number", "")  // Phone number not available from notification
        }
        val pendingIntent = PendingIntent.getActivity(
            this, System.currentTimeMillis().toInt(),
            detailIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val notification = NotificationCompat.Builder(this, PHISHING_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle("🚨 SMS Penipuan Disembunyikan")
            .setContentText("Sentuh untuk melihat detail pesan mencurigakan")
            .setStyle(NotificationCompat.BigTextStyle()
                .bigText("Pesan terindikasi penipuan dari ${getAppLabel(originalPackage)}.\n\nAlasan: $reason")
            )
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setColor(0xFFD32F2F.toInt()) // Merah
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
            .build()

        notifManager.notify(System.currentTimeMillis().toInt(), notification)
        Log.d(TAG, "✅ Notifikasi peringatan phishing ditampilkan.")
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                PHISHING_CHANNEL_ID,
                PHISHING_CHANNEL_NAME,
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Peringatan PhishGuard saat mendeteksi SMS/pesan penipuan"
                enableLights(true)
                enableVibration(true)
            }
            val manager = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(channel)
        }
    }

    private fun getAppLabel(packageName: String): String {
        return when {
            packageName.contains("messaging") -> "Pesan (SMS)"
            packageName.contains("telegram")  -> "Telegram"
            packageName.contains("whatsapp")  -> "WhatsApp"
            packageName.contains("facebook")  || packageName.contains("orca") -> "Messenger"
            packageName.contains("instagram") -> "Instagram"
            else -> packageName
        }
    }
}
