package com.phishguard.ai.ui

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.widget.ImageView
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.google.android.material.button.MaterialButton
import com.phishguard.ai.PhishGuardService
import com.phishguard.ai.R
import com.phishguard.ai.core.network.FirebaseSyncManager

/**
 * Layar peringatan yang muncul di atas browser/aplikasi lain.
 *
 * Prinsip UX di sini:
 *  - tampilkan NAMA SITUS besar-besar; itu satu-satunya hal yang benar-benar
 *    perlu dinilai pengguna, bukan URL panjang penuh parameter
 *  - tingkat risiko dibedakan (tinggi vs perlu diperiksa) agar peringatan
 *    tidak semuanya terasa sama dan berhenti dibaca
 *  - aksi aman jadi tombol utama, "situs ini aman" tetap satu ketukan —
 *    salah tebak sistem tidak boleh menjebak pengguna
 */
class WarningActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_PHISHING_URL       = "phishing_url"
        const val EXTRA_REASON             = "reason"
        const val EXTRA_SOURCE             = "source"
        const val EXTRA_IS_PERMANENT_BLOCK = "is_permanent_block"
        const val EXTRA_CONFIDENCE         = "confidence"

        /** Di bawah ini deteksi disebut "perlu diperiksa", bukan "berbahaya". */
        private const val HIGH_RISK_THRESHOLD = 0.80f
    }

    private val TAG = "WarningActivity"

    /**
     * Minta service menavigasi kembali satu halaman saat overlay ditutup.
     *
     * Dipakai mode "sudah diblokir permanen", yang dulu melompat ke layar
     * Home — itu menutup konteks pengguna sepenuhnya. Kembali satu halaman
     * mengembalikannya ke tempat sebelum situs berbahaya dibuka, dan tab
     * peramban tetap utuh.
     */
    private var requestBackOnClose = false

    override fun onDestroy() {
        // Beri tahu PhishGuardService bahwa overlay sudah benar-benar tertutup.
        // Service memakai sinyal ini untuk mengeksekusi navigasi Back ke
        // browser (back-after-block) — deterministik, tidak balapan dengan
        // animasi penutupan activity.
        try {
            sendBroadcast(Intent(PhishGuardService.ACTION_WARNING_CLOSED).apply {
                setPackage(packageName)
                putExtra("request_back", requestBackOnClose)
            })
        } catch (_: Exception) {}
        super.onDestroy()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_warning)

        val url        = intent.getStringExtra(EXTRA_PHISHING_URL) ?: "Tidak diketahui"
        val ignoredMessage = intent.getStringExtra("ignored_message") ?: url
        val reason     = intent.getStringExtra(EXTRA_REASON) ?: getString(R.string.warning_subtitle)
        val source     = intent.getStringExtra(EXTRA_SOURCE).orEmpty()
        val confidence = intent.getFloatExtra(EXTRA_CONFIDENCE, 0.90f)
        val isPermanentBlock = intent.getBooleanExtra(EXTRA_IS_PERMANENT_BLOCK, false)
        val isSmsMode        = intent.getBooleanExtra("is_sms_mode", false)

        val ivIcon     = findViewById<ImageView>(R.id.ivRiskIcon)
        val tvBadge    = findViewById<TextView>(R.id.tvRiskBadge)
        val tvTitle    = findViewById<TextView>(R.id.tvWarningTitle)
        val tvHost     = findViewById<TextView>(R.id.tvWarningHost)
        val tvReason   = findViewById<TextView>(R.id.tvWarningReason)
        val tvUrl      = findViewById<TextView>(R.id.tvWarningUrl)
        val tvSource   = findViewById<TextView>(R.id.tvSource)
        val tvQuestion = findViewById<TextView>(R.id.tvQuestion)
        val pbConf     = findViewById<ProgressBar>(R.id.pbConfidence)
        val tvConf     = findViewById<TextView>(R.id.tvConfidence)
        val btnBlock   = findViewById<MaterialButton>(R.id.btnCloseWarning)
        val btnSafe    = findViewById<MaterialButton>(R.id.btnMarkSafe)

        // ── Warna & label mengikuti tingkat risiko ──────────────────────
        val highRisk = confidence >= HIGH_RISK_THRESHOLD
        val accent = ContextCompat.getColor(this, if (highRisk) R.color.error else R.color.warning)
        val accentDark = ContextCompat.getColor(this, if (highRisk) R.color.error_dark else R.color.warning_dark)
        val accentLight = ContextCompat.getColor(this, if (highRisk) R.color.error_light else R.color.warning_light)

        ivIcon.setColorFilter(accent)
        findViewById<android.view.View>(R.id.iconRiskContainer).background
            ?.mutate()?.setTint(accentLight)
        tvBadge.background?.mutate()?.setTint(accentLight)
        tvBadge.setTextColor(accentDark)
        tvBadge.setText(if (highRisk) R.string.risk_high else R.string.risk_medium)
        tvHost.setTextColor(accentDark)
        pbConf.progressTintList = android.content.res.ColorStateList.valueOf(accent)
        btnBlock.backgroundTintList = android.content.res.ColorStateList.valueOf(accent)

        val percent = (confidence.coerceIn(0f, 1f) * 100).toInt()
        pbConf.progress = percent
        tvConf.text = "$percent%"

        tvReason.text = reason
        tvUrl.text = url
        tvSource.text = if (source.isBlank()) "" else getString(R.string.warning_source, source)
        tvSource.visibility = if (source.isBlank()) android.view.View.GONE else android.view.View.VISIBLE

        // ── MODE: pesan SMS / chat ──────────────────────────────────────
        if (isSmsMode) {
            val phoneNumber = intent.getStringExtra("phone_number").orEmpty()
            tvTitle.setText(R.string.warning_title_sms)
            tvHost.text = phoneNumber.ifBlank { source }
            tvHost.visibility = if (tvHost.text.isNullOrBlank()) android.view.View.GONE else android.view.View.VISIBLE
            tvQuestion.setText(R.string.warning_sms_advice)

            if (phoneNumber.isNotBlank()) {
                btnBlock.setText(R.string.warning_btn_block_number)
                btnSafe.setText(R.string.warning_btn_ignore)
                btnBlock.setOnClickListener {
                    setBusy(btnBlock, btnSafe)
                    sendToService(PhishGuardService.ACTION_BLOCK_NUMBER) {
                        putExtra("phone_number", phoneNumber)
                    }
                    logActivity("Blocked SMS from: $phoneNumber", "SMS", "PHISHING", countAsBlocked = true)
                    Toast.makeText(this, getString(R.string.risk_number_blocked, phoneNumber), Toast.LENGTH_SHORT).show()
                    finish()
                }
            } else {
                // Chat tanpa nomor: laporkan, jangan hanya menutup popup.
                btnBlock.setText(R.string.warning_btn_close)
                btnSafe.setText(R.string.warning_btn_ignore)
                btnBlock.setOnClickListener {
                    setBusy(btnBlock, btnSafe)
                    val reportedUrl = extractFirstUrl(ignoredMessage)
                    sendToService(PhishGuardService.ACTION_REPORT_MESSAGE) {
                        putExtra("target_url", reportedUrl)
                        putExtra("ignored_message", ignoredMessage)
                    }
                    logActivity("Reported message${reportedUrl.takeIf { it.isNotBlank() }?.let { ": $it"} ?: ""}", source, "USER_REPORTED", countAsBlocked = false)
                    val reportUrls = if (reportedUrl.isBlank()) emptyList() else listOf(reportedUrl)
                    val localReportId = java.util.UUID.randomUUID().toString()
                    saveLocalReport(localReportId, reportedUrl, "Terkirim")
                    FirebaseSyncManager(applicationContext).uploadUserReport(
                        message = ignoredMessage,
                        urls = reportUrls,
                        source = source,
                        reason = reason,
                        confidence = confidence,
                        reportId = localReportId,
                        onSuccess = { updateLocalReport(localReportId, "Diproses") }
                    )
                    if (reportedUrl.isNotBlank()) uploadToFirebase(reportedUrl, reason, confidence)
                    Toast.makeText(this, R.string.risk_message_reported, Toast.LENGTH_SHORT).show()
                    finish()
                }
            }
            btnSafe.setOnClickListener {
                sendToService(PhishGuardService.ACTION_IGNORE_MESSAGE) {
                    putExtra("ignored_message", ignoredMessage)
                }
                finish()
            }
            return
        }

        // ── MODE: sudah diblokir permanen ───────────────────────────────
        if (isPermanentBlock) {
            tvQuestion.setText(R.string.warning_blocked_permanent)
            btnSafe.visibility = android.view.View.GONE
            btnBlock.setText(R.string.warning_btn_block)
            btnBlock.setOnClickListener {
                requestBackOnClose = true
                finish()
            }
            return
        }

        // ── MODE: keputusan HITL ────────────────────────────────────────
        tvTitle.setText(if (highRisk) R.string.warning_title else R.string.warning_title_medium)
        tvHost.text = hostOf(url)

        btnSafe.setOnClickListener {
            sendToService(PhishGuardService.ACTION_MARK_SAFE) { putExtra("target_url", url) }
            finish()
        }

        btnBlock.setOnClickListener {
            setBusy(btnBlock, btnSafe)

            // 1. Simpan keputusan ke service (Room DB + daftar blokir + Back)
            sendToService(PhishGuardService.ACTION_MARK_THREAT) { putExtra("target_url", url) }

            // 2. Catat ke log aktivitas
            logActivity("Blocked: $url", "Browser", "PHISHING", countAsBlocked = true)

            // 3. Bagikan ke database komunitas agar pengguna lain ikut terlindungi
            uploadToFirebase(url, reason, confidence)

            // 4. Tutup; service yang menavigasi kembali satu halaman
            // Tunda sedikit untuk memastikan overlay tertutup sepenuhnya sebelum Back
            Handler(Looper.getMainLooper()).postDelayed({ finish() }, 150)
        }
    }

    // ── Helper ──────────────────────────────────────────────────────────

    /** Broadcast eksplisit ke paket sendiri — tanpa ini receiver bisa tidak kebagian. */
    private fun sendToService(action: String, extras: Intent.() -> Unit) {
        sendBroadcast(Intent(action).apply {
            setPackage(packageName)
            extras()
        })
    }

    private fun setBusy(primary: MaterialButton, secondary: MaterialButton) {
        primary.setText(R.string.warning_blocking)
        primary.isEnabled = false
        secondary.isEnabled = false
    }

    private fun extractFirstUrl(text: String): String =
        Regex("https?://[^\\s]+|(?:www\\.)?[a-zA-Z0-9-]+\\.[a-zA-Z]{2,}(?:/[^\\s]*)?")
            .find(text)?.value?.trimEnd('.', ',', '!', '?', ')') ?: ""

    private fun hostOf(url: String): String =
        url.removePrefix("https://").removePrefix("http://")
            .substringBefore('/').substringBefore('?').removePrefix("www.")
            .ifBlank { url.take(60) }

    private fun logActivity(message: String, source: String, type: String, countAsBlocked: Boolean) {
        val prefs = getSharedPreferences("activity_log", Context.MODE_PRIVATE)
        val logs = (prefs.getStringSet("logs", emptySet()) ?: emptySet()).toMutableSet()
        logs.add("${System.currentTimeMillis()}|${message.replace('|', ' ')}|$source|$type")
        prefs.edit().apply {
            putStringSet("logs", logs)
            if (countAsBlocked) putInt("blocked_count", prefs.getInt("blocked_count", 0) + 1)
        }.apply()

        sendBroadcast(Intent("com.phishguard.ai.LOG_UPDATE").apply {
            setPackage(packageName)
            putExtra("message", message)
            putExtra("source", source)
            putExtra("type", type)
        })
    }

    private fun saveLocalReport(reportId: String, indicator: String, status: String) {
        val prefs = getSharedPreferences("activity_log", Context.MODE_PRIVATE)
        val record = "$reportId|${System.currentTimeMillis()}|${indicator.replace('|', ' ')}|$status"
        val reports = (prefs.getStringSet("reports", emptySet()) ?: emptySet()).toMutableSet()
        reports.add(record)
        prefs.edit().putStringSet("reports", reports.toList().takeLast(50).toSet()).apply()
        sendBroadcast(Intent("com.phishguard.ai.REPORT_UPDATE").setPackage(packageName))
    }

    private fun updateLocalReport(reportId: String, status: String) {
        val prefs = getSharedPreferences("activity_log", Context.MODE_PRIVATE)
        val reports = (prefs.getStringSet("reports", emptySet()) ?: emptySet()).map { record ->
            if (record.startsWith("$reportId|")) "$record".substringBeforeLast('|') + "|$status" else record
        }.toSet()
        prefs.edit().putStringSet("reports", reports).apply()
        sendBroadcast(Intent("com.phishguard.ai.REPORT_UPDATE").setPackage(packageName))
    }

    private fun uploadToFirebase(url: String, reason: String, confidence: Float) {
        FirebaseSyncManager(applicationContext).uploadPhishingUrl(
            url = url,
            reason = reason,
            confidence = confidence,
            onSuccess = {
                Log.d(TAG, "URL dilaporkan ke komunitas: $url")
                runOnUiThread {
                    Toast.makeText(this, R.string.risk_reported, Toast.LENGTH_SHORT).show()
                }
            },
            onFailure = { err ->
                // Blokir lokal tetap berlaku meski unggahan gagal.
                Log.e(TAG, "Gagal upload ke Firebase: $err")
            }
        )
    }
}
