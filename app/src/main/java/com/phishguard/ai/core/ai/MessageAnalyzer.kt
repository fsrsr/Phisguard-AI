package com.phishguard.ai.core.ai

import android.content.Context
import android.util.Log

/**
 * Message Phishing Analyzer.
 *
 * Delegates analysis to AnalysisPipeline which follows the full workflow:
 * Extract URL+Number → Local DB → Server DB → AI Model → Result
 *
 * INTEGRASI:
 * - Dipanggil oleh SmsReceiver untuk SMS masuk.
 * - Dipanggil oleh PhishGuardService untuk pesan dari chat apps.
 *
 * TIM AI:
 * Untuk mengganti AI model, buat class yang implement AIModelProvider
 * lalu set di AnalysisPipeline.messageProvider.
 */
class MessageAnalyzer(private val context: Context) {

    private val TAG = "MessageAnalyzer"
    private val pipeline = AnalysisPipeline(context)

    /**
     * Menganalisis pesan teks untuk mendeteksi konten mencurigakan.
     *
     * @param message   Teks pesan yang akan dianalisis
     * @param sourceApp Nama aplikasi sumber (SMS, WhatsApp, dll)
     * @param onResult  Callback: (isSuspicious: Boolean, confidence: Float, reason: String)
     */
    fun analyzeMessage(message: String, sourceApp: String, onResult: (Boolean, Float, String) -> Unit) {
        Log.d(TAG, "Analyzing message from $sourceApp: ${message.take(50)}...")

        // Pakai pipeline BERLAPIS, bukan analyzeMessage biasa. Bedanya:
        // setiap URL di dalam pesan ikut diadu ke daftar putih resmi,
        // database phishing, dan blocklist global 4,1 juta domain —
        // bukan hanya dicocokkan persis. Tautan judol/phishing di
        // notifikasi WhatsApp sebelumnya lolos karena hanya teksnya
        // yang dinilai.
        pipeline.analyzeMessageLayers(message, "", sourceApp) { result ->
            val alasan = when (result.layer) {
                ThreatLayer.URL     -> "Pesan memuat tautan berbahaya: ${result.detectedValue}. ${result.reason}"
                ThreatLayer.NUMBER  -> "Pengirim terdaftar sebagai penipu. ${result.reason}"
                ThreatLayer.CONTENT -> result.reason
                null                -> result.reason
            }
            onResult(result.isThreat, result.confidence, alasan)
        }
    }

    fun release() {
        pipeline.release()
    }
}
