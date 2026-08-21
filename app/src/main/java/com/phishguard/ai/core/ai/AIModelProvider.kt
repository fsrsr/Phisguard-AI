package com.phishguard.ai.core.ai

import android.content.Context

/**
 * Interface generic untuk semua AI model.
 *
 * Tim AI implement interface ini dengan backend apapun:
 * - TFLite, ONNX, Cloud API (Gemini/OpenAI), rule-based, dll.
 *
 * Contoh implementasi:
 *   class TFLiteUrlProvider : AIModelProvider { ... }
 *   class GeminiApiProvider : AIModelProvider { ... }
 *   class DefaultRuleProvider : AIModelProvider { ... }  // sudah tersedia
 *
 * Cara integrasi:
 *   pipeline.urlProvider = TFLiteUrlProvider()
 *   // Done — plug and play
 */
interface AIModelProvider {

    /**
     * Inisialisasi model/resource yang dibutuhkan.
     * Dipanggil sekali saat provider pertama kali digunakan.
     */
    fun initialize(context: Context)

    /**
     * Cek apakah provider sudah siap digunakan.
     * Return false jika model belum di-load atau error.
     */
    fun isReady(): Boolean

    /**
     * Analisis input dan return hasil.
     * HARUS dipanggil dari background thread jika melakukan network/heavy computation.
     */
    fun analyze(input: AnalysisInput): AnalysisResult

    /**
     * Bersihkan resource (model, connection, dll).
     * Dipanggil saat provider tidak lagi digunakan.
     */
    fun release()
}

/**
 * Input untuk analisis AI.
 */
data class AnalysisInput(
    val type: InputType,
    val content: String,          // URL / message text / transkripsi suara
    val source: String,           // Chrome, WhatsApp, SMS, Phone, dll
    val metadata: Map<String, String> = emptyMap()   // Data tambahan jika diperlukan
)

/**
 * Hasil analisis AI.
 */
data class AnalysisResult(
    val isThreat: Boolean,
    val confidence: Float,        // 0.0 - 1.0
    val reason: String,
    val threatType: ThreatCategory,
    val metadata: Map<String, String> = emptyMap()
) {
    companion object {
        /** Helper untuk membuat result SAFE */
        fun safe(confidence: Float = 0.95f, reason: String = "No threat detected") =
            AnalysisResult(false, confidence, reason, ThreatCategory.SAFE)

        /** Helper untuk membuat result THREAT */
        fun threat(
            confidence: Float,
            reason: String,
            category: ThreatCategory = ThreatCategory.PHISHING
        ) = AnalysisResult(true, confidence, reason, category)
    }
}

/**
 * Tipe input yang didukung.
 */
enum class InputType {
    URL,            // URL dari browser
    MESSAGE,        // Pesan teks (SMS, chat)
    VOICE_TEXT      // Transkripsi suara dari panggilan
}

/**
 * Kategori ancaman yang terdeteksi.
 */
enum class ThreatCategory {
    PHISHING,       // Web/URL phishing
    SCAM_MESSAGE,   // Pesan penipuan
    FRAUD_CALL,     // Panggilan penipuan
    SAFE            // Aman
}
