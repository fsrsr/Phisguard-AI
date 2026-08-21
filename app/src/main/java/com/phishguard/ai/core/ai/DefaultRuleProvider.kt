package com.phishguard.ai.core.ai

import android.content.Context
import android.util.Log

/**
 * Implementasi default rule-based untuk AIModelProvider.
 *
 * Menggunakan pattern matching sederhana sebagai fallback
 * sebelum AI model sesungguhnya diintegrasikan.
 *
 * Tim AI: Buat class baru yang implement AIModelProvider,
 * lalu set di AnalysisPipeline. Class ini akan tetap sebagai fallback.
 */
class DefaultRuleProvider : AIModelProvider {

    private val TAG = "DefaultRuleProvider"
    private var initialized = false

    // URL suspicious patterns
    private val suspiciousUrlPatterns = listOf(
        "login", "verify", "secure", "update-account", "free-gift",
        "hadiah", "menang", "undian", "klik-disini", "confirm",
        "verify-identity", "suspended", "blocked"
    )

    // Known safe domains (whitelist)
    private val safeDomains = listOf(
        "google.com", "facebook.com", "instagram.com", "whatsapp.com",
        "twitter.com", "youtube.com", "github.com", "microsoft.com",
        "apple.com", "bca.co.id", "bri.co.id", "mandiri.co.id",
        "bni.co.id", "btn.co.id"
    )

    // Message suspicious patterns
    private val suspiciousMessagePatterns = listOf(
        "surat tilang", "paket anda", "kurir J&T", "kurir sicepat", "undangan pernikahan",
        "tagihan bpln", "tagihan bpjs", "klik link ini", "verifikasi data", "pemblokiran rekening",
        "hadiah dari bca", "hadiah dari bri", "pemenang undian", "klaim hadiah", 
        "segera transfer", "login sekarang", "rekening anda dibekukan",
        "apk surat", "cek resi", "unduh aplikasi", "bantuan sosial"
    )

    // Voice fraud keywords (Indonesian common scam patterns)
    private val fraudVoiceKeywords = listOf(
        // Financial terms
        "transfer", "rekening", "saldo", "mutasi", "tabungan", "kredit", "pinjaman",
        // Prize/lottery scams
        "hadiah", "menang", "undian", "pemenang", "kupon", "voucher",
        // Verification scams
        "verifikasi", "konfirmasi", "aktivasi", "validasi", "update data",
        // Security credentials
        "otp", "kode otp", "pin", "password", "kata sandi", "cvv", "cvc",
        // Urgency tactics
        "segera", "cepat", "sekarang juga", "dalam 24 jam", "darurat", "penting",
        // Authority impersonation
        "polisi", "kepolisian", "cyber crime", "interpol", "pajak", "dirjen pajak",
        "bank indonesia", "bi", "ojk", "otoritas", "pejabat",
        // Threats
        "denda", "tilang", "sanksi", "blokir", "dibekukan", "ditangkap", "laporan polisi",
        // Social engineering
        "keluarga", "anak anda", "istri anda", "suami anda", "kecelakaan", "rumah sakit",
        // Package delivery scams
        "paket", "kiriman", "jne", "j&t", "sicepat", "pos indonesia",
        // Account suspension scams
        "dinonaktifkan", "suspended", "kadaluarsa", "expired", "pemblokiran",
        // Investment scams
        "investasi", "profit", "untung besar", "passive income", "binary option",
        // Government aid scams
        "bansos", "bantuan sosial", "subsidi", "dana pemerintah"
    )

    override fun initialize(context: Context) {
        initialized = true
        Log.d(TAG, "DefaultRuleProvider initialized (rule-based fallback)")
    }

    override fun isReady(): Boolean = initialized

    override fun analyze(input: AnalysisInput): AnalysisResult {
        return when (input.type) {
            InputType.URL -> analyzeUrl(input)
            InputType.MESSAGE -> analyzeMessage(input)
            InputType.VOICE_TEXT -> analyzeVoice(input)
        }
    }

    override fun release() {
        initialized = false
    }

    // --- Internal Analysis ---

    private fun analyzeUrl(input: AnalysisInput): AnalysisResult {
        val url = input.content.lowercase()
        Log.d(TAG, "Analyzing URL: ${url.take(80)}")

        // Check whitelist first
        if (safeDomains.any { url.contains(it) }) {
            return AnalysisResult.safe(0.95f, "URL matches known safe domain")
        }

        // Check suspicious patterns
        val matchedPattern = suspiciousUrlPatterns.firstOrNull { url.contains(it) }
        return if (matchedPattern != null) {
            AnalysisResult.threat(
                confidence = 0.75f,
                reason = "URL contains suspicious pattern: '$matchedPattern'",
                category = ThreatCategory.PHISHING
            )
        } else {
            AnalysisResult.safe(0.80f, "No suspicious patterns found in URL")
        }
    }

    private fun analyzeMessage(input: AnalysisInput): AnalysisResult {
        val message = input.content.lowercase()
        Log.d(TAG, "Analyzing message: ${message.take(50)}...")

        val matchedPattern = suspiciousMessagePatterns.firstOrNull { message.contains(it) }
        return if (matchedPattern != null) {
            AnalysisResult.threat(
                confidence = 0.70f,
                reason = "Message contains suspicious pattern: '$matchedPattern'",
                category = ThreatCategory.SCAM_MESSAGE
            )
        } else {
            AnalysisResult.safe(0.85f, "Message appears safe")
        }
    }

    private fun analyzeVoice(input: AnalysisInput): AnalysisResult {
        val text = input.content.lowercase()
        Log.d(TAG, "Analyzing voice: ${text.take(100)}...")

        // Count matched keywords
        val matchedKeywords = fraudVoiceKeywords.filter { text.contains(it) }
        val matchCount = matchedKeywords.size

        // Advanced scoring with context
        var score = 0f
        var reasons = mutableListOf<String>()

        // Financial + credentials = high risk
        val hasFinancial = matchedKeywords.any { it in listOf("transfer", "rekening", "saldo", "mutasi") }
        val hasCredentials = matchedKeywords.any { it in listOf("otp", "pin", "password", "cvv", "cvc") }
        if (hasFinancial && hasCredentials) {
            score += 0.50f
            reasons.add("Kombinasi istilah finansial + kredensial")
        }

        // Authority + threat = impersonation scam
        val hasAuthority = matchedKeywords.any { it in listOf("polisi", "pajak", "ojk", "bank indonesia") }
        val hasThreat = matchedKeywords.any { it in listOf("denda", "blokir", "ditangkap", "sanksi") }
        if (hasAuthority && hasThreat) {
            score += 0.45f
            reasons.add("Modus penyamaran otoritas + ancaman")
        }

        // Social engineering (family emergency)
        val hasFamilyEmergency = matchedKeywords.any { it in listOf("keluarga", "anak anda", "istri anda", "kecelakaan", "rumah sakit") }
        if (hasFamilyEmergency) {
            score += 0.40f
            reasons.add("Modus rekayasa sosial (darurat keluarga)")
        }

        // Urgency tactics
        val hasUrgency = matchedKeywords.any { it in listOf("segera", "cepat", "sekarang juga", "dalam 24 jam") }
        if (hasUrgency && matchCount >= 3) {
            score += 0.25f
            reasons.add("Tekanan waktu (urgency)")
        }

        // Prize/lottery scam
        val hasPrize = matchedKeywords.any { it in listOf("hadiah", "menang", "undian", "pemenang") }
        if (hasPrize) {
            score += 0.20f
            reasons.add("Modus hadiah/undian palsu")
        }

        // Base score from keyword count
        val baseScore = when {
            matchCount >= 5 -> 0.40f
            matchCount >= 3 -> 0.25f
            matchCount >= 2 -> 0.15f
            matchCount >= 1 -> 0.05f
            else -> 0.0f
        }
        score += baseScore

        // Cap at 1.0
        val confidence = minOf(score, 1.0f)

        return if (confidence >= 0.6f) {
            val reasonText = buildString {
                append("Terdeteksi $matchCount kata kunci penipuan")
                if (matchedKeywords.isNotEmpty()) {
                    append(": ${matchedKeywords.take(5).joinToString(", ")}")
                }
                if (reasons.isNotEmpty()) {
                    append("\n\nPola: ${reasons.joinToString("; ")}")
                }
            }
            AnalysisResult.threat(
                confidence = confidence,
                reason = reasonText,
                category = ThreatCategory.FRAUD_CALL
            )
        } else {
            AnalysisResult.safe(1.0f - confidence, "Percakapan normal")
        }
    }
}
