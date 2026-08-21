package com.phishguard.ai.core.ai

import android.content.Context
import android.util.Log
import com.phishguard.ai.data.db.PhishingDatabase
import kotlin.concurrent.thread

// ──────────────────────────────────────────────────────────────────────
// 3-Layer Message Phishing Pipeline Result
// Layer 1: URL  |  Layer 2: Contact/Number  |  Layer 3: AI NLP Content
// ──────────────────────────────────────────────────────────────────────
enum class ThreatLayer { URL, NUMBER, CONTENT }

data class LayeredResult(
    val isThreat: Boolean,
    val layer: ThreatLayer? = null,
    val detectedValue: String = "",   // URL atau Nomor yang terdeteksi
    val reason: String = "",
    val confidence: Float = 0f
) {
    companion object {
        fun safe() = LayeredResult(false)
        fun threat(layer: ThreatLayer, value: String, reason: String, confidence: Float = 1.0f) =
            LayeredResult(true, layer, value, reason, confidence)
    }
}

/**
 * Orchestrator untuk analisis phishing.
 *
 * Urutan pemeriksaan, dari yang paling tepercaya:
 * 1. Daftar putih domain resmi — MENANG atas semua sumber lain
 * 2. Database phishing lokal (URL persis, lalu per-host)
 * 3. Blocklist global Lyra (Bloom filter luring)
 * 4. Model AI / heuristik (AIModelProvider)
 * 5. Return result → pemanggil menangani Human-in-the-Loop
 *
 * Daftar putih sengaja didahulukan: entri dari laporan komunitas dan umpan
 * publik bisa keliru atau disuntik pihak lain, dan domain bank tidak boleh
 * bisa dijatuhkan oleh sumber semacam itu.
 *
 * Provider bisa di-swap kapan saja (plug and play):
 *   pipeline.urlProvider = TFLiteUrlProvider()
 */
class AnalysisPipeline(private val context: Context) {

    private val TAG = "AnalysisPipeline"

    // AI Providers — TFLite NLP untuk SMS, rule-based LSTM untuk URL
    var urlProvider: AIModelProvider = LstmUrlProvider()
    var messageProvider: AIModelProvider = TFLiteMessageProvider()  // NLP Classifier
    var voiceProvider: AIModelProvider = DefaultRuleProvider()

    // Database instance
    private val database: PhishingDatabase by lazy {
        PhishingDatabase.getInstance(context)
    }

    init {
        // Initialize default providers
        urlProvider.initialize(context)
        messageProvider.initialize(context)
        voiceProvider.initialize(context)
    }

    /**
     * Full analysis flow untuk URL (Web Phishing):
     * 1. Cek local phishing URL DB
     * 2. Cek official URL DB (whitelist)
     * 3. Run AI provider
     */
    fun analyzeUrl(
        url: String,
        source: String,
        pageText: String = "",
        callback: (AnalysisResult) -> Unit
    ) {
        thread {
            try {
                Log.d(TAG, "Analyzing URL: $url from $source")

                // Step 1: DAFTAR PUTIH RESMI — DIDAHULUKAN.
                //
                // Dulu pemeriksaan database phishing berjalan lebih dulu,
                // sehingga satu entri buruk dari laporan komunitas bisa
                // membuat bca.co.id divonis phishing untuk SEMUA pengguna.
                // Basis data komunitas ditulis tanpa autentikasi, jadi
                // siapa pun yang mengekstrak konfigurasi dari APK bisa
                // menyuntikkan domain bank ke sana.
                //
                // Domain resmi kini tidak bisa dijatuhkan oleh sumber mana
                // pun — komunitas, umpan publik, maupun blocklist global.
                val domain = extractDomain(url)
                val knownOfficial = database.officialUrlDao().findByDomain(domain)
                if (knownOfficial != null) {
                    Log.d(TAG, "URL cocok domain resmi: $domain")
                    callback(AnalysisResult.safe(1.0f, "Domain resmi: ${knownOfficial.organization}"))
                    return@thread
                }

                // Step 2: Cek database phishing lokal (URL persis)
                val knownPhishing = database.phishingUrlDao().findByUrl(url)
                if (knownPhishing != null) {
                    Log.d(TAG, "URL ada di database phishing lokal")
                    callback(AnalysisResult.threat(
                        confidence = 1.0f,
                        reason = "URL terdaftar dalam database phishing: ${knownPhishing.reason}",
                        category = ThreatCategory.PHISHING
                    ))
                    return@thread
                }

                // Step 2.5: Check local phishing DB by HOST (bukan hanya exact URL).
                // Feed ribuan URL (PhishTank/OpenPhish) tersimpan per-domain; query ini
                // menangkap subdomain/path variant yang tak match exact URL.
                // Host besar/berbagi-pakai dikecualikan dari pencocokan
                // per-domain: satu URL abusif yang menumpang di sana tidak
                // boleh menjatuhkan seluruh hostnya. URL persisnya sudah
                // ditangani Step 2 di atas.
                val knownByDomain = if (UrlRiskScorer.isSharedOrMajorHost(domain)) {
                    Log.d(TAG, "Host berbagi-pakai $domain — lewati pencocokan per-domain")
                    null
                } else {
                    database.phishingUrlDao().findByDomain(domain)
                }
                if (knownByDomain != null) {
                    Log.d(TAG, "Hostname ${extractDomain(url)} matched in phishing DB")
                    callback(AnalysisResult.threat(
                        confidence = knownByDomain.confidence.coerceAtLeast(0.9f),
                        reason = "Domain terdaftar database phishing: ${knownByDomain.reason}",
                        category = ThreatCategory.PHISHING
                    ))
                    return@thread
                }

                // Step 2.6: Blocklist Lyra (4,1 juta domain, luring via Bloom
                // filter). Ditaruh SETELAH whitelist domain resmi supaya
                // kekeliruan filter tidak pernah mengenai situs tepercaya.
                DomainBlocklist.get(context)?.let { blocklist ->
                    if (blocklist.contains(domain)) {
                        Log.d(TAG, "Domain $domain cocok di blocklist Lyra")
                        callback(AnalysisResult(
                            isThreat = true,
                            confidence = 0.95f,
                            reason = "Domain terdaftar di basis data ancaman global " +
                                    "(phishing, malware, atau judi online).",
                            threatType = ThreatCategory.PHISHING,
                            metadata = mapOf("level" to "DANGEROUS", "source" to "lyra")
                        ))
                        return@thread
                    }
                }

                // Step 3: Run AI provider
                val input = AnalysisInput(
                    type = InputType.URL,
                    content = url,
                    source = source,
                    metadata = if (pageText.isBlank()) emptyMap() else mapOf("pageText" to pageText)
                )
                val result = urlProvider.analyze(input)
                callback(result)

            } catch (e: Exception) {
                Log.e(TAG, "URL analysis error", e)
                callback(AnalysisResult.safe(0.5f, "Analysis error: ${e.message}"))
            }
        }
    }

    /**
     * Full analysis flow untuk Message (Message Phishing):
     * 1. Ekstrak URL dari pesan → cek DB
     * 2. Run AI provider pada message
     */
    fun analyzeMessage(message: String, source: String, callback: (AnalysisResult) -> Unit) {
        thread {
            try {
                Log.d(TAG, "Analyzing message from $source: ${message.take(50)}...")

                // Step 1: Ekstrak URL dari pesan lalu cek DB.
                // Domain resmi dilewati lebih dulu — alasan sama seperti di
                // analyzeUrl: entri komunitas tak boleh menjatuhkan bank.
                val urls = extractUrls(message)
                for (url in urls) {
                    if (database.officialUrlDao().findByDomain(extractDomain(url)) != null) continue
                    val knownPhishing = database.phishingUrlDao().findByUrl(url)
                    if (knownPhishing != null) {
                        callback(AnalysisResult.threat(
                            confidence = 1.0f,
                            reason = "Pesan mengandung URL phishing: $url",
                            category = ThreatCategory.SCAM_MESSAGE
                        ))
                        return@thread
                    }
                }

                // Step 2: Run AI provider on full message
                val input = AnalysisInput(
                    type = InputType.MESSAGE,
                    content = message,
                    source = source,
                    metadata = mapOf("extracted_urls" to urls.joinToString(","))
                )
                val result = messageProvider.analyze(input)
                callback(result)

            } catch (e: Exception) {
                Log.e(TAG, "Message analysis error", e)
                callback(AnalysisResult.safe(0.5f, "Analysis error: ${e.message}"))
            }
        }
    }

    /**
     * Full analysis flow untuk Voice (Voice Phishing):
     * 1. Run AI provider pada transkripsi
     */
    fun analyzeVoice(transcription: String, callback: (AnalysisResult) -> Unit) {
        thread {
            try {
                Log.d(TAG, "Analyzing voice: ${transcription.take(100)}...")

                val input = AnalysisInput(
                    type = InputType.VOICE_TEXT,
                    content = transcription,
                    source = "Phone"
                )
                val result = voiceProvider.analyze(input)
                callback(result)

            } catch (e: Exception) {
                Log.e(TAG, "Voice analysis error", e)
                callback(AnalysisResult.safe(0.5f, "Analysis error: ${e.message}"))
            }
        }
    }

    /**
     * Check phone number against local database.
     */
    fun checkPhoneNumber(number: String, callback: (AnalysisResult) -> Unit) {
        thread {
            try {
                val knownPhishing = database.phishingNumberDao().findByNumber(number)
                if (knownPhishing != null) {
                    callback(AnalysisResult.threat(
                        confidence = 1.0f,
                        reason = "Nomor terdaftar dalam database penipuan: ${knownPhishing.reason}",
                        category = ThreatCategory.FRAUD_CALL
                    ))
                } else {
                    callback(AnalysisResult.safe(0.5f, "Nomor tidak ditemukan di database"))
                }
            } catch (e: Exception) {
                Log.e(TAG, "Phone check error", e)
                callback(AnalysisResult.safe(0.5f, "Check error: ${e.message}"))
            }
        }
    }

    /**
     * Release all provider resources.
     */
    fun release() {
        urlProvider.release()
        messageProvider.release()
        voiceProvider.release()
    }

    // --- Helpers ---

    private fun extractDomain(url: String): String {
        return try {
            val cleaned = url.removePrefix("http://").removePrefix("https://").removePrefix("www.")
            cleaned.split("/").firstOrNull()?.split("?")?.firstOrNull() ?: url
        } catch (e: Exception) {
            url
        }
    }

    /**
     * ═══════════════════════════════════════════════════════════════
     * 3-LAYER MESSAGE PHISHING PIPELINE (sesuai arsitektur)
     * ═══════════════════════════════════════════════════════════════
     *
     * Layer 1 — URL Check:
     *   Ekstrak semua URL dari pesan → cek phishing URL DB → cek AI URL
     *   Jika threat → callback (HITL overlay)
     *
     * Layer 2 — Sender / Number Check:
     *   Nomor pengirim → cek Database phishing number
     *   Jika threat → callback (HITL overlay)
     *
     * Layer 3 — AI NLP Content Analysis:
     *   Full teks pesan ke TFLite message classifier
     *   Jika threat → callback (HITL overlay)
     *
     * Jika semua layer aman → callback LayeredResult.safe()
     */
    fun analyzeMessageLayers(
        message: String,
        sender: String = "",
        source: String,
        callback: (LayeredResult) -> Unit
    ) {
        thread {
            try {
                Log.d(TAG, "=== 3-Layer Message Analysis ===")
                Log.d(TAG, "Source: $source | Sender: $sender | Msg: ${message.take(60)}...")

                // ─────────────────────────────────────────────────────
                // LAYER 1: URL CHECK
                // ─────────────────────────────────────────────────────
                val urls = extractUrls(message)
                Log.d(TAG, "Layer 1: Found URLs = $urls")

                for (url in urls) {
                    // Daftar putih resmi didahulukan (lihat catatan di analyzeUrl).
                    if (database.officialUrlDao().findByDomain(extractDomain(url)) != null) {
                        Log.d(TAG, "Layer 1 ✅ Domain resmi: ${extractDomain(url)}")
                        continue
                    }

                    // Cek local phishing URL DB
                    val knownPhishing = database.phishingUrlDao().findByUrl(url)
                    if (knownPhishing != null) {
                        Log.w(TAG, "Layer 1 🔴 URL in local DB: $url")
                        callback(LayeredResult.threat(
                            ThreatLayer.URL, url,
                            "URL terdaftar sebagai phishing: ${knownPhishing.reason}"
                        ))
                        return@thread
                    }

                    val domain = extractDomain(url)

                    // Blocklist global Lyra — tautan di SMS/chat adalah jalur
                    // penipuan nomor satu, jadi diperiksa di sini juga.
                    if (DomainBlocklist.get(context)?.contains(domain) == true) {
                        Log.w(TAG, "Layer 1 🔴 $domain ada di blocklist Lyra")
                        callback(LayeredResult.threat(
                            ThreatLayer.URL, url,
                            "Domain terdaftar di basis data ancaman global.", 0.95f
                        ))
                        return@thread
                    }

                    // Analisis AI URL (LstmUrlProvider)
                    val urlInput = AnalysisInput(InputType.URL, url, source)
                    val urlResult = urlProvider.analyze(urlInput)
                    if (urlResult.isThreat) {
                        Log.w(TAG, "Layer 1 🔴 URL AI threat: $url | ${urlResult.reason}")
                        callback(LayeredResult.threat(
                            ThreatLayer.URL, url, urlResult.reason, urlResult.confidence
                        ))
                        return@thread
                    }
                }
                Log.d(TAG, "Layer 1 ✅ Semua URL aman atau tidak ada URL.")

                // ─────────────────────────────────────────────────────
                // LAYER 2: SENDER / NOMOR CHECK
                // ─────────────────────────────────────────────────────
                if (sender.isNotBlank()) {
                    val phoneNumber = extractPhoneNumber(sender)
                    Log.d(TAG, "Layer 2: Sender='$sender' | Phone='$phoneNumber'")

                    if (phoneNumber.isNotBlank()) {
                        val knownBadNumber = database.phishingNumberDao().findByNumber(phoneNumber)
                        if (knownBadNumber != null) {
                            Log.w(TAG, "Layer 2 🔴 Bad number: $phoneNumber")
                            callback(LayeredResult.threat(
                                ThreatLayer.NUMBER, phoneNumber,
                                "Nomor terdata sebagai penipu: ${knownBadNumber.reason}"
                            ))
                            return@thread
                        }
                    }
                }
                Log.d(TAG, "Layer 2 ✅ Sender aman.")

                // ─────────────────────────────────────────────────────
                // LAYER 3: AI NLP CONTENT ANALYSIS
                // ─────────────────────────────────────────────────────
                Log.d(TAG, "Layer 3: Running TFLite NLP...")
                val msgInput = AnalysisInput(InputType.MESSAGE, message, source)
                val nlpResult = messageProvider.analyze(msgInput)

                if (nlpResult.isThreat) {
                    Log.w(TAG, "Layer 3 🔴 NLP threat: ${nlpResult.reason}")
                    callback(LayeredResult.threat(
                        ThreatLayer.CONTENT, message.take(80),
                        nlpResult.reason, nlpResult.confidence
                    ))
                } else {
                    Log.d(TAG, "Layer 3 ✅ Pesan aman.")
                    callback(LayeredResult.safe())
                }

            } catch (e: Exception) {
                Log.e(TAG, "analyzeMessageLayers error", e)
                callback(LayeredResult.safe())
            }
        }
    }

    /**
     * Ekstrak nomor telepon dari string sender.
     * Mendukung format: +62857xxx, 08571xxx, "Farhan Telyu 62857xxx"
     */
    private fun extractPhoneNumber(text: String): String {
        val phoneRegex = Regex("[+]?[0-9]{8,15}")
        return phoneRegex.find(text)?.value ?: ""
    }

    /**
     * Ekstrak URL dari teks — mendukung URL dengan dan tanpa protokol.
     * Menangkap: https://bit.ly/... MAUPUN bca.100.juta.vercel.app
     */
    private fun extractUrls(text: String): List<String> {
        val urlPattern = Regex(
            """(https?://[\w\-.~:/?#\[\]@!${'$'}&'()*+,;=%]+|[\w\-]+\.(?:app|com|co\.id|net|org|id|info|xyz|biz|io|web\.id|vercel\.app|netlify\.app|github\.io)(?:/[\w\-.~:/?#\[\]@!${'$'}&'()*+,;=%]*)?)""",
            RegexOption.IGNORE_CASE
        )
        return urlPattern.findAll(text).map { it.value }.distinct().toList()
    }
}
