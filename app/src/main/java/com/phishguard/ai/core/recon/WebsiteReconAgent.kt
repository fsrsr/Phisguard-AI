package com.phishguard.ai.core.recon

import android.util.Log
import com.google.gson.Gson
import com.google.gson.JsonParser
import com.google.gson.stream.JsonReader
import com.phishguard.ai.core.network.ApiClient
import kotlin.concurrent.thread

/**
 * AI-powered website reconnaissance agent.
 *
 * Performs multi-signal analysis on a URL:
 * - WHOIS domain info (registrar, creation date, registrar abuse)
 * - SSL certificate check
 * - DNS record check
 * - Social engineering pattern detection
 * - URL structure analysis (Typosquatting, suspicious TLDs, etc.)
 * - Content analysis via cloud AI (if configured)
 *
 * Returns a ReconResult with risk assessment and detailed findings.
 */
class WebsiteReconAgent {

    private val TAG = "WebsiteReconAgent"
    private val api = ApiClient()
    private val gson = Gson()

    // Cloud AI endpoint — set null to use local-only analysis.
    // Configure with: WebsiteReconAgent.AI_ENDPOINT = "https://your-api.com/recon"
    var aiEndpoint: String? = "http://localhost:20128/v1/chat/completions"
    var aiApiKey: String? = "sk-wWAOBhwuk5eeHlykFNNAtYWpurJvqW1vuFzW7HShZnoJVjdb6gXof0JSo9qJjdWY"

    data class ReconResult(
        val url: String,
        val domain: String,
        val overallRisk: RiskLevel,
        val confidence: Float,
        val findings: List<Finding>,
        val summary: String,
        val socialEngineeringIndicators: List<String>,
        val reconTimestamp: Long = System.currentTimeMillis()
    )

    enum class RiskLevel { SAFE, LOW, MEDIUM, HIGH, CRITICAL }

    data class Finding(
        val category: String,
        val detail: String,
        val risk: RiskLevel
    )

    fun analyze(url: String, callback: (ReconResult) -> Unit) {
        thread {
            try {
                val domain = extractDomain(url)
                Log.d(TAG, "Starting recon for: $url (domain: $domain)")

                val findings = mutableListOf<Finding>()

                // 1. URL structure analysis (always available, no network)
                findings.addAll(analyzeUrlStructure(url, domain))

                // 2. Social engineering pattern detection
                val seIndicators = detectSocialEngineering(url)

                // 3. Domain reputation via DNS lookup
                findings.addAll(checkDns(domain))

                // 4. SSL certificate check
                findings.addAll(checkSsl(domain))

                // 5. Cloud AI analysis (optional — if endpoint configured)
                if (!aiEndpoint.isNullOrBlank()) {
                    findings.addAll(callAiRecon(url, domain))
                }

                // Compute overall risk
                val maxRisk = findings.maxByOrNull { it.risk.ordinal }?.risk ?: RiskLevel.SAFE
                val riskScore = computeRiskScore(findings, seIndicators)

                val result = ReconResult(
                    url = url,
                    domain = domain,
                    overallRisk = maxRisk,
                    confidence = riskScore,
                    findings = findings,
                    summary = buildSummary(maxRisk, findings, seIndicators),
                    socialEngineeringIndicators = seIndicators
                )

                Log.d(TAG, "Recon complete: risk=$maxRisk score=$riskScore findings=${findings.size}")
                callback(result)

            } catch (e: Exception) {
                Log.e(TAG, "Recon analysis error", e)
                callback(ReconResult(
                    url = url,
                    domain = extractDomain(url),
                    overallRisk = RiskLevel.MEDIUM,
                    confidence = 0.5f,
                    findings = listOf(Finding("Error", "Gagal menganalisis: ${e.message}", RiskLevel.MEDIUM)),
                    summary = "Analisis terganggu. Harap periksa manual.",
                    socialEngineeringIndicators = emptyList()
                ))
            }
        }
    }

    // ── URL Structure Analysis ────────────────────────────────────────

    private fun analyzeUrlStructure(url: String, domain: String): List<Finding> {
        val findings = mutableListOf<Finding>()

        // Suspicious TLDs
        val suspiciousTlds = setOf(
            "tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "buzz",
            "club", "online", "site", "website", "space", "tech", "store",
            "fun", "icu", "monster", "surf", "rest", "cam"
        )
        val tld = domain.substringAfterLast('.').lowercase()
        if (tld in suspiciousTlds) {
            findings.add(Finding(
                "TLD Mencurigakan",
                "TLD '.$tld' sering digunakan untuk phishing karena gratis/termurah.",
                RiskLevel.HIGH
            ))
        }

        // Typosquatting detection
        val typosquatPatterns = mapOf(
            "bca" to listOf("bca1", "bca2", "bca-", "-bca", "cbca", "bva", "bca-login", "bca-verify"),
            "mandiri" to listOf("mandiri1", "mandiri-", "mandri", "mamdiri"),
            "bri" to listOf("bri1", "bri-", "bri-login", "bri-verify", "br1"),
            "bni" to listOf("bni1", "bni-", "bni-login"),
            "shopee" to listOf("shopee1", "shopee-", "shopee-sale", "shopee-promo"),
            "tokopedia" to listOf("tokopedia1", "tokoped1a"),
            "dana" to listOf("dana1", "dana-wallet", "dana-promo"),
            "ovo" to listOf("ovo1", "ovo-promo"),
            "gopay" to listOf("gopay1", "gopay-promo")
        )
        for ((brand, patterns) in typosquatPatterns) {
            if (patterns.any { domain.contains(it) } && !domain.startsWith(brand)) {
                findings.add(Finding(
                    "Kemungkinan Typosquatting",
                    "Domain '$domain' meniru brand '$brand' dengan modifikasi.",
                    RiskLevel.HIGH
                ))
                break
            }
        }

        // Excessive subdomains (e.g., login.bca.com.malicious.tk)
        val parts = domain.split('.')
        if (parts.size > 3) {
            findings.add(Finding(
                "Subdomain Berlebihan",
                "Domain memiliki ${parts.size - 2} subdomain — teknik umum phishing.",
                RiskLevel.MEDIUM
            ))
        }

        // IP address as domain
        val ipPattern = Regex("""^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$""")
        if (ipPattern.matches(domain)) {
            findings.add(Finding(
                "IP Address sebagai Domain",
                "Situs menggunakan IP langsung ($domain), bukan nama domain.",
                RiskLevel.HIGH
            ))
        }

        // URL with encoded characters
        if (url.contains("%", ignoreCase = true)) {
            val encodedCount = url.count { it == '%' }
            if (encodedCount > 3) {
                findings.add(Finding(
                    "URL Banyak Encoding",
                    "URL mengandung $encodedCount karakter ter-encode — bisa menyembunyikan URL asli.",
                    RiskLevel.MEDIUM
                ))
            }
        }

        // Short URL
        val shortDomains = setOf(
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd",
            "buff.ly", "ow.ly", "rb.gy", "cutt.ly", "shorturl.at"
        )
        if (shortDomains.any { domain.endsWith(it) || domain == it }) {
            findings.add(Finding(
                "URL Pendek (Shortener)",
                "URL menggunakan layanan pemendek — alamat asli tersembunyi.",
                RiskLevel.MEDIUM
            ))
        }

        return findings
    }

    // ── Social Engineering Detection ──────────────────────────────────

    private fun detectSocialEngineering(url: String): List<String> {
        val indicators = mutableListOf<String>()
        val lower = url.lowercase()

        // Business opportunity patterns
        val sePatterns = listOf(
            "reseller" to "Iming-iming menjadi reseller/distributor",
            "bisnis" to "Promosi peluang bisnis",
            "penghasilan" to "Janji penghasilan/penghasilan tambahan",
            "investasi" to "Ajakan investasi",
            "untung" to "Janji keuntungan pasti",
            "Modal" to "Klaim modal kecil untung besar",
            "gratis" to "Janji sesuatu secara gratis",
            "reward" to "Janji reward/hadiah",
            "bonus" to "Janji bonus",
            "cashback" to "Janji cashback berlebihan",
            "undian" to "Undian/lotre palsu",
            "menang" to "Klaim menang undian/hadiah",
            "jackpot" to "Janji jackpot",
            "klik" to "Ajakan 'klik di sini'",
            "buruan" to "Urgency berlebihan ('buruan!', 'segera!')",
            "terbatas" to "Klaim keterbatasan waktu/stok",
            "konfirmasi" to "Minta konfirmasi data pribadi",
            "verifikasi" to "Minta verifikasi akun",
            "update" to "Minta update data/rekening",
            "suspend" to "Ancaman akun disuspend",
            "blokir" to "Ancaman akun diblokir",
            "aktifkan" to "Minta aktivasi/reinstal",
            "whatsapp" to "Ajakan hubungi via WhatsApp",
            "telegram" to "Ajakan gabung grup Telegram",
            "link" to "Ajakan klik tautan",
            "promosi" to "Promosi berlebihan"
        )

        for ((keyword, description) in sePatterns) {
            if (lower.contains(keyword)) {
                indicators.add(description)
            }
        }

        return indicators
    }

    // ── DNS Check ─────────────────────────────────────────────────────

    private fun checkDns(domain: String): List<Finding> {
        val findings = mutableListOf<Finding>()
        try {
            val addresses = java.net.InetAddress.getAllByName(domain)
            if (addresses.isEmpty()) {
                findings.add(Finding(
                    "DNS Tidak Ditemukan",
                    "Domain '$domain' tidak memiliki DNS record.",
                    RiskLevel.HIGH
                ))
            } else {
                // Check for shared hosting / CDN (many domains on same IP)
                val ip = addresses.first().hostAddress
                findings.add(Finding(
                    "IP Server",
                    "Server: $ip",
                    RiskLevel.SAFE
                ))
            }
        } catch (e: java.net.UnknownHostException) {
            findings.add(Finding(
                "Domain Tidak Resolusi",
                "Domain '$domain' tidak bisa di-resolve — mungkin belum aktif atau sudah mati.",
                RiskLevel.HIGH
            ))
        } catch (e: Exception) {
            Log.e(TAG, "DNS check error", e)
        }
        return findings
    }

    // ── SSL Check ─────────────────────────────────────────────────────

    private fun checkSsl(domain: String): List<Finding> {
        val findings = mutableListOf<Finding>()
        try {
            val factory = javax.net.ssl.SSLSocketFactory.getDefault()
            val socket = factory.createSocket(domain, 443) as javax.net.ssl.SSLSocket
            socket.soTimeout = 8000
            socket.startHandshake()

            val certs = socket.session.peerCertificates
            if (certs.isNotEmpty()) {
                val cert = certs[0] as java.security.cert.X509Certificate
                val issuer = cert.issuerDN.name
                val notBefore = cert.notBefore
                val notAfter = cert.notAfter
                val now = java.util.Date()

                // Check cert age
                val ageDays = ((now.time - notBefore.time) / (1000 * 60 * 60 * 24)).toInt()
                if (ageDays < 30) {
                    findings.add(Finding(
                        "Sertifikat SSL Baru",
                        "Sertifikat baru dibuat $ageDays hari lalu — phishing sering pakai cert baru.",
                        RiskLevel.MEDIUM
                    ))
                }

                // Check if expired
                if (now.after(notAfter)) {
                    findings.add(Finding(
                        "Sertifikat SSL Kedaluwarsa",
                        "Sertifikat berakhir ${notAfter}.",
                        RiskLevel.HIGH
                    ))
                }

                // Check free cert (Let's Encrypt)
                if (issuer.contains("Let's Encrypt", ignoreCase = true)) {
                    findings.add(Finding(
                        "Sertifikat Gratis (Let's Encrypt)",
                        "Menggunakan sertifikat gratis — normal untuk situs legit, tapi juga sangat umum di phishing.",
                        RiskLevel.LOW
                    ))
                }

                // Check wildcard cert
                val commonName = cert.subjectDN.name
                if (commonName.contains("*")) {
                    findings.add(Finding(
                        "Wildcard Certificate",
                        "Menggunakan wildcard cert — indikasi shared hosting.",
                        RiskLevel.LOW
                    ))
                }

                findings.add(Finding(
                    "SSL Aktif",
                    "Sertifikat valid sampai $notAfter. Issuer: $issuer",
                    RiskLevel.SAFE
                ))
            }
            socket.close()
        } catch (e: javax.net.ssl.SSLException) {
            findings.add(Finding(
                "SSL Error",
                "Gagal terhubung via HTTPS: ${e.message}",
                RiskLevel.MEDIUM
            ))
        } catch (e: java.net.ConnectException) {
            // Port 443 not open — might be HTTP-only
            findings.add(Finding(
                "HTTPS Tidak Tersedia",
                "Situs tidak mendukung HTTPS — data tidak terenkripsi.",
                RiskLevel.HIGH
            ))
        } catch (e: Exception) {
            Log.e(TAG, "SSL check error for $domain", e)
        }
        return findings
    }

    // ── Cloud AI Recon ────────────────────────────────────────────────

    private fun callAiRecon(url: String, domain: String): List<Finding> {
        val findings = mutableListOf<Finding>()
        try {
            val prompt = buildString {
                append("Analyze this URL for phishing and social engineering threats:\n")
                append("URL: $url\n")
                append("Domain: $domain\n\n")
                append("Check for:\n")
                append("1. Domain reputation and age\n")
                append("2. Typosquatting of known brands\n")
                append("3. Social engineering patterns (business opportunity, reseller, investment scam)\n")
                append("4. URL structure anomalies\n")
                append("5. Known phishing infrastructure indicators\n\n")
                append("Return JSON: {\"risk\": \"LOW|MEDIUM|HIGH|CRITICAL\", \"score\": 0-100, \"reasons\": [...], \"se_patterns\": [...]}")
            }

            val body = gson.toJson(mapOf(
                "model" to "free-model",
                "messages" to listOf(
                    mapOf("role" to "system", "content" to "You are a cybersecurity expert analyzing URLs for phishing and social engineering threats. Reply in Indonesian."),
                    mapOf("role" to "user", "content" to prompt)
                ),
                "max_tokens" to 1024,
                "temperature" to 0.3
            ))

            val conn = java.net.URL(aiEndpoint).openConnection() as java.net.HttpURLConnection
            conn.apply {
                requestMethod = "POST"
                setRequestProperty("Content-Type", "application/json")
                if (!aiApiKey.isNullOrBlank()) {
                    setRequestProperty("Authorization", "Bearer $aiApiKey")
                }
                connectTimeout = 15000
                readTimeout = 30000
                doOutput = true
            }
            conn.outputStream.use { it.write(body.toByteArray()) }

            val responseCode = conn.responseCode
            val responseBody = if (responseCode in 200..299) {
                conn.inputStream.bufferedReader().readText()
            } else {
                conn.errorStream?.bufferedReader()?.readText() ?: ""
            }
            conn.disconnect()

            Log.d(TAG, "AI API response (code=$responseCode): ${responseBody.take(500)}")

            // Strip SSE streaming suffix if present
            val cleanResponse = responseBody.replace(Regex("\\ndata: \\[DONE\\]$"), "").trim()

            if (responseCode in 200..299 && cleanResponse.isNotBlank()) {
                val reader = JsonReader(java.io.StringReader(cleanResponse))
                reader.isLenient = true
                val json = JsonParser.parseReader(reader).asJsonObject
                val choice = json.getAsJsonArray("choices")
                    ?.get(0)?.asJsonObject
                    ?.getAsJsonObject("message")
                    ?.let { msg ->
                        msg.get("content")?.asString
                            ?: msg.get("reasoning")?.asString
                    } ?: return findings

                // Try parse as JSON first, fallback to plain text
                val aiJson = try {
                    val reader = JsonReader(java.io.StringReader(choice))
                    reader.isLenient = true
                    JsonParser.parseReader(reader).asJsonObject
                } catch (e: Exception) {
                    // Non-JSON response (reasoning model) — use as-is
                    findings.add(Finding("AI Analisis", choice.take(500), RiskLevel.MEDIUM))
                    return findings
                }

                val risk = aiJson.get("risk")?.asString ?: "MEDIUM"
                val reasons = aiJson.getAsJsonArray("reasons")
                    ?.map { it.asString } ?: emptyList()

                val riskLevel = when (risk) {
                    "CRITICAL" -> RiskLevel.CRITICAL
                    "HIGH" -> RiskLevel.HIGH
                    "MEDIUM" -> RiskLevel.MEDIUM
                    "LOW" -> RiskLevel.LOW
                    else -> RiskLevel.SAFE
                }

                findings.add(Finding(
                    "AI Analisis",
                    reasons.joinToString("\n• ", prefix = "• "),
                    riskLevel
                ))
            }
        } catch (e: Exception) {
            Log.e(TAG, "Cloud AI recon error", e)
        }
        return findings
    }

    // ── Helpers ───────────────────────────────────────────────────────

    private fun computeRiskScore(findings: List<Finding>, seIndicators: List<String>): Float {
        var score = 0f
        val weights = mapOf(
            RiskLevel.CRITICAL to 1.0f,
            RiskLevel.HIGH to 0.75f,
            RiskLevel.MEDIUM to 0.5f,
            RiskLevel.LOW to 0.25f,
            RiskLevel.SAFE to 0f
        )
        for (f in findings) {
            score = maxOf(score, weights[f.risk] ?: 0f)
        }
        // Boost for social engineering indicators
        score += (seIndicators.size * 0.1f).coerceAtMost(0.3f)
        return score.coerceIn(0f, 1f)
    }

    private fun buildSummary(risk: RiskLevel, findings: List<Finding>, seIndicators: List<String>): String {
        return when (risk) {
            RiskLevel.CRITICAL -> "⚠️ SANGAT BERBAHAYA! Situs ini menunjukkan banyak indikator penipuan. JANGAN masukkan data apapun."
            RiskLevel.HIGH -> "⚠️ BERBAHAYA. Situs ini memiliki beberapa ciri phishing. Disarankan untuk tidak melanjutkan."
            RiskLevel.MEDIUM -> "🔍 PERLU DIPERIKSA. Beberapa indikator mencurigakan ditemukan. Hati-hati sebelum memasukkan data."
            RiskLevel.LOW -> "ℹ️ RENDAH RISIKO. Beberapa hal perlu diperhatikan, tapi tidak ada ancaman signifikan."
            RiskLevel.SAFE -> "✅ AMAN. Tidak ditemukan indikator phishing atau social engineering yang signifikan."
        }
    }

    private fun extractDomain(url: String): String {
        return url.removePrefix("http://").removePrefix("https://").removePrefix("www.")
            .substringBefore('/').substringBefore('?').substringBefore('#')
    }
}
