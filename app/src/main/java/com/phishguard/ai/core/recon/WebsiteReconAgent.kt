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

    /** Batas lompatan redirect yang diikuti sebelum menyerah (lihat resolveRedirects). */
    private val MAX_REDIRECT_HOPS = 5

    // Cloud AI endpoint — set null to use local-only analysis.
    // Configure with: WebsiteReconAgent.AI_ENDPOINT = "https://your-api.com/recon"
    var aiEndpoint: String? = "http://103.197.189.70:8888/v1/chat/completions"
    var aiApiKey: String? = ""

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
                // Ikuti redirect DULU — tanpa ini, URL shortener/redirector
                // (bit.ly, urlto.me, dst.) dinilai dari domain shortener-nya
                // sendiri, bukan dari situs sebenarnya yang dituju. Itu celah
                // paling gampang: shortener apa pun otomatis lolos analisis.
                val resolusi = resolveRedirects(url)
                val finalUrl = resolusi.finalUrl
                val domain = resolusi.finalDomain
                Log.d(TAG, "Starting recon for: $url -> final: $finalUrl (domain: $domain)")

                val findings = mutableListOf<Finding>()

                if (resolusi.hopCount > 0) {
                    val domainAsli = extractDomain(url)
                    // http→https atau bare-domain→www itu redirect KANONIK, dipakai
                    // hampir semua situs — bukan sinyal risiko. Yang berarti adalah
                    // lompat ke domain lain sama sekali (pola shortener/redirector).
                    val lintasDomain = rootDomain(domain) != rootDomain(domainAsli)
                    findings.add(Finding(
                        "Redirect Terdeteksi",
                        "URL asli ($domainAsli) redirect ${resolusi.hopCount}x " +
                            (if (lintasDomain) "ke DOMAIN LAIN sebelum sampai ke tujuan akhir:\n$finalUrl"
                             else "di dalam domain yang sama, ke:\n$finalUrl") +
                            if (resolusi.hopCount >= MAX_REDIRECT_HOPS) "\n\n⚠️ Batas ${MAX_REDIRECT_HOPS}x redirect tercapai — mungkin masih ada lompatan lanjutan yang tidak diikuti." else "",
                        if (lintasDomain) RiskLevel.MEDIUM else RiskLevel.SAFE
                    ))
                }

                // 1. URL structure analysis — pada URL TUJUAN AKHIR, bukan shortener-nya
                findings.addAll(analyzeUrlStructure(finalUrl, domain))

                // 2. Social engineering pattern detection
                val seIndicators = detectSocialEngineering(finalUrl)

                // 3. Domain reputation via DNS lookup
                findings.addAll(checkDns(domain))

                // 4. SSL certificate check
                findings.addAll(checkSsl(domain))

                // 5. Cloud AI analysis (optional — if endpoint configured)
                if (!aiEndpoint.isNullOrBlank()) {
                    findings.addAll(callAiRecon(finalUrl, domain))
                }

                // Compute overall risk
                val maxRisk = findings.maxByOrNull { it.risk.ordinal }?.risk ?: RiskLevel.SAFE
                val riskScore = computeRiskScore(findings, seIndicators)

                val result = ReconResult(
                    url = finalUrl,
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

    // ── Redirect Resolution ─────────────────────────────────────────────

    private data class RedirectResolution(
        val finalUrl: String,
        val finalDomain: String,
        val hopCount: Int
    )

    /**
     * Ikuti redirect HTTP (3xx + Location) sampai ke tujuan akhir, maksimal
     * [MAX_REDIRECT_HOPS] lompatan. Ini menutup celah shortener/redirector
     * apa pun — bukan cuma yang ada di [shortDomains] — karena yang dianalisis
     * jadi domain sebenarnya, bukan domain perantara.
     *
     * ponytail: hanya redirect HTTP (Location header). Redirect via
     * meta-refresh/JavaScript tidak terdeteksi — itu perlu render halaman
     * penuh (WebView), di luar cakupan perbaikan cepat ini.
     */
    private fun resolveRedirects(url: String): RedirectResolution {
        var current = url
        var hops = 0
        while (hops < MAX_REDIRECT_HOPS) {
            val next = try {
                val conn = (java.net.URL(current).openConnection() as java.net.HttpURLConnection).apply {
                    instanceFollowRedirects = false
                    connectTimeout = 6000
                    readTimeout = 6000
                    requestMethod = "GET"
                    setRequestProperty("User-Agent", "Mozilla/5.0 (Android) PhishGuard-Recon")
                }
                val code = conn.responseCode
                val location = conn.getHeaderField("Location")
                conn.disconnect()
                if (code in 300..399 && !location.isNullOrBlank()) {
                    java.net.URL(java.net.URL(current), location).toString()
                } else null
            } catch (e: Exception) {
                Log.d(TAG, "Redirect check berhenti di hop $hops untuk $current: ${e.message}")
                null
            }
            if (next == null || next == current) break
            current = next
            hops++
        }
        return RedirectResolution(current, extractDomain(current), hops)
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

                // Check cert age. Let's Encrypt (gratis, paling umum) auto-renew
                // tiap ~60 hari dari masa berlaku 90 hari — threshold 30 hari
                // membuat sepertiga situs HTTPS legit kena tag ini kapan saja
                // secara kebetulan. 14 hari jauh lebih spesifik ke pola
                // "domain+cert dibikin dadakan buat kampanye phishing".
                val ageDays = ((now.time - notBefore.time) / (1000 * 60 * 60 * 24)).toInt()
                if (ageDays < 14) {
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
        // Calls the VPS recon server: POST /v1/recon with {"url": "..."}
        // Returns comprehensive analysis including website fetch, DNS, SSL, AI

        private fun callAiRecon(url: String, domain: String): List<Finding> {
            val findings = mutableListOf<Finding>()
            try {
                val body = gson.toJson(mapOf("url" to url))

                val reconEndpoint = aiEndpoint!!.replace("/v1/chat/completions", "/v1/recon")
                val conn = java.net.URL(reconEndpoint).openConnection() as java.net.HttpURLConnection
                conn.apply {
                    requestMethod = "POST"
                    setRequestProperty("Content-Type", "application/json")
                    if (!aiApiKey.isNullOrBlank()) {
                        setRequestProperty("Authorization", "Bearer $aiApiKey")
                    }
                    connectTimeout = 60000
                    readTimeout = 60000
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

                Log.d(TAG, "Recon API response (code=$responseCode): ${responseBody.take(500)}")

                if (responseCode in 200..299 && responseBody.isNotBlank()) {
                    val json = JsonParser.parseString(responseBody).asJsonObject

                    // Extract overall risk from recon server
                    val risk = json.get("overall_risk")?.asString ?: "UNKNOWN"
                    val score = json.get("overall_score")?.asInt ?: 0
                    val reasons = json.get("reasons")?.asJsonArray?.map { it.asString }?.toList() ?: emptyList()

                    val aiRisk = json.get("ai")?.asJsonObject?.get("ai_risk")?.asString ?: risk
                    val aiScore = json.get("ai")?.asJsonObject?.get("ai_score")?.asInt ?: score
                    val aiReasons = json.get("ai")?.asJsonObject?.get("ai_reasons")?.asJsonArray?.map { it.asString }?.toList() ?: reasons
                    val aiSummary = json.get("ai")?.asJsonObject?.get("ai_summary")?.asString ?: ""
                    val aiBrand = json.get("ai")?.asJsonObject?.get("ai_brand_impersonation")?.asString
                    val aiForms = json.get("ai")?.asJsonObject?.get("ai_suspicious_forms")?.asJsonArray?.map { it.asString }?.toList() ?: emptyList()
                    val aiPatterns = json.get("ai")?.asJsonObject?.get("ai_se_patterns")?.asJsonArray?.map { it.asString }?.toList() ?: emptyList()

                    // Website data
                    val website = json.get("website")?.asJsonObject
                    val statusCode = website?.get("status_code")?.asInt
                    val title = website?.get("title")?.asString ?: ""
                    val fetchError = website?.get("fetch_error")?.asString

                    // SSL data
                    val ssl = json.get("ssl")?.asJsonObject
                    val sslValid = ssl?.get("valid")?.asBoolean ?: false
                    val sslIssuer = ssl?.get("issuer")?.asString ?: ""
                    val sslError = ssl?.get("error")?.asString

                    // DNS data
                    val dns = json.get("dns")?.asJsonObject
                    val aRecords = dns?.get("a_records")?.asJsonArray?.map { it.asString }?.toList() ?: emptyList()
                    val dnsError = dns?.get("error")?.asString

                    // Content data
                    val content = json.get("content")?.asJsonObject
                    val formCount = content?.get("form_count")?.asInt ?: 0
                    val passwordForms = content?.get("password_forms")?.asInt ?: 0
                    val iframeCount = content?.get("iframe_count")?.asInt ?: 0

                    // Determine risk level
                    val riskLevel = when (aiRisk.uppercase()) {
                        "CRITICAL" -> RiskLevel.CRITICAL
                        "HIGH" -> RiskLevel.HIGH
                        "MEDIUM" -> RiskLevel.MEDIUM
                        else -> RiskLevel.LOW
                    }

                    // Get conclusion from AI (simple language for non-tech users)
                    val aiConclusion = json.get("ai")?.asJsonObject?.get("ai_conclusion")?.asString ?: ""

                    // Main AI analysis finding
                    val summary = buildString {
                        append("🤖 AI Analisis (Full Website Recon)\n")
                        append("Risk: $aiRisk | Score: $aiScore/100\n")
                        if (aiBrand != null) append("Brand tiruan: $aiBrand\n")
                        if (statusCode != null) append("HTTP: $statusCode\n")
                        if (title.isNotBlank()) append("Title: $title\n")
                        append("SSL: ${if (sslValid) "Valid ($sslIssuer)" else "Invalid/Tidak ada"} \n")
                        if (aRecords.isNotEmpty()) append("IP: ${aRecords.joinToString(", ")} \n")
                        append("Forms: $formCount (password: $passwordForms) | Iframes: $iframeCount\n")
                        if (fetchError != null) append("Fetch error: $fetchError\n")
                        if (sslError != null) append("SSL error: $sslError\n")
                        if (dnsError != null) append("DNS error: $dnsError\n")
                        if (aiConclusion.isNotBlank()) {
                            append("\n📋 KESIMPULAN: $aiConclusion\n")
                        } else if (aiSummary.isNotBlank()) {
                            append("\nDetail: ${aiSummary.take(1000)}\n")
                        }
                    }

                    findings.add(Finding("AI Full Recon", summary, riskLevel))

                    // Add reasons
                    for (reason in aiReasons) {
                        findings.add(Finding("AI Reason", reason, riskLevel))
                    }

                    // Brand impersonation
                    if (aiBrand != null && aiBrand.isNotBlank()) {
                        findings.add(Finding("Brand Tiruan", "Diduga menirukan: $aiBrand", RiskLevel.HIGH))
                    }

                    // Suspicious forms
                    for (form in aiForms) {
                        findings.add(Finding("Form Mencurigakan", form, RiskLevel.HIGH))
                    }

                    // SE patterns
                    for (pattern in aiPatterns) {
                        findings.add(Finding("Social Engineering", pattern, RiskLevel.MEDIUM))
                    }

                    // SSL info
                    if (!sslValid) {
                        findings.add(Finding("SSL Invalid", "Sertifikat SSL tidak valid: ${sslError ?: "unknown"}", RiskLevel.HIGH))
                    } else if (sslIssuer.isNotBlank()) {
                        findings.add(Finding("SSL Info", "Issuer: $sslIssuer", RiskLevel.LOW))
                    }

                } else {
                    findings.add(Finding("Recon Error", "Server recon gagal: HTTP $responseCode - $responseBody", RiskLevel.MEDIUM))
                }

            } catch (e: Exception) {
                Log.e(TAG, "Recon error", e)
                findings.add(Finding("Error", "Recon exception: ${e.message ?: "unknown"}", RiskLevel.MEDIUM))
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
        val base = when (risk) {
            RiskLevel.CRITICAL -> "⚠️ SANGAT BERBAHAYA! Situs ini menunjukkan banyak indikator penipuan. JANGAN masukkan data apapun."
            RiskLevel.HIGH -> "⚠️ BERBAHAYA. Situs ini memiliki beberapa ciri phishing. Disarankan untuk tidak melanjutkan."
            RiskLevel.MEDIUM -> "🔍 PERLU DIPERIKSA. Beberapa indikator mencurigakan ditemukan. Hati-hati sebelum memasukkan data."
            RiskLevel.LOW -> "ℹ️ RENDAH RISIKO. Beberapa hal perlu diperhatikan, tapi tidak ada ancaman signifikan."
            RiskLevel.SAFE -> "✅ AMAN. Tidak ditemukan indikator phishing atau social engineering yang signifikan."
        }
        // callAiRecon gagal terhubung (server cloud down/URL tunnel kadaluarsa) → hasil di atas
        // HANYA dari heuristik lokal dangkal (TLD/DNS/SSL), belum analisis konten AI yang kritis.
        // Jangan biarkan itu tersembunyi di balik satu Finding — pengguna awam perlu tahu batasnya.
        val aiUnreachable = findings.any { it.category == "Error" || it.category == "Recon Error" }
        return if (aiUnreachable) {
            "$base\n\n⚠️ Catatan: server AI cloud tidak dapat dihubungi saat ini — ini baru hasil pengecekan lokal dasar (TLD, DNS, SSL), BELUM analisis konten mendalam. Jangan jadikan \"aman\" di atas sebagai kepastian."
        } else base
    }

    private fun extractDomain(url: String): String {
        return url.removePrefix("http://").removePrefix("https://").removePrefix("www.")
            .substringBefore('/').substringBefore('?').substringBefore('#')
    }

    /**
     * Domain inti yang dipakai membandingkan "situs sama atau lompat ke lain
     * sama sekali" untuk finding redirect. Naif (2 label terakhir) — tidak
     * paham eTLD majemuk seperti .co.id/.co.uk, sama seperti heuristik lain
     * di file ini. Cukup untuk kasus umum (google.com vs www.google.com).
     */
    private fun rootDomain(domain: String): String {
        val parts = domain.removePrefix("www.").split('.')
        return if (parts.size <= 2) parts.joinToString(".") else parts.takeLast(2).joinToString(".")
    }
}
