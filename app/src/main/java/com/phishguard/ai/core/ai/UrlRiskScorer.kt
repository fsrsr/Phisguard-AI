package com.phishguard.ai.core.ai

import kotlin.math.abs

/**
 * Penilai risiko URL — agregasi sinyal berbobot, bukan rantai if-block.
 *
 * ALASAN DESAIN (fix false-positive):
 * Versi lama memblokir begitu SATU aturan cocok — kata "login" di path,
 * 2 tanda hubung di domain, TLD ".shop"/".online". Akibatnya situs normal
 * (`toko-kopi-enak.com`, `stackoverflow.com/questions/update`, tiap situs
 * yang punya halaman /login) ikut diblokir.
 *
 * Di sini setiap sinyal hanya MENYUMBANG bobot. Hanya akumulasi yang
 * melewati ambang yang memicu peringatan, dan hanya akumulasi tinggi yang
 * memblokir layar. Satu sinyal lemah tidak pernah cukup.
 *
 * Pure Kotlin (tanpa dependensi Android) supaya bisa diuji langsung —
 * lihat app/src/test/java/com/phishguard/ai/core/ai/UrlRiskScorerTest.kt
 */
object UrlRiskScorer {

    /** Di bawah SUSPICIOUS = diam. SUSPICIOUS = notifikasi. DANGEROUS = blokir layar penuh. */
    const val THRESHOLD_SUSPICIOUS = 0.55f
    const val THRESHOLD_DANGEROUS  = 0.80f

    enum class Level { SAFE, SUSPICIOUS, DANGEROUS }

    data class Signal(val label: String, val weight: Float)

    data class Verdict(
        val score: Float,
        val signals: List<Signal>,
        val level: Level,
        val hostname: String,
        val registrable: String
    ) {
        /** Alasan yang dibaca pengguna: sinyal terkuat lebih dulu, maksimal 3. */
        val reason: String
            get() = if (signals.isEmpty()) "Tidak ada indikasi phishing."
            else signals.sortedByDescending { it.weight }.take(3)
                .joinToString(". ") { it.label } + "."
    }

    // ── Daftar acuan ────────────────────────────────────────────────────

    /**
     * TLD yang benar-benar disalahgunakan — DIKALIBRASI DARI DATA, bukan
     * tebakan. Dihitung oleh tools/build_blocklist.py sebagai lift: pangsa
     * TLD di 4,1 juta domain jahat (Lyra) dibagi pangsanya di Tranco top 1M.
     * Ambang lift ≥ 8×. Lihat tools/blocklist_report.md untuk angkanya.
     *
     * Beberapa terlihat tidak berbahaya (.digital, .store, .site) tapi
     * memang terbukti disalahgunakan berlipat kali. Itu aman diadopsi
     * KARENA arsitektur skoring baru: TLD hanya menyumbang 0,30 dan tidak
     * pernah cukup untuk memblokir sendirian.
     */
    private val CHEAP_TLDS = setOf(
        "tk", "gdn", "stream", "beer", "review", "digital", "boats", "loan",
        "motorcycles", "irish", "gq", "autos", "click", "homes", "sbs", "lol",
        "christmas", "cf", "forum", "beauty", "rest", "pics", "yoga", "college",
        "cyou", "makeup", "download", "skin", "bid", "hair", "quest", "icu",
        "poker", "yachts", "garden", "buzz", "ga", "help", "today", "vu",
        "store", "art", "site", "xyz", "lat", "ml", "rent", "bond",
        // Tetap dipertahankan dari daftar sebelumnya: jumlahnya di Lyra
        // di bawah ambang sampel, tapi reputasinya sudah mapan.
        "top", "work", "mom", "party", "racing", "date", "win", "trade",
        "country", "science", "cricket", "accountant", "faith", "zip", "mov",
        "cam", "surf", "monster"
    )

    /** Hosting gratis / page-builder: sah dipakai, tapi juga sarang phishing. */
    private val FREE_HOSTS = setOf(
        "vercel.app", "netlify.app", "github.io", "gitlab.io", "pages.dev",
        "web.app", "firebaseapp.com", "000webhostapp.com", "glitch.me",
        "repl.co", "replit.app", "wixsite.com", "weeblysite.com",
        "blogspot.com", "herokuapp.com", "onrender.com", "surge.sh",
        "neocities.org", "workers.dev", "r2.dev", "ngrok.io",
        "ngrok-free.app", "trycloudflare.com", "serveo.net", "loca.lt",
        "my.id", "rf.gd", "epizy.com", "infinityfreeapp.com"
    )

    /** Kata khas halaman pengambilan kredensial / iming-iming. */
    private val SENSITIVE_TOKENS = setOf(
        "login", "signin", "secure", "security", "verify", "verifikasi",
        "validasi", "update", "konfirmasi", "confirm", "account", "akun",
        "banking", "ibank", "password", "otp", "auth", "wallet", "topup",
        "hadiah", "undian", "bonus", "claim", "klaim", "gift", "reward",
        "recovery", "unlock", "suspended", "pembayaran", "invoice", "tagihan"
    )

    /**
     * Afiks yang lazim ditempel penipu ke nama brand ("klikbca", "bankbca",
     * "bcamobile"). Dipakai agar pencocokan brand tidak perlu substring bebas
     * — substring bebas-lah yang dulu memblokir "bridge.com" karena "bri".
     */
    private val BRAND_AFFIXES = setOf(
        "bank", "m", "my", "klik", "ib", "mobile", "online", "secure",
        "login", "web", "apps", "app", "id", "indonesia", "cs", "care",
        "info", "update", "verif", "verifikasi", "akun", "digital", "new"
    )

    /**
     * Brand yang juga kata umum bahasa Indonesia/Inggris. Kecocokan brand
     * saja tidak boleh langsung memblokir — "dana bantuan", "grab a coffee".
     */
    private val AMBIGUOUS_BRANDS = setOf("dana", "grab", "bola", "toto", "link", "bank", "one")

    private val GENERIC_SECOND_LEVELS = setOf(
        "co", "com", "net", "org", "go", "ac", "or", "sch", "gov", "mil",
        "id", "uk", "us", "my", "sg", "au", "in", "jp", "kr"
    )

    private val IPV4 = Regex("""^\d{1,3}(\.\d{1,3}){3}$""")

    // ── API utama ───────────────────────────────────────────────────────

    /**
     * @param officialDomains whitelist domain resmi (dari Room DB)
     * @param brandToOfficial brand → himpunan domain resmi brand tersebut
     * @param pageText cuplikan teks halaman yang sedang dibuka (opsional)
     */
    fun score(
        rawUrl: String,
        officialDomains: Set<String> = emptySet(),
        brandToOfficial: Map<String, Set<String>> = emptyMap(),
        pageText: String = "",
        benignDomains: Set<String> = COMMON_BENIGN
    ): Verdict {
        val url = rawUrl.lowercase().trim()
        val authority = authorityOf(url)
        val hostname = hostOf(authority)
        val path = url.removePrefix("https://").removePrefix("http://")
            .substringAfter('/', "")
        val registrable = registrableDomain(hostname)
        val signals = mutableListOf<Signal>()

        // Whitelist: domain resmi & domain besar yang dikenal → berhenti di sini.
        if (matchesDomain(hostname, officialDomains)) {
            return Verdict(0f, emptyList(), Level.SAFE, hostname, registrable)
        }
        if (matchesDomain(hostname, benignDomains)) {
            return Verdict(0f, emptyList(), Level.SAFE, hostname, registrable)
        }

        // ── Judi online (judol) — CEK PALING AWAL ───────────────────────
        // Langsung DANGEROUS: domain mengandung istilah judi ATAU konten
        // halaman adalah promosi judi — keduanya indikasi kuat situs judol.
        // Ditaruh sebelum sinyal lain supaya judol TIDAK PERNAH bisa turun
        // ke SUSPICIOUS karena sinyal lain menambah/mengurangi bobot.
        // Istilah tak ambigu ("gacor", "sbobet", "casino") → satu sudah cukup.
        // Istilah ambigu ("slot", "toto", "olympus") → butuh dua, karena
        // sendirian ia menjerat toto.co.jp, slotcarshop.com, olympus.com.
        // Domain judol asli hampir selalu menumpuk beberapa istilah, jadi
        // deteksinya tidak berkurang — yang hilang cuma salah tangkapnya.
        val ambiguousInHost = JudolWordlist.countAmbiguousSignals(hostname)
        if (JudolWordlist.hasUnambiguousSignal(hostname) || ambiguousInHost >= 2) {
            val hit = JudolWordlist.scan(hostname)
            return Verdict(0.99f, listOf(Signal("Nama domain memuat istilah judi online (${hit.summary})", 0.99f)), Level.DANGEROUS, hostname, registrable)
        } else if (ambiguousInHost == 1) {
            // Satu istilah ambigu saja: cukup untuk diperiksa, tidak untuk
            // divonis. Dengan sinyal lain (TLD murah, angka, hosting gratis)
            // ia tetap menembus ambang berbahaya.
            signals += Signal("Nama domain memuat istilah yang lazim pada situs judi", 0.72f)
        }

        // Isi halaman diperiksa TERPISAH, bukan sebagai cabang else.
        // Sebelumnya ia berada di rantai else-if, sehingga domain yang memuat
        // satu istilah ambigu tidak pernah diperiksa isinya sama sekali —
        // justru kasus yang paling butuh pemeriksaan konten.
        // Isi halaman judol juga sering dikaburkan; nilai bentuk
        // ternormalisasinya di samping teks asli.
        val pageNormal = if (pageText.isBlank()) "" else TextNormalizer.normalize(pageText)
        if (pageText.isNotBlank() &&
            (JudolWordlist.hasStrongSignal(pageText) || JudolWordlist.hasStrongSignal(pageNormal))
        ) {
            val asli = JudolWordlist.scan(pageText)
            val kabur = JudolWordlist.scan(pageNormal)
            val hit = if (kabur.score > asli.score) kabur else asli
            if (JudolWordlist.isLikelyJudol(hit)) {
                return Verdict(0.99f, listOf(Signal("Isi halaman berupa promosi judi online (${hit.summary})", 0.99f)), Level.DANGEROUS, hostname, registrable)
            } else if (hit.score >= 4) {
                signals += Signal("Isi halaman mengandung istilah judi (${hit.summary})", 0.30f)
            }
        }

        // ── Sinyal struktural (murah, sangat jarang salah) ──────────────
        if (authority.contains('@')) {
            signals += Signal("Alamat menyembunyikan tujuan asli dengan tanda '@'", 0.40f)
        }
        if (IPV4.matches(hostname)) {
            signals += Signal("Situs diakses lewat alamat IP mentah, bukan nama domain", 0.55f)
        }
        if (hostname.contains("xn--")) {
            signals += Signal("Nama domain memakai karakter non-latin yang menyerupai huruf biasa", 0.50f)
        }

        // ── Peniruan brand ──────────────────────────────────────────────
        for ((brand, officialSet) in brandToOfficial) {
            if (matchesDomain(hostname, officialSet)) continue
            if (!brandMatches(hostname, brand)) continue
            val weight = if (brand in AMBIGUOUS_BRANDS) 0.45f else 0.75f
            signals += Signal("Memakai nama '$brand' padahal domainnya ($registrable) bukan milik resminya", weight)
            break
        }
        if (signals.none { it.weight >= 0.45f }) {
            // Brand hanya muncul di path: "situs-acak.com/bca/login"
            val inPath = brandToOfficial.keys.firstOrNull {
                it.length >= 3 && it !in AMBIGUOUS_BRANDS && pathHasToken(path, it)
            }
            if (inPath != null) {
                signals += Signal("Halaman mengatasnamakan '$inPath' di domain yang tidak terkait", 0.40f)
            }
        }

        // ── Infrastruktur ───────────────────────────────────────────────
        val tld = hostname.substringAfterLast('.', "")
        if (tld in CHEAP_TLDS) {
            signals += Signal("Domain memakai akhiran .$tld yang banyak dipakai penipuan", 0.30f)
        }
        if (FREE_HOSTS.any { hostname == it || hostname.endsWith(".$it") }) {
            signals += Signal("Situs menumpang hosting gratis, bukan domain milik sendiri", 0.25f)
        }

        // ── Kata kunci: di hostname berbobot, di path nyaris tidak ──────
        val hostKw = SENSITIVE_TOKENS.firstOrNull { hasToken(hostname, it) }
        if (hostKw != null) {
            signals += Signal("Nama domain memuat kata '$hostKw' yang khas halaman pencuri data", 0.35f)
        }
        val pathKw = SENSITIVE_TOKENS.firstOrNull { pathHasToken(path, it) }
        if (pathKw != null) {
            // Sengaja kecil: hampir semua situs sah punya /login, /update, /account.
            signals += Signal("Alamat halaman memuat kata '$pathKw'", 0.12f)
        }

        // ── Anomali leksikal ────────────────────────────────────────────
        val hyphens = hostname.count { it == '-' }
        when {
            hyphens >= 4 -> signals += Signal("Domain dipenuhi $hyphens tanda hubung", 0.30f)
            hyphens == 3 -> signals += Signal("Domain memakai 3 tanda hubung", 0.18f)
            // 2 tanda hubung TIDAK dihitung: "toko-kopi-enak.com" itu wajar.
        }
        val labels = hostname.split('.').filter { it.isNotBlank() }
        if (labels.size >= 6) {
            signals += Signal("Struktur subdomain terlalu dalam (${labels.size} tingkat)", 0.22f)
        }
        val digits = hostname.count { it.isDigit() }
        if (digits >= 4 && digits.toFloat() / hostname.length > 0.30f) {
            signals += Signal("Nama domain didominasi angka acak", 0.20f)
        }
        if (hostname.length > 45) {
            signals += Signal("Nama domain luar biasa panjang (${hostname.length} karakter)", 0.15f)
        }

        val total = signals.fold(0f) { acc, s -> acc + s.weight }.coerceAtMost(0.99f)
        val level = when {
            total >= THRESHOLD_DANGEROUS  -> Level.DANGEROUS
            total >= THRESHOLD_SUSPICIOUS -> Level.SUSPICIOUS
            else -> Level.SAFE
        }
        return Verdict(total, signals, level, hostname, registrable)
    }

    // ── Helper (internal, dipakai juga oleh test) ───────────────────────

    /**
     * Cocokkan brand ke hostname secara TERIKAT: token utuh, token+afiks yang
     * dikenal, atau typosquat berjarak edit 1. Tidak pernah substring bebas —
     * itu sumber false-positive "bridge.com" ↔ brand "bri".
     */
    fun brandMatches(hostname: String, brand: String): Boolean {
        if (brand.length < 3) return false
        for (label in hostname.split('.')) {
            for (rawToken in label.split('-', '_')) {
                // "bca123" → "bca": penipu sering menempel angka.
                val tok = rawToken.trimEnd { it.isDigit() }
                if (tok.isEmpty()) continue
                if (tok == brand) return true
                // "klikbca", "bankbri", "bcamobile" — brand + afiks yang dikenal.
                if (BRAND_AFFIXES.any { tok == it + brand || tok == brand + it }) return true
                // Typosquat hanya untuk brand panjang; pada brand 3-4 huruf
                // jarak edit 1 terlalu mudah kena kata biasa.
                if (brand.length >= 5 && abs(tok.length - brand.length) <= 1 &&
                    editDistance(tok, brand) == 1
                ) return true
            }
        }
        return false
    }

    /**
     * Host besar/berbagi-pakai yang TIDAK boleh divonis per-domain.
     *
     * Umpan publik (PhishTank, OpenPhish) melaporkan URL abusif yang
     * menumpang di host sah — mis. "google.com/share.google?q=…" atau
     * "sites.google.com/view/…". Entri semacam itu tersimpan dengan
     * domain="google.com", dan pencocokan per-domain lalu memvonis SELURUH
     * google.com sebagai phishing. Terbukti terjadi di perangkat uji.
     *
     * URL persisnya tetap diblokir lewat pencocokan URL penuh; yang
     * dilarang hanya menggeneralisasi satu URL jadi seluruh host.
     */
    fun isSharedOrMajorHost(host: String): Boolean {
        val h = host.lowercase().removePrefix("www.")
        return matchesDomain(h, COMMON_BENIGN) || matchesDomain(h, FREE_HOSTS)
    }

    fun registrableDomain(host: String): String {
        val l = host.split('.').filter { it.isNotBlank() }
        if (l.size <= 2) return host
        val tld = l.last()
        val sld = l[l.size - 2]
        val take = if (tld.length == 2 && sld in GENERIC_SECOND_LEVELS) 3 else 2
        return l.takeLast(take).joinToString(".")
    }

    private fun matchesDomain(host: String, domains: Set<String>): Boolean =
        domains.any { host == it || host.endsWith(".$it") }

    /** Bagian otoritas URL: setelah skema, sebelum path. */
    private fun authorityOf(url: String): String =
        url.removePrefix("https://").removePrefix("http://").substringBefore('/')

    private fun hostOf(authority: String): String =
        authority.substringAfterLast('@').substringBefore(':').removePrefix("www.")

    /** Token utuh, dibatasi karakter non-alfanumerik di kedua sisi. */
    private fun hasToken(text: String, token: String): Boolean =
        Regex("(^|[^a-z0-9])${Regex.escape(token)}([^a-z0-9]|$)").containsMatchIn(text)

    private fun pathHasToken(path: String, token: String): Boolean =
        path.isNotBlank() && hasToken(path, token)

    private fun editDistance(a: String, b: String): Int {
        var prev = IntArray(b.length + 1) { it }
        var cur = IntArray(b.length + 1)
        for (i in 1..a.length) {
            cur[0] = i
            for (j in 1..b.length) {
                val cost = if (a[i - 1] == b[j - 1]) 0 else 1
                cur[j] = minOf(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            }
            val t = prev; prev = cur; cur = t
        }
        return prev[b.length]
    }

    /**
     * Domain besar yang dikenal. Bukan "aman selamanya" — hanya menghentikan
     * skoring heuristik yang tidak relevan untuk situs sebesar ini.
     */
    val COMMON_BENIGN = setOf(
        "google.com", "google.co.id", "gstatic.com", "googleapis.com",
        "apple.com", "icloud.com", "microsoft.com", "live.com", "outlook.com",
        "office.com", "microsoftonline.com", "bing.com",
        "facebook.com", "whatsapp.com", "instagram.com", "threads.net",
        "youtube.com", "twitter.com", "x.com", "tiktok.com", "snapchat.com",
        "linkedin.com", "pinterest.com", "reddit.com", "quora.com",
        "wikipedia.org", "medium.com", "github.com", "gitlab.com",
        "stackoverflow.com", "stackexchange.com",
        "amazon.com", "netflix.com", "spotify.com", "twitch.tv",
        "discord.com", "telegram.org", "steampowered.com", "epicgames.com",
        "roblox.com", "paypal.com", "stripe.com", "wise.com", "revolut.com",
        "yahoo.com", "proton.me", "protonmail.com", "mail.com",
        "cloudflare.com", "amazonaws.com", "azure.com", "detik.com",
        // Merek besar yang namanya kebetulan memuat jargon judi. Tanpa ini
        // mereka hanya turun ke SUSPICIOUS; dengan ini benar-benar aman.
        "olympus.com", "toto.co.jp", "rtp.pt", "bonanza.com", "zeus.com",
        "kompas.com", "tribunnews.com", "cnnindonesia.com", "liputan6.com"
    )
}
