package com.phishguard.ai.core.ai

import android.content.Context
import android.util.Log
import com.phishguard.ai.data.db.PhishingDatabase
import kotlin.concurrent.thread

/**
 * Provider deteksi Web Phishing.
 *
 * Tugas class ini tinggal dua: menyiapkan daftar domain resmi + peta brand
 * dari Room DB, lalu menyerahkan penilaian ke [UrlRiskScorer]. Seluruh logika
 * penilaian ada di scorer supaya bisa diuji tanpa Android — lihat
 * UrlRiskScorerTest.
 *
 * Hasil membawa metadata "level" (SAFE/SUSPICIOUS/DANGEROUS) agar pemanggil
 * bisa memilih respons: diam, notifikasi, atau blokir layar penuh.
 */
class LstmUrlProvider : AIModelProvider {

    private val TAG = "LstmUrlProvider"
    private var isModelLoaded = false

    private var officialDomains = setOf<String>()
    private var brandToOfficialDomains = mapOf<String, Set<String>>()

    /** Token yang terlalu umum untuk dianggap nama brand. */
    private val genericBrandTokens = setOf(
        "bank", "indonesia", "id", "co", "com", "go", "gov", "my", "i",
        "ib", "one", "klik", "link", "online", "m", "www", "account", "register"
    )

    override fun initialize(context: Context) {
        thread {
            try {
                val db = PhishingDatabase.getInstance(context)
                officialDomains = db.officialUrlDao().getAll().map { it.domain.lowercase() }.toSet()

                val map = mutableMapOf<String, MutableSet<String>>()
                officialDomains.forEach { d ->
                    val brand = brandFromDomain(d)
                    if (brand != null && brand.length >= 3 && brand !in genericBrandTokens) {
                        map.getOrPut(brand) { mutableSetOf() }.add(d)
                    }
                }
                // Jaring pengaman bila seeder DB belum jalan.
                BUILT_IN_BRANDS.forEach { (brand, domains) ->
                    map.getOrPut(brand) { mutableSetOf() }.addAll(domains)
                }
                brandToOfficialDomains = map

                Log.d(TAG, "Init: ${officialDomains.size} domain resmi, ${map.size} brand.")
            } catch (e: Exception) {
                Log.e(TAG, "Gagal memuat domain resmi", e)
                brandToOfficialDomains = BUILT_IN_BRANDS
            } finally {
                isModelLoaded = true
            }
        }
    }

    override fun isReady(): Boolean = isModelLoaded

    override fun analyze(input: AnalysisInput): AnalysisResult {
        val verdict = UrlRiskScorer.score(
            rawUrl = input.content,
            officialDomains = officialDomains,
            brandToOfficial = brandToOfficialDomains,
            pageText = input.metadata["pageText"].orEmpty()
        )

        val pageLen = input.metadata["pageText"].orEmpty().length
        Log.d(TAG, "${verdict.level} ${"%.2f".format(verdict.score)} — ${verdict.hostname} " +
                "(teks halaman: $pageLen karakter) :: ${verdict.reason}")

        val meta = mapOf(
            "level" to verdict.level.name,
            "host" to verdict.hostname,
            "registrable" to verdict.registrable
        )

        return if (verdict.level == UrlRiskScorer.Level.SAFE) {
            AnalysisResult(false, 1f - verdict.score, "Tidak ada indikasi phishing.", ThreatCategory.SAFE, meta)
        } else {
            AnalysisResult(true, verdict.score, verdict.reason, ThreatCategory.PHISHING, meta)
        }
    }

    override fun release() {
        isModelLoaded = false
    }

    private fun brandFromDomain(d: String): String? =
        d.lowercase().removePrefix("www.").split('.')
            .firstOrNull { it.length >= 3 && it !in genericBrandTokens }

    companion object {
        private val BUILT_IN_BRANDS: Map<String, Set<String>> = mapOf(
            "bca" to setOf("bca.co.id", "klikbca.com"),
            "klikbca" to setOf("klikbca.com"),
            "bni" to setOf("bni.co.id"),
            "bri" to setOf("bri.co.id"),
            "brimo" to setOf("brimo.bri.co.id", "bri.co.id"),
            "mandiri" to setOf("bankmandiri.co.id"),
            "livin" to setOf("livinbymandiri.co.id"),
            "bsi" to setOf("bankbsi.co.id"),
            "btn" to setOf("btn.co.id"),
            "cimbniaga" to setOf("cimbniaga.co.id"),
            "danamon" to setOf("danamon.co.id"),
            "shopee" to setOf("shopee.co.id", "shopee.com"),
            "tokopedia" to setOf("tokopedia.com"),
            "bukalapak" to setOf("bukalapak.com"),
            "dana" to setOf("dana.id"),
            "ovo" to setOf("ovo.id"),
            "gopay" to setOf("gopay.co.id", "gojek.com"),
            "gojek" to setOf("gojek.com"),
            "grab" to setOf("grab.com"),
            "linkaja" to setOf("linkaja.id")
        )
    }
}
