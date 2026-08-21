package com.phishguard.ai.data.db

import android.content.Context
import android.util.Log
import kotlin.concurrent.thread

/**
 * Seeder untuk mengisi Database Domain Resmi Bank Indonesia.
 * Dipanggil sekali saat app pertama kali dijalankan.
 *
 * Arsitektur: Sesuai Database Official URL pada blueprint Web Phishing.
 * URL yang ada di sini = LANGSUNG AMAN, tidak akan ada pop-up peringatan.
 */
object DatabaseSeeder {
    private const val TAG = "DatabaseSeeder"
    private const val PREF_KEY = "db_seeded_v2"

    fun seedIfNeeded(context: Context) {
        thread {
            try {
                val pref = context.getSharedPreferences("phishguard_setup", Context.MODE_PRIVATE)
                if (pref.getBoolean(PREF_KEY, false)) {
                    Log.d(TAG, "Database sudah di-seed sebelumnya, skip.")
                    return@thread
                }

                val db = PhishingDatabase.getInstance(context)
                val officialUrls = buildOfficialDomainList()
                db.officialUrlDao().insertAll(officialUrls)

                pref.edit().putBoolean(PREF_KEY, true).apply()
                Log.d(TAG, "✅ Database di-seed: ${officialUrls.size} domain resmi berhasil disimpan.")
            } catch (e: Exception) {
                Log.e(TAG, "Error saat seeding database", e)
            }
        }
    }

    private fun buildOfficialDomainList(): List<OfficialUrl> {
        return listOf(
            // ===== BCA =====
            OfficialUrl(domain = "bca.co.id",           organization = "Bank BCA",     category = "banking"),
            OfficialUrl(domain = "www.bca.co.id",        organization = "Bank BCA",     category = "banking"),
            OfficialUrl(domain = "klikbca.com",          organization = "Bank BCA",     category = "banking"),
            OfficialUrl(domain = "www.klikbca.com",      organization = "Bank BCA",     category = "banking"),
            OfficialUrl(domain = "m.klikbca.com",        organization = "Bank BCA",     category = "banking"),
            OfficialUrl(domain = "mybca.bca.co.id",      organization = "Bank BCA",     category = "banking"),
            OfficialUrl(domain = "oneklik.bca.co.id",    organization = "Bank BCA",     category = "banking"),

            // ===== BNI =====
            OfficialUrl(domain = "bni.co.id",            organization = "Bank BNI",     category = "banking"),
            OfficialUrl(domain = "www.bni.co.id",        organization = "Bank BNI",     category = "banking"),
            OfficialUrl(domain = "ibank.bni.co.id",      organization = "Bank BNI",     category = "banking"),
            OfficialUrl(domain = "bnidirect.bni.co.id",  organization = "Bank BNI",     category = "banking"),

            // ===== BRI =====
            OfficialUrl(domain = "bri.co.id",            organization = "Bank BRI",     category = "banking"),
            OfficialUrl(domain = "www.bri.co.id",        organization = "Bank BRI",     category = "banking"),
            OfficialUrl(domain = "ib.bri.co.id",         organization = "Bank BRI",     category = "banking"),
            OfficialUrl(domain = "brimo.bri.co.id",      organization = "Bank BRI",     category = "banking"),
            OfficialUrl(domain = "brilink.bri.co.id",    organization = "Bank BRI",     category = "banking"),

            // ===== MANDIRI =====
            OfficialUrl(domain = "bankmandiri.co.id",           organization = "Bank Mandiri", category = "banking"),
            OfficialUrl(domain = "www.bankmandiri.co.id",        organization = "Bank Mandiri", category = "banking"),
            OfficialUrl(domain = "ib.bankmandiri.co.id",         organization = "Bank Mandiri", category = "banking"),
            OfficialUrl(domain = "livinbymandiri.co.id",         organization = "Bank Mandiri", category = "banking"),
            OfficialUrl(domain = "www.livinbymandiri.co.id",     organization = "Bank Mandiri", category = "banking"),

            // ===== CIMB NIAGA =====
            OfficialUrl(domain = "cimbniaga.co.id",      organization = "CIMB Niaga",   category = "banking"),
            OfficialUrl(domain = "www.cimbniaga.co.id",  organization = "CIMB Niaga",   category = "banking"),
            OfficialUrl(domain = "octo.cimbniaga.co.id", organization = "CIMB Niaga",   category = "banking"),

            // ===== DANAMON =====
            OfficialUrl(domain = "danamon.co.id",        organization = "Bank Danamon", category = "banking"),
            OfficialUrl(domain = "www.danamon.co.id",    organization = "Bank Danamon", category = "banking"),

            // ===== BTN =====
            OfficialUrl(domain = "btn.co.id",            organization = "Bank BTN",     category = "banking"),
            OfficialUrl(domain = "www.btn.co.id",        organization = "Bank BTN",     category = "banking"),

            // ===== BSI =====
            OfficialUrl(domain = "bankbsi.co.id",        organization = "Bank BSI",     category = "banking"),
            OfficialUrl(domain = "www.bankbsi.co.id",    organization = "Bank BSI",     category = "banking"),

            // ===== OJK & BI =====
            OfficialUrl(domain = "ojk.go.id",            organization = "OJK",          category = "government"),
            OfficialUrl(domain = "www.ojk.go.id",        organization = "OJK",          category = "government"),
            OfficialUrl(domain = "bi.go.id",             organization = "Bank Indonesia", category = "government"),
            OfficialUrl(domain = "www.bi.go.id",         organization = "Bank Indonesia", category = "government"),

            // ===== INSTANSI PEMERINTAH =====
            OfficialUrl(domain = "kemenkeu.go.id",       organization = "Kemenkeu",     category = "government"),
            OfficialUrl(domain = "bpjs-kesehatan.go.id", organization = "BPJS Kesehatan", category = "government"),
            OfficialUrl(domain = "bpjsketenagakerjaan.go.id", organization = "BPJS TK", category = "government"),

            // ===== E-COMMERCE =====
            OfficialUrl(domain = "tokopedia.com",        organization = "Tokopedia",    category = "ecommerce"),
            OfficialUrl(domain = "www.tokopedia.com",    organization = "Tokopedia",    category = "ecommerce"),
            OfficialUrl(domain = "shopee.co.id",         organization = "Shopee",       category = "ecommerce"),
            OfficialUrl(domain = "shopee.com",           organization = "Shopee",       category = "ecommerce"),
            OfficialUrl(domain = "bukalapak.com",        organization = "Bukalapak",    category = "ecommerce"),
            OfficialUrl(domain = "lazada.co.id",         organization = "Lazada",       category = "ecommerce"),

            // ===== TRANSPORTASI / FINTECH =====
            OfficialUrl(domain = "gojek.com",            organization = "Gojek",        category = "fintech"),
            OfficialUrl(domain = "grab.com",             organization = "Grab",         category = "fintech"),
            OfficialUrl(domain = "ovo.id",               organization = "OVO",          category = "fintech"),
            OfficialUrl(domain = "dana.id",              organization = "DANA",         category = "fintech"),
            OfficialUrl(domain = "linkaja.id",           organization = "LinkAja",      category = "fintech"),
        )
    }
}
