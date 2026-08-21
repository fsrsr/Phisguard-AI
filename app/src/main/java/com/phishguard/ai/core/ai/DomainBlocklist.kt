package com.phishguard.ai.core.ai

import android.content.Context
import android.util.Log
import java.io.FileInputStream
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.security.MessageDigest

/**
 * Pemeriksaan domain terhadap blocklist Lyra (ITSEC Research) secara luring.
 *
 * 4,1 juta domain (phishing/scam, malware/C2, judi) tidak mungkin disimpan
 * apa adanya di ponsel — mentahnya lebih dari 80 MB. Bloom filter memampatkan
 * semuanya jadi ~9,4 MB dengan pencarian O(1) dan tanpa jaringan.
 *
 * KONSEKUENSI: Bloom filter bisa keliru bilang "ada" untuk domain yang
 * sebenarnya tidak terdaftar (tidak pernah sebaliknya). Peluangnya disetel
 * 0,01% — pada ~100 domain per hari, sekitar sekali salah per tiga tahun.
 * Domain resmi dan situs besar tetap diperiksa lebih dulu di
 * [UrlRiskScorer], jadi kekeliruan itu tidak akan mengenai situs populer.
 *
 * Berkasnya dipetakan ke memori (mmap), bukan dibaca ke heap — sistem
 * operasi yang mengatur halaman mana yang perlu dimuat. Karena itu
 * "bloom" harus masuk daftar noCompress di build.gradle.kts.
 *
 * Aset dibangun oleh tools/build_blocklist.py — algoritma indeksnya wajib
 * sama persis dengan yang di sana (SHA-256 + double hashing).
 */
class DomainBlocklist private constructor(
    private val bits: ByteBuffer,
    private val m: Long,
    private val k: Int,
    val domainCount: Long
) {

    /**
     * Apakah domain ini (atau domain induknya) ada di blocklist?
     * Diperiksa berjenjang: "login.aman.contoh.com" → "aman.contoh.com" →
     * "contoh.com", karena daftarnya berisi domain, bukan URL lengkap.
     */
    fun contains(hostname: String): Boolean {
        val host = hostname.lowercase().removePrefix("www.").substringBefore(':')
        if (host.isBlank() || !host.contains('.')) return false

        var candidate = host
        while (true) {
            if (mightContain(candidate)) return true
            val dot = candidate.indexOf('.')
            // Berhenti saat tersisa dua label ("contoh.com"); lebih pendek
            // dari itu bukan domain yang bisa didaftarkan.
            if (dot < 0 || candidate.count { it == '.' } <= 1) return false
            candidate = candidate.substring(dot + 1)
        }
    }

    private fun mightContain(domain: String): Boolean {
        for (idx in indicesFor(domain, m, k)) {
            val byteIndex = (idx ushr 3).toInt()
            val bit = (idx and 7L).toInt()
            if ((bits.get(byteIndex).toInt() shr bit) and 1 == 0) return false
        }
        return true
    }

    companion object {
        private const val TAG = "DomainBlocklist"
        private const val ASSET = "blocklist.bloom"
        private const val MAGIC = 0x5047424C   // "PGBL"
        private const val SUPPORTED_VERSION = 1
        /** magic(4) + versi(4) + m(8) + k(4) + n(8) */
        private const val HEADER_BYTES = 28

        @Volatile
        private var instance: DomainBlocklist? = null

        /**
         * Indeks bit untuk sebuah domain: double hashing dari satu SHA-256.
         *
         * WAJIB identik dengan bloom_indices() di tools/build_blocklist.py.
         * Kalau keduanya menyimpang, aset 9,4 MB itu diam-diam jadi tidak
         * berguna tanpa error apa pun — karena itu ada uji vektor silang
         * di DomainBlocklistTest.
         */
        fun indicesFor(domain: String, m: Long, k: Int): LongArray {
            val d = MessageDigest.getInstance("SHA-256").digest(domain.toByteArray(Charsets.UTF_8))
            val h1 = readLong(d, 0)
            val h2 = readLong(d, 8)
            return LongArray(k) { i ->
                // Penjumlahan Long meluap dengan sendirinya — itu setara
                // dengan masking 64-bit di sisi Python. remainderUnsigned
                // menjaga hasilnya sama untuk nilai berbit-tinggi menyala.
                java.lang.Long.remainderUnsigned(h1 + i.toLong() * h2, m)
            }
        }

        private fun readLong(b: ByteArray, offset: Int): Long {
            var v = 0L
            for (i in 0 until 8) v = (v shl 8) or (b[offset + i].toLong() and 0xFF)
            return v
        }

        /**
         * Muat sekali, pakai berkali-kali. Mengembalikan null bila aset
         * tidak ada atau rusak — aplikasi tetap berjalan dengan heuristik
         * saja, blocklist sifatnya menambah, bukan menggantikan.
         */
        fun get(context: Context): DomainBlocklist? {
            instance?.let { return it }
            synchronized(this) {
                instance?.let { return it }
                instance = load(context)
                return instance
            }
        }

        private fun load(context: Context): DomainBlocklist? = try {
            context.assets.openFd(ASSET).use { fd ->
                FileInputStream(fd.fileDescriptor).use { stream ->
                    val buf = stream.channel.map(
                        FileChannel.MapMode.READ_ONLY, fd.startOffset, fd.declaredLength
                    )
                    val magic = buf.int
                    val version = buf.int
                    require(magic == MAGIC) { "magic tidak cocok: $magic" }
                    require(version == SUPPORTED_VERSION) { "versi format $version tidak didukung" }
                    val m = buf.long
                    val k = buf.int
                    val n = buf.long
                    require(m > 0 && k in 1..64) { "parameter tidak masuk akal m=$m k=$k" }

                    val bits = buf.slice()
                    Log.d(TAG, "Blocklist dimuat: $n domain, m=$m bit, k=$k " +
                            "(${(fd.declaredLength - HEADER_BYTES) / 1024 / 1024} MB)")
                    DomainBlocklist(bits, m, k, n)
                }
            }
        } catch (e: Exception) {
            // Paling sering: aset belum dibangun (jalankan tools/build_blocklist.py),
            // atau "bloom" belum masuk noCompress sehingga tidak bisa di-mmap.
            Log.w(TAG, "Blocklist tidak tersedia, lanjut dengan heuristik saja: ${e.message}")
            null
        }
    }
}
