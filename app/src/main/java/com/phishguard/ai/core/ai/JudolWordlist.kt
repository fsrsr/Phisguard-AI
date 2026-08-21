package com.phishguard.ai.core.ai

/**
 * Wordlist terkurasi untuk deteksi situs judol / slot / togel Indonesia dan
 * faktor scam. Dipakai dua mode: scan token URL & scan teks konten halaman.
 * Term punya bobot supaya AI-nya tidak asal ter-trigger (FP rendah).
 */
class JudolWordlist {

    /** Hasil scan: term yang cocok + skor terbobot. */
    data class Hit(val matches: List<String>, val score: Int, val summary: String)

    companion object {
        private data class Entry(val terms: List<String>, val weight: Int)

        /**
         * TIDAK AMBIGU — istilah ini hampir mustahil muncul di domain sah,
         * atau memang menandakan judi menurut definisinya (casino, poker).
         * Satu kecocokan sudah cukup untuk memvonis.
         *
         * Dikalibrasi dari dua sumber: 1,8 juta nama domain judi
         * (tools/blocklist_report.md) dan 989 halaman judol nyata
         * (tools/page_terms_report.md).
         *
         * Yang SENGAJA DITOLAK meski lift-nya tinggi: kata Indonesia biasa
         * ("daftar", "situs", "klik", "cuan", "menang") — lift-nya tampak
         * besar hanya karena korpus pembanding kurang memuat situs
         * berbahasa Indonesia. Nama merek judi juga tidak dimasukkan:
         * domain persisnya sudah ditangani DomainBlocklist, sedangkan
         * daftar ini bertugas menebak domain yang BELUM terdaftar.
         */
        private val STRONG_UNAMBIGUOUS = listOf(
            "judi", "togel", "gacor", "maxwin", "sbobet", "bandarq",
            "pragmaticplay", "slot88", "bolatangkas", "sportsbook", "kasino",
            "casino", "poker", "baccarat", "roulette", "parlay", "habanero",
            "microgaming", "jackpot", "taruhan",
            // Ditambahkan dari penambangan 989 halaman judol nyata
            // (tools/page_terms_report.md): nama penyedia game, dompet judi,
            // dan mekanik slot. Semuanya nyaris tak punya pemakaian sah.
            "netent", "skrill", "neteller", "paysafecard", "megaways",
            "blackjack", "freespin", "freebet", "sportsbet", "judibola",
            "situsjudi", "linkalternatif", "depositpulsa"
        )

        /**
         * AMBIGU — istilah judi yang juga kata/merek sah. Dicocokkan sebagai
         * substring (karena domain judol menyambung kata: "slotgacor"), jadi
         * sendirian ia akan menjerat situs yang tidak bersalah:
         *
         *   toto     → toto.co.jp (produsen sanitasi Jepang)
         *   slot     → slotcarshop.com (toko mainan slot car)
         *   olympus  → olympus.com (kamera & alat medis)
         *   rtp      → rtp.pt (penyiar nasional Portugal)
         *   bonanza  → bonanza.com (e-commerce)
         *
         * Karena itu istilah di sini butuh SATU sinyal judi lagi sebelum
         * memvonis. Domain judol sungguhan hampir selalu menumpuk beberapa
         * ("slotgacor", "totomaxwin", "slot88maxwin"), jadi deteksinya tidak
         * berkurang — yang hilang justru salah tangkapnya.
         */
        private val STRONG_AMBIGUOUS = listOf(
            "slot", "toto", "rtp", "mpo", "zeus", "olympus", "starlight",
            "aztec", "bonanza", "mahjong", "scatter", "pragmatic"
        )

        private val STRONG = STRONG_UNAMBIGUOUS + STRONG_AMBIGUOUS

        private val LIST = listOf(
            Entry(listOf("judi", "togel", "slot", "kasino", "bandar"), 4),
            Entry(listOf("gacor", "tenggelam", "jagoan", "raja", "sensasi"), 4),
            Entry(listOf("bocoran", "rtp", "scatter", "olympus", "starlight", "aztec", "bonanza", "sweet"), 3),
            Entry(listOf("pragmatic", "slot88", "slotclub", "habanero", "microgaming", "pragmaticplay"), 4),
            Entry(listOf("sbobet", "127", "bandarq", "joker", "hugo", "maxwin"), 3),
            Entry(listOf("deposit", "depo", "wd", "saldo", "referral", "affiliate", "komisi", "cashback"), 2),
            Entry(listOf("jackpot", "payout", "keluaran", "pengeluaran", "result", "tembus"), 2),
            Entry(listOf("bonus", "member baru", "gratis", "daftar sekarang", "login sekarang", "situs"), 3),
            // "d" satu huruf dibuang: ia mencocoki hampir semua teks dan
            // menyumbang skor palsu, sehingga halaman judi tampak sudah
            // memenuhi ambang padahal buktinya cuma satu istilah asli.
            Entry(listOf("toto", "pulsa", "diamond", "koin"), 1)
        )

        /** Scan sebuah teks (URL penuh atau konten halaman). */
        fun scan(text: String): Hit {
            if (text.isBlank()) return Hit(emptyList(), 0, "")
            val t = text.lowercase()
            var score = 0
            val found = LinkedHashSet<String>()
            for (entry in LIST) {
                for (term in entry.terms) {
                    if (term.length >= 5) {
                        if (t.contains(term)) { score += entry.weight; found.add(term) }
                    } else {
                        if (Regex("(^|[^a-z0-9])${Regex.escape(term)}([^a-z0-9]|$)").containsMatchIn(t)) {
                            score += entry.weight; found.add(term)
                        }
                    }
                }
            }
            if (found.isEmpty()) return Hit(emptyList(), 0, "")
            return Hit(found.toList(), score, found.take(10).joinToString(", "))
        }

        /** Ambang: halaman/domain judol nyata biasanya >= 6 & >=2 term. */
        fun isLikelyJudol(hit: Hit): Boolean = hit.score >= 6 && hit.matches.size >= 2

        /**
         * Teks mengandung minimal 1 istilah judi berkeyakinan tinggi. Dipakai
         * menaikkan page-content jadi ancaman (FP-reduction): "bonus gratis"
         * saja belum cukup; harus ada slot/judi/togel/gacor/etc.
         */
        fun hasStrongSignal(text: String): Boolean =
            matches(text, STRONG).isNotEmpty()

        /** Istilah judi yang tak punya pemakaian sah — satu saja sudah cukup. */
        fun hasUnambiguousSignal(text: String): Boolean =
            matches(text, STRONG_UNAMBIGUOUS).isNotEmpty()

        /**
         * Berapa istilah AMBIGU yang cocok. Dipakai pemanggil untuk menuntut
         * dua sinyal sebelum memvonis, supaya "toto.co.jp" dan
         * "slotcarshop.com" tidak ikut terjaring.
         */
        fun countAmbiguousSignals(text: String): Int =
            matches(text, STRONG_AMBIGUOUS).size

        private fun matches(text: String, terms: List<String>): List<String> {
            if (text.isBlank()) return emptyList()
            val t = text.lowercase()
            return terms.filter { term ->
                if (term.length >= 4) {
                    t.contains(term)
                } else {
                    Regex("(^|[^a-z0-9])${Regex.escape(term)}([^a-z0-9]|$)").containsMatchIn(t)
                }
            }
        }
    }
}