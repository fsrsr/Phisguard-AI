package com.phishguard.ai.core.ai

/**
 * Menormalkan teks yang sengaja dikaburkan agar lolos penyaring kata.
 *
 * Spam judol di SMS dan WhatsApp hampir selalu ditulis begini:
 *
 *     "Klaim Saldo Gratiss tanpa D e p 0
 *      Mahy'0ng ways 3| M4X'W1N | W 'D 3min."
 *
 * Empat teknik dipakai sekaligus — huruf dipisah spasi (`D e p 0`), angka
 * menggantikan huruf (`M4X'W1N`), tanda baca disisipkan di tengah kata
 * (`Mahy'0ng`), dan huruf digandakan (`Gratiss`). Pencocokan kata biasa
 * tidak akan pernah menangkapnya.
 *
 * PENTING: hasil normalisasi dipakai sebagai teks TAMBAHAN, bukan
 * pengganti. Melipat angka jadi huruf merusak makna aslinya — "100 juta"
 * menjadi "ioo juta" — jadi pemanggil harus memeriksa teks asli DAN teks
 * ternormalisasi, lalu mengambil yang paling meyakinkan. Lihat
 * TextNormalizerTest.
 */
object TextNormalizer {

    /** Karakter yang disisipkan di tengah kata untuk memecah kecocokan. */
    private val PENYISIP = Regex("['`´*_^~|+.,;:!?()\\[\\]{}<>\\\\/\"-]")

    /**
     * Angka dan simbol yang lazim menggantikan huruf. Sengaja tidak memuat
     * '6'→'g' dan '2'→'z': keduanya terlalu sering muncul sebagai angka
     * sungguhan dalam pesan sah (harga, tanggal, jumlah).
     */
    private val LEET = mapOf(
        '0' to 'o', '1' to 'i', '3' to 'e', '4' to 'a',
        '5' to 's', '7' to 't', '8' to 'b', '9' to 'g',
        '@' to 'a', '$' to 's'
    )

    /** Tiga atau lebih karakter tunggal berspasi: "d e p o" → "depo". */
    private val HURUF_BERSPASI = Regex("(?<![\\p{L}\\p{N}])([\\p{L}\\p{N}](?:\\s+[\\p{L}\\p{N}]){2,})(?![\\p{L}\\p{N}])")

    /**
     * @return bentuk ternormalisasi. Pakai bersama teks aslinya, jangan
     *   menggantikannya.
     */
    fun normalize(raw: String): String {
        if (raw.isBlank()) return ""
        var t = raw.lowercase()

        // 1. Buang tanda baca penyisip: "mahy'0ng" → "mahy0ng"
        t = PENYISIP.replace(t, "")

        // 2. Rapatkan huruf yang dipisah spasi: "d e p 0" → "dep0".
        //    Hanya untuk rentetan karakter TUNGGAL — merapatkan semua spasi
        //    akan menyatukan kata-kata wajar dan melahirkan kecocokan palsu
        //    ("auto totalan" → "autototalan" memuat "toto").
        t = HURUF_BERSPASI.replace(t) { m -> m.value.replace(Regex("\\s+"), "") }

        // 3. Lipat leetspeak: "m4xw1n" → "maxwin"
        t = buildString(t.length) { for (c in t) append(LEET[c] ?: c) }

        // 4. Rapatkan huruf berulang: "gratiss" → "gratis"
        t = Regex("([\\p{L}])\\1+").replace(t) { m -> m.groupValues[1] }

        return t
    }

    /**
     * Seberapa kuat teks ini terlihat sengaja dikaburkan. Dipakai sebagai
     * sinyal tersendiri: pesan wajar nyaris tak pernah memakai teknik ini,
     * jadi kehadirannya sendiri sudah mencurigakan.
     *
     * @return 0..3 — jumlah teknik pengaburan yang terdeteksi.
     */
    fun obfuscationScore(raw: String): Int {
        if (raw.length < 12) return 0
        var skor = 0
        // Huruf dipisah spasi
        if (HURUF_BERSPASI.containsMatchIn(raw.lowercase())) skor++
        // Angka menempel di tengah kata huruf: "m4xw1n", "bu5f44"
        if (Regex("[\\p{L}][0-9@$][\\p{L}]").containsMatchIn(raw.lowercase())) skor++
        // Tanda baca menempel di tengah kata: "mahy'0ng", "w'd"
        if (Regex("[\\p{L}]['`´*_^|][\\p{L}0-9]").containsMatchIn(raw)) skor++
        return skor
    }

    /**
     * Tautan apa pun di dalam pesan, termasuk pemendek tanpa skema
     * ("bit.ly/xxx"). Penyaring URL di TFLiteMessageProvider memakai daftar
     * TLD tetap yang tidak memuat .ly/.la/.gl, sehingga justru pemendek —
     * yang paling sering dipakai spam — tidak pernah terlihat.
     */
    private val TAUTAN = Regex(
        "https?://\\S+|[\\w-]+\\.[a-z]{2,}(?:\\.[a-z]{2,})?/\\S+",
        RegexOption.IGNORE_CASE
    )

    /** @return tautan pertama di teks, atau null. */
    fun findLink(raw: String): String? = TAUTAN.find(raw)?.value

    /**
     * Angka atau simbol terjepit di antara dua huruf: "c4r1", "g00gl3",
     * "m*h", "har!an".
     *
     * Apostrof sengaja TIDAK ikut dihitung. "Jum'at", "ba'da", "Ma'ruf",
     * "Insya'Allah" lazim dalam bahasa Indonesia, dan satu pesan undangan
     * pengajian saja sudah memuat empat di antaranya — cukup untuk
     * melewati ambang di bawah. Tanda hubung juga tidak: reduplikasi
     * ("anak-anak") ada di mana-mana.
     */
    private val TERJEPIT = Regex("[\\p{L}][0-9@\\$]+[\\p{L}]|[\\p{L}][*_^|!~][\\p{L}]")

    /**
     * Pesan yang HAMPIR SELURUH katanya dikaburkan.
     *
     * obfuscationScore() hanya mencatat ada/tidaknya tiap teknik, jadi satu
     * kata aneh bernilai sama dengan pesan yang setiap katanya dirusak.
     * Padahal kepadatannya-lah yang membedakan spam dari pesan wajar: tidak
     * ada orang menulis "m*h jng lagl gha c- 0r lh0". Spam seperti itu tidak
     * menyisakan satu pun kata kunci yang bisa dibaca, sehingga semua jalur
     * deteksi berbasis kata pasti meleset — pengaburannya sendiri yang jadi
     * satu-satunya bukti.
     *
     * Ambang (>=4 kata terjepit, >=30% kata, minimal 6 kata) dikalibrasi
     * agar pesan sah berisi kode kelas, nomor resi, serial, atau daftar
     * harga tetap lolos. Lihat TextNormalizerTest.
     */
    fun heavilyObfuscated(raw: String): Boolean {
        val kata = raw.split(Regex("\\s+")).filter {
            it.length >= 2 && it.any(Char::isLetter) && !TAUTAN.containsMatchIn(it)
        }
        if (kata.size < 6) return false
        val terjepit = kata.count { TERJEPIT.containsMatchIn(it) }
        return terjepit >= 4 && terjepit.toFloat() / kata.size >= 0.30f
    }
}
