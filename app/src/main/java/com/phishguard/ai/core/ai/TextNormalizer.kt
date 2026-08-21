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
}
