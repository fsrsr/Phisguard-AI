package com.phishguard.ai.core.ai

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Contoh nyata dari laporan pengguna — spam judol yang lolos penyaring kata
 * karena ditulis dengan sengaja dikaburkan.
 */
class TextNormalizerTest {

    private val spamAsli = """
        Klaim Saldo Gratiss tanpa D e p 0
        Mahy'0ng ways 3| M4X'W1N | W 'D 3min.
        https://wde.la/bu5f44
    """.trimIndent()

    @Test
    fun `huruf berspasi dirapatkan`() {
        assertTrue(TextNormalizer.normalize("tanpa D e p 0").contains("depo"))
    }

    @Test
    fun `leetspeak dilipat jadi huruf`() {
        assertTrue(TextNormalizer.normalize("M4X'W1N").contains("maxwin"))
        assertTrue(TextNormalizer.normalize("5L0T G4C0R").contains("slot"))
        assertTrue(TextNormalizer.normalize("5L0T G4C0R").contains("gacor"))
    }

    @Test
    fun `tanda baca penyisip dibuang`() {
        assertTrue(TextNormalizer.normalize("Mahy'0ng").contains("mahyong"))
        assertTrue(TextNormalizer.normalize("s.l.o.t").contains("slot"))
    }

    @Test
    fun `huruf berulang dirapatkan`() {
        assertTrue(TextNormalizer.normalize("Gratiss").contains("gratis"))
        assertTrue(TextNormalizer.normalize("sllooott").contains("slot"))
    }

    @Test
    fun `spam judol nyata terurai jadi istilah yang dikenali`() {
        val n = TextNormalizer.normalize(spamAsli)
        listOf("gratis", "saldo", "depo", "maxwin").forEach {
            assertTrue("'$it' tidak ditemukan di: $n", n.contains(it))
        }
    }

    @Test
    fun `wordlist judol mengenali spam setelah dinormalkan`() {
        val n = TextNormalizer.normalize(spamAsli)
        assertTrue("tidak ada istilah judi kuat", JudolWordlist.hasUnambiguousSignal(n))
        val hit = JudolWordlist.scan(n)
        assertTrue("skor terlalu rendah: ${hit.score} (${hit.summary})", hit.score >= 6)
    }

    @Test
    fun `pesan wajar tidak berubah jadi istilah judi`() {
        // Normalisasi tidak boleh mengarang kecocokan pada teks biasa.
        listOf(
            "Halo bu, besok jadi ketemu jam 10 di kantor ya",
            "Tolong transfer 250 ribu ke rekening yang kemarin",
            "Paket sudah sampai depan pagar, saya taruh di situ"
        ).forEach {
            val n = TextNormalizer.normalize(it)
            assertTrue("keliru menandai: $it → $n", !JudolWordlist.hasUnambiguousSignal(n))
        }
    }

    @Test
    fun `skor pengaburan membedakan spam dari pesan biasa`() {
        assertTrue(TextNormalizer.obfuscationScore(spamAsli) >= 2)
        assertEquals(0, TextNormalizer.obfuscationScore("Besok kita ketemu jam 10 pagi di kantor ya"))
    }

    /**
     * Spam yang dilaporkan lolos: tidak ada satu pun kata kunci yang
     * terbaca setelah normalisasi ("mimpi 88" hancur jadi "mimpi b",
     * "gacor" tersebar jadi "gha c- 0r"), jadi hanya kepadatan
     * pengaburan yang tersisa sebagai bukti.
     */
    private val spamPadat = """
        c4r1 d1 g00gl3 r3sm1 mimpi 88
        m*h jng lagl gha c- 0r lh0
        ada j'g k0m lsl har!an
        bit.ly/mp8-89f6n-29
    """.trimIndent()

    @Test
    fun `pesan yang tiap katanya dikaburkan terdeteksi`() {
        assertTrue(TextNormalizer.heavilyObfuscated(spamPadat))
    }

    @Test
    fun `pemendek tanpa skema tetap terbaca sebagai tautan`() {
        // urlPattern di TFLiteMessageProvider tidak memuat TLD .ly/.la,
        // sehingga pemendek dulu dianggap "pesan tanpa tautan".
        assertEquals("bit.ly/mp8-89f6n-29", TextNormalizer.findLink(spamPadat))
        assertEquals(null, TextNormalizer.findLink("Besok jam 10 di kantor ya"))
    }

    @Test
    fun `pesan sah tidak dianggap dikaburkan`() {
        listOf(
            "Kode OTP BCA Anda 483920. JANGAN beri ke siapapun termasuk pihak bank.",
            "Nasi goreng Rp15.000 Ayam bakar Rp20.000 Es teh Rp5.000 Total Rp40.000",
            "Assalamualaikum, Jum'at besok pengajian ba'da maghrib di rumah Pak Ma'ruf, Insya'Allah hadir",
            "Paket J&T JX1234567890 sudah dikirim, cek di jet.co.id/track/JX1234567890",
            "Jadwal: IF3110 Senin 08.00, IF3140 Rabu 13.00, EL2008 Jumat 10.00 di ruang R4102",
            "Jl. Merdeka No.45 RT.02/RW.03 Kel. Sukamaju, Bandung 40123 dekat pasar",
            "Bro besok jadi futsal? Jam 4 di lapangan biasa ya, anak-anak udah pada konfirmasi"
        ).forEach {
            assertTrue("false positive: $it", !TextNormalizer.heavilyObfuscated(it))
        }
    }
}
