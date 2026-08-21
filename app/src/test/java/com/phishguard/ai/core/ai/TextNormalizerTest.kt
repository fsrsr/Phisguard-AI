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
}
